//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"context"
	"path/filepath"
	"syscall"
	"time"

	ownership "biozero/ownership-authority"
)

// executeStep publishes the local intent before the next library action. The
// library independently persists its own intent before any upstream mutation.
func (s *ownerGatewayStore) executeStep(ctx context.Context, runID, phase, jobID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.preflight(ctx); err != nil {
		return err
	}
	i := s.index(runID)
	if i < 0 || !s.running[runID] {
		return ogStoreError("owner_gateway_operation_invalid")
	}
	r := s.ledger.Runs[i]
	r.Phase = phase
	if jobID != "" {
		if r.JobID != "" && r.JobID != jobID {
			return s.latch()
		}
		r.JobID = jobID
	}
	return s.updateLocked(r, nil)
}

func (s *ownerGatewayStore) retainOperation(runID string, op *ownership.ClientOperation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.operationsLive[runID] != nil {
		return s.latch()
	}
	s.operationsLive[runID] = op
	return nil
}
func (s *ownerGatewayStore) retainDelivery(runID string, d *ownership.ClientDelivery) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.deliveriesLive[runID] != nil {
		return s.latch()
	}
	s.deliveriesLive[runID] = d
	return nil
}

// A failed constructor may already have retained partial custody without
// returning an object. Such a directory is never treated as checked history.
func (s *ownerGatewayStore) failedCreate(runID, child string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	dir, err := ogStoreDir(s.operations, runID)
	if err != nil {
		return s.latch()
	}
	fd, openErr := syscall.Openat(int(dir.Fd()), child, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	closeErr := dir.Close()
	if openErr == nil {
		_ = syscall.Close(fd)
		return s.latch()
	}
	if closeErr != nil || openErr != syscall.ENOENT {
		return s.latch()
	}
	return ogStoreError("owner_gateway_operation_uncertain")
}

func (s *ownerGatewayStore) saveAcceptance(ctx context.Context, runID string, bundle ownership.AcceptedBundle) error {
	verified, err := ownership.VerifyAcceptance(bundle.Acceptance, s.material.Pin, s.material.Config.ExpectedScope)
	if err != nil {
		return ogStoreError("owner_gateway_acceptance_invalid")
	}
	b := verified.Binding()
	if ogConfigDigest(bundle.Ciphertext) != b.CiphertextSHA256 || int64(len(bundle.Ciphertext)) != b.CiphertextBytes || ogConfigDigest(bundle.KeyEnvelope) != b.KeyEnvelopeSHA256 {
		return ogStoreError("owner_gateway_acceptance_invalid")
	}
	var signed ownership.SignedAcceptance
	if err = ogStoreJSON(bundle.Acceptance, &signed); err != nil {
		return err
	}
	canonical, err := ownership.MarshalAcceptance(signed)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err = s.preflight(ctx); err != nil {
		return err
	}
	i := s.index(runID)
	if i < 0 {
		return s.latch()
	}
	r := s.ledger.Runs[i]
	if b.JobID != r.JobID || b.CredentialSHA256 != r.CredentialSHA256 || b.OriginalName != r.OriginalName || b.PipelineMode != s.material.Config.PipelineMode || b.ExecutionProfileSHA256 != s.material.Config.ExecutionProfileSHA256 || b.CiphertextBytes != r.InputBytes+16 {
		return s.latch()
	}
	r.Phase = "accepted"
	r.AcceptanceSHA256 = verified.SHA256()
	r.CiphertextSHA256 = b.CiphertextSHA256
	r.CiphertextBytes = b.CiphertextBytes
	r.KeyEnvelopeSHA256 = b.KeyEnvelopeSHA256
	return s.updateLocked(r, func() error {
		dir, err := ogStoreDir(s.operations, runID)
		if err != nil {
			return err
		}
		err = ogStoreWrite(dir, "acceptance.json", canonical)
		if err == nil {
			err = dir.Sync()
		}
		closeErr := dir.Close()
		if err != nil {
			return err
		}
		return closeErr
	})
}

// Execute accepts only a newly persisted intent from this process. Cold Open
// never populates hot, and neither polling nor retries can dispatch this method.
// ctx belongs to the service (150s total), never to an HTTP request/session.
func (s *ownerGatewayStore) Execute(ctx context.Context, runID string) (returned error) {
	s.mu.Lock()
	if err := s.preflight(ctx); err != nil {
		s.mu.Unlock()
		return err
	}
	i := s.index(runID)
	if i < 0 || !s.hot[runID] || s.running[runID] || s.ledger.Runs[i].Phase != "intent" {
		s.mu.Unlock()
		return ogStoreError("owner_gateway_operation_not_fresh")
	}
	r := s.ledger.Runs[i]
	reviewer := s.material.Reviewers[r.ReviewerID]
	experiment := s.material.Experiments[r.ExperimentID]
	s.running[runID] = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		delete(s.running, runID)
		delete(s.hot, runID)
		if returned == nil {
			return
		}
		if s.sticky || s.closed {
			return
		}
		if err := s.preflight(context.Background()); err != nil {
			returned = err
			return
		}
		i := s.index(runID)
		if i < 0 {
			returned = s.latch()
			return
		}
		current := s.ledger.Runs[i]
		current.ErrorCode = "owner_gateway_operation_uncertain"
		if err := s.updateLocked(current, nil); err != nil {
			returned = err
		}
	}()
	root := filepath.Join(s.material.Config.StateDirectory, "operations", r.RunID)
	if err := s.executeStep(ctx, runID, "creating_operation", ""); err != nil {
		return err
	}
	op, err := ownership.CreateClientOperation(ownership.ClientOperationConfig{Directory: filepath.Join(root, "authority"), Client: reviewer.AuthorityConfig, EncryptionKey: s.material.EncryptionKey, OriginalName: r.OriginalName})
	if err != nil {
		return s.failedCreate(runID, "authority")
	}
	if err = s.retainOperation(runID, op); err != nil {
		return err
	}
	if err = s.executeStep(ctx, runID, "reserving", ""); err != nil {
		return err
	}
	if err = op.Reserve(ctx); err != nil {
		return ogStoreError("owner_gateway_operation_uncertain")
	}
	if err = s.executeStep(ctx, runID, "reserved", op.JobID()); err != nil {
		return err
	}
	if err = s.executeStep(ctx, runID, "preparing", ""); err != nil {
		return err
	}
	input := append([]byte(nil), experiment.Input...)
	err = op.Prepare(ctx, input, time.Now())
	clear(input)
	if err != nil {
		return ogStoreError("owner_gateway_operation_uncertain")
	}
	if err = s.executeStep(ctx, runID, "prepared", ""); err != nil {
		return err
	}
	if err = s.executeStep(ctx, runID, "finalizing", ""); err != nil {
		return err
	}
	if err = op.Finalize(ctx); err != nil {
		return ogStoreError("owner_gateway_operation_uncertain")
	}
	bundle, err := op.AcceptedBundle()
	if err != nil {
		return ogStoreError("owner_gateway_operation_uncertain")
	}
	if err = s.saveAcceptance(ctx, runID, bundle); err != nil {
		return err
	}
	if err = s.executeStep(ctx, runID, "creating_delivery", ""); err != nil {
		return err
	}
	delivery, err := ownership.CreateClientDelivery(ctx, filepath.Join(root, "delivery"), reviewer.UploadConfig, bundle)
	clear(bundle.Ciphertext)
	clear(bundle.KeyEnvelope)
	if err != nil {
		return s.failedCreate(runID, "delivery")
	}
	if err = s.retainDelivery(runID, delivery); err != nil {
		return err
	}
	if err = s.executeStep(ctx, runID, "delivering", ""); err != nil {
		return err
	}
	receipt, err := delivery.Deliver(ctx)
	if err != nil {
		return ogStoreError("owner_gateway_operation_uncertain")
	}
	s.mu.Lock()
	i = s.index(runID)
	if i < 0 {
		s.mu.Unlock()
		return ogStoreError("owner_gateway_operation_invalid")
	}
	current := s.ledger.Runs[i]
	s.mu.Unlock()
	if receipt.SchemaVersion != 1 || receipt.State != "delivered" || receipt.JobID != current.JobID || receipt.AcceptanceSHA256 != current.AcceptanceSHA256 || receipt.CredentialSHA256 != current.CredentialSHA256 || receipt.CiphertextSHA256 != current.CiphertextSHA256 || receipt.CiphertextBytes != current.CiphertextBytes || receipt.KeyEnvelopeSHA256 != current.KeyEnvelopeSHA256 {
		return ogStoreError("owner_gateway_delivery_mismatch")
	}
	return s.executeStep(ctx, runID, "delivered", "")
}
