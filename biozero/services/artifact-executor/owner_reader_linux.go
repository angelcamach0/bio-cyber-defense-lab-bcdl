//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package artifactexecutor

import (
	"context"
	"errors"
	"io"
	"os"
	"reflect"
	"syscall"
)

// OwnerReader shares the writer's custody. It has no execution or ACK authority.
type OwnerReader struct{ broker *Broker }

// ownerReadFailure distinguishes broker-observed history faults from this read's
// cancellation, stale snapshot, authorization or network failure. Only the former
// is accompanied by the writer's durable-custody fence.
type ownerReadFailure struct {
	storage bool
	cause   error
}

func (e *ownerReadFailure) Error() string { return e.cause.Error() }
func (e *ownerReadFailure) Unwrap() error { return e.cause }
func ownerReadLocal(code string) error    { return &ownerReadFailure{cause: fail(code)} }

func NewOwnerReader(b *Broker) (*OwnerReader, error) {
	if b == nil {
		return nil, ownerReadLocal("artifact_owner_read_unavailable")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.owner == nil || b.data.SchemaVersion != 3 {
		return nil, ownerReadLocal("artifact_owner_read_version_invalid")
	}
	if e := b.ready(); e != nil {
		return nil, &ownerReadFailure{true, e}
	}
	return &OwnerReader{broker: b}, nil
}

// snapshotLocked requires b.mu. Storage validation deliberately does not inherit
// a remote client's cancellation. These bounded reads have no hard kernel I/O
// deadline. Nothing here saves, acknowledges, reconciles or changes accounting.
func (r *OwnerReader) snapshotLocked(q OwnerReadRequest, deliver func(OwnerReadResponse, *os.File) error) (OwnerReadResponse, *os.File, error) {
	b := r.broker
	bad := func(code string) (OwnerReadResponse, *os.File, error) {
		return NewOwnerReadError(code), nil, ownerReadLocal(code)
	}
	if b.sticky {
		return NewOwnerReadError("artifact_owner_read_unavailable"), nil, &ownerReadFailure{true, fail("artifact_owner_read_unavailable")}
	}
	if b.owner == nil || b.data.SchemaVersion != 3 || b.closed {
		return bad("artifact_owner_read_unavailable")
	}
	if e := b.ownerPreflight(context.Background()); e != nil {
		return NewOwnerReadError("artifact_owner_read_history_invalid"), nil, &ownerReadFailure{true, e}
	}
	o, ok := b.owner.bindings[q.JobID]
	v, has := b.data.Records[q.JobID]
	if !ok || !has || o.AcceptanceSHA256 != q.AcceptanceSHA256 || o.Binding.CredentialSHA256 != q.CredentialSHA256 || b.owner.config.Scope != q.AuthorityScope || v.UploadSHA256 != q.UploadSHA256 || b.data.ProfileSHA256 != q.ExpectedProfileSHA256 {
		return bad("artifact_owner_read_binding_unavailable")
	}
	if v.LeaseID == "" {
		return bad("artifact_owner_read_pending")
	}
	s := b.coordinator.store
	s.mu.Lock()
	defer s.mu.Unlock()
	history := func() (OwnerReadResponse, *os.File, error) {
		e := b.latchStoreLocked("artifact_owner_read_history_invalid")
		return NewOwnerReadError("artifact_owner_read_history_invalid"), nil, &ownerReadFailure{true, e}
	}
	if e := s.ready(); e != nil {
		return NewOwnerReadError("artifact_owner_read_unavailable"), nil, &ownerReadFailure{true, e}
	}
	if b.point("owner_read_storage") != nil {
		return history()
	}
	raw, e := boundedRead(context.Background(), s.root, "ledger.json", ledgerLimit)
	if e != nil || digest(raw) != s.ledgerSHA || s.data.StoreID != b.data.StoreID || s.policySHA() != b.data.PolicySHA256 || !safeInfo(s.root, true) || !safeInfo(s.objects, true) || !safeInfo(s.lock, false) {
		return history()
	}
	// Reopen the fixed children through the held root: replacing a directory or
	// lock must not let a stale descriptor bypass current history validation.
	objects, oe := childDir(s.root, "objects", false)
	if oe != nil {
		return history()
	}
	a, ae := objects.Stat()
	z, ze := s.objects.Stat()
	objects.Close()
	if ae != nil || ze != nil || !os.SameFile(a, z) {
		return history()
	}
	lock, le := regular(s.root, "instance.lock", false)
	if le != nil {
		return history()
	}
	a, ae = lock.Stat()
	z, ze = s.lock.Stat()
	lock.Close()
	if ae != nil || ze != nil || !os.SameFile(a, z) {
		return history()
	}
	names, ne := entries(s.root)
	if ne != nil {
		return history()
	}
	for _, n := range names {
		if n.Name() != "objects" && n.Name() != "ledger.json" && n.Name() != "instance.lock" {
			return history()
		}
	}
	names, ne = entries(s.objects)
	if ne != nil {
		return history()
	}
	for _, n := range names {
		if _, ok := s.data.Records[n.Name()]; !ok {
			return history()
		}
	}
	rec, e := s.record(v.LeaseID)
	if e != nil || rec.JobID != v.JobID || rec.InputSHA256 != v.UploadSHA256 {
		return history()
	}
	x := BridgeResponse{SchemaVersion: 2, JobID: v.JobID, UploadSHA256: v.UploadSHA256, ProfileSHA256: b.data.ProfileSHA256, StoreID: b.data.StoreID, LeaseID: v.LeaseID, State: rec.State, Manifest: emptyBridgeManifest()}
	var receipt *os.File
	if rec.State == "committed" {
		// Store commit may precede the writer's journal seal while its submit handler
		// is reacquiring b.mu. A reader must wait, never complete that seal itself.
		if v.Stage != "committed" {
			return bad("artifact_owner_read_pending")
		}
		if v.ManifestSHA256 != rec.ManifestSHA256 {
			return history()
		}
		dir, e := childDir(s.objects, v.LeaseID, false)
		if e != nil {
			return history()
		}
		defer dir.Close()
		if e = s.verifyRecord(context.Background(), dir, v.LeaseID, rec); e != nil {
			return history()
		}
		raw, e = boundedRead(context.Background(), dir, "manifest.json", manifestLimit)
		if e != nil || digest(raw) != rec.ManifestSHA256 || strictJSON(raw, &x.Manifest) != nil || !s.matchManifest(v.LeaseID, rec, x.Manifest) {
			return history()
		}
		x.HasManifest = true
		x.ManifestSHA256 = rec.ManifestSHA256
		if f, has := x.Manifest.Files["execution_receipt"]; has {
			x.ReceiptSHA256 = f.SHA256
			x.ReceiptBytes = f.Bytes
			if v.ReceiptSHA256 != f.SHA256 || v.ReceiptBytes != f.Bytes {
				return history()
			}
			if q.Operation == "receipt" {
				receipt, e = regular(dir, "execution_receipt", false)
				if e != nil {
					return history()
				}
				if checkInputFile(receipt, f.Bytes) != nil {
					receipt.Close()
					return history()
				}
				if _, e = ReceiveInput(context.Background(), io.Discard, io.NewSectionReader(receipt, 0, f.Bytes+1), f.Bytes, f.SHA256); e != nil {
					receipt.Close()
					return history()
				}
			}
		} else if v.ReceiptSHA256 != "" || v.ReceiptBytes != 0 {
			return history()
		}
	} else if v.Stage == "committed" {
		return history()
	}
	binding := BridgeResponseV3{SchemaVersion: 3, AcceptanceSHA256: o.AcceptanceSHA256, CredentialSHA256: o.Binding.CredentialSHA256, AuthorityScope: b.owner.config.Scope, ProcessedSHA256: v.ProcessedSHA256, ProcessedBytes: v.ProcessedBytes, AnalysisContext: b.analysisContexts[q.JobID], Execution: x}
	response, e := NewOwnerReadSuccess(q, binding)
	if e != nil {
		if receipt != nil {
			receipt.Close()
		}
		return history()
	}
	if deliver != nil {
		if e := deliver(response, receipt); e != nil {
			return response, receipt, e
		}
	}
	return response, receipt, nil
}

func (r *OwnerReader) HandleOwnerRead(ctx context.Context, q OwnerReadRequest) (OwnerReadResponse, *os.File, error) {
	if r == nil || r.broker == nil || ctx == nil || ValidateOwnerReadRequest(q) != nil {
		return NewOwnerReadError("artifact_owner_read_request_invalid"), nil, ownerReadLocal("artifact_owner_read_request_invalid")
	}
	if ctx.Err() != nil {
		return NewOwnerReadError("artifact_owner_read_cancelled"), nil, ownerReadLocal("artifact_owner_read_cancelled")
	}
	b := r.broker
	b.mu.Lock()
	defer b.mu.Unlock()
	response, f, e := r.snapshotLocked(q, nil)
	// A real storage fault already observed is never hidden by a concurrent cancel.
	if e != nil {
		return response, f, e
	}
	if ctx.Err() != nil {
		if f != nil {
			f.Close()
		}
		return NewOwnerReadError("artifact_owner_read_cancelled"), nil, ownerReadLocal("artifact_owner_read_cancelled")
	}
	return response, f, nil
}

// DeliverOwnerRead revalidates the snapshot and FD while holding b.mu -> s.mu
// through the actual, synchronous transport write. The transport must bound that
// callback to five seconds. Network/cancel/dup errors remain local. A typed
// failure of the final trusted receipt validation fences custody, never Store ACK.
func (r *OwnerReader) DeliverOwnerRead(ctx context.Context, q OwnerReadRequest, response OwnerReadResponse, f *os.File, write func() error) error {
	if r == nil || r.broker == nil || ctx == nil || ctx.Err() != nil || write == nil || ValidateOwnerReadResponse(q, response) != nil || response.ErrorCode != "" {
		return ownerReadLocal("artifact_owner_read_delivery_invalid")
	}
	b := r.broker
	b.mu.Lock()
	defer b.mu.Unlock()
	_, checked, e := r.snapshotLocked(q, func(fresh OwnerReadResponse, check *os.File) error {
		if !reflect.DeepEqual(fresh, response) || (check == nil) != (f == nil) {
			return ownerReadLocal("artifact_owner_read_snapshot_changed")
		}
		storageFault := func() error {
			cause := b.latchStoreLocked("artifact_owner_read_history_invalid")
			return &ownerReadFailure{storage: true, cause: cause}
		}
		if check != nil {
			a, ea := check.Stat()
			z, ez := f.Stat()
			// check is a fresh core-owned descriptor. A closed/different caller
			// descriptor is misuse, whereas EIO or changed metadata on the same
			// trusted receipt is an observed storage fault.
			if ea != nil || errors.Is(ez, syscall.EIO) {
				return storageFault()
			}
			if ez != nil || !os.SameFile(a, z) {
				return ownerReadLocal("artifact_owner_read_descriptor_invalid")
			}
			if !ownerInfoEqual(a, z) || checkInputFile(f, response.Binding.Execution.ReceiptBytes) != nil {
				return storageFault()
			}
		}
		if ctx.Err() != nil {
			return ownerReadLocal("artifact_owner_read_cancelled")
		}
		if err := write(); err != nil {
			// Only the trusted server's final receipt checker may tag storage.
			// A client's report, network callback or cancellation never does.
			var classified *ownerReadFailure
			if errors.As(err, &classified) && classified.storage {
				return storageFault()
			}
			return &ownerReadFailure{cause: err}
		}
		return nil
	})
	if checked != nil {
		checked.Close()
	}
	return e
}
