//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"syscall"
	"time"

	projection "biozero/enclave-runner/receiptprojection"
	ownership "biozero/ownership-authority"
)

type ownerGatewayLedger struct {
	SchemaVersion int               `json:"schema_version"`
	Domain        string            `json:"domain"`
	ContextSHA256 string            `json:"context_sha256"`
	RetainedBytes int64             `json:"retained_bytes"`
	Runs          []ownerGatewayRun `json:"runs"`
}

// A raw duplicate deliberately retains the writer flock after uncertain IO,
// including when an os.File finalizer runs. Only healthy Close releases it.
type ownerGatewayStore struct {
	mu                      sync.Mutex
	material                ownerGatewayMaterial
	root, lock, operations  *os.File
	rawFD                   int
	rawHeld, sticky, closed bool
	ledger                  ownerGatewayLedger
	ledgerSHA               string
	hot                     map[string]bool
	running                 map[string]bool
	operationsLive          map[string]*ownership.ClientOperation
	deliveriesLive          map[string]*ownership.ClientDelivery
	firstCloseErr           error
	fault                   func(string) error // Test-only publication boundaries, never configuration.
}

func ogStoreError(code string) error { return errors.New(code) }
func ogHex(value string, n int) bool {
	if len(value) != n {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func ogStoreContext(ctx context.Context) error {
	if ctx == nil {
		return ogStoreError("owner_gateway_context_invalid")
	}
	return ctx.Err()
}
func ogStoreSame(a, b *os.File) bool {
	var x, y syscall.Stat_t
	return syscall.Fstat(int(a.Fd()), &x) == nil && syscall.Fstat(int(b.Fd()), &y) == nil && x.Dev == y.Dev && x.Ino == y.Ino && x.Mode == y.Mode && x.Uid == y.Uid
}
func ogStoreDir(parent *os.File, name string) (*os.File, error) {
	fd, err := syscall.Openat(int(parent.Fd()), name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil || st.Mode&07777 != 0700 || st.Uid != uint32(os.Geteuid()) {
		f.Close()
		return nil, ogStoreError("owner_gateway_storage_invalid")
	}
	return f, nil
}
func ogStoreNames(dir *os.File, limit int) ([]string, error) {
	fd, err := syscall.Openat(int(dir.Fd()), ".", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "owner-gateway-list")
	names, readErr := f.Readdirnames(limit + 1)
	closeErr := f.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return nil, readErr
	}
	if len(names) > limit {
		return nil, ogStoreError("owner_gateway_directory_limit")
	}
	if closeErr != nil {
		return nil, closeErr
	}
	sort.Strings(names)
	return names, nil
}
func ogStoreRead(dir *os.File, name string, limit int64) ([]byte, error) {
	fd, err := syscall.Openat(int(dir.Fd()), name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	valid := func(st syscall.Stat_t) bool {
		return st.Mode&syscall.S_IFMT == syscall.S_IFREG && st.Mode&07777 == 0600 && st.Uid == uint32(os.Geteuid()) && st.Nlink == 1 && st.Size > 0 && st.Size <= limit
	}
	var before, after syscall.Stat_t
	if syscall.Fstat(fd, &before) != nil || !valid(before) {
		f.Close()
		return nil, ogStoreError("owner_gateway_storage_invalid")
	}
	raw, readErr := io.ReadAll(io.NewSectionReader(f, 0, limit+1))
	statErr := syscall.Fstat(fd, &after)
	closeErr := f.Close()
	if readErr != nil || statErr != nil || closeErr != nil || !valid(after) || before.Dev != after.Dev || before.Ino != after.Ino || before.Mode != after.Mode || before.Uid != after.Uid || before.Nlink != after.Nlink || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim || int64(len(raw)) != before.Size {
		return nil, ogStoreError("owner_gateway_storage_invalid")
	}
	return raw, nil
}
func ogStoreWrite(dir *os.File, name string, raw []byte) error {
	fd, err := syscall.Openat(int(dir.Fd()), name, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), name)
	n, err := f.Write(raw)
	if err == nil && n != len(raw) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}
func ogStoreJSON(raw []byte, out any) error {
	return projection.DecodeClosedJSON(context.Background(), raw, out)
}
func (s *ownerGatewayStore) latch() error {
	s.sticky = true
	return ogStoreError("owner_gateway_storage_unhealthy")
}
func (s *ownerGatewayStore) point(name string) error {
	if s.fault != nil {
		return s.fault(name)
	}
	return nil
}

// Initialization is a separate explicit action. Failure leaves its partial root
// intact and future Open refuses it. An existing root is never adopted/reset.
func initializeOwnerGatewayStore(ctx context.Context, m ownerGatewayMaterial) error {
	if err := ogStoreContext(ctx); err != nil {
		return err
	}
	if !ogHex(m.ContextSHA256, 64) || !ogConfigPath(m.Config.StateDirectory) {
		return ogStoreError("owner_gateway_context_invalid")
	}
	parent, err := ogOpenPrivateDir(filepath.Dir(m.Config.StateDirectory))
	if err != nil {
		return err
	}
	defer parent.Close()
	name := filepath.Base(m.Config.StateDirectory)
	if err = syscall.Mkdirat(int(parent.Fd()), name, 0700); err != nil {
		return ogStoreError("owner_gateway_state_exists_or_invalid")
	}
	root, err := ogStoreDir(parent, name)
	if err != nil {
		return err
	}
	defer root.Close()
	if err = ogStoreWrite(root, "instance.lock", []byte(ownerGatewayDomain+"\n")); err != nil {
		return err
	}
	if err = syscall.Mkdirat(int(root.Fd()), "operations", 0700); err != nil {
		return err
	}
	operations, err := ogStoreDir(root, "operations")
	if err != nil {
		return err
	}
	if err = operations.Sync(); err != nil {
		operations.Close()
		return err
	}
	if err = operations.Close(); err != nil {
		return err
	}
	l := ownerGatewayLedger{1, ownerGatewayDomain, m.ContextSHA256, 0, []ownerGatewayRun{}}
	raw, err := json.Marshal(l)
	if err != nil {
		return err
	}
	if err = ogStoreWrite(root, "ledger.json", raw); err != nil {
		return err
	}
	if err = root.Sync(); err != nil {
		return err
	}
	return parent.Sync()
}

func openOwnerGatewayStore(ctx context.Context, m ownerGatewayMaterial) (*ownerGatewayStore, error) {
	if err := ogStoreContext(ctx); err != nil {
		return nil, err
	}
	if !ogHex(m.ContextSHA256, 64) {
		return nil, ogStoreError("owner_gateway_context_invalid")
	}
	root, err := ogOpenPrivateDir(m.Config.StateDirectory)
	if err != nil {
		return nil, err
	}
	fd, err := syscall.Openat(int(root.Fd()), "instance.lock", syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		root.Close()
		return nil, ogStoreError("owner_gateway_storage_invalid")
	}
	lock := os.NewFile(uintptr(fd), "owner-gateway-lock")
	raw, err := ogStoreRead(root, "instance.lock", 128)
	if err != nil || string(raw) != ownerGatewayDomain+"\n" {
		lock.Close()
		root.Close()
		return nil, ogStoreError("owner_gateway_storage_invalid")
	}
	if err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		root.Close()
		return nil, ogStoreError("owner_gateway_writer_exists")
	}
	rawFD, err := syscall.Dup(fd)
	if err != nil {
		lock.Close()
		root.Close()
		return nil, err
	}
	syscall.CloseOnExec(rawFD)
	s := &ownerGatewayStore{material: m, root: root, lock: lock, rawFD: rawFD, rawHeld: true, hot: map[string]bool{}, running: map[string]bool{}, operationsLive: map[string]*ownership.ClientOperation{}, deliveriesLive: map[string]*ownership.ClientDelivery{}}
	// After acquiring the lifetime writer lock, malformed history retains it.
	s.operations, err = ogStoreDir(root, "operations")
	if err != nil {
		return nil, s.latch()
	}
	raw, err = ogStoreRead(root, "ledger.json", ownerGatewayRegistryLimit)
	if err != nil || ogStoreJSON(raw, &s.ledger) != nil {
		return nil, s.latch()
	}
	s.ledgerSHA = ogConfigDigest(raw)
	if err = s.validateLedger(); err != nil {
		return nil, s.latch()
	}
	if err = s.preflight(ctx); err != nil {
		return nil, err
	}
	// Cold startup validates journals without issuing any network operations.
	for _, run := range s.ledger.Runs {
		if err = s.openRetained(run); err != nil {
			return nil, s.latch()
		}
	}
	return s, nil
}

func ogImmutableRun(run ownerGatewayRun) ownerGatewayRun {
	run.Phase = "intent"
	run.ErrorCode = ""
	run.JobID = ""
	run.AcceptanceSHA256 = ""
	run.CiphertextSHA256 = ""
	run.CiphertextBytes = 0
	run.KeyEnvelopeSHA256 = ""
	run.Commit = nil
	return run
}
func ogCloneRun(run ownerGatewayRun) ownerGatewayRun {
	raw, _ := json.Marshal(run)
	var out ownerGatewayRun
	_ = json.Unmarshal(raw, &out)
	return out
}
func (s *ownerGatewayStore) index(runID string) int {
	for i := range s.ledger.Runs {
		if s.ledger.Runs[i].RunID == runID {
			return i
		}
	}
	return -1
}
func (s *ownerGatewayStore) validateLedger() error {
	l := s.ledger
	if l.SchemaVersion != 1 || l.Domain != ownerGatewayDomain || l.ContextSHA256 != s.material.ContextSHA256 || l.Runs == nil || len(l.Runs) > ownerGatewayRunLimit || l.RetainedBytes != int64(len(l.Runs))*ownerGatewayRunCharge {
		return s.latch()
	}
	ids, requests, jobs := map[string]bool{}, map[string]bool{}, map[string]bool{}
	counts := map[string]int{}
	for _, r := range l.Runs {
		reviewer, ok := s.material.Reviewers[r.ReviewerID]
		experiment, expOK := s.material.Experiments[r.ExperimentID]
		created, err := time.Parse(time.RFC3339Nano, r.CreatedAt)
		if !ok || !expOK || r.SchemaVersion != 1 || !ogHex(r.RunID, 16) || !ogHex(r.RequestID, 32) || ids[r.RunID] || requests[r.ReviewerID+":"+r.RequestID] || r.ContextSHA256 != l.ContextSHA256 || r.CredentialSHA256 != reviewer.CredentialSHA256 || r.InputSHA256 != experiment.InputSHA256 || r.InputBytes != experiment.InputBytes || r.ReferenceSHA256 != experiment.ReferenceSHA256 || r.ReferenceBytes != experiment.ReferenceBytes || r.OriginalName != experiment.Config.OriginalName || r.ChargeBytes != ownerGatewayRunCharge || err != nil || created.IsZero() || created.UTC().Format(time.RFC3339Nano) != r.CreatedAt {
			return s.latch()
		}
		ids[r.RunID] = true
		requests[r.ReviewerID+":"+r.RequestID] = true
		counts[r.ReviewerID]++
		if counts[r.ReviewerID] > ownerGatewayReviewerRunLimit {
			return s.latch()
		}
		phases := map[string]bool{"intent": true, "creating_operation": true, "reserving": true, "reserved": true, "preparing": true, "prepared": true, "finalizing": true, "accepted": true, "creating_delivery": true, "delivering": true, "delivered": true}
		if !phases[r.Phase] || r.ErrorCode != "" && r.ErrorCode != "owner_gateway_operation_uncertain" {
			return s.latch()
		}
		if r.JobID != "" {
			if !ogHex(r.JobID, 16) || jobs[r.JobID] {
				return s.latch()
			}
			jobs[r.JobID] = true
		}
		if (r.Phase == "reserved" || r.Phase == "preparing" || r.Phase == "prepared" || r.Phase == "finalizing") && !ogHex(r.JobID, 16) {
			return s.latch()
		}
		if r.AcceptanceSHA256 != "" {
			if r.Phase != "accepted" && r.Phase != "creating_delivery" && r.Phase != "delivering" && r.Phase != "delivered" {
				return s.latch()
			}
			if !ogHex(r.AcceptanceSHA256, 64) || !ogHex(r.JobID, 16) || !ogHex(r.CiphertextSHA256, 64) || !ogHex(r.KeyEnvelopeSHA256, 64) || r.CiphertextBytes != r.InputBytes+16 {
				return s.latch()
			}
		} else if r.CiphertextSHA256 != "" || r.CiphertextBytes != 0 || r.KeyEnvelopeSHA256 != "" || r.Commit != nil {
			return s.latch()
		}
		if (r.Phase == "accepted" || r.Phase == "creating_delivery" || r.Phase == "delivering" || r.Phase == "delivered") && r.AcceptanceSHA256 == "" {
			return s.latch()
		}
		if r.Commit != nil {
			if !s.validCommit(r.Commit) {
				return s.latch()
			}
		}
	}
	return nil
}

func (s *ownerGatewayStore) validCommit(commit *ownerGatewayCommit) bool {
	if commit == nil || !ogHex(commit.ResultSHA256, 64) || commit.Artifact.ProfileSHA256 != s.material.Config.ExecutionProfileSHA256 {
		return false
	}
	raw, err := json.Marshal(commit.Artifact)
	if err != nil {
		return false
	}
	_, err = projection.ValidateArtifactExecution(raw, commit.Status, commit.ReleaseStatus)
	return err == nil
}

func (s *ownerGatewayStore) preflight(ctx context.Context) error {
	if err := ogStoreContext(ctx); err != nil {
		return err
	}
	if s.sticky || s.closed {
		return ogStoreError("owner_gateway_storage_unhealthy")
	}
	fresh, err := ogOpenPrivateDir(s.material.Config.StateDirectory)
	if err != nil {
		return s.latch()
	}
	same := ogStoreSame(s.root, fresh)
	closeErr := fresh.Close()
	if !same || closeErr != nil {
		return s.latch()
	}
	names, err := ogStoreNames(s.root, 3)
	if err != nil || !reflect.DeepEqual(names, []string{"instance.lock", "ledger.json", "operations"}) {
		return s.latch()
	}
	fd, err := syscall.Openat(int(s.root.Fd()), "instance.lock", syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return s.latch()
	}
	lock := os.NewFile(uintptr(fd), "owner-gateway-lock-check")
	same = ogStoreSame(s.lock, lock)
	closeErr = lock.Close()
	if !same || closeErr != nil {
		return s.latch()
	}
	lockRaw, lockReadErr := ogStoreRead(s.root, "instance.lock", 128)
	if lockReadErr != nil || string(lockRaw) != ownerGatewayDomain+"\n" {
		return s.latch()
	}
	raw, err := ogStoreRead(s.root, "ledger.json", ownerGatewayRegistryLimit)
	if err != nil || ogConfigDigest(raw) != s.ledgerSHA {
		return s.latch()
	}
	ops, err := ogStoreDir(s.root, "operations")
	if err != nil {
		return s.latch()
	}
	same = ogStoreSame(s.operations, ops)
	closeErr = ops.Close()
	if !same || closeErr != nil {
		return s.latch()
	}
	names, err = ogStoreNames(s.operations, ownerGatewayRunLimit)
	if err != nil || len(names) != len(s.ledger.Runs) {
		return s.latch()
	}
	for _, name := range names {
		idx := s.index(name)
		if idx < 0 {
			return s.latch()
		}
		r := s.ledger.Runs[idx]
		dir, err := ogStoreDir(s.operations, name)
		if err != nil {
			return s.latch()
		}
		raw, err := ogStoreRead(dir, "intent.json", 16<<10)
		var intent ownerGatewayRun
		if err != nil || ogStoreJSON(raw, &intent) != nil || !reflect.DeepEqual(intent, ogImmutableRun(r)) {
			dir.Close()
			return s.latch()
		}
		children, err := ogStoreNames(dir, 4)
		if err != nil {
			dir.Close()
			return s.latch()
		}
		hasAuthority, hasDelivery := false, false
		for _, child := range children {
			if child == "authority" {
				hasAuthority = true
			}
			if child == "delivery" {
				hasDelivery = true
			}
		}
		if r.Phase != "intent" && r.Phase != "creating_operation" && !hasAuthority {
			dir.Close()
			return s.latch()
		}
		if (r.Phase == "delivering" || r.Phase == "delivered") && !hasDelivery {
			dir.Close()
			return s.latch()
		}
		if r.Phase == "intent" && hasAuthority {
			dir.Close()
			return s.latch()
		}
		if hasDelivery && r.Phase != "creating_delivery" && r.Phase != "delivering" && r.Phase != "delivered" {
			dir.Close()
			return s.latch()
		}
		if hasDelivery && r.AcceptanceSHA256 == "" {
			dir.Close()
			return s.latch()
		}
		for _, child := range children {
			if child != "intent.json" && child != "authority" && child != "delivery" && child != "acceptance.json" {
				dir.Close()
				return s.latch()
			}
		}
		if r.AcceptanceSHA256 != "" {
			if _, err = s.acceptance(dir, r); err != nil {
				dir.Close()
				return s.latch()
			}
		} else {
			for _, child := range children {
				if child == "acceptance.json" {
					dir.Close()
					return s.latch()
				}
			}
		}
		if err = dir.Close(); err != nil {
			return s.latch()
		}
	}
	if err := s.checkChildren(true); err != nil {
		return err
	}
	return nil
}

// All registry writes use a durable intent marker. Any interrupted replacement
// is refused at cold Open; no rollback, refund, or unknown-file cleanup occurs.
func (s *ownerGatewayStore) transaction(next ownerGatewayLedger, mutate func() error) error {
	raw, err := json.Marshal(next)
	if err != nil || len(raw) > ownerGatewayRegistryLimit {
		return s.latch()
	}
	if s.point("intent_write") != nil || ogStoreWrite(s.root, "transaction.intent", []byte(ogConfigDigest(raw)+"\n")) != nil {
		return s.latch()
	}
	if s.point("intent_dir_sync") != nil || s.root.Sync() != nil {
		return s.latch()
	}
	if mutate != nil {
		if err = mutate(); err != nil {
			return s.latch()
		}
	}
	if s.point("ledger_write") != nil || ogStoreWrite(s.root, "ledger.next", raw) != nil {
		return s.latch()
	}
	if s.point("ledger_rename") != nil || syscall.Renameat(int(s.root.Fd()), "ledger.next", int(s.root.Fd()), "ledger.json") != nil {
		return s.latch()
	}
	if s.point("ledger_dir_sync") != nil || s.root.Sync() != nil {
		return s.latch()
	}
	if s.point("intent_unlink") != nil || syscall.Unlinkat(int(s.root.Fd()), "transaction.intent") != nil {
		return s.latch()
	}
	if s.point("final_dir_sync") != nil || s.root.Sync() != nil {
		return s.latch()
	}
	s.ledger = next
	s.ledgerSHA = ogConfigDigest(raw)
	return nil
}
func (s *ownerGatewayStore) nextLedger() ownerGatewayLedger {
	raw, _ := json.Marshal(s.ledger)
	var next ownerGatewayLedger
	_ = json.Unmarshal(raw, &next)
	return next
}
func (s *ownerGatewayStore) updateLocked(r ownerGatewayRun, mutate func() error) error {
	i := s.index(r.RunID)
	if i < 0 || !reflect.DeepEqual(ogImmutableRun(r), ogImmutableRun(s.ledger.Runs[i])) {
		return s.latch()
	}
	next := s.nextLedger()
	next.Runs[i] = ogCloneRun(r)
	return s.transaction(next, mutate)
}
func (s *ownerGatewayStore) lookupRequestLocked(reviewerID, requestID string) (ownerGatewayRun, bool) {
	for _, r := range s.ledger.Runs {
		if r.ReviewerID == reviewerID && r.RequestID == requestID {
			return ogCloneRun(r), true
		}
	}
	return ownerGatewayRun{}, false
}
func (s *ownerGatewayStore) LookupRequest(ctx context.Context, reviewerID, requestID string) (ownerGatewayRun, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.preflight(ctx); err != nil {
		return ownerGatewayRun{}, false, err
	}
	if !ogHex(requestID, 32) {
		return ownerGatewayRun{}, false, ogStoreError("owner_gateway_request_invalid")
	}
	r, ok := s.lookupRequestLocked(reviewerID, requestID)
	return s.view(r), ok, nil
}
func (s *ownerGatewayStore) Intent(ctx context.Context, reviewerID, experimentID, requestID string) (ownerGatewayRun, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.preflight(ctx); err != nil {
		return ownerGatewayRun{}, false, err
	}
	reviewer, ok := s.material.Reviewers[reviewerID]
	experiment, expOK := s.material.Experiments[experimentID]
	if !ok || !reviewer.Config.Enabled || !expOK || !ogHex(requestID, 32) {
		return ownerGatewayRun{}, false, ogStoreError("owner_gateway_intent_invalid")
	}
	if previous, exists := s.lookupRequestLocked(reviewerID, requestID); exists {
		if previous.ExperimentID != experimentID {
			return ownerGatewayRun{}, false, ogStoreError("owner_gateway_request_conflict")
		}
		return s.view(previous), false, nil
	}
	count, active, ownActive := 0, 0, 0
	for _, r := range s.ledger.Runs {
		if r.ReviewerID == reviewerID {
			count++
		}
		if r.Commit == nil {
			active++
			if r.ReviewerID == reviewerID {
				ownActive++
			}
		}
	}
	if len(s.ledger.Runs) >= ownerGatewayRunLimit || count >= ownerGatewayReviewerRunLimit {
		return ownerGatewayRun{}, false, ogStoreError("owner_gateway_retention_limit")
	}
	if active >= 2 || ownActive >= 1 {
		return ownerGatewayRun{}, false, ogStoreError("owner_gateway_active_limit")
	}
	entropy := make([]byte, 8)
	if _, err := rand.Read(entropy); err != nil {
		return ownerGatewayRun{}, false, ogStoreError("owner_gateway_entropy_failed")
	}
	runID := hex.EncodeToString(entropy)
	if s.index(runID) >= 0 {
		return ownerGatewayRun{}, false, ogStoreError("owner_gateway_entropy_collision")
	}
	r := ownerGatewayRun{SchemaVersion: 1, RunID: runID, RequestID: requestID, ReviewerID: reviewerID, CredentialSHA256: reviewer.CredentialSHA256, ExperimentID: experimentID, ContextSHA256: s.material.ContextSHA256, InputSHA256: experiment.InputSHA256, InputBytes: experiment.InputBytes, ReferenceSHA256: experiment.ReferenceSHA256, ReferenceBytes: experiment.ReferenceBytes, OriginalName: experiment.Config.OriginalName, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), Phase: "intent", ChargeBytes: ownerGatewayRunCharge}
	next := s.nextLedger()
	next.Runs = append(next.Runs, r)
	next.RetainedBytes += r.ChargeBytes
	err := s.transaction(next, func() error {
		if s.point("run_mkdir") != nil {
			return ogStoreError("owner_gateway_storage_fault")
		}
		if err := syscall.Mkdirat(int(s.operations.Fd()), r.RunID, 0700); err != nil {
			return err
		}
		dir, err := ogStoreDir(s.operations, r.RunID)
		if err != nil {
			return err
		}
		raw, err := json.Marshal(r)
		if err == nil {
			err = ogStoreWrite(dir, "intent.json", raw)
		}
		if err == nil {
			err = dir.Sync()
		}
		closeErr := dir.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		return s.operations.Sync()
	})
	if err != nil {
		return ownerGatewayRun{}, false, err
	}
	s.hot[r.RunID] = true
	return ogCloneRun(r), true, nil
}
func (s *ownerGatewayStore) view(r ownerGatewayRun) ownerGatewayRun {
	r = ogCloneRun(r)
	if r.RunID != "" && !s.hot[r.RunID] && r.Phase != "delivered" && r.ErrorCode == "" {
		r.ErrorCode = "owner_gateway_needs_operator"
	}
	return r
}
func (s *ownerGatewayStore) Run(ctx context.Context, reviewerID, runID string) (ownerGatewayRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.preflight(ctx); err != nil {
		return ownerGatewayRun{}, err
	}
	i := s.index(runID)
	if i < 0 || s.ledger.Runs[i].ReviewerID != reviewerID {
		return ownerGatewayRun{}, ogStoreError("owner_gateway_run_forbidden")
	}
	return s.view(s.ledger.Runs[i]), nil
}
func (s *ownerGatewayStore) Runs(ctx context.Context, reviewerID string) ([]ownerGatewayRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.preflight(ctx); err != nil {
		return nil, err
	}
	out := []ownerGatewayRun{}
	for _, r := range s.ledger.Runs {
		if r.ReviewerID == reviewerID {
			out = append(out, s.view(r))
		}
	}
	return out, nil
}
func (s *ownerGatewayStore) Guard(ctx context.Context, write func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.preflight(ctx); err != nil {
		return err
	}
	if write == nil {
		return ogStoreError("owner_gateway_callback_invalid")
	}
	return write()
}
func (s *ownerGatewayStore) GuardRun(ctx context.Context, reviewerID string, expected ownerGatewayRun, write func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.preflight(ctx); err != nil {
		return err
	}
	if err := s.checkChildren(false); err != nil {
		return err
	}
	i := s.index(expected.RunID)
	if i < 0 || s.ledger.Runs[i].ReviewerID != reviewerID || !reflect.DeepEqual(s.view(s.ledger.Runs[i]), expected) {
		return ogStoreError("owner_gateway_run_changed")
	}
	if write == nil {
		return ogStoreError("owner_gateway_callback_invalid")
	}
	return write()
}

// Pending operation summaries contain local identity/phase only. The callback
// builds from the latest row under the same lock used by durable transitions.
func (s *ownerGatewayStore) GuardRunCurrent(ctx context.Context, reviewerID, runID string, write func(ownerGatewayRun) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.preflight(ctx); err != nil {
		return err
	}
	i := s.index(runID)
	if i < 0 || s.ledger.Runs[i].ReviewerID != reviewerID {
		return ogStoreError("owner_gateway_run_forbidden")
	}
	if write == nil {
		return ogStoreError("owner_gateway_callback_invalid")
	}
	return write(s.view(s.ledger.Runs[i]))
}

func (s *ownerGatewayStore) checkChildren(allowActive bool) error {
	check := func(runID string, err error, busy string) error {
		if err == nil {
			return nil
		}
		if err.Error() == busy {
			if allowActive && s.running[runID] {
				return nil
			}
			return ogStoreError("owner_gateway_operation_busy")
		}
		return s.latch()
	}
	for id, op := range s.operationsLive {
		if err := check(id, op.Check(), "ownership_client_busy"); err != nil {
			return err
		}
	}
	for id, delivery := range s.deliveriesLive {
		if err := check(id, delivery.Check(), "ownership_delivery_busy"); err != nil {
			return err
		}
	}
	return nil
}
func (s *ownerGatewayStore) acceptance(dir *os.File, r ownerGatewayRun) (ownership.VerifiedAcceptance, error) {
	raw, err := ogStoreRead(dir, "acceptance.json", ownership.MaxAcceptanceBytes)
	if err != nil {
		return ownership.VerifiedAcceptance{}, err
	}
	verified, err := ownership.VerifyAcceptance(raw, s.material.Pin, s.material.Config.ExpectedScope)
	if err != nil {
		return verified, err
	}
	b := verified.Binding()
	if verified.SHA256() != r.AcceptanceSHA256 || b.JobID != r.JobID || b.CredentialSHA256 != r.CredentialSHA256 || b.OriginalName != r.OriginalName || b.PipelineMode != s.material.Config.PipelineMode || b.ExecutionProfileSHA256 != s.material.Config.ExecutionProfileSHA256 || b.CiphertextSHA256 != r.CiphertextSHA256 || b.CiphertextBytes != r.CiphertextBytes || b.KeyEnvelopeSHA256 != r.KeyEnvelopeSHA256 {
		return ownership.VerifiedAcceptance{}, ogStoreError("owner_gateway_acceptance_mismatch")
	}
	return verified, nil
}
func (s *ownerGatewayStore) AuthorizeJob(ctx context.Context, reviewerID, jobID string) (ownerGatewayRun, ownership.VerifiedAcceptance, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.preflight(ctx); err != nil {
		return ownerGatewayRun{}, ownership.VerifiedAcceptance{}, err
	}
	for _, r := range s.ledger.Runs {
		if r.JobID == jobID && r.ReviewerID == reviewerID && r.AcceptanceSHA256 != "" {
			dir, err := ogStoreDir(s.operations, r.RunID)
			if err != nil {
				return ownerGatewayRun{}, ownership.VerifiedAcceptance{}, s.latch()
			}
			verified, err := s.acceptance(dir, r)
			closeErr := dir.Close()
			if err != nil || closeErr != nil {
				return ownerGatewayRun{}, verified, s.latch()
			}
			return s.view(r), verified, nil
		}
	}
	return ownerGatewayRun{}, ownership.VerifiedAcceptance{}, ogStoreError("owner_gateway_run_forbidden")
}
func (s *ownerGatewayStore) ObserveResult(ctx context.Context, runID string, result ownerGatewayResult) (ownerGatewayRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.preflight(ctx); err != nil {
		return ownerGatewayRun{}, err
	}
	i := s.index(runID)
	if i < 0 {
		return ownerGatewayRun{}, ogStoreError("owner_gateway_run_forbidden")
	}
	r := s.ledger.Runs[i]
	if result.JobID != r.JobID || r.AcceptanceSHA256 == "" || result.AcceptanceSHA256 != r.AcceptanceSHA256 {
		return ownerGatewayRun{}, ogStoreError("owner_gateway_result_mismatch")
	}
	if result.ExecutionState != "committed" {
		if r.Commit != nil {
			return ownerGatewayRun{}, ogStoreError("owner_gateway_result_stale")
		}
		return s.view(r), nil
	}
	if result.ArtifactExecution == nil || result.ArtifactExecution.ProfileSHA256 != s.material.Config.ExecutionProfileSHA256 || result.ProcessedSHA256 != r.InputSHA256 || result.UploadSHA256 != r.CiphertextSHA256 {
		return ownerGatewayRun{}, ogStoreError("owner_gateway_result_mismatch")
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return ownerGatewayRun{}, err
	}
	commit := &ownerGatewayCommit{ogConfigDigest(raw), result.Status, result.ReleaseStatus, *result.ArtifactExecution}
	if !s.validCommit(commit) {
		return ownerGatewayRun{}, ogStoreError("owner_gateway_result_mismatch")
	}
	if r.Commit != nil {
		if !reflect.DeepEqual(r.Commit, commit) {
			conflict, _ := json.Marshal(struct {
				RunID    string              `json:"run_id"`
				Previous *ownerGatewayCommit `json:"previous"`
				Observed *ownerGatewayCommit `json:"observed"`
			}{runID, r.Commit, commit})
			_ = ogStoreWrite(s.root, "conflicting-observation.json", conflict)
			_ = s.root.Sync()
			return ownerGatewayRun{}, s.latch()
		}
		return s.view(r), nil
	}
	r.Commit = commit
	if err = s.updateLocked(r, nil); err != nil {
		return ownerGatewayRun{}, err
	}
	return s.view(r), nil
}

func (s *ownerGatewayStore) openRetained(r ownerGatewayRun) error {
	dir, err := ogStoreDir(s.operations, r.RunID)
	if err != nil {
		return err
	}
	names, err := ogStoreNames(dir, 4)
	closeErr := dir.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	reviewer := s.material.Reviewers[r.ReviewerID]
	for _, name := range names {
		switch name {
		case "authority":
			op, err := ownership.OpenClientOperation(ownership.ClientOperationConfig{Directory: filepath.Join(s.material.Config.StateDirectory, "operations", r.RunID, "authority"), Client: reviewer.AuthorityConfig, EncryptionKey: s.material.EncryptionKey, OriginalName: r.OriginalName})
			if err != nil {
				return err
			}
			s.operationsLive[r.RunID] = op
			state := op.State()
			allowed := map[string]map[string]bool{"creating_operation": {"intent": true}, "reserving": {"intent": true, "reserved": true}, "reserved": {"reserved": true}, "preparing": {"reserved": true, "prepared": true}, "prepared": {"prepared": true}, "finalizing": {"prepared": true, "finalizing": true, "accepted": true}, "accepted": {"accepted": true}, "creating_delivery": {"accepted": true}, "delivering": {"accepted": true}, "delivered": {"accepted": true}}
			if !allowed[r.Phase][state] {
				return s.latch()
			}
			if r.JobID != "" && op.JobID() != r.JobID {
				return s.latch()
			}
			if r.AcceptanceSHA256 != "" {
				raw, err := op.Acceptance()
				if err != nil {
					return err
				}
				v, err := ownership.VerifyAcceptance(raw, s.material.Pin, s.material.Config.ExpectedScope)
				if err != nil || v.SHA256() != r.AcceptanceSHA256 {
					return s.latch()
				}
			}
		case "delivery":
			delivery, err := ownership.OpenClientDelivery(context.Background(), filepath.Join(s.material.Config.StateDirectory, "operations", r.RunID, "delivery"), reviewer.UploadConfig)
			if err != nil {
				return err
			}
			s.deliveriesLive[r.RunID] = delivery
			state := delivery.State()
			allowed := map[string]map[string]bool{"creating_delivery": {"prepared": true}, "delivering": {"prepared": true, "delivering": true, "delivered": true}, "delivered": {"delivered": true}}
			if !allowed[r.Phase][state] {
				return s.latch()
			}
			sha, err := delivery.AcceptanceSHA256()
			if err != nil || sha != r.AcceptanceSHA256 || delivery.JobID() != r.JobID {
				return s.latch()
			}
		}
	}
	return nil
}
func (s *ownerGatewayStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.firstCloseErr != nil {
		return s.firstCloseErr
	}
	if s.closed {
		return nil
	}
	if err := s.preflight(context.Background()); err != nil {
		return err
	}
	if len(s.running) > 0 {
		return ogStoreError("owner_gateway_operation_pending")
	}
	// Preserve every object if any Close reports uncertainty, especially a
	// delivering ClientDelivery, whose raw lifetime lock must remain held.
	var first error
	for _, delivery := range s.deliveriesLive {
		if err := delivery.Close(); err != nil && first == nil {
			first = err
		}
	}
	for _, op := range s.operationsLive {
		if err := op.Close(); err != nil && first == nil {
			first = err
		}
	}
	if first != nil {
		s.sticky = true
		s.firstCloseErr = first
		return first
	}
	if s.point("close_operations") != nil || s.operations.Close() != nil {
		return s.latch()
	}
	if s.point("close_root") != nil || s.root.Close() != nil {
		return s.latch()
	}
	if s.point("close_lock") != nil || s.lock.Close() != nil {
		return s.latch()
	}
	if s.rawHeld {
		if syscall.Close(s.rawFD) != nil {
			return s.latch()
		}
		s.rawHeld = false
	}
	s.closed = true
	return nil
}
