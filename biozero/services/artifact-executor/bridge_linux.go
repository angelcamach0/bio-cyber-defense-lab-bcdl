//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package artifactexecutor

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
)

type BrokerConfig struct {
	JournalRoot   string
	ProfileSHA256 string
}
type bridgeBinding struct {
	JobID           string `json:"job_id"`
	UploadSHA256    string `json:"upload_sha256"`
	ProcessedSHA256 string `json:"processed_sha256"`
	ProcessedBytes  int64  `json:"processed_bytes"`
	OriginalName    string `json:"original_name"`
	LeaseID         string `json:"lease_id"`
	Stage           string `json:"stage"`
	ManifestSHA256  string `json:"manifest_sha256"`
	ReceiptSHA256   string `json:"receipt_sha256"`
	ReceiptBytes    int64  `json:"receipt_bytes"`
}
type bridgeJournal struct {
	SchemaVersion int                      `json:"schema_version"`
	StoreID       string                   `json:"store_id"`
	PolicySHA256  string                   `json:"policy_sha256"`
	ProfileSHA256 string                   `json:"profile_sha256"`
	Records       map[string]bridgeBinding `json:"records"`
}

// bridgeJournalV2 is deliberately separate: legacy journals never acquire empty
// contexts by migration. Exact map-key equality is required before any recovery.
type bridgeJournalV2 struct {
	SchemaVersion    int                        `json:"schema_version"`
	StoreID          string                     `json:"store_id"`
	PolicySHA256     string                     `json:"policy_sha256"`
	ProfileSHA256    string                     `json:"profile_sha256"`
	Records          map[string]bridgeBinding   `json:"records"`
	AnalysisContexts map[string]AnalysisContext `json:"analysis_contexts"`
}

// Broker is the trusted worker FD bridge. Its journal is bounded metadata outside
// Store's managed byte charge: <=1MiB plus one <=1MiB atomic replacement. It adds
// no terminal release/TTL and never turns an ambiguous historical job into a retry.
// Store/coordinator ownership stays with the caller until provider Wait finishes.
type Broker struct {
	mu               sync.Mutex
	coordinator      *Coordinator
	root, lock       *os.File
	data             bridgeJournal
	analysisContexts map[string]AnalysisContext
	journalSHA       string
	sticky, closed   bool
	released         bool
	activeDone       chan struct{}
	fault            func(string) error // private injection points, never wire fields
}

func (b *Broker) point(name string) error {
	if b.fault != nil {
		return b.fault(name)
	}
	return nil
}
func (b *Broker) latch(code string) error {
	b.sticky = true
	b.coordinator.store.mu.Lock()
	defer b.coordinator.store.mu.Unlock()
	b.coordinator.store.latch(code)
	return fail(code)
}
func (b *Broker) ready() error {
	if b.closed || b.sticky {
		return fail("artifact_bridge_unavailable")
	}
	s := b.coordinator.store
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ready()
}
func NewBroker(ctx context.Context, cfg BrokerConfig, c *Coordinator) (*Broker, error) {
	return newBroker(ctx, cfg, c, 1)
}

// NewBrokerV2 selects analysis-bearing history explicitly. It refuses v1 history
// and never adopts existing Store records into an empty analysis baseline.
func NewBrokerV2(ctx context.Context, cfg BrokerConfig, c *Coordinator) (*Broker, error) {
	return newBroker(ctx, cfg, c, 2)
}
func newBroker(ctx context.Context, cfg BrokerConfig, c *Coordinator, version int) (*Broker, error) {
	if ctx == nil || c == nil || !hexID(cfg.ProfileSHA256, 64) || cfg.JournalRoot == "" {
		return nil, fail("artifact_bridge_config_invalid")
	}
	c.mu.Lock()
	unavailable := c.closed || c.active != nil
	c.mu.Unlock()
	if unavailable {
		return nil, fail("artifact_bridge_unavailable")
	}
	s := c.store
	s.mu.Lock()
	err := s.ready()
	storeID, policySHA, maxJobs := s.data.StoreID, s.policySHA(), s.data.Policy.Jobs
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	// Journal cannot be Store, an ancestor, or a descendant. It must not widen the
	// Store directory allowlist or make either accounting domain adopt the other.
	storePath, err := os.Readlink(fdPath(s.root))
	if err != nil {
		return nil, fail("artifact_bridge_config_invalid")
	}
	journalPath, err := filepath.Abs(cfg.JournalRoot)
	if err != nil {
		return nil, fail("artifact_bridge_config_invalid")
	}
	if journalPath == storePath || strings.HasPrefix(journalPath, storePath+"/") || strings.HasPrefix(storePath, journalPath+"/") {
		return nil, fail("artifact_bridge_config_invalid")
	}
	root, err := openRoot(journalPath)
	if err != nil {
		return nil, err
	}
	b := &Broker{coordinator: c, root: root, analysisContexts: map[string]AnalysisContext{}}
	keep := false
	defer func() {
		if !keep {
			if b.lock != nil {
				b.lock.Close()
			}
			root.Close()
		}
	}()
	lock, err := regular(root, "instance.lock", true)
	if err != nil {
		lock, err = regular(root, "instance.lock", false)
	}
	if err != nil {
		return nil, fail("artifact_bridge_lock_unsafe")
	}
	b.lock = lock
	info, e := lock.Stat()
	if e != nil || info.Size() != 0 {
		return nil, fail("artifact_bridge_lock_unsafe")
	}
	if syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return nil, fail("artifact_bridge_instance_locked")
	}
	if root.Sync() != nil {
		return nil, b.latch("artifact_bridge_persistence_failed")
	}
	list, layoutErr := entries(root)
	if layoutErr != nil {
		return nil, b.latch("artifact_bridge_history_invalid")
	}
	for _, entry := range list {
		if entry.Name() != "instance.lock" && entry.Name() != "journal.json" {
			return nil, b.latch("artifact_bridge_history_unaccounted")
		}
	}
	raw, err := boundedRead(ctx, root, "journal.json", bridgeJournalLimit)
	if absent(err) {
		list, e := entries(root)
		if e != nil {
			return nil, b.latch("artifact_bridge_history_invalid")
		}
		for _, x := range list {
			if x.Name() != "instance.lock" {
				return nil, b.latch("artifact_bridge_history_unaccounted")
			}
		}
		s.mu.Lock()
		empty := len(s.data.Records) == 0
		s.mu.Unlock()
		if !empty {
			return nil, b.latch("artifact_bridge_history_missing")
		}
		b.data = bridgeJournal{version, storeID, policySHA, cfg.ProfileSHA256, map[string]bridgeBinding{}}
		if e = b.save(); e != nil {
			return nil, e
		}
	} else {
		if err != nil || b.decodeJournal(raw, version) != nil {
			return nil, b.latch("artifact_bridge_history_invalid")
		}
		b.journalSHA = digest(raw)
		if b.data.SchemaVersion != version || b.data.StoreID != storeID || b.data.PolicySHA256 != policySHA || b.data.ProfileSHA256 != cfg.ProfileSHA256 || b.data.Records == nil || len(b.data.Records) > maxJobs {
			return nil, b.latch("artifact_bridge_history_invalid")
		}
		if e := b.validateHistory(ctx); e != nil {
			return nil, e
		}
	}
	keep = true
	return b, nil
}
func (b *Broker) decodeJournal(raw []byte, version int) error {
	if version == 1 {
		return strictJSON(raw, &b.data)
	}
	var j bridgeJournalV2
	if strictJSON(raw, &j) != nil || j.SchemaVersion != 2 || j.AnalysisContexts == nil || j.Records == nil || len(j.AnalysisContexts) != len(j.Records) {
		return fail("artifact_bridge_history_invalid")
	}
	for job, v := range j.Records {
		facts, ok := j.AnalysisContexts[job]
		if !ok || validateAnalysisContext(facts, v.ProcessedBytes) != nil || facts.OriginalName != v.OriginalName {
			return fail("artifact_bridge_history_invalid")
		}
	}
	b.data = bridgeJournal{j.SchemaVersion, j.StoreID, j.PolicySHA256, j.ProfileSHA256, j.Records}
	b.analysisContexts = j.AnalysisContexts
	return nil
}
func (b *Broker) save() error {
	if b.closed || b.sticky {
		return fail("artifact_bridge_unavailable")
	}
	var raw []byte
	var err error
	if b.data.SchemaVersion == 2 {
		raw, err = jsonBytes(bridgeJournalV2{2, b.data.StoreID, b.data.PolicySHA256, b.data.ProfileSHA256, b.data.Records, b.analysisContexts})
	} else {
		raw, err = jsonBytes(b.data)
	}
	if err != nil || int64(len(raw)) > bridgeJournalLimit {
		return b.latch("artifact_bridge_journal_oversized")
	}
	list, err := entries(b.root)
	if err != nil {
		return b.latch("artifact_bridge_history_invalid")
	}
	for _, x := range list {
		if x.Name() != "instance.lock" && x.Name() != "journal.json" {
			return b.latch("artifact_bridge_history_unaccounted")
		}
	}
	if b.journalSHA != "" {
		old, e := boundedRead(context.Background(), b.root, "journal.json", bridgeJournalLimit)
		if e != nil || digest(old) != b.journalSHA {
			return b.latch("artifact_bridge_history_changed")
		}
	}
	tok, err := token()
	if err != nil {
		return b.latch("artifact_bridge_persistence_failed")
	}
	tmp := ".tmp-" + tok
	f, err := regular(b.root, tmp, true)
	if err != nil {
		return b.latch("artifact_bridge_persistence_failed")
	}
	defer f.Close()
	if b.point("journal_write") != nil {
		return b.latch("artifact_bridge_persistence_failed")
	}
	n, err := f.Write(raw)
	if err != nil || n != len(raw) || b.point("journal_file_sync") != nil || f.Sync() != nil {
		return b.latch("artifact_bridge_persistence_failed")
	}
	if f.Close() != nil {
		return b.latch("artifact_bridge_persistence_failed")
	}
	if b.journalSHA == "" {
		if b.point("journal_link") != nil || os.Link(fdPath(b.root)+"/"+tmp, fdPath(b.root)+"/journal.json") != nil || syscall.Unlinkat(int(b.root.Fd()), tmp) != nil {
			return b.latch("artifact_bridge_persistence_failed")
		}
	} else if b.point("journal_rename") != nil || syscall.Renameat(int(b.root.Fd()), tmp, int(b.root.Fd()), "journal.json") != nil {
		return b.latch("artifact_bridge_persistence_failed")
	}
	if b.point("journal_directory_sync") != nil || b.root.Sync() != nil {
		return b.latch("artifact_bridge_persistence_failed")
	}
	b.journalSHA = digest(raw)
	return nil
}
func (b *Broker) validateHistory(ctx context.Context) error {
	// A preexisting binding is required for every Store record. Only Store's fully
	// verified committed history can complete an already-linked journal stage.
	s := b.coordinator.store
	s.mu.Lock()
	records := make(map[string]Record, len(s.data.Records))
	for k, v := range s.data.Records {
		records[k] = v
	}
	s.mu.Unlock()
	seen := map[string]bool{}
	changed := false
	for job, v := range b.data.Records {
		q := BridgeRequest{1, "submit", v.JobID, v.UploadSHA256, b.data.ProfileSHA256, v.ProcessedSHA256, v.ProcessedBytes, v.OriginalName}
		if job != v.JobID || validateBridgeRequest(q) != nil || !hexID(v.LeaseID, 32) || seen[v.LeaseID] || (v.Stage != "linked" && v.Stage != "committed") {
			return b.latch("artifact_bridge_history_pending")
		}
		seen[v.LeaseID] = true
		r, ok := records[v.LeaseID]
		if !ok || r.JobID != job || r.InputSHA256 != v.UploadSHA256 || r.State != "committed" {
			return b.latch("artifact_bridge_history_invalid")
		}
		response, err := b.response(ctx, v, false)
		if err != nil {
			return err
		}
		if v.Stage == "committed" {
			if v.ManifestSHA256 != response.ManifestSHA256 || v.ReceiptSHA256 != response.ReceiptSHA256 || v.ReceiptBytes != response.ReceiptBytes {
				return b.latch("artifact_bridge_history_invalid")
			}
		} else {
			if v.ManifestSHA256 != "" || v.ReceiptSHA256 != "" || v.ReceiptBytes != 0 {
				return b.latch("artifact_bridge_history_invalid")
			}
			v.Stage = "committed"
			v.ManifestSHA256 = response.ManifestSHA256
			v.ReceiptSHA256 = response.ReceiptSHA256
			v.ReceiptBytes = response.ReceiptBytes
			b.data.Records[job] = v
			changed = true
		}
	}
	if len(seen) != len(records) {
		return b.latch("artifact_bridge_history_unaccounted")
	}
	if changed {
		return b.save()
	}
	return nil
}
func (b *Broker) response(ctx context.Context, v bridgeBinding, cancelled bool) (BridgeResponse, error) {
	raw, err := b.coordinator.response(v.LeaseID, cancelled)
	if err != nil {
		return BridgeResponse{}, err
	}
	// ExecutionResponse uses pointer/omitempty, unlike the fixed bridge envelope.
	// It is constructed only by the local coordinator. Decode after its verified
	// bounded manifest read, then independently validate the public bridge tuple.
	var e ExecutionResponse
	if err = json.Unmarshal(raw, &e); err != nil {
		return BridgeResponse{}, b.latch("artifact_bridge_history_invalid")
	}
	r := BridgeResponse{SchemaVersion: 1, JobID: v.JobID, UploadSHA256: v.UploadSHA256, ProfileSHA256: b.data.ProfileSHA256, StoreID: b.data.StoreID, LeaseID: v.LeaseID, State: e.State, ManifestSHA256: e.ManifestSHA256, Manifest: emptyBridgeManifest(), CancelRequested: cancelled}
	if e.Manifest != nil {
		r.HasManifest = true
		r.Manifest = *e.Manifest
		if f, ok := r.Manifest.Files["execution_receipt"]; ok {
			r.ReceiptSHA256 = f.SHA256
			r.ReceiptBytes = f.Bytes
		}
	}
	q := BridgeRequest{SchemaVersion: 1, Operation: "status", JobID: v.JobID, UploadSHA256: v.UploadSHA256, ExpectedProfileSHA256: b.data.ProfileSHA256}
	if cancelled {
		q.Operation = "cancel"
	}
	if ctx.Err() != nil {
		return BridgeResponse{}, fail("artifact_cancelled")
	}
	if validateBridgeResponse(q, r) != nil {
		return BridgeResponse{}, b.latch("artifact_bridge_history_invalid")
	}
	return r, nil
}

// HandleBridge borrows input only for the duration of this call. Registry.Bind
// duplicates it atomically. Returning a receipt transfers that descriptor to the
// transport; neither arbitrary Store files nor namespace paths are exposed.
func (b *Broker) HandleBridge(ctx context.Context, q BridgeRequest, input *os.File) (BridgeResponse, *os.File, error) {
	return b.handleBridge(ctx, q, input, nil, 1)
}

// HandleBridgeV2 binds supplied verifier facts durably before Reserve and into
// the one-shot FD registry. These caller facts are not cryptographic proofs.
func (b *Broker) HandleBridgeV2(ctx context.Context, q BridgeRequestV2, input *os.File) (BridgeResponse, *os.File, error) {
	if validateBridgeRequestV2(q) != nil {
		return BridgeResponse{}, nil, fail("artifact_bridge_request_invalid")
	}
	r, f, e := b.handleBridge(ctx, q.legacy(), input, &q.AnalysisContext, 2)
	if e == nil {
		r.SchemaVersion = 2
	}
	return r, f, e
}
func (b *Broker) handleBridge(ctx context.Context, q BridgeRequest, input *os.File, facts *AnalysisContext, version int) (BridgeResponse, *os.File, error) {
	if ctx == nil || ctx.Err() != nil || validateBridgeRequest(q) != nil || (q.Operation == "submit") != (input != nil) {
		return BridgeResponse{}, nil, fail("artifact_bridge_request_invalid")
	}
	b.mu.Lock()
	if err := b.ready(); err != nil {
		b.mu.Unlock()
		return BridgeResponse{}, nil, err
	}
	if version != b.data.SchemaVersion || q.ExpectedProfileSHA256 != b.data.ProfileSHA256 {
		b.mu.Unlock()
		return BridgeResponse{}, nil, fail("artifact_bridge_profile_mismatch")
	}
	v, exists := b.data.Records[q.JobID]
	if exists && (v.UploadSHA256 != q.UploadSHA256 || (q.Operation == "submit" && (v.ProcessedSHA256 != q.ProcessedSHA256 || v.ProcessedBytes != q.ProcessedBytes || v.OriginalName != q.OriginalName || (version == 2 && b.analysisContexts[q.JobID] != *facts)))) {
		b.mu.Unlock()
		return BridgeResponse{}, nil, fail("artifact_bridge_conflict")
	}
	if exists {
		if v.Stage != "linked" && v.Stage != "committed" {
			err := b.latch("artifact_bridge_history_pending")
			b.mu.Unlock()
			return BridgeResponse{}, nil, err
		}
		cancelled := false
		if q.Operation == "cancel" {
			raw, err := b.coordinator.Handle(ctx, Request{SchemaVersion: 1, Operation: "cancel", LeaseID: v.LeaseID})
			var response ExecutionResponse
			if err != nil || json.Unmarshal(raw, &response) != nil {
				b.mu.Unlock()
				return BridgeResponse{}, nil, fail("artifact_bridge_cancel_failed")
			}
			cancelled = response.CancelRequested
		}
		response, err := b.response(ctx, v, cancelled)
		if err == nil && response.State == "committed" && v.Stage != "committed" {
			b.mu.Unlock()
			return BridgeResponse{}, nil, fail("artifact_bridge_commit_pending")
		}
		var output *os.File
		if err == nil && q.Operation == "receipt" {
			output, err = b.receipt(ctx, v, response)
		}
		b.mu.Unlock()
		return response, output, err
	}
	if q.Operation != "submit" {
		b.mu.Unlock()
		return BridgeResponse{}, nil, fail("artifact_bridge_job_unavailable")
	}
	if b.activeDone != nil {
		b.mu.Unlock()
		return BridgeResponse{}, nil, fail("artifact_execution_busy")
	}
	s := b.coordinator.store
	s.mu.Lock()
	maxJobs := s.data.Policy.Jobs
	s.mu.Unlock()
	if len(b.data.Records) >= maxJobs {
		b.mu.Unlock()
		return BridgeResponse{}, nil, fail("artifact_bridge_budget_exceeded")
	}
	// Validate the actual descriptor before creating durable intent/reservation.
	// Bind repeats this after Reserve; changed input cannot reach the provider.
	verified, err := duplicateReadOnly(input)
	if err == nil {
		err = checkInputFile(verified, q.ProcessedBytes)
	}
	if err == nil {
		_, err = ReceiveInput(ctx, io.Discard, io.NewSectionReader(verified, 0, q.ProcessedBytes+1), q.ProcessedBytes, q.ProcessedSHA256)
	}
	if err == nil {
		err = checkInputFile(verified, q.ProcessedBytes)
	}
	if verified != nil {
		defer verified.Close()
	}
	if err != nil {
		b.mu.Unlock()
		return BridgeResponse{}, nil, err
	}
	v = bridgeBinding{JobID: q.JobID, UploadSHA256: q.UploadSHA256, ProcessedSHA256: q.ProcessedSHA256, ProcessedBytes: q.ProcessedBytes, OriginalName: q.OriginalName, Stage: "intent"}
	b.data.Records[q.JobID] = v
	if version == 2 {
		b.analysisContexts[q.JobID] = *facts
	}
	if err = b.save(); err != nil {
		b.mu.Unlock()
		return BridgeResponse{}, nil, err
	}
	if b.point("after_intent") != nil {
		err = b.latch("artifact_bridge_interrupted")
		b.mu.Unlock()
		return BridgeResponse{}, nil, err
	}
	// Split Reserve/Bind deliberately so the durable lease binding precedes Bind.
	// A crash in either gap leaves intent/pending history; no restart auto-reserves.
	v.LeaseID, err = s.Reserve(q.JobID, q.UploadSHA256)
	if err != nil {
		err = b.latch("artifact_bridge_reservation_failed")
		b.mu.Unlock()
		return BridgeResponse{}, nil, err
	}
	if b.point("after_reserve") != nil {
		err = b.latch("artifact_bridge_interrupted")
		b.mu.Unlock()
		return BridgeResponse{}, nil, err
	}
	v.Stage = "linked"
	b.data.Records[q.JobID] = v
	if err = b.save(); err != nil {
		b.mu.Unlock()
		return BridgeResponse{}, nil, err
	}
	if b.point("after_link") != nil {
		err = b.latch("artifact_bridge_interrupted")
		b.mu.Unlock()
		return BridgeResponse{}, nil, err
	}
	var ref string
	if version == 2 {
		ref, err = b.coordinator.registry.BindWithAnalysis(ctx, v.LeaseID, verified, v.ProcessedSHA256, v.ProcessedBytes, *facts)
	} else {
		ref, err = b.coordinator.registry.Bind(ctx, v.LeaseID, verified, v.ProcessedSHA256, v.ProcessedBytes)
	}
	if err != nil {
		err = b.latch("artifact_bridge_input_binding_failed")
		b.mu.Unlock()
		return BridgeResponse{}, nil, err
	}
	if b.point("after_bind") != nil {
		err = b.latch("artifact_bridge_interrupted")
		b.mu.Unlock()
		return BridgeResponse{}, nil, err
	}
	done := make(chan struct{})
	b.activeDone = done
	b.mu.Unlock()
	defer func() { b.mu.Lock(); b.activeDone = nil; close(done); b.mu.Unlock() }()
	_, err = b.coordinator.Handle(ctx, Request{SchemaVersion: 1, Operation: "run", LeaseID: v.LeaseID, InputRef: ref})
	if err == nil {
		err = b.point("before_commit_journal")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if err != nil {
		return BridgeResponse{}, nil, b.latch("artifact_bridge_execution_failed")
	}
	if b.point("after_commit") != nil {
		return BridgeResponse{}, nil, b.latch("artifact_bridge_interrupted")
	}
	// Shutdown/cancel can happen after Store commit. Preserve the linked journal
	// for verified committed-only startup completion rather than a second run.
	if b.closed || ctx.Err() != nil {
		return BridgeResponse{}, nil, fail("artifact_cancelled")
	}
	response, err := b.response(ctx, v, false)
	if err != nil {
		return BridgeResponse{}, nil, err
	}
	if response.State != "committed" {
		return BridgeResponse{}, nil, b.latch("artifact_bridge_commit_required")
	}
	v.Stage = "committed"
	v.ManifestSHA256 = response.ManifestSHA256
	v.ReceiptSHA256 = response.ReceiptSHA256
	v.ReceiptBytes = response.ReceiptBytes
	b.data.Records[q.JobID] = v
	if err = b.save(); err != nil {
		return BridgeResponse{}, nil, err
	}
	return response, nil, nil
}
func (b *Broker) receipt(ctx context.Context, v bridgeBinding, response BridgeResponse) (*os.File, error) {
	q := BridgeRequest{SchemaVersion: 1, Operation: "receipt", JobID: v.JobID, UploadSHA256: v.UploadSHA256, ExpectedProfileSHA256: b.data.ProfileSHA256}
	if validateBridgeResponse(q, response) != nil {
		return nil, fail("artifact_bridge_receipt_unavailable")
	}
	s := b.coordinator.store
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ready(); err != nil {
		return nil, err
	}
	r, err := s.record(v.LeaseID)
	if err != nil || r.State != "committed" || r.ManifestSHA256 != response.ManifestSHA256 {
		return nil, b.latchStoreLocked("artifact_bridge_history_invalid")
	}
	dir, err := childDir(s.objects, v.LeaseID, false)
	if err != nil {
		return nil, b.latchStoreLocked("artifact_bridge_history_invalid")
	}
	defer dir.Close()
	// Recheck proof, manifest and all exports under Store's lock before giving the
	// one allowlisted descriptor. Health errors are never bypassed for readback.
	if err = s.verifyRecord(ctx, dir, v.LeaseID, r); err != nil {
		return nil, b.latchStoreLocked("artifact_bridge_history_invalid")
	}
	f, err := regular(dir, "execution_receipt", false)
	if err != nil {
		return nil, b.latchStoreLocked("artifact_bridge_history_invalid")
	}
	if checkInputFile(f, response.ReceiptBytes) != nil {
		f.Close()
		return nil, b.latchStoreLocked("artifact_bridge_history_invalid")
	}
	if _, err = ReceiveInput(ctx, io.Discard, io.NewSectionReader(f, 0, response.ReceiptBytes+1), response.ReceiptBytes, response.ReceiptSHA256); err != nil {
		f.Close()
		return nil, b.latchStoreLocked("artifact_bridge_history_invalid")
	}
	return f, nil
}
func (b *Broker) latchStoreLocked(code string) error {
	b.sticky = true
	return b.coordinator.store.latch(code)
}
func (b *Broker) AcknowledgeBridge(ctx context.Context, q BridgeRequest, write func() error) error {
	return b.acknowledgeBridge(ctx, q, write, nil, 1)
}
func (b *Broker) AcknowledgeBridgeV2(ctx context.Context, q BridgeRequestV2, write func() error) error {
	if validateBridgeRequestV2(q) != nil {
		return fail("artifact_bridge_ack_invalid")
	}
	return b.acknowledgeBridge(ctx, q.legacy(), write, &q.AnalysisContext, 2)
}
func (b *Broker) acknowledgeBridge(ctx context.Context, q BridgeRequest, write func() error, facts *AnalysisContext, version int) error {
	if ctx == nil || ctx.Err() != nil || validateBridgeRequest(q) != nil || write == nil {
		return fail("artifact_bridge_ack_invalid")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.ready(); err != nil {
		return err
	}
	v, ok := b.data.Records[q.JobID]
	if version != b.data.SchemaVersion || !ok || v.UploadSHA256 != q.UploadSHA256 || q.ExpectedProfileSHA256 != b.data.ProfileSHA256 {
		return fail("artifact_bridge_ack_invalid")
	}
	if q.Operation == "submit" && (v.ProcessedSHA256 != q.ProcessedSHA256 || v.ProcessedBytes != q.ProcessedBytes || v.OriginalName != q.OriginalName || (version == 2 && b.analysisContexts[q.JobID] != *facts)) {
		return fail("artifact_bridge_ack_invalid")
	}
	if b.point("before_ack_store_lock") != nil {
		return fail("artifact_bridge_ack_invalid")
	}
	s := b.coordinator.store
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ready(); err != nil {
		return err
	}
	current, err := s.record(v.LeaseID)
	if err != nil {
		return fail("artifact_bridge_ack_invalid")
	}
	callback := func() error {
		if ctx.Err() != nil {
			return fail("artifact_cancelled")
		}
		return write()
	}
	if current.State == "committed" {
		// Journal and Store predicates are held together through the actual wire
		// callback. A pending journal is rejected before entering Store ACK, so a
		// benign concurrent status does not latch an otherwise healthy commit.
		if v.Stage != "committed" || v.ManifestSHA256 != current.ManifestSHA256 {
			return fail("artifact_bridge_commit_pending")
		}
		return s.acknowledgeLocked(v.LeaseID, callback)
	}
	return callback()
}

// Close requests shutdown. It does not release the journal lock while a handler
// or provider can still write. Wait must succeed before closing Store/registry.
func (b *Broker) Close() error {
	b.mu.Lock()
	b.closed = true
	b.mu.Unlock()
	return b.coordinator.Close()
}
func (b *Broker) Wait(ctx context.Context) error {
	if ctx == nil {
		return fail("artifact_bridge_context_invalid")
	}
	b.mu.Lock()
	if !b.closed {
		b.mu.Unlock()
		return fail("artifact_bridge_shutdown_required")
	}
	done := b.activeDone
	b.mu.Unlock()
	if done != nil {
		select {
		case <-done:
		case <-ctx.Done():
			return fail("artifact_provider_wait_pending")
		}
	}
	if err := b.coordinator.Wait(ctx); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.released {
		return nil
	}
	if b.sticky {
		return fail("artifact_bridge_unavailable")
	}
	s := b.coordinator.store
	s.mu.Lock()
	err := s.ready()
	s.mu.Unlock()
	if err != nil {
		return err
	}
	b.released = true
	a := b.lock.Close()
	e := b.root.Close()
	if a != nil {
		return a
	}
	return e
}
