//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package artifactexecutor

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"syscall"

	ownership "biozero/ownership-authority"
)

// Public authority material only. Scope is external genesis, never a claim read
// from an incoming acceptance. The trusted worker establishes GCM/plaintext facts.
type OwnerBrokerConfig struct {
	JournalRoot, ProfileSHA256 string
	Pin                        ownership.AuthorityPin
	Scope                      ownership.AcceptanceScope
}
type ownerBrokerTrust struct {
	AuthorityID  string                    `json:"authority_id"`
	PublicKeyHex string                    `json:"public_key_hex"`
	PipelineMode string                    `json:"pipeline_mode"`
	Scope        ownership.AcceptanceScope `json:"scope"`
}
type ownerBrokerRecord struct {
	AcceptanceSHA256 string            `json:"acceptance_sha256"`
	AcceptanceBytes  int64             `json:"acceptance_bytes"`
	RawSHA256        string            `json:"raw_sha256"`
	Binding          ownership.Binding `json:"binding"`
}
type bridgeJournalV3 struct {
	SchemaVersion    int                          `json:"schema_version"`
	StoreID          string                       `json:"store_id"`
	PolicySHA256     string                       `json:"policy_sha256"`
	ProfileSHA256    string                       `json:"profile_sha256"`
	OwnerTrust       ownerBrokerTrust             `json:"owner_trust"`
	Records          map[string]bridgeBinding     `json:"records"`
	AnalysisContexts map[string]AnalysisContext   `json:"analysis_contexts"`
	OwnerBindings    map[string]ownerBrokerRecord `json:"owner_bindings"`
}
type ownerBrokerState struct {
	config   OwnerBrokerConfig
	trust    ownerBrokerTrust
	bindings map[string]ownerBrokerRecord
	sidecars *os.File
	rawFD    int // no Go finalizer: uncertain custody retains lifetime flock
	rawHeld  bool
}
type ownerInvocation struct {
	sha       string
	bytes     int64
	record    ownerBrokerRecord
	canonical []byte
}

func ownerBrokerConfigValid(c OwnerBrokerConfig) bool {
	return servicePath(c.JournalRoot) && hexID(c.ProfileSHA256, 64) && c.Pin.ExecutionProfileSHA256 == c.ProfileSHA256 && hexID(c.Pin.AuthorityID, 32) && len(c.Pin.PublicKey) == 32 && (c.Pin.PipelineMode == "stats" || c.Pin.PipelineMode == "variants") && hexID(c.Scope.StoreID, 32) && hexID(c.Scope.PolicySHA256, 64)
}

// NewBrokerV3 only opens established v3 history. Genesis is always explicit.
func NewBrokerV3(ctx context.Context, c OwnerBrokerConfig, engine *Coordinator) (*Broker, error) {
	return OpenBrokerV3(ctx, c, engine)
}
func CreateBrokerV3(ctx context.Context, c OwnerBrokerConfig, engine *Coordinator) (*Broker, error) {
	return openOwnerBroker(ctx, c, engine, true)
}
func OpenBrokerV3(ctx context.Context, c OwnerBrokerConfig, engine *Coordinator) (*Broker, error) {
	return openOwnerBroker(ctx, c, engine, false)
}
func openOwnerBroker(ctx context.Context, c OwnerBrokerConfig, engine *Coordinator, create bool) (*Broker, error) {
	if ctx == nil || ctx.Err() != nil || engine == nil || !ownerBrokerConfigValid(c) {
		return nil, fail("artifact_owner_config_invalid")
	}
	engine.mu.Lock()
	unavailable := engine.closed || engine.active != nil
	engine.mu.Unlock()
	if unavailable {
		return nil, fail("artifact_bridge_unavailable")
	}
	s := engine.store
	s.mu.Lock()
	err := s.ready()
	empty := len(s.data.Records) == 0
	sid, policy := s.data.StoreID, s.policySHA()
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if create && !empty {
		return nil, fail("artifact_bridge_history_unaccounted")
	}
	storePath, e := os.Readlink(fdPath(s.root))
	if e != nil || authorityPathOverlap(c.JournalRoot, storePath) {
		return nil, fail("artifact_owner_config_invalid")
	}
	if create {
		parent, e := unixExistingDirectory(filepath.Dir(c.JournalRoot))
		if e != nil {
			return nil, e
		}
		e = syscall.Mkdirat(int(parent.Fd()), filepath.Base(c.JournalRoot), 0700)
		if e == nil {
			e = parent.Sync()
		}
		parent.Close()
		if e != nil {
			return nil, fail("artifact_owner_root_not_new")
		}
	}
	root, e := unixExistingDirectory(c.JournalRoot)
	if e != nil {
		return nil, e
	}
	c.Pin.PublicKey = append([]byte(nil), c.Pin.PublicKey...)
	o := &ownerBrokerState{config: c, trust: ownerBrokerTrust{c.Pin.AuthorityID, hex.EncodeToString(c.Pin.PublicKey), c.Pin.PipelineMode, c.Scope}, bindings: map[string]ownerBrokerRecord{}, rawFD: -1}
	b := &Broker{coordinator: engine, root: root, analysisContexts: map[string]AnalysisContext{}, owner: o, data: bridgeJournal{3, sid, policy, c.ProfileSHA256, map[string]bridgeBinding{}}}
	keep := false
	defer func() {
		if !keep && !o.rawHeld {
			if b.lock != nil {
				b.lock.Close()
			}
			root.Close()
		}
	}()
	b.lock, e = regular(root, "instance.lock", create)
	if e != nil {
		return nil, fail("artifact_bridge_lock_unsafe")
	}
	info, e := b.lock.Stat()
	if e != nil || info.Size() != 0 {
		return nil, fail("artifact_bridge_lock_unsafe")
	}
	if syscall.Flock(int(b.lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return nil, fail("artifact_bridge_instance_locked")
	}
	fd, _, errno := syscall.Syscall(syscall.SYS_FCNTL, b.lock.Fd(), syscall.F_DUPFD_CLOEXEC, 0)
	if errno != 0 {
		return nil, fail("artifact_bridge_lock_unsafe")
	}
	o.rawFD = int(fd)
	o.rawHeld = true
	failOpen := func() (*Broker, error) { return b, b.latch("artifact_owner_history_invalid") }
	if create && (b.lock.Sync() != nil || root.Sync() != nil) {
		return failOpen()
	}
	o.sidecars, e = childDir(root, "acceptances", create)
	if e != nil {
		return failOpen()
	}
	if create {
		if err = b.save(); err != nil {
			return b, err
		}
	} else {
		raw, e := boundedRead(ctx, root, "journal.json", bridgeJournalLimit)
		if e != nil {
			return failOpen()
		}
		var j bridgeJournalV3
		if strictJSON(raw, &j) != nil || j.SchemaVersion != 3 || j.StoreID != sid || j.PolicySHA256 != policy || j.ProfileSHA256 != c.ProfileSHA256 || j.OwnerTrust != o.trust || j.Records == nil || j.AnalysisContexts == nil || j.OwnerBindings == nil {
			return failOpen()
		}
		b.data = bridgeJournal{3, j.StoreID, j.PolicySHA256, j.ProfileSHA256, j.Records}
		b.analysisContexts = j.AnalysisContexts
		o.bindings = j.OwnerBindings
		b.journalSHA = digest(raw)
		if b.ownerPreflight(ctx) != nil {
			return b, fail("artifact_owner_history_invalid")
		}
		if e = b.validateHistory(ctx); e != nil {
			return b, e
		}
	}
	if e = b.ownerPreflight(ctx); e != nil {
		return b, e
	}
	keep = true
	return b, nil
}
func authorityPathOverlap(a, b string) bool {
	return a == b || filepathHasPrefix(a, b) || filepathHasPrefix(b, a)
}
func filepathHasPrefix(a, b string) bool {
	rel, e := filepath.Rel(b, a)
	return e == nil && rel != "." && rel != ".." && len(rel) > 0 && rel[0] != '/' && !(len(rel) >= 3 && rel[:3] == "../")
}

func (b *Broker) encodeOwnerJournal() ([]byte, error) {
	o := b.owner
	if o == nil || b.data.SchemaVersion != 3 || len(b.data.Records) != len(o.bindings) || len(b.analysisContexts) != len(o.bindings) || len(o.bindings) > 64 {
		return nil, fail("artifact_owner_history_invalid")
	}
	return jsonBytes(bridgeJournalV3{3, b.data.StoreID, b.data.PolicySHA256, b.data.ProfileSHA256, o.trust, b.data.Records, b.analysisContexts, o.bindings})
}
func (b *Broker) ownerPreflight(ctx context.Context) error {
	o := b.owner
	if o == nil || !o.rawHeld || !safeInfo(b.root, true) || !safeInfo(b.lock, false) || !safeInfo(o.sidecars, true) {
		return b.latch("artifact_owner_history_invalid")
	}
	fresh, e := unixExistingDirectory(o.config.JournalRoot)
	if e != nil {
		return b.latch("artifact_owner_history_changed")
	}
	a, e1 := fresh.Stat()
	fresh.Close()
	z, e2 := b.root.Stat()
	if e1 != nil || e2 != nil || !os.SameFile(a, z) {
		return b.latch("artifact_owner_history_changed")
	}
	lock, e := regular(b.root, "instance.lock", false)
	if e != nil {
		return b.latch("artifact_owner_history_changed")
	}
	a, e1 = lock.Stat()
	lock.Close()
	z, e2 = b.lock.Stat()
	if e1 != nil || e2 != nil || !os.SameFile(a, z) {
		return b.latch("artifact_owner_history_changed")
	}
	dir, e := childDir(b.root, "acceptances", false)
	if e != nil {
		return b.latch("artifact_owner_history_changed")
	}
	a, e1 = dir.Stat()
	dir.Close()
	z, e2 = o.sidecars.Stat()
	if e1 != nil || e2 != nil || !os.SameFile(a, z) {
		return b.latch("artifact_owner_history_changed")
	}
	list, e := entries(b.root)
	if e != nil {
		return b.latch("artifact_owner_history_invalid")
	}
	for _, f := range list {
		if f.Name() != "instance.lock" && f.Name() != "journal.json" && f.Name() != "acceptances" {
			return b.latch("artifact_owner_history_unknown")
		}
	}
	if b.journalSHA != "" {
		raw, e := boundedRead(ctx, b.root, "journal.json", bridgeJournalLimit)
		if e != nil || digest(raw) != b.journalSHA {
			return b.latch("artifact_owner_history_changed")
		}
	}
	if len(o.bindings) > 64 || len(o.bindings) != len(b.data.Records) || len(o.bindings) != len(b.analysisContexts) {
		return b.latch("artifact_owner_history_invalid")
	}
	list, e = entries(o.sidecars)
	if e != nil || len(list) != len(o.bindings) {
		return b.latch("artifact_owner_history_unknown")
	}
	seen := map[string]bool{}
	for job, v := range o.bindings {
		core, ok := b.data.Records[job]
		facts, has := b.analysisContexts[job]
		if !ok || !has || job != core.JobID || v.Binding.JobID != job || v.Binding.CiphertextSHA256 != core.UploadSHA256 || v.Binding.OriginalName != core.OriginalName || v.Binding.ExecutionProfileSHA256 != b.data.ProfileSHA256 || v.Binding.PipelineMode != o.config.Pin.PipelineMode || validateAnalysisContext(facts, core.ProcessedBytes) != nil || facts.OriginalName != core.OriginalName || !facts.Decrypted || !facts.SignatureValid || facts.DecryptionError != "" || facts.SignatureError != "" || !hexID(v.AcceptanceSHA256, 64) || v.AcceptanceBytes < 1 || v.AcceptanceBytes > ownership.MaxAcceptanceBytes || v.RawSHA256 != v.AcceptanceSHA256 || seen[v.AcceptanceSHA256] {
			return b.latch("artifact_owner_history_invalid")
		}
		seen[v.AcceptanceSHA256] = true
		raw, e := boundedRead(ctx, o.sidecars, v.AcceptanceSHA256+".json", ownership.MaxAcceptanceBytes)
		if e != nil || int64(len(raw)) != v.AcceptanceBytes || digest(raw) != v.RawSHA256 {
			return b.latch("artifact_owner_history_changed")
		}
		verified, e := ownership.VerifyAcceptance(raw, o.config.Pin, o.config.Scope)
		var signed ownership.SignedAcceptance
		if e != nil || verified.SHA256() != v.AcceptanceSHA256 || verified.Binding() != v.Binding || json.Unmarshal(raw, &signed) != nil {
			return b.latch("artifact_owner_history_invalid")
		}
		canonical, e := ownership.MarshalAcceptance(signed)
		if e != nil || !bytes.Equal(raw, canonical) {
			return b.latch("artifact_owner_history_invalid")
		}
	}
	for _, f := range list {
		n := f.Name()
		if len(n) != 69 || n[64:] != ".json" || !seen[n[:64]] {
			return b.latch("artifact_owner_history_unknown")
		}
	}
	return nil
}
func (b *Broker) ownerMatches(job string, call *ownerInvocation) bool {
	v, ok := b.owner.bindings[job]
	return ok && call != nil && v.AcceptanceSHA256 == call.sha && (call.bytes == 0 || call.bytes == v.AcceptanceBytes) && (call.canonical == nil || v == call.record)
}
func (b *Broker) publishOwner(ctx context.Context, job string, call *ownerInvocation) error {
	if call == nil || len(call.canonical) == 0 || call.record.Binding.JobID != job || len(b.owner.bindings) >= 64 {
		return fail("artifact_owner_binding_invalid")
	}
	if b.point("owner_before_sidecar") != nil {
		return b.latch("artifact_owner_persistence_failed")
	}
	f, e := regular(b.owner.sidecars, "acceptance.pending", true)
	if e != nil {
		return b.latch("artifact_owner_persistence_failed")
	}
	defer f.Close()
	n, e := f.Write(call.canonical)
	if e != nil || n != len(call.canonical) || b.point("owner_sidecar_file_sync") != nil || f.Sync() != nil || f.Close() != nil {
		return b.latch("artifact_owner_persistence_failed")
	}
	// Persist the pending name before publishing the final sidecar. A crash in
	// the subsequent link/unlink gap preserves evidence and cold-open fences it.
	if b.point("owner_pending_directory_sync") != nil || b.owner.sidecars.Sync() != nil {
		return b.latch("artifact_owner_persistence_failed")
	}
	base := fdPath(b.owner.sidecars)
	if b.point("owner_sidecar_link") != nil || os.Link(base+"/acceptance.pending", base+"/"+call.sha+".json") != nil || syscall.Unlinkat(int(b.owner.sidecars.Fd()), "acceptance.pending") != nil {
		return b.latch("artifact_owner_persistence_failed")
	}
	if b.point("owner_sidecar_directory_sync") != nil || b.owner.sidecars.Sync() != nil {
		return b.latch("artifact_owner_persistence_failed")
	}
	b.owner.bindings[job] = call.record
	return nil
}
func (b *Broker) verifyOwnerSubmission(ctx context.Context, q BridgeRequestV3, file *os.File) (*ownerInvocation, error) {
	call := &ownerInvocation{sha: q.AcceptanceSHA256, bytes: q.AcceptanceBytes}
	if q.Operation != "submit" {
		return call, nil
	}
	if b.owner == nil || bridgeCheckFile(file, ownership.MaxAcceptanceBytes, q.AcceptanceBytes) != nil {
		return nil, fail("artifact_owner_acceptance_invalid")
	}
	copy, e := duplicateReadOnly(file)
	if e != nil {
		return nil, e
	}
	defer copy.Close()
	before, e := copy.Stat()
	if e != nil {
		return nil, fail("artifact_owner_acceptance_invalid")
	}
	raw, e := io.ReadAll(io.NewSectionReader(copy, 0, q.AcceptanceBytes+1))
	after, se := copy.Stat()
	if e != nil || se != nil || int64(len(raw)) != q.AcceptanceBytes || !ownerInfoEqual(before, after) || bridgeCheckFile(copy, ownership.MaxAcceptanceBytes, q.AcceptanceBytes) != nil || ctx.Err() != nil {
		return nil, fail("artifact_owner_acceptance_invalid")
	}
	v, e := ownership.VerifyAcceptance(raw, b.owner.config.Pin, b.owner.config.Scope)
	var signed ownership.SignedAcceptance
	if e != nil || v.SHA256() != q.AcceptanceSHA256 || json.Unmarshal(raw, &signed) != nil {
		return nil, fail("artifact_owner_acceptance_invalid")
	}
	canonical, e := ownership.MarshalAcceptance(signed)
	binding := v.Binding()
	if e != nil || !bytes.Equal(raw, canonical) || digest(raw) != q.AcceptanceSHA256 || binding.JobID != q.JobID || binding.CiphertextSHA256 != q.UploadSHA256 || binding.OriginalName != q.OriginalName || binding.ExecutionProfileSHA256 != q.ExpectedProfileSHA256 || binding.PipelineMode != b.owner.config.Pin.PipelineMode {
		return nil, fail("artifact_owner_binding_invalid")
	}
	call.canonical = canonical
	call.record = ownerBrokerRecord{v.SHA256(), int64(len(canonical)), digest(raw), binding}
	return call, nil
}
func ownerInfoEqual(a, z os.FileInfo) bool {
	x, ok := a.Sys().(*syscall.Stat_t)
	y, yes := z.Sys().(*syscall.Stat_t)
	return ok && yes && x.Dev == y.Dev && x.Ino == y.Ino && x.Mode == y.Mode && x.Uid == y.Uid && x.Gid == y.Gid && x.Nlink == y.Nlink && x.Size == y.Size && x.Mtim == y.Mtim && x.Ctim == y.Ctim
}
func (b *Broker) HandleBridgeV3(ctx context.Context, q BridgeRequestV3, input, acceptance *os.File) (BridgeResponseV3, *os.File, error) {
	if ctx == nil || validateBridgeRequestV3(q) != nil || (q.Operation == "submit") != (acceptance != nil) {
		return BridgeResponseV3{}, nil, fail("artifact_bridge_request_invalid")
	}
	call, e := b.verifyOwnerSubmission(ctx, q, acceptance)
	if e != nil {
		return BridgeResponseV3{}, nil, e
	}
	r, fd, e := b.handleBridgeOwned(ctx, q.analysisRequest().legacy(), input, &q.AnalysisContext, 3, call)
	if e != nil {
		return BridgeResponseV3{}, fd, e
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if e = b.ready(); e != nil {
		if fd != nil {
			fd.Close()
		}
		return BridgeResponseV3{}, nil, e
	}
	v, ok := b.owner.bindings[q.JobID]
	core := b.data.Records[q.JobID]
	if !ok || v.AcceptanceSHA256 != q.AcceptanceSHA256 {
		if fd != nil {
			fd.Close()
		}
		return BridgeResponseV3{}, nil, fail("artifact_owner_binding_invalid")
	}
	r.SchemaVersion = 2
	return BridgeResponseV3{3, v.AcceptanceSHA256, v.Binding.CredentialSHA256, b.owner.config.Scope, core.ProcessedSHA256, core.ProcessedBytes, b.analysisContexts[q.JobID], r}, fd, nil
}
func (b *Broker) AcknowledgeBridgeV3(ctx context.Context, q BridgeRequestV3, write func() error) error {
	if validateBridgeRequestV3(q) != nil {
		return fail("artifact_bridge_ack_invalid")
	}
	call := &ownerInvocation{sha: q.AcceptanceSHA256, bytes: q.AcceptanceBytes}
	return b.acknowledgeBridgeOwned(ctx, q.analysisRequest().legacy(), write, &q.AnalysisContext, 3, call)
}
func (b *Broker) releaseOwner() error {
	o := b.owner
	if b.ownerPreflight(context.Background()) != nil {
		return fail("artifact_owner_history_invalid")
	}
	if o.sidecars.Close() != nil || b.root.Close() != nil || b.lock.Close() != nil {
		return b.latch("artifact_owner_close_failed")
	}
	if syscall.Close(o.rawFD) != nil {
		return b.latch("artifact_owner_close_failed")
	}
	o.rawHeld = false
	b.released = true
	return nil
}
