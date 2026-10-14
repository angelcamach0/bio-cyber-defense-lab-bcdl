package artifactexecutor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"reflect"
	"strconv"
	"sync"
	"syscall"
)

type Store struct {
	mu                  sync.Mutex
	root, objects, lock *os.File
	data                ledger
	ledgerSHA           string
	sticky, closed      bool
	fault               func(string) error // Internal failpoints; never exposed to RPC.
}

func (s *Store) point(name string) error {
	if s.fault != nil {
		return s.fault(name)
	}
	return nil
}
func (s *Store) latch(code string) error { s.sticky = true; return fail(code) }
func (s *Store) ready() error {
	if s.closed || s.sticky {
		return fail("artifact_store_unavailable")
	}
	return nil
}
func Open(ctx context.Context, path string, policy Policy) (*Store, error) {
	if e := policy.validate(); e != nil {
		return nil, e
	}
	policy.ArtifactIDs = append([]string{}, policy.ArtifactIDs...)
	root, e := openRoot(path)
	if e != nil {
		return nil, e
	}
	s := &Store{root: root}
	ok := false
	defer func() {
		if !ok {
			s.Close()
		}
	}()
	lock, e := regular(root, "instance.lock", true)
	if e != nil {
		lock, e = regular(root, "instance.lock", false)
	}
	if e != nil {
		return nil, fail("artifact_lock_unsafe")
	}
	s.lock = lock
	info, statErr := lock.Stat()
	if statErr != nil || info.Size() != 0 {
		return nil, fail("artifact_lock_unsafe")
	}
	if syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return nil, fail("artifact_instance_locked")
	}
	if root.Sync() != nil {
		return nil, fail("artifact_directory_sync_failed")
	}
	objects, e := childDir(root, "objects", true)
	if e != nil {
		return nil, e
	}
	s.objects = objects
	raw, e := boundedRead(ctx, root, "ledger.json", ledgerLimit)
	if absent(e) {
		all, e := entries(root)
		if e != nil {
			return nil, e
		}
		for _, x := range all {
			if x.Name() != "instance.lock" && x.Name() != "objects" {
				return nil, fail("artifact_history_unaccounted")
			}
		}
		all, e = entries(objects)
		if e != nil || len(all) != 0 {
			return nil, fail("artifact_history_unaccounted")
		}
		id, e := token()
		if e != nil {
			return nil, e
		}
		s.data = ledger{1, id, policy, map[string]Record{}}
		if e = s.save(); e != nil {
			return nil, e
		}
	} else {
		if e != nil {
			return nil, e
		}
		if e = strictJSON(raw, &s.data); e != nil {
			return nil, e
		}
		if e = s.validateLedger(policy); e != nil {
			return nil, e
		}
		s.ledgerSHA = digest(raw)
		if e = s.verifyHistory(ctx); e != nil {
			return nil, e
		}
	}
	ok = true
	return s, nil
}
func (s *Store) validateLedger(policy Policy) error {
	if s.data.SchemaVersion != 1 || !hexID(s.data.StoreID, 32) || !reflect.DeepEqual(s.data.Policy, policy) || len(s.data.Records) > policy.Jobs {
		return fail("artifact_ledger_invalid")
	}
	total := storeHeaderReserve
	jobs := map[string]bool{}
	allowed := map[string]bool{}
	for _, x := range policy.ArtifactIDs {
		allowed[x] = true
	}
	for lease, r := range s.data.Records {
		if !hexID(lease, 32) || !hexID(r.JobID, 16) || !hexID(r.InputSHA256, 64) || jobs[r.JobID] || r.Charge <= 0 || r.Charge > policy.ExportBytes+policy.PublicationHeadroom || len(r.Files) > len(allowed) {
			return fail("artifact_ledger_invalid")
		}
		jobs[r.JobID] = true
		switch r.State {
		case "reserved", "executing", "prepared", "committed":
		default:
			return fail("artifact_ledger_invalid")
		}
		if r.State != "committed" {
			if r.Charge != policy.ExportBytes+policy.PublicationHeadroom {
				return fail("artifact_ledger_invalid")
			}
			s.sticky = true
		}
		if r.State == "reserved" && (len(r.Files) != 0 || r.ManifestSHA256 != "" || r.ProofSHA256 != "") {
			return fail("artifact_ledger_invalid")
		}
		if r.State == "prepared" || r.State == "committed" {
			if !hexID(r.ManifestSHA256, 64) {
				return fail("artifact_ledger_invalid")
			}
		}
		if r.State == "executing" && (r.ManifestSHA256 != "" || r.ProofSHA256 != "") {
			return fail("artifact_ledger_invalid")
		}
		if r.State == "committed" && !hexID(r.ProofSHA256, 64) {
			return fail("artifact_ledger_invalid")
		}
		var exported int64
		for id, f := range r.Files {
			if !allowed[id] || !hexID(f.SHA256, 64) || f.Bytes < 0 || f.Bytes > policy.ExportBytes {
				return fail("artifact_ledger_invalid")
			}
			if exported > policy.ExportBytes-f.Bytes || (f.State == "planned" && f.Bytes != 0) {
				return fail("artifact_ledger_invalid")
			}
			exported += f.Bytes
			if f.State != "planned" && f.State != "verified" {
				return fail("artifact_ledger_invalid")
			}
			if (r.State == "prepared" || r.State == "committed") && f.State != "verified" {
				return fail("artifact_ledger_invalid")
			}
		}
		if total > policy.GlobalBytes-r.Charge {
			return fail("artifact_ledger_invalid")
		}
		total += r.Charge
	}
	return nil
}
func (s *Store) verifyHistory(ctx context.Context) error {
	all, e := entries(s.root)
	if e != nil {
		return e
	}
	for _, x := range all {
		if x.Name() != "ledger.json" && x.Name() != "instance.lock" && x.Name() != "objects" {
			return fail("artifact_history_unaccounted")
		}
	}
	all, e = entries(s.objects)
	if e != nil {
		return e
	}
	for _, x := range all {
		if _, ok := s.data.Records[x.Name()]; !ok {
			return fail("artifact_history_unaccounted")
		}
	}
	for lease, r := range s.data.Records {
		dir, e := childDir(s.objects, lease, false)
		if absent(e) && r.State == "reserved" {
			continue
		}
		if e != nil {
			return fail("artifact_history_missing")
		}
		e = s.verifyRecord(ctx, dir, lease, r)
		dir.Close()
		if e != nil {
			return e
		}
	}
	return nil
}
func (s *Store) verifyRecord(ctx context.Context, dir *os.File, lease string, r Record) error {
	all, e := entries(dir)
	if e != nil {
		return e
	}
	known := map[string]bool{}
	for id := range r.Files {
		known[id] = true
	}
	if r.ManifestSHA256 != "" {
		known["manifest.json"] = true
	}
	if r.ProofSHA256 != "" {
		known["proof.json"] = true
	}
	for _, x := range all {
		if !known[x.Name()] {
			return fail("artifact_history_unaccounted")
		}
	}
	for id, f := range r.Files {
		if f.State == "planned" {
			h, _, err := hashFile(ctx, dir, id, s.data.Policy.ExportBytes)
			if absent(err) {
				continue
			}
			if err != nil || h != f.SHA256 {
				return fail("artifact_history_invalid")
			}
			continue
		}
		h, n, e := hashFile(ctx, dir, id, s.data.Policy.ExportBytes)
		if e != nil || h != f.SHA256 || n != f.Bytes {
			return fail("artifact_history_invalid")
		}
	}
	if r.ManifestSHA256 != "" {
		b, e := boundedRead(ctx, dir, "manifest.json", manifestLimit)
		if e != nil || digest(b) != r.ManifestSHA256 {
			return fail("artifact_history_invalid")
		}
		var m Manifest
		if strictJSON(b, &m) != nil || !s.matchManifest(lease, r, m) {
			return fail("artifact_history_invalid")
		}
	}
	if r.ProofSHA256 != "" {
		b, e := boundedRead(ctx, dir, "proof.json", proofLimit)
		if e != nil || digest(b) != r.ProofSHA256 {
			return fail("artifact_history_invalid")
		}
		var p Proof
		if strictJSON(b, &p) != nil || !s.matchProof(lease, r, p) {
			return fail("artifact_history_invalid")
		}
	}
	if r.State == "committed" {
		actual, e := s.actualCharge(dir, r)
		if e != nil || actual != r.Charge {
			return fail("artifact_ledger_invalid")
		}
	}
	return nil
}
func hashFile(ctx context.Context, dir *os.File, name string, limit int64) (string, int64, error) {
	f, e := regular(dir, name, false)
	if e != nil {
		return "", 0, e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || st.Size() > limit {
		return "", 0, fail("artifact_file_oversized")
	}
	h := sha256.New()
	buf := make([]byte, 65536)
	var size int64
	for {
		if ctx.Err() != nil {
			return "", 0, fail("artifact_cancelled")
		}
		n, e := f.Read(buf)
		size += int64(n)
		if size > limit {
			return "", 0, fail("artifact_file_oversized")
		}
		h.Write(buf[:n])
		if e == io.EOF {
			break
		}
		if e != nil {
			return "", 0, fail("artifact_read_failed")
		}
	}
	return hex.EncodeToString(h.Sum(nil)), size, nil
}
func (s *Store) save() error {
	b, e := jsonBytes(s.data)
	if e != nil || int64(len(b)) > ledgerLimit {
		return s.latch("artifact_ledger_oversized")
	}
	if s.ledgerSHA != "" {
		old, e := boundedRead(context.Background(), s.root, "ledger.json", ledgerLimit)
		if e != nil || digest(old) != s.ledgerSHA {
			return s.latch("artifact_ledger_changed")
		}
	}
	if e = s.publish(s.root, "ledger.json", b, true); e != nil {
		return s.latch("artifact_persistence_failed")
	}
	s.ledgerSHA = digest(b)
	return nil
}
func (s *Store) publish(dir *os.File, name string, data []byte, replace bool) error {
	tok, e := token()
	if e != nil {
		return e
	}
	tmp := ".tmp-" + tok
	f, e := regular(dir, tmp, true)
	if e != nil {
		return e
	}
	defer f.Close()
	if e = s.point("write"); e != nil {
		return e
	}
	if _, e = f.Write(data); e != nil {
		return e
	}
	if e = s.point("file_sync"); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if replace {
		if e = s.point("rename"); e == nil {
			e = syscall.Renameat(int(dir.Fd()), tmp, int(dir.Fd()), name)
		}
	} else {
		if e = s.point("link"); e == nil {
			e = os.Link(fdPath(dir)+"/"+tmp, fdPath(dir)+"/"+name)
		}
		if e == nil {
			e = syscall.Unlinkat(int(dir.Fd()), tmp)
		}
	}
	if e != nil {
		return e
	}
	if e = s.point("directory_sync"); e != nil {
		return e
	}
	return dir.Sync()
}
func fdPath(f *os.File) string { return "/proc/self/fd/" + strconv.Itoa(int(f.Fd())) }
func (s *Store) Snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64 = storeHeaderReserve
	for _, r := range s.data.Records {
		n += r.Charge
	}
	return Snapshot{len(s.data.Records), n, !s.sticky && !s.closed}
}
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	for _, f := range []*os.File{s.objects, s.lock, s.root} {
		if f != nil {
			f.Close()
		}
	}
	return nil
}
func (s *Store) Reserve(jobID, inputSHA string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.ready(); e != nil {
		return "", e
	}
	if !hexID(jobID, 16) || !hexID(inputSHA, 64) {
		return "", fail("artifact_identity_invalid")
	}
	total := storeHeaderReserve
	for _, r := range s.data.Records {
		if r.JobID == jobID {
			return "", fail("artifact_job_conflict")
		}
		total += r.Charge
	}
	reserve := s.data.Policy.ExportBytes + s.data.Policy.PublicationHeadroom
	if len(s.data.Records) >= s.data.Policy.Jobs || total > s.data.Policy.GlobalBytes-reserve {
		return "", fail("artifact_quota_exceeded")
	}
	lease, e := token()
	if e != nil {
		return "", e
	}
	s.data.Records[lease] = Record{jobID, inputSHA, "reserved", reserve, map[string]FileRecord{}, "", ""}
	if e = s.save(); e != nil {
		return "", e
	}
	return lease, nil
}
func (s *Store) record(lease string) (Record, error) {
	if !hexID(lease, 32) {
		return Record{}, fail("artifact_lease_invalid")
	}
	r, ok := s.data.Records[lease]
	if !ok {
		return Record{}, fail("artifact_lease_invalid")
	}
	return r, nil
}
func (s *Store) Begin(lease string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.ready(); e != nil {
		return e
	}
	r, e := s.record(lease)
	if e != nil {
		return e
	}
	if r.State != "reserved" {
		return fail("artifact_transition_invalid")
	}
	for _, x := range s.data.Records {
		if x.State == "executing" || x.State == "prepared" {
			return fail("artifact_execution_busy")
		}
	}
	r.State = "executing"
	s.data.Records[lease] = r
	if e = s.save(); e != nil {
		return e
	}
	d, e := childDir(s.objects, lease, true)
	if e != nil {
		return s.latch("artifact_directory_unavailable")
	}
	d.Close()
	return nil
}
func (s *Store) Export(ctx context.Context, lease, id, expectedSHA string, src io.Reader) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.ready(); e != nil {
		return e
	}
	r, e := s.record(lease)
	if e != nil {
		return e
	}
	if r.State != "executing" || !hexID(expectedSHA, 64) {
		return fail("artifact_transition_invalid")
	}
	allowed := false
	for _, x := range s.data.Policy.ArtifactIDs {
		if x == id {
			allowed = true
		}
	}
	if !allowed {
		return fail("artifact_id_invalid")
	}
	if _, ok := r.Files[id]; ok {
		return fail("artifact_export_conflict")
	}
	used := int64(0)
	for _, f := range r.Files {
		used += f.Bytes
	}
	remaining := s.data.Policy.ExportBytes - used
	r.Files[id] = FileRecord{"planned", expectedSHA, 0}
	s.data.Records[lease] = r
	if e = s.save(); e != nil {
		return e
	}
	dir, e := childDir(s.objects, lease, false)
	if e != nil {
		return s.latch("artifact_export_failed")
	}
	defer dir.Close()
	tok, e := token()
	if e != nil {
		return s.latch("artifact_export_failed")
	}
	tmp := ".tmp-" + tok
	out, e := regular(dir, tmp, true)
	if e != nil {
		return s.latch("artifact_export_failed")
	}
	defer out.Close()
	h := sha256.New()
	buf := make([]byte, 65536)
	var count int64
	for {
		if ctx.Err() != nil {
			return s.latch("artifact_cancelled")
		}
		want := int64(len(buf))
		if remaining-count+1 < want {
			want = remaining - count + 1
		}
		n, readErr := src.Read(buf[:want])
		if n < 0 || int64(n) > want {
			return s.latch("artifact_export_invalid")
		}
		if n == 0 && readErr == nil {
			return s.latch("artifact_export_no_progress")
		}
		count += int64(n)
		if count > remaining {
			return s.latch("artifact_budget_exceeded")
		}
		if _, e = out.Write(buf[:n]); e != nil {
			return s.latch("artifact_export_failed")
		}
		h.Write(buf[:n])
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return s.latch("artifact_export_failed")
		}
	}
	if hex.EncodeToString(h.Sum(nil)) != expectedSHA {
		return s.latch("artifact_export_digest_mismatch")
	}
	if s.point("file_sync") != nil || out.Sync() != nil || out.Close() != nil {
		return s.latch("artifact_export_failed")
	}
	if s.point("link") != nil || os.Link(fdPath(dir)+"/"+tmp, fdPath(dir)+"/"+id) != nil {
		return s.latch("artifact_export_failed")
	}
	if syscall.Unlinkat(int(dir.Fd()), tmp) != nil || s.point("directory_sync") != nil || dir.Sync() != nil {
		return s.latch("artifact_export_failed")
	}
	r.Files[id] = FileRecord{"verified", expectedSHA, count}
	s.data.Records[lease] = r
	return s.save()
}
func (s *Store) policySHA() string { b, _ := json.Marshal(s.data.Policy); return digest(b) }
func (s *Store) matchManifest(lease string, r Record, m Manifest) bool {
	if !(m.SchemaVersion == 1 && m.StoreID == s.data.StoreID && m.PolicySHA256 == s.policySHA() && m.LeaseID == lease && m.JobID == r.JobID && m.InputSHA256 == r.InputSHA256 && reflect.DeepEqual(m.Files, r.Files)) {
		return false
	}
	switch m.ExecutionStatus {
	case "succeeded", "incomplete", "failed":
	default:
		return false
	}
	switch m.ReleaseStatus {
	case "evaluated_passed", "withheld", "unassessed":
	default:
		return false
	}
	if m.ErrorCode != "" && (!artifactCode.MatchString(m.ErrorCode)) {
		return false
	}
	if (m.ExecutionStatus != "succeeded" || m.ReleaseStatus == "withheld") && m.ErrorCode == "" {
		return false
	}
	if f, ok := m.Files["normalized_vcf"]; ok {
		if !hexID(m.ObservedSHA256, 64) || m.ObservedSHA256 != f.SHA256 {
			return false
		}
	} else if m.ObservedSHA256 != "" {
		return false
	}
	if m.EvaluatedSHA256 != "" && (!hexID(m.EvaluatedSHA256, 64) || m.EvaluatedSHA256 != m.ObservedSHA256) {
		return false
	}
	if m.ReleaseStatus == "evaluated_passed" {
		return m.ExecutionStatus == "succeeded" && m.ErrorCode == "" && hexID(m.ObservedSHA256, 64) && m.ObservedSHA256 == m.EvaluatedSHA256
	}
	return true
}
func (s *Store) matchProof(lease string, r Record, p Proof) bool {
	return p.SchemaVersion == 1 && p.StoreID == s.data.StoreID && p.PolicySHA256 == s.policySHA() && p.LeaseID == lease && p.JobID == r.JobID && p.InputSHA256 == r.InputSHA256 && p.ManifestSHA256 == r.ManifestSHA256 && p.CapsuleWaitFinished && p.ExportAuthorityClosed
}
func (s *Store) Prepare(lease string, outcome Outcome) (Manifest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.ready(); e != nil {
		return Manifest{}, e
	}
	r, e := s.record(lease)
	if e != nil {
		return Manifest{}, e
	}
	if r.State != "executing" {
		return Manifest{}, fail("artifact_transition_invalid")
	}
	for _, f := range r.Files {
		if f.State != "verified" {
			return Manifest{}, s.latch("artifact_export_incomplete")
		}
	}
	m := Manifest{1, s.data.StoreID, s.policySHA(), lease, r.JobID, r.InputSHA256, outcome.ObservedSHA256, outcome.EvaluatedSHA256, r.Files, outcome.ExecutionStatus, outcome.ReleaseStatus, outcome.ErrorCode}
	if !s.matchManifest(lease, r, m) {
		return Manifest{}, s.latch("artifact_evaluation_digest_mismatch")
	}
	b, _ := jsonBytes(m)
	if int64(len(b)) > manifestLimit {
		return Manifest{}, s.latch("artifact_manifest_oversized")
	}
	d, e := childDir(s.objects, lease, false)
	if e != nil {
		return Manifest{}, s.latch("artifact_export_failed")
	}
	defer d.Close()
	if e = s.publish(d, "manifest.json", b, false); e != nil {
		return Manifest{}, s.latch("artifact_export_failed")
	}
	r.State = "prepared"
	r.ManifestSHA256 = digest(b)
	s.data.Records[lease] = r
	if e = s.save(); e != nil {
		return Manifest{}, e
	}
	m.Files = cloneFiles(m.Files)
	return m, nil
}
func cloneFiles(files map[string]FileRecord) map[string]FileRecord {
	m := map[string]FileRecord{}
	for k, v := range files {
		m[k] = v
	}
	return m
}
func (s *Store) RecordQuiescence(lease string, p Proof) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.ready(); e != nil {
		return e
	}
	r, e := s.record(lease)
	if e != nil {
		return e
	}
	if r.State != "prepared" || r.ProofSHA256 != "" || !s.matchProof(lease, r, p) {
		return s.latch("artifact_quiescence_invalid")
	}
	b, _ := jsonBytes(p)
	if int64(len(b)) > proofLimit {
		return s.latch("artifact_proof_oversized")
	}
	d, e := childDir(s.objects, lease, false)
	if e != nil {
		return s.latch("artifact_export_failed")
	}
	defer d.Close()
	if e = s.publish(d, "proof.json", b, false); e != nil {
		return s.latch("artifact_export_failed")
	}
	r.ProofSHA256 = digest(b)
	s.data.Records[lease] = r
	return s.save()
}
func (s *Store) actualCharge(d *os.File, r Record) (int64, error) {
	total := int64(0)
	for _, f := range r.Files {
		total += f.Bytes
	}
	for _, name := range []string{"manifest.json", "proof.json"} {
		b, e := boundedRead(context.Background(), d, name, manifestLimit)
		if e != nil {
			return 0, e
		}
		total += int64(len(b))
	}
	// Twice the serialized record plus its map key covers both ledger copies.
	// Fixed store header reserve covers original/replacement headers.
	for i := 0; i < 8; i++ {
		b, _ := jsonBytes(r)
		next := total + 2*int64(len(b)) + 72
		if next == r.Charge {
			return next, nil
		}
		r.Charge = next
	}
	return 0, fail("artifact_charge_invalid")
}
func (s *Store) Commit(lease string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.ready(); e != nil {
		return e
	}
	r, e := s.record(lease)
	if e != nil {
		return e
	}
	if r.State != "prepared" || r.ProofSHA256 == "" {
		return fail("artifact_quiescence_required")
	}
	d, e := childDir(s.objects, lease, false)
	if e != nil {
		return s.latch("artifact_history_missing")
	}
	defer d.Close()
	if e = s.verifyRecord(context.Background(), d, lease, r); e != nil {
		return s.latch("artifact_history_invalid")
	}
	previous := r
	r.State = "committed"
	charge, e := s.actualCharge(d, r)
	if e != nil || charge > s.data.Policy.ExportBytes+s.data.Policy.PublicationHeadroom {
		return s.latch("artifact_charge_invalid")
	}
	r.Charge = charge
	s.data.Records[lease] = r
	if e = s.save(); e != nil {
		// Ambiguous publication must not release the in-memory reservation or
		// advertise a committed state. The sticky latch prevents further writes.
		s.data.Records[lease] = previous
		return e
	}
	return nil
}
func (s *Store) Acknowledge(lease string, callback func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.ready(); e != nil {
		return e
	}
	r, e := s.record(lease)
	if e != nil {
		return e
	}
	if r.State != "committed" {
		return fail("artifact_commit_required")
	}
	if s.point("ack") != nil {
		return s.latch("artifact_ack_failed")
	}
	if callback == nil {
		return fail("artifact_ack_invalid")
	}
	if callback() == nil {
		return nil
	}
	return s.latch("artifact_ack_failed")
}
