//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"unicode/utf8"

	artifact "biozero/artifact-executor"
	ownership "biozero/ownership-authority"
)

const ownerCustodyDomain = "biozero.owner-worker-custody.v1"
const ownerCustodyAcceptanceLimit int64 = 64 << 10
const ownerCustodyJournalLimit int64 = 1 << 20
const ownerCustodyRecordLimit = 64

// These are verifier-established facts, not evidence of execution or release.
// Processed facts are supplied only after authenticated decryption and staging.
type OwnerWorkerBinding struct {
	JobID            string                   `json:"job_id"`
	AcceptanceSHA256 string                   `json:"acceptance_sha256"`
	CredentialSHA256 string                   `json:"credential_sha256"`
	UploadSHA256     string                   `json:"upload_sha256"`
	EnvelopeSHA256   string                   `json:"envelope_sha256"`
	OriginalName     string                   `json:"original_name"`
	ProcessedSHA256  string                   `json:"processed_sha256"`
	ProcessedBytes   int64                    `json:"processed_bytes"`
	AnalysisContext  artifact.AnalysisContext `json:"analysis_context"`
	AcceptanceBytes  int64                    `json:"acceptance_bytes"`
}
type ownerCustodyJournal struct {
	SchemaVersion int                           `json:"schema_version"`
	Domain        string                        `json:"domain"`
	Trust         ownerWorkerTrust              `json:"trust"`
	Records       map[string]OwnerWorkerBinding `json:"records"`
}
type ownerCustodyMarker struct {
	SchemaVersion  int    `json:"schema_version"`
	Domain         string `json:"domain"`
	PreviousSHA256 string `json:"previous_sha256"`
	NextSHA256     string `json:"next_sha256"`
}

// Raw descriptors have no finalizers. Uncertain transactions keep the flock
// until process death, even if the caller drops the handle or calls Close.
// Bounds cover logical custody metadata; they are not a filesystem hard quota.
type OwnerWorkerCustody struct {
	mu                           sync.Mutex
	root                         string
	rootFD, lockFD, acceptanceFD int
	data                         ownerCustodyJournal
	journalSHA                   string
	journalStat                  syscall.Stat_t
	sidecarStats                 map[string]syscall.Stat_t
	sticky                       error
	closed                       bool
	fault                        func(string) error
}

func ownerCustodyError(code string) error { return ownerWorkerError("owner_worker_custody_" + code) }
func (c *OwnerWorkerCustody) latch(code string) error {
	if c.sticky == nil {
		c.sticky = ownerCustodyError(code)
	}
	return c.sticky
}
func (c *OwnerWorkerCustody) point(name string) error {
	if c.fault != nil {
		return c.fault(name)
	}
	return nil
}
func ownerCustodyContext(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return ownerCustodyError("cancelled")
	}
	return nil
}

// Only the final component is created. Existing parents are never adopted as
// custody roots and every component is opened with openat and O_NOFOLLOW.
func ownerCustodyRoot(ctx context.Context, path string, create bool) (int, error) {
	if ownerCustodyContext(ctx) != nil || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || len(path) > 4096 || !utf8.ValidString(path) || strings.ContainsAny(path, "\x00\r\n") {
		return -1, ownerCustodyError("config_invalid")
	}
	fd, e := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if e != nil {
		return -1, ownerCustodyError("root_unsafe")
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, p := range parts {
		if ownerCustodyContext(ctx) != nil {
			syscall.Close(fd)
			return -1, ownerCustodyError("cancelled")
		}
		if create && i == len(parts)-1 {
			if e = syscall.Mkdirat(fd, p, 0700); e != nil {
				syscall.Close(fd)
				return -1, ownerCustodyError("root_exists_or_unsafe")
			}
			if syscall.Fsync(fd) != nil {
				syscall.Close(fd)
				return -1, ownerCustodyError("persistence_failed")
			}
		}
		next, e := syscall.Openat(fd, p, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
		syscall.Close(fd)
		if e != nil {
			return -1, ownerCustodyError("root_unsafe")
		}
		fd = next
	}
	if !workerCustodySafeFD(fd, true) {
		syscall.Close(fd)
		return -1, ownerCustodyError("root_unsafe")
	}
	return fd, nil
}
func ownerCustodySame(a, b syscall.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid && a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}
func ownerCustodyIdentity(a, b int, dir bool) bool {
	var x, y syscall.Stat_t
	return workerCustodySafeFD(a, dir) && workerCustodySafeFD(b, dir) && syscall.Fstat(a, &x) == nil && syscall.Fstat(b, &y) == nil && x.Dev == y.Dev && x.Ino == y.Ino
}
func ownerCustodyEntries(fd, max int) ([]os.DirEntry, error) {
	n, e := syscall.Openat(fd, ".", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, ownerCustodyError("history_unsafe")
	}
	f := os.NewFile(uintptr(n), "owner-custody-directory")
	defer f.Close()
	v, e := f.ReadDir(max + 1)
	if e != nil && e != io.EOF {
		return nil, ownerCustodyError("history_unsafe")
	}
	if len(v) > max {
		return nil, ownerCustodyError("history_unaccounted")
	}
	return v, nil
}
func ownerCustodyRead(ctx context.Context, dir int, name string, limit int64) ([]byte, *os.File, error) {
	if ownerCustodyContext(ctx) != nil {
		return nil, nil, ownerCustodyError("cancelled")
	}
	fd, e := syscall.Openat(dir, name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, nil, ownerCustodyError("history_unsafe")
	}
	f := os.NewFile(uintptr(fd), "owner-custody-metadata")
	ok := false
	defer func() {
		if !ok {
			f.Close()
		}
	}()
	var a, b syscall.Stat_t
	if !workerCustodySafeFD(fd, false) || syscall.Fstat(fd, &a) != nil || a.Size < 1 || a.Size > limit {
		return nil, nil, ownerCustodyError("history_unsafe")
	}
	var buf bytes.Buffer
	block := make([]byte, 32<<10)
	for {
		if ownerCustodyContext(ctx) != nil {
			return nil, nil, ownerCustodyError("cancelled")
		}
		n, e := f.Read(block)
		buf.Write(block[:n])
		if int64(buf.Len()) > limit {
			return nil, nil, ownerCustodyError("history_oversized")
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, nil, ownerCustodyError("history_unreadable")
		}
	}
	if !workerCustodySafeFD(fd, false) || syscall.Fstat(fd, &b) != nil || !ownerCustodySame(a, b) || int64(buf.Len()) != a.Size {
		return nil, nil, ownerCustodyError("history_changed")
	}
	if _, e = f.Seek(0, io.SeekStart); e != nil {
		return nil, nil, ownerCustodyError("history_unreadable")
	}
	ok = true
	return buf.Bytes(), f, nil
}
func validateOwnerCustodyBinding(v OwnerWorkerBinding, raw []byte, trust ownerWorkerTrust) error {
	if !workerCustodyHex(v.JobID, 16) || !workerCustodyHex(v.AcceptanceSHA256, 64) || !workerCustodyHex(v.ProcessedSHA256, 64) || v.ProcessedBytes < 0 || v.ProcessedBytes > artifact.MaxInputBytes || v.AcceptanceBytes != int64(len(raw)) || len(raw) == 0 || int64(len(raw)) > ownerCustodyAcceptanceLimit || workerCustodyDigest(raw) != v.AcceptanceSHA256 {
		return ownerCustodyError("binding_invalid")
	}
	a, e := ownership.VerifyAcceptance(raw, trust.pin(), trust.Scope)
	if e != nil {
		return ownerCustodyError("acceptance_invalid")
	}
	canonical, e := ownerWorkerCanonical(raw, a)
	if e != nil || !bytes.Equal(raw, canonical) || a.SHA256() != v.AcceptanceSHA256 {
		return ownerCustodyError("acceptance_noncanonical")
	}
	b := a.Binding()
	c := v.AnalysisContext
	if b.JobID != v.JobID || b.CredentialSHA256 != v.CredentialSHA256 || b.CiphertextSHA256 != v.UploadSHA256 || b.KeyEnvelopeSHA256 != v.EnvelopeSHA256 || b.OriginalName != v.OriginalName || b.PipelineMode != trust.PipelineMode || b.ExecutionProfileSHA256 != trust.ProfileSHA256 || c.OriginalName != v.OriginalName || c.ProcessedSizeBytes != v.ProcessedBytes || !c.Decrypted || !c.SignatureValid || c.DecryptionError != "" || c.SignatureError != "" {
		return ownerCustodyError("binding_mismatch")
	}
	return nil
}
func CreateOwnerWorkerCustody(ctx context.Context, root string, trust ownerWorkerTrust) (*OwnerWorkerCustody, error) {
	return openOwnerWorkerCustody(ctx, root, trust, true, nil)
}
func OpenOwnerWorkerCustody(ctx context.Context, root string, trust ownerWorkerTrust) (*OwnerWorkerCustody, error) {
	return openOwnerWorkerCustody(ctx, root, trust, false, nil)
}
func openOwnerWorkerCustody(ctx context.Context, root string, trust ownerWorkerTrust, create bool, fault func(string) error) (*OwnerWorkerCustody, error) {
	if !trust.valid() || ownerCustodyContext(ctx) != nil {
		return nil, ownerCustodyError("config_invalid")
	}
	fd, e := ownerCustodyRoot(ctx, root, create)
	if e != nil {
		return nil, e
	}
	c := &OwnerWorkerCustody{root: root, rootFD: fd, lockFD: -1, acceptanceFD: -1, fault: fault, data: ownerCustodyJournal{1, ownerCustodyDomain, trust, map[string]OwnerWorkerBinding{}}}
	flags := syscall.O_RDWR | syscall.O_NOFOLLOW | syscall.O_NONBLOCK | syscall.O_CLOEXEC
	if create {
		flags |= syscall.O_CREAT | syscall.O_EXCL
	}
	lock, e := syscall.Openat(fd, "instance.lock", flags, 0600)
	if e != nil {
		syscall.Close(fd)
		return nil, ownerCustodyError("lock_unsafe")
	}
	var st syscall.Stat_t
	if !workerCustodySafeFD(lock, false) || syscall.Fstat(lock, &st) != nil || st.Size != 0 {
		syscall.Close(lock)
		syscall.Close(fd)
		return nil, ownerCustodyError("lock_unsafe")
	}
	if syscall.Flock(lock, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		syscall.Close(lock)
		syscall.Close(fd)
		return nil, ownerCustodyError("instance_locked")
	}
	c.lockFD = lock
	// Once authority is acquired, every ambiguous error returns a sticky handle.
	if create {
		if syscall.Fsync(lock) != nil || syscall.Mkdirat(fd, "acceptances", 0700) != nil || syscall.Fsync(fd) != nil {
			return c, c.latch("persistence_failed")
		}
	}
	c.acceptanceFD, e = syscall.Openat(fd, "acceptances", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if e != nil || !workerCustodySafeFD(c.acceptanceFD, true) {
		return c, c.latch("history_unsafe")
	}
	if create {
		if e = c.layout(false); e != nil {
			return c, e
		}
		if e = c.commit(ctx, c.data, nil, ""); e != nil {
			return c, e
		}
	} else {
		if e = c.layout(true); e != nil {
			return c, e
		}
		raw, f, e := ownerCustodyRead(ctx, fd, "journal.json", ownerCustodyJournalLimit)
		if e != nil {
			return c, c.latch("history_unsafe")
		}
		if syscall.Fstat(int(f.Fd()), &c.journalStat) != nil {
			f.Close()
			return c, c.latch("history_unsafe")
		}
		f.Close()
		var j ownerCustodyJournal
		if ownerWorkerDecode(raw, &j, ownerCustodyJournalLimit) != nil || j.SchemaVersion != 1 || j.Domain != ownerCustodyDomain || j.Trust != trust || j.Records == nil || len(j.Records) > ownerCustodyRecordLimit {
			return c, c.latch("history_invalid")
		}
		c.data = j
		c.journalSHA = workerCustodyDigest(raw)
	}
	if e = c.ready(ctx); e != nil {
		return c, e
	}
	return c, nil
}
func (c *OwnerWorkerCustody) layout(requireJournal bool) error {
	if !workerCustodySafeFD(c.rootFD, true) || !workerCustodySafeFD(c.acceptanceFD, true) || !workerCustodySafeFD(c.lockFD, false) {
		return c.latch("history_unsafe")
	}
	current, e := ownerCustodyRoot(context.Background(), c.root, false)
	if e != nil {
		return c.latch("root_changed")
	}
	same := ownerCustodyIdentity(current, c.rootFD, true)
	syscall.Close(current)
	if !same {
		return c.latch("root_changed")
	}
	for _, x := range []struct {
		name string
		fd   int
		dir  bool
	}{{"instance.lock", c.lockFD, false}, {"acceptances", c.acceptanceFD, true}} {
		flags := syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK | syscall.O_CLOEXEC
		if x.dir {
			flags |= syscall.O_DIRECTORY
		}
		n, e := syscall.Openat(c.rootFD, x.name, flags, 0)
		if e != nil {
			return c.latch("anchor_changed")
		}
		same := ownerCustodyIdentity(n, x.fd, x.dir)
		var st syscall.Stat_t
		valid := syscall.Fstat(n, &st) == nil && (x.dir || st.Size == 0)
		syscall.Close(n)
		if !same || !valid {
			return c.latch("anchor_changed")
		}
	}
	entries, e := ownerCustodyEntries(c.rootFD, 3)
	if e != nil {
		return c.latch("history_unaccounted")
	}
	seen := map[string]bool{}
	for _, v := range entries {
		switch v.Name() {
		case "instance.lock", "acceptances", "journal.json":
			seen[v.Name()] = true
		default:
			return c.latch("history_unaccounted")
		}
	}
	if !seen["instance.lock"] || !seen["acceptances"] || (requireJournal && !seen["journal.json"]) {
		return c.latch("history_missing")
	}
	return nil
}
func (c *OwnerWorkerCustody) ready(ctx context.Context) error {
	if ownerCustodyContext(ctx) != nil {
		return ownerCustodyError("cancelled")
	}
	if c.closed {
		return ownerCustodyError("closed")
	}
	if c.sticky != nil {
		return c.sticky
	}
	if e := c.layout(true); e != nil {
		return e
	}
	raw, f, e := ownerCustodyRead(ctx, c.rootFD, "journal.json", ownerCustodyJournalLimit)
	if e != nil {
		return c.latch("history_changed")
	}
	var journalStat syscall.Stat_t
	statErr := syscall.Fstat(int(f.Fd()), &journalStat)
	f.Close()
	if statErr != nil || !ownerCustodySame(c.journalStat, journalStat) || workerCustodyDigest(raw) != c.journalSHA {
		return c.latch("history_changed")
	}
	names, e := ownerCustodyEntries(c.acceptanceFD, ownerCustodyRecordLimit)
	if e != nil || len(names) != len(c.data.Records) {
		return c.latch("history_unaccounted")
	}
	wanted := map[string]OwnerWorkerBinding{}
	for job, b := range c.data.Records {
		if job != b.JobID {
			return c.latch("history_invalid")
		}
		name := b.AcceptanceSHA256 + ".json"
		if _, ok := wanted[name]; ok {
			return c.latch("history_invalid")
		}
		wanted[name] = b
	}
	if c.sidecarStats == nil {
		c.sidecarStats = map[string]syscall.Stat_t{}
	}
	for _, entry := range names {
		b, ok := wanted[entry.Name()]
		if !ok {
			return c.latch("history_unaccounted")
		}
		raw, f, e := ownerCustodyRead(ctx, c.acceptanceFD, entry.Name(), ownerCustodyAcceptanceLimit)
		if e != nil {
			return c.latch("history_unsafe")
		}
		var st syscall.Stat_t
		statErr := syscall.Fstat(int(f.Fd()), &st)
		f.Close()
		if statErr != nil {
			return c.latch("history_unsafe")
		}
		if old, ok := c.sidecarStats[entry.Name()]; ok && !ownerCustodySame(old, st) {
			return c.latch("history_changed")
		}
		c.sidecarStats[entry.Name()] = st
		if validateOwnerCustodyBinding(b, raw, c.data.Trust) != nil {
			return c.latch("history_invalid")
		}
	}
	return nil
}
func (c *OwnerWorkerCustody) write(dir int, name string, raw []byte, kind string) error {
	fd, e := syscall.Openat(dir, name, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0600)
	if e != nil {
		return c.latch("persistence_failed")
	}
	f := os.NewFile(uintptr(fd), "owner-custody-publication")
	defer f.Close()
	if !workerCustodySafeFD(fd, false) || c.point(kind+"_write") != nil {
		return c.latch("persistence_failed")
	}
	n, e := f.Write(raw)
	if e != nil || n != len(raw) || c.point(kind+"_file_sync") != nil || f.Sync() != nil {
		return c.latch("persistence_failed")
	}
	if c.point(kind+"_close") != nil || f.Close() != nil {
		return c.latch("persistence_failed")
	}
	return nil
}
func (c *OwnerWorkerCustody) sync(dir int, point string) error {
	if c.point(point) != nil || syscall.Fsync(dir) != nil {
		return c.latch("persistence_failed")
	}
	return nil
}
func (c *OwnerWorkerCustody) link(dir int, from, to string, point string) error {
	prefix := fmt.Sprintf("/proc/self/fd/%d/", dir)
	if c.point(point) != nil || os.Link(prefix+from, prefix+to) != nil {
		return c.latch("persistence_failed")
	}
	if c.sync(dir, point+"_directory_sync") != nil {
		return c.sticky
	}
	if syscall.Unlinkat(dir, from) != nil {
		return c.latch("persistence_failed")
	}
	return c.sync(dir, point+"_unlink_sync")
}

// A marker precedes all publication. No uncertain leftover is removed on Open.
func (c *OwnerWorkerCustody) commit(ctx context.Context, next ownerCustodyJournal, acceptance []byte, name string) error {
	raw, e := json.Marshal(next)
	if e != nil || int64(len(raw)) > ownerCustodyJournalLimit {
		return ownerCustodyError("budget_exceeded")
	}
	if ownerCustodyContext(ctx) != nil {
		return ownerCustodyError("cancelled")
	}
	marker, _ := json.Marshal(ownerCustodyMarker{1, ownerCustodyDomain, c.journalSHA, workerCustodyDigest(raw)})
	if e = c.write(c.rootFD, "transaction.pending", marker, "marker"); e != nil {
		return e
	}
	if e = c.sync(c.rootFD, "marker_directory_sync"); e != nil {
		return e
	}
	if acceptance != nil {
		if e = c.write(c.acceptanceFD, ".acceptance.next", acceptance, "acceptance"); e != nil {
			return e
		}
		if e = c.link(c.acceptanceFD, ".acceptance.next", name, "acceptance_link"); e != nil {
			return e
		}
	}
	if e = c.write(c.rootFD, ".journal.next", raw, "journal"); e != nil {
		return e
	}
	if c.journalSHA == "" {
		if e = c.link(c.rootFD, ".journal.next", "journal.json", "journal_link"); e != nil {
			return e
		}
	} else {
		if c.point("journal_rename") != nil || syscall.Renameat(c.rootFD, ".journal.next", c.rootFD, "journal.json") != nil {
			return c.latch("persistence_failed")
		}
		if e = c.sync(c.rootFD, "journal_directory_sync"); e != nil {
			return e
		}
	}
	if c.point("marker_unlink") != nil || syscall.Unlinkat(c.rootFD, "transaction.pending") != nil {
		return c.latch("persistence_failed")
	}
	if e = c.sync(c.rootFD, "marker_retirement_sync"); e != nil {
		return e
	}
	// Capture the exact published inode before acknowledging it. A failure
	// here remains uncertain; the old in-memory record set is not advanced.
	published, jf, err := ownerCustodyRead(ctx, c.rootFD, "journal.json", ownerCustodyJournalLimit)
	if err != nil {
		return c.latch("history_unsafe")
	}
	var journalStat syscall.Stat_t
	statErr := syscall.Fstat(int(jf.Fd()), &journalStat)
	jf.Close()
	if statErr != nil || !bytes.Equal(published, raw) {
		return c.latch("history_changed")
	}
	c.data = next
	c.journalSHA = workerCustodyDigest(raw)
	c.journalStat = journalStat
	if e := c.ready(ctx); e != nil {
		return e
	}
	if c.point("ack") != nil {
		return c.latch("delivery_failed")
	}
	return nil
}

// Callers retain their stage on any ambiguous error. Idempotence never grants
// permission to rerun execution; only the broker's existing status may do that.
func (c *OwnerWorkerCustody) PutVerified(ctx context.Context, v OwnerWorkerBinding, raw []byte) error {
	if c == nil || ownerCustodyContext(ctx) != nil {
		return ownerCustodyError("cancelled")
	}
	if len(raw) == 0 || int64(len(raw)) > ownerCustodyAcceptanceLimit {
		return ownerCustodyError("binding_invalid")
	}
	raw = append([]byte(nil), raw...)
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.ready(ctx); e != nil {
		return e
	}
	if e := validateOwnerCustodyBinding(v, raw, c.data.Trust); e != nil {
		return e
	}
	if old, ok := c.data.Records[v.JobID]; ok {
		if old != v {
			return ownerCustodyError("conflict")
		}
		return nil
	}
	if len(c.data.Records) >= ownerCustodyRecordLimit {
		return ownerCustodyError("budget_exceeded")
	}
	next := c.data
	next.Records = make(map[string]OwnerWorkerBinding, len(c.data.Records)+1)
	for k, b := range c.data.Records {
		next.Records[k] = b
	}
	next.Records[v.JobID] = v
	return c.commit(ctx, next, raw, v.AcceptanceSHA256+".json")
}
func (c *OwnerWorkerCustody) Lookup(job string) (OwnerWorkerBinding, bool, error) {
	if c == nil || !workerCustodyHex(job, 16) {
		return OwnerWorkerBinding{}, false, ownerCustodyError("job_invalid")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.ready(context.Background()); e != nil {
		return OwnerWorkerBinding{}, false, e
	}
	v, ok := c.data.Records[job]
	return v, ok, nil
}
func (c *OwnerWorkerCustody) Bindings() ([]OwnerWorkerBinding, error) {
	if c == nil {
		return nil, ownerCustodyError("unavailable")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.ready(context.Background()); e != nil {
		return nil, e
	}
	out := make([]OwnerWorkerBinding, 0, len(c.data.Records))
	for _, v := range c.data.Records {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].JobID < out[j].JobID })
	return out, nil
}
func (c *OwnerWorkerCustody) AcceptanceFile(ctx context.Context, job string) (*os.File, error) {
	if c == nil || !workerCustodyHex(job, 16) {
		return nil, ownerCustodyError("job_invalid")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.ready(ctx); e != nil {
		return nil, e
	}
	b, ok := c.data.Records[job]
	if !ok {
		return nil, ownerCustodyError("not_found")
	}
	raw, f, e := ownerCustodyRead(ctx, c.acceptanceFD, b.AcceptanceSHA256+".json", ownerCustodyAcceptanceLimit)
	if e != nil {
		return nil, c.latch("history_unsafe")
	}
	if e = validateOwnerCustodyBinding(b, raw, c.data.Trust); e != nil {
		f.Close()
		return nil, c.latch("history_invalid")
	}
	return f, nil
}
func (c *OwnerWorkerCustody) Acceptance(ctx context.Context, job string) ([]byte, error) {
	if c == nil || !workerCustodyHex(job, 16) {
		return nil, ownerCustodyError("job_invalid")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.ready(ctx); e != nil {
		return nil, e
	}
	b, ok := c.data.Records[job]
	if !ok {
		return nil, ownerCustodyError("not_found")
	}
	raw, f, e := ownerCustodyRead(ctx, c.acceptanceFD, b.AcceptanceSHA256+".json", ownerCustodyAcceptanceLimit)
	if e != nil {
		return nil, c.latch("history_unsafe")
	}
	f.Close()
	if validateOwnerCustodyBinding(b, raw, c.data.Trust) != nil {
		return nil, c.latch("history_invalid")
	}
	return raw, nil
}

func (c *OwnerWorkerCustody) Close() error {
	if c == nil {
		return ownerCustodyError("unavailable")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	if e := c.ready(context.Background()); e != nil {
		return e
	}
	// Retain the lock if an earlier descriptor close is uncertain.
	for _, fd := range []*int{&c.acceptanceFD, &c.rootFD, &c.lockFD} {
		if c.point("close") != nil || syscall.Close(*fd) != nil {
			return c.latch("close_failed")
		}
		*fd = -1
	}
	c.closed = true
	return nil
}
