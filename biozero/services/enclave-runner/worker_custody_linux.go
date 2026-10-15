//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"syscall"
	"unicode/utf8"

	artifact "biozero/artifact-executor"
)

const workerCustodyJournalLimit int64 = 1 << 20
const workerCustodyRecordLimit = 64

// WorkerCustodyBinding contains only verifier-established input facts. It is
// neither a Submit receipt nor evidence that execution or scientific approval
// occurred. JobFingerprint binds immutable metadata supplied by the caller.
type WorkerCustodyBinding struct {
	JobID           string                   `json:"job_id"`
	JobFingerprint  string                   `json:"job_fingerprint"`
	UploadSHA256    string                   `json:"upload_sha256"`
	ProcessedSHA256 string                   `json:"processed_sha256"`
	ProcessedBytes  int64                    `json:"processed_bytes"`
	AnalysisContext artifact.AnalysisContext `json:"analysis_context"`
}
type workerCustodyJournal struct {
	SchemaVersion int                             `json:"schema_version"`
	ProfileSHA256 string                          `json:"profile_sha256"`
	PipelineMode  string                          `json:"pipeline_mode"`
	Records       map[string]WorkerCustodyBinding `json:"records"`
}

// WorkerCustody owns raw lifetime directory/lock descriptors. They deliberately
// have no Go finalizer: losing a sticky handle cannot silently release authority.
// A healthy Close closes them; uncertain history retains them until process exit.
type WorkerCustody struct {
	mu             sync.Mutex
	rootFD, lockFD int
	data           workerCustodyJournal
	journalSHA     string
	sticky         error
	closed         bool
	fault          func(string) error // private deterministic fault injection, never config/RPC
}

func workerCustodyError(code string) error { return errors.New(code) }
func workerCustodyHex(value string, n int) bool {
	if len(value) != n {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'f' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}
func workerCustodyDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func validateWorkerCustodyBinding(v WorkerCustodyBinding) error {
	c := v.AnalysisContext
	if !workerCustodyHex(v.JobID, 16) || !workerCustodyHex(v.JobFingerprint, 64) || !workerCustodyHex(v.UploadSHA256, 64) || !workerCustodyHex(v.ProcessedSHA256, 64) || v.ProcessedBytes < 0 || v.ProcessedBytes > artifact.MaxInputBytes || c.ProcessedSizeBytes != v.ProcessedBytes || len(c.OriginalName) > 4096 || !utf8.ValidString(c.OriginalName) || len(c.DecryptionError) > 128 || !utf8.ValidString(c.DecryptionError) || len(c.SignatureError) > 128 || !utf8.ValidString(c.SignatureError) || (c.Decrypted && c.DecryptionError != "") || (c.SignatureValid && c.SignatureError != "") {
		return workerCustodyError("worker_custody_binding_invalid")
	}
	return nil
}
func (c *WorkerCustody) latch(code string) error {
	if c.sticky == nil {
		c.sticky = workerCustodyError(code)
	}
	return c.sticky
}
func (c *WorkerCustody) point(name string) error {
	if c.fault != nil {
		return c.fault(name)
	}
	return nil
}
func workerCustodySafeFD(fd int, directory bool) bool {
	var stat syscall.Stat_t
	if fd < 0 || syscall.Fstat(fd, &stat) != nil || stat.Uid != uint32(os.Geteuid()) {
		return false
	}
	if directory {
		return stat.Mode&syscall.S_IFMT == syscall.S_IFDIR && stat.Mode&07777 == 0700
	}
	return stat.Mode&syscall.S_IFMT == syscall.S_IFREG && stat.Mode&07777 == 0600 && stat.Nlink == 1
}
func workerCustodyOpenRoot(ctx context.Context, path string, fault func(string) error) (int, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || !utf8.ValidString(path) || strings.ContainsAny(path, "\x00\r\n") {
		return -1, workerCustodyError("worker_custody_root_invalid")
	}
	fd, e := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if e != nil {
		return -1, workerCustodyError("worker_custody_root_unsafe")
	}
	for _, component := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if e := ctx.Err(); e != nil {
			syscall.Close(fd)
			return -1, e
		}
		next, e := syscall.Openat(fd, component, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
		if e == syscall.ENOENT {
			if e = syscall.Mkdirat(fd, component, 0700); e != nil && e != syscall.EEXIST {
				syscall.Close(fd)
				return -1, workerCustodyError("worker_custody_root_unsafe")
			}
			next, e = syscall.Openat(fd, component, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
		}
		// Existing entries also need their parent synchronized: an earlier
		// failed creation sync must not become an accepted baseline on retry.
		if e == nil {
			var syncErr error
			if fault != nil {
				syncErr = fault("root_parent_sync:" + component)
			}
			if syncErr != nil || syscall.Fsync(fd) != nil {
				syscall.Close(next)
				syscall.Close(fd)
				return -1, workerCustodyError("worker_custody_persistence_failed")
			}
		}
		syscall.Close(fd)
		if e != nil {
			return -1, workerCustodyError("worker_custody_root_unsafe")
		}
		fd = next
	}
	if !workerCustodySafeFD(fd, true) {
		syscall.Close(fd)
		return -1, workerCustodyError("worker_custody_root_unsafe")
	}
	return fd, nil
}
func (c *WorkerCustody) entries() ([]os.DirEntry, error) {
	fd, e := syscall.Openat(c.rootFD, ".", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, workerCustodyError("worker_custody_history_invalid")
	}
	directory := os.NewFile(uintptr(fd), "worker-custody-list")
	defer directory.Close()
	entries, e := directory.ReadDir(3)
	if e != nil && e != io.EOF {
		return nil, workerCustodyError("worker_custody_history_invalid")
	}
	return entries, nil
}
func (c *WorkerCustody) layout() error {
	if !workerCustodySafeFD(c.rootFD, true) || !workerCustodySafeFD(c.lockFD, false) {
		return c.latch("worker_custody_history_unsafe")
	}
	entries, e := c.entries()
	if e != nil {
		return c.latch("worker_custody_history_invalid")
	}
	seenLock := false
	for _, entry := range entries {
		if entry.Name() == "instance.lock" {
			seenLock = true
		} else if entry.Name() != "journal.json" {
			return c.latch("worker_custody_history_unaccounted")
		}
	}
	if !seenLock || len(entries) > 2 {
		return c.latch("worker_custody_history_unaccounted")
	}
	fd, e := syscall.Openat(c.rootFD, "instance.lock", syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if e != nil {
		return c.latch("worker_custody_lock_unsafe")
	}
	defer syscall.Close(fd)
	var held, current syscall.Stat_t
	if !workerCustodySafeFD(fd, false) || syscall.Fstat(c.lockFD, &held) != nil || syscall.Fstat(fd, &current) != nil || held.Size != 0 || current.Size != 0 || held.Dev != current.Dev || held.Ino != current.Ino {
		return c.latch("worker_custody_lock_changed")
	}
	return nil
}
func (c *WorkerCustody) read(ctx context.Context) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, workerCustodyError("worker_custody_context_invalid")
	}
	fd, e := syscall.Openat(c.rootFD, "journal.json", syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if e == syscall.ENOENT {
		return nil, os.ErrNotExist
	}
	if e != nil {
		return nil, workerCustodyError("worker_custody_history_unsafe")
	}
	file := os.NewFile(uintptr(fd), "worker-custody-journal")
	defer file.Close()
	var before, after syscall.Stat_t
	if !workerCustodySafeFD(fd, false) || syscall.Fstat(fd, &before) != nil || before.Size < 1 || before.Size > workerCustodyJournalLimit {
		return nil, workerCustodyError("worker_custody_history_unsafe")
	}
	var out bytes.Buffer
	block := make([]byte, 32<<10)
	for {
		if ctx.Err() != nil {
			return nil, workerCustodyError("worker_custody_context_invalid")
		}
		n, e := file.Read(block)
		out.Write(block[:n])
		if int64(out.Len()) > workerCustodyJournalLimit {
			return nil, workerCustodyError("worker_custody_history_oversized")
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, workerCustodyError("worker_custody_history_unreadable")
		}
	}
	if !workerCustodySafeFD(fd, false) || syscall.Fstat(fd, &after) != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || int64(out.Len()) != after.Size {
		return nil, workerCustodyError("worker_custody_history_changed")
	}
	return out.Bytes(), nil
}

// NewWorkerCustody selects one exact profile/mode. Only a newly created lock in
// an otherwise empty root may initialize a journal. Existing lock without journal
// is ambiguous history. A non-nil error handle retains raw FD authority until exit.
func NewWorkerCustody(ctx context.Context, root, profile, mode string) (*WorkerCustody, error) {
	return newWorkerCustody(ctx, root, profile, mode, nil)
}
func newWorkerCustody(ctx context.Context, root, profile, mode string, fault func(string) error) (*WorkerCustody, error) {
	if ctx == nil || ctx.Err() != nil || !workerCustodyHex(profile, 64) || (mode != "stats" && mode != "variants") {
		return nil, workerCustodyError("worker_custody_config_invalid")
	}
	fd, e := workerCustodyOpenRoot(ctx, root, fault)
	if e != nil {
		return nil, e
	}
	c := &WorkerCustody{rootFD: fd, lockFD: -1, fault: fault, data: workerCustodyJournal{1, profile, mode, map[string]WorkerCustodyBinding{}}}
	preliminary, e := c.entries()
	if e != nil {
		syscall.Close(fd)
		return nil, e
	}
	hasLock := false
	for _, entry := range preliminary {
		if entry.Name() == "instance.lock" {
			hasLock = true
		}
	}
	if len(preliminary) > 0 && !hasLock {
		syscall.Close(fd)
		return nil, workerCustodyError("worker_custody_history_missing_lock")
	}
	lock, e := syscall.Openat(fd, "instance.lock", syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0600)
	created := e == nil
	if e == syscall.EEXIST {
		lock, e = syscall.Openat(fd, "instance.lock", syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	}
	if e != nil {
		syscall.Close(fd)
		return nil, workerCustodyError("worker_custody_lock_unsafe")
	}
	c.lockFD = lock
	var st syscall.Stat_t
	if !workerCustodySafeFD(lock, false) || syscall.Fstat(lock, &st) != nil || st.Size != 0 {
		syscall.Close(lock)
		syscall.Close(fd)
		return nil, workerCustodyError("worker_custody_lock_unsafe")
	}
	if syscall.Flock(lock, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		syscall.Close(lock)
		syscall.Close(fd)
		return nil, workerCustodyError("worker_custody_instance_locked")
	}
	if syscall.Fsync(fd) != nil {
		return c, c.latch("worker_custody_persistence_failed")
	}
	if e = c.layout(); e != nil {
		return c, e
	}
	raw, e := c.read(ctx)
	if errors.Is(e, os.ErrNotExist) {
		if !created {
			return c, c.latch("worker_custody_history_missing")
		}
		if e = c.save(ctx, c.data); e != nil {
			return c, e
		}
	} else {
		if e != nil {
			return c, c.latch("worker_custody_history_invalid")
		}
		var history workerCustodyJournal
		if workerCustodyStrictJSON(raw, &history) != nil || history.SchemaVersion != 1 || history.ProfileSHA256 != profile || history.PipelineMode != mode || history.Records == nil || len(history.Records) > workerCustodyRecordLimit {
			return c, c.latch("worker_custody_history_invalid")
		}
		for job, binding := range history.Records {
			if job != binding.JobID || validateWorkerCustodyBinding(binding) != nil {
				return c, c.latch("worker_custody_history_invalid")
			}
		}
		c.data = history
		c.journalSHA = workerCustodyDigest(raw)
	}
	return c, nil
}
func (c *WorkerCustody) ready(ctx context.Context) error {
	if c.closed {
		return workerCustodyError("worker_custody_closed")
	}
	if c.sticky != nil {
		return c.sticky
	}
	if e := c.layout(); e != nil {
		return e
	}
	raw, e := c.read(ctx)
	if e != nil || workerCustodyDigest(raw) != c.journalSHA {
		return c.latch("worker_custody_history_changed")
	}
	return nil
}
func (c *WorkerCustody) save(ctx context.Context, next workerCustodyJournal) error {
	raw, e := json.Marshal(next)
	if e != nil || int64(len(raw)) > workerCustodyJournalLimit {
		return workerCustodyError("worker_custody_budget_exceeded")
	}
	if ctx.Err() != nil {
		return workerCustodyError("worker_custody_context_invalid")
	}
	if c.closed || c.sticky != nil {
		return workerCustodyError("worker_custody_unavailable")
	}
	if e = c.layout(); e != nil {
		return e
	}
	if c.journalSHA != "" {
		old, e := c.read(ctx)
		if e != nil || workerCustodyDigest(old) != c.journalSHA {
			return c.latch("worker_custody_history_changed")
		}
	}
	var nonce [16]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return c.latch("worker_custody_persistence_failed")
	}
	name := ".tmp-" + hex.EncodeToString(nonce[:])
	fd, e := syscall.Openat(c.rootFD, name, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0600)
	if e != nil {
		return c.latch("worker_custody_persistence_failed")
	}
	file := os.NewFile(uintptr(fd), "worker-custody-replacement")
	defer file.Close()
	if !workerCustodySafeFD(fd, false) || c.point("journal_write") != nil {
		return c.latch("worker_custody_persistence_failed")
	}
	n, e := file.Write(raw)
	if e != nil || n != len(raw) || c.point("journal_file_sync") != nil || file.Sync() != nil {
		return c.latch("worker_custody_persistence_failed")
	}
	if file.Close() != nil {
		return c.latch("worker_custody_persistence_failed")
	}
	if c.journalSHA == "" {
		prefix := fmt.Sprintf("/proc/self/fd/%d/", c.rootFD)
		if c.point("journal_link") != nil || os.Link(prefix+name, prefix+"journal.json") != nil || c.point("journal_unlink") != nil || syscall.Unlinkat(c.rootFD, name) != nil {
			return c.latch("worker_custody_persistence_failed")
		}
	} else if c.point("journal_rename") != nil || syscall.Renameat(c.rootFD, name, c.rootFD, "journal.json") != nil {
		return c.latch("worker_custody_persistence_failed")
	}
	if c.point("journal_directory_sync") != nil || syscall.Fsync(c.rootFD) != nil {
		return c.latch("worker_custody_persistence_failed")
	}
	c.data = next
	c.journalSHA = workerCustodyDigest(raw)
	return nil
}

// PutVerified must succeed before the caller attempts Submit. Identical bindings
// are idempotent; any changed fact conflicts. No error frees records or grants
// permission to reexecute. Published facts do not prove that Submit was attempted.
func (c *WorkerCustody) PutVerified(ctx context.Context, binding WorkerCustodyBinding) error {
	if c == nil || ctx == nil || ctx.Err() != nil {
		return workerCustodyError("worker_custody_context_invalid")
	}
	if e := validateWorkerCustodyBinding(binding); e != nil {
		return e
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.ready(ctx); e != nil {
		return e
	}
	if existing, ok := c.data.Records[binding.JobID]; ok {
		if existing != binding {
			return workerCustodyError("worker_custody_conflict")
		}
		return nil
	}
	if len(c.data.Records) >= workerCustodyRecordLimit {
		return workerCustodyError("worker_custody_budget_exceeded")
	}
	next := workerCustodyJournal{c.data.SchemaVersion, c.data.ProfileSHA256, c.data.PipelineMode, make(map[string]WorkerCustodyBinding, len(c.data.Records)+1)}
	for job, record := range c.data.Records {
		next.Records[job] = record
	}
	next.Records[binding.JobID] = binding
	return c.save(ctx, next)
}

// Lookup returns a value copy only after checking live journal integrity/metadata.
// No binding means no authority to resubmit a running job. Callers compare the
// immutable job fingerprint and query broker status/receipt rather than rerun.
func (c *WorkerCustody) Lookup(jobID string) (WorkerCustodyBinding, bool, error) {
	if c == nil || !workerCustodyHex(jobID, 16) {
		return WorkerCustodyBinding{}, false, workerCustodyError("worker_custody_job_invalid")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.ready(context.Background()); e != nil {
		return WorkerCustodyBinding{}, false, e
	}
	binding, ok := c.data.Records[jobID]
	return binding, ok, nil
}

// Bindings returns sorted value copies after the same live integrity checks as
// Lookup. A caller may query their broker states, but cannot remove retained
// journal records or infer that an unavailable RPC means the job was never sent.
func (c *WorkerCustody) Bindings() ([]WorkerCustodyBinding, error) {
	if c == nil {
		return nil, workerCustodyError("worker_custody_unavailable")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.ready(context.Background()); e != nil {
		return nil, e
	}
	result := make([]WorkerCustodyBinding, 0, len(c.data.Records))
	for _, binding := range c.data.Records {
		result = append(result, binding)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].JobID < result[j].JobID })
	return result, nil
}
func (c *WorkerCustody) Close() error {
	if c == nil {
		return workerCustodyError("worker_custody_unavailable")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	if e := c.ready(context.Background()); e != nil {
		return e
	}
	if syscall.Close(c.lockFD) != nil {
		return c.latch("worker_custody_close_failed")
	}
	c.lockFD = -1
	if syscall.Close(c.rootFD) != nil {
		return c.latch("worker_custody_close_failed")
	}
	c.rootFD = -1
	c.closed = true
	return nil
}

// This parser is private to the exact custody schema. Existing metadata parsing,
// job/result contracts and the SDK's strict JSON parser are not widened.
func workerCustodyStrictJSON(raw []byte, out *workerCustodyJournal) error {
	if !utf8.Valid(raw) {
		return workerCustodyError("worker_custody_json_invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, e := workerCustodyScanJSON(decoder, 0)
	if e != nil {
		return e
	}
	if _, e = decoder.Token(); e != io.EOF || !workerCustodyTypedJSON(value, reflect.TypeOf(*out)) || json.Unmarshal(raw, out) != nil {
		return workerCustodyError("worker_custody_json_invalid")
	}
	return nil
}
func workerCustodyScanJSON(d *json.Decoder, depth int) (any, error) {
	if depth > 32 {
		return nil, workerCustodyError("worker_custody_json_invalid")
	}
	token, e := d.Token()
	if e != nil {
		return nil, workerCustodyError("worker_custody_json_invalid")
	}
	switch token {
	case json.Delim('{'):
		object := map[string]any{}
		for d.More() {
			key, e := d.Token()
			if e != nil {
				return nil, workerCustodyError("worker_custody_json_invalid")
			}
			name, ok := key.(string)
			if !ok {
				return nil, workerCustodyError("worker_custody_json_invalid")
			}
			if _, duplicate := object[name]; duplicate {
				return nil, workerCustodyError("worker_custody_json_invalid")
			}
			value, e := workerCustodyScanJSON(d, depth+1)
			if e != nil {
				return nil, e
			}
			object[name] = value
		}
		if _, e = d.Token(); e != nil {
			return nil, workerCustodyError("worker_custody_json_invalid")
		}
		return object, nil
	case json.Delim('['):
		array := []any{}
		for d.More() {
			value, e := workerCustodyScanJSON(d, depth+1)
			if e != nil {
				return nil, e
			}
			array = append(array, value)
		}
		if _, e = d.Token(); e != nil {
			return nil, workerCustodyError("worker_custody_json_invalid")
		}
		return array, nil
	default:
		return token, nil
	}
}
func workerCustodyTypedJSON(value any, typ reflect.Type) bool {
	if value == nil {
		return false
	}
	switch typ.Kind() {
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok || len(object) != typ.NumField() {
			return false
		}
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			v, found := object[field.Tag.Get("json")]
			if !found || !workerCustodyTypedJSON(v, field.Type) {
				return false
			}
		}
		return true
	case reflect.Map:
		object, ok := value.(map[string]any)
		if !ok {
			return false
		}
		for _, v := range object {
			if !workerCustodyTypedJSON(v, typ.Elem()) {
				return false
			}
		}
		return true
	case reflect.String:
		_, ok := value.(string)
		return ok
	case reflect.Bool:
		_, ok := value.(bool)
		return ok
	case reflect.Int, reflect.Int64:
		_, ok := value.(json.Number)
		return ok
	default:
		return false
	}
}
