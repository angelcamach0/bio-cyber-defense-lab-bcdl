//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"

	artifact "biozero/artifact-executor"
)

func workerCustodyTestBinding(i int) WorkerCustodyBinding {
	return WorkerCustodyBinding{JobID: fmt.Sprintf("%016x", i), JobFingerprint: strings.Repeat("b", 64), UploadSHA256: strings.Repeat("c", 64), ProcessedSHA256: strings.Repeat("d", 64), ProcessedBytes: 23, AnalysisContext: artifact.AnalysisContext{OriginalName: "synthetic.fastq", ProcessedSizeBytes: 23, Decrypted: true, SignatureValid: true}}
}
func workerCustodyTestOpen(t *testing.T) (*WorkerCustody, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "custody")
	c, e := NewWorkerCustody(context.Background(), root, strings.Repeat("a", 64), "variants")
	if e != nil {
		t.Fatal(e)
	}
	workerCustodyTestOwn(t, c)
	return c, root
}
func workerCustodyTestOwn(t *testing.T, c *WorkerCustody) {
	t.Helper()
	if c == nil {
		return
	}
	t.Cleanup(func() {
		// Synthetic metadata fixtures only: raw close explicitly simulates process
		// exit. Production Close deliberately cannot release sticky uncertain custody.
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.lockFD >= 0 {
			syscall.Close(c.lockFD)
			c.lockFD = -1
		}
		if c.rootFD >= 0 {
			syscall.Close(c.rootFD)
			c.rootFD = -1
		}
	})
}
func workerCustodyTestRead(t *testing.T, path string) []byte {
	t.Helper()
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func workerCustodyTestWrite(t *testing.T, path string, raw []byte) {
	t.Helper()
	if e := os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
}

func TestWorkerCustodyDurableFactsIdempotenceAndCopies(t *testing.T) {
	c, root := workerCustodyTestOpen(t)
	ctx := context.Background()
	first := workerCustodyTestBinding(2)
	second := workerCustodyTestBinding(1)
	if e := c.PutVerified(ctx, first); e != nil {
		t.Fatal(e)
	}
	if e := c.PutVerified(ctx, second); e != nil {
		t.Fatal(e)
	}
	original := workerCustodyTestRead(t, filepath.Join(root, "journal.json"))
	if e := c.PutVerified(ctx, first); e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(original, workerCustodyTestRead(t, filepath.Join(root, "journal.json"))) {
		t.Fatal("idempotent Put changed history")
	}
	first.AnalysisContext.OriginalName = "caller-local-change"
	got, ok, e := c.Lookup(first.JobID)
	if e != nil || !ok || got.AnalysisContext.OriginalName != "synthetic.fastq" {
		t.Fatal("caller aliased facts", e)
	}
	got.AnalysisContext.OriginalName = "lookup-local-change"
	all, e := c.Bindings()
	if e != nil || len(all) != 2 || all[0].JobID != second.JobID || all[1].JobID != first.JobID || all[1].AnalysisContext.OriginalName != "synthetic.fastq" {
		t.Fatal("snapshot unordered or aliased", e)
	}
	all[0].AnalysisContext.OriginalName = "snapshot-local-change"
	if got, ok, e = c.Lookup(second.JobID); e != nil || !ok || got.AnalysisContext.OriginalName != "synthetic.fastq" {
		t.Fatal("snapshot aliased registry", e)
	}
	if _, ok, e = c.Lookup(workerCustodyTestBinding(9).JobID); e != nil || ok {
		t.Fatal("unknown job fabricated facts", e)
	}
	if e = c.Close(); e != nil {
		t.Fatal(e)
	}
	if e = c.Close(); e != nil {
		t.Fatal("healthy Close not idempotent", e)
	}
	reopened, e := NewWorkerCustody(ctx, root, strings.Repeat("a", 64), "variants")
	workerCustodyTestOwn(t, reopened)
	if e != nil {
		t.Fatal(e)
	}
	rows, e := reopened.Bindings()
	if e != nil || len(rows) != 2 || rows[0] != second || rows[1] != workerCustodyTestBinding(2) {
		t.Fatal("restart lost exact context", e)
	}
	if !bytes.Equal(original, workerCustodyTestRead(t, filepath.Join(root, "journal.json"))) {
		t.Fatal("restart rewrote or adopted history")
	}
}

func TestWorkerCustodyConflictsAndInvalidFactsNeverConsume(t *testing.T) {
	c, root := workerCustodyTestOpen(t)
	ctx := context.Background()
	v := workerCustodyTestBinding(1)
	if e := c.PutVerified(ctx, v); e != nil {
		t.Fatal(e)
	}
	original := workerCustodyTestRead(t, filepath.Join(root, "journal.json"))
	conflicts := map[string]func(*WorkerCustodyBinding){"metadata": func(v *WorkerCustodyBinding) { v.JobFingerprint = strings.Repeat("e", 64) }, "upload": func(v *WorkerCustodyBinding) { v.UploadSHA256 = strings.Repeat("e", 64) }, "processed": func(v *WorkerCustodyBinding) { v.ProcessedSHA256 = strings.Repeat("e", 64) }, "bytes": func(v *WorkerCustodyBinding) { v.ProcessedBytes++; v.AnalysisContext.ProcessedSizeBytes++ }, "name": func(v *WorkerCustodyBinding) { v.AnalysisContext.OriginalName = "other.fastq" }, "decrypted": func(v *WorkerCustodyBinding) { v.AnalysisContext.Decrypted = false }, "signature": func(v *WorkerCustodyBinding) { v.AnalysisContext.SignatureValid = false }, "decrypt_error": func(v *WorkerCustodyBinding) {
		v.AnalysisContext.Decrypted = false
		v.AnalysisContext.DecryptionError = "synthetic_failed"
	}, "signature_error": func(v *WorkerCustodyBinding) {
		v.AnalysisContext.SignatureValid = false
		v.AnalysisContext.SignatureError = "synthetic_failed"
	}}
	for name, mutate := range conflicts {
		t.Run(name, func(t *testing.T) {
			changed := v
			mutate(&changed)
			if e := c.PutVerified(ctx, changed); e == nil || e.Error() != "worker_custody_conflict" {
				t.Fatal("changed binding not conflicted", e)
			}
		})
	}
	invalid := map[string]func(*WorkerCustodyBinding){"job": func(v *WorkerCustodyBinding) { v.JobID = "../bad" }, "fingerprint": func(v *WorkerCustodyBinding) { v.JobFingerprint = "" }, "upload": func(v *WorkerCustodyBinding) { v.UploadSHA256 = strings.Repeat("G", 64) }, "negative_size": func(v *WorkerCustodyBinding) { v.ProcessedBytes = -1; v.AnalysisContext.ProcessedSizeBytes = -1 }, "over_size": func(v *WorkerCustodyBinding) {
		v.ProcessedBytes = artifact.MaxInputBytes + 1
		v.AnalysisContext.ProcessedSizeBytes = v.ProcessedBytes
	}, "mismatch_size": func(v *WorkerCustodyBinding) { v.AnalysisContext.ProcessedSizeBytes++ }, "name_limit": func(v *WorkerCustodyBinding) { v.AnalysisContext.OriginalName = strings.Repeat("x", 4097) }, "name_utf8": func(v *WorkerCustodyBinding) { v.AnalysisContext.OriginalName = string([]byte{0xff}) }, "error_limit": func(v *WorkerCustodyBinding) { v.AnalysisContext.SignatureError = strings.Repeat("x", 129) }, "error_utf8": func(v *WorkerCustodyBinding) { v.AnalysisContext.DecryptionError = string([]byte{0xff}) }, "decrypt_contradiction": func(v *WorkerCustodyBinding) { v.AnalysisContext.DecryptionError = "failed" }, "signature_contradiction": func(v *WorkerCustodyBinding) { v.AnalysisContext.SignatureError = "failed" }}
	for name, mutate := range invalid {
		t.Run("invalid_"+name, func(t *testing.T) {
			changed := workerCustodyTestBinding(2)
			mutate(&changed)
			if e := c.PutVerified(ctx, changed); e == nil || e.Error() != "worker_custody_binding_invalid" {
				t.Fatal("invalid binding accepted", e)
			}
		})
	}
	if !bytes.Equal(original, workerCustodyTestRead(t, filepath.Join(root, "journal.json"))) {
		t.Fatal("conflict/invalid changed journal")
	}
	if e := c.PutVerified(ctx, workerCustodyTestBinding(2)); e != nil {
		t.Fatal("nonsticky rejected input poisoned custody", e)
	}
	rows, e := c.Bindings()
	if e != nil || len(rows) != 2 {
		t.Fatal("invalid facts consumed slots", e)
	}
}

func TestWorkerCustodyRetainedRecordAndSerializedByteCaps(t *testing.T) {
	t.Run("retained64", func(t *testing.T) {
		c, root := workerCustodyTestOpen(t)
		for i := 1; i <= 64; i++ {
			if e := c.PutVerified(context.Background(), workerCustodyTestBinding(i)); e != nil {
				t.Fatal(i, e)
			}
		}
		before := workerCustodyTestRead(t, filepath.Join(root, "journal.json"))
		if e := c.PutVerified(context.Background(), workerCustodyTestBinding(65)); e == nil || e.Error() != "worker_custody_budget_exceeded" {
			t.Fatal("retained cap bypassed", e)
		}
		if e := c.PutVerified(context.Background(), workerCustodyTestBinding(1)); e != nil {
			t.Fatal("cap lost idempotency", e)
		}
		rows, e := c.Bindings()
		if e != nil || len(rows) != 64 || !bytes.Equal(before, workerCustodyTestRead(t, filepath.Join(root, "journal.json"))) {
			t.Fatal("cap evicted/reset history", e)
		}
	})
	t.Run("serialized1MiB", func(t *testing.T) {
		c, root := workerCustodyTestOpen(t)
		count := 0
		for i := 1; i <= 64; i++ {
			v := workerCustodyTestBinding(i)
			v.AnalysisContext.OriginalName = strings.Repeat("\x01", 4096)
			before := workerCustodyTestRead(t, filepath.Join(root, "journal.json"))
			e := c.PutVerified(context.Background(), v)
			if e != nil {
				if e.Error() != "worker_custody_budget_exceeded" || count == 0 || count >= 64 {
					t.Fatal("wrong byte cap", count, e)
				}
				if !bytes.Equal(before, workerCustodyTestRead(t, filepath.Join(root, "journal.json"))) {
					t.Fatal("oversize candidate changed publication")
				}
				break
			}
			count++
		}
		if count >= 64 {
			t.Fatal("escaped metadata bypassed actual byte limit")
		}
		rows, e := c.Bindings()
		if e != nil || len(rows) != count {
			t.Fatal("byte cap reset slots", e)
		}
		entries, e := os.ReadDir(root)
		if e != nil || len(entries) != 2 {
			t.Fatal("oversize created temp/replacement", e)
		}
	})
}

func TestWorkerCustodyRejectsUnsafeOrUnknownHistory(t *testing.T) {
	for _, kind := range []string{"unknown", "temp", "missing_journal", "missing_lock", "journal_mode", "journal_hardlink", "journal_symlink", "journal_fifo", "root_mode", "root_symlink", "changed_lock"} {
		t.Run(kind, func(t *testing.T) {
			c, root := workerCustodyTestOpen(t)
			if e := c.PutVerified(context.Background(), workerCustodyTestBinding(1)); e != nil {
				t.Fatal(e)
			}
			if e := c.Close(); e != nil {
				t.Fatal(e)
			}
			journal := filepath.Join(root, "journal.json")
			switch kind {
			case "unknown":
				workerCustodyTestWrite(t, filepath.Join(root, "extra"), []byte("private synthetic remnant"))
			case "temp":
				workerCustodyTestWrite(t, filepath.Join(root, ".tmp-interrupted"), []byte("private synthetic remnant"))
			case "missing_journal":
				if e := os.Remove(journal); e != nil {
					t.Fatal(e)
				}
			case "missing_lock":
				if e := os.Remove(filepath.Join(root, "instance.lock")); e != nil {
					t.Fatal(e)
				}
			case "journal_mode":
				if e := os.Chmod(journal, 0640); e != nil {
					t.Fatal(e)
				}
			case "journal_hardlink":
				if e := os.Link(journal, filepath.Join(t.TempDir(), "link")); e != nil {
					t.Fatal(e)
				}
			case "journal_symlink":
				raw := workerCustodyTestRead(t, journal)
				other := filepath.Join(t.TempDir(), "other.json")
				workerCustodyTestWrite(t, other, raw)
				if e := os.Remove(journal); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink(other, journal); e != nil {
					t.Fatal(e)
				}
			case "journal_fifo":
				if e := os.Remove(journal); e != nil {
					t.Fatal(e)
				}
				if e := syscall.Mkfifo(journal, 0600); e != nil {
					t.Fatal(e)
				}
			case "root_mode":
				if e := os.Chmod(root, 0750); e != nil {
					t.Fatal(e)
				}
			case "root_symlink":
				alias := filepath.Join(t.TempDir(), "root")
				if e := os.Symlink(root, alias); e != nil {
					t.Fatal(e)
				}
				root = alias
			case "changed_lock":
				if e := os.WriteFile(filepath.Join(root, "instance.lock"), []byte("not empty"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			reopen, e := NewWorkerCustody(context.Background(), root, strings.Repeat("a", 64), "variants")
			workerCustodyTestOwn(t, reopen)
			if e == nil {
				t.Fatal("unsafe history accepted")
			}
			if reopen != nil {
				if e := reopen.Close(); e == nil {
					t.Fatal("sticky history released lock")
				}
			}
			if kind == "missing_journal" {
				if _, e := os.Lstat(journal); !errors.Is(e, os.ErrNotExist) {
					t.Fatal("missing history initialized")
				}
			}
		})
	}
}

func TestWorkerCustodyExactSchemaAndHeaderMismatch(t *testing.T) {
	for _, kind := range []string{"profile", "mode", "version", "missing_field", "unknown_field", "null_records", "null_context", "missing_context_field", "case_alias", "duplicate_context_field", "record_key", "oversized", "invalid_utf8"} {
		t.Run(kind, func(t *testing.T) {
			c, root := workerCustodyTestOpen(t)
			if e := c.PutVerified(context.Background(), workerCustodyTestBinding(1)); e != nil {
				t.Fatal(e)
			}
			if e := c.Close(); e != nil {
				t.Fatal(e)
			}
			path := filepath.Join(root, "journal.json")
			raw := workerCustodyTestRead(t, path)
			var object map[string]any
			if json.Unmarshal(raw, &object) != nil {
				t.Fatal("fixture")
			}
			records := object["records"].(map[string]any)
			record := records[workerCustodyTestBinding(1).JobID].(map[string]any)
			facts := record["analysis_context"].(map[string]any)
			switch kind {
			case "profile":
				object["profile_sha256"] = strings.Repeat("e", 64)
			case "mode":
				object["pipeline_mode"] = "stats"
			case "version":
				object["schema_version"] = 2
			case "missing_field":
				delete(record, "job_fingerprint")
			case "unknown_field":
				record["path"] = "/private/not-authority"
			case "null_records":
				object["records"] = nil
			case "null_context":
				record["analysis_context"] = nil
			case "missing_context_field":
				delete(facts, "decrypted")
			case "case_alias":
				record["Job_Fingerprint"] = record["job_fingerprint"]
				delete(record, "job_fingerprint")
			case "record_key":
				records[workerCustodyTestBinding(2).JobID] = record
				delete(records, workerCustodyTestBinding(1).JobID)
			}
			raw, _ = json.Marshal(object)
			if kind == "duplicate_context_field" {
				raw = bytes.Replace(raw, []byte(`"decrypted":true`), []byte(`"decrypted":true,"decrypted":true`), 1)
			}
			if kind == "oversized" {
				raw = bytes.Repeat([]byte(" "), int(workerCustodyJournalLimit)+1)
			}
			if kind == "invalid_utf8" {
				raw = []byte{0xff}
			}
			workerCustodyTestWrite(t, path, raw)
			reopen, e := NewWorkerCustody(context.Background(), root, strings.Repeat("a", 64), "variants")
			workerCustodyTestOwn(t, reopen)
			if e == nil {
				t.Fatal("mismatched schema/header accepted")
			}
			if !bytes.Equal(raw, workerCustodyTestRead(t, path)) {
				t.Fatal("rejected history was reset/rewritten")
			}
		})
	}
}

func TestWorkerCustodyPublicationFailuresRetainLockAndFacts(t *testing.T) {
	for _, point := range []string{"journal_write", "journal_file_sync", "journal_rename", "journal_directory_sync"} {
		t.Run(point, func(t *testing.T) {
			c, root := workerCustodyTestOpen(t)
			if e := c.PutVerified(context.Background(), workerCustodyTestBinding(1)); e != nil {
				t.Fatal(e)
			}
			before := workerCustodyTestRead(t, filepath.Join(root, "journal.json"))
			c.fault = func(name string) error {
				if name == point {
					return errors.New("synthetic persistence fault")
				}
				return nil
			}
			if e := c.PutVerified(context.Background(), workerCustodyTestBinding(2)); e == nil {
				t.Fatal("publication fault ignored")
			}
			if _, _, e := c.Lookup(workerCustodyTestBinding(1).JobID); e == nil {
				t.Fatal("sticky failure allowed Lookup")
			}
			if _, e := c.Bindings(); e == nil {
				t.Fatal("sticky failure allowed snapshot")
			}
			if e := c.Close(); e == nil {
				t.Fatal("sticky Close released custody")
			}
			other, e := NewWorkerCustody(context.Background(), root, strings.Repeat("a", 64), "variants")
			workerCustodyTestOwn(t, other)
			if e == nil || e.Error() != "worker_custody_instance_locked" {
				t.Fatal("sticky lifetime lock released", e)
			}
			if point != "journal_directory_sync" && !bytes.Equal(before, workerCustodyTestRead(t, filepath.Join(root, "journal.json"))) {
				t.Fatal("prepublication failure replaced original facts")
			}
			// Explicit fake process exit, followed by a new process's read-only facts.
			syscall.Close(c.lockFD)
			c.lockFD = -1
			syscall.Close(c.rootFD)
			c.rootFD = -1
			reopened, e := NewWorkerCustody(context.Background(), root, strings.Repeat("a", 64), "variants")
			workerCustodyTestOwn(t, reopened)
			if point == "journal_directory_sync" {
				if e != nil {
					t.Fatal("complete exact published facts unreadable", e)
				}
				rows, e := reopened.Bindings()
				if e != nil || len(rows) != 2 {
					t.Fatal("published facts not preserved", e)
				}
			} else {
				if e == nil {
					t.Fatal("interrupted temporary history adopted")
				}
			}
		})
	}
}

func TestWorkerCustodyBootstrapGapsAndNoGCUnlock(t *testing.T) {
	t.Run("lock_without_journal", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "custody")
		if e := os.Mkdir(root, 0700); e != nil {
			t.Fatal(e)
		}
		workerCustodyTestWrite(t, filepath.Join(root, "instance.lock"), nil)
		c, e := NewWorkerCustody(context.Background(), root, strings.Repeat("a", 64), "variants")
		workerCustodyTestOwn(t, c)
		if e == nil || c == nil {
			t.Fatal("ambiguous bootstrap adopted", e)
		}
		if _, e = os.Lstat(filepath.Join(root, "journal.json")); !errors.Is(e, os.ErrNotExist) {
			t.Fatal("unknown baseline initialized")
		}
	})
	for _, point := range []string{"journal_write", "journal_file_sync", "journal_link", "journal_unlink"} {
		t.Run(point, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "custody")
			c, e := newWorkerCustody(context.Background(), root, strings.Repeat("a", 64), "variants", func(name string) error {
				if name == point {
					return errors.New("synthetic bootstrap crash")
				}
				return nil
			})
			if e == nil || c == nil {
				t.Fatal("bootstrap fault ignored", e)
			}
			rootFD, lockFD := c.rootFD, c.lockFD
			t.Cleanup(func() { syscall.Close(lockFD); syscall.Close(rootFD) })
			c = nil
			runtime.GC()
			var stat syscall.Stat_t
			if syscall.Fstat(rootFD, &stat) != nil || syscall.Fstat(lockFD, &stat) != nil {
				t.Fatal("GC released raw authority")
			}
			other, e := NewWorkerCustody(context.Background(), root, strings.Repeat("a", 64), "variants")
			workerCustodyTestOwn(t, other)
			if e == nil || e.Error() != "worker_custody_instance_locked" {
				t.Fatal("GC released sticky flock", e)
			}
		})
	}
}

func TestWorkerCustodyLiveMutationFencesReadWriteAndClose(t *testing.T) {
	for _, kind := range []string{"journal_change", "lock_replace", "unknown_file", "root_permissions"} {
		t.Run(kind, func(t *testing.T) {
			c, root := workerCustodyTestOpen(t)
			v := workerCustodyTestBinding(1)
			if e := c.PutVerified(context.Background(), v); e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "journal_change":
				path := filepath.Join(root, "journal.json")
				raw := workerCustodyTestRead(t, path)
				workerCustodyTestWrite(t, path, append(raw, ' '))
			case "lock_replace":
				path := filepath.Join(root, "instance.lock")
				if e := os.Remove(path); e != nil {
					t.Fatal(e)
				}
				workerCustodyTestWrite(t, path, nil)
			case "unknown_file":
				workerCustodyTestWrite(t, filepath.Join(root, "unexpected"), []byte("keep"))
			case "root_permissions":
				if e := os.Chmod(root, 0750); e != nil {
					t.Fatal(e)
				}
			}
			if _, _, e := c.Lookup(v.JobID); e == nil {
				t.Fatal("live mutation passed Lookup")
			}
			if e := c.PutVerified(context.Background(), workerCustodyTestBinding(2)); e == nil {
				t.Fatal("live mutation admitted write")
			}
			if _, e := c.Bindings(); e == nil {
				t.Fatal("live mutation passed snapshot")
			}
			if e := c.Close(); e == nil {
				t.Fatal("live mutation released sticky custody")
			}
		})
	}
}

func TestWorkerCustodyConcurrentIdenticalPutKeepsOneRecord(t *testing.T) {
	c, _ := workerCustodyTestOpen(t)
	v := workerCustodyTestBinding(1)
	var group sync.WaitGroup
	errs := make(chan error, 12)
	for i := 0; i < 12; i++ {
		group.Add(1)
		go func() { defer group.Done(); errs <- c.PutVerified(context.Background(), v) }()
	}
	group.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	rows, e := c.Bindings()
	if e != nil || len(rows) != 1 || rows[0] != v {
		t.Fatal("concurrent duplicate consumed slots or changed facts", e)
	}
}

func TestWorkerCustodyExistingRootRetriesParentSync(t *testing.T) {
	root := filepath.Join(t.TempDir(), "custody")
	attempts := 0
	fault := func(point string) error {
		if point == "root_parent_sync:custody" {
			attempts++
			return errors.New("synthetic parent sync failure")
		}
		return nil
	}
	for i := 0; i < 2; i++ {
		c, e := newWorkerCustody(context.Background(), root, strings.Repeat("a", 64), "variants", fault)
		workerCustodyTestOwn(t, c)
		if e == nil || e.Error() != "worker_custody_persistence_failed" || c != nil {
			t.Fatal("failed parent sync became accepted baseline", i, e)
		}
		if _, e := os.Lstat(root); e != nil {
			t.Fatal("first attempt did not create root before injected sync failure", e)
		}
		for _, name := range []string{"instance.lock", "journal.json"} {
			if _, e := os.Lstat(filepath.Join(root, name)); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("unsynced root acquired journal authority", name, e)
			}
		}
	}
	if attempts != 2 {
		t.Fatal("retry skipped existing-entry parent sync", attempts)
	}
	c, e := NewWorkerCustody(context.Background(), root, strings.Repeat("a", 64), "variants")
	workerCustodyTestOwn(t, c)
	if e != nil {
		t.Fatal("explicit retry after healthy parent sync failed", e)
	}
	if e = c.PutVerified(context.Background(), workerCustodyTestBinding(1)); e != nil {
		t.Fatal(e)
	}
}
