//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"

	artifact "biozero/artifact-executor"
)

func ownerCustodyTestBinding(a ownerWorkerTestBundle) OwnerWorkerBinding {
	return OwnerWorkerBinding{JobID: a.Job.JobID, AcceptanceSHA256: workerCustodyDigest(a.Acceptance), CredentialSHA256: func() string {
		var s struct {
			Record struct {
				Binding struct {
					CredentialSHA256 string `json:"credential_sha256"`
				} `json:"binding"`
			} `json:"record"`
		}
		_ = json.Unmarshal(a.Acceptance, &s)
		return s.Record.Binding.CredentialSHA256
	}(), UploadSHA256: workerCustodyDigest(a.Ciphertext), EnvelopeSHA256: workerCustodyDigest(a.Envelope), OriginalName: a.Job.OriginalName, ProcessedSHA256: workerCustodyDigest(a.Plaintext), ProcessedBytes: int64(len(a.Plaintext)), AnalysisContext: artifact.AnalysisContext{OriginalName: a.Job.OriginalName, ProcessedSizeBytes: int64(len(a.Plaintext)), Decrypted: true, SignatureValid: true}, AcceptanceBytes: int64(len(a.Acceptance))}
}
func ownerCustodyTestWrite(t *testing.T, path string, raw []byte) {
	t.Helper()
	if e := os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
}
func ownerCustodyTestNew(t *testing.T, f *ownerWorkerTestFixture) (*OwnerWorkerCustody, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "custody")
	c, e := CreateOwnerWorkerCustody(context.Background(), root, f.trust)
	if e != nil {
		t.Fatal(e)
	}
	return c, root
}
func TestOwnerWorkerCustodyDurableCanonicalAndReadOnlyFD(t *testing.T) {
	f := newOwnerWorkerTestFixture(t)
	a := f.bundle(t, false, nil)
	b := ownerCustodyTestBinding(a)
	ctx := context.Background()
	c, root := ownerCustodyTestNew(t, f)
	if e := c.PutVerified(ctx, b, a.Acceptance); e != nil {
		t.Fatal(e)
	}
	journal, e := os.ReadFile(filepath.Join(root, "journal.json"))
	if e != nil {
		t.Fatal(e)
	}
	if e = c.PutVerified(ctx, b, append([]byte(nil), a.Acceptance...)); e != nil {
		t.Fatal(e)
	}
	again, _ := os.ReadFile(filepath.Join(root, "journal.json"))
	if !bytes.Equal(journal, again) {
		t.Fatal("identical put rewrote history")
	}
	got, ok, e := c.Lookup(b.JobID)
	if e != nil || !ok || got != b {
		t.Fatal("lookup", got, ok, e)
	}
	all, e := c.Bindings()
	if e != nil || len(all) != 1 || all[0] != b {
		t.Fatal("bindings", e)
	}
	all[0].ProcessedSHA256 = strings.Repeat("f", 64)
	got, _, _ = c.Lookup(b.JobID)
	if got != b {
		t.Fatal("caller mutated binding")
	}
	raw, e := c.Acceptance(ctx, b.JobID)
	if e != nil || !bytes.Equal(raw, a.Acceptance) {
		t.Fatal("acceptance", e)
	}
	raw[0] = '!'
	fd, e := c.AcceptanceFile(ctx, b.JobID)
	if e != nil {
		t.Fatal(e)
	}
	defer fd.Close()
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd.Fd(), syscall.F_GETFL, 0)
	if errno != 0 || flags&syscall.O_ACCMODE != syscall.O_RDONLY {
		t.Fatal("acceptance descriptor is not read-only")
	}
	if _, e = fd.Write([]byte("x")); e == nil {
		t.Fatal("writable acceptance FD")
	}
	raw, e = io.ReadAll(fd)
	if e != nil || !bytes.Equal(raw, a.Acceptance) {
		t.Fatal("file offset/content", e)
	}
	if e = c.Close(); e != nil {
		t.Fatal(e)
	}
	c, e = OpenOwnerWorkerCustody(ctx, root, f.trust)
	if e != nil {
		t.Fatal("cold open", e)
	}
	defer c.Close()
	got, ok, e = c.Lookup(b.JobID)
	if e != nil || !ok || got != b {
		t.Fatal("cold binding", e)
	}
	st, e := os.Stat(filepath.Join(root, "acceptances", b.AcceptanceSHA256+".json"))
	if e != nil || st.Mode().Perm() != 0600 {
		t.Fatal("sidecar mode", e)
	}
}
func TestOwnerWorkerCustodySignedAndProcessedFactsCannotChange(t *testing.T) {
	f := newOwnerWorkerTestFixture(t)
	a := f.bundle(t, false, nil)
	b := ownerCustodyTestBinding(a)
	ctx := context.Background()
	c, root := ownerCustodyTestNew(t, f)
	defer c.Close()
	changes := map[string]func(*OwnerWorkerBinding){"job": func(v *OwnerWorkerBinding) { v.JobID = strings.Repeat("f", 16) }, "credential": func(v *OwnerWorkerBinding) { v.CredentialSHA256 = strings.Repeat("f", 64) }, "original_cipher": func(v *OwnerWorkerBinding) { v.UploadSHA256 = v.ProcessedSHA256 }, "envelope": func(v *OwnerWorkerBinding) { v.EnvelopeSHA256 = strings.Repeat("f", 64) }, "name": func(v *OwnerWorkerBinding) { v.OriginalName = "other.fastq" }, "size_negative": func(v *OwnerWorkerBinding) { v.ProcessedBytes = -1 }, "size_over": func(v *OwnerWorkerBinding) { v.ProcessedBytes = artifact.MaxInputBytes + 1 }, "context_size": func(v *OwnerWorkerBinding) { v.AnalysisContext.ProcessedSizeBytes++ }, "context_name": func(v *OwnerWorkerBinding) { v.AnalysisContext.OriginalName = "other.fastq" }, "not_decrypted": func(v *OwnerWorkerBinding) { v.AnalysisContext.Decrypted = false }, "signature_invalid": func(v *OwnerWorkerBinding) { v.AnalysisContext.SignatureValid = false }, "crypto_error": func(v *OwnerWorkerBinding) { v.AnalysisContext.DecryptionError = "failure" }, "signature_error": func(v *OwnerWorkerBinding) { v.AnalysisContext.SignatureError = "failure" }, "acceptance_size": func(v *OwnerWorkerBinding) { v.AcceptanceBytes++ }, "processed_hash": func(v *OwnerWorkerBinding) { v.ProcessedSHA256 = "invalid" }}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			v := b
			change(&v)
			if e := c.PutVerified(ctx, v, a.Acceptance); e == nil {
				t.Fatal("changed signed/processed fact accepted")
			}
			all, e := c.Bindings()
			if e != nil || len(all) != 0 {
				t.Fatal("invalid put mutated records", e)
			}
		})
	}
	for name, raw := range map[string][]byte{"whitespace": append([]byte(" "), a.Acceptance...), "signature": bytes.Replace(a.Acceptance, []byte(`"signature":"`), []byte(`"signature":"0`), 1), "oversize": bytes.Repeat([]byte("x"), int(ownerCustodyAcceptanceLimit)+1)} {
		t.Run(name, func(t *testing.T) {
			v := b
			v.AcceptanceBytes = int64(len(raw))
			v.AcceptanceSHA256 = workerCustodyDigest(raw)
			if e := c.PutVerified(ctx, v, raw); e == nil {
				t.Fatal("unverified/noncanonical sidecar accepted")
			}
		})
	}
	if e := c.PutVerified(ctx, b, a.Acceptance); e != nil {
		t.Fatal(e)
	}
	v := b
	v.ProcessedSHA256 = strings.Repeat("f", 64)
	if e := c.PutVerified(ctx, v, a.Acceptance); e == nil {
		t.Fatal("processed conflict accepted")
	}
	all, e := c.Bindings()
	if e != nil || len(all) != 1 || all[0] != b {
		t.Fatal("conflict mutated retained record", e)
	}
	entries, e := os.ReadDir(root)
	if e != nil || len(entries) != 3 {
		t.Fatal("rejected put left publications", e)
	}
}
func TestOwnerWorkerCustodyExplicitGenesisAndNoAdoption(t *testing.T) {
	f := newOwnerWorkerTestFixture(t)
	ctx := context.Background()
	t.Run("open_missing", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "missing")
		if _, e := OpenOwnerWorkerCustody(ctx, path, f.trust); e == nil {
			t.Fatal("Open initialized")
		}
		if _, e := os.Stat(path); !os.IsNotExist(e) {
			t.Fatal("missing root created")
		}
	})
	t.Run("existing_empty", func(t *testing.T) {
		path := t.TempDir()
		if _, e := CreateOwnerWorkerCustody(ctx, path, f.trust); e == nil {
			t.Fatal("Create adopted existing root")
		}
		names, _ := os.ReadDir(path)
		if len(names) != 0 {
			t.Fatal("existing root changed")
		}
	})
	t.Run("missing_parent", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "missing", "child")
		if _, e := CreateOwnerWorkerCustody(ctx, path, f.trust); e == nil {
			t.Fatal("created ancestor")
		}
		if _, e := os.Stat(filepath.Dir(path)); !os.IsNotExist(e) {
			t.Fatal("ancestor materialized")
		}
	})
	t.Run("ancestor_symlink", func(t *testing.T) {
		parent := t.TempDir()
		real := filepath.Join(parent, "real")
		os.Mkdir(real, 0700)
		link := filepath.Join(parent, "link")
		os.Symlink(real, link)
		if _, e := CreateOwnerWorkerCustody(ctx, filepath.Join(link, "child"), f.trust); e == nil {
			t.Fatal("followed ancestor symlink")
		}
	})
	t.Run("legacy", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "legacy")
		old, e := NewWorkerCustody(ctx, path, f.trust.ProfileSHA256, f.trust.PipelineMode)
		if e != nil {
			t.Fatal(e)
		}
		if e = old.Close(); e != nil {
			t.Fatal(e)
		}
		before, _ := os.ReadFile(filepath.Join(path, "journal.json"))
		c, e := OpenOwnerWorkerCustody(ctx, path, f.trust)
		if e == nil {
			t.Fatal("adopted legacy")
		}
		if c != nil && c.Close() == nil {
			t.Fatal("unsafe history released authority")
		}
		after, _ := os.ReadFile(filepath.Join(path, "journal.json"))
		if !bytes.Equal(before, after) {
			t.Fatal("legacy history changed")
		}
	})
}
func TestOwnerWorkerCustodyClosedSchemaAndFixedBudgets(t *testing.T) {
	f := newOwnerWorkerTestFixture(t)
	ctx := context.Background()
	cases := map[string]func([]byte) []byte{
		"duplicate": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"schema_version":1`), []byte(`"schema_version":1,"schema_version":1`), 1)
		},
		"case_alias": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"schema_version"`), []byte(`"Schema_Version"`), 1)
		},
		"null_records": func(b []byte) []byte { return bytes.Replace(b, []byte(`"records":{}`), []byte(`"records":null`), 1) },
		"unknown":      func(b []byte) []byte { return append([]byte(`{"unknown":0,`), b[1:]...) },
		"trailing":     func(b []byte) []byte { return append(b, []byte(" {}")...) },
		"depth":        func(b []byte) []byte { return []byte(strings.Repeat("[", 34) + "0" + strings.Repeat("]", 34)) },
		"version": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"schema_version":1`), []byte(`"schema_version":2`), 1)
		},
		"domain": func(b []byte) []byte {
			return bytes.Replace(b, []byte(ownerCustodyDomain), []byte("legacy-custody"), 1)
		},
		"record_count": func(b []byte) []byte {
			var j ownerCustodyJournal
			json.Unmarshal(b, &j)
			for i := 0; i < 65; i++ {
				j.Records[fmt.Sprintf("%016x", i)] = OwnerWorkerBinding{}
			}
			out, _ := json.Marshal(j)
			return out
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			c, path := ownerCustodyTestNew(t, f)
			if e := c.Close(); e != nil {
				t.Fatal(e)
			}
			file := filepath.Join(path, "journal.json")
			raw, _ := os.ReadFile(file)
			changed := change(raw)
			ownerCustodyTestWrite(t, file, changed)
			got, e := OpenOwnerWorkerCustody(ctx, path, f.trust)
			if e == nil {
				t.Fatal("invalid history opened")
			}
			if got != nil && got.Close() == nil {
				t.Fatal("unsafe handle released")
			}
			after, _ := os.ReadFile(file)
			if !bytes.Equal(after, changed) {
				t.Fatal("history repaired")
			}
		})
	}
	t.Run("sparse_oversize", func(t *testing.T) {
		c, path := ownerCustodyTestNew(t, f)
		c.Close()
		fp, e := os.OpenFile(filepath.Join(path, "journal.json"), os.O_WRONLY, 0)
		if e != nil {
			t.Fatal(e)
		}
		fp.Truncate(ownerCustodyJournalLimit + 1)
		fp.Close()
		if _, e = OpenOwnerWorkerCustody(ctx, path, f.trust); e == nil {
			t.Fatal("oversize journal accepted")
		}
	})
	t.Run("external_trust", func(t *testing.T) {
		c, path := ownerCustodyTestNew(t, f)
		c.Close()
		trust := f.trust
		trust.ContextSHA256 = strings.Repeat("f", 64)
		if _, e := OpenOwnerWorkerCustody(ctx, path, trust); e == nil {
			t.Fatal("changed context adopted")
		}
	})
}
func TestOwnerWorkerCustodyUnsafeHistoryAndLiveReplacement(t *testing.T) {
	f := newOwnerWorkerTestFixture(t)
	a := f.bundle(t, false, nil)
	b := ownerCustodyTestBinding(a)
	ctx := context.Background()
	changes := map[string]func(string){
		"unknown_root": func(p string) { ownerCustodyTestWrite(t, filepath.Join(p, "foreign"), []byte("private-canary")) },
		"marker":       func(p string) { ownerCustodyTestWrite(t, filepath.Join(p, "transaction.pending"), []byte(`{}`)) },
		"replacement":  func(p string) { ownerCustodyTestWrite(t, filepath.Join(p, ".journal.next"), []byte(`{}`)) },
		"unknown_sidecar": func(p string) {
			ownerCustodyTestWrite(t, filepath.Join(p, "acceptances", "foreign.json"), []byte("private-canary"))
		},
		"sidecar_temp": func(p string) {
			ownerCustodyTestWrite(t, filepath.Join(p, "acceptances", ".acceptance.next"), []byte("private-canary"))
		},
		"sidecar_permissions": func(p string) { os.Chmod(filepath.Join(p, "acceptances", b.AcceptanceSHA256+".json"), 0644) },
		"sidecar_link": func(p string) {
			src := filepath.Join(p, "acceptances", b.AcceptanceSHA256+".json")
			os.Link(src, filepath.Join(filepath.Dir(p), "external-hardlink"))
		},
		"sidecar_symlink": func(p string) {
			src := filepath.Join(p, "acceptances", b.AcceptanceSHA256+".json")
			dest := filepath.Join(filepath.Dir(p), "external-sidecar")
			os.Rename(src, dest)
			os.Symlink(dest, src)
		},
		"sidecar_fifo": func(p string) {
			src := filepath.Join(p, "acceptances", b.AcceptanceSHA256+".json")
			os.Remove(src)
			syscall.Mkfifo(src, 0600)
		},
		"sidecar_sparse": func(p string) {
			src := filepath.Join(p, "acceptances", b.AcceptanceSHA256+".json")
			fp, _ := os.OpenFile(src, os.O_WRONLY, 0)
			fp.Truncate(ownerCustodyAcceptanceLimit + 1)
			fp.Close()
		},
		"same_bytes_new_journal_inode": func(p string) {
			src := filepath.Join(p, "journal.json")
			raw, _ := os.ReadFile(src)
			ownerCustodyTestWrite(t, src+".foreign", raw)
			os.Rename(src+".foreign", src)
		},
		"same_bytes_new_sidecar_inode": func(p string) {
			src := filepath.Join(p, "acceptances", b.AcceptanceSHA256+".json")
			raw, _ := os.ReadFile(src)
			ownerCustodyTestWrite(t, src+".foreign", raw)
			os.Rename(src+".foreign", src)
		},
		"replaced_root": func(p string) { os.Rename(p, p+".old"); os.Mkdir(p, 0700) },
		"replaced_lock": func(p string) {
			os.Rename(filepath.Join(p, "instance.lock"), filepath.Join(p, "old.lock"))
			ownerCustodyTestWrite(t, filepath.Join(p, "instance.lock"), nil)
		},
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			c, path := ownerCustodyTestNew(t, f)
			if e := c.PutVerified(ctx, b, a.Acceptance); e != nil {
				t.Fatal(e)
			}
			change(path)
			if _, _, e := c.Lookup(b.JobID); e == nil {
				t.Fatal("unsafe live history accepted")
			}
			if _, e := c.AcceptanceFile(ctx, b.JobID); e == nil {
				t.Fatal("unsafe acceptance returned")
			}
			if e := c.Close(); e == nil {
				t.Fatal("unsafe store released lifetime lock")
			}
		})
	}
}
func TestOwnerWorkerCustodyConcurrentPutAndCancellation(t *testing.T) {
	f := newOwnerWorkerTestFixture(t)
	a := f.bundle(t, false, nil)
	b := ownerCustodyTestBinding(a)
	c, _ := ownerCustodyTestNew(t, f)
	defer c.Close()
	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- c.PutVerified(ctx, b, a.Acceptance) }()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	all, e := c.Bindings()
	if e != nil || len(all) != 1 {
		t.Fatal("parallel duplicate records", e)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if e = c.PutVerified(canceled, b, a.Acceptance); e == nil {
		t.Fatal("canceled put accepted")
	}
	if _, e = c.AcceptanceFile(canceled, b.JobID); e == nil {
		t.Fatal("canceled FD returned")
	}
	if _, _, e = c.Lookup(b.JobID); e != nil {
		t.Fatal("preflight cancellation poisoned durable history", e)
	}
}

// Child process deliberately loses the final Store pointer after a real
// uncertain write. No defer or Cleanup captures it; only raw descriptor numbers
// survive. The parent proves lock lifetime and then uses actual SIGKILL/Wait.
func TestOwnerWorkerCustodyProcess(t *testing.T) {
	if os.Getenv("BIOZERO_OWNER_CUSTODY_CHILD") != "1" {
		return
	}
	base := os.Getenv("BIOZERO_OWNER_CUSTODY_FIXTURE")
	raw, e := os.ReadFile(filepath.Join(base, "trust.json"))
	if e != nil {
		t.Fatal(e)
	}
	var trust ownerWorkerTrust
	json.Unmarshal(raw, &trust)
	raw, e = os.ReadFile(filepath.Join(base, "binding.json"))
	if e != nil {
		t.Fatal(e)
	}
	var b OwnerWorkerBinding
	json.Unmarshal(raw, &b)
	acceptance, e := os.ReadFile(filepath.Join(base, "acceptance.json"))
	if e != nil {
		t.Fatal(e)
	}
	lockFD := func() int {
		c, e := OpenOwnerWorkerCustody(context.Background(), filepath.Join(base, "custody"), trust)
		if e != nil {
			t.Fatal(e)
		}
		point := os.Getenv("BIOZERO_OWNER_CUSTODY_POINT")
		c.fault = func(p string) error {
			if p == point {
				return errors.New("synthetic fault")
			}
			return nil
		}
		if c.PutVerified(context.Background(), b, acceptance) == nil {
			t.Fatal("fault did not fire")
		}
		if c.Close() == nil {
			t.Fatal("sticky Close unlocked")
		}
		return c.lockFD
	}()
	runtime.GC()
	runtime.GC()
	var st syscall.Stat_t
	if syscall.Fstat(lockFD, &st) != nil {
		t.Fatal("raw lock finalized")
	}
	fmt.Print("R")
	if _, e = io.Copy(io.Discard, os.Stdin); e != nil {
		t.Fatal(e)
	}
}
func TestOwnerWorkerCustodyPublicationFailuresKeepAuthorityThroughGCAndDeath(t *testing.T) {
	f := newOwnerWorkerTestFixture(t)
	a := f.bundle(t, false, nil)
	b := ownerCustodyTestBinding(a)
	for _, point := range []string{"marker_write", "marker_file_sync", "marker_directory_sync", "acceptance_write", "acceptance_file_sync", "acceptance_link", "acceptance_link_directory_sync", "journal_write", "journal_file_sync", "journal_rename", "journal_directory_sync", "marker_unlink", "marker_retirement_sync", "ack"} {
		t.Run(point, func(t *testing.T) {
			base := t.TempDir()
			root := filepath.Join(base, "custody")
			c, e := CreateOwnerWorkerCustody(context.Background(), root, f.trust)
			if e != nil {
				t.Fatal(e)
			}
			if e = c.Close(); e != nil {
				t.Fatal(e)
			}
			trust, _ := json.Marshal(f.trust)
			binding, _ := json.Marshal(b)
			ownerCustodyTestWrite(t, filepath.Join(base, "trust.json"), trust)
			ownerCustodyTestWrite(t, filepath.Join(base, "binding.json"), binding)
			ownerCustodyTestWrite(t, filepath.Join(base, "acceptance.json"), a.Acceptance)
			cmd := exec.Command(os.Args[0], "-test.run=^TestOwnerWorkerCustodyProcess$", "-test.timeout=20s")
			cmd.Env = append(os.Environ(), "BIOZERO_OWNER_CUSTODY_CHILD=1", "BIOZERO_OWNER_CUSTODY_FIXTURE="+base, "BIOZERO_OWNER_CUSTODY_POINT="+point)
			stdout, e := cmd.StdoutPipe()
			if e != nil {
				t.Fatal(e)
			}
			stdin, e := cmd.StdinPipe()
			if e != nil {
				t.Fatal(e)
			}
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if e = cmd.Start(); e != nil {
				t.Fatal(e)
			}
			defer func() { stdin.Close(); cmd.Process.Kill(); cmd.Wait() }()
			var signal [1]byte
			if _, e = io.ReadFull(stdout, signal[:]); e != nil || signal[0] != 'R' {
				t.Fatal("helper not ready", e, stderr.String())
			}
			if _, e = OpenOwnerWorkerCustody(context.Background(), root, f.trust); e == nil || e.Error() != "owner_worker_custody_instance_locked" {
				t.Fatal("GC/Close released authority", e)
			}
			if e = cmd.Process.Kill(); e != nil {
				t.Fatal(e)
			}
			e = cmd.Wait()
			var exit *exec.ExitError
			if !errors.As(e, &exit) || !exit.ProcessState.Sys().(syscall.WaitStatus).Signaled() || exit.ProcessState.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
				t.Fatal("helper did not die by SIGKILL", e)
			}
			opened, err := OpenOwnerWorkerCustody(context.Background(), root, f.trust)
			if point == "ack" || point == "marker_retirement_sync" {
				if err != nil {
					t.Fatal("coherent visible cold history not verifiable", err)
				}
				defer opened.Close()
				got, ok, e := opened.Lookup(b.JobID)
				if e != nil || !ok || got != b {
					t.Fatal("published acceptance changed", e)
				}
			} else {
				if err == nil {
					t.Fatal("uncertain remainder auto-repaired")
				}
				if opened != nil && opened.Close() == nil {
					t.Fatal("uncertain cold handle released")
				}
			}
		})
	}
}
func TestOwnerWorkerCustodyBootstrapFailureNeverInitializesOnOpen(t *testing.T) {
	f := newOwnerWorkerTestFixture(t)
	for _, point := range []string{"marker_file_sync", "journal_write", "journal_link", "journal_link_unlink_sync"} {
		t.Run(point, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "custody")
			c, e := openOwnerWorkerCustody(context.Background(), path, f.trust, true, func(p string) error {
				if p == point {
					return errors.New("synthetic init fault")
				}
				return nil
			})
			if e == nil || c == nil {
				t.Fatal("init fault ignored", e)
			}
			if c.Close() == nil {
				t.Fatal("init fault unlocked")
			}
			if _, e = OpenOwnerWorkerCustody(context.Background(), path, f.trust); e == nil || e.Error() != "owner_worker_custody_instance_locked" {
				t.Fatal("live init authority lost", e)
			}
		})
	}
}
func TestOwnerWorkerCustodyJournalSignedFieldsReverifiedOnColdOpen(t *testing.T) {
	f := newOwnerWorkerTestFixture(t)
	a := f.bundle(t, false, nil)
	b := ownerCustodyTestBinding(a)
	for _, field := range []string{"credential_sha256", "upload_sha256", "envelope_sha256", "original_name", "processed_bytes", "acceptance_sha256"} {
		t.Run(field, func(t *testing.T) {
			c, path := ownerCustodyTestNew(t, f)
			if e := c.PutVerified(context.Background(), b, a.Acceptance); e != nil {
				t.Fatal(e)
			}
			if e := c.Close(); e != nil {
				t.Fatal(e)
			}
			file := filepath.Join(path, "journal.json")
			raw, _ := os.ReadFile(file)
			var j map[string]any
			json.Unmarshal(raw, &j)
			row := j["records"].(map[string]any)[b.JobID].(map[string]any)
			if field == "processed_bytes" {
				row[field] = float64(b.ProcessedBytes + 1)
			} else if field == "original_name" {
				row[field] = "other.fastq"
			} else {
				row[field] = strings.Repeat("f", 64)
			}
			raw, _ = json.Marshal(j)
			ownerCustodyTestWrite(t, file, raw)
			if _, e := OpenOwnerWorkerCustody(context.Background(), path, f.trust); e == nil {
				t.Fatal("recomputed ledger accepted inconsistent signed facts")
			}
		})
	}
}
func TestOwnerWorkerCustodyNoSecretErrorsAndValueTypes(t *testing.T) {
	f := newOwnerWorkerTestFixture(t)
	c, path := ownerCustodyTestNew(t, f)
	ownerCustodyTestWrite(t, filepath.Join(path, "private-canary-filename"), []byte("private-canary-value"))
	_, e := c.Bindings()
	if e == nil || strings.Contains(e.Error(), path) || strings.Contains(e.Error(), "canary") {
		t.Fatal("unstable/private error", e)
	}
	typ := reflect.TypeOf(OwnerWorkerBinding{})
	for i := 0; i < typ.NumField(); i++ {
		if typ.Field(i).Tag.Get("json") == "" {
			t.Fatal("missing exact JSON tag")
		}
	}
}
