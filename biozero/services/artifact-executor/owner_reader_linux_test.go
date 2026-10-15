//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package artifactexecutor

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"
)

func ownerReaderRequest(f *ownerTestFixture, op string) OwnerReadRequest {
	o := f.b.owner.bindings[f.q.JobID]
	return OwnerReadRequest{1, OwnerReadRequestDomain, op, f.q.JobID, f.q.AcceptanceSHA256, o.Binding.CredentialSHA256, f.q.UploadSHA256, f.cfg.ProfileSHA256, f.cfg.Scope}
}
func ownerReaderSubmit(t *testing.T, f *ownerTestFixture) {
	t.Helper()
	r, fd, e := f.b.HandleBridgeV3(context.Background(), f.q, f.plain, f.acceptance)
	if fd != nil {
		fd.Close()
	}
	if e != nil || r.Execution.State != "committed" {
		t.Fatal("fixture submit", e, r.Execution.State)
	}
}
func ownerReaderHistory(t *testing.T, f *ownerTestFixture) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, root := range []string{filepath.Join(f.root, "store"), f.cfg.JournalRoot} {
		if e := filepath.Walk(root, func(path string, info os.FileInfo, e error) error {
			if e != nil {
				return e
			}
			if !info.IsDir() {
				raw, e := os.ReadFile(path)
				if e != nil {
					return e
				}
				out[path] = digest(raw)
			}
			return nil
		}); e != nil {
			t.Fatal(e)
		}
	}
	return out
}
func TestOwnerReaderTransportFailureAndCancellationPreserveExecution(t *testing.T) {
	f := newOwnerTestFixture(t)
	ownerReaderSubmit(t, f)
	reader, e := NewOwnerReader(f.b)
	if e != nil {
		t.Fatal(e)
	}
	before := ownerReaderHistory(t, f)
	charge := f.s.Snapshot()
	q := ownerReaderRequest(f, "receipt")
	response, fd, e := reader.HandleOwnerRead(context.Background(), q)
	if e != nil || fd == nil || !response.HasReceipt {
		t.Fatal(e)
	}
	defer fd.Close()
	called := 0
	network := errors.New("synthetic transport write failed")
	e = reader.DeliverOwnerRead(context.Background(), q, response, fd, func() error { called++; return network })
	var classified *ownerReadFailure
	if !errors.Is(e, network) || !errors.As(e, &classified) || classified.storage || called != 1 {
		t.Fatal("transport misclassified", e, called)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, f2, e := reader.HandleOwnerRead(ctx, q); e == nil || f2 != nil {
		if f2 != nil {
			f2.Close()
		}
		t.Fatal("cancel accepted")
	}
	if e = reader.DeliverOwnerRead(ctx, q, response, fd, func() error { called++; return nil }); e == nil || called != 1 {
		t.Fatal("cancel delivered")
	}
	again, f2, e := reader.HandleOwnerRead(context.Background(), q)
	if e != nil || f2 == nil || !reflect.DeepEqual(response, again) {
		t.Fatal("same receipt unavailable", e)
	}
	defer f2.Close()
	if e = reader.DeliverOwnerRead(context.Background(), q, again, f2, func() error { called++; return nil }); e != nil || called != 2 {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(charge, f.s.Snapshot()) || !reflect.DeepEqual(before, ownerReaderHistory(t, f)) || f.calls.Load() != 1 {
		t.Fatal("read modified custody/accounting")
	}
	if e = f.b.AcknowledgeBridgeV3(context.Background(), ownerTestQuery(f.q, "status"), func() error { return nil }); e != nil {
		t.Fatal("reader poisoned worker ACK", e)
	}
}
func TestOwnerReaderStorageFaultFencesSnapshotAndWorkerACK(t *testing.T) {
	for _, kind := range []string{"receipt_tamper", "ledger_tamper", "eio_with_cancel"} {
		t.Run(kind, func(t *testing.T) {
			f := newOwnerTestFixture(t)
			ownerReaderSubmit(t, f)
			reader, e := NewOwnerReader(f.b)
			if e != nil {
				t.Fatal(e)
			}
			q := ownerReaderRequest(f, "receipt")
			response, fd, e := reader.HandleOwnerRead(context.Background(), q)
			if e != nil {
				t.Fatal(e)
			}
			defer fd.Close()
			charge := f.s.Snapshot()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch kind {
			case "receipt_tamper":
				if e = os.WriteFile(filepath.Join(f.root, "store", "objects", response.Binding.Execution.LeaseID, "execution_receipt"), []byte(`{"tampered":true}`), 0600); e != nil {
					t.Fatal(e)
				}
			case "ledger_tamper":
				if e = os.WriteFile(filepath.Join(f.root, "store", "ledger.json"), []byte("{}"), 0600); e != nil {
					t.Fatal(e)
				}
			case "eio_with_cancel":
				f.b.fault = func(point string) error {
					if point == "owner_read_storage" {
						cancel()
						return syscall.EIO
					}
					return nil
				}
			}
			called := false
			e = reader.DeliverOwnerRead(ctx, q, response, fd, func() error { called = true; return nil })
			var classified *ownerReadFailure
			if e == nil || called || !errors.As(e, &classified) || !classified.storage || f.s.Snapshot().Healthy {
				t.Fatal("storage not fenced", e, called)
			}
			ack := false
			if e = f.b.AcknowledgeBridgeV3(context.Background(), ownerTestQuery(f.q, "status"), func() error { ack = true; return nil }); e == nil || ack {
				t.Fatal("worker ACK bypassed storage fence")
			}
			after := f.s.Snapshot()
			if after.ChargedBytes != charge.ChargedBytes || after.RetainedOrReservedJobs != charge.RetainedOrReservedJobs || f.calls.Load() != 1 {
				t.Fatal("fault released custody")
			}
		})
	}
}
func TestOwnerReaderFreshGuardBlocksSnapshotAfterConcurrentPoison(t *testing.T) {
	f := newOwnerTestFixture(t)
	ownerReaderSubmit(t, f)
	reader, e := NewOwnerReader(f.b)
	if e != nil {
		t.Fatal(e)
	}
	q := ownerReaderRequest(f, "status")
	response, fd, e := reader.HandleOwnerRead(context.Background(), q)
	if e != nil || fd != nil {
		t.Fatal(e)
	}
	poisoned := make(chan struct{})
	go func() {
		f.b.mu.Lock()
		f.s.mu.Lock()
		f.b.latchStoreLocked("artifact_test_storage_fault")
		f.s.mu.Unlock()
		f.b.mu.Unlock()
		close(poisoned)
	}()
	<-poisoned
	called := false
	if e = reader.DeliverOwnerRead(context.Background(), q, response, nil, func() error { called = true; return nil }); e == nil || called {
		t.Fatal("stale snapshot delivered")
	}
}
func TestOwnerReaderPendingAndFailedCommitWithoutReceipt(t *testing.T) {
	t.Run("pending", func(t *testing.T) {
		f := newOwnerTestFixture(t)
		entered, release := make(chan struct{}), make(chan struct{})
		f.c.provider = fixtureProvider(func(context.Context, *ScopedInput, *Exporter) ProviderCompletion {
			close(entered)
			<-release
			return nativeFailure("artifact_synthetic_failed", true)
		})
		reader, e := NewOwnerReader(f.b)
		if e != nil {
			t.Fatal(e)
		}
		done := make(chan error, 1)
		go func() {
			_, fd, e := f.b.HandleBridgeV3(context.Background(), f.q, f.plain, f.acceptance)
			if fd != nil {
				fd.Close()
			}
			done <- e
		}()
		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			t.Fatal("provider not reached")
		}
		q := ownerReaderRequest(f, "receipt")
		response, fd, e := reader.HandleOwnerRead(context.Background(), q)
		if e != nil || fd != nil || response.HasReceipt || response.Binding.Execution.State == "committed" {
			close(release)
			<-done
			t.Fatal("pending released", e)
		}
		close(release)
		if e = <-done; e != nil {
			t.Fatal(e)
		}
	})
	t.Run("failed_without_receipt", func(t *testing.T) {
		f := newOwnerTestFixture(t)
		f.c.provider = ownerInitializationProvider{}
		ownerReaderSubmit(t, f)
		reader, e := NewOwnerReader(f.b)
		if e != nil {
			t.Fatal(e)
		}
		before := ownerReaderHistory(t, f)
		q := ownerReaderRequest(f, "receipt")
		response, fd, e := reader.HandleOwnerRead(context.Background(), q)
		if e != nil || fd != nil || response.HasReceipt || response.Binding.Execution.Manifest.ExecutionStatus != "failed" || response.Binding.Execution.Manifest.ReleaseStatus != "withheld" {
			t.Fatal("legitimate no-receipt failed", e)
		}
		if e = reader.DeliverOwnerRead(context.Background(), q, response, nil, func() error { return nil }); e != nil {
			t.Fatal(e)
		}
		if !reflect.DeepEqual(before, ownerReaderHistory(t, f)) {
			t.Fatal("no-receipt read changed history")
		}
	})
}
func TestOwnerReaderActualWriteHoldsStoreGuard(t *testing.T) {
	f := newOwnerTestFixture(t)
	ownerReaderSubmit(t, f)
	reader, e := NewOwnerReader(f.b)
	if e != nil {
		t.Fatal(e)
	}
	q := ownerReaderRequest(f, "receipt")
	response, fd, e := reader.HandleOwnerRead(context.Background(), q)
	if e != nil {
		t.Fatal(e)
	}
	defer fd.Close()
	if e = reader.DeliverOwnerRead(context.Background(), q, response, fd, func() error {
		if f.b.mu.TryLock() {
			f.b.mu.Unlock()
			t.Error("broker guard absent")
		}
		if f.s.mu.TryLock() {
			f.s.mu.Unlock()
			t.Error("Store guard absent")
		}
		_, e := io.Copy(io.Discard, io.NewSectionReader(fd, 0, response.Binding.Execution.ReceiptBytes))
		return e
	}); e != nil {
		t.Fatal(e)
	}
}

func TestOwnerReaderCommittedStoreWaitsForWriterSeal(t *testing.T) {
	f := newOwnerTestFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	f.b.fault = func(point string) error {
		if point == "before_commit_journal" {
			close(entered)
			<-release
		}
		return nil
	}
	reader, e := NewOwnerReader(f.b)
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() {
		_, fd, e := f.b.HandleBridgeV3(context.Background(), f.q, f.plain, f.acceptance)
		if fd != nil {
			fd.Close()
		}
		done <- e
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("commit barrier not reached")
	}
	before := ownerReaderHistory(t, f)
	q := ownerReaderRequest(f, "receipt")
	response, fd, e := reader.HandleOwnerRead(context.Background(), q)
	if e == nil || fd != nil || response.ErrorCode != "artifact_owner_read_pending" || !f.s.Snapshot().Healthy {
		if fd != nil {
			fd.Close()
		}
		t.Fatal("reader adopted/unsealed or poisoned commit", e)
	}
	if !reflect.DeepEqual(before, ownerReaderHistory(t, f)) {
		t.Fatal("reader sealed writer journal")
	}
	close(release)
	released = true
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	response, fd, e = reader.HandleOwnerRead(context.Background(), q)
	if fd != nil {
		defer fd.Close()
	}
	if e != nil || !response.HasReceipt {
		t.Fatal("sealed receipt unavailable", e)
	}
}

func TestOwnerReaderFinalReceiptCheckClassifiesStorageAndCancel(t *testing.T) {
	for _, fault := range []bool{false, true} {
		t.Run(map[bool]string{false: "callback_cancel_local", true: "last_receipt_validation_storage"}[fault], func(t *testing.T) {
			f := newOwnerTestFixture(t)
			ownerReaderSubmit(t, f)
			reader, e := NewOwnerReader(f.b)
			if e != nil {
				t.Fatal(e)
			}
			q := ownerReaderRequest(f, "receipt")
			response, fd, e := reader.HandleOwnerRead(context.Background(), q)
			if e != nil {
				t.Fatal(e)
			}
			defer fd.Close()
			before := ownerReaderHistory(t, f)
			charge := f.s.Snapshot()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			called := 0
			e = reader.DeliverOwnerRead(ctx, q, response, fd, func() error {
				called++
				// This barrier is after core revalidation while both locks remain held.
				// Cancellation alone is local; a real newly observed hash/metadata fault
				// wins over simultaneous cancellation because the trusted read uses its
				// own context rather than the disconnected client's context.
				cancel()
				if !fault {
					return ctx.Err()
				}
				path := filepath.Join(f.root, "store", "objects", response.Binding.Execution.LeaseID, "execution_receipt")
				if err := os.WriteFile(path, []byte(`{"post_guard_tamper":true}`), 0600); err != nil {
					t.Fatal(err)
				}
				err := checkOwnerReceipt(context.Background(), fd, uint32(os.Geteuid()), response.Binding.Execution)
				if err == nil {
					t.Error("actual final FD validation missed tamper")
					return nil
				}
				return &ownerReadFailure{storage: true, cause: err}
			})
			var classified *ownerReadFailure
			if called != 1 || e == nil || !errors.As(e, &classified) || classified.storage != fault {
				t.Fatal("wrong final validation class", e, called)
			}
			after := f.s.Snapshot()
			if after.Healthy == fault || after.ChargedBytes != charge.ChargedBytes || after.RetainedOrReservedJobs != charge.RetainedOrReservedJobs {
				t.Fatal("wrong final validation custody", after)
			}
			ack := false
			ackErr := f.b.AcknowledgeBridgeV3(context.Background(), ownerTestQuery(f.q, "status"), func() error { ack = true; return nil })
			if fault {
				if ack || ackErr == nil {
					t.Fatal("worker ACK bypassed final storage fault")
				}
			} else {
				if ackErr != nil || !ack {
					t.Fatal("callback cancellation poisoned worker", ackErr)
				}
				if !reflect.DeepEqual(before, ownerReaderHistory(t, f)) {
					t.Fatal("cancel changed history")
				}
			}
		})
	}
}
