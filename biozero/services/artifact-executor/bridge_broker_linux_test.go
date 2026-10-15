//go:build linux

package artifactexecutor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// These use actual private Store/journal/socket persistence and synthetic Go
// providers only. No kernel capsule, crypto worker, model or Docker is run.
type brokerFixture struct {
	b             *Broker
	c             *Coordinator
	s             *Store
	root, journal string
	input         *os.File
	q             BridgeRequest
	calls         *atomic.Int32
}

func newBrokerFixture(t *testing.T, provider Provider) *brokerFixture {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	f := &brokerFixture{root: root, journal: filepath.Join(root, "bridge"), calls: new(atomic.Int32)}
	if provider == nil {
		provider = fixtureProvider(func(ctx context.Context, in *ScopedInput, out *Exporter) ProviderCompletion {
			f.calls.Add(1)
			if _, e := in.CopyTo(ctx, io.Discard); e != nil {
				return ProviderCompletion{Quiescent: true, Err: e}
			}
			receipt := []byte(`{"schema_version":1,"synthetic_only":true}`)
			if e := out.Export("execution_receipt", digest(receipt), bytes.NewReader(receipt)); e != nil {
				return ProviderCompletion{Quiescent: true, Err: e}
			}
			return ProviderCompletion{Quiescent: true, Outcome: Outcome{ExecutionStatus: "succeeded", ReleaseStatus: "unassessed"}}
		})
	}
	var err error
	f.s, err = Open(context.Background(), filepath.Join(root, "store"), NativeArtifactPolicy())
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewInputRegistry(f.s)
	if err != nil {
		t.Fatal(err)
	}
	f.c, err = NewCoordinator(f.s, registry, provider)
	if err != nil {
		t.Fatal(err)
	}
	f.b, err = NewBroker(context.Background(), BrokerConfig{f.journal, strings.Repeat("c", 64)}, f.c)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("@synthetic\nACGT\n+\nIIII\n")
	path := filepath.Join(root, "verified.fastq")
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	f.input, err = os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	f.q = BridgeRequest{1, "submit", strings.Repeat("a", 16), digest([]byte("original ciphertext placeholder")), strings.Repeat("c", 64), digest(data), int64(len(data)), "synthetic.fastq"}
	t.Cleanup(func() {
		f.input.Close()
		if f.b != nil {
			f.b.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			_ = f.b.Wait(ctx)
			cancel()
			// Test-only end-of-process simulation for known fake providers. Real keepers
			// must retain these FDs when Wait or quiescence is uncertain.
			f.b.lock.Close()
			f.b.root.Close()
		}
		if f.c != nil {
			f.c.Close()
			f.c.registry.Close()
		}
		if f.s != nil {
			f.s.Close()
		}
	})
	return f
}
func brokerQuery(q BridgeRequest, op string) BridgeRequest {
	q.Operation = op
	q.ProcessedSHA256 = ""
	q.ProcessedBytes = 0
	q.OriginalName = ""
	return q
}
func brokerRead(t *testing.T, path string) []byte {
	t.Helper()
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func (f *brokerFixture) restart(t *testing.T) {
	t.Helper()
	f.c.Close()
	f.c.registry.Close()
	f.b.lock.Close()
	f.b.root.Close()
	f.s.Close()
	s, e := Open(context.Background(), filepath.Join(f.root, "store"), NativeArtifactPolicy())
	if e != nil {
		t.Fatal(e)
	}
	f.s = s
	r, e := NewInputRegistry(s)
	if e != nil {
		t.Fatal(e)
	}
	c, e := NewCoordinator(s, r, fixtureProvider(func(context.Context, *ScopedInput, *Exporter) ProviderCompletion {
		f.calls.Add(1)
		panic("recovery reexecuted provider")
	}))
	if e != nil {
		t.Fatal(e)
	}
	f.c = c
	b, e := NewBroker(context.Background(), BrokerConfig{f.journal, f.q.ExpectedProfileSHA256}, c)
	if e != nil {
		t.Fatal(e)
	}
	f.b = b
}
func TestBrokerCommitDuplicateLostACKAndRestartReadback(t *testing.T) {
	f := newBrokerFixture(t, nil)
	ctx := context.Background()
	response, fd, e := f.b.HandleBridge(ctx, f.q, f.input)
	if e != nil || fd != nil || response.State != "committed" || !response.HasManifest || response.Manifest.ReleaseStatus != "unassessed" || f.calls.Load() != 1 {
		t.Fatal("initial custody failed", e)
	}
	beforeStore := brokerRead(t, filepath.Join(f.root, "store/ledger.json"))
	beforeJournal := brokerRead(t, filepath.Join(f.journal, "journal.json"))
	snapshot := f.s.Snapshot()
	second, _, e := f.b.HandleBridge(ctx, f.q, f.input)
	if e != nil || second.ManifestSHA256 != response.ManifestSHA256 || f.calls.Load() != 1 {
		t.Fatal("duplicate reexecuted", e)
	}
	if !bytes.Equal(beforeStore, brokerRead(t, filepath.Join(f.root, "store/ledger.json"))) || !bytes.Equal(beforeJournal, brokerRead(t, filepath.Join(f.journal, "journal.json"))) {
		t.Fatal("duplicate changed durable accounting")
	}
	called := false
	if e = f.b.AcknowledgeBridge(ctx, f.q, func() error { called = true; return errors.New("synthetic lost socket ACK") }); e == nil || !called {
		t.Fatal("lost ACK not observed")
	}
	if f.s.Snapshot().Healthy || f.s.Snapshot().ChargedBytes != snapshot.ChargedBytes {
		t.Fatal("ACK lost custody")
	}
	if _, _, e = f.b.HandleBridge(ctx, brokerQuery(f.q, "status"), nil); e == nil {
		t.Fatal("status bypassed unhealthy Store")
	}
	f.restart(t)
	status, _, e := f.b.HandleBridge(ctx, brokerQuery(f.q, "status"), nil)
	if e != nil || status.ManifestSHA256 != response.ManifestSHA256 || f.calls.Load() != 1 {
		t.Fatal("committed restart changed execution", e)
	}
	meta, receipt, e := f.b.HandleBridge(ctx, brokerQuery(f.q, "receipt"), nil)
	if e != nil || receipt == nil {
		t.Fatal("readback failed", e)
	}
	defer receipt.Close()
	raw, e := io.ReadAll(receipt)
	if e != nil || digest(raw) != meta.ReceiptSHA256 || int64(len(raw)) != meta.ReceiptBytes {
		t.Fatal("wrong receipt custody")
	}
	if _, _, e = f.b.HandleBridge(ctx, f.q, f.input); e != nil || f.calls.Load() != 1 {
		t.Fatal("restart duplicate replayed", e)
	}
	if !bytes.Equal(beforeStore, brokerRead(t, filepath.Join(f.root, "store/ledger.json"))) || !bytes.Equal(beforeJournal, brokerRead(t, filepath.Join(f.journal, "journal.json"))) {
		t.Fatal("readback changed retained history")
	}
}
func TestBrokerCrashGapsPreservePendingAndOnlySealActualCommit(t *testing.T) {
	for _, stage := range []string{"after_intent", "after_reserve", "after_link", "after_bind", "after_commit"} {
		t.Run(stage, func(t *testing.T) {
			f := newBrokerFixture(t, nil)
			f.b.fault = func(name string) error {
				if name == stage {
					return errors.New("synthetic crash")
				}
				return nil
			}
			if _, _, e := f.b.HandleBridge(context.Background(), f.q, f.input); e == nil {
				t.Fatal("crash ignored")
			}
			beforeJournal := brokerRead(t, filepath.Join(f.journal, "journal.json"))
			beforeStore := brokerRead(t, filepath.Join(f.root, "store/ledger.json"))
			calls := f.calls.Load()
			f.c.Close()
			f.c.registry.Close()
			f.b.lock.Close()
			f.b.root.Close()
			f.s.Close()
			s, e := Open(context.Background(), filepath.Join(f.root, "store"), NativeArtifactPolicy())
			if e != nil {
				t.Fatal(e)
			}
			f.s = s
			registry, e := NewInputRegistry(s)
			if stage != "after_intent" && stage != "after_commit" {
				if e == nil || s.Snapshot().Healthy {
					t.Fatal("pending history admitted registry")
				}
				if !bytes.Equal(beforeStore, brokerRead(t, filepath.Join(f.root, "store/ledger.json"))) || !bytes.Equal(beforeJournal, brokerRead(t, filepath.Join(f.journal, "journal.json"))) {
					t.Fatal("pending restart modified history")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			c, e := NewCoordinator(s, registry, fixtureProvider(func(context.Context, *ScopedInput, *Exporter) ProviderCompletion {
				t.Error("restart invoked provider")
				return ProviderCompletion{}
			}))
			if e != nil {
				t.Fatal(e)
			}
			f.c = c
			b, e := NewBroker(context.Background(), BrokerConfig{f.journal, f.q.ExpectedProfileSHA256}, c)
			if stage == "after_intent" {
				if e == nil {
					t.Fatal("intent adopted")
				}
				if !bytes.Equal(beforeJournal, brokerRead(t, filepath.Join(f.journal, "journal.json"))) {
					t.Fatal("intent was erased")
				}
				return
			}
			if e != nil {
				t.Fatal("fully committed prior binding not sealable", e)
			}
			f.b = b
			r, _, e := b.HandleBridge(context.Background(), brokerQuery(f.q, "status"), nil)
			if e != nil || r.State != "committed" || f.calls.Load() != calls {
				t.Fatal("commit readback reexecuted", e)
			}
			if !bytes.Equal(beforeStore, brokerRead(t, filepath.Join(f.root, "store/ledger.json"))) {
				t.Fatal("journal seal changed Store history")
			}
		})
	}
}
func TestBrokerJournalPersistenceFaultsNeverACKOrRerun(t *testing.T) {
	for _, point := range []string{"journal_write", "journal_file_sync", "journal_rename", "journal_directory_sync"} {
		t.Run(point, func(t *testing.T) {
			f := newBrokerFixture(t, nil)
			before := f.s.Snapshot()
			f.b.fault = func(p string) error {
				if p == point {
					return errors.New("synthetic persistence failure")
				}
				return nil
			}
			if _, _, e := f.b.HandleBridge(context.Background(), f.q, f.input); e == nil {
				t.Fatal("persistence failure ignored")
			}
			called := false
			if e := f.b.AcknowledgeBridge(context.Background(), f.q, func() error { called = true; return nil }); e == nil || called {
				t.Fatal("failed persistence ACKed")
			}
			if f.calls.Load() != 0 || f.s.Snapshot().Healthy || f.s.Snapshot().RetainedOrReservedJobs != before.RetainedOrReservedJobs {
				t.Fatal("intent failure invoked work or adopted store")
			}
		})
	}
}
func TestBrokerRejectsTupleFDAndProfileBeforeReservation(t *testing.T) {
	for _, kind := range []string{"profile", "hash", "size", "writable", "linked", "extra_fd", "invalid_name"} {
		t.Run(kind, func(t *testing.T) {
			f := newBrokerFixture(t, nil)
			q := f.q
			input := f.input
			var extra *os.File
			switch kind {
			case "profile":
				q.ExpectedProfileSHA256 = strings.Repeat("d", 64)
			case "hash":
				q.ProcessedSHA256 = strings.Repeat("0", 64)
			case "size":
				q.ProcessedBytes++
			case "writable":
				var e error
				extra, e = os.OpenFile(filepath.Join(f.root, "verified.fastq"), os.O_RDWR, 0)
				if e != nil {
					t.Fatal(e)
				}
				defer extra.Close()
				input = extra
			case "linked":
				if e := os.Link(filepath.Join(f.root, "verified.fastq"), filepath.Join(f.root, "second-link")); e != nil {
					t.Fatal(e)
				}
			case "extra_fd":
				q = brokerQuery(q, "status")
			case "invalid_name":
				q.OriginalName = strings.Repeat("x", 4097)
			}
			beforeStore := brokerRead(t, filepath.Join(f.root, "store/ledger.json"))
			beforeJournal := brokerRead(t, filepath.Join(f.journal, "journal.json"))
			if _, _, e := f.b.HandleBridge(context.Background(), q, input); e == nil {
				t.Fatal("unsafe input accepted")
			}
			if f.calls.Load() != 0 || !bytes.Equal(beforeStore, brokerRead(t, filepath.Join(f.root, "store/ledger.json"))) || !bytes.Equal(beforeJournal, brokerRead(t, filepath.Join(f.journal, "journal.json"))) {
				t.Fatal("preflight reserved or changed history")
			}
		})
	}
}
func TestBrokerChangedDuplicateCannotTakeAnotherLease(t *testing.T) {
	f := newBrokerFixture(t, nil)
	if _, _, e := f.b.HandleBridge(context.Background(), f.q, f.input); e != nil {
		t.Fatal(e)
	}
	before := brokerRead(t, filepath.Join(f.root, "store/ledger.json"))
	for _, field := range []string{"upload", "processed", "size", "name", "profile"} {
		q := f.q
		switch field {
		case "upload":
			q.UploadSHA256 = strings.Repeat("d", 64)
		case "processed":
			q.ProcessedSHA256 = strings.Repeat("d", 64)
		case "size":
			q.ProcessedBytes++
		case "name":
			q.OriginalName = "different"
		case "profile":
			q.ExpectedProfileSHA256 = strings.Repeat("d", 64)
		}
		if _, _, e := f.b.HandleBridge(context.Background(), q, f.input); e == nil {
			t.Fatal("changed tuple accepted", field)
		}
	}
	if f.calls.Load() != 1 || !bytes.Equal(before, brokerRead(t, filepath.Join(f.root, "store/ledger.json"))) {
		t.Fatal("conflict changed execution/accounting")
	}
}
func TestBrokerHistoryNoEmptyBaselineOrUnaccountedAdoption(t *testing.T) {
	for _, kind := range []string{"missing_journal", "extra_file", "profile", "binding", "lock"} {
		t.Run(kind, func(t *testing.T) {
			f := newBrokerFixture(t, nil)
			if _, _, e := f.b.HandleBridge(context.Background(), f.q, f.input); e != nil {
				t.Fatal(e)
			}
			f.b.Close()
			if e := f.b.Wait(context.Background()); e != nil {
				t.Fatal(e)
			}
			path := filepath.Join(f.journal, "journal.json")
			beforeStore := brokerRead(t, filepath.Join(f.root, "store/ledger.json"))
			switch kind {
			case "missing_journal":
				if e := os.Rename(path, filepath.Join(f.root, "preserved-journal.json")); e != nil {
					t.Fatal(e)
				}
			case "extra_file":
				if e := os.WriteFile(filepath.Join(f.journal, "unknown"), []byte("historical"), 0600); e != nil {
					t.Fatal(e)
				}
			case "profile", "binding":
				var j bridgeJournal
				if json.Unmarshal(brokerRead(t, path), &j) != nil {
					t.Fatal("decode")
				}
				if kind == "profile" {
					j.ProfileSHA256 = strings.Repeat("d", 64)
				} else {
					v := j.Records[f.q.JobID]
					v.ManifestSHA256 = strings.Repeat("d", 64)
					j.Records[f.q.JobID] = v
				}
				raw, _ := json.Marshal(j)
				if e := os.WriteFile(path, raw, 0600); e != nil {
					t.Fatal(e)
				}
			case "lock":
				if e := os.WriteFile(filepath.Join(f.journal, "instance.lock"), []byte("history"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			c, e := NewCoordinator(f.s, f.c.registry, fixtureProvider(successfulFixtureProvider))
			if e != nil {
				t.Fatal(e)
			}
			f.c = c
			if b, e := NewBroker(context.Background(), BrokerConfig{f.journal, f.q.ExpectedProfileSHA256}, c); e == nil {
				b.Close()
				t.Fatal("unknown history adopted")
			}
			if !bytes.Equal(beforeStore, brokerRead(t, filepath.Join(f.root, "store/ledger.json"))) {
				t.Fatal("history failure rewrote Store")
			}
		})
	}
}
func TestBrokerRealUnixSubmitReceiptAndCommitBeforeACK(t *testing.T) {
	f := newBrokerFixture(t, nil)
	uid := uint32(os.Geteuid())
	socket := filepath.Join(f.root, "channel", "bridge.sock")
	server, e := ListenBridgeUnix(UnixServerConfig{SocketPath: socket, AllowedUID: &uid}, f.b)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	defer func() { cancel(); server.Close(); <-done }()
	response, fd, e := CallBridgeUnix(context.Background(), socket, f.q, f.input)
	if e != nil || fd != nil || response.State != "committed" {
		t.Fatal("actual submit response failed", e)
	}
	if f.s.data.Records[response.LeaseID].ProofSHA256 == "" || f.b.data.Records[f.q.JobID].Stage != "committed" {
		t.Fatal("wire preceded proof/journal commit")
	}
	r, fd, e := CallBridgeUnix(context.Background(), socket, brokerQuery(f.q, "receipt"), nil)
	if e != nil || fd == nil {
		t.Fatal("actual receipt transfer failed", e)
	}
	defer fd.Close()
	raw, e := io.ReadAll(fd)
	if e != nil || digest(raw) != r.ReceiptSHA256 {
		t.Fatal("receipt descriptor mismatch")
	}
	if _, _, e = CallBridgeUnix(context.Background(), socket, f.q, f.input); e != nil || f.calls.Load() != 1 {
		t.Fatal("wire duplicate reran", e)
	}
}

func TestBrokerCannotACKCommittedStoreBeforeJournalSeal(t *testing.T) {
	f := newBrokerFixture(t, nil)
	reached, proceed := make(chan struct{}), make(chan struct{})
	var released atomic.Bool
	defer func() {
		if released.CompareAndSwap(false, true) {
			close(proceed)
		}
	}()
	f.b.fault = func(point string) error {
		if point == "before_commit_journal" {
			close(reached)
			<-proceed
		}
		return nil
	}
	done := make(chan error, 1)
	go func() { _, _, e := f.b.HandleBridge(context.Background(), f.q, f.input); done <- e }()
	select {
	case <-reached:
	case <-time.After(2 * time.Second):
		t.Fatal("commit barrier not reached")
	}
	// Provider has returned and Store has actually committed, while bridge state
	// remains linked. Neither a committed response nor an ACK may escape this gap.
	if _, _, e := f.b.HandleBridge(context.Background(), brokerQuery(f.q, "status"), nil); e == nil || e.Error() != "artifact_bridge_commit_pending" {
		t.Fatal("unsealed commit advertised", e)
	}
	called := false
	if e := f.b.AcknowledgeBridge(context.Background(), brokerQuery(f.q, "status"), func() error { called = true; return nil }); e == nil || called {
		t.Fatal("unsealed journal ACKed")
	}
	released.Store(true)
	close(proceed)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	if e := f.b.AcknowledgeBridge(context.Background(), f.q, func() error { called = true; return nil }); e != nil || !called {
		t.Fatal("sealed commit could not ACK", e)
	}
}

func TestBrokerACKRechecksStoreCommitUnderTheSameLock(t *testing.T) {
	started, continueProvider := make(chan struct{}), make(chan struct{})
	ackReached, continueACK := make(chan struct{}), make(chan struct{})
	commitReached, continueCommit := make(chan struct{}), make(chan struct{})
	for _, ch := range []chan struct{}{continueProvider, continueACK, continueCommit} {
		defer func(ch chan struct{}) {
			select {
			case <-ch:
			default:
				close(ch)
			}
		}(ch)
	}
	provider := fixtureProvider(func(ctx context.Context, in *ScopedInput, out *Exporter) ProviderCompletion {
		close(started)
		<-continueProvider
		return successfulFixtureProvider(ctx, in, out)
	})
	f := newBrokerFixture(t, provider)
	f.b.fault = func(point string) error {
		switch point {
		case "before_ack_store_lock":
			close(ackReached)
			<-continueACK
		case "before_commit_journal":
			close(commitReached)
			<-continueCommit
		}
		return nil
	}
	submitted := make(chan error, 1)
	go func() { _, _, e := f.b.HandleBridge(context.Background(), f.q, f.input); submitted <- e }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("provider barrier missing")
	}
	var called atomic.Bool
	acked := make(chan error, 1)
	go func() {
		acked <- f.b.AcknowledgeBridge(context.Background(), brokerQuery(f.q, "status"), func() error { called.Store(true); return nil })
	}()
	select {
	case <-ackReached:
	case <-time.After(2 * time.Second):
		t.Fatal("ACK barrier missing")
	}
	close(continueProvider)
	select {
	case <-commitReached:
	case <-time.After(2 * time.Second):
		t.Fatal("Store commit barrier missing")
	}
	close(continueACK)
	if e := <-acked; e == nil || e.Error() != "artifact_bridge_commit_pending" || called.Load() {
		t.Fatal("racing commit bypassed journal ACK guard", e)
	}
	if !f.s.Snapshot().Healthy {
		t.Fatal("benign pending ACK latched committed Store")
	}
	close(continueCommit)
	if e := <-submitted; e != nil {
		t.Fatal("final journal seal failed", e)
	}
}
