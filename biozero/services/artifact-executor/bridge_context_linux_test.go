//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package artifactexecutor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Actual Store/journal/socket tests with synthetic providers, without a kernel
// capsule or protected-entry verifier. Caller facts grant no crypto authority.
type brokerV2Fixture struct {
	*brokerFixture
	q2 BridgeRequestV2
}

func newBrokerV2Fixture(t *testing.T, provider Provider) *brokerV2Fixture {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	f := &brokerFixture{root: root, journal: filepath.Join(root, "bridge"), calls: new(atomic.Int32)}
	if provider == nil {
		provider = fixtureProvider(func(ctx context.Context, in *ScopedInput, out *Exporter) ProviderCompletion {
			f.calls.Add(1)
			if in.AnalysisContext == nil {
				t.Error("v2 facts absent from registry acquisition")
			}
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
	f.b, err = NewBrokerV2(context.Background(), BrokerConfig{f.journal, strings.Repeat("c", 64)}, f.c)
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
	f.q = BridgeRequest{1, "submit", strings.Repeat("a", 16), digest([]byte("ciphertext placeholder")), strings.Repeat("c", 64), digest(data), int64(len(data)), "synthetic.fastq"}
	facts := AnalysisContext{OriginalName: f.q.OriginalName, ProcessedSizeBytes: f.q.ProcessedBytes, Decrypted: true, SignatureValid: true}
	v := &brokerV2Fixture{f, BridgeRequestV2{2, f.q.Operation, f.q.JobID, f.q.UploadSHA256, f.q.ExpectedProfileSHA256, f.q.ProcessedSHA256, f.q.ProcessedBytes, f.q.OriginalName, facts}}
	t.Cleanup(func() {
		f.input.Close()
		f.c.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_ = f.b.Close()
		_ = f.b.Wait(ctx)
		cancel()
		f.b.lock.Close()
		f.b.root.Close()
		f.c.registry.Close()
		f.s.Close()
	})
	return v
}
func brokerQueryV2(q BridgeRequestV2, op string) BridgeRequestV2 {
	q.Operation = op
	q.ProcessedSHA256 = ""
	q.ProcessedBytes = 0
	q.OriginalName = ""
	q.AnalysisContext = AnalysisContext{}
	return q
}
func (f *brokerV2Fixture) stopFixture() {
	f.c.Close()
	f.c.registry.Close()
	f.b.lock.Close()
	f.b.root.Close()
	f.s.Close()
}
func (f *brokerV2Fixture) reopenCoordinator(t *testing.T) {
	t.Helper()
	s, e := Open(context.Background(), filepath.Join(f.root, "store"), NativeArtifactPolicy())
	if e != nil {
		t.Fatal(e)
	}
	f.s = s
	r, e := NewInputRegistry(s)
	if e != nil {
		t.Fatal(e)
	}
	f.c, e = NewCoordinator(s, r, fixtureProvider(func(context.Context, *ScopedInput, *Exporter) ProviderCompletion {
		f.calls.Add(1)
		panic("v2 recovery reexecuted provider")
	}))
	if e != nil {
		t.Fatal(e)
	}
}
func (f *brokerV2Fixture) restartV2(t *testing.T) {
	t.Helper()
	f.stopFixture()
	f.reopenCoordinator(t)
	b, e := NewBrokerV2(context.Background(), BrokerConfig{f.journal, f.q2.ExpectedProfileSHA256}, f.c)
	if e != nil {
		t.Fatal(e)
	}
	f.b = b
}

func TestBridgeV2StrictContextCodec(t *testing.T) {
	f := newBrokerV2Fixture(t, nil)
	raw, e := json.Marshal(f.q2)
	if e != nil {
		t.Fatal(e)
	}
	var q BridgeRequestV2
	if strictJSON(raw, &q) != nil || validateBridgeRequestV2(q) != nil {
		t.Fatal("valid v2 failed")
	}
	for name, change := range map[string]func(map[string]any){
		"missing_context": func(m map[string]any) { delete(m, "analysis_context") },
		"null_context":    func(m map[string]any) { m["analysis_context"] = nil },
		"unknown_context": func(m map[string]any) { m["analysis_context"].(map[string]any)["executable"] = "/bin/sh" },
		"missing_fact":    func(m map[string]any) { delete(m["analysis_context"].(map[string]any), "decrypted") },
		"null_fact":       func(m map[string]any) { m["analysis_context"].(map[string]any)["signature_valid"] = nil },
		"size_mismatch":   func(m map[string]any) { m["analysis_context"].(map[string]any)["processed_size_bytes"] = float64(1) },
		"name_mismatch":   func(m map[string]any) { m["analysis_context"].(map[string]any)["original_name"] = "other.fastq" },
		"version_one":     func(m map[string]any) { m["schema_version"] = float64(1) },
	} {
		t.Run(name, func(t *testing.T) {
			var m map[string]any
			if json.Unmarshal(raw, &m) != nil {
				t.Fatal("fixture")
			}
			change(m)
			b, _ := json.Marshal(m)
			var invalid BridgeRequestV2
			if strictJSON(b, &invalid) == nil && validateBridgeRequestV2(invalid) == nil {
				t.Fatal("accepted invalid fixed context")
			}
		})
	}
	duplicate := bytes.Replace(raw, []byte(`"decrypted":true`), []byte(`"decrypted":true,"decrypted":true`), 1)
	if strictJSON(duplicate, &q) == nil {
		t.Fatal("duplicate fact accepted")
	}
	query := brokerQueryV2(f.q2, "status")
	query.AnalysisContext.SignatureValid = true
	if validateBridgeRequestV2(query) == nil {
		t.Fatal("query replaced context")
	}
	if validateBridgeResponseV2(f.q2, bridgeErrorResponseV2("fixture_failed")) != nil || validateBridgeResponseV2(f.q2, bridgeErrorResponse("fixture_failed")) == nil {
		t.Fatal("response version not fixed")
	}
}

func TestBrokerV2ContextBindingDuplicateConflictAndLostACK(t *testing.T) {
	var seen AnalysisContext
	f := newBrokerV2Fixture(t, fixtureProvider(func(ctx context.Context, in *ScopedInput, out *Exporter) ProviderCompletion {
		if in.AnalysisContext == nil {
			t.Fatal("missing context")
		}
		seen = *in.AnalysisContext
		return successfulFixtureProvider(ctx, in, out)
	}))
	r, fd, e := f.b.HandleBridgeV2(context.Background(), f.q2, f.input)
	if e != nil || fd != nil || r.SchemaVersion != 2 || r.State != "committed" || seen != f.q2.AnalysisContext {
		t.Fatal("facts not preserved", e)
	}
	journal := brokerRead(t, filepath.Join(f.journal, "journal.json"))
	ledger := brokerRead(t, filepath.Join(f.root, "store/ledger.json"))
	again, _, e := f.b.HandleBridgeV2(context.Background(), f.q2, f.input)
	if e != nil || again.LeaseID != r.LeaseID {
		t.Fatal("duplicate changed custody", e)
	}
	for _, mutate := range []func(*AnalysisContext){func(c *AnalysisContext) { c.Decrypted = false }, func(c *AnalysisContext) { c.SignatureValid = false }, func(c *AnalysisContext) { c.Decrypted = false; c.DecryptionError = "fixture_decryption_failed" }, func(c *AnalysisContext) { c.SignatureValid = false; c.SignatureError = "fixture_signature_failed" }} {
		changed := f.q2
		mutate(&changed.AnalysisContext)
		if _, _, e = f.b.HandleBridgeV2(context.Background(), changed, f.input); e == nil || e.Error() != "artifact_bridge_conflict" {
			t.Fatal("changed facts not rejected", e)
		}
		called := false
		if e = f.b.AcknowledgeBridgeV2(context.Background(), changed, func() error { called = true; return nil }); e == nil || called {
			t.Fatal("changed-fact ACK accepted")
		}
	}
	if !bytes.Equal(journal, brokerRead(t, filepath.Join(f.journal, "journal.json"))) || !bytes.Equal(ledger, brokerRead(t, filepath.Join(f.root, "store/ledger.json"))) {
		t.Fatal("duplicate/conflict mutated history")
	}
	if _, _, e = f.b.HandleBridge(context.Background(), brokerQuery(f.q, "status"), nil); e == nil {
		t.Fatal("v1 query bypassed v2")
	}
	if e = f.b.AcknowledgeBridge(context.Background(), brokerQuery(f.q, "status"), func() error { return nil }); e == nil {
		t.Fatal("v1 ACK bypassed v2")
	}
	called := false
	if e = f.b.AcknowledgeBridgeV2(context.Background(), f.q2, func() error { called = true; return errors.New("lost wire") }); e == nil || !called {
		t.Fatal("missing lost ACK")
	}
	if _, _, e = f.b.HandleBridgeV2(context.Background(), brokerQueryV2(f.q2, "status"), nil); e == nil {
		t.Fatal("bypassed unhealthy Store")
	}
	f.restartV2(t)
	status, _, e := f.b.HandleBridgeV2(context.Background(), brokerQueryV2(f.q2, "status"), nil)
	if e != nil || status.LeaseID != r.LeaseID || status.ManifestSHA256 != r.ManifestSHA256 {
		t.Fatal("restart changed custody", e)
	}
	if !bytes.Equal(journal, brokerRead(t, filepath.Join(f.journal, "journal.json"))) || !bytes.Equal(ledger, brokerRead(t, filepath.Join(f.root, "store/ledger.json"))) {
		t.Fatal("restart modified committed history")
	}
	if _, _, e = f.b.HandleBridgeV2(context.Background(), f.q2, f.input); e != nil {
		t.Fatal("duplicate after recovery", e)
	}
}

func TestBrokerV2RefusesHistoryContextMismatch(t *testing.T) {
	changes := map[string]func(*bridgeJournalV2){
		"missing": func(j *bridgeJournalV2) { delete(j.AnalysisContexts, strings.Repeat("a", 16)) },
		"extra":   func(j *bridgeJournalV2) { j.AnalysisContexts[strings.Repeat("b", 16)] = AnalysisContext{} },
		"wrong_key": func(j *bridgeJournalV2) {
			j.AnalysisContexts[strings.Repeat("b", 16)] = j.AnalysisContexts[strings.Repeat("a", 16)]
			delete(j.AnalysisContexts, strings.Repeat("a", 16))
		},
		"wrong_size": func(j *bridgeJournalV2) {
			c := j.AnalysisContexts[strings.Repeat("a", 16)]
			c.ProcessedSizeBytes++
			j.AnalysisContexts[strings.Repeat("a", 16)] = c
		},
		"wrong_name": func(j *bridgeJournalV2) {
			c := j.AnalysisContexts[strings.Repeat("a", 16)]
			c.OriginalName = "other.fastq"
			j.AnalysisContexts[strings.Repeat("a", 16)] = c
		},
		"null_map":    func(j *bridgeJournalV2) { j.AnalysisContexts = nil },
		"version_one": func(j *bridgeJournalV2) { j.SchemaVersion = 1 },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			f := newBrokerV2Fixture(t, nil)
			if _, _, e := f.b.HandleBridgeV2(context.Background(), f.q2, f.input); e != nil {
				t.Fatal(e)
			}
			f.stopFixture()
			var j bridgeJournalV2
			if json.Unmarshal(brokerRead(t, filepath.Join(f.journal, "journal.json")), &j) != nil {
				t.Fatal("fixture")
			}
			change(&j)
			raw, _ := json.Marshal(j)
			if os.WriteFile(filepath.Join(f.journal, "journal.json"), raw, 0600) != nil {
				t.Fatal("fixture write")
			}
			f.reopenCoordinator(t)
			if b, e := NewBrokerV2(context.Background(), BrokerConfig{f.journal, f.q2.ExpectedProfileSHA256}, f.c); e == nil {
				b.Close()
				t.Fatal("adopted mismatched history")
			}
			if !bytes.Equal(raw, brokerRead(t, filepath.Join(f.journal, "journal.json"))) {
				t.Fatal("rejected history rewritten")
			}
		})
	}
}

func TestBrokerV2HistoryNeverMigratesAcrossVersions(t *testing.T) {
	t.Run("v1_to_v2", func(t *testing.T) {
		f := newBrokerFixture(t, nil)
		f.b.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if e := f.b.Wait(ctx); e != nil {
			t.Fatal(e)
		}
		r, e := NewInputRegistry(f.s)
		if e != nil {
			t.Fatal(e)
		}
		c, e := NewCoordinator(f.s, r, fixtureProvider(successfulFixtureProvider))
		if e != nil {
			t.Fatal(e)
		}
		defer c.Close()
		defer r.Close()
		if _, e = NewBrokerV2(context.Background(), BrokerConfig{f.journal, f.q.ExpectedProfileSHA256}, c); e == nil {
			t.Fatal("adopted legacy baseline")
		}
	})
	t.Run("v2_to_v1", func(t *testing.T) {
		f := newBrokerV2Fixture(t, nil)
		f.stopFixture()
		f.reopenCoordinator(t)
		if _, e := NewBroker(context.Background(), BrokerConfig{f.journal, f.q.ExpectedProfileSHA256}, f.c); e == nil {
			t.Fatal("legacy adopted v2")
		}
	})
}

func TestBrokerV2ContextIntentPrecedesReserveAndCrashRecovery(t *testing.T) {
	for _, point := range []string{"after_intent", "after_reserve", "after_link", "after_bind", "after_commit"} {
		t.Run(point, func(t *testing.T) {
			f := newBrokerV2Fixture(t, nil)
			f.b.fault = func(p string) error {
				if p != point {
					return nil
				}
				var j bridgeJournalV2
				if strictJSON(brokerRead(t, filepath.Join(f.journal, "journal.json")), &j) != nil || j.AnalysisContexts[f.q2.JobID] != f.q2.AnalysisContext {
					t.Error("facts not durable at barrier")
				}
				if p == "after_intent" && f.s.Snapshot().RetainedOrReservedJobs != 0 {
					t.Error("Reserve preceded intent")
				}
				return errors.New("crash")
			}
			if _, _, e := f.b.HandleBridgeV2(context.Background(), f.q2, f.input); e == nil {
				t.Fatal("fault ignored")
			}
			raw := brokerRead(t, filepath.Join(f.journal, "journal.json"))
			ledger := brokerRead(t, filepath.Join(f.root, "store/ledger.json"))
			f.stopFixture()
			if point != "after_intent" && point != "after_commit" {
				reopened, e := Open(context.Background(), filepath.Join(f.root, "store"), NativeArtifactPolicy())
				if e != nil {
					t.Fatal(e)
				}
				f.s = reopened
				if r, e := NewInputRegistry(reopened); e == nil {
					r.Close()
					t.Fatal("pending history admitted registry")
				}
				if reopened.Snapshot().Healthy || !bytes.Equal(raw, brokerRead(t, filepath.Join(f.journal, "journal.json"))) || !bytes.Equal(ledger, brokerRead(t, filepath.Join(f.root, "store/ledger.json"))) {
					t.Fatal("pending history lost custody or changed bytes")
				}
				return
			}
			f.reopenCoordinator(t)
			b, e := NewBrokerV2(context.Background(), BrokerConfig{f.journal, f.q2.ExpectedProfileSHA256}, f.c)
			if point == "after_commit" {
				if e != nil {
					t.Fatal("verified committed-only restart failed", e)
				}
				f.b = b
				if _, _, e = b.HandleBridgeV2(context.Background(), brokerQueryV2(f.q2, "status"), nil); e != nil {
					t.Fatal(e)
				}
			} else {
				if e == nil {
					b.Close()
					t.Fatal("pending history adopted")
				}
				if !bytes.Equal(raw, brokerRead(t, filepath.Join(f.journal, "journal.json"))) {
					t.Fatal("ambiguous history rewritten")
				}
			}
		})
	}
}

func TestBridgeV2RealSocketFDAndFixedVersion(t *testing.T) {
	f := newBrokerV2Fixture(t, nil)
	uid := uint32(os.Geteuid())
	socket := filepath.Join(f.root, "socket", "bridge.sock")
	s, e := ListenBridgeUnixV2(UnixServerConfig{SocketPath: socket, AllowedUID: &uid}, f.b)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ended := make(chan error, 1)
	go func() { ended <- s.Serve(ctx) }()
	defer func() {
		cancel()
		s.Close()
		if e := <-ended; e != nil {
			t.Error(e)
		}
	}()
	r, fd, e := CallBridgeUnixV2(context.Background(), socket, f.q2, f.input)
	if e != nil || fd != nil || r.SchemaVersion != 2 || r.State != "committed" {
		t.Fatal("submit failed", e)
	}
	rr, fd, e := CallBridgeUnixV2(context.Background(), socket, brokerQueryV2(f.q2, "receipt"), nil)
	if e != nil || fd == nil {
		t.Fatal("receipt failed", e)
	}
	defer fd.Close()
	raw, e := io.ReadAll(fd)
	if e != nil || digest(raw) != rr.ReceiptSHA256 {
		t.Fatal("receipt mismatch")
	}
	if _, _, e = CallBridgeUnix(context.Background(), socket, brokerQuery(f.q, "status"), nil); e == nil {
		t.Fatal("v1 client accepted v2 listener")
	}
	conn, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: socket, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Second))
	invalid, _ := json.Marshal(brokerQuery(f.q, "status"))
	if e = bridgeWriteFrame(conn, invalid, nil); e != nil {
		t.Fatal(e)
	}
	data, output, e := bridgeReadFrame(conn)
	if output != nil {
		output.Close()
		t.Fatal("error leaked FD")
	}
	var response BridgeResponse
	if e != nil || strictJSON(data, &response) != nil || response.SchemaVersion != 2 || response.ErrorCode == "" {
		t.Fatal("v2 error version not fixed", e)
	}
	if f.calls.Load() != 1 {
		t.Fatal("socket duplicate/rejection reran provider")
	}
}

func TestBrokerV2CannotACKCommittedStoreBeforeJournalSeal(t *testing.T) {
	f := newBrokerV2Fixture(t, nil)
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
	go func() { _, _, e := f.b.HandleBridgeV2(context.Background(), f.q2, f.input); done <- e }()
	select {
	case <-reached:
	case <-time.After(2 * time.Second):
		t.Fatal("commit barrier not reached")
	}
	// Provider has returned and Store has actually committed, while bridge state
	// remains linked. Neither a committed response nor an ACK may escape this gap.
	if _, _, e := f.b.HandleBridgeV2(context.Background(), brokerQueryV2(f.q2, "status"), nil); e == nil || e.Error() != "artifact_bridge_commit_pending" {
		t.Fatal("unsealed commit advertised", e)
	}
	called := false
	if e := f.b.AcknowledgeBridgeV2(context.Background(), brokerQueryV2(f.q2, "status"), func() error { called = true; return nil }); e == nil || called {
		t.Fatal("unsealed journal ACKed")
	}
	released.Store(true)
	close(proceed)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	if e := f.b.AcknowledgeBridgeV2(context.Background(), f.q2, func() error { called = true; return nil }); e != nil || !called {
		t.Fatal("sealed commit could not ACK", e)
	}
}

func TestBrokerV2ACKRechecksStoreCommitUnderTheSameLock(t *testing.T) {
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
	f := newBrokerV2Fixture(t, provider)
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
	go func() { _, _, e := f.b.HandleBridgeV2(context.Background(), f.q2, f.input); submitted <- e }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("provider barrier missing")
	}
	var called atomic.Bool
	acked := make(chan error, 1)
	go func() {
		acked <- f.b.AcknowledgeBridgeV2(context.Background(), brokerQueryV2(f.q2, "status"), func() error { called.Store(true); return nil })
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

func TestBridgeV2CannotUseLegacyListenerOrChangedProfile(t *testing.T) {
	var calls atomic.Int32
	_, socket := bridgeTestStart(t, UnixServerConfig{}, bridgeTestHandler(func(ctx context.Context, q BridgeRequest, in *os.File) (BridgeResponse, *os.File, error) {
		calls.Add(1)
		return bridgeTestResponse(q), nil, nil
	}))
	f := newBrokerV2Fixture(t, nil)
	if _, _, e := CallBridgeUnixV2(context.Background(), socket, brokerQueryV2(f.q2, "status"), nil); e == nil {
		t.Fatal("v2 accepted v1 response/listener")
	}
	if calls.Load() != 0 {
		t.Fatal("legacy listener dispatched v2")
	}
	q := f.q2
	q.ExpectedProfileSHA256 = strings.Repeat("d", 64)
	if _, _, e := f.b.HandleBridgeV2(context.Background(), q, f.input); e == nil || e.Error() != "artifact_bridge_profile_mismatch" {
		t.Fatal("submit profile mismatch admitted", e)
	}
	if f.s.Snapshot().RetainedOrReservedJobs != 0 {
		t.Fatal("profile mismatch reserved")
	}
	if _, _, e := f.b.HandleBridgeV2(context.Background(), f.q2, f.input); e != nil {
		t.Fatal(e)
	}
	for _, op := range []string{"status", "cancel", "receipt"} {
		q := brokerQueryV2(f.q2, op)
		q.ExpectedProfileSHA256 = strings.Repeat("d", 64)
		if _, _, e := f.b.HandleBridgeV2(context.Background(), q, nil); e == nil || e.Error() != "artifact_bridge_profile_mismatch" {
			t.Fatal("query bypassed profile", op, e)
		}
		called := false
		if e := f.b.AcknowledgeBridgeV2(context.Background(), q, func() error { called = true; return nil }); e == nil || called {
			t.Fatal("ACK bypassed profile", op)
		}
	}
}

func TestBrokerV2JournalPersistenceFaultsPreserveIntentContext(t *testing.T) {
	for _, point := range []string{"journal_write", "journal_file_sync", "journal_rename", "journal_directory_sync"} {
		t.Run(point, func(t *testing.T) {
			f := newBrokerV2Fixture(t, nil)
			f.b.fault = func(p string) error {
				if p == point {
					return errors.New("storage fault")
				}
				return nil
			}
			if _, _, e := f.b.HandleBridgeV2(context.Background(), f.q2, f.input); e == nil {
				t.Fatal("persistence fault ignored")
			}
			if f.s.Snapshot().Healthy || f.s.Snapshot().RetainedOrReservedJobs != 0 || f.calls.Load() != 0 {
				t.Fatal("fault admitted work or cleared health")
			}
			if f.b.analysisContexts[f.q2.JobID] != f.q2.AnalysisContext {
				t.Fatal("intent context disappeared")
			}
			if _, _, e := f.b.HandleBridgeV2(context.Background(), f.q2, f.input); e == nil {
				t.Fatal("faulted broker admitted retry")
			}
		})
	}
}
