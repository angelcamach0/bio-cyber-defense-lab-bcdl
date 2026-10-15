//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package artifactexecutor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	ownership "biozero/ownership-authority"
)

// Real signatures, authority Store and artifact files; the TLS state in this
// fixture is built from an x509-verified chain, not an observed TLS handshake.
// Providers are synthetic. Independent security tests use actual mTLS as well.
var ownerTestOnce sync.Once
var ownerTestSigner ed25519.PrivateKey
var ownerTestPin ownership.AuthorityPin
var ownerTestKey, ownerTestRecipient *rsa.PrivateKey
var ownerTestLeaf *x509.Certificate
var ownerTestState tls.ConnectionState

func ownerTestKeys(t *testing.T) {
	t.Helper()
	ownerTestOnce.Do(func() {
		var e error
		ownerTestKey, e = rsa.GenerateKey(rand.Reader, 2048)
		if e != nil {
			t.Fatal(e)
		}
		ownerTestRecipient, e = rsa.GenerateKey(rand.Reader, 2048)
		if e != nil {
			t.Fatal(e)
		}
		now := time.Now()
		caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "owner-unit-ca"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
		der, e := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &ownerTestKey.PublicKey, ownerTestKey)
		if e != nil {
			t.Fatal(e)
		}
		ca, e := x509.ParseCertificate(der)
		if e != nil {
			t.Fatal(e)
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "owner-unit-client"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		der, e = x509.CreateCertificate(rand.Reader, leaf, ca, &ownerTestKey.PublicKey, ownerTestKey)
		if e != nil {
			t.Fatal(e)
		}
		ownerTestLeaf, e = x509.ParseCertificate(der)
		if e != nil {
			t.Fatal(e)
		}
		pool := x509.NewCertPool()
		pool.AddCert(ca)
		chains, e := ownerTestLeaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
		if e != nil {
			t.Fatal(e)
		}
		ownerTestState = tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true, PeerCertificates: []*x509.Certificate{ownerTestLeaf}, VerifiedChains: chains}
		pub, key, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		ownerTestSigner = key
		ownerTestPin = ownership.AuthorityPin{AuthorityID: strings.Repeat("1", 32), PublicKey: pub, PipelineMode: "stats", ExecutionProfileSHA256: strings.Repeat("c", 64)}
	})
}

type ownerTestFixture struct {
	b                 *Broker
	s                 *Store
	c                 *Coordinator
	cfg               OwnerBrokerConfig
	q                 BridgeRequestV3
	root              string
	plain, acceptance *os.File
	raw, body         []byte
	calls             atomic.Int32
}

func ownerTestFile(t *testing.T, path string, data []byte) *os.File {
	t.Helper()
	if e := os.WriteFile(path, data, 0600); e != nil {
		t.Fatal(e)
	}
	f, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { f.Close() })
	return f
}
func ownerTestProvider(f *ownerTestFixture) Provider {
	return fixtureProvider(func(ctx context.Context, in *ScopedInput, out *Exporter) ProviderCompletion {
		f.calls.Add(1)
		if in.AnalysisContext == nil {
			return ProviderCompletion{Quiescent: true, Err: errors.New("missing context")}
		}
		if _, e := in.CopyTo(ctx, io.Discard); e != nil {
			return ProviderCompletion{Quiescent: true, Err: e}
		}
		raw := []byte(`{"synthetic_provider":true}`)
		if e := out.Export("execution_receipt", digest(raw), bytes.NewReader(raw)); e != nil {
			return ProviderCompletion{Quiescent: true, Err: e}
		}
		return ProviderCompletion{Quiescent: true, Outcome: Outcome{ExecutionStatus: "succeeded", ReleaseStatus: "unassessed"}}
	})
}
func ownerTestEngine(t *testing.T, f *ownerTestFixture) {
	t.Helper()
	var e error
	f.s, e = Open(context.Background(), filepath.Join(f.root, "store"), NativeArtifactPolicy())
	if e != nil {
		t.Fatal(e)
	}
	r, e := NewInputRegistry(f.s)
	if e != nil {
		t.Fatal(e)
	}
	f.c, e = NewCoordinator(f.s, r, ownerTestProvider(f))
	if e != nil {
		t.Fatal(e)
	}
}
func ownerTestDestroy(b *Broker) {
	if b == nil {
		return
	}
	b.Close()
	ctx, stop := context.WithTimeout(context.Background(), time.Second)
	b.Wait(ctx)
	stop()
	// Test-only process-exit simulation for known in-process fake providers.
	if b.owner != nil {
		if b.owner.sidecars != nil {
			b.owner.sidecars.Close()
		}
		if b.owner.rawHeld {
			syscall.Close(b.owner.rawFD)
			b.owner.rawHeld = false
		}
	}
	if b.lock != nil {
		b.lock.Close()
	}
	if b.root != nil {
		b.root.Close()
	}
}
func newOwnerTestFixture(t *testing.T) *ownerTestFixture {
	t.Helper()
	ownerTestKeys(t)
	root := t.TempDir()
	os.Chmod(root, 0700)
	f := &ownerTestFixture{root: root, body: []byte("@owner\nACGT\n+\nIIII\n")}
	policy := ownership.DefaultStorePolicy()
	policy.MaxBodyBytes = 4096
	policy.FreeSpaceFloorBytes = 0
	a, e := ownership.CreateStore(ownership.StoreConfig{Directory: filepath.Join(root, "authority"), Namespace: "broker-unit", Pin: ownerTestPin, SigningKey: ownerTestSigner, Policy: policy})
	if e != nil {
		t.Fatal(e)
	}
	request := make([]byte, 16)
	rand.Read(request)
	now := time.Now().UTC().Truncate(time.Second)
	challenge, e := a.Reserve(&ownerTestState, hex.EncodeToString(request), "owner.fastq", now)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := ownership.MarshalChallenge(challenge)
	if e != nil {
		t.Fatal(e)
	}
	p, e := ownership.EncryptForChallenge(raw, ownerTestPin, ownerTestLeaf, ownerTestKey, &ownerTestRecipient.PublicKey, f.body, now)
	if e != nil {
		t.Fatal(e)
	}
	signed, e := a.Finalize(context.Background(), &ownerTestState, raw, p.Manifest, bytes.NewReader(p.Ciphertext), now)
	if e != nil {
		t.Fatal(e)
	}
	f.raw, e = ownership.MarshalAcceptance(signed)
	if e != nil {
		t.Fatal(e)
	}
	verified, e := ownership.VerifyAcceptance(f.raw, ownerTestPin, a.Scope())
	if e != nil {
		t.Fatal(e)
	}
	f.cfg = OwnerBrokerConfig{filepath.Join(root, "journal"), ownerTestPin.ExecutionProfileSHA256, ownerTestPin, a.Scope()}
	if e = a.Close(); e != nil {
		t.Fatal(e)
	}
	f.q = BridgeRequestV3{SchemaVersion: 3, Operation: "submit", JobID: verified.Binding().JobID, UploadSHA256: verified.Binding().CiphertextSHA256, ExpectedProfileSHA256: f.cfg.ProfileSHA256, ProcessedSHA256: digest(f.body), ProcessedBytes: int64(len(f.body)), OriginalName: "owner.fastq", AnalysisContext: AnalysisContext{OriginalName: "owner.fastq", ProcessedSizeBytes: int64(len(f.body)), Decrypted: true, SignatureValid: true}, AcceptanceSHA256: verified.SHA256(), AcceptanceBytes: int64(len(f.raw))}
	f.plain = ownerTestFile(t, filepath.Join(root, "plain"), f.body)
	f.acceptance = ownerTestFile(t, filepath.Join(root, "accepted"), f.raw)
	ownerTestEngine(t, f)
	f.b, e = CreateBrokerV3(context.Background(), f.cfg, f.c)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { ownerTestDestroy(f.b); f.c.registry.Close(); f.s.Close() })
	return f
}
func ownerTestQuery(q BridgeRequestV3, op string) BridgeRequestV3 {
	q.Operation = op
	q.ProcessedSHA256 = ""
	q.ProcessedBytes = 0
	q.OriginalName = ""
	q.AnalysisContext = AnalysisContext{}
	q.AcceptanceBytes = 0
	return q
}
func ownerTestRestart(t *testing.T, f *ownerTestFixture) {
	t.Helper()
	ownerTestDestroy(f.b)
	if e := f.c.registry.Close(); e != nil {
		t.Fatal(e)
	}
	if e := f.s.Close(); e != nil {
		t.Fatal(e)
	}
	ownerTestEngine(t, f)
	var e error
	f.b, e = OpenBrokerV3(context.Background(), f.cfg, f.c)
	if e != nil {
		t.Fatal(e)
	}
}
func TestOwnerBrokerIntentSidecarPrecedesReserveAndCommittedRestart(t *testing.T) {
	f := newOwnerTestFixture(t)
	seen := false
	f.b.fault = func(point string) error {
		if point == "after_intent" {
			seen = true
			if f.s.Snapshot().RetainedOrReservedJobs != 0 {
				t.Error("Reserve preceded durable owner intent")
			}
			raw := brokerRead(t, filepath.Join(f.cfg.JournalRoot, "journal.json"))
			var j bridgeJournalV3
			if strictJSON(raw, &j) != nil || j.OwnerBindings[f.q.JobID].AcceptanceSHA256 != f.q.AcceptanceSHA256 {
				t.Error("owner binding absent at intent barrier")
			}
			if !bytes.Equal(brokerRead(t, filepath.Join(f.cfg.JournalRoot, "acceptances", f.q.AcceptanceSHA256+".json")), f.raw) {
				t.Error("canonical sidecar not durable at intent barrier")
			}
		}
		return nil
	}
	r, fd, e := f.b.HandleBridgeV3(context.Background(), f.q, f.plain, f.acceptance)
	if e != nil || fd != nil || !seen || r.Execution.State != "committed" || validateBridgeResponseV3(f.q, r) != nil || f.calls.Load() != 1 {
		t.Fatal("owned execution", e)
	}
	snapshot := f.s.Snapshot()
	f.b.fault = nil
	ownerTestRestart(t, f)
	got, fd, e := f.b.HandleBridgeV3(context.Background(), ownerTestQuery(f.q, "status"), nil, nil)
	if e != nil || fd != nil || !reflect.DeepEqual(got, r) || f.calls.Load() != 1 || f.s.Snapshot().ChargedBytes != snapshot.ChargedBytes {
		t.Fatal("recovery changed owned commit", e)
	}
	dup, fd, e := f.b.HandleBridgeV3(context.Background(), f.q, f.plain, f.acceptance)
	if e != nil || fd != nil || !reflect.DeepEqual(dup, r) || f.calls.Load() != 1 {
		t.Fatal("duplicate reran", e)
	}
}
func TestOwnerBrokerRejectsChangedFactsWithoutNewCharge(t *testing.T) {
	for _, kind := range []string{"acceptance", "job", "upload", "name", "context", "bytes", "profile", "whitespace"} {
		t.Run(kind, func(t *testing.T) {
			f := newOwnerTestFixture(t)
			q := f.q
			fd := f.acceptance
			switch kind {
			case "acceptance":
				q.AcceptanceSHA256 = strings.Repeat("e", 64)
			case "job":
				q.JobID = strings.Repeat("e", 16)
			case "upload":
				q.UploadSHA256 = strings.Repeat("e", 64)
			case "name":
				q.OriginalName = "different"
				q.AnalysisContext.OriginalName = q.OriginalName
			case "context":
				q.AnalysisContext.Decrypted = false
			case "bytes":
				q.AcceptanceBytes--
			case "profile":
				q.ExpectedProfileSHA256 = strings.Repeat("e", 64)
			case "whitespace":
				var v any
				json.Unmarshal(f.raw, &v)
				raw, _ := json.MarshalIndent(v, "", "  ")
				fd = ownerTestFile(t, filepath.Join(f.root, "noncanonical"), raw)
				q.AcceptanceBytes = int64(len(raw))
			}
			before := f.s.Snapshot()
			if _, out, e := f.b.HandleBridgeV3(context.Background(), q, f.plain, fd); e == nil || out != nil {
				t.Fatal("changed facts accepted")
			}
			if f.s.Snapshot() != before || f.calls.Load() != 0 || len(f.b.owner.bindings) != 0 {
				t.Fatal("rejection consumed custody")
			}
		})
	}
}
func TestOwnerBrokerPublicationFaultKeepsRawLockAndNeverReserves(t *testing.T) {
	for _, point := range []string{"owner_before_sidecar", "owner_sidecar_file_sync", "owner_pending_directory_sync", "owner_sidecar_link", "owner_sidecar_directory_sync", "journal_write", "journal_file_sync", "journal_rename", "journal_directory_sync"} {
		t.Run(point, func(t *testing.T) {
			f := newOwnerTestFixture(t)
			f.b.fault = func(p string) error {
				if p == point {
					return errors.New("injected")
				}
				return nil
			}
			if _, out, e := f.b.HandleBridgeV3(context.Background(), f.q, f.plain, f.acceptance); e == nil || out != nil {
				t.Fatal("publication fault accepted")
			}
			if !f.b.owner.rawHeld || !f.b.sticky || f.s.Snapshot().RetainedOrReservedJobs != 0 || f.calls.Load() != 0 {
				t.Fatal("uncertain publication released/reserved")
			}
			if point == "owner_pending_directory_sync" {
				pending := filepath.Join(f.cfg.JournalRoot, "acceptances", "acceptance.pending")
				if !bytes.Equal(brokerRead(t, pending), f.raw) {
					t.Fatal("pending sync failure lost original canonical acceptance")
				}
				if _, err := os.Lstat(filepath.Join(f.cfg.JournalRoot, "acceptances", f.q.AcceptanceSHA256+".json")); !os.IsNotExist(err) {
					t.Fatal("pending sync failure published final sidecar")
				}
				var journal bridgeJournalV3
				if strictJSON(brokerRead(t, filepath.Join(f.cfg.JournalRoot, "journal.json")), &journal) != nil || len(journal.Records) != 0 || len(journal.OwnerBindings) != 0 {
					t.Fatal("pending sync failure published owner intent")
				}
			}
			if other, e := OpenBrokerV3(context.Background(), f.cfg, f.c); e == nil {
				ownerTestDestroy(other)
				t.Fatal("live uncertain writer reopened")
			}
		})
	}
}
func TestOwnerBrokerACKRechecksJournalAndSidecars(t *testing.T) {
	for _, kind := range []string{"sidecar", "journal"} {
		t.Run(kind, func(t *testing.T) {
			f := newOwnerTestFixture(t)
			r, _, e := f.b.HandleBridgeV3(context.Background(), f.q, f.plain, f.acceptance)
			if e != nil {
				t.Fatal(e)
			}
			before := f.s.Snapshot().ChargedBytes
			f.b.fault = func(point string) error {
				if point == "before_ack_store_lock" {
					path := filepath.Join(f.cfg.JournalRoot, "journal.json")
					if kind == "sidecar" {
						path = filepath.Join(f.cfg.JournalRoot, "acceptances", f.q.AcceptanceSHA256+".json")
					}
					if e := os.WriteFile(path, []byte("preserve tamper"), 0600); e != nil {
						t.Error(e)
					}
				}
				return nil
			}
			called := false
			e = f.b.AcknowledgeBridgeV3(context.Background(), f.q, func() error { called = true; return nil })
			if e == nil || called || !f.b.sticky || f.s.Snapshot().ChargedBytes != before || r.Execution.LeaseID == "" {
				t.Fatal("ACK bypassed changed ownership custody")
			}
		})
	}
}
func TestOwnerBridgeRealSocketTwoFDAndQueryReceipt(t *testing.T) {
	f := newOwnerTestFixture(t)
	socket := filepath.Join(f.root, "owner.sock")
	uid := uint32(os.Geteuid())
	server, e := ListenBridgeUnixV3(UnixServerConfig{SocketPath: socket, AllowedUID: &uid}, f.b)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	t.Cleanup(func() { cancel(); server.Close(); <-done })
	r, fd, e := CallBridgeUnixV3(context.Background(), socket, f.q, f.plain, f.acceptance)
	if e != nil || fd != nil || r.Execution.State != "committed" {
		t.Fatal("socket submit", e)
	}
	q := ownerTestQuery(f.q, "receipt")
	receipt, fd, e := CallBridgeUnixV3(context.Background(), socket, q, nil, nil)
	if e != nil || fd == nil || receipt.Execution.LeaseID != r.Execution.LeaseID {
		t.Fatal("receipt readback", e)
	}
	raw, e := io.ReadAll(fd)
	fd.Close()
	if e != nil || digest(raw) != receipt.Execution.ReceiptSHA256 {
		t.Fatal("receipt digest", e)
	}
	bad := ownerTestQuery(f.q, "status")
	bad.AcceptanceSHA256 = strings.Repeat("e", 64)
	denied, fd, e := CallBridgeUnixV3(context.Background(), socket, bad, nil, nil)
	if e != nil || fd != nil || denied.Execution.ErrorCode == "" || f.calls.Load() != 1 {
		t.Fatal("query eluded owner binding", e)
	}
	connection, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: socket, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	raw, _ = json.Marshal(f.q)
	if e = bridgeWriteFrame(connection, raw, f.plain); e != nil {
		t.Fatal(e)
	}
	reply, files, e := ownerReadFrame(connection, 1)
	connection.Close()
	for _, f := range files {
		f.Close()
	}
	var malformed BridgeResponseV3
	if e != nil || strictJSON(reply, &malformed) != nil || malformed.Execution.ErrorCode == "" {
		t.Fatal("one FD accepted by two-FD protocol", e)
	}
}
func TestOwnerBridgeQueryCodecCannotCarrySubmitFacts(t *testing.T) {
	f := newOwnerTestFixture(t)
	q := ownerTestQuery(f.q, "status")
	if validateBridgeRequestV3(q) != nil {
		t.Fatal("valid query rejected")
	}
	for _, change := range []func(*BridgeRequestV3){func(q *BridgeRequestV3) { q.AcceptanceSHA256 = "" }, func(q *BridgeRequestV3) { q.AcceptanceBytes = 1 }, func(q *BridgeRequestV3) { q.ProcessedSHA256 = f.q.ProcessedSHA256 }, func(q *BridgeRequestV3) { q.AnalysisContext = f.q.AnalysisContext }, func(q *BridgeRequestV3) { q.SchemaVersion = 2 }} {
		bad := q
		change(&bad)
		if validateBridgeRequestV3(bad) == nil {
			t.Fatal("query/version bypass accepted")
		}
	}
}
