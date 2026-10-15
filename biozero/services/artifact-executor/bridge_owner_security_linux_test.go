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
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
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

// These independent tests compose real mTLS-derived principals, the public
// authority Store and private artifact custody. Providers are synthetic Go
// functions; no worker, kernel capsule, science or deployed isolation is implied.
type ownerSecurityIdentity struct {
	key   *rsa.PrivateKey
	leaf  *x509.Certificate
	state tls.ConnectionState
}

type ownerSecurityCrypto struct {
	a, b      ownerSecurityIdentity
	recipient *rsa.PrivateKey
	signer    ed25519.PrivateKey
	pin       ownership.AuthorityPin
}

var ownerSecurityCryptoOnce sync.Once
var ownerSecurityCryptoData *ownerSecurityCrypto
var ownerSecurityRequestNumber atomic.Uint64

func ownerSecurityKeys(t *testing.T) *ownerSecurityCrypto {
	t.Helper()
	ownerSecurityCryptoOnce.Do(func() {
		key := func() *rsa.PrivateKey {
			k, e := rsa.GenerateKey(rand.Reader, 2048)
			if e != nil {
				t.Fatal(e)
			}
			return k
		}
		now := time.Now().UTC().Truncate(time.Second)
		caKey := key()
		caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "owner-security-ca"},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true,
			BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
		der, e := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
		if e != nil {
			t.Fatal(e)
		}
		ca, e := x509.ParseCertificate(der)
		if e != nil {
			t.Fatal(e)
		}
		leaf := func() ownerSecurityIdentity {
			k := key()
			// Same CN and serial deliberately require DER/key identity, not either
			// mutable or nonunique display field, to distinguish these owners.
			template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "same-owner-bucket"},
				DNSNames: []string{"localhost"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
				KeyUsage:    x509.KeyUsageDigitalSignature,
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
			b, e := x509.CreateCertificate(rand.Reader, template, ca, &k.PublicKey, caKey)
			if e != nil {
				t.Fatal(e)
			}
			c, e := x509.ParseCertificate(b)
			if e != nil {
				t.Fatal(e)
			}
			return ownerSecurityIdentity{key: k, leaf: c}
		}
		f := &ownerSecurityCrypto{a: leaf(), b: leaf(), recipient: key()}
		pool := x509.NewCertPool()
		pool.AddCert(ca)
		states := make(chan tls.ConnectionState, 2)
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			states <- *r.TLS
			w.WriteHeader(http.StatusNoContent)
		}))
		server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool,
			Certificates: []tls.Certificate{{Certificate: [][]byte{f.a.leaf.Raw}, PrivateKey: f.a.key}}}
		server.StartTLS()
		defer server.Close()
		for _, id := range []*ownerSecurityIdentity{&f.a, &f.b} {
			tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: "localhost",
				Certificates: []tls.Certificate{{Certificate: [][]byte{id.leaf.Raw}, PrivateKey: id.key}}}, DisableKeepAlives: true}
			client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
			response, e := client.Get(server.URL)
			if e != nil {
				t.Fatal(e)
			}
			response.Body.Close()
			tr.CloseIdleConnections()
			id.state = <-states
		}
		public, private, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		f.signer = private
		f.pin = ownership.AuthorityPin{AuthorityID: strings.Repeat("1", 32), PublicKey: public,
			PipelineMode: "stats", ExecutionProfileSHA256: strings.Repeat("c", 64)}
		ownerSecurityCryptoData = f
	})
	if ownerSecurityCryptoData == nil {
		t.Fatal("owner security crypto unavailable")
	}
	return ownerSecurityCryptoData
}

type ownerSecurityAcceptance struct {
	plain, raw, cipher, envelope []byte
	verified                     ownership.VerifiedAcceptance
	scope                        ownership.AcceptanceScope
	pin                          ownership.AuthorityPin
}

func ownerSecurityTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	return dir
}

func ownerSecurityAccepted(t *testing.T) ownerSecurityAcceptance {
	t.Helper()
	f := ownerSecurityKeys(t)
	policy := ownership.DefaultStorePolicy()
	policy.MaxBodyBytes = 4096
	policy.FreeSpaceFloorBytes = 0
	s, e := ownership.CreateStore(ownership.StoreConfig{Directory: filepath.Join(ownerSecurityTempDir(t), "authority"),
		Namespace: "broker-owner-security", Pin: f.pin, SigningKey: f.signer, Policy: policy})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := s.Close(); e != nil {
			t.Error("authority fixture close failed", e)
		}
	})
	now := time.Now().UTC().Truncate(time.Second)
	challenge, e := s.Reserve(&f.a.state, fmt.Sprintf("%032x", ownerSecurityRequestNumber.Add(1)), "owner.synthetic", now)
	if e != nil {
		t.Fatal(e)
	}
	rawChallenge, e := ownership.MarshalChallenge(challenge)
	if e != nil {
		t.Fatal(e)
	}
	plain := []byte("synthetic owner-security payload")
	payload, e := ownership.EncryptForChallenge(rawChallenge, f.pin, f.a.leaf, f.a.key, &f.recipient.PublicKey, plain, now)
	if e != nil {
		t.Fatal(e)
	}
	accepted, e := s.Finalize(context.Background(), &f.a.state, rawChallenge, payload.Manifest, bytes.NewReader(payload.Ciphertext), now)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := json.Marshal(accepted)
	if e != nil {
		t.Fatal(e)
	}
	v, e := ownership.VerifyAcceptance(raw, f.pin, s.Scope())
	if e != nil {
		t.Fatal(e)
	}
	// This check establishes genuine fixture bytes only. The worker's mandatory
	// before-Submit GCM gate is independently exercised in its own module.
	decrypted, e := ownership.DecryptAcceptedPayload(v, payload.Ciphertext, payload.KeyEnvelope, f.recipient)
	if e != nil || !bytes.Equal(decrypted, plain) {
		t.Fatal("fixture payload did not authenticate", e)
	}
	return ownerSecurityAcceptance{plain, raw, payload.Ciphertext, payload.KeyEnvelope, v, s.Scope(), f.pin}
}

func ownerSecurityFile(t *testing.T, name string, raw []byte) *os.File {
	t.Helper()
	path := filepath.Join(ownerSecurityTempDir(t), name)
	if e := os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	f, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

type ownerSecurityBroker struct {
	b                 *Broker
	c                 *Coordinator
	s                 *Store
	config            OwnerBrokerConfig
	root              string
	a                 ownerSecurityAcceptance
	q                 BridgeRequestV3
	plain, acceptance *os.File
	calls             atomic.Int32
}

func ownerSecurityNewBroker(t *testing.T, mutate func(*OwnerBrokerConfig)) *ownerSecurityBroker {
	t.Helper()
	f := &ownerSecurityBroker{root: ownerSecurityTempDir(t), a: ownerSecurityAccepted(t)}
	f.config = OwnerBrokerConfig{JournalRoot: filepath.Join(f.root, "journal"), ProfileSHA256: f.a.pin.ExecutionProfileSHA256, Pin: f.a.pin, Scope: f.a.scope}
	if mutate != nil {
		mutate(&f.config)
	}
	var e error
	f.s, e = Open(context.Background(), filepath.Join(f.root, "store"), NativeArtifactPolicy())
	if e != nil {
		t.Fatal(e)
	}
	r, e := NewInputRegistry(f.s)
	if e != nil {
		t.Fatal(e)
	}
	f.c, e = NewCoordinator(f.s, r, fixtureProvider(func(ctx context.Context, in *ScopedInput, out *Exporter) ProviderCompletion {
		f.calls.Add(1)
		if in.AnalysisContext == nil || !in.AnalysisContext.Decrypted || !in.AnalysisContext.SignatureValid {
			return ProviderCompletion{Quiescent: true, Err: errors.New("fixture facts absent")}
		}
		if _, e := in.CopyTo(ctx, io.Discard); e != nil {
			return ProviderCompletion{Quiescent: true, Err: e}
		}
		data := []byte(`{"schema_version":1,"synthetic_only":true}`)
		if e := out.Export("execution_receipt", digest(data), bytes.NewReader(data)); e != nil {
			return ProviderCompletion{Quiescent: true, Err: e}
		}
		return ProviderCompletion{Quiescent: true, Outcome: Outcome{ExecutionStatus: "succeeded", ReleaseStatus: "unassessed"}}
	}))
	if e != nil {
		t.Fatal(e)
	}
	f.b, e = CreateBrokerV3(context.Background(), f.config, f.c)
	if e != nil {
		t.Fatal(e)
	}
	b := f.a.verified.Binding()
	f.q = BridgeRequestV3{SchemaVersion: 3, Operation: "submit", JobID: b.JobID, UploadSHA256: b.CiphertextSHA256, ExpectedProfileSHA256: b.ExecutionProfileSHA256,
		ProcessedSHA256: digest(f.a.plain), ProcessedBytes: int64(len(f.a.plain)), OriginalName: b.OriginalName,
		AnalysisContext:  AnalysisContext{OriginalName: b.OriginalName, ProcessedSizeBytes: int64(len(f.a.plain)), Decrypted: true, SignatureValid: true},
		AcceptanceSHA256: f.a.verified.SHA256(), AcceptanceBytes: int64(len(f.a.raw))}
	f.plain = ownerSecurityFile(t, "plaintext.fixture", f.a.plain)
	f.acceptance = ownerSecurityFile(t, "acceptance.json", f.a.raw)
	t.Cleanup(func() {
		f.b.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		f.b.Wait(ctx)
		cancel()
		// Test-only process-end simulation: providers above are known synchronous,
		// synthetic and quiescent. This is not operational uncertain-lock release.
		ownerSecurityDropFixtureBroker(f.b)
		f.c.Close()
		f.c.registry.Close()
		f.s.Close()
	})
	return f
}

func ownerSecurityDropFixtureBroker(b *Broker) {
	if b == nil {
		return
	}
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

func ownerSecurityQuery(q BridgeRequestV3, op string) BridgeRequestV3 {
	q.Operation = op
	q.ProcessedSHA256 = ""
	q.ProcessedBytes = 0
	q.OriginalName = ""
	q.AnalysisContext = AnalysisContext{}
	q.AcceptanceBytes = 0
	return q
}

func ownerSecurityHistory(t *testing.T, root string) map[string]string {
	t.Helper()
	m := map[string]string{}
	e := filepath.WalkDir(root, func(path string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.Type().IsRegular() {
			raw, e := os.ReadFile(path)
			if e != nil {
				return e
			}
			rel, e := filepath.Rel(root, path)
			if e != nil {
				return e
			}
			m[rel] = digest(raw)
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	return m
}

func TestBridgeOwnerSecuritySignedAdmissionAndUnixReadback(t *testing.T) {
	f := ownerSecurityNewBroker(t, nil)
	seenIntent := false
	f.b.fault = func(point string) error {
		if point != "after_intent" {
			return nil
		}
		var j bridgeJournalV3
		if strictJSON(brokerRead(t, filepath.Join(f.config.JournalRoot, "journal.json")), &j) != nil || j.OwnerBindings[f.q.JobID].AcceptanceSHA256 != f.q.AcceptanceSHA256 || j.Records[f.q.JobID].Stage != "intent" || f.s.Snapshot().RetainedOrReservedJobs != 0 {
			t.Error("owner binding was not durable before Reserve")
		}
		if !bytes.Equal(brokerRead(t, filepath.Join(f.config.JournalRoot, "acceptances", f.q.AcceptanceSHA256+".json")), f.a.raw) {
			t.Error("signed sidecar was not durable before Reserve")
		}
		seenIntent = true
		return nil
	}
	dir, e := os.MkdirTemp("", "bz-owner-unix-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	uid := uint32(os.Geteuid())
	socket := filepath.Join(dir, "s")
	s, e := ListenBridgeUnixV3(UnixServerConfig{SocketPath: socket, AllowedUID: &uid, MaxConnections: 2, RequestTimeout: time.Second, RunTimeout: 5 * time.Second, WriteTimeout: time.Second}, f.b)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		s.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("owner listener did not join")
		}
	})
	r, out, e := CallBridgeUnixV3(context.Background(), socket, f.q, f.plain, f.acceptance)
	if e != nil || out != nil || !seenIntent || r.Execution.State != "committed" || f.calls.Load() != 1 || r.AcceptanceSHA256 != f.q.AcceptanceSHA256 || r.CredentialSHA256 != f.a.verified.Binding().CredentialSHA256 || r.AuthorityScope != f.a.scope || r.ProcessedSHA256 != f.q.ProcessedSHA256 || r.AnalysisContext != f.q.AnalysisContext {
		t.Fatal("owner admission failed", e)
	}
	before := ownerSecurityHistory(t, f.config.JournalRoot)
	ledger := brokerRead(t, filepath.Join(f.root, "store/ledger.json"))
	snapshot := f.s.Snapshot()
	duplicate, _, e := CallBridgeUnixV3(context.Background(), socket, f.q, f.plain, f.acceptance)
	if e != nil || !reflect.DeepEqual(duplicate, r) || f.calls.Load() != 1 {
		t.Fatal("duplicate changed execution", e)
	}
	query := ownerSecurityQuery(f.q, "receipt")
	got, fd, e := CallBridgeUnixV3(context.Background(), socket, query, nil, nil)
	if e != nil || fd == nil || got.AcceptanceSHA256 != r.AcceptanceSHA256 || got.Execution.ManifestSHA256 != r.Execution.ManifestSHA256 {
		t.Fatal("owner receipt failed", e)
	}
	raw, e := io.ReadAll(io.NewSectionReader(fd, 0, MaxBridgeReceiptBytes+1))
	fd.Close()
	if e != nil || digest(raw) != r.Execution.ReceiptSHA256 {
		t.Fatal("receipt actual bytes mismatch")
	}
	query.AcceptanceSHA256 = strings.Repeat("0", 64)
	denied, _, e := CallBridgeUnixV3(context.Background(), socket, query, nil, nil)
	if e == nil && denied.Execution.ErrorCode == "" {
		t.Fatal("wrong acceptance query authorized")
	}
	if f.s.Snapshot() != snapshot || !bytes.Equal(ledger, brokerRead(t, filepath.Join(f.root, "store/ledger.json"))) || !reflect.DeepEqual(before, ownerSecurityHistory(t, f.config.JournalRoot)) {
		t.Fatal("query/duplicate changed custody or charge")
	}
}

func TestBridgeOwnerSecurityDeniesBeforeReserve(t *testing.T) {
	for _, kind := range []string{"wrong_pin", "wrong_scope", "wrong_mode", "tampered_signature", "noncanonical", "trailing", "missing_acceptance", "writable_acceptance", "unsafe_mode", "hardlink", "oversized_acceptance", "actual_oversized_acceptance", "fifo_acceptance", "wrong_acceptance_hash", "wrong_job", "wrong_upload", "wrong_profile", "wrong_name", "false_decrypted", "false_signature", "error_fact", "context_size", "missing_plaintext", "changed_plaintext", "wrong_plaintext_size", "writable_plaintext", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			f := ownerSecurityNewBroker(t, func(c *OwnerBrokerConfig) {
				switch kind {
				case "wrong_pin":
					c.Pin.PublicKey = append([]byte(nil), c.Pin.PublicKey...)
					c.Pin.PublicKey[0] ^= 1
				case "wrong_scope":
					c.Scope.PolicySHA256 = strings.Repeat("0", 64)
				case "wrong_mode":
					c.Pin.PipelineMode = "variants"
				}
			})
			q, p, a := f.q, f.plain, f.acceptance
			ctx := context.Background()
			switch kind {
			case "tampered_signature":
				raw := append([]byte(nil), f.a.raw...)
				var s ownership.SignedAcceptance
				if json.Unmarshal(raw, &s) != nil {
					t.Fatal("fixture")
				}
				s.Signature = strings.Repeat("0", 128)
				raw, _ = json.Marshal(s)
				a = ownerSecurityFile(t, "bad.json", raw)
				q.AcceptanceBytes = int64(len(raw))
				q.AcceptanceSHA256 = digest(raw)
			case "noncanonical":
				raw := append(append([]byte(nil), f.a.raw...), byte(' '))
				a = ownerSecurityFile(t, "space.json", raw)
				q.AcceptanceBytes = int64(len(raw))
			case "trailing":
				raw := append(append([]byte(nil), f.a.raw...), []byte("{}")...)
				a = ownerSecurityFile(t, "trailing.json", raw)
				q.AcceptanceBytes = int64(len(raw))
			case "missing_acceptance":
				a = nil
			case "writable_acceptance":
				var e error
				a, e = os.OpenFile(f.acceptance.Name(), os.O_RDWR, 0)
				if e != nil {
					t.Fatal(e)
				}
				defer a.Close()
			case "unsafe_mode":
				if os.Chmod(f.acceptance.Name(), 0644) != nil {
					t.Fatal("mode fixture")
				}
			case "hardlink":
				if os.Link(f.acceptance.Name(), f.acceptance.Name()+".other") != nil {
					t.Fatal("link fixture")
				}
			case "oversized_acceptance":
				q.AcceptanceBytes = ownership.MaxAcceptanceBytes + 1
			case "actual_oversized_acceptance":
				path := filepath.Join(ownerSecurityTempDir(t), "large")
				file, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
				if e != nil {
					t.Fatal(e)
				}
				if e = file.Truncate(ownership.MaxAcceptanceBytes + 1); e != nil {
					t.Fatal(e)
				}
				file.Close()
				a, e = os.Open(path)
				if e != nil {
					t.Fatal(e)
				}
				defer a.Close()
			case "fifo_acceptance":
				path := filepath.Join(ownerSecurityTempDir(t), "fifo")
				if e := syscall.Mkfifo(path, 0600); e != nil {
					t.Fatal(e)
				}
				fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
				if e != nil {
					t.Fatal(e)
				}
				a = os.NewFile(uintptr(fd), "fixture-fifo")
				defer a.Close()
			case "wrong_acceptance_hash":
				q.AcceptanceSHA256 = strings.Repeat("0", 64)
			case "wrong_job":
				q.JobID = strings.Repeat("0", 16)
			case "wrong_upload":
				q.UploadSHA256 = strings.Repeat("0", 64)
			case "wrong_profile":
				q.ExpectedProfileSHA256 = strings.Repeat("0", 64)
			case "wrong_name":
				q.OriginalName = "other"
				q.AnalysisContext.OriginalName = "other"
			case "false_decrypted":
				q.AnalysisContext.Decrypted = false
			case "false_signature":
				q.AnalysisContext.SignatureValid = false
			case "error_fact":
				q.AnalysisContext.DecryptionError = "decrypt_failed"
			case "context_size":
				q.AnalysisContext.ProcessedSizeBytes++
			case "missing_plaintext":
				p = nil
			case "changed_plaintext":
				raw := append([]byte(nil), f.a.plain...)
				raw[0] ^= 1
				p = ownerSecurityFile(t, "different", raw)
			case "wrong_plaintext_size":
				p = ownerSecurityFile(t, "extra", append(append([]byte(nil), f.a.plain...), byte('x')))
			case "writable_plaintext":
				var e error
				p, e = os.OpenFile(f.plain.Name(), os.O_RDWR, 0)
				if e != nil {
					t.Fatal(e)
				}
				defer p.Close()
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			before := ownerSecurityHistory(t, f.config.JournalRoot)
			snapshot := f.s.Snapshot()
			_, out, e := f.b.HandleBridgeV3(ctx, q, p, a)
			if out != nil {
				out.Close()
			}
			if e == nil || f.calls.Load() != 0 || f.s.Snapshot() != snapshot || snapshot.RetainedOrReservedJobs != 0 || !reflect.DeepEqual(before, ownerSecurityHistory(t, f.config.JournalRoot)) {
				t.Fatal("invalid owner consumed custody", e)
			}
		})
	}
}

func TestBridgeOwnerSecurityStrictShapeAndVersions(t *testing.T) {
	f := ownerSecurityNewBroker(t, nil)
	raw, e := json.Marshal(f.q)
	if e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"legacy1", "legacy2", "missing_acceptance", "null_hash", "unknown_path", "alias", "missing_fact", "null_fact", "duplicate", "trailing"} {
		t.Run(kind, func(t *testing.T) {
			var m map[string]any
			if json.Unmarshal(raw, &m) != nil {
				t.Fatal("fixture")
			}
			wire := append([]byte(nil), raw...)
			switch kind {
			case "legacy1":
				m["schema_version"] = 1
			case "legacy2":
				m["schema_version"] = 2
			case "missing_acceptance":
				delete(m, "acceptance_sha256")
			case "null_hash":
				m["acceptance_sha256"] = nil
			case "unknown_path":
				m["path"] = "/private/never-open"
			case "alias":
				m["Acceptance_sha256"] = m["acceptance_sha256"]
				delete(m, "acceptance_sha256")
			case "missing_fact":
				delete(m["analysis_context"].(map[string]any), "decrypted")
			case "null_fact":
				m["analysis_context"].(map[string]any)["decrypted"] = nil
			}
			if kind == "duplicate" {
				wire = bytes.Replace(raw, []byte(`"decrypted":true`), []byte(`"decrypted":true,"decrypted":true`), 1)
			} else if kind == "trailing" {
				wire = append(wire, []byte("{}")...)
			} else {
				wire, _ = json.Marshal(m)
			}
			var q BridgeRequestV3
			if strictJSON(wire, &q) == nil && validateBridgeRequestV3(q) == nil {
				t.Fatal("malformed owner request accepted")
			}
		})
	}
	if _, _, e := f.b.HandleBridgeV2(context.Background(), f.q.analysisRequest(), f.plain); e == nil {
		t.Fatal("v2 fallback reached owner broker")
	}
	if _, _, e := f.b.HandleBridge(context.Background(), f.q.analysisRequest().legacy(), f.plain); e == nil {
		t.Fatal("v1 fallback reached owner broker")
	}
	q := ownerSecurityQuery(f.q, "status")
	q.AnalysisContext.SignatureValid = true
	if validateBridgeRequestV3(q) == nil {
		t.Fatal("query replaced facts")
	}
	if f.s.Snapshot().RetainedOrReservedJobs != 0 || f.calls.Load() != 0 {
		t.Fatal("shape failure admitted execution")
	}
}

func TestBridgeOwnerSecurityPersistenceFailureKeepsRawCustody(t *testing.T) {
	for _, point := range []string{"owner_before_sidecar", "owner_sidecar_file_sync", "owner_sidecar_link", "owner_sidecar_directory_sync", "journal_file_sync", "after_intent", "after_reserve", "after_link"} {
		t.Run(point, func(t *testing.T) {
			f := ownerSecurityNewBroker(t, nil)
			f.b.fault = func(at string) error {
				if at == point {
					return errors.New("synthetic owner persistence fault")
				}
				return nil
			}
			if _, _, e := f.b.HandleBridgeV3(context.Background(), f.q, f.plain, f.acceptance); e == nil {
				t.Fatal("uncertain owner publication succeeded")
			}
			if f.calls.Load() != 0 {
				t.Fatal("fault invoked provider")
			}
			before := ownerSecurityHistory(t, f.config.JournalRoot)
			snapshot := f.s.Snapshot()
			flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(f.b.owner.rawFD), syscall.F_GETFD, 0)
			if errno != 0 || flags&syscall.FD_CLOEXEC == 0 || !f.b.owner.rawHeld {
				t.Fatal("raw custody FD unavailable")
			}
			f.b.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			e := f.b.Wait(ctx)
			cancel()
			if e == nil {
				t.Fatal("uncertainty released owner lock")
			}
			// Probe the kernel flock independently of the now-closed coordinator
			// and sticky Store, so those earlier guards cannot fake lock exclusion.
			probe, e := os.Open(filepath.Join(f.config.JournalRoot, "instance.lock"))
			if e != nil {
				t.Fatal(e)
			}
			e = syscall.Flock(int(probe.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
			probe.Close()
			if e != syscall.EWOULDBLOCK && e != syscall.EAGAIN {
				t.Fatal("raw lifetime flock not retained", e)
			}
			if !reflect.DeepEqual(before, ownerSecurityHistory(t, f.config.JournalRoot)) || f.s.Snapshot().ChargedBytes != snapshot.ChargedBytes {
				t.Fatal("failure changed retained history or refunded")
			}
			if point == "after_reserve" || point == "after_link" {
				p := NativeArtifactPolicy()
				if snapshot.RetainedOrReservedJobs != 1 || snapshot.ChargedBytes != storeHeaderReserve+p.ExportBytes+p.PublicationHeadroom {
					t.Fatal("full pending reservation missing")
				}
			}
		})
	}
}

func TestBridgeOwnerSecurityLostACKColdReadbackAndUnknownHistory(t *testing.T) {
	for _, kind := range []string{"committed_lost_ack", "unknown_sidecar", "wrong_scope_on_reopen"} {
		t.Run(kind, func(t *testing.T) {
			f := ownerSecurityNewBroker(t, nil)
			r, out, e := f.b.HandleBridgeV3(context.Background(), f.q, f.plain, f.acceptance)
			if out != nil {
				out.Close()
			}
			if e != nil || r.Execution.State != "committed" {
				t.Fatal("initial commit", e)
			}
			if kind == "committed_lost_ack" {
				called := false
				e = f.b.AcknowledgeBridgeV3(context.Background(), f.q, func() error { called = true; return errors.New("synthetic actual ACK callback failure") })
				if e == nil || !called || f.s.Snapshot().Healthy {
					t.Fatal("lost ACK bypassed custody latch")
				}
				called = false
				if e = f.b.AcknowledgeBridgeV3(context.Background(), f.q, func() error { called = true; return nil }); e == nil || called {
					t.Fatal("live sticky ACK bypass")
				}
			}
			before := ownerSecurityHistory(t, f.root)
			charged := f.s.Snapshot().ChargedBytes
			f.b.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			f.b.Wait(ctx)
			cancel()
			ownerSecurityDropFixtureBroker(f.b)
			f.c.Close()
			f.c.registry.Close()
			f.s.Close()
			// Explicit test-only process-end simulation above; no SIGKILL or kernel
			// capsule claim. Cold Open now validates actual retained files/proofs.
			f.s, e = Open(context.Background(), filepath.Join(f.root, "store"), NativeArtifactPolicy())
			if e != nil {
				t.Fatal(e)
			}
			reg, e := NewInputRegistry(f.s)
			if e != nil {
				t.Fatal(e)
			}
			f.c, e = NewCoordinator(f.s, reg, fixtureProvider(func(context.Context, *ScopedInput, *Exporter) ProviderCompletion {
				f.calls.Add(1)
				return ProviderCompletion{Quiescent: true, Err: errors.New("recovery must not execute")}
			}))
			if e != nil {
				t.Fatal(e)
			}
			cfg := f.config
			if kind == "unknown_sidecar" {
				if e = os.WriteFile(filepath.Join(cfg.JournalRoot, "acceptances", "unknown.json"), []byte("preserve"), 0600); e != nil {
					t.Fatal(e)
				}
				before = ownerSecurityHistory(t, f.root)
			}
			if kind == "wrong_scope_on_reopen" {
				cfg.Scope.PolicySHA256 = strings.Repeat("0", 64)
			}
			b, e := OpenBrokerV3(context.Background(), cfg, f.c)
			if b != nil {
				f.b = b
			}
			if kind != "committed_lost_ack" {
				if e == nil {
					t.Fatal("ambiguous/mismatched history adopted")
				}
				if f.s.Snapshot().ChargedBytes != charged || !reflect.DeepEqual(before, ownerSecurityHistory(t, f.root)) || f.calls.Load() != 1 {
					t.Fatal("failed Open changed history/charge")
				}
				return
			}
			if e != nil {
				t.Fatal("committed history failed reopen", e)
			}
			query := ownerSecurityQuery(f.q, "receipt")
			got, fd, e := b.HandleBridgeV3(context.Background(), query, nil, nil)
			if e != nil || fd == nil || got.AcceptanceSHA256 != r.AcceptanceSHA256 || got.AuthorityScope != r.AuthorityScope || got.Execution.LeaseID != r.Execution.LeaseID || got.Execution.ManifestSHA256 != r.Execution.ManifestSHA256 {
				t.Fatal("cold owner binding changed", e)
			}
			fd.Close()
			if e = b.AcknowledgeBridgeV3(context.Background(), query, func() error { return nil }); e != nil {
				t.Fatal("cold ACK failed", e)
			}
			if f.calls.Load() != 1 || f.s.Snapshot().ChargedBytes != charged || !reflect.DeepEqual(before, ownerSecurityHistory(t, f.root)) {
				t.Fatal("recovery reran/refunded/rewrote original evidence")
			}
		})
	}
}

func TestBridgeOwnerSecurityLateRightsAndRejectedFDClosure(t *testing.T) {
	dir, e := os.MkdirTemp("", "bz-owner-codec-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(dir)
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(dir, "s"), Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	client, e := net.DialUnix("unix", nil, listener.Addr().(*net.UnixAddr))
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	server, e := listener.AcceptUnix()
	if e != nil {
		t.Fatal(e)
	}
	defer server.Close()
	server.SetReadDeadline(time.Now().Add(time.Second))
	file := ownerSecurityFile(t, "rights", []byte("synthetic"))
	body := []byte(`{"synthetic":true}`)
	frame := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(body)))
	copy(frame[4:], body)
	if n, e := client.Write(frame[:2]); e != nil || n != 2 {
		t.Fatal(e)
	}
	control := syscall.UnixRights(int(file.Fd()), int(file.Fd()))
	if n, count, e := client.WriteMsgUnix(frame[2:], control, nil); e != nil || n != len(frame)-2 || count != len(control) {
		t.Fatal(e)
	}
	_, files, e := ownerReadFrame(server, 2)
	if e == nil {
		for _, f := range files {
			f.Close()
		}
		t.Fatal("rights after first byte accepted")
	}
	for _, f := range files {
		if _, e := f.Stat(); !errors.Is(e, os.ErrClosed) {
			t.Fatal("received rejected descriptor still open")
		}
	}
}
