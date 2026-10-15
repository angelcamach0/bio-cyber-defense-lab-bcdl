//go:build linux

package main

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
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	artifact "biozero/artifact-executor"
	projection "biozero/enclave-runner/receiptprojection"
	ownership "biozero/ownership-authority"
)

type ownerResultsTestFixture struct {
	root                   string
	material               ownerResultsMaterial
	pool                   *x509.CertPool
	clients                [2]tls.Certificate
	leaves                 [2]*x509.Certificate
	keys                   [2]*rsa.PrivateKey
	acceptance             []byte
	accepted               ownership.VerifiedAcceptance
	certRaw, keyRaw, caRaw []byte
}

func newOwnerResultsTestFixture(t *testing.T) *ownerResultsTestFixture {
	t.Helper()
	f := &ownerResultsTestFixture{root: t.TempDir()}
	os.Chmod(f.root, 0700)
	generate := func() *rsa.PrivateKey {
		k, e := rsa.GenerateKey(rand.Reader, 2048)
		if e != nil {
			t.Fatal(e)
		}
		return k
	}
	caKey := generate()
	now := time.Now()
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "owner-results-fixture-ca"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, e := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if e != nil {
		t.Fatal(e)
	}
	ca, e := x509.ParseCertificate(caDER)
	if e != nil {
		t.Fatal(e)
	}
	f.pool = x509.NewCertPool()
	f.pool.AddCert(ca)
	makeLeaf := func(key *rsa.PrivateKey, server bool) *x509.Certificate {
		c := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "same-name-and-serial"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		if server {
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			c.DNSNames = []string{"localhost"}
			c.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		}
		der, e := x509.CreateCertificate(rand.Reader, c, ca, &key.PublicKey, caKey)
		if e != nil {
			t.Fatal(e)
		}
		leaf, e := x509.ParseCertificate(der)
		if e != nil {
			t.Fatal(e)
		}
		return leaf
	}
	serverKey := generate()
	serverLeaf := makeLeaf(serverKey, true)
	for i := range f.clients {
		f.keys[i] = generate()
		f.leaves[i] = makeLeaf(f.keys[i], false)
		f.clients[i] = tls.Certificate{Certificate: [][]byte{f.leaves[i].Raw}, PrivateKey: f.keys[i]}
	}
	f.certRaw = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverLeaf.Raw})
	f.keyRaw = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)})
	f.caRaw = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})
	pub, signer, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	pin := ownership.AuthorityPin{AuthorityID: strings.Repeat("1", 32), PublicKey: pub, PipelineMode: "stats", ExecutionProfileSHA256: strings.Repeat("2", 64)}
	policy := ownership.DefaultStorePolicy()
	policy.MaxBodyBytes = 4096
	policy.FreeSpaceFloorBytes = 0
	store, e := ownership.CreateStore(ownership.StoreConfig{Directory: filepath.Join(f.root, "authority"), Namespace: "results-fixture", Pin: pin, SigningKey: signer, Policy: policy})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := store.Close(); e != nil {
			t.Error(e)
		}
	})
	authority, e := ownership.NewHTTPHandler(ownership.HTTPHandlerConfig{Store: store})
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewUnstartedServer(authority)
	server.Config.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){}
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{serverLeaf.Raw}, PrivateKey: serverKey}}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: f.pool, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}}
	server.StartTLS()
	t.Cleanup(server.Close)
	client, e := ownership.NewAuthorityClient(ownership.AuthorityClientConfig{BaseURL: server.URL, Certificate: f.clients[0], RootCAs: f.pool, ServerName: "localhost", Pin: pin, Scope: store.Scope()})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(client.CloseIdleConnections)
	var token [16]byte
	rand.Read(token[:])
	challenge, e := client.Reserve(context.Background(), ownership.HTTPReserveRequest{SchemaVersion: 1, RequestID: hex.EncodeToString(token[:]), OriginalName: "synthetic.fastq"})
	if e != nil {
		t.Fatal(e)
	}
	workerKey := generate()
	payload, e := ownership.EncryptForChallenge(challenge, pin, f.leaves[0], f.keys[0], &workerKey.PublicKey, []byte("@synthetic\nACGT\n+\nIIII\n"), time.Now())
	if e != nil {
		t.Fatal(e)
	}
	f.acceptance, e = client.Finalize(context.Background(), challenge, payload.Manifest, bytes.NewReader(payload.Ciphertext), int64(len(payload.Ciphertext)))
	if e != nil {
		t.Fatal(e)
	}
	f.accepted, e = ownership.VerifyAcceptance(f.acceptance, pin, store.Scope())
	if e != nil {
		t.Fatal(e)
	}
	inbox := filepath.Join(f.root, "acceptances")
	os.Mkdir(inbox, 0700)
	if e := os.WriteFile(filepath.Join(inbox, f.accepted.Binding().JobID+".json"), f.acceptance, 0600); e != nil {
		t.Fatal(e)
	}
	sourcePins := map[string]projection.SourcePin{}
	for _, name := range []string{"pipeline", "resource_budget", "analysis_executable", "analysis_rules"} {
		sourcePins[name] = projection.SourcePin{SHA256: strings.Repeat("3", 64), Bytes: 1}
	}
	c := ownerResultsConfig{SchemaVersion: 1, Protocol: "owner-v1", Address: "127.0.0.1:0", AcceptancesDirectory: inbox, ExpectedAcceptancesUID: uint32(os.Geteuid()), ReaderSocket: filepath.Join(f.root, "reader", "reader.sock"), ExpectedBrokerUID: uint32(os.Geteuid()), AuthorityID: pin.AuthorityID, PublicKeyHex: hex.EncodeToString(pin.PublicKey), PipelineMode: pin.PipelineMode, ExecutionProfileSHA256: pin.ExecutionProfileSHA256, ExpectedScope: store.Scope()}
	f.material = ownerResultsMaterial{config: c, pin: pin, policy: projection.Policy{SchemaVersion: 1, ProfileSHA256: pin.ExecutionProfileSHA256, PipelineMode: "stats", CapsuleKind: "native", SourcePins: sourcePins}, tls: server.TLS.Clone()}
	return f
}

func ownerResultsTestBinding(q artifact.OwnerReadRequest, receipt []byte) artifact.BridgeResponseV3 {
	x := artifact.BridgeResponse{SchemaVersion: 2, JobID: q.JobID, UploadSHA256: q.UploadSHA256, ProfileSHA256: q.ExpectedProfileSHA256, StoreID: strings.Repeat("4", 32), LeaseID: strings.Repeat("5", 32), State: "committed", HasManifest: true}
	x.Manifest = artifact.Manifest{SchemaVersion: 1, JobID: q.JobID, InputSHA256: q.UploadSHA256, StoreID: x.StoreID, LeaseID: x.LeaseID, PolicySHA256: strings.Repeat("6", 64), ExecutionStatus: "failed", ReleaseStatus: "withheld", ErrorCode: "artifact_cancelled", Files: map[string]artifact.FileRecord{}}
	if receipt != nil {
		x.ReceiptBytes = int64(len(receipt))
		x.ReceiptSHA256 = ownerResultsDigest(receipt)
		x.Manifest.Files["execution_receipt"] = artifact.FileRecord{State: "verified", SHA256: x.ReceiptSHA256, Bytes: x.ReceiptBytes}
	}
	raw, _ := json.Marshal(x.Manifest)
	x.ManifestSHA256 = ownerResultsDigest(raw)
	return artifact.BridgeResponseV3{SchemaVersion: 3, AcceptanceSHA256: q.AcceptanceSHA256, CredentialSHA256: q.CredentialSHA256, AuthorityScope: q.AuthorityScope, ProcessedSHA256: strings.Repeat("7", 64), ProcessedBytes: 1, AnalysisContext: artifact.AnalysisContext{OriginalName: "synthetic.fastq", ProcessedSizeBytes: 1, Decrypted: true, SignatureValid: true}, Execution: x}
}

func ownerResultsTestStart(t *testing.T, f *ownerResultsTestFixture, configure func(*ownerResultsHandler)) (*ownerResultsService, string) {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	s, e := newOwnerResultsService(context.Background(), l, f.material)
	if e != nil {
		l.Close()
		t.Fatal(e)
	}
	if configure != nil {
		configure(s.handler)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if e := s.Shutdown(ctx); e != nil {
			t.Error(e)
		}
		if e := <-done; e != nil {
			t.Error(e)
		}
	})
	return s, "https://" + l.Addr().String()
}

func (f *ownerResultsTestFixture) httpClient(i int) *http.Client {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: f.pool, ServerName: "localhost", NextProtos: []string{"http/1.1"}}
	if i >= 0 {
		tlsConfig.Certificates = []tls.Certificate{f.clients[i]}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig, DisableKeepAlives: true}, Timeout: 3 * time.Second}
}

func ownerResultsTestGet(t *testing.T, client *http.Client, url string) (int, []byte) {
	t.Helper()
	r, e := client.Get(url)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Body.Close()
	raw, e := io.ReadAll(r.Body)
	if e != nil {
		t.Fatal(e)
	}
	if r.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("cacheable response")
	}
	return r.StatusCode, raw
}

func TestOwnerResultsRealMTLSExactLeafBeforeReader(t *testing.T) {
	f := newOwnerResultsTestFixture(t)
	var queries, receipts atomic.Int32
	_, base := ownerResultsTestStart(t, f, func(h *ownerResultsHandler) {
		h.query = func(ctx context.Context, _ artifact.OwnerReadClientConfig, q artifact.OwnerReadRequest) (artifact.OwnerReadResponse, error) {
			queries.Add(1)
			return artifact.NewOwnerReadSuccess(q, ownerResultsTestBinding(q, nil))
		}
		h.receipt = func(context.Context, artifact.OwnerReadClientConfig, artifact.OwnerReadRequest) (artifact.OwnerReadResponse, *os.File, error) {
			receipts.Add(1)
			return artifact.OwnerReadResponse{}, nil, ownerResultsError("unexpected")
		}
	})
	url := base + "/v1/results/" + f.accepted.Binding().JobID
	if code, raw := ownerResultsTestGet(t, f.httpClient(0), url); code != 200 || !bytes.Contains(raw, []byte(`"status":"failed"`)) {
		t.Fatal("authorized failed projection", code, string(raw))
	}
	if queries.Load() != 1 || receipts.Load() != 0 {
		t.Fatal("no-receipt commit performed wrong reads")
	}
	if f.leaves[0].Subject.CommonName != f.leaves[1].Subject.CommonName || f.leaves[0].SerialNumber.Cmp(f.leaves[1].SerialNumber) != 0 {
		t.Fatal("fixture does not collide legacy identity")
	}
	request, _ := http.NewRequest(http.MethodGet, url, nil)
	request.Header.Set("X-Client-Id", f.leaves[0].Subject.CommonName)
	request.Header.Set("X-Client-Cert", hex.EncodeToString(f.leaves[0].Raw))
	r, e := f.httpClient(1).Do(request)
	if e != nil {
		t.Fatal(e)
	}
	r.Body.Close()
	if r.StatusCode != 403 || queries.Load() != 1 || receipts.Load() != 0 {
		t.Fatal("B reached broker despite different leaf", r.StatusCode)
	}
	if r, e := f.httpClient(-1).Get(url); e == nil {
		r.Body.Close()
		t.Fatal("missing certificate passed TLS")
	}
	// A fabricated application TLS state cannot replace the actual connection.
	w := httptest.NewRecorder()
	fake := httptest.NewRequest(http.MethodGet, url, nil)
	fake.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true, PeerCertificates: []*x509.Certificate{f.leaves[0]}, VerifiedChains: [][]*x509.Certificate{{f.leaves[0]}}}
	h, e := newOwnerResultsHandler(f.material)
	if e != nil {
		t.Fatal(e)
	}
	defer h.Close()
	h.ServeHTTP(w, fake)
	if w.Code != 403 {
		t.Fatal("fabricated TLS state accepted")
	}
	path := filepath.Join(f.material.config.AcceptancesDirectory, f.accepted.Binding().JobID+".json")
	for _, kind := range []string{"corrupt", "tampered_signature", "missing", "fifo", "symlink", "linked", "unsafe_mode", "copied_job"} {
		t.Run(kind, func(t *testing.T) {
			os.Remove(path)
			targetURL := url
			switch kind {
			case "corrupt":
				os.WriteFile(path, []byte(`{}`), 0600)
			case "tampered_signature":
				var a ownership.SignedAcceptance
				json.Unmarshal(f.acceptance, &a)
				a.Signature = strings.Repeat("0", 128)
				raw, _ := json.Marshal(a)
				os.WriteFile(path, raw, 0600)
			case "missing":
			case "fifo":
				if e := syscall.Mkfifo(path, 0600); e != nil {
					t.Fatal(e)
				}
			case "symlink":
				target := filepath.Join(f.root, "other-acceptance")
				os.WriteFile(target, f.acceptance, 0600)
				os.Symlink(target, path)
			case "linked":
				target := filepath.Join(f.root, "linked-acceptance")
				os.WriteFile(target, f.acceptance, 0600)
				os.Link(target, path)
				defer os.Remove(target)
			case "unsafe_mode":
				os.WriteFile(path, f.acceptance, 0600)
				if err := os.Chmod(path, 0640); err != nil {
					t.Fatal(err)
				}
			case "copied_job":
				other := strings.Repeat("9", 16)
				os.WriteFile(filepath.Join(f.material.config.AcceptancesDirectory, other+".json"), f.acceptance, 0600)
				targetURL = base + "/v1/results/" + other
			}
			if code, _ := ownerResultsTestGet(t, f.httpClient(0), targetURL); code != 403 || queries.Load() != 1 || receipts.Load() != 0 {
				t.Fatal("invalid authorization touched broker", code)
			}
			os.Remove(path)
			os.WriteFile(path, f.acceptance, 0600)
		})
	}
}

func TestOwnerResultsExternalAuthorityAndScopeDenyBeforeReader(t *testing.T) {
	f := newOwnerResultsTestFixture(t)
	for _, field := range []string{"pin", "scope", "profile", "mode"} {
		t.Run(field, func(t *testing.T) {
			copyFixture := *f
			copyFixture.material = f.material
			switch field {
			case "pin":
				pub, _, _ := ed25519.GenerateKey(rand.Reader)
				copyFixture.material.pin.PublicKey = pub
			case "scope":
				copyFixture.material.config.ExpectedScope.PolicySHA256 = strings.Repeat("8", 64)
			case "profile":
				copyFixture.material.config.ExecutionProfileSHA256 = strings.Repeat("8", 64)
				copyFixture.material.pin.ExecutionProfileSHA256 = strings.Repeat("8", 64)
			case "mode":
				copyFixture.material.config.PipelineMode = "variants"
				copyFixture.material.pin.PipelineMode = "variants"
			}
			var reads atomic.Int32
			_, base := ownerResultsTestStart(t, &copyFixture, func(h *ownerResultsHandler) {
				h.query = func(context.Context, artifact.OwnerReadClientConfig, artifact.OwnerReadRequest) (artifact.OwnerReadResponse, error) {
					reads.Add(1)
					return artifact.OwnerReadResponse{}, nil
				}
				h.receipt = func(context.Context, artifact.OwnerReadClientConfig, artifact.OwnerReadRequest) (artifact.OwnerReadResponse, *os.File, error) {
					reads.Add(1)
					return artifact.OwnerReadResponse{}, nil, nil
				}
			})
			if code, _ := ownerResultsTestGet(t, f.httpClient(0), base+"/v1/results/"+f.accepted.Binding().JobID); code != 403 || reads.Load() != 0 {
				t.Fatal("external policy mismatch reached reader", code)
			}
		})
	}
}

type ownerResultsLossWriter struct {
	http.ResponseWriter
	entered chan struct{}
	release chan struct{}
	errors  chan error
	once    sync.Once
}

func (w *ownerResultsLossWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *ownerResultsLossWriter) Write(raw []byte) (int, error) {
	w.once.Do(func() { close(w.entered); <-w.release })
	n, e := w.ResponseWriter.Write(raw)
	if e != nil {
		w.errors <- e
	}
	return n, e
}
func (w *ownerResultsLossWriter) FlushError() error {
	e := http.NewResponseController(w.ResponseWriter).Flush()
	w.errors <- e
	return e
}

func TestOwnerResultsRealResponseResetAfterProjectionIsLocal(t *testing.T) {
	f := newOwnerResultsTestFixture(t)
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	s, e := newOwnerResultsService(context.Background(), l, f.material)
	if e != nil {
		l.Close()
		t.Fatal(e)
	}
	var reads, requests atomic.Int32
	s.handler.query = func(_ context.Context, _ artifact.OwnerReadClientConfig, q artifact.OwnerReadRequest) (artifact.OwnerReadResponse, error) {
		reads.Add(1)
		return artifact.NewOwnerReadSuccess(q, ownerResultsTestBinding(q, nil))
	}
	entered, release := make(chan struct{}), make(chan struct{})
	writeErrors := make(chan error, 2)
	s.server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			s.handler.ServeHTTP(&ownerResultsLossWriter{ResponseWriter: w, entered: entered, release: release, errors: writeErrors}, r)
			return
		}
		s.handler.ServeHTTP(w, r)
	})
	done := make(chan error, 1)
	go func() { done <- s.Serve() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if e := s.Shutdown(ctx); e != nil {
			t.Error(e)
		}
		if e := <-done; e != nil {
			t.Error(e)
		}
	})
	conn, e := tls.Dial("tcp", l.Addr().String(), &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: f.pool, ServerName: "localhost", Certificates: []tls.Certificate{f.clients[0]}})
	if e != nil {
		t.Fatal(e)
	}
	path := "/v1/results/" + f.accepted.Binding().JobID
	if _, e := io.WriteString(conn, "GET "+path+" HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"); e != nil {
		t.Fatal(e)
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("response did not reach real write barrier")
	}
	// The shared projector and complete DTO serialization have finished. Reset
	// the real TLS/TCP peer before allowing the actual ResponseWriter write.
	tcp := conn.NetConn().(*net.TCPConn)
	tcp.SetLinger(0)
	tcp.Close()
	close(release)
	select {
	case err := <-writeErrors:
		if err == nil {
			t.Fatal("reset did not cause actual response write/flush error")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("write failure not observed")
	}
	code, raw := ownerResultsTestGet(t, f.httpClient(0), "https://"+l.Addr().String()+path)
	if code != 200 || reads.Load() != 2 || !bytes.Contains(raw, []byte(`"error_code":"artifact_cancelled"`)) {
		t.Fatal("response loss changed subsequent explicit read", code, string(raw))
	}
	// This transport unit test proves no mutation capability is called. Real
	// custody/accounting immutability belongs to the broker/native acceptance.
}

func TestOwnerResultsFinalSerializationBound(t *testing.T) {
	response := ownerResultsResponse{SchemaVersion: 1, Domain: ownerResultsDomain, PipelineOutput: json.RawMessage(`"` + strings.Repeat("x", ownerResultsResponseLimit) + `"`), ScientificEvaluation: json.RawMessage("null")}
	if _, e := encodeOwnerResultsResponse(context.Background(), response); e == nil {
		t.Fatal("complete serialized DTO exceeded response cap")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := encodeOwnerResultsResponse(ctx, ownerResultsResponse{}); e == nil {
		t.Fatal("cancelled response serialized")
	}
}

func TestOwnerResultsCrossedReceiptTupleFailsClosed(t *testing.T) {
	f := newOwnerResultsTestFixture(t)
	body := []byte("transport-only invalid scientific receipt")
	path := filepath.Join(f.root, "tuple-receipt")
	os.WriteFile(path, body, 0600)
	for _, field := range []string{"matching_read_control", "processed", "context", "lease", "manifest", "receipt", "owner", "scope", "profile", "acceptance", "missing_fd"} {
		t.Run(field, func(t *testing.T) {
			observedReads := ownerResultsObserveReceiptReads(t, path)
			var calls atomic.Int32
			_, base := ownerResultsTestStart(t, f, func(h *ownerResultsHandler) {
				h.query = func(_ context.Context, _ artifact.OwnerReadClientConfig, q artifact.OwnerReadRequest) (artifact.OwnerReadResponse, error) {
					calls.Add(1)
					return artifact.NewOwnerReadSuccess(q, ownerResultsTestBinding(q, body))
				}
				h.receipt = func(_ context.Context, _ artifact.OwnerReadClientConfig, q artifact.OwnerReadRequest) (artifact.OwnerReadResponse, *os.File, error) {
					calls.Add(1)
					b := ownerResultsTestBinding(q, body)
					switch field {
					case "processed":
						b.ProcessedSHA256 = strings.Repeat("8", 64)
					case "context":
						b.AnalysisContext.OriginalName = "changed.fastq"
					case "lease":
						b.Execution.LeaseID = strings.Repeat("8", 32)
						b.Execution.Manifest.LeaseID = b.Execution.LeaseID
					case "manifest":
						b.Execution.Manifest.PolicySHA256 = strings.Repeat("8", 64)
					case "receipt":
						b.Execution.ReceiptSHA256 = strings.Repeat("8", 64)
						record := b.Execution.Manifest.Files["execution_receipt"]
						record.SHA256 = b.Execution.ReceiptSHA256
						b.Execution.Manifest.Files["execution_receipt"] = record
					case "owner":
						b.CredentialSHA256 = strings.Repeat("8", 64)
					case "scope":
						b.AuthorityScope.StoreID = strings.Repeat("8", 32)
					case "profile":
						b.Execution.ProfileSHA256 = strings.Repeat("8", 64)
					case "acceptance":
						b.AcceptanceSHA256 = strings.Repeat("8", 64)
					}
					manifest, _ := json.Marshal(b.Execution.Manifest)
					b.Execution.ManifestSHA256 = ownerResultsDigest(manifest)
					r := artifact.OwnerReadResponse{SchemaVersion: 1, Domain: artifact.OwnerReadResponseDomain, HasReceipt: true, Binding: b}
					switch field {
					case "matching_read_control", "processed", "context", "lease", "manifest", "receipt":
						if err := artifact.ValidateOwnerReadResponse(q, r); err != nil {
							t.Errorf("tuple fixture must otherwise satisfy response validator: %v", err)
							return r, nil, err
						}
					}
					if field == "missing_fd" {
						return r, nil, nil
					}
					fd, e := os.Open(path)
					return r, fd, e
				}
			})
			code, raw := ownerResultsTestGet(t, f.httpClient(0), base+"/v1/results/"+f.accepted.Binding().JobID)
			if code != 503 || calls.Load() != 2 || bytes.Contains(raw, body) {
				t.Fatal("crossed tuple released result", code, string(raw))
			}
			accesses := observedReads()
			if field == "matching_read_control" {
				var failure errorResponse
				if accesses == 0 || json.Unmarshal(raw, &failure) != nil || failure.Code != "owner_results_projection_invalid" {
					t.Fatal("matching binding never attempted a real receipt read/projection", accesses, string(raw))
				}
			} else if accesses != 0 {
				t.Fatal("crossed binding was rejected only after reading private receipt", accesses)
			}
		})
	}
}

// IN_ACCESS is generated by the kernel for reads through the actual regular FD,
// including pread/SectionReader. Open/Stat/Close alone do not satisfy this oracle.
// Matching invalid-science control must read; crossed bindings must never read.
func ownerResultsObserveReceiptReads(t *testing.T, path string) func() int {
	t.Helper()
	fd, err := syscall.InotifyInit1(syscall.IN_CLOEXEC | syscall.IN_NONBLOCK)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := syscall.InotifyAddWatch(fd, path, syscall.IN_ACCESS); err != nil {
		syscall.Close(fd)
		t.Fatal(err)
	}
	t.Cleanup(func() { syscall.Close(fd) })
	return func() int {
		t.Helper()
		count := 0
		var buf [4096]byte
		for {
			n, err := syscall.Read(fd, buf[:])
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
				return count
			}
			if err != nil {
				t.Fatal(err)
			}
			if n == 0 {
				t.Fatal("inotify returned empty nonblocking read")
			}
			for offset := 0; offset < n; {
				if n-offset < syscall.SizeofInotifyEvent {
					t.Fatal("inotify truncated event")
				}
				mask := binary.NativeEndian.Uint32(buf[offset+4 : offset+8])
				length := int(binary.NativeEndian.Uint32(buf[offset+12 : offset+16]))
				if length > n-offset-syscall.SizeofInotifyEvent {
					t.Fatal("inotify truncated event name")
				}
				if mask&syscall.IN_ACCESS != 0 {
					count++
				}
				if mask&syscall.IN_Q_OVERFLOW != 0 {
					t.Fatal("inotify observer overflowed")
				}
				offset += syscall.SizeofInotifyEvent + length
			}
		}
	}
}
