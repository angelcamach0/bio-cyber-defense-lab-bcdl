package main

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
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
	"testing"
	"time"
)

func localGateway(t *testing.T) *Gateway {
	t.Helper()
	code := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	hash := sha256.Sum256([]byte(code))
	private := filepath.Join(t.TempDir(), "registry")
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	return &Gateway{healthy: true, config: Config{Origin: "http://127.0.0.1:8083", Registry: filepath.Join(private, "runs.json")},
		reviewers:   map[string]identity{"a": {Spec: Reviewer{ID: "a", Principal: "researcher-a", Enabled: true}, Hash: hash}, "b": {Spec: Reviewer{ID: "b", Principal: "researcher-b", Enabled: true}, Hash: hash}},
		experiments: map[string]prepared{"fixture": {Spec: Experiment{ID: "fixture", Scope: "synthetic"}}}, sessions: map[[32]byte]session{}, runs: map[string]run{}, reserved: map[string]bool{}, rates: map[string]throttle{}, now: time.Now}
}
func request(g *Gateway, method, path, body string, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, g.config.Origin+path, strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:5555"
	if method != "GET" {
		req.Header.Set("Origin", g.config.Origin)
		req.Header.Set("Content-Type", "application/json")
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	w := httptest.NewRecorder()
	g.ServeHTTP(w, req)
	return w
}
func login(t *testing.T, g *Gateway, id string) (*http.Cookie, string) {
	t.Helper()
	code := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	w := request(g, "POST", "/api/sign-in", fmt.Sprintf(`{"id":%q,"access_code":%q}`, id, code), nil, "")
	if w.Code != 200 {
		t.Fatalf("sign-in status=%d body=%s", w.Code, w.Body.String())
	}
	var response map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &response)
	return w.Result().Cookies()[0], response["csrf_token"]
}
func TestSessionOriginCSRFOwnershipAndLogout(t *testing.T) {
	g := localGateway(t)
	if w := request(g, "GET", "/api/session", "", nil, ""); w.Code != 401 {
		t.Fatal(w.Code)
	}
	a, csrf := login(t, g, "a")
	b, bcsrf := login(t, g, "b")
	if !a.HttpOnly || a.SameSite != http.SameSiteStrictMode || a.Path != "/" || a.Domain != "" {
		t.Fatal("unsafe cookie")
	}
	cases := []struct {
		name, body, csrf string
		want             int
	}{
		{"no csrf", "{}", "", 403}, {"other session csrf", "{}", bcsrf, 403}, {"caller paths", `{"file":"/etc/passwd"}`, csrf, 400},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if w := request(g, "POST", "/api/experiments/fixture/runs", test.body, a, test.csrf); w.Code != test.want {
				t.Fatal(w.Code, w.Body.String())
			}
		})
	}
	g.runs["abcd1234"] = run{JobID: "abcd1234", Reviewer: "a", Principal: "researcher-a", Experiment: "fixture"}
	req := httptest.NewRequest("GET", g.config.Origin+"/api/results/abcd1234", nil)
	req.AddCookie(b)
	req.Header.Set("X-Client-Id", "researcher-a")
	w := httptest.NewRecorder()
	g.ServeHTTP(w, req)
	if w.Code != 404 {
		t.Fatal("cross-owner result leaked", w.Code)
	}
	for _, origin := range []string{"https://evil.example", "null", ""} {
		req := httptest.NewRequest("POST", g.config.Origin+"/api/sign-out", strings.NewReader("{}"))
		req.AddCookie(a)
		req.Header.Set("Origin", origin)
		req.Header.Set("X-CSRF-Token", csrf)
		w := httptest.NewRecorder()
		g.ServeHTTP(w, req)
		if w.Code != 403 {
			t.Fatal("bad origin accepted", origin, w.Code)
		}
	}
	req = httptest.NewRequest("GET", g.config.Origin+"/api/session", nil)
	req.Host = "evil.example"
	req.AddCookie(a)
	req.Header.Set("X-Forwarded-Host", "127.0.0.1:8083")
	w = httptest.NewRecorder()
	g.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatal("forged host accepted")
	}
	if w := request(g, "POST", "/api/sign-out", "{}", a, csrf); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := request(g, "GET", "/api/session", "", a, ""); w.Code != 401 {
		t.Fatal("logout did not revoke")
	}
}
func TestExpirationFixationDisabledAndRateLimit(t *testing.T) {
	g := localGateway(t)
	now := time.Now()
	g.now = func() time.Time { return now }
	a, _ := login(t, g, "a")
	fresh, _ := login(t, g, "a")
	if a.Value == fresh.Value {
		t.Fatal("session not rotated")
	}
	if w := request(g, "GET", "/api/session", "", a, ""); w.Code != 401 {
		t.Fatal("old session still active")
	}
	now = now.Add(30 * time.Minute)
	if w := request(g, "GET", "/api/session", "", fresh, ""); w.Code != 401 {
		t.Fatal("idle expiration missing")
	}
	a, _ = login(t, g, "a")
	key := sha256.Sum256([]byte(a.Value))
	s := g.sessions[key]
	s.Created = now.Add(-8 * time.Hour)
	g.sessions[key] = s
	if w := request(g, "GET", "/api/session", "", a, ""); w.Code != 401 {
		t.Fatal("absolute expiration missing")
	}
	a, _ = login(t, g, "a")
	id := g.reviewers["a"]
	id.Spec.Enabled = false
	g.reviewers["a"] = id
	if w := request(g, "GET", "/api/session", "", a, ""); w.Code != 401 {
		t.Fatal("disabled user accepted")
	}
	g = localGateway(t)
	for i := 0; i < 10; i++ {
		w := request(g, "POST", "/api/sign-in", `{"id":"a","access_code":"wrong"}`, nil, "")
		if w.Code != 401 {
			t.Fatal(w.Code)
		}
	}
	if w := request(g, "POST", "/api/sign-in", `{"id":"a","access_code":"wrong"}`, nil, ""); w.Code != 429 {
		t.Fatal("rate limit missing")
	}
}
func TestPersistentRegistryAndInvalidIdentity(t *testing.T) {
	g := localGateway(t)
	g.runs["abcd1234"] = run{JobID: "abcd1234", Reviewer: "a", Principal: "researcher-a", Experiment: "fixture", Created: time.Now(), Terminal: true}
	if err := g.saveRegistryLocked(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(g.config.Registry)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("registry not private")
	}
	g.runs = map[string]run{}
	if err := g.loadRegistry(); err != nil {
		t.Fatal(err)
	}
	if g.runs["abcd1234"].Reviewer != "a" {
		t.Fatal("owner lost on restart")
	}
	bad := g.runs["abcd1234"]
	bad.Principal = "researcher-b"
	data, _ := json.Marshal([]run{bad})
	_ = os.WriteFile(g.config.Registry, data, 0600)
	g.runs = map[string]run{}
	if g.loadRegistry() == nil {
		t.Fatal("registry identity tampering accepted")
	}
}

func issue(t *testing.T, ca *x509.Certificate, caKey *rsa.PrivateKey, cn string, usage x509.ExtKeyUsage, server bool) (tls.Certificate, []byte, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	spec := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
	if server {
		spec.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	der, err := x509.CreateCertificate(rand.Reader, spec, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return pair, certPEM, keyPEM
}
func TestConcurrentABTLSIdentityAndActualEncryptedSubmission(t *testing.T) {
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caSpec := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caSpec, caSpec, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	serverCert, _, _ := issue(t, ca, caKey, "backend", x509.ExtKeyUsageServerAuth, true)
	signer, _ := rsa.GenerateKey(rand.Reader, 2048)
	decrypt, _ := rsa.GenerateKey(rand.Reader, 2048)
	var calls atomic.Int32
	var submissions atomic.Int32
	expected := map[string]string{"aaaa1111": "researcher-a", "bbbb2222": "researcher-b"}
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		principal := r.TLS.PeerCertificates[0].Subject.CommonName
		if r.URL.Path == "/upload" {
			if err := r.ParseMultipartForm(1 << 20); err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			if r.FormValue("client_id") != principal {
				t.Error("identity claim disagrees with TLS")
			}
			file, _, err := r.FormFile("file")
			if err != nil {
				t.Error(err)
				return
			}
			defer file.Close()
			encrypted, _ := io.ReadAll(file)
			digest := sha256.Sum256(encrypted)
			sig, _ := hex.DecodeString(r.FormValue("sig"))
			if rsa.VerifyPSS(&signer.PublicKey, crypto.SHA256, digest[:], sig, nil) != nil {
				t.Error("payload not signed")
			}
			wrapped, _ := hex.DecodeString(r.FormValue("enc_key"))
			material, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, decrypt, wrapped, nil)
			if err != nil {
				t.Error(err)
				return
			}
			block, _ := aes.NewCipher(material[:32])
			aead, _ := cipher.NewGCM(block)
			plain, err := aead.Open(nil, material[32:], encrypted, nil)
			if err != nil || string(plain) != "prepared synthetic input" {
				t.Error("fixture encryption mismatch")
			}
			if submissions.Add(1) >= 3 {
				_, _ = w.Write([]byte(`{"job_id":"cccc3333"}`))
			} else if principal == "researcher-a" {
				_, _ = w.Write([]byte(`{"job_id":"aaaa1111"}`))
			} else {
				_, _ = w.Write([]byte(`{"job_id":"bbbb2222"}`))
			}
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/results/")
		if expected[id] != principal {
			t.Error("TLS identity crossed between reviewers")
			w.WriteHeader(403)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "succeeded", "data": map[string]any{"job_id": id, "status": "succeeded", "release_status": "evaluated_passed", "enc_key": "DO-NOT-EXPOSE", "pipeline_output": map[string]any{"input": "/private/secret", "read_count": 3, "stages": []map[string]any{{"name": "align", "status": "succeeded", "secret": "DO-NOT-EXPOSE"}}}, "scientific_evaluation": map[string]any{"tp": 3, "fp": 0, "fn": 0, "evaluation_status": "passed", "error": "DO-NOT-EXPOSE"}}})
	}))
	backend.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS12}
	backend.StartTLS()
	defer backend.Close()
	g := localGateway(t)
	g.config.UploadURL = backend.URL + "/upload"
	g.config.ResultsURL = backend.URL + "/results"
	g.signKey = signer
	g.encryptKey = &decrypt.PublicKey
	g.experiments["fixture"] = prepared{Spec: Experiment{ID: "fixture", Scope: "synthetic"}, Input: []byte("prepared synthetic input")}
	for _, id := range []string{"a", "b"} {
		r := g.reviewers[id]
		pair, _, _ := issue(t, ca, caKey, r.Spec.Principal, x509.ExtKeyUsageClientAuth, false)
		r.Client = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{pair}}}}
		g.reviewers[id] = r
		defer r.Client.CloseIdleConnections()
	}
	a, ac := login(t, g, "a")
	b, bc := login(t, g, "b")
	for _, test := range []struct {
		cookie *http.Cookie
		csrf   string
	}{{a, ac}, {b, bc}} {
		if w := request(g, "POST", "/api/experiments/fixture/runs", "{}", test.cookie, test.csrf); w.Code != 202 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cookie, id := a, "aaaa1111"
			if i%2 == 1 {
				cookie, id = b, "bbbb2222"
			}
			w := request(g, "GET", "/api/results/"+id, "", cookie, "")
			if w.Code != 200 {
				t.Error(w.Code, w.Body.String())
			}
			if strings.Contains(w.Body.String(), "DO-NOT-EXPOSE") || strings.Contains(w.Body.String(), "/private/") {
				t.Error("unsafe report fields released")
			}
		}(i)
	}
	wg.Wait()
	before := calls.Load()
	if w := request(g, "GET", "/api/results/aaaa1111", "", b, ""); w.Code != 404 {
		t.Fatal("B could obtain A report")
	}
	if calls.Load() != before {
		t.Fatal("cross-owner request reached backend")
	}
	if w := request(g, "POST", "/api/experiments/unknown/runs", "{}", a, ac); w.Code != 404 {
		t.Fatal("unknown experiment accepted")
	}
	if err := os.Remove(g.config.Registry); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(g.config.Registry, 0700); err != nil {
		t.Fatal(err)
	}
	w := request(g, "POST", "/api/experiments/fixture/runs", "{}", a, ac)
	if w.Code != 503 {
		t.Fatal("upstream success with registry failure did not fail closed", w.Code, w.Body.String())
	}
	if _, exists := g.runs["cccc3333"]; exists || g.healthy {
		t.Fatal("provisional submission remained available")
	}
	if w := request(g, "GET", "/api/results/cccc3333", "", a, ""); w.Code != 503 {
		t.Fatal("unpersisted submission was released")
	}
}

func TestRegistryFailureBlocksAllRunRelease(t *testing.T) {
	g := localGateway(t)
	a, csrf := login(t, g, "a")
	// A directory cannot be atomically replaced by the registry's regular file.
	if err := os.Mkdir(g.config.Registry, 0700); err != nil {
		t.Fatal(err)
	}
	g.runs["aaaa1111"] = run{JobID: "aaaa1111", Reviewer: "a", Principal: "researcher-a", Experiment: "fixture", InputHash: strings.Repeat("1", 64), ReferenceHash: strings.Repeat("2", 64)}
	g.reviewers["a"] = identity{Spec: g.reviewers["a"].Spec, Hash: g.reviewers["a"].Hash, Client: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"status":"failed","data":{"job_id":"aaaa1111","status":"failed","release_status":"withheld"}}`)), Header: make(http.Header)}, nil
	})}}
	g.config.ResultsURL = "https://backend.test/results"
	if w := request(g, "GET", "/api/results/aaaa1111", "", a, ""); w.Code != 503 {
		t.Fatal("failed persistence released report", w.Code)
	}
	if g.healthy || g.runs["aaaa1111"].Terminal {
		t.Fatal("registry failure not rolled back/latched")
	}
	for _, path := range []string{"/api/results/aaaa1111", "/api/runs"} {
		if w := request(g, "GET", path, "", a, ""); w.Code != 503 {
			t.Fatal("provisional report accessible", path, w.Code)
		}
	}
	if w := request(g, "POST", "/api/experiments/fixture/runs", "{}", a, csrf); w.Code != 503 {
		t.Fatal("unhealthy gateway submitted run", w.Code)
	}
	if w := request(g, "POST", "/api/sign-out", "{}", a, csrf); w.Code != 200 {
		t.Fatal("logout blocked by unhealthy registry")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return fn(r) }
func TestTypedDTOAndScientificReleaseFailClosed(t *testing.T) {
	cases := []struct {
		name, body string
		want       int
	}{
		{"unknown nested maps", `{"status":"succeeded","data":{"job_id":"aaaa1111","status":"succeeded","release_status":"unassessed","pipeline_output":{"metrics":{"secret":"DO-NOT-EXPOSE"}},"scientific_evaluation":{"evaluation_error_message":"/private/DO-NOT-EXPOSE"}}}`, 200},
		{"tool not boolean", `{"status":"succeeded","data":{"job_id":"aaaa1111","pipeline_output":{"tools":{"minimap2":{"secret":"DO-NOT-EXPOSE"}}}}}`, 502},
		{"incoherent status", `{"status":"succeeded","data":{"job_id":"aaaa1111","status":"failed","release_status":"evaluated_passed"}}`, 502},
		{"positive frozen scientific evidence", fmt.Sprintf(`{"status":"succeeded","data":{"job_id":"aaaa1111","status":"succeeded","release_status":"evaluated_passed","processed_sha256":%q,"scientific_evaluation":{"evaluation_status":"passed","tp":3,"fp":0,"fn":0,"precision":1,"recall":1,"evaluator_returncode":0,"reference_sha256":%q,"truth_sha256":%q,"observed_sha256":%q,"evaluator_sha256":%q}}}`, strings.Repeat("1", 64), strings.Repeat("2", 64), strings.Repeat("3", 64), strings.Repeat("4", 64), strings.Repeat("5", 64)), 200},
		{"unsupported scientific approval", `{"status":"succeeded","data":{"job_id":"aaaa1111","status":"succeeded","release_status":"evaluated_passed","scientific_evaluation":{"evaluation_status":"passed","tp":0,"fp":0,"fn":0,"precision":1,"recall":1}}}`, 200},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			g := localGateway(t)
			a, _ := login(t, g, "a")
			g.runs["aaaa1111"] = run{JobID: "aaaa1111", Reviewer: "a", Principal: "researcher-a", Experiment: "fixture", InputHash: strings.Repeat("1", 64), ReferenceHash: strings.Repeat("2", 64)}
			g.config.ResultsURL = "https://backend.test/results"
			identity := g.reviewers["a"]
			identity.Client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(test.body)), Header: make(http.Header)}, nil
			})}
			g.reviewers["a"] = identity
			w := request(g, "GET", "/api/results/aaaa1111", "", a, "")
			if w.Code != test.want {
				t.Fatal(w.Code, w.Body.String())
			}
			if strings.Contains(w.Body.String(), "DO-NOT-EXPOSE") || strings.Contains(w.Body.String(), "/private/") {
				t.Fatal("nested private material released")
			}
			if test.name == "positive frozen scientific evidence" && !strings.Contains(w.Body.String(), `"release_status":"evaluated_passed"`) {
				t.Fatal("positive evidence blocked", w.Body.String())
			}
			if test.name == "unsupported scientific approval" && strings.Contains(w.Body.String(), `"release_status":"evaluated_passed"`) {
				t.Fatal("empty evaluation approved")
			}
		})
	}
}
func TestRejectUnsafeDeploymentConfiguration(t *testing.T) {
	configs := []Config{
		{Origin: "http://0.0.0.0:8083", Listen: "0.0.0.0:8083", InsecureLoopback: true},
		{Origin: "http://127.0.0.1:8083", Listen: "127.0.0.1:8083"},
		{Origin: "https://example.test/path", TLSCert: "certificate", TLSKey: "key"},
		{Origin: "https://example.test", TLSCert: "certificate", TLSKey: "key", UploadURL: "http://backend/upload", ResultsURL: "https://backend/results"},
	}
	for _, config := range configs {
		if _, err := NewGateway(config); err == nil {
			t.Fatal("unsafe deployment configuration accepted")
		}
	}
}

func TestInFlightReportCannotReleaseAfterPersistenceLatch(t *testing.T) {
	g := localGateway(t)
	a, _ := login(t, g, "a")
	g.config.ResultsURL = "https://backend.test/results"
	for _, id := range []string{"aaaa1111", "bbbb2222"} {
		g.runs[id] = run{JobID: id, Reviewer: "a", Principal: "researcher-a", Experiment: "fixture", InputHash: strings.Repeat("1", 64), ReferenceHash: strings.Repeat("2", 64)}
	}
	// Report A is fully approved upstream, but blocked until report B trips the latch.
	entered, unblock := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(unblock) }) }
	defer release()
	reviewer := g.reviewers["a"]
	reviewer.Client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body := `{"status":"failed","data":{"job_id":"bbbb2222","status":"failed","release_status":"withheld"}}`
		if strings.HasSuffix(r.URL.Path, "aaaa1111") {
			close(entered)
			<-unblock
			body = fmt.Sprintf(`{"status":"succeeded","data":{"job_id":"aaaa1111","status":"succeeded","release_status":"evaluated_passed","processed_sha256":%q,"scientific_evaluation":{"evaluation_status":"passed","tp":3,"fp":0,"fn":0,"precision":1,"recall":1,"evaluator_returncode":0,"reference_sha256":%q,"truth_sha256":%q,"observed_sha256":%q,"evaluator_sha256":%q}}}`, strings.Repeat("1", 64), strings.Repeat("2", 64), strings.Repeat("3", 64), strings.Repeat("4", 64), strings.Repeat("5", 64))
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	g.reviewers["a"] = reviewer
	response := make(chan *httptest.ResponseRecorder, 1)
	go func() { response <- request(g, "GET", "/api/results/aaaa1111", "", a, "") }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("upstream report did not enter blocked phase")
	}
	if err := os.Mkdir(g.config.Registry, 0700); err != nil {
		t.Fatal(err)
	}
	failure := request(g, "GET", "/api/results/bbbb2222", "", a, "")
	if failure.Code != 503 {
		t.Fatal("second report did not latch persistence failure", failure.Code)
	}
	// Storage recovers, but no subsequent successful save may clear the process latch.
	if err := os.Remove(g.config.Registry); err != nil {
		t.Fatal(err)
	}
	release()
	var blocked *httptest.ResponseRecorder
	select {
	case blocked = <-response:
	case <-time.After(3 * time.Second):
		t.Fatal("blocked report did not complete")
	}
	if blocked.Code != 503 || strings.Contains(blocked.Body.String(), "evaluated_passed") {
		t.Fatal("in-flight approved report released after latch", blocked.Code, blocked.Body.String())
	}
	g.mu.Lock()
	healthy, terminal := g.healthy, g.runs["aaaa1111"].Terminal
	g.mu.Unlock()
	if healthy || terminal {
		t.Fatal("later report implicitly recovered or committed registry")
	}
	if _, err := os.Stat(g.config.Registry); !os.IsNotExist(err) {
		t.Fatal("later request rewrote the repaired registry")
	}
	if history := request(g, "GET", "/api/runs", "", a, ""); history.Code != 503 {
		t.Fatal("history released after latch", history.Code)
	}
}
