// SPDX-License-Identifier: AGPL-3.0-only
// Reviewer browser entry: explicit identities, prepared synthetic inputs and per-owner mTLS.
package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const maxFixtureBytes = 10 << 20

var safeID = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)
var jobIDPattern = regexp.MustCompile(`^[a-f0-9]{8,64}$`)

type Reviewer struct {
	ID         string `json:"id"`
	Principal  string `json:"principal"`
	Cert       string `json:"cert"`
	Key        string `json:"key"`
	AccessHash string `json:"access_code_sha256"`
	Enabled    bool   `json:"enabled"`
}
type Experiment struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	File      string `json:"file"`
	Reference string `json:"reference"`
	Scope     string `json:"scope"`
}
type Config struct {
	Listen           string       `json:"listen_address"`
	Origin           string       `json:"public_origin"`
	TLSCert          string       `json:"tls_cert"`
	TLSKey           string       `json:"tls_key"`
	InsecureLoopback bool         `json:"allow_insecure_loopback"`
	UploadURL        string       `json:"upload_url"`
	ResultsURL       string       `json:"results_url"`
	CA               string       `json:"ca_cert"`
	EncryptionCert   string       `json:"encryption_cert"`
	SigningKey       string       `json:"signing_key"`
	Registry         string       `json:"run_registry_path"`
	UIDir            string       `json:"ui_dir"`
	Reviewers        []Reviewer   `json:"reviewers"`
	Experiments      []Experiment `json:"experiments"`
}
type prepared struct {
	Spec          Experiment
	Input         []byte
	Hash          string
	ReferenceHash string
}
type identity struct {
	Spec   Reviewer
	Hash   [32]byte
	Client *http.Client
}
type session struct {
	Reviewer          string
	CSRF              string
	Created, LastSeen time.Time
}
type run struct {
	JobID         string    `json:"job_id"`
	Reviewer      string    `json:"reviewer_id"`
	Principal     string    `json:"principal"`
	Experiment    string    `json:"experiment_id"`
	Created       time.Time `json:"created_at"`
	Terminal      bool      `json:"terminal"`
	InputHash     string    `json:"input_sha256"`
	ReferenceHash string    `json:"reference_sha256"`
}
type throttle struct {
	Start time.Time
	Count int
}
type Gateway struct {
	config      Config
	reviewers   map[string]identity
	experiments map[string]prepared
	encryptKey  *rsa.PublicKey
	signKey     *rsa.PrivateKey
	mu          sync.Mutex
	sessions    map[[32]byte]session
	runs        map[string]run
	reserved    map[string]bool
	rates       map[string]throttle
	now         func() time.Time
	healthy     bool
	secure      bool
}

func main() {
	path := os.Getenv("BIOZERO_REVIEWER_CONFIG")
	if path == "" {
		log.Fatal("BIOZERO_REVIEWER_CONFIG is required")
	}
	file, err := os.Open(path)
	if err != nil {
		log.Fatal("reviewer configuration unavailable")
	}
	defer file.Close()
	var cfg Config
	dec := json.NewDecoder(io.LimitReader(file, 1<<20))
	dec.DisallowUnknownFields()
	if dec.Decode(&cfg) != nil || dec.Decode(new(any)) != io.EOF {
		log.Fatal("invalid reviewer configuration")
	}
	gateway, err := NewGateway(cfg)
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{Addr: cfg.Listen, Handler: gateway, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 15 * time.Second, WriteTimeout: 45 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	log.Print("reviewer gateway starting; prepared synthetic experiments only")
	if gateway.secure {
		err = server.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
	} else {
		err = server.ListenAndServe()
	}
	log.Fatal(err)
}

func NewGateway(cfg Config) (*Gateway, error) {
	origin, err := url.Parse(cfg.Origin)
	if err != nil || origin.Host == "" || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" {
		return nil, errors.New("public_origin must be an exact HTTP(S) origin")
	}
	secure := origin.Scheme == "https"
	if !secure {
		host, _, splitErr := net.SplitHostPort(cfg.Listen)
		ip := net.ParseIP(host)
		if origin.Scheme != "http" || !cfg.InsecureLoopback || splitErr != nil || ip == nil || !ip.IsLoopback() || origin.Host != cfg.Listen {
			return nil, errors.New("HTTP requires explicit loopback-only mode and matching public origin")
		}
	} else if cfg.InsecureLoopback || cfg.TLSCert == "" || cfg.TLSKey == "" {
		return nil, errors.New("HTTPS requires TLS keys and no insecure mode")
	}
	for _, upstream := range []string{cfg.UploadURL, cfg.ResultsURL} {
		u, e := url.Parse(upstream)
		if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return nil, errors.New("fixed HTTPS upstream URLs required")
		}
	}
	if cfg.Registry == "" {
		return nil, errors.New("run_registry_path is required")
	}
	caBytes, err := os.ReadFile(cfg.CA)
	if err != nil {
		return nil, errors.New("CA unavailable")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caBytes) {
		return nil, errors.New("invalid CA")
	}
	g := &Gateway{config: cfg, secure: secure, healthy: true, reviewers: map[string]identity{}, experiments: map[string]prepared{},
		sessions: map[[32]byte]session{}, runs: map[string]run{}, reserved: map[string]bool{}, rates: map[string]throttle{}, now: time.Now}
	if len(cfg.Reviewers) == 0 || len(cfg.Reviewers) > 100 || len(cfg.Experiments) == 0 || len(cfg.Experiments) > 16 {
		return nil, errors.New("bounded reviewers and prepared experiments required")
	}
	usedPrincipals := map[string]bool{}
	for _, r := range cfg.Reviewers {
		if !safeID.MatchString(r.ID) || !safeID.MatchString(r.Principal) || usedPrincipals[r.Principal] {
			return nil, errors.New("reviewer identities must be distinct")
		}
		if _, exists := g.reviewers[r.ID]; exists {
			return nil, errors.New("duplicate reviewer ID")
		}
		usedPrincipals[r.Principal] = true
		hash, e := hex.DecodeString(r.AccessHash)
		if e != nil || len(hash) != 32 {
			return nil, errors.New("reviewer needs SHA256 of random access code")
		}
		cert, e := tls.LoadX509KeyPair(r.Cert, r.Key)
		if e != nil {
			return nil, errors.New("reviewer certificate unavailable")
		}
		leaf, e := x509.ParseCertificate(cert.Certificate[0])
		if e != nil || leaf.Subject.CommonName != r.Principal {
			return nil, errors.New("reviewer principal disagrees with certificate")
		}
		if _, e = leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); e != nil {
			return nil, errors.New("reviewer certificate is not a valid client identity")
		}
		// A separate immutable transport owns each TLS identity; keep-alive cannot mix principals.
		client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{cert}}, MaxConnsPerHost: 4, IdleConnTimeout: 30 * time.Second},
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
		var digest [32]byte
		copy(digest[:], hash)
		g.reviewers[r.ID] = identity{r, digest, client}
	}
	certBytes, err := os.ReadFile(cfg.EncryptionCert)
	if err != nil {
		return nil, errors.New("encryption certificate unavailable")
	}
	block, _ := pem.Decode(certBytes)
	if block == nil {
		return nil, errors.New("invalid encryption certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.New("invalid encryption certificate")
	}
	if _, err = cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return nil, errors.New("untrusted encryption certificate")
	}
	g.encryptKey, _ = cert.PublicKey.(*rsa.PublicKey)
	if g.encryptKey == nil || g.encryptKey.N.BitLen() < 2048 {
		return nil, errors.New("RSA encryption key of at least 2048 bits required")
	}
	keyBytes, err := os.ReadFile(cfg.SigningKey)
	if err != nil {
		return nil, errors.New("signing key unavailable")
	}
	block, _ = pem.Decode(keyBytes)
	if block == nil {
		return nil, errors.New("invalid signing key")
	}
	g.signKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		key, e := x509.ParsePKCS8PrivateKey(block.Bytes)
		if e == nil {
			g.signKey, _ = key.(*rsa.PrivateKey)
		}
	}
	if g.signKey == nil || g.signKey.N.BitLen() < 2048 {
		return nil, errors.New("RSA signing key of at least 2048 bits required")
	}
	for _, e := range cfg.Experiments {
		if !safeID.MatchString(e.ID) || e.Scope != "synthetic" || e.Label == "" {
			return nil, errors.New("only named synthetic prepared experiments are allowed")
		}
		if _, exists := g.experiments[e.ID]; exists {
			return nil, errors.New("duplicate experiment ID")
		}
		input, err := readBoundedRegular(e.File)
		if err != nil || len(input) == 0 {
			return nil, errors.New("prepared fixture must be a regular file of at most 10 MiB")
		}
		reference, err := readBoundedRegular(e.Reference)
		if err != nil || len(reference) == 0 {
			return nil, errors.New("prepared reference must be a regular file of at most 10 MiB")
		}
		a, b := sha256.Sum256(input), sha256.Sum256(reference)
		g.experiments[e.ID] = prepared{e, input, hex.EncodeToString(a[:]), hex.EncodeToString(b[:])}
	}
	if err = g.loadRegistry(); err != nil {
		return nil, err
	}
	return g, nil
}
func readBoundedRegular(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxFixtureBytes {
		return nil, errors.New("invalid prepared file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxFixtureBytes+1))
	if len(data) > maxFixtureBytes {
		return nil, errors.New("fixture too large")
	}
	return data, err
}
func token() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}
func (g *Gateway) cookieName() string {
	if g.secure {
		return "__Host-bz_session"
	}
	return "bz_local_session"
}
func (g *Gateway) json(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
func (g *Gateway) fail(w http.ResponseWriter, status int, code string) {
	g.json(w, status, map[string]string{"error": code})
}
func parseJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return false
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	dec.DisallowUnknownFields()
	return dec.Decode(target) == nil && dec.Decode(new(any)) == io.EOF
}
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; connect-src 'self'")
	origin, _ := url.Parse(g.config.Origin)
	if r.Host != origin.Host {
		g.fail(w, 403, "host_invalid")
		return
	}
	if supplied := r.Header.Get("Origin"); supplied != "" && supplied != g.config.Origin {
		g.fail(w, 403, "origin_invalid")
		return
	}
	if r.Method != "GET" {
		if r.Header.Get("Origin") != g.config.Origin || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			g.fail(w, 403, "origin_invalid")
			return
		}
	}
	if r.URL.Path == "/health" && r.Method == "GET" {
		g.json(w, 200, map[string]string{"status": "gateway_alive", "scientific_readiness": "unverified"})
		return
	}
	if r.URL.Path == "/api/sign-in" && r.Method == "POST" {
		g.signIn(w, r)
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/api/") {
		// Serve only fixed UI assets. No arbitrary file paths or directory listings.
		names := map[string]string{"/": "index.html", "/index.html": "index.html", "/app.js": "app.js", "/styles.css": "styles.css"}
		if name, ok := names[r.URL.Path]; ok && r.Method == "GET" && g.config.UIDir != "" {
			http.ServeFile(w, r, filepath.Join(g.config.UIDir, name))
			return
		}
		g.fail(w, 404, "not_found")
		return
	}
	s, key, ok := g.authenticate(r)
	if !ok {
		g.fail(w, 401, "session_required")
		return
	}
	if r.Method != "GET" && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(s.CSRF)) != 1 {
		g.fail(w, 403, "csrf_invalid")
		return
	}
	g.mu.Lock()
	healthy := g.healthy
	g.mu.Unlock()
	if !healthy && r.URL.Path != "/api/session" && r.URL.Path != "/api/sign-out" && r.URL.Path != "/api/experiments" {
		g.fail(w, 503, "run_registry_unavailable")
		return
	}
	switch {
	case r.URL.Path == "/api/session" && r.Method == "GET":
		g.json(w, 200, map[string]string{"reviewer": s.Reviewer, "csrf_token": s.CSRF})
	case r.URL.Path == "/api/experiments" && r.Method == "GET":
		catalog := []map[string]string{}
		for _, e := range g.experiments {
			catalog = append(catalog, map[string]string{"id": e.Spec.ID, "label": e.Spec.Label, "scope": e.Spec.Scope, "input_sha256": e.Hash, "reference_sha256": e.ReferenceHash})
		}
		sort.Slice(catalog, func(i, j int) bool { return catalog[i]["id"] < catalog[j]["id"] })
		g.json(w, 200, catalog)
	case r.URL.Path == "/api/runs" && r.Method == "GET":
		g.mu.Lock()
		defer g.mu.Unlock()
		if !g.healthy {
			g.fail(w, 503, "run_registry_unavailable")
			return
		}
		rows := []run{}
		for _, row := range g.runs {
			if row.Reviewer == s.Reviewer {
				rows = append(rows, row)
			}
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].Created.After(rows[j].Created) })
		g.json(w, 200, rows)
	case r.URL.Path == "/api/sign-out" && r.Method == "POST":
		g.mu.Lock()
		delete(g.sessions, key)
		g.mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: g.cookieName(), Path: "/", MaxAge: -1, HttpOnly: true, Secure: g.secure, SameSite: http.SameSiteStrictMode})
		g.json(w, 200, map[string]string{"status": "signed_out"})
	case strings.HasPrefix(r.URL.Path, "/api/experiments/") && strings.HasSuffix(r.URL.Path, "/runs") && r.Method == "POST":
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/experiments/"), "/runs")
		g.startRun(w, r, s, id)
	case strings.HasPrefix(r.URL.Path, "/api/results/") && r.Method == "GET":
		g.results(w, r, s, strings.TrimPrefix(r.URL.Path, "/api/results/"))
	default:
		g.fail(w, 404, "not_found")
	}
}
func (g *Gateway) allowRate(key string, limit int) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	for k, v := range g.rates {
		if now.Sub(v.Start) > time.Minute {
			delete(g.rates, k)
		}
	}
	v := g.rates[key]
	if now.Sub(v.Start) > time.Minute {
		v = throttle{Start: now}
	}
	if v.Count >= limit || len(g.rates) > 10000 {
		return false
	}
	v.Count++
	g.rates[key] = v
	return true
}
func (g *Gateway) signIn(w http.ResponseWriter, r *http.Request) {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if !g.allowRate("signin:"+ip, 10) {
		g.fail(w, 429, "rate_limited")
		return
	}
	var body struct {
		ID   string `json:"id"`
		Code string `json:"access_code"`
	}
	if !parseJSON(w, r, &body) {
		g.fail(w, 400, "invalid_request")
		return
	}
	reviewer, ok := g.reviewers[body.ID]
	raw, e := base64.RawURLEncoding.DecodeString(body.Code)
	digest := sha256.Sum256([]byte(body.Code))
	valid := subtle.ConstantTimeCompare(digest[:], reviewer.Hash[:]) == 1
	if !ok || !reviewer.Spec.Enabled || e != nil || len(raw) != 32 || !valid {
		g.fail(w, 401, "credentials_invalid")
		return
	}
	value, err := token()
	if err != nil {
		g.fail(w, 503, "entropy_unavailable")
		return
	}
	csrf, err := token()
	if err != nil {
		g.fail(w, 503, "entropy_unavailable")
		return
	}
	key := sha256.Sum256([]byte(value))
	g.mu.Lock()
	// Single active browser session per reviewer; a new sign-in revokes the old one.
	for existing, s := range g.sessions {
		if s.Reviewer == body.ID || g.now().Sub(s.Created) > 8*time.Hour {
			delete(g.sessions, existing)
		}
	}
	g.sessions[key] = session{body.ID, csrf, g.now(), g.now()}
	g.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: g.cookieName(), Value: value, Path: "/", Secure: g.secure, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 28800})
	g.json(w, 200, map[string]string{"reviewer": body.ID, "csrf_token": csrf})
}
func (g *Gateway) authenticate(r *http.Request) (session, [32]byte, bool) {
	var empty [32]byte
	cookies := r.Cookies()
	count := 0
	value := ""
	for _, c := range cookies {
		if c.Name == g.cookieName() {
			count++
			value = c.Value
		}
	}
	if count != 1 {
		return session{}, empty, false
	}
	decoded, e := base64.RawURLEncoding.DecodeString(value)
	if e != nil || len(decoded) != 32 {
		return session{}, empty, false
	}
	key := sha256.Sum256([]byte(value))
	g.mu.Lock()
	defer g.mu.Unlock()
	s, ok := g.sessions[key]
	reviewer, exists := g.reviewers[s.Reviewer]
	if !ok || !exists || !reviewer.Spec.Enabled || g.now().Sub(s.Created) >= 8*time.Hour || g.now().Sub(s.LastSeen) >= 30*time.Minute {
		delete(g.sessions, key)
		return session{}, key, false
	}
	s.LastSeen = g.now()
	g.sessions[key] = s
	return s, key, true
}
func (g *Gateway) startRun(w http.ResponseWriter, r *http.Request, s session, id string) {
	experiment, ok := g.experiments[id]
	if !ok {
		g.fail(w, 404, "experiment_not_found")
		return
	}
	// Request content is intentionally empty JSON: no filename, paths or identities are accepted.
	var body struct{}
	if !parseJSON(w, r, &body) {
		g.fail(w, 400, "invalid_request")
		return
	}
	if !g.allowRate("run:"+s.Reviewer, 5) {
		g.fail(w, 429, "rate_limited")
		return
	}
	g.mu.Lock()
	if !g.healthy {
		g.mu.Unlock()
		g.fail(w, 503, "run_registry_unavailable")
		return
	}
	active, total := 0, 0
	busy := g.reserved[s.Reviewer]
	for _, row := range g.runs {
		if !row.Terminal {
			active++
			if row.Reviewer == s.Reviewer {
				busy = true
			}
		}
		if row.Reviewer == s.Reviewer {
			total++
		}
	}
	for _, reserved := range g.reserved {
		if reserved {
			active++
		}
	}
	if busy || active >= 2 || total >= 20 {
		g.mu.Unlock()
		g.fail(w, 429, "run_quota_exceeded")
		return
	}
	g.reserved[s.Reviewer] = true
	g.mu.Unlock()
	defer func() { g.mu.Lock(); delete(g.reserved, s.Reviewer); g.mu.Unlock() }()
	reviewer := g.reviewers[s.Reviewer]
	job, err := g.submit(r.Context(), reviewer, experiment)
	if err != nil {
		g.fail(w, 502, "prepared_run_submission_failed")
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	// Upstream requests admitted earlier may finish privately after a failure.
	// The latch is authoritative at commit/release and cannot heal via a later save.
	if !g.healthy {
		g.fail(w, 503, "run_registry_unavailable")
		return
	}
	if _, exists := g.runs[job]; exists {
		g.fail(w, 502, "backend_duplicate_job")
		return
	}
	g.runs[job] = run{JobID: job, Reviewer: s.Reviewer, Principal: reviewer.Spec.Principal, Experiment: id, Created: g.now(), InputHash: experiment.Hash, ReferenceHash: experiment.ReferenceHash}
	err = g.saveRegistryLocked()
	if err != nil {
		delete(g.runs, job)
		g.healthy = false
	}
	if err != nil {
		g.fail(w, 503, "run_registry_unavailable")
		return
	}
	g.json(w, 202, map[string]string{"job_id": job, "experiment_id": id})
}
func (g *Gateway) submit(ctx context.Context, reviewer identity, experiment prepared) (string, error) {
	aesKey, iv := make([]byte, 32), make([]byte, 12)
	if _, err := rand.Read(aesKey); err != nil {
		return "", err
	}
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	ciphertext := aead.Seal(nil, iv, experiment.Input, nil)
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, g.encryptKey, append(aesKey, iv...), nil)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(ciphertext)
	sig, err := rsa.SignPSS(rand.Reader, g.signKey, crypto.SHA256, digest[:], nil)
	if err != nil {
		return "", err
	}
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", experiment.Spec.ID+".enc")
	if err != nil {
		return "", err
	}
	if _, err = part.Write(ciphertext); err != nil {
		return "", err
	}
	fields := map[string]string{"client_id": reviewer.Spec.Principal, "enc_alg": "aes-256-gcm+rsa-oaep-sha256", "enc_key": hex.EncodeToString(wrapped), "sig_alg": "rsa-pss-sha256", "sig": hex.EncodeToString(sig)}
	for key, value := range fields {
		if err = writer.WriteField(key, value); err != nil {
			return "", err
		}
	}
	if err = writer.Close(); err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.config.UploadURL, &body)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("X-Content-SHA256", hex.EncodeToString(digest[:]))
	resp, err := reviewer.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", errors.New("upstream rejected submission")
	}
	var output struct {
		JobID string `json:"job_id"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&output) != nil || !jobIDPattern.MatchString(output.JobID) {
		return "", errors.New("invalid upload response")
	}
	return output.JobID, nil
}
func (g *Gateway) results(w http.ResponseWriter, r *http.Request, s session, id string) {
	if !jobIDPattern.MatchString(id) {
		g.fail(w, 404, "report_not_found")
		return
	}
	g.mu.Lock()
	if !g.healthy {
		g.mu.Unlock()
		g.fail(w, 503, "run_registry_unavailable")
		return
	}
	row, ok := g.runs[id]
	g.mu.Unlock()
	reviewer := g.reviewers[s.Reviewer]
	if !ok || row.Reviewer != s.Reviewer || row.Principal != reviewer.Spec.Principal {
		g.fail(w, 404, "report_not_found")
		return
	}
	if !g.allowRate("results:"+s.Reviewer, 120) {
		g.fail(w, 429, "rate_limited")
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, strings.TrimRight(g.config.ResultsURL, "/")+"/"+id, nil)
	if err != nil {
		g.fail(w, 502, "backend_unavailable")
		return
	}
	resp, err := reviewer.Client.Do(req)
	if err != nil {
		g.fail(w, 502, "backend_unavailable")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		g.fail(w, 502, "backend_authorization_or_result_failed")
		return
	}
	var output struct {
		Status    string     `json:"status"`
		ErrorCode string     `json:"error_code,omitempty"`
		Data      reportData `json:"data,omitempty"`
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))
	if dec.Decode(&output) != nil || dec.Decode(new(any)) != io.EOF || !validReport(&output.Data) {
		g.fail(w, 502, "backend_protocol_invalid")
		return
	}
	terminal := false
	switch output.Status {
	case "succeeded", "incomplete", "rejected", "failed", "timed_out":
		terminal = true
	case "uploaded", "running":
	default:
		g.fail(w, 502, "backend_protocol_invalid")
		return
	}
	if (output.Data.JobID != "" && output.Data.JobID != id) || (output.Data.Status != "" && output.Data.Status != output.Status) || !optionalWord(output.ErrorCode) {
		g.fail(w, 502, "backend_protocol_invalid")
		return
	}
	output.Data.JobID = "" // Envelope contains the authorized job ID once.
	if output.Data.ReleaseStatus == "evaluated_passed" {
		e := output.Data.Evaluation
		if output.Status != "succeeded" || e == nil || e.Status != "passed" || e.TP == nil || *e.TP <= 0 || e.FP == nil || *e.FP != 0 || e.FN == nil || *e.FN != 0 || e.Precision == nil || *e.Precision != 1 || e.Recall == nil || *e.Recall != 1 || e.ReturnCode == nil || *e.ReturnCode != 0 || e.TruthHash == "" || e.ObservedHash == "" || e.EvaluatorHash == "" || row.InputHash == "" || output.Data.ProcessedHash != row.InputHash || row.ReferenceHash == "" || e.ReferenceHash != row.ReferenceHash {
			output.Data.ReleaseStatus = "withheld"
			if e == nil {
				e = &evaluationDTO{}
				output.Data.Evaluation = e
			}
			e.ErrorCode = "gateway_evidence_mismatch"
		}
	}
	if output.Data.Evaluation != nil {
		output.Data.Evaluation.Scope = "synthetic normalized allele presence; no clinical validation"
	}
	// Serialize the complete report release with persistence failures. A response
	// released before a later latch stays historical; an in-flight response which
	// reaches this boundary after the latch returns 503, even if storage recovered.
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.healthy {
		g.fail(w, 503, "run_registry_unavailable")
		return
	}
	if terminal {
		previous := g.runs[id]
		row.Terminal = true
		g.runs[id] = row
		err = g.saveRegistryLocked()
		if err != nil {
			g.runs[id] = previous
			g.healthy = false
		}
		if err != nil {
			g.fail(w, 503, "run_registry_unavailable")
			return
		}
	}
	g.json(w, 200, map[string]any{"job_id": id, "experiment_id": row.Experiment, "status": output.Status, "error_code": output.ErrorCode, "data": output.Data})

}
func (g *Gateway) loadRegistry() error {
	dir := filepath.Dir(g.config.Registry)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return errors.New("registry directory unavailable")
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return errors.New("registry directory must have mode 0700")
	}
	info, err = os.Lstat(g.config.Registry)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return errors.New("registry must be a regular mode-0600 file")
	}
	data, err := os.ReadFile(g.config.Registry)
	if err != nil || len(data) > 1<<20 {
		return errors.New("registry unavailable or too large")
	}
	var rows []run
	if json.Unmarshal(data, &rows) != nil {
		return errors.New("invalid run registry")
	}
	for _, row := range rows {
		reviewer, exists := g.reviewers[row.Reviewer]
		if !exists || row.Principal != reviewer.Spec.Principal || !jobIDPattern.MatchString(row.JobID) {
			return errors.New("registry identity invalid")
		}
		if _, exists = g.experiments[row.Experiment]; !exists {
			return errors.New("registry experiment unavailable")
		}
		if _, exists = g.runs[row.JobID]; exists {
			return errors.New("duplicate registry job")
		}
		g.runs[row.JobID] = row
	}
	return nil
}
func (g *Gateway) saveRegistryLocked() error {
	rows := make([]run, 0, len(g.runs))
	for _, row := range g.runs {
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].JobID < rows[j].JobID })
	data, err := json.Marshal(rows)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(g.config.Registry), ".registry-*")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write(data)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(name, g.config.Registry); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(g.config.Registry))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

// Typed report DTOs deliberately exclude paths, raw stderr, key metadata and arbitrary maps.
type reportData struct {
	JobID          string         `json:"job_id,omitempty"`
	Status         string         `json:"status,omitempty"`
	UploadHash     string         `json:"upload_sha256,omitempty"`
	ProcessedHash  string         `json:"processed_sha256,omitempty"`
	SignatureValid *bool          `json:"signature_valid,omitempty"`
	Decrypted      *bool          `json:"decrypted,omitempty"`
	ErrorCode      string         `json:"error_code,omitempty"`
	ReleaseStatus  string         `json:"release_status,omitempty"`
	Evaluation     *evaluationDTO `json:"scientific_evaluation,omitempty"`
	Pipeline       *pipelineDTO   `json:"pipeline_output,omitempty"`
}
type evaluationDTO struct {
	Status        string   `json:"evaluation_status,omitempty"`
	TP            *int     `json:"tp,omitempty"`
	FP            *int     `json:"fp,omitempty"`
	FN            *int     `json:"fn,omitempty"`
	Precision     *float64 `json:"precision,omitempty"`
	Recall        *float64 `json:"recall,omitempty"`
	Reproducible  *bool    `json:"reproducible_callset,omitempty"`
	ReturnCode    *int     `json:"evaluator_returncode,omitempty"`
	TruthHash     string   `json:"truth_sha256,omitempty"`
	ReferenceHash string   `json:"reference_sha256,omitempty"`
	ObservedHash  string   `json:"observed_sha256,omitempty"`
	EvaluatorHash string   `json:"evaluator_sha256,omitempty"`
	ErrorCode     string   `json:"evaluation_error_code,omitempty"`
	Scope         string   `json:"scope,omitempty"`
}
type pipelineDTO struct {
	Schema        int             `json:"schema_version,omitempty"`
	Status        string          `json:"pipeline_status,omitempty"`
	Mode          string          `json:"mode,omitempty"`
	ReadCount     int             `json:"read_count,omitempty"`
	ReadLength    int             `json:"avg_read_length,omitempty"`
	LineCount     int             `json:"line_count,omitempty"`
	Hash          string          `json:"sha256,omitempty"`
	ReferenceHash string          `json:"reference_sha256,omitempty"`
	Tools         map[string]bool `json:"tools,omitempty"`
	Stages        []struct {
		Name       string `json:"name"`
		Status     string `json:"status"`
		Code       string `json:"error_code,omitempty"`
		ReturnCode int    `json:"returncode"`
	} `json:"stages,omitempty"`
	Errors []struct {
		Stage string `json:"stage"`
		Code  string `json:"code"`
	} `json:"errors,omitempty"`
}

func optionalWord(value string) bool { return value == "" || safeID.MatchString(value) }
func optionalHash(value string) bool {
	if value == "" {
		return true
	}
	data, err := hex.DecodeString(value)
	return err == nil && len(data) == 32
}
func validReport(report *reportData) bool {
	if !optionalHash(report.UploadHash) || !optionalHash(report.ProcessedHash) || !optionalWord(report.ErrorCode) {
		return false
	}
	switch report.ReleaseStatus {
	case "", "unassessed", "withheld", "evaluated_passed":
	default:
		return false
	}
	if e := report.Evaluation; e != nil {
		if !optionalWord(e.Status) || !optionalWord(e.ErrorCode) || !optionalHash(e.TruthHash) || !optionalHash(e.ReferenceHash) || !optionalHash(e.ObservedHash) || !optionalHash(e.EvaluatorHash) {
			return false
		}
		for _, count := range []*int{e.TP, e.FP, e.FN} {
			if count != nil && (*count < 0 || *count > 10000000) {
				return false
			}
		}
		for _, fraction := range []*float64{e.Precision, e.Recall} {
			if fraction != nil && (*fraction < 0 || *fraction > 1) {
				return false
			}
		}
	}
	if p := report.Pipeline; p != nil {
		if !optionalWord(p.Status) || !optionalWord(p.Mode) || !optionalHash(p.Hash) || !optionalHash(p.ReferenceHash) || p.ReadCount < 0 || p.ReadLength < 0 || p.LineCount < 0 || len(p.Stages) > 32 || len(p.Errors) > 32 {
			return false
		}
		for tool := range p.Tools {
			if tool != "minimap2" && tool != "samtools" && tool != "bcftools" && tool != "fastp" {
				delete(p.Tools, tool)
			}
		}
		for _, stage := range p.Stages {
			if !optionalWord(stage.Name) || !optionalWord(stage.Status) || !optionalWord(stage.Code) {
				return false
			}
		}
		for _, stage := range p.Errors {
			if !optionalWord(stage.Stage) || !optionalWord(stage.Code) {
				return false
			}
		}
	}
	return true
}
