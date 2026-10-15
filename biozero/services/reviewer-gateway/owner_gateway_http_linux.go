//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	projection "biozero/enclave-runner/receiptprojection"
	ownership "biozero/ownership-authority"
)

const ogCookieName = "__Host-bz_session"
const ogPostLimit int64 = 4096

type ownerGatewayHTTPStore interface {
	LookupRequest(context.Context, string, string) (ownerGatewayRun, bool, error)
	Intent(context.Context, string, string, string) (ownerGatewayRun, bool, error)
	Run(context.Context, string, string) (ownerGatewayRun, error)
	Runs(context.Context, string) ([]ownerGatewayRun, error)
	AuthorizeJob(context.Context, string, string) (ownerGatewayRun, ownership.VerifiedAcceptance, error)
	ObserveResult(context.Context, string, ownerGatewayResult) (ownerGatewayRun, error)
	Guard(context.Context, func() error) error
	GuardRun(context.Context, string, ownerGatewayRun, func() error) error
	GuardRunCurrent(context.Context, string, string, func(ownerGatewayRun) error) error
	Execute(context.Context, string) error
	Close() error
}
type ogSession struct {
	Reviewer, Credential, CSRF string
	Epoch                      uint64
	Created, Seen              time.Time
}
type ogLease struct {
	Key     [32]byte
	Session ogSession
}
type ogRate struct {
	Start time.Time
	Count int
}
type ownerGateway struct {
	// Session/queue authority always precedes Store authority. Never acquire this
	// mutex from inside Execute or a Store callback that did not enter here first.
	mu            sync.Mutex
	material      ownerGatewayMaterial
	store         ownerGatewayHTTPStore
	host          string
	sessions      map[[32]byte]ogSession
	peers         map[string]ogRate
	reviewerRates map[string]ogRate
	epoch         uint64
	now           func() time.Time
	handlers      chan struct{}
	active        map[string]string
	queue         chan ownerGatewayRun
	workers       sync.WaitGroup
	serviceCtx    context.Context
	cancel        context.CancelFunc
	stopping      bool
	execute       func(context.Context, string) error
	query         func(context.Context, ownerGatewayReviewer, ownerGatewayRun, ownership.VerifiedAcceptance) (ownerGatewayResult, error)
	beforeWrite   func() // private causal barrier, never request/config controlled
}
type ogRunView struct {
	SchemaVersion int    `json:"schema_version"`
	Domain        string `json:"domain"`
	RunID         string `json:"run_id"`
	RequestID     string `json:"request_id"`
	JobID         string `json:"job_id"`
	ExperimentID  string `json:"experiment_id"`
	Phase         string `json:"phase"`
	ErrorCode     string `json:"error_code"`
	NeedsOperator bool   `json:"needs_operator"`
}
type ogEvaluation struct {
	EvaluationStatus string   `json:"evaluation_status"`
	Error            string   `json:"error,omitempty"`
	TP               *int64   `json:"tp,omitempty"`
	FP               *int64   `json:"fp,omitempty"`
	FN               *int64   `json:"fn,omitempty"`
	Precision        *float64 `json:"precision"`
	Recall           *float64 `json:"recall"`
	Unexpected       *int64   `json:"unexpected_count,omitempty"`
	Missing          *int64   `json:"missing_count,omitempty"`
	Scope            string   `json:"scope,omitempty"`
}
type ogPipelineView struct {
	SchemaVersion     int    `json:"schema_version"`
	Mode              string `json:"mode"`
	Status            string `json:"pipeline_status"`
	ReadCount         *int64 `json:"read_count,omitempty"`
	AverageReadLength *int64 `json:"avg_read_length,omitempty"`
	LineCount         *int64 `json:"line_count,omitempty"`
	ByteCount         *int64 `json:"byte_count,omitempty"`
	VariantCount      *int64 `json:"variant_count,omitempty"`
	SHA256            string `json:"sha256,omitempty"`
	ReferenceSHA256   string `json:"reference_sha256,omitempty"`
	Stages            []struct {
		Status    string `json:"status"`
		ErrorCode string `json:"error_code,omitempty"`
	} `json:"stages"`
}
type ogDetectionView struct {
	Score   float64  `json:"score"`
	Verdict string   `json:"verdict"`
	Reasons []string `json:"reasons"`
}
type ogResultView struct {
	SchemaVersion        int                           `json:"schema_version"`
	Domain               string                        `json:"domain"`
	RunID                string                        `json:"run_id"`
	JobID                string                        `json:"job_id"`
	ExperimentID         string                        `json:"experiment_id"`
	AcceptanceSHA256     string                        `json:"acceptance_sha256"`
	ExecutionState       string                        `json:"execution_state"`
	Status               string                        `json:"status"`
	ReleaseStatus        string                        `json:"release_status"`
	ErrorCode            string                        `json:"error_code"`
	PipelineOutput       *ogPipelineView               `json:"pipeline_output"`
	ScientificEvaluation *ogEvaluation                 `json:"scientific_evaluation"`
	Detection            *ogDetectionView              `json:"detection"`
	ArtifactExecution    *projection.ArtifactExecution `json:"artifact_execution"`
}

func newOwnerGateway(ctx context.Context, m ownerGatewayMaterial, s ownerGatewayHTTPStore) (*ownerGateway, error) {
	u, e := url.Parse(m.Config.PublicOrigin)
	if ctx == nil || s == nil || e != nil || u.Scheme != "https" || u.Host == "" || len(m.Reviewers) < 1 || len(m.Reviewers) > 100 || len(m.Experiments) < 1 || len(m.Experiments) > 16 {
		return nil, errors.New("owner_gateway_http_config_invalid")
	}
	owned, cancel := context.WithCancel(ctx)
	g := &ownerGateway{material: m, store: s, host: u.Host, sessions: map[[32]byte]ogSession{}, peers: map[string]ogRate{}, reviewerRates: map[string]ogRate{}, now: time.Now, handlers: make(chan struct{}, 4), active: map[string]string{}, queue: make(chan ownerGatewayRun, 2), serviceCtx: owned, cancel: cancel, execute: s.Execute}
	g.query = func(ctx context.Context, r ownerGatewayReviewer, run ownerGatewayRun, v ownership.VerifiedAcceptance) (ownerGatewayResult, error) {
		return r.Results.Query(ctx, run, v)
	}
	g.workers.Add(2)
	for i := 0; i < 2; i++ {
		go func() {
			defer g.workers.Done()
			for run := range g.queue {
				budget, stop := context.WithTimeout(g.serviceCtx, 150*time.Second)
				g.execute(budget, run.RunID)
				stop()
				g.mu.Lock()
				delete(g.active, run.ReviewerID)
				g.mu.Unlock()
			}
		}()
	}
	return g, nil
}
func ogError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	http.NewResponseController(w).SetWriteDeadline(time.Now().Add(5 * time.Second))
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(struct {
		ErrorCode string `json:"error_code"`
	}{code})
}
func ogEncode(value any) ([]byte, error) {
	raw, e := json.Marshal(value)
	if e != nil || len(raw) > ownerGatewayResponseLimit {
		return nil, errors.New("owner_gateway_response_invalid")
	}
	return raw, nil
}
func ogWrite(w http.ResponseWriter, status int, raw []byte) error {
	if e := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(5 * time.Second)); e != nil {
		return e
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	n, e := w.Write(raw)
	if e != nil {
		return e
	}
	if n != len(raw) {
		return io.ErrShortWrite
	}
	return http.NewResponseController(w).Flush()
}
func ogBody(w http.ResponseWriter, r *http.Request, out any) error {
	content := r.Header.Values("Content-Type")
	if len(content) != 1 || r.ContentLength < 1 || r.ContentLength > ogPostLimit || len(r.TransferEncoding) != 0 || len(r.Trailer) != 0 {
		return errors.New("owner_gateway_request_invalid")
	}
	media, params, e := mime.ParseMediaType(content[0])
	if e != nil || media != "application/json" || len(params) > 1 || (len(params) == 1 && !strings.EqualFold(params["charset"], "utf-8")) {
		return errors.New("owner_gateway_request_invalid")
	}
	if e = http.NewResponseController(w).SetReadDeadline(time.Now().Add(5 * time.Second)); e != nil {
		return e
	}
	raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, ogPostLimit))
	if e != nil || int64(len(raw)) != r.ContentLength || len(r.Trailer) != 0 || projection.DecodeClosedJSON(r.Context(), raw, out) != nil {
		return errors.New("owner_gateway_request_invalid")
	}
	return nil
}
func ogOneHeader(r *http.Request, key string) (string, bool) {
	v := r.Header.Values(key)
	if len(v) > 1 {
		return "", false
	}
	if len(v) == 0 {
		return "", true
	}
	return v[0], true
}
func (g *ownerGateway) pruneLocked() {
	now := g.now()
	for k, s := range g.sessions {
		if now.Sub(s.Created) >= 8*time.Hour || now.Sub(s.Seen) >= 30*time.Minute {
			delete(g.sessions, k)
		}
	}
}
func (g *ownerGateway) liveLocked(l ogLease) bool {
	g.pruneLocked()
	s, ok := g.sessions[l.Key]
	reviewer, exists := g.material.Reviewers[l.Session.Reviewer]
	return ok && exists && reviewer.Config.Enabled && s.Epoch == l.Session.Epoch && s.Reviewer == l.Session.Reviewer && s.Credential == l.Session.Credential && reviewer.CredentialSHA256 == s.Credential
}
func (g *ownerGateway) authenticate(r *http.Request) (ogLease, bool) {
	value := ""
	count := 0
	for _, c := range r.Cookies() {
		if c.Name == ogCookieName {
			count++
			value = c.Value
		}
	}
	decoded, e := base64.RawURLEncoding.DecodeString(value)
	if count != 1 || e != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return ogLease{}, false
	}
	key := sha256.Sum256([]byte(value))
	g.mu.Lock()
	defer g.mu.Unlock()
	g.pruneLocked()
	s, ok := g.sessions[key]
	if !ok {
		return ogLease{}, false
	}
	l := ogLease{key, s}
	if !g.liveLocked(l) {
		delete(g.sessions, key)
		return ogLease{}, false
	}
	s.Seen = g.now()
	g.sessions[key] = s
	l.Session = s
	return l, true
}
func (g *ownerGateway) rateLocked(key string, limit int, peers bool) bool {
	rates := g.reviewerRates
	if peers {
		rates = g.peers
	}
	now := g.now()
	for k, v := range rates {
		if now.Sub(v.Start) >= time.Minute {
			delete(rates, k)
		}
	}
	v, exists := rates[key]
	if !exists {
		if peers && len(rates) >= 1024 {
			return false
		}
		v = ogRate{Start: now}
	}
	if v.Count >= limit {
		return false
	}
	v.Count++
	rates[key] = v
	return true
}
func (g *ownerGateway) writeBarrier() {
	g.mu.Lock()
	hook := g.beforeWrite
	g.mu.Unlock()
	if hook != nil {
		hook()
	}
}
func (g *ownerGateway) sessionWrite(w http.ResponseWriter, r *http.Request, l ogLease, status int, value any, expected *ownerGatewayRun) {
	raw, e := ogEncode(value)
	if e != nil {
		ogError(w, 503, "owner_gateway_response_invalid")
		return
	}
	g.writeBarrier()
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.liveLocked(l) {
		ogError(w, 401, "owner_gateway_session_required")
		return
	}
	started := false
	write := func() error {
		if r.Context().Err() != nil {
			return r.Context().Err()
		}
		started = true
		return ogWrite(w, status, raw)
	}
	if expected != nil {
		e = g.store.GuardRun(context.Background(), l.Session.Reviewer, *expected, write)
	} else {
		e = g.store.Guard(context.Background(), write)
	}
	// No fallback after a partial callback write. Guard errors are local to this
	// read unless the Store itself observed its own history fault.
	if e != nil && !started && r.Context().Err() == nil {
		ogError(w, 503, "owner_gateway_history_unavailable")
	}
}

// The final run is obtained while both session and Store authority are held.
func (g *ownerGateway) currentRunWrite(w http.ResponseWriter, r *http.Request, l ogLease, status int, id string) {
	g.writeBarrier()
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.liveLocked(l) {
		ogError(w, 401, "owner_gateway_session_required")
		return
	}
	started := false
	err := g.store.GuardRunCurrent(context.Background(), l.Session.Reviewer, id, func(row ownerGatewayRun) error {
		if r.Context().Err() != nil {
			return r.Context().Err()
		}
		raw, e := ogEncode(g.viewLocked(row))
		if e != nil {
			return e
		}
		started = true
		return ogWrite(w, status, raw)
	})
	if err != nil && !started && r.Context().Err() == nil {
		if err.Error() == "owner_gateway_run_forbidden" {
			ogError(w, 404, "owner_gateway_operation_unavailable")
			return
		}
		ogError(w, 503, "owner_gateway_history_unavailable")
	}
}
func (g *ownerGateway) viewLocked(run ownerGatewayRun) ogRunView {
	job := ""
	if run.AcceptanceSHA256 != "" {
		job = run.JobID
	}
	return ogRunView{1, ownerGatewayDomain, run.RunID, run.RequestID, job, run.ExperimentID, run.Phase, run.ErrorCode, run.ErrorCode != "" || ((run.Phase != "delivered") && g.active[run.ReviewerID] != run.RunID)}
}
func (g *ownerGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; connect-src 'self'")
	select {
	case g.handlers <- struct{}{}:
		defer func() { <-g.handlers }()
	default:
		ogError(w, 503, "owner_gateway_busy")
		return
	}
	origin, one := ogOneHeader(r, "Origin")
	fetch, oneFetch := ogOneHeader(r, "Sec-Fetch-Site")
	if r.TLS == nil || !r.TLS.HandshakeComplete || r.TLS.Version != tls.VersionTLS13 || r.Host != g.host || !one || !oneFetch || (origin != "" && origin != g.material.Config.PublicOrigin) || fetch == "cross-site" || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" {
		ogError(w, 403, "owner_gateway_origin_invalid")
		return
	}
	if (r.Method == http.MethodGet && (r.ContentLength != 0 || len(r.TransferEncoding) != 0 || len(r.Trailer) != 0)) || (r.Method != http.MethodGet && origin != g.material.Config.PublicOrigin) {
		ogError(w, 403, "owner_gateway_request_invalid")
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/health" {
		raw, _ := ogEncode(map[string]string{"status": "gateway_alive", "scientific_readiness": "unverified"})
		ogWrite(w, 200, raw)
		return
	}
	if r.Method == http.MethodGet {
		names := map[string]string{"/": "index.html", "/index.html": "index.html", "/app.js": "app.js", "/styles.css": "styles.css"}
		if name, ok := names[r.URL.Path]; ok {
			data, has := g.material.UI[name]
			if !has || len(data) > 256<<10 {
				ogError(w, 503, "owner_gateway_ui_unavailable")
				return
			}
			if http.NewResponseController(w).SetWriteDeadline(time.Now().Add(5*time.Second)) != nil {
				return
			}
			types := map[string]string{"index.html": "text/html; charset=utf-8", "app.js": "text/javascript; charset=utf-8", "styles.css": "text/css; charset=utf-8"}
			w.Header().Set("Content-Type", types[name])
			w.WriteHeader(200)
			w.Write(data)
			return
		}
	}
	if r.Method == http.MethodPost && r.URL.Path == "/api/sign-in" {
		g.signIn(w, r)
		return
	}
	l, ok := g.authenticate(r)
	if !ok {
		ogError(w, 401, "owner_gateway_session_required")
		return
	}
	if r.Method != http.MethodGet {
		csrf, one := ogOneHeader(r, "X-CSRF-Token")
		if !one || subtle.ConstantTimeCompare([]byte(csrf), []byte(l.Session.CSRF)) != 1 {
			ogError(w, 403, "owner_gateway_csrf_invalid")
			return
		}
	}
	if r.Method == http.MethodPost && r.URL.Path == "/api/sign-out" {
		var empty struct{}
		if ogBody(w, r, &empty) != nil {
			ogError(w, 400, "owner_gateway_request_invalid")
			return
		}
		g.mu.Lock()
		defer g.mu.Unlock()
		if !g.liveLocked(l) {
			ogError(w, 401, "owner_gateway_session_required")
			return
		}
		delete(g.sessions, l.Key)
		http.SetCookie(w, &http.Cookie{Name: ogCookieName, Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		raw, _ := ogEncode(map[string]string{"status": "signed_out"})
		ogWrite(w, 200, raw)
		return
	}
	g.mu.Lock()
	allowed := g.liveLocked(l)
	if allowed && r.Method == http.MethodGet {
		allowed = g.rateLocked(l.Session.Reviewer+":poll", 120, false)
	}
	g.mu.Unlock()
	if !allowed {
		ogError(w, 429, "owner_gateway_rate_limited")
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/session":
		g.sessionWrite(w, r, l, 200, map[string]string{"reviewer": l.Session.Reviewer, "csrf_token": l.Session.CSRF}, nil)
	case r.Method == http.MethodGet && r.URL.Path == "/api/experiments":
		rows := []map[string]string{}
		for _, e := range g.material.Experiments {
			rows = append(rows, map[string]string{"id": e.Config.ID, "label": e.Config.Label, "scope": e.Config.Scope})
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i]["id"] < rows[j]["id"] })
		g.sessionWrite(w, r, l, 200, rows, nil)
	case r.Method == http.MethodGet && r.URL.Path == "/api/runs":
		rows, e := g.store.Runs(context.Background(), l.Session.Reviewer)
		if e != nil {
			ogError(w, 503, "owner_gateway_history_unavailable")
			return
		}
		g.mu.Lock()
		views := make([]ogRunView, 0, len(rows))
		for _, row := range rows {
			views = append(views, g.viewLocked(row))
		}
		g.mu.Unlock()
		g.sessionWrite(w, r, l, 200, views, nil)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/operations/"):
		id := strings.TrimPrefix(r.URL.Path, "/api/operations/")
		if !projection.ArtifactHex(id, 16) {
			ogError(w, 400, "owner_gateway_request_invalid")
			return
		}
		g.currentRunWrite(w, r, l, 200, id)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/experiments/") && strings.HasSuffix(r.URL.Path, "/runs"):
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/experiments/"), "/runs")
		g.startRun(w, r, l, id)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/results/"):
		id := strings.TrimPrefix(r.URL.Path, "/api/results/")
		g.results(w, r, l, id)
	default:
		ogError(w, 404, "owner_gateway_not_found")
	}
}
func (g *ownerGateway) signIn(w http.ResponseWriter, r *http.Request) {
	peer, _, e := net.SplitHostPort(r.RemoteAddr)
	if e != nil || net.ParseIP(peer) == nil {
		ogError(w, 400, "owner_gateway_peer_invalid")
		return
	}
	g.mu.Lock()
	allow := !g.stopping && g.rateLocked(peer, 10, true)
	g.mu.Unlock()
	if !allow {
		ogError(w, 429, "owner_gateway_rate_limited")
		return
	}
	var input struct {
		ID   string `json:"id"`
		Code string `json:"access_code"`
	}
	if ogBody(w, r, &input) != nil {
		ogError(w, 400, "owner_gateway_request_invalid")
		return
	}
	reviewer, exists := g.material.Reviewers[input.ID]
	decoded, e := base64.RawURLEncoding.DecodeString(input.Code)
	digest := sha256.Sum256([]byte(input.Code))
	valid := subtle.ConstantTimeCompare(digest[:], reviewer.AccessSHA256[:]) == 1
	if !exists || !reviewer.Config.Enabled || e != nil || len(decoded) != 32 || !valid {
		ogError(w, 401, "owner_gateway_credentials_invalid")
		return
	}
	var entropy [64]byte
	if _, e = rand.Read(entropy[:]); e != nil {
		ogError(w, 503, "owner_gateway_entropy_unavailable")
		return
	}
	value := base64.RawURLEncoding.EncodeToString(entropy[:32])
	csrf := base64.RawURLEncoding.EncodeToString(entropy[32:])
	key := sha256.Sum256([]byte(value))
	g.mu.Lock()
	g.pruneLocked()
	for k, s := range g.sessions {
		if s.Reviewer == input.ID {
			delete(g.sessions, k)
		}
	}
	if len(g.sessions) >= 100 || g.epoch == ^uint64(0) || g.stopping {
		g.mu.Unlock()
		ogError(w, 503, "owner_gateway_session_capacity")
		return
	}
	g.epoch++
	s := ogSession{input.ID, reviewer.CredentialSHA256, csrf, g.epoch, g.now(), g.now()}
	g.sessions[key] = s
	g.mu.Unlock()
	raw, e := ogEncode(map[string]string{"reviewer": input.ID, "csrf_token": csrf})
	if e != nil {
		ogError(w, 503, "owner_gateway_response_invalid")
		return
	}
	g.writeBarrier()
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.liveLocked(ogLease{key, s}) {
		ogError(w, 401, "owner_gateway_session_required")
		return
	}
	started := false
	e = g.store.Guard(context.Background(), func() error {
		if r.Context().Err() != nil {
			return r.Context().Err()
		}
		started = true
		http.SetCookie(w, &http.Cookie{Name: ogCookieName, Value: value, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 28800})
		return ogWrite(w, 200, raw)
	})
	if e != nil && !started && r.Context().Err() == nil {
		delete(g.sessions, key)
		ogError(w, 503, "owner_gateway_history_unavailable")
	}
}
func (g *ownerGateway) startRun(w http.ResponseWriter, r *http.Request, l ogLease, experiment string) {
	var input struct {
		RequestID string `json:"request_id"`
	}
	if !safeID.MatchString(experiment) || ogBody(w, r, &input) != nil || !projection.ArtifactHex(input.RequestID, 32) {
		ogError(w, 400, "owner_gateway_request_invalid")
		return
	}
	if _, ok := g.material.Experiments[experiment]; !ok {
		ogError(w, 404, "owner_gateway_experiment_unavailable")
		return
	}
	g.mu.Lock()
	if !g.liveLocked(l) || g.stopping || r.Context().Err() != nil {
		g.mu.Unlock()
		ogError(w, 401, "owner_gateway_session_required")
		return
	}
	row, found, e := g.store.LookupRequest(context.Background(), l.Session.Reviewer, input.RequestID)
	if e == nil && !found {
		if len(g.active) >= 2 || g.active[l.Session.Reviewer] != "" || !g.rateLocked(l.Session.Reviewer+":submit", 5, false) {
			g.mu.Unlock()
			ogError(w, 429, "owner_gateway_operation_busy")
			return
		}
	}
	if e == nil {
		var fresh bool
		row, fresh, e = g.store.Intent(context.Background(), l.Session.Reviewer, experiment, input.RequestID)
		if e == nil && fresh {
			g.active[l.Session.Reviewer] = row.RunID
			g.queue <- row
		}
	}
	g.mu.Unlock()
	if e != nil {
		ogError(w, 503, "owner_gateway_operation_unavailable")
		return
	}
	g.currentRunWrite(w, r, l, 202, row.RunID)
}
func (g *ownerGateway) results(w http.ResponseWriter, r *http.Request, l ogLease, job string) {
	if !projection.ArtifactHex(job, 16) {
		ogError(w, 400, "owner_gateway_request_invalid")
		return
	}
	row, accepted, e := g.store.AuthorizeJob(context.Background(), l.Session.Reviewer, job)
	if e != nil {
		ogError(w, 404, "owner_gateway_result_unavailable")
		return
	}
	reviewer := g.material.Reviewers[l.Session.Reviewer]
	budget, stop := context.WithTimeout(r.Context(), 30*time.Second)
	defer stop()
	result, e := g.query(budget, reviewer, row, accepted)
	if e != nil {
		ogError(w, 503, "owner_gateway_result_unavailable")
		return
	}
	row, e = g.store.ObserveResult(context.Background(), row.RunID, result)
	if e != nil {
		ogError(w, 503, "owner_gateway_result_unavailable")
		return
	}
	view := ogResultView{SchemaVersion: 1, Domain: ownerGatewayDomain, RunID: row.RunID, JobID: job, ExperimentID: row.ExperimentID, AcceptanceSHA256: row.AcceptanceSHA256, ExecutionState: result.ExecutionState, Status: result.Status, ReleaseStatus: result.ReleaseStatus, ErrorCode: result.ErrorCode, ArtifactExecution: result.ArtifactExecution}
	if len(result.PipelineOutput) > 0 && string(result.PipelineOutput) != "null" {
		var pipeline ogPipelineView
		if json.Unmarshal(result.PipelineOutput, &pipeline) != nil {
			ogError(w, 503, "owner_gateway_result_invalid")
			return
		}
		view.PipelineOutput = &pipeline
	}
	if result.Detection != nil {
		view.Detection = &ogDetectionView{Score: result.Detection.Score, Verdict: result.Detection.Verdict, Reasons: append([]string{}, result.Detection.Reasons...)}
	}
	if len(result.ScientificEvaluation) > 0 && string(result.ScientificEvaluation) != "null" {
		var evaluation ogEvaluation
		if json.Unmarshal(result.ScientificEvaluation, &evaluation) != nil {
			ogError(w, 503, "owner_gateway_result_invalid")
			return
		}
		if evaluation.Error != "" {
			evaluation.Error = "scientific_evaluation_failed"
		}
		view.ScientificEvaluation = &evaluation
	}
	g.sessionWrite(w, r, l, 200, view, &row)
}
