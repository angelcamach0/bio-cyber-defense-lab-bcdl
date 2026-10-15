//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ownership "biozero/ownership-authority"
)

// These doubles exercise browser/session/admission authority, not the signed
// acceptance or scientific pipeline. Those have separate integration gates.
type ogHTTPTestStore struct {
	mu                                                                  sync.Mutex
	rows                                                                map[string]ownerGatewayRun
	intentCalls, executeCalls, authorizeCalls, observeCalls, closeCalls int
	guardFault                                                          bool
	executeFn                                                           func(context.Context, string) error
}

func ogNewTestStore() *ogHTTPTestStore { return &ogHTTPTestStore{rows: map[string]ownerGatewayRun{}} }
func (s *ogHTTPTestStore) LookupRequest(_ context.Context, reviewer, request string) (ownerGatewayRun, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.rows {
		if r.ReviewerID == reviewer && r.RequestID == request {
			return r, true, nil
		}
	}
	return ownerGatewayRun{}, false, nil
}
func (s *ogHTTPTestStore) Intent(_ context.Context, reviewer, experiment, request string) (ownerGatewayRun, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.intentCalls++
	for _, r := range s.rows {
		if r.ReviewerID == reviewer && r.RequestID == request {
			if r.ExperimentID != experiment {
				return ownerGatewayRun{}, false, errors.New("conflict")
			}
			return r, false, nil
		}
	}
	id := strings.Repeat("0", 15) + string("123456789abcdef"[len(s.rows)%15])
	r := ownerGatewayRun{SchemaVersion: 1, RunID: id, RequestID: request, ReviewerID: reviewer, ExperimentID: experiment, Phase: "intent"}
	s.rows[id] = r
	return r, true, nil
}
func (s *ogHTTPTestStore) Run(_ context.Context, reviewer, id string) (ownerGatewayRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.rows[id]
	if !ok || r.ReviewerID != reviewer {
		return ownerGatewayRun{}, errors.New("not_owned")
	}
	return r, nil
}
func (s *ogHTTPTestStore) Runs(_ context.Context, reviewer string) ([]ownerGatewayRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows := []ownerGatewayRun{}
	for _, r := range s.rows {
		if r.ReviewerID == reviewer {
			rows = append(rows, r)
		}
	}
	return rows, nil
}
func (s *ogHTTPTestStore) AuthorizeJob(_ context.Context, reviewer, job string) (ownerGatewayRun, ownership.VerifiedAcceptance, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authorizeCalls++
	for _, r := range s.rows {
		if r.ReviewerID == reviewer && r.JobID == job && r.AcceptanceSHA256 != "" {
			return r, ownership.VerifiedAcceptance{}, nil
		}
	}
	return ownerGatewayRun{}, ownership.VerifiedAcceptance{}, errors.New("not_owned")
}
func (s *ogHTTPTestStore) ObserveResult(_ context.Context, id string, _ ownerGatewayResult) (ownerGatewayRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.observeCalls++
	r, ok := s.rows[id]
	if !ok {
		return r, errors.New("missing")
	}
	return r, nil
}
func (s *ogHTTPTestStore) Guard(_ context.Context, write func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.guardFault {
		return errors.New("history_fault")
	}
	return write()
}
func (s *ogHTTPTestStore) GuardRun(_ context.Context, reviewer string, expected ownerGatewayRun, write func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.guardFault || s.rows[expected.RunID].ReviewerID != reviewer || !reflect.DeepEqual(s.rows[expected.RunID], expected) {
		return errors.New("history_changed")
	}
	return write()
}
func (s *ogHTTPTestStore) GuardRunCurrent(_ context.Context, reviewer, id string, write func(ownerGatewayRun) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.guardFault {
		return errors.New("history_fault")
	}
	r, ok := s.rows[id]
	if !ok || r.ReviewerID != reviewer {
		return errors.New("owner_gateway_run_forbidden")
	}
	return write(r)
}
func (s *ogHTTPTestStore) Execute(ctx context.Context, id string) error {
	s.mu.Lock()
	s.executeCalls++
	fn := s.executeFn
	s.mu.Unlock()
	if fn != nil {
		return fn(ctx, id)
	}
	return nil
}
func (s *ogHTTPTestStore) Close() error { s.mu.Lock(); defer s.mu.Unlock(); s.closeCalls++; return nil }
func (s *ogHTTPTestStore) snapshot() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, _ := json.Marshal(s.rows)
	return string(b)
}

type ogHTTPFixture struct {
	g            *ownerGateway
	store        *ogHTTPTestStore
	server       *httptest.Server
	client       *http.Client
	origin, code string
}
type ogLogin struct {
	cookie *http.Cookie
	csrf   string
}

func ogTestMaterial(origin string) ownerGatewayMaterial {
	code := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	hash := sha256.Sum256([]byte(code))
	reviewers := map[string]ownerGatewayReviewer{}
	for _, id := range []string{"a", "b", "c"} {
		reviewers[id] = ownerGatewayReviewer{Config: ownerGatewayReviewerConfig{ID: id, Enabled: true}, CredentialSHA256: strings.Repeat(id, 64), AccessSHA256: hash}
	}
	return ownerGatewayMaterial{Config: ownerGatewayConfig{PublicOrigin: origin}, Reviewers: reviewers, Experiments: map[string]ownerGatewayExperiment{"fixture": {Config: ownerGatewayExperimentConfig{ID: "fixture", Label: "Synthetic fixture", Scope: "synthetic"}}, "second": {Config: ownerGatewayExperimentConfig{ID: "second", Label: "Second fixture", Scope: "synthetic"}}}, UI: map[string][]byte{"index.html": []byte("private synthetic review"), "app.js": []byte("'use strict';"), "styles.css": []byte("body{}")}, BrowserTLS: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}}
}
func ogNewHTTPFixture(t *testing.T) *ogHTTPFixture {
	t.Helper()
	server := httptest.NewUnstartedServer(nil)
	origin := "https://" + server.Listener.Addr().String()
	store := ogNewTestStore()
	g, err := newOwnerGateway(context.Background(), ogTestMaterial(origin), store)
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = g
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	server.StartTLS()
	client := server.Client()
	client.Timeout = 5 * time.Second
	f := &ogHTTPFixture{g: g, store: store, server: server, client: client, origin: origin, code: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))}
	t.Cleanup(func() {
		g.mu.Lock()
		g.stopping = true
		close(g.queue)
		g.cancel()
		g.mu.Unlock()
		g.workers.Wait()
		server.Close()
	})
	return f
}
func (f *ogHTTPFixture) request(t *testing.T, method, path, body string, session ogLogin, change func(*http.Request)) (*http.Response, []byte) {
	t.Helper()
	req, e := http.NewRequest(method, f.origin+path, strings.NewReader(body))
	if e != nil {
		t.Fatal(e)
	}
	if method != http.MethodGet {
		req.Header.Set("Origin", f.origin)
		req.Header.Set("Content-Type", "application/json")
		if session.csrf != "" {
			req.Header.Set("X-CSRF-Token", session.csrf)
		}
	}
	if session.cookie != nil {
		req.AddCookie(session.cookie)
	}
	if change != nil {
		change(req)
	}
	res, e := f.client.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := io.ReadAll(res.Body)
	res.Body.Close()
	if e != nil {
		t.Fatal(e)
	}
	return res, raw
}
func (f *ogHTTPFixture) login(t *testing.T, id string) ogLogin {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"id": id, "access_code": f.code})
	res, raw := f.request(t, "POST", "/api/sign-in", string(b), ogLogin{}, nil)
	if res.StatusCode != 200 {
		t.Fatalf("login %d %s", res.StatusCode, raw)
	}
	var v struct {
		CSRF string `json:"csrf_token"`
	}
	if json.Unmarshal(raw, &v) != nil || v.CSRF == "" || len(res.Cookies()) != 1 {
		t.Fatal("session missing")
	}
	cookie := res.Cookies()[0]
	if !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/" || cookie.Domain != "" {
		t.Fatal("cookie authority weakened")
	}
	return ogLogin{cookie, v.CSRF}
}
func ogWait(t *testing.T, channel <-chan struct{}) {
	t.Helper()
	select {
	case <-channel:
	case <-time.After(3 * time.Second):
		t.Fatal("causal barrier timeout")
	}
}

func TestOwnerGatewayHTTPSessionAndOrigin(t *testing.T) {
	f := ogNewHTTPFixture(t)
	session := f.login(t, "a")
	res, raw := f.request(t, "GET", "/api/session", "", session, nil)
	if res.StatusCode != 200 || !bytes.Contains(raw, []byte(session.csrf)) {
		t.Fatalf("session %d", res.StatusCode)
	}
	for _, test := range []struct {
		name, method, path, body string
		change                   func(*http.Request)
	}{
		{"origin", "GET", "/api/session", "", func(r *http.Request) { r.Header.Set("Origin", "https://other.invalid") }},
		{"duplicate_origin", "GET", "/api/session", "", func(r *http.Request) { r.Header.Add("Origin", f.origin); r.Header.Add("Origin", f.origin) }},
		{"host", "GET", "/api/session", "", func(r *http.Request) { r.Host = "other.invalid" }},
		{"fetch_site", "GET", "/api/session", "", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }},
		{"duplicate_cookie", "GET", "/api/session", "", func(r *http.Request) { r.AddCookie(session.cookie) }},
		{"csrf", "POST", "/api/experiments/fixture/runs", `{"request_id":"11111111111111111111111111111111"}`, func(r *http.Request) { r.Header.Set("X-CSRF-Token", "wrong") }},
		{"duplicate_csrf", "POST", "/api/experiments/fixture/runs", `{"request_id":"11111111111111111111111111111111"}`, func(r *http.Request) { r.Header.Add("X-CSRF-Token", session.csrf) }},
		{"unknown_json", "POST", "/api/experiments/fixture/runs", `{"request_id":"11111111111111111111111111111111","job_id":"0000000000000001"}`, nil},
		{"duplicate_json", "POST", "/api/experiments/fixture/runs", `{"request_id":"11111111111111111111111111111111","request_id":"11111111111111111111111111111111"}`, nil},
		{"query", "GET", "/api/session?owner=a", "", nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			res, raw := f.request(t, test.method, test.path, test.body, session, test.change)
			if res.StatusCode < 400 || bytes.Contains(raw, []byte(session.csrf)) {
				t.Fatalf("accepted/leaked %d %s", res.StatusCode, raw)
			}
		})
	}
	f.store.mu.Lock()
	defer f.store.mu.Unlock()
	if f.store.intentCalls != 0 || f.store.executeCalls != 0 {
		t.Fatal("invalid browser request admitted operation")
	}
}
func TestOwnerGatewayHTTPFreshSessionAtActualWrite(t *testing.T) {
	f := ogNewHTTPFixture(t)
	old := f.login(t, "a")
	reached, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	f.g.mu.Lock()
	f.g.beforeWrite = func() {
		if calls.Add(1) == 1 {
			close(reached)
			<-release
		}
	}
	f.g.mu.Unlock()
	done := make(chan struct{})
	var status int
	var body []byte
	go func() {
		defer close(done)
		res, raw := f.request(t, "GET", "/api/session", "", old, nil)
		status = res.StatusCode
		body = raw
	}()
	ogWait(t, reached)
	fresh := f.login(t, "a")
	close(release)
	ogWait(t, done)
	if status != 401 || bytes.Contains(body, []byte(old.csrf)) || bytes.Contains(body, []byte(fresh.csrf)) {
		t.Fatalf("stale session released %d %s", status, body)
	}
	res, _ := f.request(t, "GET", "/api/session", "", fresh, nil)
	if res.StatusCode != 200 {
		t.Fatal("fresh session unavailable")
	}
}
func TestOwnerGatewayHTTPIntentDedupeAndOwnedBudget(t *testing.T) {
	f := ogNewHTTPFixture(t)
	session := f.login(t, "a")
	entered, release := make(chan struct{}), make(chan struct{})
	var deadline time.Duration
	f.store.executeFn = func(ctx context.Context, id string) error {
		limit, ok := ctx.Deadline()
		if !ok {
			return errors.New("missing deadline")
		}
		deadline = time.Until(limit)
		close(entered)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	body := `{"request_id":"11111111111111111111111111111111"}`
	res, raw := f.request(t, "POST", "/api/experiments/fixture/runs", body, session, nil)
	if res.StatusCode != 202 {
		t.Fatalf("submit %d %s", res.StatusCode, raw)
	}
	var first ogRunView
	json.Unmarshal(raw, &first)
	ogWait(t, entered)
	if deadline < 149*time.Second || deadline > 150*time.Second {
		t.Fatalf("not server-owned 150s budget: %v", deadline)
	}
	res, raw = f.request(t, "POST", "/api/experiments/fixture/runs", body, session, nil)
	var duplicate ogRunView
	json.Unmarshal(raw, &duplicate)
	if res.StatusCode != 202 || first.RunID != duplicate.RunID {
		t.Fatal("dedupe changed operation")
	}
	res, _ = f.request(t, "POST", "/api/experiments/fixture/runs", `{"request_id":"22222222222222222222222222222222"}`, session, nil)
	if res.StatusCode != 429 {
		t.Fatal("reviewer concurrent operation admitted")
	}
	res, _ = f.request(t, "POST", "/api/sign-out", "{}", session, nil)
	if res.StatusCode != 200 {
		t.Fatal("logout failed")
	}
	f.store.mu.Lock()
	executions := f.store.executeCalls
	f.store.mu.Unlock()
	if executions != 1 {
		t.Fatal("duplicate executed")
	}
	select {
	case <-release:
		t.Fatal("impossible")
	default:
	}
	close(release)
}
func TestOwnerGatewayHTTPFreshPhaseBeforePublish(t *testing.T) {
	f := ogNewHTTPFixture(t)
	session := f.login(t, "a")
	advanced := make(chan struct{})
	f.store.executeFn = func(_ context.Context, id string) error {
		f.store.mu.Lock()
		row := f.store.rows[id]
		row.Phase = "reserved"
		row.JobID = "2222222222222222"
		f.store.rows[id] = row
		f.store.mu.Unlock()
		close(advanced)
		return nil
	}
	f.g.mu.Lock()
	f.g.beforeWrite = func() { ogWait(t, advanced) }
	f.g.mu.Unlock()
	res, raw := f.request(t, "POST", "/api/experiments/fixture/runs", `{"request_id":"11111111111111111111111111111111"}`, session, nil)
	var row ogRunView
	if json.Unmarshal(raw, &row) != nil || res.StatusCode != 202 || row.Phase != "reserved" || row.JobID != "" {
		t.Fatalf("not current or exposed unsigned job %d %s", res.StatusCode, raw)
	}
}
func TestOwnerGatewayHTTPColdHistoryNeverDispatches(t *testing.T) {
	f := ogNewHTTPFixture(t)
	f.store.mu.Lock()
	f.store.rows["1111111111111111"] = ownerGatewayRun{RunID: "1111111111111111", ReviewerID: "a", RequestID: strings.Repeat("1", 32), ExperimentID: "fixture", Phase: "prepared"}
	f.store.mu.Unlock()
	session := f.login(t, "a")
	res, raw := f.request(t, "GET", "/api/operations/1111111111111111", "", session, nil)
	var row ogRunView
	json.Unmarshal(raw, &row)
	if res.StatusCode != 200 || !row.NeedsOperator {
		t.Fatal("cold history not fenced")
	}
	res, _ = f.request(t, "POST", "/api/experiments/fixture/runs", `{"request_id":"11111111111111111111111111111111"}`, session, nil)
	if res.StatusCode != 202 {
		t.Fatal("cold duplicate unavailable")
	}
	f.store.mu.Lock()
	defer f.store.mu.Unlock()
	if f.store.executeCalls != 0 {
		t.Fatal("cold request dispatched")
	}
}
func TestOwnerGatewayHTTPAuthorizesBeforeResultsAndFilters(t *testing.T) {
	f := ogNewHTTPFixture(t)
	f.store.mu.Lock()
	f.store.rows["1111111111111111"] = ownerGatewayRun{RunID: "1111111111111111", ReviewerID: "a", ExperimentID: "fixture", Phase: "delivered", JobID: "2222222222222222", AcceptanceSHA256: strings.Repeat("a", 64)}
	f.store.mu.Unlock()
	var queries atomic.Int32
	f.g.query = func(_ context.Context, _ ownerGatewayReviewer, _ ownerGatewayRun, _ ownership.VerifiedAcceptance) (ownerGatewayResult, error) {
		queries.Add(1)
		return ownerGatewayResult{ExecutionState: "committed", Status: "failed", ReleaseStatus: "withheld", PipelineOutput: json.RawMessage(`{"schema_version":1,"mode":"variants","pipeline_status":"failed","stages":[{"name":"private_stage","status":"failed","error_code":"input_invalid","stderr":"private diagnostic"}],"outputs":{"fastp_summary":{"secret":"private diagnostic"}},"read_count":0}`), ScientificEvaluation: json.RawMessage(`{"evaluation_status":"failed","error":"evaluation_failed"}`)}, nil
	}
	b := f.login(t, "b")
	res, _ := f.request(t, "GET", "/api/results/2222222222222222", "", b, nil)
	if res.StatusCode != 404 || queries.Load() != 0 {
		t.Fatal("cross-owner reached results")
	}
	a := f.login(t, "a")
	res, raw := f.request(t, "GET", "/api/results/2222222222222222", "", a, nil)
	if res.StatusCode != 200 || queries.Load() != 1 || bytes.Contains(raw, []byte("private")) || bytes.Contains(raw, []byte(`"tp":0`)) {
		t.Fatalf("projection lost variant/leaked diagnostics %d %s", res.StatusCode, raw)
	}
	var view ogResultView
	json.Unmarshal(raw, &view)
	if view.AcceptanceSHA256 != strings.Repeat("a", 64) || view.ScientificEvaluation == nil || view.ScientificEvaluation.TP != nil || view.ScientificEvaluation.Error != "scientific_evaluation_failed" {
		t.Fatal("error evaluation fabricated counts")
	}
	f.store.mu.Lock()
	defer f.store.mu.Unlock()
	if f.store.observeCalls != 1 {
		t.Fatal("result not durably observed before release")
	}
}
func TestOwnerGatewayHTTPHistoryFaultBeforeWriteIs503(t *testing.T) {
	f := ogNewHTTPFixture(t)
	session := f.login(t, "a")
	f.store.mu.Lock()
	f.store.guardFault = true
	f.store.mu.Unlock()
	res, raw := f.request(t, "GET", "/api/session", "", session, nil)
	if res.StatusCode != 503 || bytes.Contains(raw, []byte(session.csrf)) {
		t.Fatalf("guard fault implicit success %d %s", res.StatusCode, raw)
	}
}

type ogFailWriter struct {
	header http.Header
	writes int
}

func (w *ogFailWriter) Header() http.Header              { return w.header }
func (w *ogFailWriter) WriteHeader(int)                  {}
func (w *ogFailWriter) Write([]byte) (int, error)        { w.writes++; return 0, io.ErrClosedPipe }
func (w *ogFailWriter) SetWriteDeadline(time.Time) error { return nil }
func (w *ogFailWriter) FlushError() error                { return io.ErrClosedPipe }
func TestOwnerGatewayHTTPFailedWriteKeepsHistoryAndSession(t *testing.T) {
	f := ogNewHTTPFixture(t)
	session := f.login(t, "a")
	req, _ := http.NewRequest("GET", f.origin+"/api/session", nil)
	req.AddCookie(session.cookie)
	lease, ok := f.g.authenticate(req)
	if !ok {
		t.Fatal("missing session")
	}
	before := f.store.snapshot()
	w := &ogFailWriter{header: make(http.Header)}
	f.g.sessionWrite(w, req, lease, 200, map[string]string{"private": "authorized"}, nil)
	if w.writes != 1 || before != f.store.snapshot() {
		t.Fatal("browser failure retried write or mutated history")
	}
	res, _ := f.request(t, "GET", "/api/session", "", session, nil)
	if res.StatusCode != 200 {
		t.Fatal("browser failure poisoned retry")
	}
}
func TestOwnerGatewayHTTPGlobalAdmissionAndHandlerBounds(t *testing.T) {
	f := ogNewHTTPFixture(t)
	a := f.login(t, "a")
	b := f.login(t, "b")
	c := f.login(t, "c")
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	defer close(release)
	f.store.executeFn = func(ctx context.Context, _ string) error {
		entered <- struct{}{}
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	for _, session := range []ogLogin{a, b} {
		res, raw := f.request(t, "POST", "/api/experiments/fixture/runs", `{"request_id":"11111111111111111111111111111111"}`, session, nil)
		if res.StatusCode != 202 {
			t.Fatalf("admission %d %s", res.StatusCode, raw)
		}
		ogWait(t, entered)
	}
	res, _ := f.request(t, "POST", "/api/experiments/fixture/runs", `{"request_id":"11111111111111111111111111111111"}`, c, nil)
	if res.StatusCode != 429 {
		t.Fatal("third active operation admitted")
	}
	// Duplicate is checked before global-capacity rejection.
	res, _ = f.request(t, "POST", "/api/experiments/fixture/runs", `{"request_id":"11111111111111111111111111111111"}`, a, nil)
	if res.StatusCode != 202 {
		t.Fatal("active duplicate was rejected by queue capacity")
	}
	reached, writeRelease := make(chan struct{}, 4), make(chan struct{})
	f.g.mu.Lock()
	f.g.beforeWrite = func() { reached <- struct{}{}; <-writeRelease }
	f.g.mu.Unlock()
	done := make(chan struct{}, 4)
	for i := 0; i < 4; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			res, _ := f.request(t, "GET", "/api/session", "", a, nil)
			if res.StatusCode != 200 {
				t.Error("admitted handler did not complete")
			}
		}()
		ogWait(t, reached)
	}
	res, _ = f.request(t, "GET", "/api/session", "", a, nil)
	if res.StatusCode != 503 {
		t.Fatal("fifth handler admitted")
	}
	close(writeRelease)
	for i := 0; i < 4; i++ {
		ogWait(t, done)
	}
}
func TestOwnerGatewayHTTPLostPOSTDoesNotCancelOrRedispatch(t *testing.T) {
	f := ogNewHTTPFixture(t)
	session := f.login(t, "a")
	reached, writeRelease, operationEntered, operationRelease := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	f.store.executeFn = func(ctx context.Context, _ string) error {
		close(operationEntered)
		select {
		case <-operationRelease:
			return ctx.Err()
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	f.g.mu.Lock()
	f.g.beforeWrite = func() { once.Do(func() { close(reached); <-writeRelease }) }
	f.g.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, "POST", f.origin+"/api/experiments/fixture/runs", strings.NewReader(`{"request_id":"11111111111111111111111111111111"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", f.origin)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", session.csrf)
	req.AddCookie(session.cookie)
	lost := make(chan error, 1)
	go func() {
		res, err := f.client.Do(req)
		if res != nil {
			res.Body.Close()
		}
		lost <- err
	}()
	ogWait(t, reached)
	ogWait(t, operationEntered)
	cancel()
	if err := <-lost; err == nil {
		t.Fatal("POST response was not lost")
	}
	close(writeRelease)
	res, raw := f.request(t, "POST", "/api/experiments/fixture/runs", `{"request_id":"11111111111111111111111111111111"}`, session, nil)
	if res.StatusCode != 202 {
		t.Fatalf("lost response dedupe unavailable %d %s", res.StatusCode, raw)
	}
	f.store.mu.Lock()
	executions := f.store.executeCalls
	f.store.mu.Unlock()
	if executions != 1 {
		t.Fatal("lost POST redispatched")
	}
	close(operationRelease)
}
func TestOwnerGatewayHTTPBoundedPeerRatesExpire(t *testing.T) {
	f := ogNewHTTPFixture(t)
	f.g.mu.Lock()
	defer f.g.mu.Unlock()
	now := time.Now()
	f.g.now = func() time.Time { return now }
	for i := 0; i < 1024; i++ {
		key := string(rune(i + 1))
		if !f.g.rateLocked(key, 10, true) {
			t.Fatal("bounded peer map rejected available slot")
		}
	}
	if f.g.rateLocked("new_peer", 10, true) || len(f.g.peers) != 1024 {
		t.Fatal("peer map exceeded bound")
	}
	now = now.Add(time.Minute)
	if !f.g.rateLocked("new_peer", 10, true) || len(f.g.peers) != 1 {
		t.Fatal("peer expiry failed")
	}
}

func TestOwnerGatewayHTTPForeignAndUnknownOperationAre404(t *testing.T) {
	f := ogNewHTTPFixture(t)
	row := ownerGatewayRun{RunID: "1111111111111111", RequestID: strings.Repeat("e", 32), ReviewerID: "a", ExperimentID: "fixture", Phase: "delivered", JobID: "2222222222222222", AcceptanceSHA256: strings.Repeat("a", 64)}
	f.store.mu.Lock()
	f.store.rows[row.RunID] = row
	f.store.mu.Unlock()
	a, b := f.login(t, "a"), f.login(t, "b")
	before := f.store.snapshot()
	var queries atomic.Int32
	f.g.query = func(context.Context, ownerGatewayReviewer, ownerGatewayRun, ownership.VerifiedAcceptance) (ownerGatewayResult, error) {
		queries.Add(1)
		return ownerGatewayResult{}, errors.New("unexpected_query")
	}
	res, raw := f.request(t, "GET", "/api/operations/"+row.RunID, "", a, nil)
	var own ogRunView
	if res.StatusCode != 200 || json.Unmarshal(raw, &own) != nil || own.RunID != row.RunID || own.JobID != row.JobID {
		t.Fatalf("own operation positive control failed %d %s", res.StatusCode, raw)
	}
	var denied []byte
	for _, id := range []string{row.RunID, "ffffffffffffffff"} {
		res, raw = f.request(t, "GET", "/api/operations/"+id, "", b, nil)
		var body map[string]string
		if res.StatusCode != 404 || json.Unmarshal(raw, &body) != nil || len(body) != 1 || body["error_code"] != "owner_gateway_operation_unavailable" {
			t.Fatalf("operation authorization misclassified %d %s", res.StatusCode, raw)
		}
		if denied != nil && !bytes.Equal(denied, raw) {
			t.Fatal("unknown and foreign operation differ")
		}
		denied = append([]byte(nil), raw...)
		for _, private := range []string{row.RunID, row.RequestID, row.JobID, row.AcceptanceSHA256} {
			if bytes.Contains(raw, []byte(private)) {
				t.Fatal("foreign operation disclosed private binding")
			}
		}
	}
	f.store.mu.Lock()
	f.store.guardFault = true
	f.store.mu.Unlock()
	for _, test := range []struct {
		session ogLogin
		id      string
	}{{a, row.RunID}, {b, row.RunID}, {b, "ffffffffffffffff"}} {
		res, raw = f.request(t, "GET", "/api/operations/"+test.id, "", test.session, nil)
		if res.StatusCode != 503 || !bytes.Contains(raw, []byte("owner_gateway_history_unavailable")) {
			t.Fatalf("storage fault disguised as absence %d %s", res.StatusCode, raw)
		}
	}
	if queries.Load() != 0 || before != f.store.snapshot() {
		t.Fatal("operation lookup queried upstream or changed history")
	}
	f.store.mu.Lock()
	defer f.store.mu.Unlock()
	if f.store.authorizeCalls != 0 || f.store.observeCalls != 0 || f.store.intentCalls != 0 || f.store.executeCalls != 0 {
		t.Fatal("operation lookup crossed into execution/results authority")
	}
}
