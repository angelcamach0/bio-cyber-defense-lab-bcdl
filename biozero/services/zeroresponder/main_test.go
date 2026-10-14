package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const testSecret = "test-only-0123456789abcdef0123456789abcdef"

func testStore(t *testing.T) (*responder, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "actions")
	r, err := newResponder(dir, testSecret)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.directory.Close() })
	return r, dir
}
func workerAlert(code string) alertPayload {
	job := "abcd1234"
	digest := sha256.Sum256([]byte("enclave-runner/" + job + "/" + code))
	return alertPayload{1, "evt-" + hex.EncodeToString(digest[:]), "enclave-runner", code, "high", "2026-10-14T00:00:00Z", map[string]string{"job_id": job}, []string{"quarantine"}}
}
func siemAlert() alertPayload {
	return alertPayload{1, "siem-01", "siem", "policy_alert", "high", "2026-10-14T01:00:00+01:00", map[string]string{"ip": "::ffff:192.0.2.1", "job_id": "abcd1234", "cert_serial": "AB01"}, []string{"revoke_cert", "quarantine", "block_ip"}}
}
func bodyOf(t *testing.T, payload alertPayload) []byte {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func call(r *responder, body []byte, secret string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "http://127.0.0.1:8090/alert", bytes.NewReader(body))
	if secret != "" {
		req.Header.Set("X-Webhook-Secret", secret)
	}
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}
func parseAck(t *testing.T, w *httptest.ResponseRecorder) acknowledgment {
	t.Helper()
	var ack acknowledgment
	if json.Unmarshal(w.Body.Bytes(), &ack) != nil {
		t.Fatal("invalid ack")
	}
	return ack
}
func TestAuthenticatedDurableSimulationAndRestartReplay(t *testing.T) {
	r, dir := testStore(t)
	payload := siemAlert()
	body := bodyOf(t, payload)
	for _, secret := range []string{"", strings.Repeat("wrong", 8)} {
		if w := call(r, body, secret); w.Code != 403 {
			t.Fatal("unauthenticated alert accepted", w.Code)
		}
	}
	req := httptest.NewRequest("POST", "/alert", bytes.NewReader(body))
	req.Header.Add("X-Webhook-Secret", testSecret)
	req.Header.Add("X-Webhook-Secret", testSecret)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatal("ambiguous credentials accepted")
	}
	w = call(r, body, testSecret)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	first := parseAck(t, w)
	if first.Status != "recorded" || first.Mode != "simulation" || first.Enforced || first.Replay || len(first.Actions) != 3 {
		t.Fatal("invalid simulation acknowledgment")
	}
	for _, action := range first.Actions {
		if action.Enforced || action.Status != "simulated" {
			t.Fatal("effective action was claimed")
		}
	}
	canonical := payload
	if err := canonicalize(&canonical); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(canonical)
	hash := sha256.Sum256(data)
	if first.PayloadSHA256 != hex.EncodeToString(hash[:]) {
		t.Fatal("canonical payload digest mismatches")
	}
	if first.Actions[0].Action != "block_ip" || first.Actions[0].Target != "192.0.2.1" || first.Actions[2].Target != "ab01" {
		t.Fatal("typed canonical targets wrong")
	}
	info, err := os.Stat(filepath.Join(dir, payload.AlertID+".json"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("receipt not private")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || entries[0].Name() != payload.AlertID+".json" {
		t.Fatal("extra/effective artifacts written")
	}
	other, err := newResponder(dir, testSecret)
	if err != nil {
		t.Fatal(err)
	}
	defer other.directory.Close()
	w = call(other, body, testSecret)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	again := parseAck(t, w)
	if !again.Replay || again.RecordedAt != first.RecordedAt || again.PayloadSHA256 != first.PayloadSHA256 {
		t.Fatal("restart replay changed receipt")
	}
	payload.Timestamp = "2026-10-15T00:00:00Z"
	if w = call(other, bodyOf(t, payload), testSecret); w.Code != 409 {
		t.Fatal("changed content replaced receipt", w.Code)
	}
}
func TestWorkerEventsAndStrictInput(t *testing.T) {
	for code := range workerEvents {
		t.Run(code, func(t *testing.T) {
			r, _ := testStore(t)
			if w := call(r, bodyOf(t, workerAlert(code)), testSecret); w.Code != 200 {
				t.Fatal(w.Code, w.Body.String())
			}
		})
	}
	tests := []struct {
		name   string
		mutate func(*alertPayload)
	}{
		{"schema", func(a *alertPayload) { a.SchemaVersion = 2 }}, {"unsafe ID", func(a *alertPayload) { a.AlertID = "../escape" }},
		{"source", func(a *alertPayload) { a.Source = "browser" }}, {"unlisted worker event", func(a *alertPayload) { a.EventCode = "clinical_hazard" }},
		{"worker severity", func(a *alertPayload) { a.Severity = "critical" }}, {"worker action", func(a *alertPayload) { a.Actions = []string{"block_ip"} }},
		{"wrong worker ID", func(a *alertPayload) { a.AlertID = "evt-" + strings.Repeat("0", 64) }}, {"timestamp", func(a *alertPayload) { a.Timestamp = "yesterday" }},
		{"job traversal", func(a *alertPayload) { a.Indicators["job_id"] = "../file" }}, {"unused indicator", func(a *alertPayload) { a.Indicators["ip"] = "192.0.2.1" }},
		{"unknown indicator", func(a *alertPayload) { a.Indicators["source"] = "injected" }}, {"duplicate action", func(a *alertPayload) { a.Actions = append(a.Actions, "quarantine") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r, dir := testStore(t)
			a := workerAlert("signature_required")
			test.mutate(&a)
			if w := call(r, bodyOf(t, a), testSecret); w.Code != 400 {
				t.Fatal(w.Code, w.Body.String())
			}
			files, _ := os.ReadDir(dir)
			if len(files) != 0 {
				t.Fatal("invalid payload wrote receipt")
			}
		})
	}
	base := bodyOf(t, workerAlert("signature_required"))
	bodies := [][]byte{
		append(append([]byte{}, base...), []byte(` {}`)...),
		bytes.Replace(base, []byte(`"schema_version":1`), []byte(`"schema_version":1,"schema_version":1`), 1),
		bytes.Replace(base, []byte(`"source":"enclave-runner"`), []byte(`"source":"enclave-runner","extra":false`), 1),
		bytes.Replace(base, []byte(`"schema_version"`), []byte(`"SCHEMA_VERSION"`), 1),
		bytes.Replace(base, []byte(`"actions":["quarantine"]`), []byte(`"actions":null`), 1),
		bytes.Replace(base, []byte(`"job_id":"abcd1234"`), []byte(`"job_id":"abcd1234","job_id":"abcd1234"`), 1),
	}
	for i, body := range bodies {
		r, _ := testStore(t)
		if w := call(r, body, testSecret); w.Code != 400 {
			t.Fatal("ambiguous JSON accepted", i, w.Code)
		}
	}
	r, _ := testStore(t)
	if w := call(r, bytes.Repeat([]byte(" "), maxPayloadBytes+1), testSecret); w.Code != 413 {
		t.Fatal("oversized payload accepted", w.Code)
	}
	for _, mutate := range []func(*alertPayload){func(a *alertPayload) { a.Indicators["ip"] = "not-ip" }, func(a *alertPayload) { a.Indicators["ip"] = "fe80::1%eth0" }, func(a *alertPayload) { a.Indicators["cert_serial"] = "not-hex" }, func(a *alertPayload) { a.Actions = []string{"execute"} }} {
		r, _ := testStore(t)
		a := siemAlert()
		mutate(&a)
		if w := call(r, bodyOf(t, a), testSecret); w.Code != 400 {
			t.Fatal("invalid SIEM target accepted", w.Code)
		}
	}
}
func TestCanonicalWorkerDigestFieldOrder(t *testing.T) {
	a := workerAlert("signature_required")
	body := bodyOf(t, a)
	expected := fmt.Sprintf(`{"schema_version":1,"alert_id":%q,"source":"enclave-runner","event_code":"signature_required","severity":"high","timestamp":"2026-10-14T00:00:00Z","indicators":{"job_id":"abcd1234"},"actions":["quarantine"]}`, a.AlertID)
	if string(body) != expected {
		t.Fatal("relay canonical field order changed")
	}
	r, _ := testStore(t)
	ack := parseAck(t, call(r, body, testSecret))
	hash := sha256.Sum256([]byte(expected))
	if ack.PayloadSHA256 != hex.EncodeToString(hash[:]) {
		t.Fatal("relay canonical digest changed")
	}
}
func TestStorageFaultsLatchAndNeverAcknowledge(t *testing.T) {
	for _, stage := range []string{"create", "write", "file_sync", "link", "remove", "dir_sync"} {
		t.Run(stage, func(t *testing.T) {
			r, dir := testStore(t)
			base := r.ops
			fault := errors.New("injected storage fault")
			switch stage {
			case "create":
				r.ops.CreateTemp = func(string, string) (*os.File, error) { return nil, fault }
			case "write":
				r.ops.Write = func(*os.File, []byte) error { return fault }
			case "file_sync":
				r.ops.SyncFile = func(*os.File) error { return fault }
			case "link":
				r.ops.Link = func(string, string) error { return fault }
			case "remove":
				calls := 0
				r.ops.Remove = func(path string) error {
					calls++
					if calls == 1 {
						return fault
					}
					return base.Remove(path)
				}
			case "dir_sync":
				r.ops.SyncDir = func(string) error { return fault }
			}
			alert := workerAlert("signature_required")
			body := bodyOf(t, alert)
			if w := call(r, body, testSecret); w.Code != 503 {
				t.Fatal("storage fault earned ACK", stage, w.Code)
			}
			r.ops = base // Filesystem recovery must not implicitly reset the process latch.
			if w := call(r, body, testSecret); w.Code != 503 {
				t.Fatal("replay recovered unhealthy instance")
			}
			next := workerAlert("signature_invalid")
			if w := call(r, bodyOf(t, next), testSecret); w.Code != 503 {
				t.Fatal("new event recovered unhealthy instance")
			}
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest("GET", "/health", nil))
			if w.Code != 503 {
				t.Fatal("unhealthy health stayed ready")
			}
			if stage == "create" || stage == "write" || stage == "file_sync" || stage == "link" {
				if _, err := os.Stat(filepath.Join(dir, alert.AlertID+".json")); !os.IsNotExist(err) {
					t.Fatal("unpublished error wrote final receipt")
				}
			}
			if stage == "remove" || stage == "dir_sync" {
				restarted, err := newResponder(dir, testSecret)
				if err != nil {
					t.Fatal(err)
				}
				defer restarted.directory.Close()
				w := call(restarted, body, testSecret)
				if w.Code != 200 || !parseAck(t, w).Replay {
					t.Fatal("explicit restart failed to recover validated durable receipt")
				}
			}
		})
	}
}
func TestConcurrentInstancesDoNotClobber(t *testing.T) {
	first, dir := testStore(t)
	second, err := newResponder(dir, testSecret)
	if err != nil {
		t.Fatal(err)
	}
	defer second.directory.Close()
	ready, start := make(chan struct{}, 2), make(chan struct{})
	for _, r := range []*responder{first, second} {
		link := r.ops.Link
		r.ops.Link = func(a, b string) error { ready <- struct{}{}; <-start; return link(a, b) }
	}
	body := bodyOf(t, workerAlert("signature_required"))
	responses := make(chan *httptest.ResponseRecorder, 2)
	for _, r := range []*responder{first, second} {
		go func(r *responder) { responses <- call(r, body, testSecret) }(r)
	}
	<-ready
	<-ready
	close(start)
	replayCount := 0
	recorded := ""
	for i := 0; i < 2; i++ {
		w := <-responses
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		ack := parseAck(t, w)
		if ack.Replay {
			replayCount++
		}
		if recorded != "" && ack.RecordedAt != recorded {
			t.Fatal("concurrent receipts disagreed")
		}
		recorded = ack.RecordedAt
	}
	if replayCount != 1 {
		t.Fatal("hardlink no-clobber did not select one publisher")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatal("multiple final or temporary artifacts")
	}
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := call(first, body, testSecret)
			if w.Code != 200 || !parseAck(t, w).Replay {
				t.Error("concurrent replay failed", w.Code)
			}
		}()
	}
	wg.Wait()
}
func TestCorruptOrUnsafeReceiptsAreRejected(t *testing.T) {
	for _, kind := range []string{"digest", "actions", "missing_enforced", "symlink", "fifo", "mode", "setuid", "setgid", "sticky"} {
		t.Run(kind, func(t *testing.T) {
			r, dir := testStore(t)
			a := workerAlert("signature_required")
			body := bodyOf(t, a)
			if w := call(r, body, testSecret); w.Code != 200 {
				t.Fatal(w.Code)
			}
			path := filepath.Join(dir, a.AlertID+".json")
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "digest":
				var record receipt
				_ = json.Unmarshal(data, &record)
				record.PayloadSHA256 = strings.Repeat("0", 64)
				data, _ = json.Marshal(record)
				_ = os.WriteFile(path, data, 0600)
			case "actions":
				var record receipt
				_ = json.Unmarshal(data, &record)
				record.Actions[0].Enforced = true
				data, _ = json.Marshal(record)
				_ = os.WriteFile(path, data, 0600)
			case "missing_enforced":
				data = bytes.Replace(data, []byte(`"enforced":false,`), nil, 1)
				_ = os.WriteFile(path, data, 0600)
			case "symlink":
				_ = os.Remove(path)
				if err := os.Symlink("not-a-receipt", path); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				_ = os.Remove(path)
				if err := syscall.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			case "mode":
				_ = os.Chmod(path, 0644)
			case "setuid":
				if err := os.Chmod(path, 0600|os.ModeSetuid); err != nil {
					t.Fatal(err)
				}
			case "setgid":
				if err := os.Chmod(path, 0600|os.ModeSetgid); err != nil {
					t.Fatal(err)
				}
			case "sticky":
				if err := os.Chmod(path, 0600|os.ModeSticky); err != nil {
					t.Fatal(err)
				}
			}
			if w := call(r, body, testSecret); w.Code != 503 {
				t.Fatal("unsafe existing receipt replayed", kind, w.Code)
			}
			if other, err := newResponder(dir, testSecret); err == nil {
				other.directory.Close()
				t.Fatal("unsafe store started ready", kind)
			}
		})
	}
}
func TestParentSyncAndDirectoryAnchoring(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "parent", "actions")
	ops := defaultOps()
	base := ops.SyncDir
	observed := map[string]int{}
	ops.SyncDir = func(fdPath string) error {
		actual, err := os.Readlink(fdPath)
		if err == nil {
			observed[actual]++
		}
		return base(fdPath)
	}
	r, err := newResponderWithOps(dir, testSecret, ops)
	if err != nil {
		t.Fatal(err)
	}
	defer r.directory.Close()
	if observed[root] == 0 || observed[filepath.Join(root, "parent")] == 0 || observed[dir] == 0 {
		t.Fatal("directory publication skipped parent fsync")
	}
	observed = map[string]int{}
	again, err := newResponderWithOps(dir, testSecret, ops)
	if err != nil {
		t.Fatal(err)
	}
	again.directory.Close()
	if observed[root] == 0 || observed[filepath.Join(root, "parent")] == 0 {
		t.Fatal("existing retry skipped parent fsync")
	}
	moved := filepath.Join(root, "retained")
	if err := os.Rename(dir, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	a := workerAlert("signature_required")
	if w := call(r, bodyOf(t, a), testSecret); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if _, err := os.Stat(filepath.Join(moved, a.AlertID+".json")); err != nil {
		t.Fatal("receipt lost pinned-directory ownership")
	}
	if _, err := os.Stat(filepath.Join(dir, a.AlertID+".json")); !os.IsNotExist(err) {
		t.Fatal("replacement directory captured receipt")
	}
	link := filepath.Join(root, "linked-parent")
	if err := os.Symlink(filepath.Join(root, "parent"), link); err != nil {
		t.Fatal(err)
	}
	if bad, err := newResponder(filepath.Join(link, "actions"), testSecret); err == nil {
		bad.directory.Close()
		t.Fatal("symlink ancestor accepted")
	}
	ops = defaultOps()
	ops.SyncDir = func(string) error { return errors.New("parent sync failed") }
	if bad, err := newResponderWithOps(filepath.Join(root, "failed", "actions"), testSecret, ops); err == nil {
		bad.directory.Close()
		t.Fatal("failed parent sync started ready")
	}
	for _, flag := range []os.FileMode{os.ModeSetuid, os.ModeSetgid, os.ModeSticky} {
		special := filepath.Join(root, fmt.Sprint(uint32(flag)))
		if err := os.Mkdir(special, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(special, 0700|flag); err != nil {
			t.Fatal(err)
		}
		if bad, err := newResponder(special, testSecret); err == nil {
			bad.directory.Close()
			t.Fatal("special directory permissions accepted")
		}
	}
}
func TestTLSConfigurationAndVerifiedTransport(t *testing.T) {
	for _, cfg := range []serverConfig{
		{Address: "127.0.0.1:8090", Secret: "short"}, {Address: ":8090", Secret: testSecret},
		{Address: "0.0.0.0:8090", Secret: testSecret}, {Address: "localhost:8090", Secret: testSecret},
		{Address: "127.0.0.1:8090", Secret: testSecret, TLSCert: "cert"},
	} {
		if validateServerConfig(cfg) == nil {
			t.Fatal("unsafe responder configuration accepted")
		}
	}
	for _, cfg := range []serverConfig{{Address: "127.0.0.1:8090", Secret: testSecret}, {Address: "[::1]:8090", Secret: testSecret}, {Address: ":8090", Secret: testSecret, TLSCert: "cert", TLSKey: "key"}} {
		if err := validateServerConfig(cfg); err != nil {
			t.Fatal(err)
		}
	}
	r, _ := testStore(t)
	server := httptest.NewUnstartedServer(r)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	client := server.Client()
	req, _ := http.NewRequest("POST", server.URL+"/alert", bytes.NewReader(bodyOf(t, workerAlert("signature_required"))))
	req.Header.Set("X-Webhook-Secret", testSecret)
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 || response.TLS == nil || response.TLS.Version < tls.VersionTLS12 {
		t.Fatal("verified TLS simulation failed")
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	old := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11}}, Timeout: 3 * time.Second}
	if response, err := old.Get(server.URL + "/health"); err == nil {
		response.Body.Close()
		t.Fatal("legacy TLS accepted")
	}
	untrusted := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS12}}, Timeout: 3 * time.Second}
	if response, err := untrusted.Get(server.URL + "/health"); err == nil {
		response.Body.Close()
		t.Fatal("untrusted TLS issuer accepted")
	}
}
