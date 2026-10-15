//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package ownership

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
)

type deliveryEndpoint struct {
	mu          sync.Mutex
	server      *httptest.Server
	bundle      AcceptedBundle
	expected    OwnerUploadReceipt
	behavior    string
	posts, gets int
	delivered   bool
	hook        func()
}

func deliveryBundle(t *testing.T) AcceptedBundle {
	t.Helper()
	f := fixture(t)
	challenge := payloadChallenge(t, false)
	encrypted, e := EncryptForChallenge(challenge, f.pin, f.certA, f.keyA, &payloadWorkerKey(t).PublicKey, []byte("synthetic private delivery input"), f.now)
	if e != nil {
		t.Fatal(e)
	}
	accepted := payloadAcceptance(t, challenge, encrypted.Ciphertext, encrypted.KeyEnvelope, false)
	return AcceptedBundle{Acceptance: append([]byte(nil), accepted.canonical...), KeyEnvelope: encrypted.KeyEnvelope, Ciphertext: encrypted.Ciphertext}
}
func deliveryFixture(t *testing.T) (*deliveryEndpoint, AuthorityClientConfig) {
	t.Helper()
	f := fixture(t)
	bundle := deliveryBundle(t)
	scope := AcceptanceScope{StoreID: strings.Repeat("1", 32), PolicySHA256: strings.Repeat("2", 64)}
	verified, e := VerifyAcceptance(bundle.Acceptance, f.pin, scope)
	if e != nil {
		t.Fatal(e)
	}
	binding := verified.Binding()
	x := &deliveryEndpoint{bundle: bundle, expected: OwnerUploadReceipt{1, binding.JobID, verified.SHA256(), binding.CredentialSHA256, binding.CiphertextSHA256, binding.CiphertextBytes, binding.KeyEnvelopeSHA256, "delivered"}}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		owner, e := PrincipalFromTLS(r.TLS)
		if e != nil || owner.CredentialSHA256() != x.expected.CredentialSHA256 {
			http.Error(w, "denied", 403)
			return
		}
		x.mu.Lock()
		behavior, hook := x.behavior, x.hook
		if r.Method == "POST" && r.URL.Path == "/v1/uploads" {
			x.posts++
		} else if r.Method == "GET" && r.URL.Path == "/v1/uploads/"+x.expected.JobID {
			x.gets++
		} else {
			x.mu.Unlock()
			http.Error(w, "fixture route", 404)
			return
		}
		delivered := x.delivered
		x.mu.Unlock()
		abort := func() {
			conn, _, e := w.(http.Hijacker).Hijack()
			if e != nil {
				t.Error(e)
				return
			}
			conn.Close()
		}
		if r.Method == "POST" {
			if hook != nil {
				hook()
			}
			if behavior == "drop_before" {
				abort()
				return
			}
			raw, e := io.ReadAll(io.LimitReader(r.Body, MaxCiphertextBytes+MaxAcceptanceBytes+521))
			if e != nil {
				http.Error(w, "fixture body", 400)
				return
			}
			if r.Header.Get("Content-Type") != "application/octet-stream" || r.ContentLength != int64(len(raw)) || len(raw) < 8 {
				t.Error("invalid delivery wire metadata")
				http.Error(w, "fixture", 400)
				return
			}
			a := int(binary.BigEndian.Uint32(raw[:4]))
			if a < 1 || a > MaxAcceptanceBytes || len(raw) < 8+a {
				t.Error("acceptance framing")
				return
			}
			n := int(binary.BigEndian.Uint32(raw[4+a : 8+a]))
			if n < 256 || n > 512 || len(raw) < 8+a+n {
				t.Error("envelope framing")
				return
			}
			if !bytes.Equal(raw[4:4+a], x.bundle.Acceptance) || !bytes.Equal(raw[8+a:8+a+n], x.bundle.KeyEnvelope) || !bytes.Equal(raw[8+a+n:], x.bundle.Ciphertext) {
				t.Error("delivery body changed or gained trailing bytes")
				return
			}
			x.mu.Lock()
			x.delivered = true
			x.mu.Unlock()
			delivered = true
			if behavior == "drop_after" {
				abort()
				return
			}
		}
		if !delivered {
			http.Error(w, "unknown transport state", 404)
			return
		}
		if behavior == "http_error" {
			http.Error(w, "PRIVATE_SERVER_DIAGNOSTIC", 500)
			return
		}
		if behavior == "redirect" {
			http.Redirect(w, r, "/wrong", 307)
			return
		}
		raw, _ := json.Marshal(x.expected)
		switch behavior {
		case "unknown":
			raw = append([]byte(`{"extra":0,`), raw[1:]...)
		case "missing":
			var m map[string]any
			json.Unmarshal(raw, &m)
			delete(m, "acceptance_sha256")
			raw, _ = json.Marshal(m)
		case "null":
			raw = bytes.Replace(raw, []byte(`"state":"delivered"`), []byte(`"state":null`), 1)
		case "duplicate":
			raw = bytes.Replace(raw, []byte(`"state":"delivered"`), []byte(`"state":"delivered","state":"delivered"`), 1)
		case "alias":
			raw = bytes.Replace(raw, []byte(`"acceptance_sha256"`), []byte(`"Acceptance_SHA256"`), 1)
		case "wrong_job":
			r := x.expected
			r.JobID = strings.Repeat("f", 16)
			raw, _ = json.Marshal(r)
		case "wrong_acceptance":
			r := x.expected
			r.AcceptanceSHA256 = strings.Repeat("f", 64)
			raw, _ = json.Marshal(r)
		case "wrong_owner":
			r := x.expected
			r.CredentialSHA256 = strings.Repeat("f", 64)
			raw, _ = json.Marshal(r)
		case "wrong_body":
			r := x.expected
			r.CiphertextSHA256 = strings.Repeat("f", 64)
			raw, _ = json.Marshal(r)
		case "wrong_bytes":
			r := x.expected
			r.CiphertextBytes++
			raw, _ = json.Marshal(r)
		case "wrong_envelope":
			r := x.expected
			r.KeyEnvelopeSHA256 = strings.Repeat("f", 64)
			raw, _ = json.Marshal(r)
		case "other_state":
			r := x.expected
			r.State = "processing"
			raw, _ = json.Marshal(r)
		case "version":
			r := x.expected
			r.SchemaVersion = 2
			raw, _ = json.Marshal(r)
		case "trailing":
			raw = append(raw, []byte(" {}")...)
		case "oversized":
			raw = bytes.Repeat([]byte("x"), clientDeliveryReceiptLimit+1)
		case "truncated":
			w.Header().Set("Content-Length", "4096")
			w.Write([]byte(`{"schema_version":`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(raw)
	}))
	pool := x509.NewCertPool()
	chain := f.stateA.VerifiedChains[0]
	pool.AddCert(chain[len(chain)-1])
	pair := tls.Certificate{Certificate: [][]byte{f.certA.Raw}, PrivateKey: f.keyA}
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, Certificates: []tls.Certificate{pair}, NextProtos: []string{"http/1.1"}}
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.Config.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){}
	server.StartTLS()
	x.server = server
	t.Cleanup(server.Close)
	return x, AuthorityClientConfig{BaseURL: server.URL, Certificate: pair, RootCAs: pool, ServerName: "localhost", Pin: f.pin, Scope: scope}
}
func (x *deliveryEndpoint) set(behavior string) { x.mu.Lock(); x.behavior = behavior; x.mu.Unlock() }
func (x *deliveryEndpoint) counts() (int, int) {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.posts, x.gets
}
func deliveryCleanup(t *testing.T, d *ClientDelivery) {
	t.Helper()
	if d == nil {
		return
	}
	t.Cleanup(func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		d.client.CloseIdleConnections()
		if d.rawHeld {
			syscall.Close(d.rawFD)
			d.rawHeld = false
		}
		if d.lock != nil {
			d.lock.Close()
		}
		if d.root != nil {
			d.root.Close()
		}
	})
}
func deliveryCreate(t *testing.T, x *deliveryEndpoint, cfg AuthorityClientConfig) (*ClientDelivery, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "delivery")
	d, e := CreateClientDelivery(context.Background(), dir, cfg, x.bundle)
	deliveryCleanup(t, d)
	if e != nil {
		t.Fatal(e)
	}
	return d, dir
}
func deliverySimulateExit(d *ClientDelivery) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.client.CloseIdleConnections()
	d.root.Close()
	d.lock.Close()
	if d.rawHeld {
		syscall.Close(d.rawFD)
		d.rawHeld = false
	}
	d.closed = true
}

func TestClientDeliveryDurableBodyIntentAndReceipt(t *testing.T) {
	x, cfg := deliveryFixture(t)
	d, dir := deliveryCreate(t, x, cfg)
	originalBody := fileBytes(t, filepath.Join(dir, "ciphertext.bin"))
	originalAcceptance := fileBytes(t, filepath.Join(dir, clientDeliveryStepNames[0]))
	if posts, gets := x.counts(); posts != 0 || gets != 0 || d.State() != "prepared" || d.JobID() != x.expected.JobID {
		t.Fatal("create performed network or lost identity")
	}
	if got, e := d.AcceptanceSHA256(); e != nil || got != x.expected.AcceptanceSHA256 || d.State() != "prepared" {
		t.Fatal("prepared acceptance identity unavailable or mistaken for delivery", e)
	}
	x.mu.Lock()
	x.hook = func() {
		var step clientDeliveryStep
		raw, e := os.ReadFile(filepath.Join(dir, clientDeliveryStepNames[1]))
		_, markerErr := os.Lstat(filepath.Join(dir, "delivery.intent"))
		if e != nil || strictJSON(raw, &step, clientDeliveryStepLimit) != nil || step.Sequence != 1 || step.JobID != x.expected.JobID || !os.IsNotExist(markerErr) {
			t.Error("POST preceded complete durable delivery intent")
		}
	}
	x.mu.Unlock()
	receipt, e := d.Deliver(context.Background())
	if e != nil || receipt != x.expected || d.State() != "delivered" {
		t.Fatal("delivery failed", e)
	}
	if again, e := d.Deliver(context.Background()); e != nil || again != receipt {
		t.Fatal("local idempotent receipt failed", e)
	}
	if again, e := d.Recover(context.Background()); e != nil || again != receipt {
		t.Fatal("delivered recovery changed receipt", e)
	}
	if posts, gets := x.counts(); posts != 1 || gets != 0 {
		t.Fatal("completed operation repeated network", posts, gets)
	}
	if !bytes.Equal(originalBody, fileBytes(t, filepath.Join(dir, "ciphertext.bin"))) || !bytes.Equal(originalAcceptance, fileBytes(t, filepath.Join(dir, clientDeliveryStepNames[0]))) {
		t.Fatal("delivery replaced original bundle")
	}
	before := operationHistory(t, dir)
	if e = d.Close(); e != nil {
		t.Fatal(e)
	}
	opened, e := OpenClientDelivery(context.Background(), dir, cfg)
	deliveryCleanup(t, opened)
	if e != nil || opened.State() != "delivered" {
		t.Fatal("cold delivered open", e)
	}
	if got, e := opened.Receipt(); e != nil || got != receipt {
		t.Fatal("cold receipt mismatch", e)
	}
	if !reflect.DeepEqual(before, operationHistory(t, dir)) {
		t.Fatal("open relabeled delivery history")
	}
	if got, e := opened.AcceptanceSHA256(); e != nil || got != receipt.AcceptanceSHA256 {
		t.Fatal("cold acceptance identity mismatch", e)
	}
	if e := os.WriteFile(filepath.Join(dir, "ciphertext.bin"), []byte("changed"), 0600); e != nil {
		t.Fatal(e)
	}
	if got, e := opened.AcceptanceSHA256(); e == nil || got != "" || opened.State() != "unavailable" {
		t.Fatal("acceptance getter ignored custody corruption")
	}
	if posts, gets := x.counts(); posts != 1 || gets != 0 {
		t.Fatal("acceptance getter performed network", posts, gets)
	}
}

func TestClientDeliveryLostResponsesRecoverOnlyKnownGET(t *testing.T) {
	for _, kind := range []string{"drop_before", "drop_after", "truncated", "http_error", "redirect"} {
		t.Run(kind, func(t *testing.T) {
			x, cfg := deliveryFixture(t)
			x.set(kind)
			d, dir := deliveryCreate(t, x, cfg)
			if _, e := d.Deliver(context.Background()); e == nil || strings.Contains(e.Error(), "PRIVATE") {
				t.Fatal("uncertain delivery accepted or leaked diagnostic", e)
			}
			if d.State() != "delivering" {
				t.Fatal("uncertain intent lost")
			}
			before := operationHistory(t, dir)
			if _, e := d.Deliver(context.Background()); e == nil {
				t.Fatal("uncertain POST repeated")
			}
			if e := d.Close(); e == nil {
				t.Fatal("pending delivery released flock")
			}
			if other, e := OpenClientDelivery(context.Background(), dir, cfg); e == nil {
				deliveryCleanup(t, other)
				t.Fatal("pending live writer exclusion lost")
			}
			deliverySimulateExit(d)
			x.set("")
			opened, e := OpenClientDelivery(context.Background(), dir, cfg)
			deliveryCleanup(t, opened)
			if e != nil || opened.State() != "delivering" {
				t.Fatal("cold intent lost", e)
			}
			receipt, e := opened.Recover(context.Background())
			if kind == "drop_before" {
				if e == nil || opened.State() != "delivering" || !reflect.DeepEqual(before, operationHistory(t, dir)) {
					t.Fatal("missing remote delivery adopted as absence/success", e)
				}
			} else {
				if e != nil || receipt != x.expected || opened.State() != "delivered" {
					t.Fatal("matching GET did not recover", e)
				}
			}
			if posts, gets := x.counts(); posts != 1 || gets != 1 {
				t.Fatal("recovery did not remain GET-only", posts, gets)
			}
		})
	}
}

func TestClientDeliveryStrictReceiptFieldsStayPending(t *testing.T) {
	for _, kind := range []string{"unknown", "missing", "null", "duplicate", "alias", "wrong_job", "wrong_acceptance", "wrong_owner", "wrong_body", "wrong_bytes", "wrong_envelope", "other_state", "version", "trailing", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			x, cfg := deliveryFixture(t)
			x.set(kind)
			d, _ := deliveryCreate(t, x, cfg)
			if _, e := d.Deliver(context.Background()); e == nil || d.State() != "delivering" {
				t.Fatal("invalid receipt accepted", e)
			}
			if _, e := d.Deliver(context.Background()); e == nil {
				t.Fatal("bad receipt authorized retry")
			}
			x.set("")
			if receipt, e := d.Recover(context.Background()); e != nil || receipt != x.expected {
				t.Fatal("matching recovery failed", e)
			}
			if posts, gets := x.counts(); posts != 1 || gets != 1 {
				t.Fatal("receipt mismatch changed network intent", posts, gets)
			}
		})
	}
}

func TestClientDeliveryRejectsBundleBeforeDirectoryOrHTTP(t *testing.T) {
	x, cfg := deliveryFixture(t)
	for _, kind := range []string{"cipher_hash", "cipher_short", "cipher_extra", "envelope_hash", "envelope_short", "envelope_long", "acceptance_tamper", "acceptance_oversize", "wrong_leaf", "wrong_scope", "wrong_profile"} {
		t.Run(kind, func(t *testing.T) {
			bundle := AcceptedBundle{append([]byte(nil), x.bundle.Acceptance...), append([]byte(nil), x.bundle.KeyEnvelope...), append([]byte(nil), x.bundle.Ciphertext...)}
			config := cfg
			switch kind {
			case "cipher_hash":
				bundle.Ciphertext[0] ^= 1
			case "cipher_short":
				bundle.Ciphertext = bundle.Ciphertext[:15]
			case "cipher_extra":
				bundle.Ciphertext = append(bundle.Ciphertext, 0)
			case "envelope_hash":
				bundle.KeyEnvelope[0] ^= 1
			case "envelope_short":
				bundle.KeyEnvelope = bundle.KeyEnvelope[:255]
			case "envelope_long":
				bundle.KeyEnvelope = make([]byte, 513)
			case "acceptance_tamper":
				bundle.Acceptance[0] = '!'
			case "acceptance_oversize":
				bundle.Acceptance = make([]byte, MaxAcceptanceBytes+1)
			case "wrong_leaf":
				f := fixture(t)
				config.Certificate = tls.Certificate{Certificate: [][]byte{f.certB.Raw}, PrivateKey: f.keyB}
			case "wrong_scope":
				config.Scope.StoreID = strings.Repeat("e", 32)
			case "wrong_profile":
				config.Pin.ExecutionProfileSHA256 = strings.Repeat("e", 64)
			}
			dir := filepath.Join(t.TempDir(), "delivery")
			if d, e := CreateClientDelivery(context.Background(), dir, config, bundle); e == nil {
				deliveryCleanup(t, d)
				t.Fatal("invalid bundle admitted")
			}
			if _, e := os.Lstat(dir); !os.IsNotExist(e) {
				t.Fatal("invalid bundle created custody")
			}
		})
	}
	if posts, gets := x.counts(); posts != 0 || gets != 0 {
		t.Fatal("invalid input reached HTTP")
	}
}

func TestClientDeliveryCanonicalAcceptanceAndNoCallerAlias(t *testing.T) {
	x, cfg := deliveryFixture(t)
	var pretty bytes.Buffer
	if json.Indent(&pretty, x.bundle.Acceptance, "", "  ") != nil {
		t.Fatal("fixture")
	}
	bundle := AcceptedBundle{pretty.Bytes(), append([]byte(nil), x.bundle.KeyEnvelope...), append([]byte(nil), x.bundle.Ciphertext...)}
	dir := filepath.Join(t.TempDir(), "delivery")
	d, e := CreateClientDelivery(context.Background(), dir, cfg, bundle)
	deliveryCleanup(t, d)
	if e != nil {
		t.Fatal(e)
	}
	bundle.Acceptance[0] = '!'
	bundle.KeyEnvelope[0] ^= 1
	bundle.Ciphertext[0] ^= 1
	receipt, e := d.Deliver(context.Background())
	if e != nil || receipt.AcceptanceSHA256 != x.expected.AcceptanceSHA256 || receipt != x.expected {
		t.Fatal("raw acceptance whitespace or caller alias changed binding", e)
	}
}

func TestClientDeliveryRefusesHistoryMutationAndTrustRebind(t *testing.T) {
	for _, kind := range []string{"unknown", "marker", "ciphertext", "metadata", "missing_step", "null_receipt", "endpoint", "scope", "credential", "profile"} {
		t.Run(kind, func(t *testing.T) {
			x, cfg := deliveryFixture(t)
			d, dir := deliveryCreate(t, x, cfg)
			if e := d.Close(); e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "unknown":
				os.WriteFile(filepath.Join(dir, "extra"), []byte("preserve"), 0600)
			case "marker":
				os.WriteFile(filepath.Join(dir, "delivery.intent"), []byte("preserve"), 0600)
			case "ciphertext":
				os.WriteFile(filepath.Join(dir, "ciphertext.bin"), []byte("changed"), 0600)
			case "metadata":
				path := filepath.Join(dir, clientDeliveryStepNames[0])
				raw := fileBytes(t, path)
				raw = bytes.Replace(raw, []byte(`"sequence":0`), []byte(`"sequence":1`), 1)
				os.WriteFile(path, raw, 0600)
			case "missing_step":
				os.Remove(filepath.Join(dir, clientDeliveryStepNames[0]))
			case "null_receipt":
				path := filepath.Join(dir, clientDeliveryStepNames[0])
				var m map[string]any
				json.Unmarshal(fileBytes(t, path), &m)
				m["receipt"] = nil
				raw, _ := json.Marshal(m)
				os.WriteFile(path, raw, 0600)
			case "endpoint":
				cfg.BaseURL = "https://different.invalid"
			case "scope":
				cfg.Scope.PolicySHA256 = strings.Repeat("e", 64)
			case "credential":
				f := fixture(t)
				cfg.Certificate = tls.Certificate{Certificate: [][]byte{f.certB.Raw}, PrivateKey: f.keyB}
			case "profile":
				cfg.Pin.ExecutionProfileSHA256 = strings.Repeat("e", 64)
			}
			before := operationHistory(t, dir)
			opened, e := OpenClientDelivery(context.Background(), dir, cfg)
			deliveryCleanup(t, opened)
			if e == nil {
				t.Fatal("changed history/trust adopted")
			}
			if !reflect.DeepEqual(before, operationHistory(t, dir)) {
				t.Fatal("rejected history repaired/reset")
			}
			if posts, gets := x.counts(); posts != 0 || gets != 0 {
				t.Fatal("Open performed network")
			}
		})
	}
}

func TestClientDeliveryPublicationFaultsBeforePOSTAndRawLock(t *testing.T) {
	for _, point := range []string{"file_sync", "marker_directory_sync", "directory_sync", "intent_unlink", "intent_directory_sync"} {
		t.Run(point, func(t *testing.T) {
			x, cfg := deliveryFixture(t)
			d, dir := deliveryCreate(t, x, cfg)
			beforeBody := fileBytes(t, filepath.Join(dir, "ciphertext.bin"))
			d.fault = func(name string) error {
				if name == point {
					return errors.New("synthetic publication fault")
				}
				return nil
			}
			if _, e := d.Deliver(context.Background()); e == nil || d.State() != "unavailable" {
				t.Fatal("failed intent allowed delivery", e)
			}
			if posts, gets := x.counts(); posts != 0 || gets != 0 {
				t.Fatal("POST preceded intent durability")
			}
			if e := d.Close(); e == nil {
				t.Fatal("sticky local IO released lock")
			}
			if !bytes.Equal(beforeBody, fileBytes(t, filepath.Join(dir, "ciphertext.bin"))) {
				t.Fatal("fault discarded encrypted bundle")
			}
			lockFD := d.rawFD
			runtime.GC()
			var stat syscall.Stat_t
			if syscall.Fstat(lockFD, &stat) != nil {
				t.Fatal("GC released raw flock")
			}
			if opened, e := OpenClientDelivery(context.Background(), dir, cfg); e == nil {
				deliveryCleanup(t, opened)
				t.Fatal("sticky live writer lost exclusion")
			}
			deliverySimulateExit(d)
			reopened, e := OpenClientDelivery(context.Background(), dir, cfg)
			deliveryCleanup(t, reopened)
			if point == "intent_directory_sync" {
				if e != nil || reopened.State() != "delivering" {
					t.Fatal("complete delivering phase lost", e)
				}
				if _, e = reopened.Recover(context.Background()); e == nil {
					t.Fatal("missing remote delivery became successful")
				}
				if posts, gets := x.counts(); posts != 0 || gets != 1 {
					t.Fatal("late publication uncertainty repeated POST", posts, gets)
				}
			} else {
				if e == nil {
					t.Fatal("unknown marker history adopted")
				}
			}
		})
	}
}

func TestClientDeliveryCancelledBeforeIntentAndConcurrentDeliver(t *testing.T) {
	x, cfg := deliveryFixture(t)
	d, _ := deliveryCreate(t, x, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := d.Deliver(ctx); e == nil || d.State() != "prepared" {
		t.Fatal("cancelled call consumed intent")
	}
	var group sync.WaitGroup
	failures := make(chan error, 8)
	for i := 0; i < 8; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			r, e := d.Deliver(context.Background())
			if e == nil && r != x.expected {
				e = errors.New("changed receipt")
			}
			failures <- e
		}()
	}
	group.Wait()
	close(failures)
	for e := range failures {
		if e != nil {
			t.Fatal(e)
		}
	}
	if posts, gets := x.counts(); posts != 1 || gets != 0 {
		t.Fatal("concurrent sends repeated POST", posts, gets)
	}
}
