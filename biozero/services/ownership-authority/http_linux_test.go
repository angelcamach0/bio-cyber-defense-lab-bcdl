//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package ownership

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
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

type httpFixture struct {
	store      *Store
	cfg        StoreConfig
	handler    *AuthorityHTTPHandler
	server     *httptest.Server
	a, b       *http.Client
	tlsA, tlsB *tls.Config
}

func newHTTPFixture(t *testing.T, setup func(*httptest.Server, *AuthorityHTTPHandler)) *httpFixture {
	t.Helper()
	f := fixture(t)
	p := DefaultStorePolicy()
	p.MaxBodyBytes = 64
	s, cfg := storeFixture(t, p)
	h, err := NewHTTPHandler(HTTPHandlerConfig{Store: s})
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	chain := f.stateA.VerifiedChains[0]
	pool.AddCert(chain[len(chain)-1])
	pairA := tls.Certificate{Certificate: [][]byte{f.certA.Raw}, PrivateKey: f.keyA}
	pairB := tls.Certificate{Certificate: [][]byte{f.certB.Raw}, PrivateKey: f.keyB}
	server := httptest.NewUnstartedServer(h)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.Config.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){}
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, Certificates: []tls.Certificate{pairA}, NextProtos: []string{"http/1.1"}}
	if setup != nil {
		setup(server, h)
	}
	server.StartTLS()
	ca := &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pairA}, NextProtos: []string{"http/1.1"}}
	cb := ca.Clone()
	cb.Certificates = []tls.Certificate{pairB}
	client := func(c *tls.Config) *http.Client {
		return &http.Client{Transport: &http.Transport{TLSClientConfig: c, DisableKeepAlives: true}, Timeout: 3 * time.Second}
	}
	out := &httpFixture{s, cfg, h, server, client(ca), client(cb), ca, cb}
	t.Cleanup(func() {
		h.StopAdmission()
		server.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if h.Wait(ctx) != nil {
			t.Error("HTTP handlers not joined")
		}
	})
	return out
}
func httpCall(t *testing.T, c *http.Client, method, url, kind string, raw []byte) (int, []byte) {
	t.Helper()
	r, err := http.NewRequest(method, url, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if kind != "" {
		r.Header.Set("Content-Type", kind)
	}
	res, err := c.Do(r)
	if err != nil {
		t.Fatal("HTTP transport", err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, HTTPResponseLimit+1))
	if err != nil || len(body) > HTTPResponseLimit {
		t.Fatal("HTTP response invalid", err)
	}
	if res.Proto != "HTTP/1.1" || !res.Close {
		t.Fatal("connection reuse/protocol policy lost")
	}
	return res.StatusCode, body
}
func httpReserve(t *testing.T, x *httpFixture, n int) ([]byte, SignedChallenge) {
	t.Helper()
	raw, _ := json.Marshal(HTTPReserveRequest{1, storeRequest(n), "input.fastq"})
	status, body := httpCall(t, x.a, "POST", x.server.URL+"/v1/reservations", "application/json", raw)
	if status != 200 {
		t.Fatal("reserve status", status)
	}
	var ch SignedChallenge
	if strictJSON(body, &ch, MaxChallengeBytes) != nil {
		t.Fatal("challenge wire invalid")
	}
	return body, ch
}
func httpManifest(t *testing.T, ch []byte, body []byte) []byte {
	t.Helper()
	f := fixture(t)
	v, err := VerifyChallengeForClient(ch, f.pin, f.certA, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	m, err := SignManifest(f.keyA, f.certA, v, ManifestInput{digest(body), int64(len(body)), strings.Repeat("a", 64)})
	if err != nil {
		t.Fatal(err)
	}
	out, err := MarshalManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func httpFraming(ch, manifest, body []byte) []byte {
	var out bytes.Buffer
	binary.Write(&out, binary.BigEndian, uint32(len(ch)))
	out.Write(ch)
	binary.Write(&out, binary.BigEndian, uint32(len(manifest)))
	out.Write(manifest)
	out.Write(body)
	return out.Bytes()
}
func rawHTTPClient(t *testing.T, x *httpFixture, cfg *tls.Config) *tls.Conn {
	t.Helper()
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", x.server.Listener.Addr().String(), cfg.Clone())
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(3 * time.Second))
	t.Cleanup(func() { c.Close() })
	return c
}
func rawFinalization(t *testing.T, c *tls.Conn, metadata []byte, total int) {
	t.Helper()
	request := fmt.Sprintf("POST /v1/finalizations HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\n\r\n", total)
	if _, err := io.WriteString(c, request); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(metadata); err != nil {
		t.Fatal(err)
	}
}
func rawResponse(t *testing.T, c *tls.Conn) (int, []byte) {
	t.Helper()
	res, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal("early HTTP response not observed", err)
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, HTTPResponseLimit+1))
	if err != nil {
		t.Fatal(err)
	}
	return res.StatusCode, b
}
func waitHTTPState(t *testing.T, s *Store, want func(StoreSnapshot) bool) StoreSnapshot {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		v := s.Snapshot()
		if want(v) {
			return v
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("HTTP state deadline")
	return StoreSnapshot{}
}
func TestHTTPRealMTLSOwnerReplayAndNoCiphertextForOtherLeaf(t *testing.T) {
	x := newHTTPFixture(t, nil)
	ch, claim := httpReserve(t, x, 1)
	body := bytes.Repeat([]byte("z"), 32)
	manifest := httpManifest(t, ch, body)
	status, accepted := httpCall(t, x.a, "POST", x.server.URL+"/v1/finalizations", "application/octet-stream", httpFraming(ch, manifest, body))
	if status != 200 {
		t.Fatal("finalize status", status)
	}
	verified, err := VerifyAcceptance(accepted, x.cfg.Pin, x.cfg.ExpectedScope)
	if err != nil || verified.Binding().CiphertextSHA256 != digest(body) {
		t.Fatal("accepted facts", err)
	}
	status, job := httpCall(t, x.a, "GET", x.server.URL+"/v1/jobs/"+claim.Claim.JobID, "", nil)
	var response HTTPJobResponse
	if status != 200 || json.Unmarshal(job, &response) != nil || response.Acceptance == nil {
		t.Fatal("owner readback")
	}
	again, _ := MarshalAcceptance(*response.Acceptance)
	if !bytes.Equal(again, accepted) {
		t.Fatal("readback changed accepted bytes")
	}
	r, _ := http.NewRequest("GET", x.server.URL+"/v1/jobs/"+claim.Claim.JobID, nil)
	r.Header.Set("X-Client-Cert", hex.EncodeToString(fixture(t).certA.Raw))
	r.Header.Set("X-Forwarded-Client-Cert", fixture(t).certA.Subject.CommonName)
	res, err := x.b.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	if res.StatusCode != 403 {
		t.Fatal("header spoof authorized other leaf")
	}
	metadata := httpFraming(ch, manifest, nil)
	for _, tc := range []struct {
		name   string
		cfg    *tls.Config
		status int
	}{{"accepted_replay_without_sending_ciphertext", x.tlsA, 200}, {"nonowner_without_sending_ciphertext", x.tlsB, 403}} {
		t.Run(tc.name, func(t *testing.T) {
			c := rawHTTPClient(t, x, tc.cfg)
			rawFinalization(t, c, metadata, len(metadata)+len(body))
			code, b := rawResponse(t, c)
			if code != tc.status {
				t.Fatal("early response status", code)
			}
			if code == 200 && !bytes.Equal(b, accepted) {
				t.Fatal("replay changed record")
			}
		})
	}
	s := x.store.Snapshot()
	if s.Jobs != 1 || s.Accepted != 1 || s.Active != 0 || s.ChargedBytes != 64+StoreMetadataHeadroom {
		t.Fatal("retained quota changed")
	}
}
func TestHTTPNoCertificateAndForeignCertificate(t *testing.T) {
	x := newHTTPFixture(t, nil)
	f := fixture(t)
	tmpl := *f.certB
	tmpl.SerialNumber = big.NewInt(999)
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &f.keyB.PublicKey, f.keyB)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		certs []tls.Certificate
	}{{"missing", nil}, {"foreign", []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: f.keyB}}}} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := x.tlsA.Clone()
			cfg.Certificates = tc.certs
			c := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg, DisableKeepAlives: true}, Timeout: time.Second}
			res, e := c.Get(x.server.URL + "/healthz")
			if e == nil {
				res.Body.Close()
				t.Fatal("unverified client reached handler")
			}
		})
	}
	if x.store.Snapshot().Jobs != 0 {
		t.Fatal("TLS rejection admitted work")
	}
}

type countedHTTPBody struct {
	data *bytes.Reader
	read int
}

func (b *countedHTTPBody) Read(p []byte) (int, error) {
	n, e := b.data.Read(p)
	b.read += n
	return n, e
}
func (b *countedHTTPBody) Close() error { return nil }

type controlledHTTPWriter struct {
	*httptest.ResponseRecorder
	flushErr error
}

func (w *controlledHTTPWriter) EnableFullDuplex() error          { return nil }
func (w *controlledHTTPWriter) SetReadDeadline(time.Time) error  { return nil }
func (w *controlledHTTPWriter) SetWriteDeadline(time.Time) error { return nil }
func (w *controlledHTTPWriter) FlushError() error {
	if w.flushErr != nil {
		return w.flushErr
	}
	w.ResponseRecorder.Flush()
	return nil
}
func directHTTPRequest(t *testing.T, h *AuthorityHTTPHandler, path, kind string, raw []byte, edit func(*http.Request)) (*controlledHTTPWriter, *countedHTTPBody) {
	t.Helper()
	b := &countedHTTPBody{data: bytes.NewReader(raw)}
	r := httptest.NewRequest("POST", path, b)
	r.Body = b
	r.ContentLength = int64(len(raw))
	r.Header.Set("Content-Type", kind)
	r.TLS = &fixture(t).stateA
	if edit != nil {
		edit(r)
	}
	w := &controlledHTTPWriter{ResponseRecorder: httptest.NewRecorder()}
	h.ServeHTTP(w, r)
	return w, b
}
func TestHTTPRejectsTransportBeforeBodyOrReservation(t *testing.T) {
	x := newHTTPFixture(t, nil)
	raw, _ := json.Marshal(HTTPReserveRequest{1, storeRequest(1), "input.fastq"})
	cases := []struct {
		name string
		edit func(*http.Request)
	}{
		{"no_tls", func(r *http.Request) { r.TLS = nil }},
		{"http2", func(r *http.Request) { r.ProtoMajor = 2 }},
		{"query", func(r *http.Request) { r.URL.RawQuery = "owner=other" }},
		{"encoded_path", func(r *http.Request) { r.URL.RawPath = "/v1/%72eservations" }},
		{"chunked", func(r *http.Request) { r.TransferEncoding = []string{"chunked"}; r.ContentLength = -1 }},
		{"trailer", func(r *http.Request) { r.Trailer = http.Header{"X-Owner": []string{"forged"}} }},
		{"compression", func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }},
		{"expect", func(r *http.Request) { r.Header.Set("Expect", "100-continue") }},
		{"upgrade", func(r *http.Request) { r.Header.Set("Upgrade", "h2c") }},
		{"oversized_headers", func(r *http.Request) { r.Header.Set("X-Extra", strings.Repeat("x", HTTPHeaderLimit)) }},
		{"unknown_length", func(r *http.Request) { r.ContentLength = -1 }},
		{"oversized_body_declaration", func(r *http.Request) { r.ContentLength = HTTPReserveLimit + 1 }},
		{"wrong_content_type", func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }},
		{"duplicate_content_type", func(r *http.Request) { r.Header.Add("Content-Type", "application/json") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, b := directHTTPRequest(t, x.handler, "/v1/reservations", "application/json", raw, tc.edit)
			if w.Code < 400 || b.read != 0 || x.store.Snapshot().Jobs != 0 {
				t.Fatal("transport rejection read body/admitted work")
			}
		})
	}
	w, _ := directHTTPRequest(t, x.handler, "/v1/reservations", "application/json", raw, nil)
	if w.Code != 200 || x.store.Snapshot().Jobs != 1 {
		t.Fatal("valid server-request control did not pass")
	}
}
func TestHTTPStrictReserveAndMetadataBeforeCiphertext(t *testing.T) {
	x := newHTTPFixture(t, nil)
	for _, raw := range []string{`{"schema_version":1,"request_id":"00000000000000000000000000000001","original_name":"input.fastq","owner":"other"}`, `{"schema_version":1,"schema_version":1,"request_id":"00000000000000000000000000000001","original_name":"input.fastq"}`, `{"schema_version":null,"request_id":"00000000000000000000000000000001","original_name":"input.fastq"}`, `{"schema_version":1,"request_id":"00000000000000000000000000000001"}`} {
		w, _ := directHTTPRequest(t, x.handler, "/v1/reservations", "application/json", []byte(raw), nil)
		if w.Code != 400 || x.store.Snapshot().Jobs != 0 {
			t.Fatal("loose reserve JSON admitted")
		}
	}
	ch, _ := httpReserve(t, x, 1)
	body := bytes.Repeat([]byte("z"), 32)
	manifest := httpManifest(t, ch, body)
	for _, tc := range []struct {
		name  string
		ch, m []byte
		other bool
	}{{"other_leaf", ch, manifest, true}, {"challenge_changed", append(append([]byte{}, ch...), byte(' ')), manifest, false}, {"manifest_signature", ch, bytes.Replace(manifest, []byte(`"signature":"`), []byte(`"signature":"0`), 1), false}} {
		t.Run(tc.name, func(t *testing.T) {
			meta := httpFraming(tc.ch, tc.m, nil)
			raw := append(append([]byte{}, meta...), body...)
			w, b := directHTTPRequest(t, x.handler, "/v1/finalizations", "application/octet-stream", raw, func(r *http.Request) {
				if tc.other {
					r.TLS = &fixture(t).stateB
				}
			})
			if w.Code < 400 || b.read != len(meta) || x.store.Snapshot().Reading != 0 {
				t.Fatalf("unauthorized ciphertext gate: status=%d read=%d metadata=%d reading=%d", w.Code, b.read, len(meta), x.store.Snapshot().Reading)
			}
		})
	}
	for _, n := range []uint32{0, 4097, ^uint32(0)} {
		var raw bytes.Buffer
		binary.Write(&raw, binary.BigEndian, n)
		raw.Write(bytes.Repeat([]byte("x"), 32))
		w, b := directHTTPRequest(t, x.handler, "/v1/finalizations", "application/octet-stream", raw.Bytes(), nil)
		if w.Code != 400 || b.read != 4 {
			t.Fatal("oversized frame consumed payload")
		}
	}
}
func TestHTTPActualCiphertextBoundariesRetainFullCharge(t *testing.T) {
	for _, kind := range []string{"short", "extra", "changed"} {
		t.Run(kind, func(t *testing.T) {
			x := newHTTPFixture(t, nil)
			ch, _ := httpReserve(t, x, 1)
			body := bytes.Repeat([]byte("z"), 32)
			m := httpManifest(t, ch, body)
			sent := append([]byte{}, body...)
			if kind == "short" {
				sent = sent[:31]
			} else if kind == "extra" {
				sent = append(sent, 0)
			} else {
				sent[0] ^= 1
			}
			status, _ := httpCall(t, x.a, "POST", x.server.URL+"/v1/finalizations", "application/octet-stream", httpFraming(ch, m, sent))
			if status < 400 {
				t.Fatal("invalid ciphertext accepted")
			}
			s := x.store.Snapshot()
			if s.Rejected != 1 || s.Accepted != 0 || s.ChargedBytes != 64+StoreMetadataHeadroom {
				t.Fatal("failure refunded charge")
			}
		})
	}
}
func TestHTTPRealBodyDeadlineAndStopWait(t *testing.T) {
	t.Run("read_deadline", func(t *testing.T) {
		x := newHTTPFixture(t, func(_ *httptest.Server, h *AuthorityHTTPHandler) { h.readTimeout = 80 * time.Millisecond })
		ch, _ := httpReserve(t, x, 1)
		body := bytes.Repeat([]byte("z"), 32)
		m := httpManifest(t, ch, body)
		metadata := httpFraming(ch, m, nil)
		c := rawHTTPClient(t, x, x.tlsA)
		rawFinalization(t, c, metadata, len(metadata)+32)
		res, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err == nil {
			res.Body.Close()
			if res.StatusCode == 200 {
				t.Fatal("stalled body accepted")
			}
		}
		s := waitHTTPState(t, x.store, func(s StoreSnapshot) bool { return s.Rejected == 1 })
		if s.ChargedBytes != 64+StoreMetadataHeadroom || s.Accepted != 0 {
			t.Fatal("deadline lost reservation")
		}
	})
	t.Run("wait_tracks_reader", func(t *testing.T) {
		x := newHTTPFixture(t, nil)
		ch, _ := httpReserve(t, x, 1)
		body := bytes.Repeat([]byte("z"), 32)
		meta := httpFraming(ch, httpManifest(t, ch, body), nil)
		c := rawHTTPClient(t, x, x.tlsA)
		rawFinalization(t, c, meta, len(meta)+32)
		waitHTTPState(t, x.store, func(s StoreSnapshot) bool { return s.Reading == 1 })
		x.handler.StopAdmission()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		if x.handler.Wait(ctx) == nil {
			t.Fatal("wait overlooked active reader")
		}
		c.Close()
		ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
		defer cancel2()
		if x.handler.Wait(ctx2) != nil {
			t.Fatal("wait did not join reader")
		}
		s := x.store.Snapshot()
		if s.Rejected != 1 || s.Active != 0 || s.ChargedBytes != 64+StoreMetadataHeadroom {
			t.Fatal("cancel changed charge")
		}
	})
}

type rstWriteObservation struct {
	n   int
	err error
}
type rstGate struct {
	armed    atomic.Bool
	entered  chan struct{}
	release  chan struct{}
	observed chan rstWriteObservation
	once     sync.Once
}
type rstNetConn struct {
	net.Conn
	gate *rstGate
}

func (c *rstNetConn) Write(p []byte) (int, error) {
	if c.gate.armed.CompareAndSwap(true, false) {
		c.gate.once.Do(func() { close(c.gate.entered) })
		<-c.gate.release
		n, e := c.Conn.Write(p)
		c.gate.observed <- rstWriteObservation{n, e}
		return n, e
	}
	return c.Conn.Write(p)
}

type rstListener struct {
	net.Listener
	gate *rstGate
}

func (l rstListener) Accept() (net.Conn, error) {
	c, e := l.Listener.Accept()
	if e != nil {
		return nil, e
	}
	return &rstNetConn{c, l.gate}, nil
}
func TestHTTPRealRSTAfterSignedCommitLatchesDelivery(t *testing.T) {
	gate := &rstGate{entered: make(chan struct{}), release: make(chan struct{}), observed: make(chan rstWriteObservation, 1)}
	var release sync.Once
	defer release.Do(func() { close(gate.release) })
	x := newHTTPFixture(t, func(server *httptest.Server, h *AuthorityHTTPHandler) {
		server.Listener = rstListener{server.Listener, gate}
		server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/finalizations" {
				gate.armed.Store(true)
			}
			h.ServeHTTP(w, r)
		})
	})
	ch, _ := httpReserve(t, x, 1)
	body := bytes.Repeat([]byte("z"), 32)
	wire := httpFraming(ch, httpManifest(t, ch, body), body)
	c := rawHTTPClient(t, x, x.tlsA)
	rawFinalization(t, c, wire, len(wire))
	select {
	case <-gate.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("real write barrier not reached")
	}
	raw, err := os.ReadFile(filepath.Join(x.cfg.Directory, "ledger.json"))
	if err != nil {
		t.Fatal(err)
	}
	var ledger signedStoreLedger
	if decodeStoreJSON(raw, &ledger) != nil {
		t.Fatal("physical ledger invalid")
	}
	canonical, _ := json.Marshal(ledger.Ledger)
	sig, _ := hex.DecodeString(ledger.Signature)
	if !ed25519.Verify(x.cfg.Pin.PublicKey, canonical, sig) {
		t.Fatal("physical ledger signature invalid")
	}
	if len(ledger.Ledger.Records) != 1 || ledger.Ledger.Records[0].State != "accepted" || ledger.Ledger.Records[0].ChargeBytes != 64+StoreMetadataHeadroom {
		t.Fatal("response began before signed commit")
	}
	prior := ledger.Ledger.Records[0].AcceptanceJSON
	if _, err = VerifyAcceptance([]byte(prior), x.cfg.Pin, x.cfg.ExpectedScope); err != nil {
		t.Fatal(err)
	}
	tcp, ok := c.NetConn().(*net.TCPConn)
	if !ok {
		t.Fatal("own TCP transport missing")
	}
	if tcp.SetLinger(0) != nil || tcp.Close() != nil {
		t.Fatal("own TCP RST not applied")
	}
	release.Do(func() { close(gate.release) })
	select {
	case actual := <-gate.observed:
		if actual.err == nil {
			t.Fatal("RST did not cause actual delegated write failure")
		}
		t.Logf("Actual delegated TCP write failed (%T), bytes=%d", actual.err, actual.n)
	case <-time.After(2 * time.Second):
		t.Fatal("delegated write not joined")
	}
	state := waitHTTPState(t, x.store, func(s StoreSnapshot) bool { return s.Sticky })
	if state.Accepted != 1 || state.ChargedBytes != 64+StoreMetadataHeadroom || x.store.Healthy() {
		t.Fatal("HTTP failure lost charge or live latch")
	}
	after, err := os.ReadFile(filepath.Join(x.cfg.Directory, "ledger.json"))
	if err != nil || !bytes.Equal(after, raw) {
		t.Fatal("delivery failure changed committed history")
	}
	if err = x.store.Close(); err == nil {
		t.Fatal("sticky writer released lock")
	}
}
func TestHTTPAdmissionGateAndCancellationBeforeDelivery(t *testing.T) {
	x := newHTTPFixture(t, nil)
	clients := make([]*tls.Conn, 0, 4)
	for i := 0; i < 4; i++ {
		c := rawHTTPClient(t, x, x.tlsA)
		clients = append(clients, c)
		if _, err := io.WriteString(c, "POST /v1/reservations HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(time.Second)
	for {
		x.handler.mu.Lock()
		active := x.handler.active
		x.handler.mu.Unlock()
		if active == 4 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("four real request readers not active")
		}
		time.Sleep(time.Millisecond)
	}
	status, _ := httpCall(t, x.a, "GET", x.server.URL+"/healthz", "", nil)
	if status != 503 || x.store.Snapshot().Jobs != 0 {
		t.Fatal("request limit failed before reservation")
	}
	x.handler.StopAdmission()
	for _, c := range clients {
		c.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if x.handler.Wait(ctx) != nil {
		t.Fatal("stopped requests not joined")
	}
	status, _ = httpCall(t, x.a, "GET", x.server.URL+"/healthz", "", nil)
	if status != 503 {
		t.Fatal("closed gate admitted new request")
	}
	canceled, stop := context.WithCancel(context.Background())
	stop()
	writes := 0
	if x.store.deliverHTTP(canceled, func() error { writes++; return errors.New("unreachable") }) == nil || writes != 0 || !x.store.Healthy() {
		t.Fatal("canceled delivery called writer or latched before writing")
	}
	w := &controlledHTTPWriter{ResponseRecorder: httptest.NewRecorder()}
	r := httptest.NewRequest("GET", "/", nil)
	x.handler.problem(w, r, 400, "private_internal_canary")
	if strings.Contains(w.Body.String(), "private_internal_canary") || !strings.Contains(w.Body.String(), "ownership_http_request_invalid") {
		t.Fatal("unknown internal error reflected")
	}
}
