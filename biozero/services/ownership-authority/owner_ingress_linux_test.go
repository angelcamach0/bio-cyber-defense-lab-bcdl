//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package ownership

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"
)

type ingressTestFixture struct {
	store      *OwnerIngressStore
	cfg        OwnerIngressConfig
	handler    *OwnerIngressHandler
	server     *httptest.Server
	a, b       *http.Client
	tlsA, tlsB *tls.Config
}

func ingressTestBundle(t *testing.T, other bool) AcceptedBundle {
	t.Helper()
	f := fixture(t)
	leaf, key := f.certA, f.keyA
	if other {
		leaf, key = f.certB, f.keyB
	}
	ch := payloadChallenge(t, other)
	p, err := EncryptForChallenge(ch, f.pin, leaf, key, &payloadWorkerKey(t).PublicKey, []byte("synthetic ingress"), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	v := payloadAcceptance(t, ch, p.Ciphertext, p.KeyEnvelope, other)
	return AcceptedBundle{bytes.Clone(v.canonical), p.KeyEnvelope, p.Ciphertext}
}

func ingressTestConfig(t *testing.T) OwnerIngressConfig {
	t.Helper()
	f := fixture(t)
	p := DefaultOwnerIngressPolicy()
	p.MaxBodyBytes = 64
	return OwnerIngressConfig{Directory: filepath.Join(t.TempDir(), "ingress"), Namespace: "ingress-test", Pin: f.pin,
		Scope: AcceptanceScope{StoreID: "11111111111111111111111111111111", PolicySHA256: "2222222222222222222222222222222222222222222222222222222222222222"}, Policy: p}
}

func ingressTestStore(t *testing.T, cfg OwnerIngressConfig, create bool) *OwnerIngressStore {
	t.Helper()
	var s *OwnerIngressStore
	var err error
	if create {
		s, err = CreateOwnerIngress(cfg)
	} else {
		s, err = OpenOwnerIngress(cfg)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if !s.sticky && !s.closed {
			if e := s.Close(); e != nil {
				t.Error(e)
			}
		}
	})
	return s
}

func ingressTestHTTP(t *testing.T, s *OwnerIngressStore, setup func(*httptest.Server, *OwnerIngressHandler)) *ingressTestFixture {
	t.Helper()
	f := fixture(t)
	h, err := NewOwnerIngressHandler(s)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	chain := f.stateA.VerifiedChains[0]
	pool.AddCert(chain[len(chain)-1])
	pair := tls.Certificate{Certificate: [][]byte{f.certA.Raw}, PrivateKey: f.keyA}
	server := httptest.NewUnstartedServer(h)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.Config.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){}
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, Certificates: []tls.Certificate{pair}, NextProtos: []string{"http/1.1"}}
	if setup != nil {
		setup(server, h)
	}
	server.StartTLS()
	a := &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, NextProtos: []string{"http/1.1"}}
	b := a.Clone()
	b.Certificates = []tls.Certificate{{Certificate: [][]byte{f.certB.Raw}, PrivateKey: f.keyB}}
	client := func(c *tls.Config) *http.Client {
		return &http.Client{Transport: &http.Transport{TLSClientConfig: c, DisableKeepAlives: true}, Timeout: 3 * time.Second}
	}
	t.Cleanup(func() {
		h.StopAdmission()
		server.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if h.Wait(ctx) != nil {
			t.Error("ingress handlers not joined")
		}
	})
	return &ingressTestFixture{s, s.config, h, server, client(a), client(b), a, b}
}

func ingressFrame(b AcceptedBundle, body bool) []byte {
	raw := make([]byte, 4)
	binary.BigEndian.PutUint32(raw, uint32(len(b.Acceptance)))
	raw = append(raw, b.Acceptance...)
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(b.KeyEnvelope)))
	raw = append(raw, n[:]...)
	raw = append(raw, b.KeyEnvelope...)
	if body {
		raw = append(raw, b.Ciphertext...)
	}
	return raw
}

type ingressReader struct {
	reader io.Reader
	before func()
	calls  int
}

func (r *ingressReader) Read(p []byte) (int, error) {
	r.calls++
	if r.before != nil {
		r.before()
		r.before = nil
	}
	return r.reader.Read(p)
}
func ingressAccept(t *testing.T, s *OwnerIngressStore, b AcceptedBundle) OwnerUploadReceipt {
	t.Helper()
	r, e := s.Accept(context.Background(), &fixture(t).stateA, b.Acceptance, b.KeyEnvelope, bytes.NewReader(b.Ciphertext), int64(len(b.Ciphertext)))
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func ingressFiles(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(path string, e os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if e.IsDir() {
			return nil
		}
		st, e2 := os.Lstat(path)
		if e2 != nil {
			return e2
		}
		name, _ := filepath.Rel(root, path)
		if st.Mode().IsRegular() && st.Size() <= StoreLedgerLimit {
			out[name] = digest(fileBytes(t, path))
		} else {
			out[name] = st.Mode().String()
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestOwnerIngressDeliveredSignedJobAndFullRetention(t *testing.T) {
	cfg := ingressTestConfig(t)
	s := ingressTestStore(t, cfg, true)
	b := ingressTestBundle(t, false)
	reader := &ingressReader{reader: bytes.NewReader(b.Ciphertext), before: func() {
		var l ownerIngressLedger
		if decodeStoreJSON(fileBytes(t, filepath.Join(cfg.Directory, "ledger.json")), &l) != nil || len(l.Records) != 1 || l.Records[0].State != "reading" || l.Records[0].ChargeBytes != cfg.Policy.MaxBodyBytes+StoreMetadataHeadroom {
			t.Error("ciphertext read preceded durable full reservation")
		}
		if _, e := os.Lstat(filepath.Join(cfg.Directory, "transaction.pending")); !os.IsNotExist(e) {
			t.Error("body read with pending ledger transaction")
		}
	}}
	r, e := s.Accept(context.Background(), &fixture(t).stateA, b.Acceptance, b.KeyEnvelope, reader, int64(len(b.Ciphertext)))
	if e != nil || reader.calls == 0 {
		t.Fatal("delivery failed", e)
	}
	v, e := VerifyAcceptance(b.Acceptance, cfg.Pin, cfg.Scope)
	if e != nil {
		t.Fatal(e)
	}
	if r.JobID != v.Binding().JobID || r.AcceptanceSHA256 != v.SHA256() || r.State != "delivered" {
		t.Fatal("receipt changed authoritative job")
	}
	if !bytes.Equal(fileBytes(t, filepath.Join(cfg.Directory, "uploads", r.JobID+"_"+v.Binding().OriginalName)), b.Ciphertext) || !bytes.Equal(fileBytes(t, filepath.Join(cfg.Directory, "acceptances", r.JobID+".json")), b.Acceptance) {
		t.Fatal("published bytes changed")
	}
	var job map[string]json.RawMessage
	if json.Unmarshal(fileBytes(t, filepath.Join(cfg.Directory, "jobs", r.JobID+".json")), &job) != nil {
		t.Fatal("job cache invalid")
	}
	var algorithm string
	json.Unmarshal(job["enc_alg"], &algorithm)
	var acceptedSHA string
	json.Unmarshal(job["ownership_acceptance_sha256"], &acceptedSHA)
	if algorithm != EncryptionAlgorithm || acceptedSHA != r.AcceptanceSHA256 || string(job["ownership_version"]) != "1" {
		t.Fatal("job cache lost owner-v1 fence")
	}
	promise := cfg.Policy.MaxBodyBytes + StoreMetadataHeadroom
	if st := s.Snapshot(); st.Jobs != 1 || st.Delivered != 1 || st.ChargedBytes != promise {
		t.Fatal("delivery reduced full charge")
	}
	before := ingressFiles(t, cfg.Directory)
	never := &ingressReader{reader: bytes.NewReader([]byte("must not read"))}
	// Equivalent whitespace is the same signed canonical acceptance, not new work.
	var formatted bytes.Buffer
	if json.Indent(&formatted, b.Acceptance, "", " ") != nil {
		t.Fatal("format fixture")
	}
	again, e := s.Accept(context.Background(), &fixture(t).stateA, formatted.Bytes(), b.KeyEnvelope, never, int64(len(b.Ciphertext)))
	if e != nil || again != r || never.calls != 0 {
		t.Fatal("delivered duplicate read or allocated", e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	cold := ingressTestStore(t, cfg, false)
	got, e := cold.Get(context.Background(), &fixture(t).stateA, r.JobID)
	if e != nil || got != r || !reflect.DeepEqual(before, ingressFiles(t, cfg.Directory)) || cold.Snapshot().ChargedBytes != promise {
		t.Fatal("cold readback changed history", e)
	}
}

func TestOwnerIngressAuthenticationAndEnvelopeBeforeReader(t *testing.T) {
	for _, name := range []string{"other_leaf_same_cn_serial", "missing_tls", "incoherent_tls", "tampered_acceptance", "wrong_scope", "wrong_pin", "wrong_envelope", "wrong_size", "nil_reader", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			cfg := ingressTestConfig(t)
			if name == "wrong_scope" {
				cfg.Scope.StoreID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			}
			if name == "wrong_pin" {
				cfg.Pin.ExecutionProfileSHA256 = digest([]byte("different"))
			}
			s := ingressTestStore(t, cfg, true)
			b := ingressTestBundle(t, false)
			state := &fixture(t).stateA
			copyState := *state
			ctx := context.Background()
			size := int64(len(b.Ciphertext))
			var body io.Reader
			r := &ingressReader{reader: bytes.NewReader(b.Ciphertext)}
			body = r
			switch name {
			case "other_leaf_same_cn_serial":
				state = &fixture(t).stateB
			case "missing_tls":
				state = nil
			case "incoherent_tls":
				copyState.VerifiedChains = nil
				state = &copyState
			case "tampered_acceptance":
				b.Acceptance[len(b.Acceptance)-5] ^= 1
			case "wrong_envelope":
				b.KeyEnvelope[0] ^= 1
			case "wrong_size":
				size++
			case "nil_reader":
				body = nil
			case "cancelled":
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			}
			if _, e := s.Accept(ctx, state, b.Acceptance, b.KeyEnvelope, body, size); e == nil || r.calls != 0 || s.Snapshot().Jobs != 0 {
				t.Fatal("unauthenticated metadata reached body/reservation", e)
			}
		})
	}
}

func TestOwnerIngressConcurrentFinalSlotAndActivePromise(t *testing.T) {
	t.Run("one_final_slot", func(t *testing.T) {
		cfg := ingressTestConfig(t)
		cfg.Policy.MaxJobs = 1
		cfg.Policy.MaxPrincipalJobs = 1
		cfg.Policy.MaxActive = 1
		cfg.Policy.MaxPrincipalActive = 1
		s := ingressTestStore(t, cfg, true)
		bundles := []AcceptedBundle{ingressTestBundle(t, false), ingressTestBundle(t, false)}
		start := make(chan struct{})
		results := make(chan error, 2)
		readers := []*ingressReader{{reader: bytes.NewReader(bundles[0].Ciphertext)}, {reader: bytes.NewReader(bundles[1].Ciphertext)}}
		for i := range bundles {
			go func(i int) {
				<-start
				b := bundles[i]
				_, e := s.Accept(context.Background(), &fixture(t).stateA, b.Acceptance, b.KeyEnvelope, readers[i], int64(len(b.Ciphertext)))
				results <- e
			}(i)
		}
		close(start)
		passes := 0
		for range bundles {
			if e := <-results; e == nil {
				passes++
			} else if e.Error() != "ownership_ingress_quota" {
				t.Fatal(e)
			}
		}
		if passes != 1 || (readers[0].calls == 0) == (readers[1].calls == 0) || s.Snapshot().ChargedBytes != cfg.Policy.MaxBodyBytes+StoreMetadataHeadroom {
			t.Fatal("last slot double admitted")
		}
	})
	t.Run("active_before_first_read", func(t *testing.T) {
		cfg := ingressTestConfig(t)
		s := ingressTestStore(t, cfg, true)
		a, b := ingressTestBundle(t, false), ingressTestBundle(t, false)
		entered, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		defer once.Do(func() { close(release) })
		r := &ingressReader{reader: bytes.NewReader(a.Ciphertext), before: func() { close(entered); <-release }}
		done := make(chan error, 1)
		go func() {
			_, e := s.Accept(context.Background(), &fixture(t).stateA, a.Acceptance, a.KeyEnvelope, r, int64(len(a.Ciphertext)))
			done <- e
		}()
		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			t.Fatal("reader not reached")
		}
		never := &ingressReader{reader: bytes.NewReader(b.Ciphertext)}
		if _, e := s.Accept(context.Background(), &fixture(t).stateA, b.Acceptance, b.KeyEnvelope, never, int64(len(b.Ciphertext))); e == nil || e.Error() != "ownership_ingress_quota" || never.calls != 0 {
			t.Fatal("active promise not enforced", e)
		}
		if s.Close() == nil {
			t.Fatal("closed while reader active")
		}
		once.Do(func() { close(release) })
		if e := <-done; e != nil {
			t.Fatal(e)
		}
	})
}

type ingressBrokenReader struct{ kind string }

func (r ingressBrokenReader) Read(p []byte) (int, error) {
	switch r.kind {
	case "negative":
		return -1, nil
	case "oversized_count":
		return len(p) + 1, nil
	case "nonprogress":
		return 0, nil
	default:
		return 0, errors.New("private_reader_error")
	}
}
func TestOwnerIngressRejectedBodyKeepsFullCharge(t *testing.T) {
	for _, name := range []string{"short", "extra", "changed", "nonprogress", "reader_error", "negative", "oversized_count"} {
		t.Run(name, func(t *testing.T) {
			cfg := ingressTestConfig(t)
			s := ingressTestStore(t, cfg, true)
			b := ingressTestBundle(t, false)
			body := bytes.Clone(b.Ciphertext)
			var input io.Reader
			switch name {
			case "short":
				body = body[:len(body)-1]
				input = bytes.NewReader(body)
			case "extra":
				input = bytes.NewReader(append(body, 1))
			case "changed":
				body[0] ^= 1
				input = bytes.NewReader(body)
			default:
				input = ingressBrokenReader{name}
			}
			if _, e := s.Accept(context.Background(), &fixture(t).stateA, b.Acceptance, b.KeyEnvelope, input, int64(len(b.Ciphertext))); e == nil {
				t.Fatal("bad body delivered")
			}
			st := s.Snapshot()
			if st.Jobs != 1 || st.Rejected != 1 || st.ChargedBytes != cfg.Policy.MaxBodyBytes+StoreMetadataHeadroom || !s.Healthy() {
				t.Fatal("rejection refunded or became unknown")
			}
			before := ingressFiles(t, cfg.Directory)
			never := &ingressReader{reader: bytes.NewReader(b.Ciphertext)}
			if _, e := s.Accept(context.Background(), &fixture(t).stateA, b.Acceptance, b.KeyEnvelope, never, int64(len(b.Ciphertext))); e == nil || never.calls != 0 {
				t.Fatal("rejected job retried")
			}
			if e := s.Close(); e != nil {
				t.Fatal(e)
			}
			cold := ingressTestStore(t, cfg, false)
			if cold.Snapshot().Rejected != 1 || cold.Snapshot().ChargedBytes != st.ChargedBytes || !reflect.DeepEqual(before, ingressFiles(t, cfg.Directory)) {
				t.Fatal("cold rejection lost history")
			}
		})
	}
}

type ingressObservedContext struct {
	context.Context
	once    sync.Once
	checked chan struct{}
}

func (c *ingressObservedContext) Err() error {
	c.once.Do(func() { close(c.checked) })
	return c.Context.Err()
}
func TestOwnerIngressCancelledWhileWaitingForAdmission(t *testing.T) {
	cfg := ingressTestConfig(t)
	s := ingressTestStore(t, cfg, true)
	b := ingressTestBundle(t, false)
	base, cancel := context.WithCancel(context.Background())
	ctx := &ingressObservedContext{Context: base, checked: make(chan struct{})}
	before := ingressFiles(t, cfg.Directory)
	s.mu.Lock()
	done := make(chan error, 1)
	r := &ingressReader{reader: bytes.NewReader(b.Ciphertext)}
	go func() {
		_, e := s.Accept(ctx, &fixture(t).stateA, b.Acceptance, b.KeyEnvelope, r, int64(len(b.Ciphertext)))
		done <- e
	}()
	<-ctx.checked
	cancel()
	s.mu.Unlock()
	if e := <-done; e == nil || r.calls != 0 || s.Snapshot().Jobs != 0 || !reflect.DeepEqual(before, ingressFiles(t, cfg.Directory)) {
		t.Fatal("canceled queued request acquired a promise", e)
	}
}

func TestOwnerIngressAmbiguousPublicationNeverACKOrUnlock(t *testing.T) {
	for _, point := range []string{"transaction.pending_sync", "ledger.next_sync", "ledger_rename", "intent_unlink", "publish_file_sync", "close"} {
		t.Run(point, func(t *testing.T) {
			cfg := ingressTestConfig(t)
			s := ingressTestStore(t, cfg, true)
			b := ingressTestBundle(t, false)
			if point == "close" {
				ingressAccept(t, s, b)
			}
			s.fault = func(name string) error {
				if name == point {
					return errors.New("injected_storage_failure")
				}
				return nil
			}
			var e error
			if point == "close" {
				e = s.Close()
			} else {
				_, e = s.Accept(context.Background(), &fixture(t).stateA, b.Acceptance, b.KeyEnvelope, bytes.NewReader(b.Ciphertext), int64(len(b.Ciphertext)))
			}
			if e == nil || !s.Snapshot().Sticky || s.Healthy() || s.Close() == nil {
				t.Fatal("ambiguous IO returned success or released custody")
			}
			before := ingressFiles(t, cfg.Directory)
			if _, e = OpenOwnerIngress(cfg); e == nil || e.Error() != "ownership_ingress_locked" {
				t.Fatal("live sticky writer lost lock", e)
			}
			if !reflect.DeepEqual(before, ingressFiles(t, cfg.Directory)) {
				t.Fatal("unknown artifacts cleaned")
			}
		})
	}
}

func TestOwnerIngressConcurrentJobCacheNeverOverwritten(t *testing.T) {
	cfg := ingressTestConfig(t)
	s := ingressTestStore(t, cfg, true)
	b := ingressTestBundle(t, false)
	v, err := VerifyAcceptance(b.Acceptance, cfg.Pin, cfg.Scope)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cfg.Directory, "jobs", v.Binding().JobID+".json")
	marker := []byte("preexisting private cache fixture")
	r := &ingressReader{reader: bytes.NewReader(b.Ciphertext), before: func() {
		f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			t.Error(e)
			return
		}
		if _, e = f.Write(marker); e != nil {
			t.Error(e)
		}
		if f.Sync() != nil || f.Close() != nil {
			t.Error("cache fixture sync failed")
		}
	}}
	if _, err = s.Accept(context.Background(), &fixture(t).stateA, b.Acceptance, b.KeyEnvelope, r, int64(len(b.Ciphertext))); err == nil || !s.Snapshot().Sticky {
		t.Fatal("existing job cache was adopted or overwritten")
	}
	if !bytes.Equal(fileBytes(t, path), marker) || s.Snapshot().ChargedBytes != cfg.Policy.MaxBodyBytes+StoreMetadataHeadroom {
		t.Fatal("exclusive publication changed existing bytes or promise")
	}
}

func TestOwnerIngressMissingCertificateFailsRealTLS(t *testing.T) {
	cfg := ingressTestConfig(t)
	s := ingressTestStore(t, cfg, true)
	x := ingressTestHTTP(t, s, nil)
	clientTLS := x.tlsA.Clone()
	clientTLS.Certificates = nil
	transport := &http.Transport{TLSClientConfig: clientTLS, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	response, err := client.Get(x.server.URL + "/healthz")
	if err == nil {
		response.Body.Close()
		t.Fatal("client without certificate reached HTTP")
	}
	if s.Snapshot().Jobs != 0 {
		t.Fatal("unauthenticated TLS admitted transport work")
	}
}

func ingressRawTLS(t *testing.T, x *ingressTestFixture, other bool) *tls.Conn {
	t.Helper()
	cfg := x.tlsA
	if other {
		cfg = x.tlsB
	}
	c, e := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", x.server.Listener.Addr().String(), cfg)
	if e != nil {
		t.Fatal(e)
	}
	c.SetDeadline(time.Now().Add(3 * time.Second))
	t.Cleanup(func() { c.Close() })
	return c
}
func ingressRawPost(t *testing.T, c *tls.Conn, metadata []byte, bodyBytes int) {
	t.Helper()
	header := "POST /v1/uploads HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/octet-stream\r\nContent-Length: " + strconv.Itoa(bodyBytes) + "\r\n\r\n"
	if _, e := io.WriteString(c, header); e != nil {
		t.Fatal(e)
	}
	if _, e := c.Write(metadata); e != nil {
		t.Fatal(e)
	}
}
func ingressRawResponse(t *testing.T, c *tls.Conn) (int, []byte) {
	t.Helper()
	r, e := http.ReadResponse(bufio.NewReader(c), nil)
	if e != nil {
		t.Fatal("expected early response without ciphertext", e)
	}
	b, e := io.ReadAll(io.LimitReader(r.Body, 4097))
	r.Body.Close()
	if e != nil {
		t.Fatal(e)
	}
	return r.StatusCode, b
}

func TestOwnerIngressRealMTLSMetadataAndDuplicateWithoutBody(t *testing.T) {
	cfg := ingressTestConfig(t)
	s := ingressTestStore(t, cfg, true)
	x := ingressTestHTTP(t, s, nil)
	bundle := ingressTestBundle(t, false)
	meta := ingressFrame(bundle, false)
	full := ingressFrame(bundle, true)
	c := ingressRawTLS(t, x, true)
	ingressRawPost(t, c, meta, len(full))
	code, _ := ingressRawResponse(t, c)
	if code != 403 || s.Snapshot().Jobs != 0 {
		t.Fatal("B read/admitted A body")
	}
	status, body := httpCall(t, x.a, "POST", x.server.URL+"/v1/uploads", "application/octet-stream", full)
	var receipt OwnerUploadReceipt
	if status != 200 || json.Unmarshal(body, &receipt) != nil {
		t.Fatal("A delivery failed", status)
	}
	before := ingressFiles(t, cfg.Directory)
	c = ingressRawTLS(t, x, false)
	ingressRawPost(t, c, meta, len(full))
	code, body = ingressRawResponse(t, c)
	var duplicate OwnerUploadReceipt
	if code != 200 || json.Unmarshal(body, &duplicate) != nil || duplicate != receipt {
		t.Fatal("duplicate waited for ciphertext")
	}
	status, _ = httpCall(t, x.b, "GET", x.server.URL+"/v1/uploads/"+receipt.JobID, "", nil)
	if status != 403 {
		t.Fatal("B queried A receipt")
	}
	// Owner denial must precede touching unsafe private output state.
	path := filepath.Join(cfg.Directory, "acceptances", receipt.JobID+".json")
	if os.Chmod(path, 0644) != nil {
		t.Fatal("permission fixture")
	}
	status, _ = httpCall(t, x.b, "GET", x.server.URL+"/v1/uploads/"+receipt.JobID, "", nil)
	if status != 403 {
		t.Fatal("B touched unsafe private sidecar")
	}
	if os.Chmod(path, 0600) != nil {
		t.Fatal("restore own fixture permissions")
	}
	if !reflect.DeepEqual(before, ingressFiles(t, cfg.Directory)) {
		t.Fatal("duplicate altered retained bytes")
	}
}

func TestOwnerIngressRejectsMalformedTransportWithoutAdmission(t *testing.T) {
	for _, name := range []string{"no_tls", "chunked", "unknown_length", "oversize", "compression", "trailer", "query", "encoded_path", "upgrade", "expect", "acceptance_frame_oversize", "envelope_frame_oversize"} {
		t.Run(name, func(t *testing.T) {
			cfg := ingressTestConfig(t)
			s := ingressTestStore(t, cfg, true)
			h, e := NewOwnerIngressHandler(s)
			if e != nil {
				t.Fatal(e)
			}
			defer h.StopAdmission()
			b := ingressTestBundle(t, false)
			wire := ingressFrame(b, true)
			if name == "acceptance_frame_oversize" {
				binary.BigEndian.PutUint32(wire[:4], MaxAcceptanceBytes+1)
			}
			if name == "envelope_frame_oversize" {
				binary.BigEndian.PutUint32(wire[4+len(b.Acceptance):8+len(b.Acceptance)], 513)
			}
			body := &countedHTTPBody{data: bytes.NewReader(wire)}
			r := httptest.NewRequest("POST", "/v1/uploads", body)
			r.TLS = &fixture(t).stateA
			r.ContentLength = int64(len(wire))
			r.Header.Set("Content-Type", "application/octet-stream")
			switch name {
			case "no_tls":
				r.TLS = nil
			case "chunked":
				r.TransferEncoding = []string{"chunked"}
			case "unknown_length":
				r.ContentLength = -1
			case "oversize":
				r.ContentLength = MaxCiphertextBytes + OwnerIngressFrameLimit + 1
			case "compression":
				r.Header.Set("Content-Encoding", "gzip")
			case "trailer":
				r.Header.Set("Trailer", "X-Extra")
			case "query":
				r.URL.RawQuery = "x=1"
			case "encoded_path":
				r.URL.RawPath = "/v1/%75ploads"
			case "upgrade":
				r.Header.Set("Upgrade", "websocket")
			case "expect":
				r.Header.Set("Expect", "100-continue")
			}
			w := &controlledHTTPWriter{ResponseRecorder: httptest.NewRecorder()}
			h.ServeHTTP(w, r)
			if w.Code == 200 || s.Snapshot().Jobs != 0 {
				t.Fatal("malformed transport admitted")
			}
			if name != "acceptance_frame_oversize" && name != "envelope_frame_oversize" && body.read != 0 {
				t.Fatal("invalid transport read application body")
			}
		})
	}
}

func TestOwnerIngressRealReadDeadlineAndStopWait(t *testing.T) {
	t.Run("read_deadline", func(t *testing.T) {
		cfg := ingressTestConfig(t)
		s := ingressTestStore(t, cfg, true)
		x := ingressTestHTTP(t, s, func(_ *httptest.Server, h *OwnerIngressHandler) { h.readTimeout = 100 * time.Millisecond })
		b := ingressTestBundle(t, false)
		c := ingressRawTLS(t, x, false)
		meta := ingressFrame(b, false)
		ingressRawPost(t, c, meta, len(meta)+len(b.Ciphertext))
		response, e := http.ReadResponse(bufio.NewReader(c), nil)
		if e == nil {
			response.Body.Close()
			if response.StatusCode == 200 {
				t.Fatal("stalled body delivered")
			}
		}
		deadline := time.Now().Add(time.Second)
		for s.Snapshot().Rejected != 1 {
			if time.Now().After(deadline) {
				t.Fatal("deadline rejection not committed")
			}
			time.Sleep(time.Millisecond)
		}
		if s.Snapshot().ChargedBytes != cfg.Policy.MaxBodyBytes+StoreMetadataHeadroom {
			t.Fatal("timed out body refunded")
		}
	})
	t.Run("wait_tracks_reader", func(t *testing.T) {
		cfg := ingressTestConfig(t)
		s := ingressTestStore(t, cfg, true)
		x := ingressTestHTTP(t, s, nil)
		b := ingressTestBundle(t, false)
		c := ingressRawTLS(t, x, false)
		meta := ingressFrame(b, false)
		ingressRawPost(t, c, meta, len(meta)+len(b.Ciphertext))
		deadline := time.Now().Add(time.Second)
		for s.Snapshot().Reading != 1 {
			if time.Now().After(deadline) {
				t.Fatal("active reader not admitted")
			}
			time.Sleep(time.Millisecond)
		}
		x.handler.StopAdmission()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		if x.handler.Wait(ctx) == nil {
			t.Fatal("wait overlooked actual reader")
		}
		c.Close()
		ctx2, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		if x.handler.Wait(ctx2) != nil {
			t.Fatal("closed reader not joined")
		}
		status, _ := httpCall(t, x.a, "GET", x.server.URL+"/healthz", "", nil)
		if status != 503 {
			t.Fatal("stop reopened admission")
		}
		if s.Snapshot().ChargedBytes != cfg.Policy.MaxBodyBytes+StoreMetadataHeadroom {
			t.Fatal("reader close refunded")
		}
	})
}

type ingressChildConfig struct {
	Config                                    OwnerIngressConfig
	Leaf, Key, CA                             []byte
	Mode, Listening, Ready, Release, Observed string
	MetadataBytes                             int
}

func ingressEvidence(path string, v any) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	n, e := f.Write(b)
	if e == nil && n != len(b) {
		e = io.ErrShortWrite
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	d, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}

type ingressBlockedBody struct {
	io.ReadCloser
	once              sync.Once
	ready             string
	metadataRemaining int
}

func (b *ingressBlockedBody) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	// The HTTP handler must first consume the two length prefixes, acceptance
	// and envelope. Only the Store's first ciphertext read is the crash barrier;
	// blocking the first body read would precede durable quota reservation.
	if b.metadataRemaining > 0 {
		if len(p) > b.metadataRemaining {
			p = p[:b.metadataRemaining]
		}
		n, err := b.ReadCloser.Read(p)
		b.metadataRemaining -= n
		return n, err
	}
	var e error
	b.once.Do(func() { e = ingressEvidence(b.ready, map[string]bool{"first_ciphertext_reader": true}) })
	if e != nil {
		return 0, e
	}
	select {}
}

func TestOwnerIngressProcessHelper(t *testing.T) {
	path := os.Getenv("BIOZERO_OWNER_INGRESS_CHILD")
	if path == "" {
		t.Skip("owned ingress subprocess helper")
	}
	var c ingressChildConfig
	if json.Unmarshal(fileBytes(t, path), &c) != nil {
		t.Fatal("child config invalid")
	}
	s, e := CreateOwnerIngress(c.Config)
	if e != nil {
		t.Fatal(e)
	}
	h, e := NewOwnerIngressHandler(s)
	if e != nil {
		t.Fatal(e)
	}
	key, e := x509.ParsePKCS1PrivateKey(c.Key)
	if e != nil {
		t.Fatal(e)
	}
	ca, e := x509.ParseCertificate(c.CA)
	if e != nil {
		t.Fatal(e)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	server := httptest.NewUnstartedServer(h)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.Config.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){}
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, Certificates: []tls.Certificate{{Certificate: [][]byte{c.Leaf}, PrivateKey: key}}, NextProtos: []string{"http/1.1"}}
	var gate *rstGate
	if c.Mode == "reading" {
		if c.MetadataBytes <= 8 || c.MetadataBytes > 8+MaxAcceptanceBytes+512 {
			t.Fatal("child metadata length invalid")
		}
		server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/uploads" {
				r.Body = &ingressBlockedBody{ReadCloser: r.Body, ready: c.Ready, metadataRemaining: c.MetadataBytes}
			}
			h.ServeHTTP(w, r)
		})
	} else {
		gate = &rstGate{entered: make(chan struct{}), release: make(chan struct{}), observed: make(chan rstWriteObservation, 1)}
		server.Listener = rstListener{server.Listener, gate}
		server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/uploads" {
				gate.armed.Store(true)
			}
			h.ServeHTTP(w, r)
		})
	}
	server.StartTLS()
	if e = ingressEvidence(c.Listening, map[string]string{"address": server.Listener.Addr().String()}); e != nil {
		t.Fatal(e)
	}
	if c.Mode == "rst" {
		select {
		case <-gate.entered:
		case <-time.After(10 * time.Second):
			t.Fatal("response write barrier missing")
		}
		if e = ingressEvidence(c.Ready, map[string]string{"ledger_sha256": digest(fileBytes(t, filepath.Join(c.Config.Directory, "ledger.json")))}); e != nil {
			t.Fatal(e)
		}
		deadline := time.Now().Add(10 * time.Second)
		for {
			if _, e = os.Stat(c.Release); e == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("RST release missing")
			}
			time.Sleep(5 * time.Millisecond)
		}
		close(gate.release)
		select {
		case actual := <-gate.observed:
			if actual.err == nil {
				t.Fatal("no delegated real TCP failure")
			}
			t.Logf("Actual ingress delegated TCP write error %T bytes=%d", actual.err, actual.n)
		case <-time.After(3 * time.Second):
			t.Fatal("delegated TCP write not joined")
		}
		deadline = time.Now().Add(2 * time.Second)
		for !s.Snapshot().Sticky {
			if time.Now().After(deadline) {
				t.Fatal("write failure did not latch")
			}
			time.Sleep(time.Millisecond)
		}
		if s.Close() == nil || s.Close() == nil {
			t.Fatal("sticky ingress close released custody")
		}
		if e = ingressEvidence(c.Observed, map[string]any{"write_error": true, "sticky": true, "snapshot": s.Snapshot()}); e != nil {
			t.Fatal(e)
		}
	}
	for {
		time.Sleep(time.Hour)
	}
}

func TestOwnerIngressOwnedSIGKILLReadingAndRealRSTRecovery(t *testing.T) {
	for _, mode := range []string{"reading", "rst"} {
		t.Run(mode, func(t *testing.T) {
			cfg := ingressTestConfig(t)
			f := fixture(t)
			parent := filepath.Dir(cfg.Directory)
			b := ingressTestBundle(t, false)
			chain := f.stateA.VerifiedChains[0]
			c := ingressChildConfig{Config: cfg, Leaf: f.certA.Raw, Key: x509.MarshalPKCS1PrivateKey(f.keyA), CA: chain[len(chain)-1].Raw, Mode: mode, Listening: filepath.Join(parent, "listening.json"), Ready: filepath.Join(parent, "ready.json"), Release: filepath.Join(parent, "release"), Observed: filepath.Join(parent, "observed.json")}
			c.MetadataBytes = len(ingressFrame(b, false))
			config := filepath.Join(parent, "child.json")
			if e := ingressEvidence(config, c); e != nil {
				t.Fatal(e)
			}
			out, e := os.OpenFile(filepath.Join(parent, "child.log"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if e != nil {
				t.Fatal(e)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestOwnerIngressProcessHelper$", "-test.v")
			cmd.Env = append(os.Environ(), "BIOZERO_OWNER_INGRESS_CHILD="+config)
			cmd.Stdout, cmd.Stderr = out, out
			if e = cmd.Start(); e != nil {
				t.Fatal(e)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			terminal := false
			defer func() {
				if !terminal {
					cmd.Process.Kill()
					<-done
				}
				out.Sync()
				out.Close()
			}()
			await := func(path string) []byte {
				deadline := time.Now().Add(10 * time.Second)
				for {
					if raw, e := os.ReadFile(path); e == nil {
						return raw
					}
					select {
					case e := <-done:
						terminal = true
						t.Fatal("child exited", e, string(fileBytes(t, out.Name())))
					default:
					}
					if time.Now().After(deadline) {
						t.Fatal("child barrier missing", string(fileBytes(t, out.Name())))
					}
					time.Sleep(5 * time.Millisecond)
				}
			}
			var listen map[string]string
			if json.Unmarshal(await(c.Listening), &listen) != nil {
				t.Fatal("child endpoint invalid")
			}
			pool := x509.NewCertPool()
			pool.AddCert(chain[len(chain)-1])
			tlsConfig := &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{f.certA.Raw}, PrivateKey: f.keyA}}, NextProtos: []string{"http/1.1"}}
			conn, e := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", listen["address"], tlsConfig)
			if e != nil {
				t.Fatal(e)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			wire := ingressFrame(b, true)
			ingressRawPost(t, conn, wire, len(wire))
			await(c.Ready)
			var ledger ownerIngressLedger
			if decodeStoreJSON(fileBytes(t, filepath.Join(cfg.Directory, "ledger.json")), &ledger) != nil || len(ledger.Records) != 1 || ledger.Records[0].ChargeBytes != cfg.Policy.MaxBodyBytes+StoreMetadataHeadroom {
				t.Fatal("physical promise missing before crash")
			}
			if mode == "reading" {
				if ledger.Records[0].State != "reading" {
					t.Fatal("first Reader preceded reading state")
				}
			} else {
				if ledger.Records[0].State != "delivered" {
					t.Fatal("response preceded committed delivery")
				}
				tcp, ok := conn.NetConn().(*net.TCPConn)
				if !ok || tcp.SetLinger(0) != nil || tcp.Close() != nil {
					t.Fatal("own TCP RST failed")
				}
				if e = ingressEvidence(c.Release, true); e != nil {
					t.Fatal(e)
				}
				var observed map[string]json.RawMessage
				if json.Unmarshal(await(c.Observed), &observed) != nil || string(observed["write_error"]) != "true" {
					t.Fatal("delegated RST failure missing")
				}
			}
			before := ingressFiles(t, cfg.Directory)
			if _, e = OpenOwnerIngress(cfg); e == nil || e.Error() != "ownership_ingress_locked" {
				t.Fatal("live writer not exclusive", e)
			}
			if e = cmd.Process.Kill(); e != nil {
				t.Fatal(e)
			}
			select {
			case e = <-done:
				terminal = true
				ex, ok := e.(*exec.ExitError)
				if !ok {
					t.Fatal("own SIGKILL unobserved", e)
				}
				st, ok := ex.Sys().(syscall.WaitStatus)
				if !ok || !st.Signaled() || st.Signal() != syscall.SIGKILL {
					t.Fatal("wrong death authority")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("own child Wait not joined")
			}
			if mode == "reading" {
				if _, e = OpenOwnerIngress(cfg); e == nil || e.Error() != "ownership_ingress_pending" {
					t.Fatal("pending cold history adopted", e)
				}
			} else {
				cold := ingressTestStore(t, cfg, false)
				x := ingressTestHTTP(t, cold, nil)
				v, e := VerifyAcceptance(b.Acceptance, cfg.Pin, cfg.Scope)
				if e != nil {
					t.Fatal(e)
				}
				status, _ := httpCall(t, x.a, "GET", x.server.URL+"/v1/uploads/"+v.Binding().JobID, "", nil)
				if status != 200 {
					t.Fatal("cold A query failed")
				}
				status, _ = httpCall(t, x.b, "GET", x.server.URL+"/v1/uploads/"+v.Binding().JobID, "", nil)
				if status != 403 {
					t.Fatal("cold B read permitted")
				}
				conn := ingressRawTLS(t, x, false)
				meta := ingressFrame(b, false)
				ingressRawPost(t, conn, meta, len(meta)+len(b.Ciphertext))
				status, _ = ingressRawResponse(t, conn)
				if status != 200 || cold.Snapshot().ChargedBytes != cfg.Policy.MaxBodyBytes+StoreMetadataHeadroom {
					t.Fatal("cold duplicate needed body or refunded")
				}
			}
			if !reflect.DeepEqual(before, ingressFiles(t, cfg.Directory)) {
				t.Fatal("death/recovery changed physical history")
			}
			t.Logf("Own SIGKILL WaitStatus verified; %s history preserved with full transport charge", mode)
			if mode == "rst" {
				t.Log(string(fileBytes(t, out.Name())))
			}
		})
	}
}
