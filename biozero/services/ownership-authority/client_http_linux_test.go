//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package ownership

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Existing synthetic TLS certificates have both clientAuth and serverAuth EKUs.
// These tests demonstrate actual mTLS transport, not deployment PKI separation.
func authorityClientFixtureConfig(t *testing.T, x *httpFixture, ownerB bool) AuthorityClientConfig {
	t.Helper()
	f := fixture(t)
	pair := x.tlsA.Certificates[0]
	if ownerB {
		pair = x.tlsB.Certificates[0]
	}
	return AuthorityClientConfig{BaseURL: x.server.URL, Certificate: pair, RootCAs: x.tlsA.RootCAs, ServerName: "localhost", Pin: f.pin, Scope: x.store.Scope()}
}
func newTestAuthorityClient(t *testing.T, cfg AuthorityClientConfig) *AuthorityClient {
	t.Helper()
	c, err := NewAuthorityClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.CloseIdleConnections)
	return c
}
func reserveClientChallenge(t *testing.T, c *AuthorityClient, id int) []byte {
	t.Helper()
	raw, err := c.Reserve(context.Background(), HTTPReserveRequest{1, storeRequest(id), "input.fastq"})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func clientJobID(t *testing.T, raw []byte) string {
	t.Helper()
	var ch SignedChallenge
	if strictJSON(raw, &ch, MaxChallengeBytes) != nil {
		t.Fatal("invalid test challenge")
	}
	return ch.Claim.JobID
}

func TestAuthorityClientRealTLSRoundTripAndHistoricalGet(t *testing.T) {
	x := newHTTPFixture(t, nil)
	a := newTestAuthorityClient(t, authorityClientFixtureConfig(t, x, false))
	b := newTestAuthorityClient(t, authorityClientFixtureConfig(t, x, true))
	raw := reserveClientChallenge(t, a, 1101)
	jobID := clientJobID(t, raw)
	before, err := a.Get(context.Background(), jobID)
	if err != nil || before.State != "reserved" || before.Acceptance != nil {
		t.Fatal("reserved DTO", err)
	}
	if _, err = b.Get(context.Background(), jobID); err == nil {
		t.Fatal("different leaf read owner A despite same CN/serial")
	}
	body := bytes.Repeat([]byte{7}, 32)
	manifest := httpManifest(t, raw, body)
	accepted, err := a.Finalize(context.Background(), raw, manifest, bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyAcceptance(accepted, a.pin, a.scope)
	if err != nil || verified.Binding().CiphertextSHA256 != digest(body) {
		t.Fatal("acceptance", err)
	}
	a.now = func() time.Time { return time.Now().Add(24 * time.Hour) }
	after, err := a.Get(context.Background(), jobID)
	if err != nil || after.State != "accepted" || after.Acceptance == nil {
		t.Fatal("historical Get", err)
	}
	retained, _ := MarshalAcceptance(*after.Acceptance)
	if !bytes.Equal(retained, accepted) {
		t.Fatal("Get changed acceptance")
	}
	spy := &observedReader{r: bytes.NewReader(body)}
	if _, err = a.Finalize(context.Background(), raw, manifest, spy, 32); err == nil || spy.calls != 0 {
		t.Fatal("expired fresh Finalize read input")
	}
}

func TestAuthorityClientInvalidMetadataBeforeInput(t *testing.T) {
	x := newHTTPFixture(t, nil)
	a := newTestAuthorityClient(t, authorityClientFixtureConfig(t, x, false))
	b := newTestAuthorityClient(t, authorityClientFixtureConfig(t, x, true))
	raw := reserveClientChallenge(t, a, 1102)
	body := bytes.Repeat([]byte{8}, 32)
	manifest := httpManifest(t, raw, body)
	for _, kind := range []string{"manifest signature", "manifest duplicate", "manifest alias", "manifest null", "manifest unknown", "challenge tamper", "wrong owner", "declared size", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			ch, m := append([]byte(nil), raw...), append([]byte(nil), manifest...)
			c := a
			size := int64(32)
			ctx := context.Background()
			switch kind {
			case "manifest signature":
				var sm SignedManifest
				json.Unmarshal(m, &sm)
				sm.Signature = strings.Repeat("0", len(sm.Signature))
				m, _ = json.Marshal(sm)
			case "manifest duplicate":
				m = append([]byte(`{"signature":"00",`), m[1:]...)
			case "manifest alias":
				m = bytes.Replace(m, []byte(`"signature"`), []byte(`"Signature"`), 1)
			case "manifest null":
				m = bytes.Replace(m, []byte(`"signature":"`), []byte(`"signature":null,"extra":"`), 1)
			case "manifest unknown":
				m = append([]byte(`{"extra":0,`), m[1:]...)
			case "challenge tamper":
				ch = bytes.Replace(ch, []byte("input.fastq"), []byte("other.fastq"), 1)
			case "wrong owner":
				c = b
			case "declared size":
				size = 31
			case "canceled":
				cancelCtx, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelCtx
			}
			spy := &observedReader{r: bytes.NewReader(body)}
			if _, err := c.Finalize(ctx, ch, m, spy, size); err == nil || spy.calls != 0 {
				t.Fatal("invalid metadata read input", err, spy.calls)
			}
		})
	}
	state, err := a.Get(context.Background(), clientJobID(t, raw))
	if err != nil || state.State != "reserved" {
		t.Fatal("invalid requests changed reservation", err)
	}
}

func TestAuthorityClientMeasuresBeforeHTTP(t *testing.T) {
	for _, kind := range []string{"short", "extra", "hash", "read error", "no progress"} {
		t.Run(kind, func(t *testing.T) {
			var requests atomic.Int32
			x := newHTTPFixture(t, func(s *httptest.Server, h *AuthorityHTTPHandler) {
				s.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); h.ServeHTTP(w, r) })
			})
			a := newTestAuthorityClient(t, authorityClientFixtureConfig(t, x, false))
			ch := reserveClientChallenge(t, a, 1103)
			body := bytes.Repeat([]byte{9}, 32)
			m := httpManifest(t, ch, body)
			var r io.Reader = bytes.NewReader(body)
			switch kind {
			case "short":
				r = bytes.NewReader(body[:31])
			case "extra":
				r = bytes.NewReader(append(body, 0))
			case "hash":
				r = bytes.NewReader(bytes.Repeat([]byte{1}, 32))
			case "read error":
				r = readerFunc(func([]byte) (int, error) { return 0, io.ErrUnexpectedEOF })
			case "no progress":
				r = readerFunc(func([]byte) (int, error) { return 0, nil })
			}
			before := requests.Load()
			if _, err := a.Finalize(context.Background(), ch, m, r, 32); err == nil {
				t.Fatal("invalid stream accepted")
			}
			if requests.Load() != before {
				t.Fatal("unmeasured stream reached HTTP")
			}
		})
	}
}

func TestAuthorityClientPinsAndConfigCopies(t *testing.T) {
	x := newHTTPFixture(t, nil)
	cfg := authorityClientFixtureConfig(t, x, false)
	for _, kind := range []string{"http", "path", "userinfo", "query", "fragment", "no roots", "wrong key", "no scope", "no pin"} {
		t.Run(kind, func(t *testing.T) {
			c := cfg
			switch kind {
			case "http":
				c.BaseURL = "http://localhost"
			case "path":
				c.BaseURL += "/path"
			case "userinfo":
				c.BaseURL = "https://user@localhost"
			case "query":
				c.BaseURL += "?q=1"
			case "fragment":
				c.BaseURL += "#x"
			case "no roots":
				c.RootCAs = nil
			case "wrong key":
				c.Certificate.PrivateKey = fixture(t).keyB
			case "no scope":
				c.Scope = AcceptanceScope{}
			case "no pin":
				c.Pin = AuthorityPin{}
			}
			if _, err := NewAuthorityClient(c); err == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
	// Mutating caller-owned public certificate bytes and pin must not change client.
	cfg.Certificate.Certificate = [][]byte{append([]byte(nil), cfg.Certificate.Certificate[0]...)}
	cfg.Pin.PublicKey = append(ed25519.PublicKey(nil), cfg.Pin.PublicKey...)
	a := newTestAuthorityClient(t, cfg)
	cfg.Certificate.Certificate[0][0] ^= 1
	cfg.Pin.PublicKey[0] ^= 1
	reserveClientChallenge(t, a, 1104)
	pinFixture := newHTTPFixture(t, nil)
	wrong := authorityClientFixtureConfig(t, pinFixture, false)
	wrong.Pin.PublicKey = append(ed25519.PublicKey(nil), wrong.Pin.PublicKey...)
	wrong.Pin.PublicKey[0] ^= 1
	if _, err := newTestAuthorityClient(t, wrong).Reserve(context.Background(), HTTPReserveRequest{1, storeRequest(1105), "input.fastq"}); err == nil {
		t.Fatal("wrong authority pin accepted")
	}
	scopeFixture := newHTTPFixture(t, nil)
	badScope := authorityClientFixtureConfig(t, scopeFixture, false)
	badScope.Scope.StoreID = strings.Repeat("f", 32)
	c := newTestAuthorityClient(t, badScope)
	ch := reserveClientChallenge(t, c, 1106)
	body := bytes.Repeat([]byte{2}, 32)
	m := httpManifest(t, ch, body)
	if _, err := c.Finalize(context.Background(), ch, m, bytes.NewReader(body), 32); err == nil {
		t.Fatal("wrong scope accepted")
	}
	if _, err := c.Get(context.Background(), clientJobID(t, ch)); err == nil {
		t.Fatal("Get exposed acceptance under wrong scope")
	}
}

func TestAuthorityClientRedirectBoundedResponsesAndDeadline(t *testing.T) {
	for _, kind := range []string{"redirect", "oversize known", "oversize streamed", "error", "malformed", "deadline"} {
		t.Run(kind, func(t *testing.T) {
			var hits atomic.Int32
			x := newHTTPFixture(t, func(s *httptest.Server, _ *AuthorityHTTPHandler) {
				s.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					hits.Add(1)
					switch kind {
					case "redirect":
						http.Redirect(w, r, "/target", http.StatusTemporaryRedirect)
					case "oversize known":
						w.Header().Set("Content-Length", "4097")
						w.Write(bytes.Repeat([]byte{'x'}, 4097))
					case "oversize streamed":
						w.(http.Flusher).Flush()
						w.Write(bytes.Repeat([]byte{'x'}, 4097))
					case "error":
						http.Error(w, "private server path and secrets", 500)
					case "malformed":
						w.Write([]byte(`{"bad":1}`))
					case "deadline":
						select {
						case <-r.Context().Done():
						case <-time.After(time.Second):
						}
					}
				})
			})
			c := newTestAuthorityClient(t, authorityClientFixtureConfig(t, x, false))
			ctx := context.Background()
			if kind == "deadline" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 30*time.Millisecond)
				defer cancel()
			}
			_, err := c.Reserve(ctx, HTTPReserveRequest{1, storeRequest(1107), "input.fastq"})
			if err == nil || strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), x.server.URL) {
				t.Fatal("unsafe/missing error", err)
			}
			if hits.Load() != 1 {
				t.Fatal("automatic redirect/retry", hits.Load())
			}
		})
	}
}

func TestAuthorityClientRequiresVerifiedServerTLS(t *testing.T) {
	x := newHTTPFixture(t, nil)
	for _, kind := range []string{"wrong hostname", "wrong trust root"} {
		t.Run(kind, func(t *testing.T) {
			cfg := authorityClientFixtureConfig(t, x, false)
			if kind == "wrong hostname" {
				cfg.ServerName = "invalid.example"
			} else {
				cfg.RootCAs = x509.NewCertPool()
				cfg.RootCAs.AddCert(fixture(t).certB)
			}
			c := newTestAuthorityClient(t, cfg)
			if _, err := c.Reserve(context.Background(), HTTPReserveRequest{1, storeRequest(1111), "input.fastq"}); err == nil {
				t.Fatal("unverified authority TLS accepted")
			}
		})
	}
}

func TestAuthorityClientRejectsOtherSignedAcceptance(t *testing.T) {
	var override atomic.Pointer[[]byte]
	x := newHTTPFixture(t, func(s *httptest.Server, h *AuthorityHTTPHandler) {
		s.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if raw := override.Load(); raw != nil && r.URL.Path == "/v1/finalizations" {
				w.Header().Set("Connection", "close")
				w.Write(*raw)
				return
			}
			h.ServeHTTP(w, r)
		})
	})
	c := newTestAuthorityClient(t, authorityClientFixtureConfig(t, x, false))
	body := bytes.Repeat([]byte{3}, 32)
	ch1 := reserveClientChallenge(t, c, 1108)
	m1 := httpManifest(t, ch1, body)
	accepted, err := c.Finalize(context.Background(), ch1, m1, bytes.NewReader(body), 32)
	if err != nil {
		t.Fatal(err)
	}
	override.Store(&accepted)
	ch2 := reserveClientChallenge(t, c, 1109)
	m2 := httpManifest(t, ch2, body)
	if _, err = c.Finalize(context.Background(), ch2, m2, bytes.NewReader(body), 32); err == nil {
		t.Fatal("other valid signed acceptance accepted")
	}
}

func TestAuthorityClientGetStrictOptionalShape(t *testing.T) {
	x := newHTTPFixture(t, nil)
	ch, _ := httpReserve(t, x, 1110)
	var signed SignedChallenge
	json.Unmarshal(ch, &signed)
	base, _ := json.Marshal(HTTPJobResponse{SchemaVersion: 1, State: "reserved", Challenge: signed})
	if _, err := decodeAuthorityClientJob(base); err != nil {
		t.Fatal("valid absent optionals rejected", err)
	}
	for _, kind := range []string{"duplicate", "case", "unknown", "null optional", "missing", "trailing", "nested duplicate", "deep"} {
		t.Run(kind, func(t *testing.T) {
			raw := append([]byte(nil), base...)
			switch kind {
			case "duplicate":
				raw = append([]byte(`{"state":"reserved",`), raw[1:]...)
			case "case":
				raw = bytes.Replace(raw, []byte(`"state"`), []byte(`"State"`), 1)
			case "unknown":
				raw = append([]byte(`{"extra":0,`), raw[1:]...)
			case "null optional":
				raw = append([]byte(`{"acceptance":null,`), raw[1:]...)
			case "missing":
				raw = bytes.Replace(raw, []byte(`"schema_version":1,`), nil, 1)
			case "trailing":
				raw = append(raw, []byte(`{}`)...)
			case "nested duplicate":
				raw = bytes.Replace(raw, []byte(`"claim":{`), []byte(`"claim":{"job_id":"0000000000000000",`), 1)
			case "deep":
				raw = []byte(`{"challenge":` + strings.Repeat("[", 65) + `0` + strings.Repeat("]", 65) + `}`)
			}
			if _, err := decodeAuthorityClientJob(raw); err == nil {
				t.Fatal("ambiguous shape accepted")
			}
		})
	}
}
