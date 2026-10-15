//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package ownership

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The existing synthetic certificates have both EKUs and equal CN/serial. These
// tests exercise real mTLS and signed metadata, not deployed PKI-role isolation
// or scientific execution. Owner A signs; distinct leaf B is the producer.
func publicationClientFixture(t *testing.T, handler http.Handler) (PublicationClientConfig, []byte, PublicationReceipt) {
	t.Helper()
	f, accepted, authorityScope := acceptanceFixture(t, true)
	raw, err := MarshalAcceptance(accepted)
	if err != nil {
		t.Fatal(err)
	}
	publisherScope := PublicationScope{PublisherID: strings.Repeat("7", 32), PolicySHA256: strings.Repeat("8", 64)}
	binding := accepted.Record.Binding
	receipt := PublicationReceipt{SchemaVersion: 1, Domain: PublicationReceiptDomain, State: "published", PublisherScope: publisherScope,
		AuthorityScope: authorityScope, JobID: binding.JobID, AcceptanceSHA256: digest(raw), CredentialSHA256: binding.CredentialSHA256,
		ExecutionProfileSHA256: binding.ExecutionProfileSHA256, PipelineMode: binding.PipelineMode}
	pool := x509.NewCertPool()
	chain := f.stateA.VerifiedChains[0]
	pool.AddCert(chain[len(chain)-1])
	server := httptest.NewUnstartedServer(handler)
	server.Config.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){}
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs: pool, Certificates: []tls.Certificate{{Certificate: [][]byte{f.certA.Raw}, PrivateKey: f.keyA}}, NextProtos: []string{"http/1.1"}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return PublicationClientConfig{Client: AuthorityClientConfig{BaseURL: server.URL, Certificate: tls.Certificate{Certificate: [][]byte{f.certB.Raw}, PrivateKey: f.keyB},
		RootCAs: pool, ServerName: "localhost", Pin: f.pin, Scope: authorityScope}, ExpectedPublisherScope: publisherScope}, raw, receipt
}

func newTestPublicationClient(t *testing.T, config PublicationClientConfig) *PublicationClient {
	t.Helper()
	c, err := NewPublicationClient(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.CloseIdleConnections)
	return c
}

func TestPublicationClientRealMTLSCanonicalPostAndKnownGet(t *testing.T) {
	var mu sync.Mutex
	var methods, paths, peers []string
	var bodies [][]byte
	var expected PublicationReceipt
	config, accepted, receipt := publicationClientFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		if r.Proto != "HTTP/1.1" || r.TLS.Version != tls.VersionTLS13 || len(r.TLS.VerifiedChains) == 0 ||
			r.URL.RawQuery != "" || r.Header.Get("X-Client-ID") != "" || r.Header.Get("X-Owner-ID") != "" || !r.Close {
			t.Error("invalid publication transport")
		}
		if r.Method == http.MethodPost && r.Header.Get("Content-Type") != "application/json" || r.Method == http.MethodGet && (len(raw) != 0 || r.ContentLength != 0) {
			t.Error("invalid publication body")
		}
		mu.Lock()
		methods = append(methods, r.Method)
		paths = append(paths, r.URL.Path)
		peers = append(peers, digest(r.TLS.PeerCertificates[0].Raw))
		bodies = append(bodies, raw)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(expected)
	}))
	expected = receipt
	client := newTestPublicationClient(t, config)
	var spaced bytes.Buffer
	if err := json.Indent(&spaced, accepted, "", "  "); err != nil {
		t.Fatal(err)
	}
	for _, operation := range []func(context.Context, []byte) (PublicationReceipt, error){client.Publish, client.Get} {
		got, err := operation(context.Background(), spaced.Bytes())
		if err != nil || got != receipt {
			t.Fatal("matching full receipt", err, got)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(methods, ",") != "POST,GET" || paths[0] != "/v1/acceptances/"+receipt.JobID+"/"+receipt.AcceptanceSHA256 || paths[0] != paths[1] ||
		!bytes.Equal(bodies[0], accepted) || len(bodies[1]) != 0 || peers[0] != digest(fixture(t).certB.Raw) || peers[1] != peers[0] || peers[0] == receipt.CredentialSHA256 {
		t.Fatal("canonical body/path or dedicated producer identity changed")
	}
	transport := client.transport.client.Transport.(*http.Transport)
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS13 || transport.TLSClientConfig.MaxVersion != tls.VersionTLS13 ||
		!transport.DisableKeepAlives || !transport.DisableCompression || transport.MaxConnsPerHost != 4 || client.transport.client.Timeout != 30*time.Second {
		t.Fatal("publication transport limits changed")
	}
}

func TestPublicationClientInvalidAuthorizationHasZeroHTTPCalls(t *testing.T) {
	var hits atomic.Int32
	config, accepted, _ := publicationClientFixture(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	for _, method := range []string{"POST", "GET"} {
		for _, kind := range []string{"signature", "duplicate", "alias", "null", "unknown", "trailing", "utf8", "oversize", "pin", "scope", "producer_is_owner", "cancelled", "nil_context"} {
			t.Run(method+"/"+kind, func(t *testing.T) {
				cfg := config
				raw := append([]byte(nil), accepted...)
				ctx := context.Background()
				switch kind {
				case "signature":
					var value SignedAcceptance
					json.Unmarshal(raw, &value)
					value.Signature = strings.Repeat("0", len(value.Signature))
					raw, _ = json.Marshal(value)
				case "duplicate":
					raw = append([]byte(`{"signature":"00",`), raw[1:]...)
				case "alias":
					raw = bytes.Replace(raw, []byte(`"record"`), []byte(`"Record"`), 1)
				case "null":
					raw = []byte(`{"record":null,"signature":"00"}`)
				case "unknown":
					raw = append([]byte(`{"extra":1,`), raw[1:]...)
				case "trailing":
					raw = append(raw, []byte(" {}")...)
				case "utf8":
					raw = append(raw, 0xff)
				case "oversize":
					raw = bytes.Repeat([]byte{'x'}, MaxAcceptanceBytes+1)
				case "pin":
					cfg.Client.Pin.PublicKey = append(ed25519.PublicKey(nil), cfg.Client.Pin.PublicKey...)
					cfg.Client.Pin.PublicKey[0] ^= 1
				case "scope":
					cfg.Client.Scope.StoreID = strings.Repeat("f", 32)
				case "producer_is_owner":
					f := fixture(t)
					cfg.Client.Certificate = tls.Certificate{Certificate: [][]byte{f.certA.Raw}, PrivateKey: f.keyA}
				case "cancelled":
					cancelled, cancel := context.WithCancel(ctx)
					cancel()
					ctx = cancelled
				case "nil_context":
					ctx = nil
				}
				client := newTestPublicationClient(t, cfg)
				var err error
				if method == "POST" {
					_, err = client.Publish(ctx, raw)
				} else {
					_, err = client.Get(ctx, raw)
				}
				if err == nil || hits.Load() != 0 {
					t.Fatal("invalid authorization reached HTTP", err, hits.Load())
				}
			})
		}
	}
}

func TestPublicationClientConfigSnapshotsAndPublisherScope(t *testing.T) {
	var expected PublicationReceipt
	config, accepted, receipt := publicationClientFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(expected)
	}))
	expected = receipt
	for _, scope := range []PublicationScope{{}, {PublisherID: strings.Repeat("a", 32)}, {PublisherID: strings.Repeat("a", 32), PolicySHA256: strings.Repeat("A", 64)}} {
		cfg := config
		cfg.ExpectedPublisherScope = scope
		if _, err := NewPublicationClient(cfg); err == nil {
			t.Fatal("invalid publisher scope accepted")
		}
	}
	config.Client.Certificate.Certificate = [][]byte{append([]byte(nil), config.Client.Certificate.Certificate[0]...)}
	config.Client.Pin.PublicKey = append(ed25519.PublicKey(nil), config.Client.Pin.PublicKey...)
	client := newTestPublicationClient(t, config)
	config.Client.Certificate.Certificate[0][0] ^= 1
	config.Client.Pin.PublicKey[0] ^= 1
	config.ExpectedPublisherScope.PublisherID = strings.Repeat("f", 32)
	if got, err := client.Publish(context.Background(), accepted); err != nil || got != receipt {
		t.Fatal("caller mutation changed copied material", err)
	}
	var absent *PublicationClient
	absent.CloseIdleConnections()
	if _, err := absent.Get(context.Background(), accepted); err == nil {
		t.Fatal("nil client succeeded")
	}
}

type publicationRoundTripFunc func(*http.Request) (*http.Response, error)

func (f publicationRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type publicationTrackedBody struct {
	io.Reader
	closed atomic.Bool
}

func (b *publicationTrackedBody) Close() error { b.closed.Store(true); return nil }

func TestPublicationClientClosedReceiptTupleAndResponseClosure(t *testing.T) {
	config, accepted, receipt := publicationClientFixture(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("unit transport unexpectedly reached real endpoint")
	}))
	client := newTestPublicationClient(t, config)
	valid, _ := json.Marshal(receipt)
	mutations := map[string]func(*PublicationReceipt){
		"schema": func(r *PublicationReceipt) { r.SchemaVersion++ }, "domain": func(r *PublicationReceipt) { r.Domain += ".other" },
		"state": func(r *PublicationReceipt) { r.State = "pending" }, "publisher": func(r *PublicationReceipt) { r.PublisherScope.PublisherID = strings.Repeat("f", 32) },
		"publisher_policy": func(r *PublicationReceipt) { r.PublisherScope.PolicySHA256 = strings.Repeat("f", 64) },
		"authority_scope":  func(r *PublicationReceipt) { r.AuthorityScope.StoreID = strings.Repeat("f", 32) },
		"authority_policy": func(r *PublicationReceipt) { r.AuthorityScope.PolicySHA256 = strings.Repeat("f", 64) },
		"job":              func(r *PublicationReceipt) { r.JobID = strings.Repeat("f", 16) }, "acceptance": func(r *PublicationReceipt) { r.AcceptanceSHA256 = strings.Repeat("f", 64) },
		"owner":   func(r *PublicationReceipt) { r.CredentialSHA256 = digest(fixture(t).certB.Raw) },
		"profile": func(r *PublicationReceipt) { r.ExecutionProfileSHA256 = strings.Repeat("f", 64) }, "mode": func(r *PublicationReceipt) { r.PipelineMode = "stats" },
	}
	bodies := map[string][]byte{"positive": valid, "duplicate": append([]byte(`{"schema_version":1,`), valid[1:]...),
		"alias": bytes.Replace(valid, []byte(`"job_id"`), []byte(`"Job_ID"`), 1), "null": bytes.Replace(valid, []byte(`"state":"published"`), []byte(`"state":null`), 1),
		"unknown": append([]byte(`{"extra":1,`), valid[1:]...), "missing": bytes.Replace(valid, []byte(`"schema_version":1,`), nil, 1),
		"trailing": append(append([]byte(nil), valid...), []byte(" {}")...), "invalid_utf8": append(append([]byte(nil), valid...), 0xff),
		"oversize": bytes.Repeat([]byte{'x'}, PublicationResponseLimit+1)}
	for name, mutate := range mutations {
		bad := receipt
		mutate(&bad)
		bodies[name], _ = json.Marshal(bad)
	}
	for name, raw := range bodies {
		t.Run(name, func(t *testing.T) {
			tracked := &publicationTrackedBody{Reader: bytes.NewReader(raw)}
			var calls atomic.Int32
			client.transport.client.Transport = publicationRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				calls.Add(1)
				if request.GetBody != nil || !request.Close || request.URL.RawQuery != "" || request.Method != "POST" {
					t.Error("request allowed replay or binding headers")
				}
				return &http.Response{StatusCode: 200, ProtoMajor: 1, ProtoMinor: 1, TLS: &fixture(t).stateB,
					Header: http.Header{"Content-Type": {"application/json"}}, Body: tracked, ContentLength: -1}, nil
			})
			got, err := client.Publish(context.Background(), accepted)
			if name == "positive" && (err != nil || got != receipt) || name != "positive" && err == nil {
				t.Fatal("receipt validation outcome", err)
			}
			if calls.Load() != 1 || !tracked.closed.Load() {
				t.Fatal("response leak or automatic retry")
			}
		})
	}
}

func TestPublicationClientStrictHTTPAndDeadline(t *testing.T) {
	config, accepted, receipt := publicationClientFixture(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	client := newTestPublicationClient(t, config)
	valid, _ := json.Marshal(receipt)
	for _, name := range []string{"absent", "http2", "tls12", "unverified_tls", "no_tls", "content_type", "duplicate_content_type", "encoding", "uncompressed", "transfer_encoding", "oversize_length", "short_body", "read_error", "trailer", "deadline"} {
		t.Run(name, func(t *testing.T) {
			tracked := &publicationTrackedBody{Reader: bytes.NewReader(valid)}
			var calls atomic.Int32
			client.transport.client.Transport = publicationRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				calls.Add(1)
				state := fixture(t).stateB
				response := &http.Response{StatusCode: 200, ProtoMajor: 1, ProtoMinor: 1, TLS: &state,
					Header: http.Header{"Content-Type": {"application/json"}}, Body: tracked, ContentLength: int64(len(valid))}
				switch name {
				case "absent":
					response.StatusCode = 404
				case "http2":
					response.ProtoMajor, response.ProtoMinor = 2, 0
				case "tls12":
					state.Version = tls.VersionTLS12
				case "unverified_tls":
					state.VerifiedChains = nil
				case "no_tls":
					response.TLS = nil
				case "content_type":
					response.Header.Set("Content-Type", "text/plain")
				case "duplicate_content_type":
					response.Header["Content-Type"] = []string{"application/json", "application/json"}
				case "encoding":
					response.Header.Set("Content-Encoding", "gzip")
				case "uncompressed":
					response.Uncompressed = true
				case "transfer_encoding":
					response.TransferEncoding = []string{"gzip"}
				case "oversize_length":
					response.ContentLength = PublicationResponseLimit + 1
				case "short_body":
					response.ContentLength++
				case "read_error":
					tracked.Reader = readerFunc(func([]byte) (int, error) { return 0, io.ErrUnexpectedEOF })
				case "trailer":
					response.Trailer = http.Header{"X-Private": {"x"}}
				case "deadline":
					deadline, ok := request.Context().Deadline()
					if !ok || time.Until(deadline) > PublicationClientTimeout {
						t.Error("unbounded request")
					}
					<-request.Context().Done()
				}
				return response, nil
			})
			ctx := context.Background()
			if name == "deadline" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 100*time.Millisecond)
				defer cancel()
			}
			if _, err := client.Get(ctx, accepted); err == nil || calls.Load() != 1 || !tracked.closed.Load() {
				t.Fatal("invalid HTTP response accepted, leaked, or retried", err, calls.Load())
			}
		})
	}
}

func TestPublicationClientActualResponseLossHasNoAutomaticPost(t *testing.T) {
	var posts, gets atomic.Int32
	var expected PublicationReceipt
	config, accepted, receipt := publicationClientFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			posts.Add(1)
			if _, err := io.Copy(io.Discard, r.Body); err != nil {
				t.Error(err)
			}
			connection, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			connection.Close() // Actual request was received; its response is lost.
			return
		}
		gets.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(expected)
	}))
	expected = receipt
	client := newTestPublicationClient(t, config)
	if _, err := client.Publish(context.Background(), accepted); err == nil || posts.Load() != 1 || gets.Load() != 0 {
		t.Fatal("lost response retried or fabricated success", err, posts.Load(), gets.Load())
	}
	if got, err := client.Get(context.Background(), accepted); err != nil || got != receipt || posts.Load() != 1 || gets.Load() != 1 {
		t.Fatal("explicit known-intent GET recovery", err, got)
	}
}

func TestPublicationClientRealTLSRedirectNeverFollowed(t *testing.T) {
	var calls atomic.Int32
	config, accepted, _ := publicationClientFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Redirect(w, r, "/must-not-follow", http.StatusTemporaryRedirect)
	}))
	client := newTestPublicationClient(t, config)
	for _, operation := range []func(context.Context, []byte) (PublicationReceipt, error){client.Publish, client.Get} {
		before := calls.Load()
		if _, err := operation(context.Background(), accepted); err == nil || calls.Load() != before+1 {
			t.Fatal("redirect followed or request retried", err, calls.Load())
		}
	}
}
