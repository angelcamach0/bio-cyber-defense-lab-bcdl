//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package ownership

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func publicationHTTPCall(t *testing.T, client *http.Client, method, url string, body []byte, headers map[string]string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, PublicationResponseLimit+1))
	res.Body.Close()
	if err != nil || len(raw) > PublicationResponseLimit {
		t.Fatal("response bound/read failed")
	}
	return res.StatusCode, raw
}
func publicationHTTPPath(t *testing.T, c PublicationServiceConfig, raw []byte) string {
	t.Helper()
	v, err := VerifyAcceptance(raw, c.loaded.pin, c.ExpectedAuthorityScope)
	if err != nil {
		t.Fatal(err)
	}
	return "/v1/acceptances/" + v.Binding().JobID + "/" + v.SHA256()
}
func TestPublicationHTTPRealTLSCanonicalDuplicateGet(t *testing.T) {
	c, raw := publicationInitializedFixture(t)
	service, url := publicationRunService(t, c, nil)
	client := publicationTestClient(t, true)
	path := publicationHTTPPath(t, c, raw)
	status, first := publicationHTTPCall(t, client, "POST", url+path, raw, map[string]string{"Content-Type": "application/json"})
	if status != 200 {
		t.Fatalf("publish %d %s", status, first)
	}
	status, again := publicationHTTPCall(t, client, "POST", url+path, raw, map[string]string{"Content-Type": "application/json"})
	if status != 200 || !bytes.Equal(first, again) {
		t.Fatal("duplicate publication changed receipt")
	}
	status, queried := publicationHTTPCall(t, client, "GET", url+path, nil, nil)
	if status != 200 || !bytes.Equal(first, queried) {
		t.Fatal("query receipt differs")
	}
	snapshot, err := service.store.Snapshot()
	if err != nil || snapshot.RetainedJobs != 1 || snapshot.RetainedBytes != PublicationRunCharge {
		t.Fatal("duplicate retained another slot")
	}
	var receipt PublicationReceipt
	if strictJSON(first, &receipt, PublicationResponseLimit) != nil || receipt.State != "published" || receipt.PublisherScope != c.ExpectedPublisherScope {
		t.Fatal("receipt not closed bound publication")
	}
	inbox, err := os.ReadFile(filepath.Join(service.InboxDirectory(), receipt.JobID+".json"))
	if err != nil || !bytes.Equal(inbox, raw) {
		t.Fatal("wrong signed inbox bytes")
	}
	status, body := publicationHTTPCall(t, client, "GET", url+"/healthz", nil, nil)
	if status != 200 || string(body) != `{"status":"publication_alive"}` {
		t.Fatal("producer health failed")
	}
}
func TestPublicationHTTPURLBodyAndShapeBeforeMutation(t *testing.T) {
	c, raw := publicationInitializedFixture(t)
	service, url := publicationRunService(t, c, nil)
	client := publicationTestClient(t, true)
	path := publicationHTTPPath(t, c, raw)
	tests := []struct {
		name, method, path string
		raw                []byte
		headers            map[string]string
	}{
		{"job", "POST", "/v1/acceptances/ffffffffffffffff/" + digest(raw), raw, map[string]string{"Content-Type": "application/json"}},
		{"hash", "POST", strings.TrimSuffix(path, digest(raw)) + strings.Repeat("e", 64), raw, map[string]string{"Content-Type": "application/json"}},
		{"whitespace", "POST", path, append([]byte(" "), raw...), map[string]string{"Content-Type": "application/json"}},
		{"media", "POST", path, raw, map[string]string{"Content-Type": "application/json; charset=utf-8"}},
		{"encoding", "POST", path, raw, map[string]string{"Content-Type": "application/json", "Content-Encoding": "gzip"}},
		{"oversize", "POST", path, bytes.Repeat([]byte("x"), MaxAcceptanceBytes+1), map[string]string{"Content-Type": "application/json"}},
		{"query", "POST", path + "?producer=owner", raw, map[string]string{"Content-Type": "application/json"}},
		{"getbody", "GET", path, []byte("x"), nil},
		{"method", "PUT", path, raw, nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			status, _ := publicationHTTPCall(t, client, test.method, url+test.path, test.raw, test.headers)
			if status < 400 {
				t.Fatal("invalid publication accepted")
			}
			snapshot, err := service.store.Snapshot()
			if err != nil || snapshot.RetainedJobs != 0 || snapshot.RetainedBytes != 0 {
				t.Fatal("invalid request changed/fenced history")
			}
			names, err := os.ReadDir(service.InboxDirectory())
			if err != nil || len(names) != 0 {
				t.Fatal("invalid request published sidecar")
			}
		})
	}
	status, _ := publicationHTTPCall(t, client, "GET", url+path, nil, nil)
	if status != 404 {
		t.Fatal("unknown publication not query-only404")
	}
}

type publicationObservedBody struct {
	io.ReadCloser
	reads *atomic.Int32
}

func (b publicationObservedBody) Read(p []byte) (int, error) {
	b.reads.Add(1)
	return b.ReadCloser.Read(p)
}
func TestPublicationHTTPUnpinnedProducerBeforeBodyRead(t *testing.T) {
	c, path, raw := publicationServiceFixture(t)
	c.ProducerCredentialSHA256 = []string{strings.Repeat("e", 64)}
	publicationWriteServiceFixture(t, path, c)
	loaded, err := LoadPublicationServiceConfig(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	c.ExpectedPublisherScope, err = InitializePublicationStore(context.Background(), loaded)
	if err != nil {
		t.Fatal(err)
	}
	publicationWriteServiceFixture(t, path, c)
	loaded, err = LoadPublicationServiceConfig(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	var reads atomic.Int32
	service, url := publicationRunService(t, loaded, func(s *PublicationService) {
		s.server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = publicationObservedBody{r.Body, &reads}
			s.handler.ServeHTTP(w, r)
		})
	})
	status, body := publicationHTTPCall(t, publicationTestClient(t, true), "POST", url+publicationHTTPPath(t, loaded, raw), raw, map[string]string{"Content-Type": "application/json", "X-Producer-Credential": fixture(t).stateB.PeerCertificates[0].SerialNumber.String()})
	if status != 403 || reads.Load() != 0 || bytes.Contains(body, []byte("record")) {
		t.Fatal("unpinned producer read body or accepted header identity")
	}
	snapshot, err := service.store.Snapshot()
	if err != nil || snapshot.RetainedJobs != 0 {
		t.Fatal("producer denial changed history")
	}
}
func TestPublicationHTTPActualConnectionRejectsTLSLookalike(t *testing.T) {
	c, raw := publicationInitializedFixture(t)
	var reads atomic.Int32
	service, url := publicationRunService(t, c, func(s *PublicationService) {
		s.server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fake := fixture(t).stateA
			r.TLS = &fake
			r.Body = publicationObservedBody{r.Body, &reads}
			s.handler.ServeHTTP(w, r)
		})
	})
	status, _ := publicationHTTPCall(t, publicationTestClient(t, true), "POST", url+publicationHTTPPath(t, c, raw), raw, map[string]string{"Content-Type": "application/json"})
	if status != 403 || reads.Load() != 0 {
		t.Fatal("request TLS lookalike replaced actual producer")
	}
	if service.store.Check() != nil {
		t.Fatal("identity denial poisoned history")
	}
}

type publicationFailedWriter struct {
	headers http.Header
	writes  int
}

func (w *publicationFailedWriter) Header() http.Header              { return w.headers }
func (w *publicationFailedWriter) WriteHeader(int)                  {}
func (w *publicationFailedWriter) Write([]byte) (int, error)        { w.writes++; return 0, io.ErrClosedPipe }
func (w *publicationFailedWriter) SetWriteDeadline(time.Time) error { return nil }
func (w *publicationFailedWriter) FlushError() error                { return io.ErrClosedPipe }
func TestPublicationHTTPReceiptWriteFailureIsLocal(t *testing.T) {
	c, raw := publicationInitializedFixture(t)
	store, err := OpenPublicationStore(c.storeConfig(c.loaded))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	f := fixture(t)
	published, err := store.Publish(context.Background(), &f.stateB, raw)
	if err != nil {
		t.Fatal(err)
	}
	before, err := store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(published)
	writer := &publicationFailedWriter{headers: make(http.Header)}
	if publicationHTTPWrite(writer, 200, body) == nil || writer.writes != 1 {
		t.Fatal("write fault not observed")
	}
	after, err := store.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("network write fenced/mutated publication")
	}
	recovered, err := store.Get(context.Background(), &f.stateB, published.JobID, published.AcceptanceSHA256)
	if err != nil || recovered != published {
		t.Fatal("query cannot recover same publication")
	}
}

// No fake handler-science claim: the positive path above publishes a real signed
// acceptance through real mTLS and a real durable PublicationStore, not execution.

type publicationRSTWriter struct {
	http.ResponseWriter
	entered, release chan struct{}
	fault            chan error
}

func (w *publicationRSTWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *publicationRSTWriter) Write(raw []byte) (int, error) {
	close(w.entered)
	<-w.release
	n, err := w.ResponseWriter.Write(raw)
	if err != nil {
		w.fault <- err
	}
	return n, err
}
func (w *publicationRSTWriter) FlushError() error {
	err := http.NewResponseController(w.ResponseWriter).Flush()
	w.fault <- err
	return err
}
func publicationWaitHTTP(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("causal HTTP barrier timed out")
	}
}
func TestPublicationHTTPActualRSTAfterDurablePublishDoesNotPoison(t *testing.T) {
	c, raw := publicationInitializedFixture(t)
	entered, release, gone, handled := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	faults := make(chan error, 2)
	service, url := publicationRunService(t, c, func(s *PublicationService) {
		s.server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				defer close(handled)
				go func() { <-r.Context().Done(); close(gone) }()
				s.handler.ServeHTTP(&publicationRSTWriter{w, entered, release, faults}, r)
				return
			}
			s.handler.ServeHTTP(w, r)
		})
	})
	client := publicationTestClient(t, true)
	conn, err := tls.Dial("tcp", service.Addr().String(), client.Transport.(*http.Transport).TLSClientConfig.Clone())
	if err != nil {
		t.Fatal(err)
	}
	path := publicationHTTPPath(t, c, raw)
	header := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", path, service.Addr().String(), len(raw))
	if _, err = io.WriteString(conn, header+string(raw)); err != nil {
		t.Fatal(err)
	}
	publicationWaitHTTP(t, entered)
	before, err := service.store.Snapshot()
	if err != nil || before.RetainedJobs != 1 {
		t.Fatal("write barrier preceded durable publication")
	}
	tcp := conn.NetConn().(*net.TCPConn)
	tcp.SetLinger(0)
	tcp.Close()
	publicationWaitHTTP(t, gone)
	close(release)
	publicationWaitHTTP(t, handled)
	select {
	case err := <-faults:
		if err == nil {
			t.Fatal("real response write did not observe socket failure")
		}
	case <-time.After(time.Second):
		t.Fatal("missing causal network failure")
	}
	after, err := service.store.Snapshot()
	if err != nil || after != before {
		t.Fatal("RST poisoned durable publication")
	}
	status, body := publicationHTTPCall(t, client, "GET", url+path, nil, nil)
	var recovered PublicationReceipt
	if status != 200 || json.Unmarshal(body, &recovered) != nil || recovered.AcceptanceSHA256 != digest(raw) {
		t.Fatal("GET did not recover publication after actual lost ACK")
	}
}
