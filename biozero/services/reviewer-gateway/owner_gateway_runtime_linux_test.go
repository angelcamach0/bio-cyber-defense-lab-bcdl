//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestOwnerGatewaySelectorClosed(t *testing.T) {
	for _, test := range []struct {
		name             string
		env              map[string]string
		handled, invalid bool
	}{
		{"legacy_absent", map[string]string{}, false, false},
		{"legacy_explicit", map[string]string{"BIOZERO_REVIEWER_PROTOCOL": "legacy"}, false, false},
		{"owner_valid", map[string]string{"BIOZERO_REVIEWER_PROTOCOL": "owner-v1", "BIOZERO_OWNER_REVIEWER_CONFIG": "/private/config.json"}, true, false},
		{"owner_missing", map[string]string{"BIOZERO_REVIEWER_PROTOCOL": "owner-v1"}, true, true},
		{"owner_relative", map[string]string{"BIOZERO_REVIEWER_PROTOCOL": "owner-v1", "BIOZERO_OWNER_REVIEWER_CONFIG": "config.json"}, true, true},
		{"owner_unclean", map[string]string{"BIOZERO_REVIEWER_PROTOCOL": "owner-v1", "BIOZERO_OWNER_REVIEWER_CONFIG": "/private/../config.json"}, true, true},
		{"owner_mixed", map[string]string{"BIOZERO_REVIEWER_PROTOCOL": "owner-v1", "BIOZERO_OWNER_REVIEWER_CONFIG": "/private/config.json", "BIOZERO_REVIEWER_CONFIG": "/legacy/fifo"}, true, true},
		{"orphan_owner_config", map[string]string{"BIOZERO_OWNER_REVIEWER_CONFIG": "/private/config.json"}, true, true},
		{"unknown", map[string]string{"BIOZERO_REVIEWER_PROTOCOL": "owner-next"}, true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			handled, path, err := selectOwnerGateway(func(k string) (string, bool) { v, ok := test.env[k]; return v, ok })
			if handled != test.handled || (err != nil) != test.invalid || (!test.invalid && handled && path != test.env["BIOZERO_OWNER_REVIEWER_CONFIG"]) {
				t.Fatal("selector changed contract")
			}
		})
	}
}
func TestOwnerGatewaySelectorProcessBeforeLegacyFIFO(t *testing.T) {
	if os.Getenv("BIOZERO_GATEWAY_SELECTOR_TEST_CHILD") == "1" {
		handled, code := ownerGatewayMain()
		if !handled {
			os.Exit(9)
		}
		os.Exit(code)
	}
	root := t.TempDir()
	fifo := filepath.Join(root, "legacy-fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestOwnerGatewaySelectorProcessBeforeLegacyFIFO$")
	for _, env := range os.Environ() {
		if !strings.HasPrefix(env, "BIOZERO_") {
			cmd.Env = append(cmd.Env, env)
		}
	}
	cmd.Env = append(cmd.Env, "BIOZERO_GATEWAY_SELECTOR_TEST_CHILD=1", "BIOZERO_REVIEWER_PROTOCOL=owner-v1", "BIOZERO_OWNER_REVIEWER_CONFIG="+filepath.Join(root, "owner-missing.json"), "BIOZERO_REVIEWER_CONFIG="+fifo)
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil || err == nil || string(output) != "owner_gateway_start_failed\n" {
		t.Fatalf("selector touched legacy or changed error: %v %q", err, output)
	}
	info, err := os.Lstat(fifo)
	if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		t.Fatal("legacy sentinel changed")
	}
}
func ogServiceFixture(t *testing.T) (*ownerGatewayService, *ogHTTPTestStore, *http.Client, string) {
	t.Helper()
	certificateServer := httptest.NewTLSServer(http.NotFoundHandler())
	cert := certificateServer.TLS.Certificates[0]
	client := certificateServer.Client()
	certificateServer.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	origin := "https://" + listener.Addr().String()
	m := ogTestMaterial(origin)
	m.BrowserTLS.Certificates = []tls.Certificate{cert}
	store := ogNewTestStore()
	service, err := newOwnerGatewayService(context.Background(), listener, m, store)
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	client.Timeout = 5 * time.Second
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		service.Shutdown(ctx)
	})
	return service, store, client, origin
}
func TestOwnerGatewayRuntimeCancelBeforeServeJoins(t *testing.T) {
	s, store, _, _ := ogServiceFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := serveOwnerGateway(ctx, s); err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.done:
	default:
		t.Fatal("launched Serve not joined")
	}
	store.mu.Lock()
	closed := store.closeCalls
	store.mu.Unlock()
	if closed != 1 {
		t.Fatal("healthy Store not closed once")
	}
	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closeCalls != 1 {
		t.Fatal("repeat Shutdown closed Store twice")
	}
}
func TestOwnerGatewayRuntimeWaitsOwnedOperationBeforeStore(t *testing.T) {
	s, store, client, origin := ogServiceFixture(t)
	entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	store.executeFn = func(ctx context.Context, _ string) error {
		close(entered)
		<-ctx.Done()
		close(canceled)
		<-release
		return ctx.Err()
	}
	served := make(chan error, 1)
	go func() { served <- s.Serve() }()
	f := &ogHTTPFixture{g: s.gateway, store: store, client: client, origin: origin, code: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))}
	session := f.login(t, "a")
	res, raw := f.request(t, "POST", "/api/experiments/fixture/runs", `{"request_id":"11111111111111111111111111111111"}`, session, nil)
	if res.StatusCode != 202 {
		t.Fatalf("submit %d %s", res.StatusCode, raw)
	}
	ogWait(t, entered)
	f.request(t, "POST", "/api/sign-out", "{}", session, nil)
	select {
	case <-canceled:
		t.Fatal("logout canceled authorized operation")
	default:
	}
	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		done <- s.Shutdown(ctx)
	}()
	ogWait(t, canceled)
	store.mu.Lock()
	closed := store.closeCalls
	store.mu.Unlock()
	if closed != 0 {
		t.Fatal("Store closed before operation Wait")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := <-served; err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closeCalls != 1 {
		t.Fatal("Store not closed after operation Wait")
	}
}
func TestOwnerGatewayRuntimeTimeoutRetainsStoreAndFirstError(t *testing.T) {
	s, store, _, _ := ogServiceFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	store.executeFn = func(ctx context.Context, _ string) error { close(entered); <-release; return ctx.Err() }
	s.gateway.mu.Lock()
	s.gateway.active["a"] = "1111111111111111"
	s.gateway.queue <- ownerGatewayRun{RunID: "1111111111111111", ReviewerID: "a"}
	s.gateway.mu.Unlock()
	ogWait(t, entered)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	err := s.Shutdown(ctx)
	if err == nil {
		t.Fatal("operation timeout hidden")
	}
	if again := s.Shutdown(context.Background()); again != err {
		t.Fatal("first shutdown error lost")
	}
	store.mu.Lock()
	closed := store.closeCalls
	store.mu.Unlock()
	if closed != 0 {
		t.Fatal("uncertain shutdown released Store")
	}
	close(release)
	s.gateway.workers.Wait()
}
func TestOwnerGatewayRuntimeEightConnections(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := &ogLimitedListener{Listener: base, slots: make(chan struct{}, 8)}
	defer l.Close()
	accepted := make(chan net.Conn, 9)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			accepted <- c
		}
	}()
	clients := []net.Conn{}
	servers := []net.Conn{}
	defer func() {
		for _, c := range clients {
			c.Close()
		}
		for _, c := range servers {
			c.Close()
		}
		l.Close()
		ogWait(t, done)
	}()
	for i := 0; i < 8; i++ {
		c, e := net.Dial("tcp", base.Addr().String())
		if e != nil {
			t.Fatal(e)
		}
		clients = append(clients, c)
		select {
		case a := <-accepted:
			servers = append(servers, a)
		case <-time.After(time.Second):
			t.Fatal("connection not admitted")
		}
	}
	ninth, e := net.Dial("tcp", base.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer ninth.Close()
	ninth.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	_, e = ninth.Read(b[:])
	if !errors.Is(e, io.EOF) {
		t.Fatalf("ninth connection not closed: %v", e)
	}
	if len(l.slots) != 8 {
		t.Fatal("connection bound changed")
	}
	servers[0].Close()
	c, e := net.Dial("tcp", base.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	clients = append(clients, c)
	select {
	case a := <-accepted:
		servers = append(servers, a)
	case <-time.After(time.Second):
		t.Fatal("released slot not reusable")
	}
}
func TestOwnerGatewayRuntimeRSTDoesNotPoisonSessionOrHistory(t *testing.T) {
	s, store, client, origin := ogServiceFixture(t)
	reached, release, requestGone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var observe atomic.Bool
	var once sync.Once
	s.server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/session" && observe.Load() {
			go func() { <-r.Context().Done(); close(requestGone) }()
		}
		s.gateway.ServeHTTP(w, r)
	})
	served := make(chan error, 1)
	go func() { served <- s.Serve() }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		s.Shutdown(ctx)
		<-served
	}()
	f := &ogHTTPFixture{g: s.gateway, store: store, client: client, origin: origin, code: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))}
	session := f.login(t, "a")
	before := store.snapshot()
	observe.Store(true)
	s.gateway.mu.Lock()
	s.gateway.beforeWrite = func() { once.Do(func() { close(reached); <-release }) }
	s.gateway.mu.Unlock()
	conn, err := tls.Dial("tcp", s.listener.Addr().String(), &tls.Config{RootCAs: client.Transport.(*http.Transport).TLSClientConfig.RootCAs, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.WriteString(conn, "GET /api/session HTTP/1.1\r\nHost: "+s.gateway.host+"\r\nCookie: "+session.cookie.Name+"="+session.cookie.Value+"\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}
	ogWait(t, reached)
	tcp := conn.NetConn().(*net.TCPConn)
	tcp.SetLinger(0)
	tcp.Close()
	ogWait(t, requestGone)
	close(release)
	// Join that handler via a same-session request after disabling only the test barrier.
	observe.Store(false)
	res, _ := f.request(t, "GET", "/api/session", "", session, nil)
	if res.StatusCode != 200 || store.snapshot() != before {
		t.Fatal("RST poisoned session or mutated custody")
	}
}
