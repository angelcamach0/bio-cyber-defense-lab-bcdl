//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package ownership

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func authorityServiceFixture(t *testing.T) (AuthorityServiceConfig, string) {
	t.Helper()
	f := fixture(t)
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	asset := func(name string, raw []byte) AuthorityServiceAsset {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		return AuthorityServiceAsset{path, digest(raw)}
	}
	ca := f.stateA.VerifiedChains[0][len(f.stateA.VerifiedChains[0])-1]
	c := AuthorityServiceConfig{SchemaVersion: 1, ListenAddress: "127.0.0.1:0", StoreRoot: filepath.Join(root, "authority"), Namespace: "test-authority", AuthorityID: f.pin.AuthorityID, PublicKeyHex: hex.EncodeToString(f.pin.PublicKey), PipelineMode: f.pin.PipelineMode, ExecutionProfileSHA256: f.pin.ExecutionProfileSHA256,
		SigningKey: asset("signing.key", f.private), TLSCertificate: asset("server.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.certA.Raw})), TLSPrivateKey: asset("server.key", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(f.keyA)})), ClientCA: asset("ca.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})), Policy: DefaultStorePolicy()}
	path := filepath.Join(root, "service.json")
	writeAuthorityServiceFixture(t, path, c)
	return c, path
}
func writeAuthorityServiceFixture(t *testing.T, path string, c AuthorityServiceConfig) {
	t.Helper()
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}
func initializedAuthorityServiceFixture(t *testing.T) (AuthorityServiceConfig, string) {
	t.Helper()
	c, path := authorityServiceFixture(t)
	loaded, err := LoadAuthorityServiceConfig(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	c.ExpectedScope, err = InitializeAuthorityStore(context.Background(), loaded)
	if err != nil {
		t.Fatal(err)
	}
	writeAuthorityServiceFixture(t, path, c)
	loaded, err = LoadAuthorityServiceConfig(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	return loaded, path
}
func authorityServiceClient(t *testing.T, withCertificate bool) *http.Client {
	t.Helper()
	f := fixture(t)
	pool := x509.NewCertPool()
	pool.AddCert(f.stateA.VerifiedChains[0][len(f.stateA.VerifiedChains[0])-1])
	cfg := &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}}
	if withCertificate {
		cfg.Certificates = []tls.Certificate{{Certificate: [][]byte{f.certA.Raw}, PrivateKey: f.keyA}}
	}
	transport := &http.Transport{TLSClientConfig: cfg, DisableKeepAlives: true, ForceAttemptHTTP2: false}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 5 * time.Second}
}

func TestAuthorityServiceConfigPrivateAndSideEffectFree(t *testing.T) {
	c, path := authorityServiceFixture(t)
	loaded, err := LoadAuthorityServiceConfig(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.loaded == nil || loaded.loaded.tls.MinVersion != tls.VersionTLS13 || loaded.loaded.tls.ClientAuth != tls.RequireAndVerifyClientCert || !loaded.loaded.tls.SessionTicketsDisabled {
		t.Fatal("TLS configuration not protected")
	}
	if _, err = os.Stat(c.StoreRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("config loader created state")
	}
	if _, err = OpenAuthorityService(context.Background(), loaded); err == nil {
		t.Fatal("service implicitly initialized store")
	}
	scope, err := InitializeAuthorityStore(context.Background(), loaded)
	if err != nil {
		t.Fatal(err)
	}
	if scope.StoreID == "" || scope.PolicySHA256 == "" {
		t.Fatal("missing external scope")
	}
	if _, err = InitializeAuthorityStore(context.Background(), loaded); err == nil {
		t.Fatal("genesis adopted existing directory")
	}
	loaded.ExpectedScope = scope
	if _, err = OpenAuthorityService(context.Background(), loaded); err == nil {
		t.Fatal("loaded configuration mutated without reload")
	}
	c.ExpectedScope = scope
	writeAuthorityServiceFixture(t, path, c)
	loaded, err = LoadAuthorityServiceConfig(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = InitializeAuthorityStore(context.Background(), loaded); err == nil {
		t.Fatal("init accepted nonempty external scope")
	}
}

func TestAuthorityServiceConfigRejectsAmbiguityAndUnsafeFiles(t *testing.T) {
	for _, kind := range []string{"duplicate", "case alias", "unknown", "null", "missing", "trailing", "deep", "oversize", "FIFO", "symlink", "hardlink", "mode", "parent mode", "ancestor symlink"} {
		t.Run(kind, func(t *testing.T) {
			c, path := authorityServiceFixture(t)
			raw := fileBytes(t, path)
			switch kind {
			case "duplicate":
				raw = bytes.Replace(raw, []byte(`"schema_version":1`), []byte(`"schema_version":1,"schema_version":1`), 1)
			case "case alias":
				raw = bytes.Replace(raw, []byte(`"namespace"`), []byte(`"Namespace"`), 1)
			case "unknown":
				raw = append([]byte(`{"extra":1,`), raw[1:]...)
			case "null":
				raw = bytes.Replace(raw, []byte(`"policy":{`), []byte(`"policy":null,"ignored":{`), 1)
			case "missing":
				raw = bytes.Replace(raw, []byte(`"schema_version":1,`), nil, 1)
			case "trailing":
				raw = append(raw, []byte(`{}`)...)
			case "deep":
				raw = []byte(`{"policy":` + strings.Repeat("[", 65) + `0` + strings.Repeat("]", 65) + `}`)
			case "oversize":
				if err := os.Truncate(path, AuthorityServiceConfigLimit+1); err != nil {
					t.Fatal(err)
				}
			case "FIFO":
				os.Remove(path)
				if err := syscall.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				target := filepath.Join(t.TempDir(), "original")
				os.Rename(path, target)
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, filepath.Join(t.TempDir(), "link")); err != nil {
					t.Fatal(err)
				}
			case "mode":
				os.Chmod(path, 0644)
			case "parent mode":
				os.Chmod(filepath.Dir(path), 0755)
			case "ancestor symlink":
				alias := filepath.Join(t.TempDir(), "alias")
				os.Symlink(filepath.Dir(path), alias)
				path = filepath.Join(alias, filepath.Base(path))
			}
			if kind == "duplicate" || kind == "case alias" || kind == "unknown" || kind == "null" || kind == "missing" || kind == "trailing" || kind == "deep" {
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			started := time.Now()
			if _, err := LoadAuthorityServiceConfig(context.Background(), path); err == nil {
				t.Fatal("unsafe configuration accepted")
			}
			if time.Since(started) > time.Second {
				t.Fatal("unsafe config read blocked")
			}
			if _, err := os.Stat(c.StoreRoot); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("invalid config created store")
			}
		})
	}
}

func TestAuthorityServiceAssetsPinsAndAddress(t *testing.T) {
	for _, kind := range []string{"signing hash", "signing key", "signing length", "private mode", "asset FIFO", "asset symlink", "key mismatch", "nonCA", "CA garbage", "TLS garbage", "address wildcard", "address DNS", "address negative", "relative root", "asset overlap", "partial scope"} {
		t.Run(kind, func(t *testing.T) {
			c, path := authorityServiceFixture(t)
			update := func(a *AuthorityServiceAsset, raw []byte) {
				if err := os.WriteFile(a.Path, raw, 0600); err != nil {
					t.Fatal(err)
				}
				a.SHA256 = digest(raw)
			}
			switch kind {
			case "signing hash":
				c.SigningKey.SHA256 = strings.Repeat("f", 64)
			case "signing key":
				raw := append([]byte(nil), fixture(t).private...)
				raw[63] ^= 1
				update(&c.SigningKey, raw)
			case "signing length":
				update(&c.SigningKey, append(append([]byte(nil), fixture(t).private...), 0))
			case "private mode":
				os.Chmod(c.TLSPrivateKey.Path, 0644)
			case "asset FIFO":
				os.Remove(c.SigningKey.Path)
				syscall.Mkfifo(c.SigningKey.Path, 0600)
			case "asset symlink":
				target := filepath.Join(t.TempDir(), "signer")
				os.Rename(c.SigningKey.Path, target)
				os.Symlink(target, c.SigningKey.Path)
			case "key mismatch":
				update(&c.TLSPrivateKey, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(fixture(t).keyB)}))
			case "nonCA":
				update(&c.ClientCA, fileBytes(t, c.TLSCertificate.Path))
			case "CA garbage":
				update(&c.ClientCA, append(fileBytes(t, c.ClientCA.Path), []byte("garbage")...))
			case "TLS garbage":
				update(&c.TLSCertificate, []byte("not a certificate"))
			case "address wildcard":
				c.ListenAddress = "0.0.0.0:8445"
			case "address DNS":
				c.ListenAddress = "localhost:8445"
			case "address negative":
				c.ListenAddress = "127.0.0.1:-1"
			case "relative root":
				c.StoreRoot = "relative"
			case "asset overlap":
				c.StoreRoot = filepath.Dir(c.SigningKey.Path)
			case "partial scope":
				c.ExpectedScope.StoreID = strings.Repeat("1", 32)
			}
			writeAuthorityServiceFixture(t, path, c)
			if _, err := LoadAuthorityServiceConfig(context.Background(), path); err == nil {
				t.Fatal("invalid asset/configuration accepted")
			}
		})
	}
}

func TestAuthorityServiceActualMTLSAndCachedMaterial(t *testing.T) {
	c, _ := initializedAuthorityServiceFixture(t)
	for _, a := range []AuthorityServiceAsset{c.SigningKey, c.TLSCertificate, c.TLSPrivateKey, c.ClientCA} {
		if err := os.Rename(a.Path, a.Path+".saved"); err != nil {
			t.Fatal(err)
		}
	}
	s, err := OpenAuthorityService(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(context.Background()) }()
	client := authorityServiceClient(t, true)
	response, err := client.Get("https://" + s.Addr().String() + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != 200 || response.Proto != "HTTP/1.1" || response.TLS.Version != tls.VersionTLS13 || !response.Close || string(body) != `{"status":"ok"}` {
		t.Fatal("protected service response mismatch")
	}
	if _, err := authorityServiceClient(t, false).Get("https://" + s.Addr().String() + "/healthz"); err == nil {
		t.Fatal("no-certificate client accepted")
	}
	if err = s.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if s.StoreScope() != c.ExpectedScope {
		t.Fatal("scope changed")
	}
	if err = s.Shutdown(context.Background()); err != nil {
		t.Fatal("repeat shutdown failed")
	}
	store, err := OpenStore(c.storeConfig(c.loaded))
	if err != nil {
		t.Fatal("healthy shutdown retained lock")
	}
	store.Close()
}

func TestAuthorityServiceConnectionLimitAndCancellation(t *testing.T) {
	c, _ := initializedAuthorityServiceFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	s, err := OpenAuthorityService(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx) }()
	connections := []net.Conn{}
	defer func() {
		for _, conn := range connections {
			conn.Close()
		}
	}()
	for i := 0; i < authorityServiceConnections+1; i++ {
		conn, err := net.DialTimeout("tcp", s.Addr().String(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, conn)
	}
	deadline := time.Now().Add(time.Second)
	for len(s.listener.slots) < authorityServiceConnections && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(s.listener.slots) != 8 {
		t.Fatal("expected all handshake slots retained")
	}
	if err := connections[8].SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	ninth := tls.Client(connections[8], authorityServiceClient(t, true).Transport.(*http.Transport).TLSClientConfig)
	handshake := make(chan error, 1)
	go func() { handshake <- ninth.Handshake() }()
	select {
	case err := <-handshake:
		t.Fatalf("ninth TLS handshake completed before a slot was released: %v", err)
	case <-time.After(40 * time.Millisecond):
	}
	connections[0].Close()
	select {
	case err := <-handshake:
		if err != nil {
			t.Fatal("ninth TLS handshake did not complete after slot release", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ninth client remained blocked after slot release")
	}
	ninth.Close()
	cancel()
	started := time.Now()
	if err = s.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if time.Since(started) > AuthorityServiceShutdownBudget {
		t.Fatal("shutdown exceeded budget")
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}

type authorityFailCloseListener struct{ net.Listener }

func (l authorityFailCloseListener) Close() error {
	l.Listener.Close()
	return errors.New("secret close diagnostic")
}

func TestAuthorityServiceShutdownWaitHonorsCallerDeadline(t *testing.T) {
	c, _ := initializedAuthorityServiceFixture(t)
	s, err := OpenAuthorityService(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	s.shutdownGate <- struct{}{}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	started := time.Now()
	err = s.Shutdown(ctx)
	cancel()
	<-s.shutdownGate
	if err == nil || err.Error() != "ownership_service_shutdown_wait_expired" || time.Since(started) > time.Second {
		t.Fatal("queued shutdown ignored caller deadline")
	}
	if s.store.closed {
		t.Fatal("queued caller took another shutdown's authority")
	}
	if err = s.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestAuthorityServiceUncertainShutdownNeverReleasesOnRetry(t *testing.T) {
	for _, kind := range []string{"pending handler", "listener close error"} {
		t.Run(kind, func(t *testing.T) {
			c, _ := initializedAuthorityServiceFixture(t)
			s, err := OpenAuthorityService(context.Background(), c)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "pending handler" {
				s.handler.mu.Lock()
				s.handler.active = 1
				s.handler.mu.Unlock()
			} else {
				s.listener.Listener = authorityFailCloseListener{s.listener.Listener}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			err = s.Shutdown(ctx)
			cancel()
			if err == nil {
				t.Fatal("uncertain shutdown reported success")
			}
			firstError := err.Error()
			if strings.Contains(firstError, "secret") {
				t.Fatal("raw close error leaked")
			}
			if kind == "pending handler" {
				s.handler.leave()
			}
			if err = s.Shutdown(context.Background()); err == nil || err.Error() != firstError {
				t.Fatal("second shutdown lost original uncertainty")
			}
			if s.store.closed || !s.store.rawLockHeld {
				t.Fatal("uncertainty released lifetime authority")
			}
			if other, err := OpenStore(c.storeConfig(c.loaded)); err == nil {
				other.Close()
				t.Fatal("second shutdown released flock")
			} else if err.Error() != "ownership_instance_locked" {
				t.Fatal(err)
			}
		})
	}
}

func TestAuthorityServiceShutdownBreaksActualBodyRead(t *testing.T) {
	f := fixture(t)
	c, _ := initializedAuthorityServiceFixture(t)
	s, err := OpenAuthorityService(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(context.Background()) }()
	client := authorityServiceClient(t, true)
	request, _ := json.Marshal(HTTPReserveRequest{1, strings.Repeat("1", 32), "sample.fastq"})
	response, err := client.Post("https://"+s.Addr().String()+"/v1/reservations", "application/json", bytes.NewReader(request))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(response.Body)
	response.Body.Close()
	var ch SignedChallenge
	if err = json.Unmarshal(raw, &ch); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 200 {
		t.Fatalf("reserve failed: %d", response.StatusCode)
	}
	verified, err := VerifyChallengeForClient(raw, f.pin, f.certA, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	body := bytes.Repeat([]byte("x"), 32)
	manifest, err := SignManifest(f.keyA, f.certA, verified, ManifestInput{digest(body), 32, strings.Repeat("4", 64)})
	if err != nil {
		t.Fatal(err)
	}
	manifestRaw, _ := MarshalManifest(manifest)
	frame := make([]byte, 4)
	binary.BigEndian.PutUint32(frame, uint32(len(raw)))
	frame = append(frame, raw...)
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(manifestRaw)))
	frame = append(frame, length...)
	frame = append(frame, manifestRaw...)
	conn, err := tls.Dial("tcp", s.Addr().String(), client.Transport.(*http.Transport).TLSClientConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err = fmt.Fprintf(conn, "POST /v1/finalizations HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", len(frame)+32); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Write(frame); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for s.store.Snapshot().Reading != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if s.store.Snapshot().Reading != 1 {
		t.Fatal("real body read did not start")
	}
	started := time.Now()
	if err = s.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if time.Since(started) > AuthorityServiceShutdownBudget {
		t.Fatal("shutdown did not break body read")
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(c.storeConfig(c.loaded))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	record, err := store.Get(&f.stateA, ch.Claim.JobID)
	if err != nil || record.State != "rejected" {
		t.Fatal("cancelled actual body was accepted or adopted")
	}
}
