//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package ownership

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// This fixture reuses the protocol's dual-EKU synthetic leaf. Runtime client/
// server role isolation is separately covered by the uploader CLI integration.
func ownerServiceFixture(t *testing.T, scope AcceptanceScope) (OwnerIngressServiceConfig, string) {
	t.Helper()
	base, path := authorityServiceFixture(t)
	if scope == (AcceptanceScope{}) {
		scope = AcceptanceScope{strings.Repeat("3", 32), strings.Repeat("4", 64)}
	}
	c := OwnerIngressServiceConfig{SchemaVersion: 1, ListenAddress: "127.0.0.1:0", StoreRoot: filepath.Join(filepath.Dir(path), "ingress"), Namespace: "transport-test", AuthorityID: base.AuthorityID, PublicKeyHex: base.PublicKeyHex, PipelineMode: base.PipelineMode, ExecutionProfileSHA256: base.ExecutionProfileSHA256, ExpectedScope: scope, Policy: DefaultOwnerIngressPolicy(), TLSCertificate: base.TLSCertificate, TLSPrivateKey: base.TLSPrivateKey, ClientCA: base.ClientCA}
	c.Policy.MaxBodyBytes = 64
	path = filepath.Join(filepath.Dir(path), "owner-service.json")
	writeOwnerServiceFixture(t, path, c)
	return c, path
}
func writeOwnerServiceFixture(t *testing.T, path string, c OwnerIngressServiceConfig) {
	t.Helper()
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if os.WriteFile(path, raw, 0600) != nil {
		t.Fatal("write service fixture")
	}
}
func initializedOwnerServiceFixture(t *testing.T, scope AcceptanceScope) OwnerIngressServiceConfig {
	t.Helper()
	_, path := ownerServiceFixture(t, scope)
	c, err := LoadOwnerIngressServiceConfig(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if err = InitializeOwnerIngress(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestOwnerIngressServiceConfigNoImplicitGenesis(t *testing.T) {
	c, path := ownerServiceFixture(t, AcceptanceScope{})
	loaded, err := LoadOwnerIngressServiceConfig(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(c.StoreRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("Load created transport history")
	}
	if _, err = OpenOwnerIngressService(context.Background(), loaded); err == nil {
		t.Fatal("Open initialized missing history")
	}
	if err = InitializeOwnerIngress(context.Background(), loaded); err != nil {
		t.Fatal(err)
	}
	before := fileBytes(t, filepath.Join(c.StoreRoot, "ledger.json"))
	if err = InitializeOwnerIngress(context.Background(), loaded); err == nil {
		t.Fatal("genesis adopted existing state")
	}
	after := fileBytes(t, filepath.Join(c.StoreRoot, "ledger.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("reinitialization changed history")
	}
	mutated := loaded
	mutated.Namespace = "changed"
	if _, err = OpenOwnerIngressService(context.Background(), mutated); err == nil {
		t.Fatal("cached config accepted mutation")
	}
	service, err := OpenOwnerIngressService(context.Background(), loaded)
	if err != nil {
		t.Fatal(err)
	}
	if service.StoreScope() != loaded.ExpectedScope || service.server.TLSConfig.MinVersion != tls.VersionTLS13 || service.server.TLSConfig.ClientAuth != tls.RequireAndVerifyClientCert || cap(service.listener.slots) != 8 {
		t.Fatal("service security settings")
	}
	if err = service.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestOwnerIngressServiceRejectsStrictConfigAndUnsafeAssets(t *testing.T) {
	for _, kind := range []string{"duplicate", "case alias", "missing", "null", "unknown signing key", "trailing", "nested null", "empty scope", "bad policy", "wildcard", "DNS listen", "asset hash", "key mismatch", "private mode", "FIFO", "symlink", "ancestor symlink", "hardlink", "parent mode"} {
		t.Run(kind, func(t *testing.T) {
			c, path := ownerServiceFixture(t, AcceptanceScope{})
			raw := fileBytes(t, path)
			rawChange := false
			switch kind {
			case "duplicate":
				raw = append([]byte(`{"schema_version":1,`), raw[1:]...)
				rawChange = true
			case "case alias":
				raw = bytes.Replace(raw, []byte(`"namespace"`), []byte(`"Namespace"`), 1)
				rawChange = true
			case "missing":
				raw = bytes.Replace(raw, []byte(`"schema_version":1,`), nil, 1)
				rawChange = true
			case "null":
				raw = bytes.Replace(raw, []byte(`"schema_version":1`), []byte(`"schema_version":null`), 1)
				rawChange = true
			case "unknown signing key":
				raw = append([]byte(`{"signing_key":{"path":"unused","sha256":"unused"},`), raw[1:]...)
				rawChange = true
			case "trailing":
				raw = append(raw, []byte(`{}`)...)
				rawChange = true
			case "nested null":
				raw = bytes.Replace(raw, []byte(`"max_jobs":64`), []byte(`"max_jobs":null`), 1)
				rawChange = true
			case "empty scope":
				c.ExpectedScope = AcceptanceScope{}
				writeOwnerServiceFixture(t, path, c)
			case "bad policy":
				c.Policy.MaxActive = 0
				writeOwnerServiceFixture(t, path, c)
			case "wildcard":
				c.ListenAddress = "0.0.0.0:0"
				writeOwnerServiceFixture(t, path, c)
			case "DNS listen":
				c.ListenAddress = "localhost:0"
				writeOwnerServiceFixture(t, path, c)
			case "asset hash":
				c.TLSPrivateKey.SHA256 = strings.Repeat("0", 64)
				writeOwnerServiceFixture(t, path, c)
			case "key mismatch":
				b := fileBytes(t, c.TLSCertificate.Path)
				os.WriteFile(c.TLSPrivateKey.Path, b, 0600)
				c.TLSPrivateKey.SHA256 = digest(b)
				writeOwnerServiceFixture(t, path, c)
			case "private mode":
				os.Chmod(c.TLSPrivateKey.Path, 0644)
			case "FIFO":
				os.Remove(path)
				syscall.Mkfifo(path, 0600)
			case "symlink":
				os.Remove(path)
				os.Symlink(c.TLSCertificate.Path, path)
			case "ancestor symlink":
				alias := filepath.Join(t.TempDir(), "alias")
				os.Symlink(filepath.Dir(path), alias)
				path = filepath.Join(alias, filepath.Base(path))
			case "hardlink":
				os.Link(path, filepath.Join(filepath.Dir(path), "extra-link"))
			case "parent mode":
				os.Chmod(filepath.Dir(path), 0755)
			}
			if rawChange && os.WriteFile(path, raw, 0600) != nil {
				t.Fatal("negative config fixture")
			}
			started := time.Now()
			if _, err := LoadOwnerIngressServiceConfig(context.Background(), path); err == nil {
				t.Fatal("invalid/unsafe config accepted")
			}
			if time.Since(started) > time.Second {
				t.Fatal("unsafe file blocked")
			}
			if _, err := os.Stat(c.StoreRoot); !os.IsNotExist(err) {
				t.Fatal("invalid config initialized state")
			}
		})
	}
}

func TestOwnerIngressServiceActualMTLSAndCachedAssets(t *testing.T) {
	c := initializedOwnerServiceFixture(t, AcceptanceScope{})
	if os.WriteFile(c.TLSPrivateKey.Path, []byte("changed after load"), 0600) != nil {
		t.Fatal("cache fixture")
	}
	service, err := OpenOwnerIngressService(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- service.Serve(context.Background()) }()
	client := authorityServiceClient(t, true)
	response, err := client.Get("https://" + service.Addr().String() + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 200 || response.Proto != "HTTP/1.1" || !response.Close || response.TLS.Version < tls.VersionTLS13 {
		t.Fatal("verified health contract")
	}
	if res, e := authorityServiceClient(t, false).Get("https://" + service.Addr().String() + "/healthz"); e == nil {
		res.Body.Close()
		t.Fatal("mTLS not required")
	}
	if err = service.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenOwnerIngressService(context.Background(), c)
	if err != nil {
		t.Fatal("clean restart", err)
	}
	if reopened.Shutdown(context.Background()) != nil {
		t.Fatal("restart close")
	}
}

func TestOwnerIngressServiceShutdownGateAndStickyCustody(t *testing.T) {
	for _, kind := range []string{"queued deadline", "pending handler", "listener close"} {
		t.Run(kind, func(t *testing.T) {
			c := initializedOwnerServiceFixture(t, AcceptanceScope{})
			s, err := OpenOwnerIngressService(context.Background(), c)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "queued deadline" {
				s.shutdownGate <- struct{}{}
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
				started := time.Now()
				err = s.Shutdown(ctx)
				cancel()
				<-s.shutdownGate
				if err == nil || time.Since(started) > time.Second || s.store.closed {
					t.Fatal("queued Shutdown exceeded caller budget")
				}
				if s.Shutdown(context.Background()) != nil {
					t.Fatal("healthy final close")
				}
				return
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
				t.Fatal("uncertain Shutdown succeeded")
			}
			original := err.Error()
			if strings.Contains(original, "secret") {
				t.Fatal("raw listener error leaked")
			}
			if kind == "pending handler" {
				s.handler.leave()
			}
			if err = s.Shutdown(context.Background()); err == nil || err.Error() != original {
				t.Fatal("second Shutdown cleared uncertainty")
			}
			if s.store.closed || !s.store.rawHeld {
				t.Fatal("uncertain Shutdown released lifetime lock")
			}
			if other, e := OpenOwnerIngress(c.ingressConfig(c.loaded)); e == nil {
				other.Close()
				t.Fatal("uncertainty allowed another live writer")
			} else if e.Error() != "ownership_ingress_locked" {
				t.Fatal(e)
			}
		})
	}
}

func TestOwnerIngressServiceConnectionLimit(t *testing.T) {
	c := initializedOwnerServiceFixture(t, AcceptanceScope{})
	s, err := OpenOwnerIngressService(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(context.Background()) }()
	conns := []net.Conn{}
	defer func() {
		for _, conn := range conns {
			conn.Close()
		}
	}()
	for i := 0; i < 9; i++ {
		conn, e := net.DialTimeout("tcp", s.Addr().String(), time.Second)
		if e != nil {
			t.Fatal(e)
		}
		conns = append(conns, conn)
	}
	deadline := time.Now().Add(time.Second)
	for len(s.listener.slots) != 8 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(s.listener.slots) != 8 {
		t.Fatal("TLS/idle connections not counted")
	}
	conns[8].SetDeadline(time.Now().Add(time.Second))
	ninth := tls.Client(conns[8], authorityServiceClient(t, true).Transport.(*http.Transport).TLSClientConfig)
	handshake := make(chan error, 1)
	go func() { handshake <- ninth.Handshake() }()
	select {
	case e := <-handshake:
		t.Fatal("ninth handshake admitted early", e)
	case <-time.After(40 * time.Millisecond):
	}
	conns[0].Close()
	select {
	case e := <-handshake:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("freed slot not admitted")
	}
	ninth.Close()
	if err = s.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}

func TestOwnerIngressServiceShutdownBreaksActualCipherRead(t *testing.T) {
	f := fixture(t)
	authority, _ := storeFixture(t, DefaultStorePolicy())
	signed := storeReserve(t, authority, 5501)
	ch, _ := MarshalChallenge(signed)
	verified, err := VerifyChallengeForClient(ch, f.pin, f.certA, f.now)
	if err != nil {
		t.Fatal(err)
	}
	body := bytes.Repeat([]byte{7}, 32)
	envelope := bytes.Repeat([]byte{9}, 256)
	manifest, err := SignManifest(f.keyA, f.certA, verified, ManifestInput{digest(body), 32, digest(envelope)})
	if err != nil {
		t.Fatal(err)
	}
	m, _ := MarshalManifest(manifest)
	accepted, err := authority.Finalize(context.Background(), &f.stateA, ch, m, bytes.NewReader(body), f.now)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := MarshalAcceptance(accepted)
	c := initializedOwnerServiceFixture(t, authority.Scope())
	s, err := OpenOwnerIngressService(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(context.Background()) }()
	conn, err := tls.Dial("tcp", s.Addr().String(), authorityServiceClient(t, true).Transport.(*http.Transport).TLSClientConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var frame bytes.Buffer
	binary.Write(&frame, binary.BigEndian, uint32(len(raw)))
	frame.Write(raw)
	binary.Write(&frame, binary.BigEndian, uint32(len(envelope)))
	frame.Write(envelope)
	if _, err = fmt.Fprintf(conn, "POST /v1/uploads HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", frame.Len()+32); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Write(frame.Bytes()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for s.store.Snapshot().Reading != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if s.store.Snapshot().Reading != 1 {
		t.Fatal("actual ciphertext body read not reached")
	}
	charge := s.store.Snapshot().ChargedBytes
	started := time.Now()
	if err = s.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if time.Since(started) > OwnerIngressServiceShutdownBudget {
		t.Fatal("Shutdown did not break read within budget")
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenOwnerIngress(c.ingressConfig(c.loaded))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	snapshot := reopened.Snapshot()
	if snapshot.Rejected != 1 || snapshot.Reading != 0 || snapshot.Delivered != 0 || snapshot.ChargedBytes != charge {
		t.Fatal("cancellation lost retained charge or published delivery")
	}
}
