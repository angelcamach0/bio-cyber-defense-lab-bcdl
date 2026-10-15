//go:build linux

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func ownerResultsTestConfig(t *testing.T, f *ownerResultsTestFixture) (ownerResultsConfig, string) {
	t.Helper()
	c := f.material.config
	policy, _ := json.Marshal(f.material.policy)
	assets := []struct {
		name   string
		raw    []byte
		target *ownerResultsAsset
	}{{"server.pem", f.certRaw, &c.TLSCertificate}, {"server.key", f.keyRaw, &c.TLSPrivateKey}, {"client-ca.pem", f.caRaw, &c.ClientCA}, {"projection.json", policy, &c.ProjectionPolicy}}
	for _, a := range assets {
		path := filepath.Join(f.root, a.name)
		if e := os.WriteFile(path, a.raw, 0600); e != nil {
			t.Fatal(e)
		}
		*a.target = ownerResultsAsset{Path: path, SHA256: ownerResultsDigest(a.raw)}
	}
	return c, filepath.Join(f.root, "results-config.json")
}

func ownerResultsTestWriteConfig(t *testing.T, path string, c ownerResultsConfig) {
	t.Helper()
	raw, e := json.Marshal(c)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
}

func TestOwnerResultsPrivatePinnedClosedConfig(t *testing.T) {
	f := newOwnerResultsTestFixture(t)
	c, path := ownerResultsTestConfig(t, f)
	ownerResultsTestWriteConfig(t, path, c)
	m, e := loadOwnerResultsConfig(context.Background(), path)
	if e != nil || m.tls.MinVersion != tls.VersionTLS13 || m.tls.MaxVersion != tls.VersionTLS13 || m.tls.ClientAuth != tls.RequireAndVerifyClientCert || !m.tls.SessionTicketsDisabled {
		t.Fatal("valid strict config", e)
	}
	for name, mutate := range map[string]func(*ownerResultsConfig){
		"schema": func(c *ownerResultsConfig) { c.SchemaVersion = 2 }, "protocol": func(c *ownerResultsConfig) { c.Protocol = "legacy" }, "scope": func(c *ownerResultsConfig) { c.ExpectedScope.StoreID = "" }, "profile": func(c *ownerResultsConfig) { c.ExecutionProfileSHA256 = strings.Repeat("8", 64) }, "mode": func(c *ownerResultsConfig) { c.PipelineMode = "variants" }, "authority": func(c *ownerResultsConfig) { c.PublicKeyHex = "00" }, "asset_pin": func(c *ownerResultsConfig) { c.ClientCA.SHA256 = strings.Repeat("8", 64) }, "asset_overlap": func(c *ownerResultsConfig) {
			c.TLSPrivateKey.Path = filepath.Join(c.AcceptancesDirectory, "private.key")
		}, "different_uid": func(c *ownerResultsConfig) { c.ExpectedBrokerUID++ }, "acceptance_uid": func(c *ownerResultsConfig) { c.ExpectedAcceptancesUID++ }, "socket_basename": func(c *ownerResultsConfig) {
			c.ReaderSocket = filepath.Join(filepath.Dir(c.ReaderSocket), "reader bad.sock")
		},
		"socket_name_length": func(c *ownerResultsConfig) {
			c.ReaderSocket = filepath.Join(filepath.Dir(c.ReaderSocket), strings.Repeat("r", 65))
		},
		"socket_overlap": func(c *ownerResultsConfig) { c.ReaderSocket = filepath.Join(c.AcceptancesDirectory, "reader.sock") }, "address": func(c *ownerResultsConfig) { c.Address = "https://localhost:8082" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := c
			mutate(&bad)
			ownerResultsTestWriteConfig(t, path, bad)
			if _, e := loadOwnerResultsConfig(context.Background(), path); e == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
	ownerResultsTestWriteConfig(t, path, c)
	raw, _ := json.Marshal(c)
	for name, bad := range map[string][]byte{"null": []byte(strings.Replace(string(raw), `"expected_broker_uid":`+jsonNumber(c.ExpectedBrokerUID), `"expected_broker_uid":null`, 1)), "case": []byte(strings.Replace(string(raw), `"schema_version"`, `"Schema_Version"`, 1)), "duplicate": []byte(strings.Replace(string(raw), `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1)), "unknown": []byte(strings.Replace(string(raw), `"schema_version":1`, `"store_root":"/private","schema_version":1`, 1)), "trailing": append(append([]byte(nil), raw...), []byte(` {}`)...), "utf8": append(append([]byte(nil), raw...), 0xff)} {
		t.Run(name, func(t *testing.T) {
			os.WriteFile(path, bad, 0600)
			if _, e := loadOwnerResultsConfig(context.Background(), path); e == nil {
				t.Fatal("nonclosed config accepted")
			}
		})
	}
	ownerResultsTestWriteConfig(t, path, c)
	os.Chmod(path, 0640)
	if _, e := loadOwnerResultsConfig(context.Background(), path); e == nil {
		t.Fatal("unsafe config mode accepted")
	}
	os.Chmod(path, 0600)
	os.Chmod(f.root, 0750)
	if _, e := loadOwnerResultsConfig(context.Background(), path); e == nil {
		t.Fatal("unsafe parent directory accepted")
	}
	os.Chmod(f.root, 0700)
}

func jsonNumber(n uint32) string { b, _ := json.Marshal(n); return string(b) }

func TestOwnerResultsSelectorClosedBeforeLegacyEffects(t *testing.T) {
	lookup := func(m map[string]string) func(string) (string, bool) {
		return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
	}
	for _, protocol := range []string{"", "legacy"} {
		handled, _, e := selectOwnerResults(lookup(map[string]string{"BIOZERO_RESULTS_PROTOCOL": protocol}))
		if handled || e != nil {
			t.Fatal("legacy compatibility changed")
		}
	}
	for _, m := range []map[string]string{{"BIOZERO_RESULTS_PROTOCOL": "unknown"}, {"BIOZERO_OWNER_RESULTS_CONFIG": "/private/config"}, {"BIOZERO_RESULTS_PROTOCOL": "legacy", "BIOZERO_OWNER_RESULTS_CONFIG": "/private/config"}, {"BIOZERO_RESULTS_PROTOCOL": "owner-v1"}} {
		handled, _, e := selectOwnerResults(lookup(m))
		if !handled || e == nil {
			t.Fatal("invalid selector fell back")
		}
	}
	for _, key := range []string{"BIOZERO_DATA_DIR", "BIOZERO_RESULTS_ADDR", "BIOZERO_TLS_CERT", "BIOZERO_TLS_KEY", "BIOZERO_TLS_CA", "BIOZERO_RATE_LIMIT", "BIOZERO_SECURITY_MODE"} {
		m := map[string]string{"BIOZERO_RESULTS_PROTOCOL": "owner-v1", "BIOZERO_OWNER_RESULTS_CONFIG": "/private/config", key: ""}
		if _, _, e := selectOwnerResults(lookup(m)); e == nil {
			t.Fatal("mixed env accepted", key)
		}
	}
	canary := filepath.Join(t.TempDir(), "legacy-created")
	cmd := exec.Command(os.Args[0], "-test.run=^TestOwnerResultsSelectorChild$")
	cmd.Env = []string{"BIOZERO_OWNER_RESULTS_SELECTOR_CHILD=1", "BIOZERO_RESULTS_PROTOCOL=unknown", "BIOZERO_DATA_DIR=" + canary}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd = exec.CommandContext(ctx, cmd.Path, cmd.Args[1:]...)
	cmd.Env = []string{"BIOZERO_OWNER_RESULTS_SELECTOR_CHILD=1", "BIOZERO_RESULTS_PROTOCOL=unknown", "BIOZERO_DATA_DIR=" + canary}
	if e := cmd.Run(); e == nil {
		t.Fatal("invalid selector process exited success")
	}
	if _, e := os.Lstat(canary); !os.IsNotExist(e) {
		t.Fatal("legacy mkdir preceded selector")
	}
}

func TestOwnerResultsSelectorChild(t *testing.T) {
	if os.Getenv("BIOZERO_OWNER_RESULTS_SELECTOR_CHILD") != "1" {
		return
	}
	os.Args = []string{"results-api"}
	main()
	os.Exit(99)
}

type ownerResultsBarrierListener struct {
	net.Listener
	entered   chan struct{}
	release   chan struct{}
	enterOnce sync.Once
	closeOnce sync.Once
}

func (l *ownerResultsBarrierListener) Accept() (net.Conn, error) {
	l.enterOnce.Do(func() { close(l.entered) })
	<-l.release
	return l.Listener.Accept()
}
func (l *ownerResultsBarrierListener) Close() error {
	l.closeOnce.Do(func() { close(l.release) })
	return l.Listener.Close()
}

func TestOwnerResultsShutdownJoinsLaunchedServe(t *testing.T) {
	f := newOwnerResultsTestFixture(t)
	for _, preCancelled := range []bool{true, false} {
		l, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		barrier := &ownerResultsBarrierListener{Listener: l, entered: make(chan struct{}), release: make(chan struct{})}
		s, e := newOwnerResultsService(context.Background(), barrier, f.material)
		if e != nil {
			t.Fatal(e)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if preCancelled {
			cancel()
		}
		done := make(chan error, 1)
		go func() { done <- serveOwnerResults(ctx, s) }()
		if !preCancelled {
			select {
			case <-barrier.entered:
			case <-time.After(time.Second):
				t.Fatal("Serve never reached Accept")
			}
			cancel()
		}
		select {
		case e := <-done:
			if e != nil {
				t.Fatal("clean cancellation", e)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("Serve was not joined")
		}
		select {
		case <-s.done:
		default:
			t.Fatal("shutdown returned before launched Serve finished")
		}
		if _, e := s.handler.inbox.Stat(); e == nil {
			t.Fatal("healthy shutdown retained inbox descriptor")
		}
	}
}

func TestOwnerResultsUnexpectedListenerFailureRetainsFirstError(t *testing.T) {
	f := newOwnerResultsTestFixture(t)
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	s, e := newOwnerResultsService(context.Background(), l, f.material)
	if e != nil {
		t.Fatal(e)
	}
	l.Close()
	if e := s.Serve(); e == nil {
		t.Fatal("unexpected accept failure was hidden")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	a, b := s.Shutdown(ctx), s.Shutdown(ctx)
	if a == nil || b == nil || a.Error() != b.Error() {
		t.Fatal("terminal failure disappeared across shutdown")
	}
}
