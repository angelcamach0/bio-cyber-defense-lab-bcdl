//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package ownership

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func publicationServiceFixture(t *testing.T) (PublicationServiceConfig, string, []byte) {
	t.Helper()
	f, a, scope := acceptanceFixture(t, false)
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	asset := func(name string, raw []byte) AuthorityServiceAsset {
		p := filepath.Join(root, name)
		if err := os.WriteFile(p, raw, 0600); err != nil {
			t.Fatal(err)
		}
		return AuthorityServiceAsset{p, digest(raw)}
	}
	ca := f.stateB.VerifiedChains[0][len(f.stateB.VerifiedChains[0])-1]
	c := PublicationServiceConfig{SchemaVersion: 1, ListenAddress: "127.0.0.1:0", StateDirectory: filepath.Join(root, "publication"), AuthorityID: f.pin.AuthorityID, PublicKeyHex: hex.EncodeToString(f.pin.PublicKey), PipelineMode: f.pin.PipelineMode, ExecutionProfileSHA256: f.pin.ExecutionProfileSHA256, ExpectedAuthorityScope: scope, ProducerCredentialSHA256: []string{digest(f.certB.Raw)}, TLSCertificate: asset("server.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.certA.Raw})), TLSPrivateKey: asset("server.key", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(f.keyA)})), ProducerCA: asset("producer-ca.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}))}
	path := filepath.Join(root, "publication.json")
	publicationWriteServiceFixture(t, path, c)
	raw, err := MarshalAcceptance(a)
	if err != nil {
		t.Fatal(err)
	}
	return c, path, raw
}
func publicationWriteServiceFixture(t *testing.T, path string, c PublicationServiceConfig) {
	t.Helper()
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}
func publicationInitializedFixture(t *testing.T) (PublicationServiceConfig, []byte) {
	t.Helper()
	c, path, raw := publicationServiceFixture(t)
	loaded, err := LoadPublicationServiceConfig(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := InitializePublicationStore(context.Background(), loaded)
	if err != nil {
		t.Fatal(err)
	}
	c.ExpectedPublisherScope = scope
	publicationWriteServiceFixture(t, path, c)
	loaded, err = LoadPublicationServiceConfig(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	return loaded, raw
}
func publicationTestClient(t *testing.T, certificate bool) *http.Client {
	t.Helper()
	f := fixture(t)
	pool := x509.NewCertPool()
	pool.AddCert(f.stateB.VerifiedChains[0][len(f.stateB.VerifiedChains[0])-1])
	cfg := &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}}
	if certificate {
		cfg.Certificates = []tls.Certificate{{Certificate: [][]byte{f.certB.Raw}, PrivateKey: f.keyB}}
	}
	transport := &http.Transport{TLSClientConfig: cfg, DisableKeepAlives: true, DisableCompression: true, ForceAttemptHTTP2: false}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 6 * time.Second}
}
func publicationRunService(t *testing.T, c PublicationServiceConfig, setup func(*PublicationService)) (*PublicationService, string) {
	t.Helper()
	service, err := OpenPublicationService(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if setup != nil {
		setup(service)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := service.Shutdown(context.Background()); err != nil {
			t.Error(err)
		}
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(6 * time.Second):
			t.Error("Serve not joined")
		}
	})
	return service, "https://" + service.Addr().String()
}

func TestPublicationServiceConfigClosedPrivateNoSideEffects(t *testing.T) {
	c, path, _ := publicationServiceFixture(t)
	raw, _ := json.Marshal(c)
	for _, test := range []struct {
		name string
		raw  []byte
	}{
		{"unknown", append([]byte(`{"extra":0,`), raw[1:]...)},
		{"duplicate", append([]byte(`{"schema_version":1,`), raw[1:]...)},
		{"case", []byte(strings.Replace(string(raw), `"schema_version"`, `"Schema_version"`, 1))},
		{"null", []byte(strings.Replace(string(raw), `"producer_credential_sha256":["`+c.ProducerCredentialSHA256[0]+`"]`, `"producer_credential_sha256":null`, 1))},
		{"trailing", append(append([]byte(nil), raw...), []byte("{}")...)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := os.WriteFile(path, test.raw, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadPublicationServiceConfig(context.Background(), path); err == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
	publicationWriteServiceFixture(t, path, c)
	loaded, err := LoadPublicationServiceConfig(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(c.StateDirectory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("Load created publication state")
	}
	if loaded.loaded.tls.MinVersion != tls.VersionTLS13 || loaded.loaded.tls.MaxVersion != tls.VersionTLS13 || loaded.loaded.tls.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatal("producer TLS not fixed")
	}
	if _, err = OpenPublicationService(context.Background(), loaded); err == nil {
		t.Fatal("serve adopted absent scope")
	}
	loaded.ListenAddress = "0.0.0.0:0"
	if _, err = loadPublicationMaterial(context.Background(), loaded); err == nil {
		t.Fatal("cached material changed")
	}
	if err = os.Chmod(path, 0640); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadPublicationServiceConfig(context.Background(), path); err == nil {
		t.Fatal("unsafe config mode accepted")
	}
}
func TestPublicationServiceConfigRolesAndOverlap(t *testing.T) {
	for _, name := range []string{"server_leaf_as_producer", "duplicate_producer", "asset_overlap", "config_overlap", "symlink", "unscoped", "partial_scope"} {
		t.Run(name, func(t *testing.T) {
			c, path, _ := publicationServiceFixture(t)
			switch name {
			case "server_leaf_as_producer":
				c.ProducerCredentialSHA256 = []string{digest(fixture(t).certA.Raw)}
			case "duplicate_producer":
				c.ProducerCredentialSHA256 = append(c.ProducerCredentialSHA256, c.ProducerCredentialSHA256[0])
			case "asset_overlap":
				c.StateDirectory = filepath.Dir(c.TLSPrivateKey.Path)
			case "config_overlap":
				c.StateDirectory = path
			case "symlink":
				alias := filepath.Join(filepath.Dir(path), "alias.key")
				if err := os.Symlink(c.TLSPrivateKey.Path, alias); err != nil {
					t.Fatal(err)
				}
				c.TLSPrivateKey.Path = alias
			case "unscoped":
				c.ExpectedAuthorityScope = AcceptanceScope{}
			case "partial_scope":
				c.ExpectedPublisherScope.PublisherID = strings.Repeat("a", 32)
			}
			publicationWriteServiceFixture(t, path, c)
			if _, err := LoadPublicationServiceConfig(context.Background(), path); err == nil {
				t.Fatal("unsafe publication config accepted")
			}
		})
	}
}
func TestPublicationServiceExplicitGenesisAndReopen(t *testing.T) {
	c, raw := publicationInitializedFixture(t)
	service, url := publicationRunService(t, c, nil)
	client := publicationTestClient(t, true)
	f := fixture(t)
	a, err := VerifyAcceptance(raw, f.pin, c.ExpectedAuthorityScope)
	if err != nil {
		t.Fatal(err)
	}
	path := "/v1/acceptances/" + a.Binding().JobID + "/" + a.SHA256()
	req, _ := http.NewRequest("POST", url+path, strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("publication %d %s", res.StatusCode, body)
	}
	if service.InboxDirectory() != filepath.Join(c.StateDirectory, "inbox") || service.Scope() != c.ExpectedPublisherScope {
		t.Fatal("operator scope/inbox changed")
	}
	if err = service.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = service.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenPublicationStore(c.storeConfig(c.loaded))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	receipt, err := reopened.Get(context.Background(), &f.stateB, a.Binding().JobID, a.SHA256())
	if err != nil {
		t.Fatal(err)
	}
	var actual PublicationReceipt
	if json.Unmarshal(body, &actual) != nil || !reflect.DeepEqual(receipt, actual) {
		t.Fatal("cold receipt changed")
	}
	if _, err = InitializePublicationStore(context.Background(), c); err == nil {
		t.Fatal("existing scope reinitialized")
	}
}
func TestPublicationServiceCancelBeforeServe(t *testing.T) {
	c, _ := publicationInitializedFixture(t)
	service, err := OpenPublicationService(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan error, 1)
	go func() { done <- service.Serve(ctx) }()
	if err = service.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("early cancellation left Serve")
	}
}

type publicationCloseFaultListener struct {
	net.Listener
	calls int
}

func (l *publicationCloseFaultListener) Close() error {
	l.calls++
	l.Listener.Close()
	return errors.New("injected_listener_cleanup_fault")
}
func TestPublicationServiceFirstCloseErrorPersistsAfterHealthyDrain(t *testing.T) {
	c, _ := publicationInitializedFixture(t)
	service, err := OpenPublicationService(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	fault := &publicationCloseFaultListener{Listener: service.listener.Listener}
	service.listener.Listener = fault
	done := make(chan error, 1)
	go func() { done <- service.Serve(context.Background()) }()
	first := service.Shutdown(context.Background())
	if first == nil {
		t.Fatal("listener cleanup error hidden")
	}
	select {
	case <-done:
	case <-time.After(6 * time.Second):
		t.Fatal("Serve not joined after close fault")
	}
	if second := service.Shutdown(context.Background()); second != first || fault.calls != 1 {
		t.Fatal("first close error lost or cleanup repeated")
	}
	if !service.store.closed || service.store.sticky {
		t.Fatal("cleanup fault was misclassified as storage fault")
	}
	reopened, err := OpenPublicationStore(c.storeConfig(c.loaded))
	if err != nil {
		t.Fatal("healthy quiescent Store not released")
	}
	reopened.Close()
}
