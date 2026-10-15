//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	projection "biozero/enclave-runner/receiptprojection"
	ownership "biozero/ownership-authority"
)

type ogConfigTestFixture struct {
	root, path string
	config     ownerGatewayConfig
	serverTLS  *tls.Config
	pool       *x509.CertPool
	store      *ownership.Store
	keys       map[string]*rsa.PrivateKey
	certs      map[string]tls.Certificate
	leaves     map[string]*x509.Certificate
	input      []byte
}

func ogNewConfigFixture(t *testing.T) *ogConfigTestFixture {
	t.Helper()
	f := &ogConfigTestFixture{root: t.TempDir(), keys: map[string]*rsa.PrivateKey{}, certs: map[string]tls.Certificate{}, leaves: map[string]*x509.Certificate{}, input: []byte("@synthetic\nACGT\n+\nIIII\n")}
	os.Chmod(f.root, 0700)
	generate := func() *rsa.PrivateKey {
		k, e := rsa.GenerateKey(rand.Reader, 2048)
		if e != nil {
			t.Fatal(e)
		}
		return k
	}
	caKey := generate()
	now := time.Now()
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "gateway-fixture-ca"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, e := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if e != nil {
		t.Fatal(e)
	}
	ca, e := x509.ParseCertificate(caDER)
	if e != nil {
		t.Fatal(e)
	}
	f.pool = x509.NewCertPool()
	f.pool.AddCert(ca)
	leaf := func(id string, server bool) {
		key := generate()
		c := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "equal-cn-serial"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		if server {
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			c.DNSNames = []string{"localhost"}
			c.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		}
		der, e := x509.CreateCertificate(rand.Reader, c, ca, &key.PublicKey, caKey)
		if e != nil {
			t.Fatal(e)
		}
		parsed, e := x509.ParseCertificate(der)
		if e != nil {
			t.Fatal(e)
		}
		f.keys[id] = key
		f.leaves[id] = parsed
		f.certs[id] = tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	}
	leaf("server", true)
	leaf("a", false)
	leaf("b", false)
	f.serverTLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{f.certs["server"]}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: f.pool, NextProtos: []string{"http/1.1"}}
	asset := func(name string, raw []byte) ownerGatewayAsset {
		path := filepath.Join(f.root, name)
		if e := os.WriteFile(path, raw, 0600); e != nil {
			t.Fatal(e)
		}
		return ownerGatewayAsset{Path: path, SHA256: ogConfigDigest(raw)}
	}
	caAsset := asset("ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	public, signer, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	pin := ownership.AuthorityPin{AuthorityID: strings.Repeat("1", 32), PublicKey: public, PipelineMode: "variants", ExecutionProfileSHA256: strings.Repeat("2", 64)}
	policy := ownership.DefaultStorePolicy()
	policy.MaxBodyBytes = 4096
	policy.FreeSpaceFloorBytes = 0
	f.store, e = ownership.CreateStore(ownership.StoreConfig{Directory: filepath.Join(f.root, "authority"), Namespace: "gateway-config-fixture", Pin: pin, SigningKey: signer, Policy: policy})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := f.store.Close(); e != nil {
			t.Error(e)
		}
	})
	h, e := ownership.NewHTTPHandler(ownership.HTTPHandlerConfig{Store: f.store})
	if e != nil {
		t.Fatal(e)
	}
	s := httptest.NewUnstartedServer(h)
	s.Config.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){}
	s.TLS = f.serverTLS.Clone()
	s.StartTLS()
	t.Cleanup(s.Close)
	reference := []byte(">synthetic\nACGT\n")
	pins := map[string]projection.SourcePin{}
	for _, name := range []string{"pipeline", "resource_budget", "analysis_executable", "analysis_rules", "evaluator", "truth"} {
		pins[name] = projection.SourcePin{SHA256: strings.Repeat("3", 64), Bytes: 1}
	}
	pins["reference"] = projection.SourcePin{SHA256: ogConfigDigest(reference), Bytes: int64(len(reference))}
	projectionPolicy := projection.Policy{SchemaVersion: 1, ProfileSHA256: pin.ExecutionProfileSHA256, PipelineMode: "variants", CapsuleKind: "native", SourcePins: pins}
	policyRaw, _ := json.Marshal(projectionPolicy)
	recipient := generate()
	publicDER, e := x509.MarshalPKIXPublicKey(&recipient.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	c := ownerGatewayConfig{SchemaVersion: 1, Protocol: "owner-v1", ListenAddress: "127.0.0.1:8443", PublicOrigin: "https://localhost:8443", StateDirectory: filepath.Join(f.root, "state"), ExpectedUID: uint32(os.Geteuid()), AuthorityURL: s.URL, UploadURL: "https://127.0.0.1:9444", ResultsURL: "https://127.0.0.1:9445", AuthorityServerName: "localhost", UploadServerName: "localhost", ResultsServerName: "localhost", AuthorityID: pin.AuthorityID, PublicKeyHex: hex.EncodeToString(public), PipelineMode: "variants", ExecutionProfileSHA256: pin.ExecutionProfileSHA256, ExpectedScope: f.store.Scope(), AuthorityCA: caAsset, UploadCA: caAsset, ResultsCA: caAsset, WorkerEncryptionPublicKey: asset("worker-public.pem", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})), ProjectionPolicy: asset("policy.json", policyRaw), UIAssets: map[string]ownerGatewayAsset{}}
	c.BrowserTLSCertificate = asset("browser-cert.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.leaves["server"].Raw}))
	c.BrowserTLSPrivateKey = asset("browser-key.pem", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(f.keys["server"])}))
	for _, id := range []string{"a", "b"} {
		c.Reviewers = append(c.Reviewers, ownerGatewayReviewerConfig{ID: id, Label: "Reviewer " + id, Enabled: true, AccessCodeSHA256: ogConfigDigest(bytes.Repeat([]byte(id), 32)), CredentialSHA256: ogConfigDigest(f.leaves[id].Raw), TLSCertificate: asset(id+"-cert.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.leaves[id].Raw})), TLSPrivateKey: asset(id+"-key.pem", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(f.keys[id])}))})
	}
	for _, name := range []string{"index.html", "app.js", "styles.css"} {
		c.UIAssets[name] = asset(name, []byte("synthetic UI asset "+name))
	}
	c.Experiments = []ownerGatewayExperimentConfig{{ID: "synthetic", Label: "Synthetic", Scope: "synthetic", OriginalName: "synthetic.fastq", Input: asset("input.fastq", f.input), Reference: asset("reference.fa", reference)}}
	f.config = c
	f.path = filepath.Join(f.root, "config.json")
	ogWriteConfig(t, f.path, c)
	return f
}

func ogWriteConfig(t *testing.T, path string, c ownerGatewayConfig) {
	t.Helper()
	raw, e := json.Marshal(c)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
}
func ogCloseMaterial(m ownerGatewayMaterial) {
	for _, r := range m.Reviewers {
		r.Results.Close()
	}
}

func TestOwnerGatewayConfigClosedPrivatePinsAndRoles(t *testing.T) {
	f := ogNewConfigFixture(t)
	m, e := loadOwnerGatewayConfig(context.Background(), f.path)
	if e != nil {
		t.Fatal(e)
	}
	defer ogCloseMaterial(m)
	if len(m.UI) != 3 || m.BrowserTLS.MinVersion != tls.VersionTLS13 || m.Reviewers["a"].CredentialSHA256 == m.Reviewers["b"].CredentialSHA256 {
		t.Fatal("configuration identity/material lost")
	}
	for name, mutate := range map[string]func(*ownerGatewayConfig){"protocol": func(c *ownerGatewayConfig) { c.Protocol = "legacy" }, "uid": func(c *ownerGatewayConfig) { c.ExpectedUID++ }, "wildcard": func(c *ownerGatewayConfig) { c.ListenAddress = "0.0.0.0:8443" }, "origin": func(c *ownerGatewayConfig) { c.PublicOrigin = "http://localhost:8443" }, "upstream_dns": func(c *ownerGatewayConfig) { c.ResultsURL = "https://results.example:443" }, "upstream_path": func(c *ownerGatewayConfig) { c.ResultsURL += "/results" }, "ui_extra": func(c *ownerGatewayConfig) {
		copyMap := map[string]ownerGatewayAsset{}
		for k, v := range c.UIAssets {
			copyMap[k] = v
		}
		copyMap["extra.js"] = copyMap["app.js"]
		c.UIAssets = copyMap
	}, "role_shared": func(c *ownerGatewayConfig) {
		copyRows := append([]ownerGatewayReviewerConfig(nil), c.Reviewers...)
		copyRows[1].TLSCertificate = copyRows[0].TLSCertificate
		copyRows[1].TLSPrivateKey = copyRows[0].TLSPrivateKey
		copyRows[1].CredentialSHA256 = copyRows[0].CredentialSHA256
		c.Reviewers = copyRows
	}, "pin": func(c *ownerGatewayConfig) { c.AuthorityCA.SHA256 = strings.Repeat("f", 64) }, "ui_key_alias": func(c *ownerGatewayConfig) {
		c.UIAssets = map[string]ownerGatewayAsset{"index.html": c.BrowserTLSPrivateKey, "app.js": c.UIAssets["app.js"], "styles.css": c.UIAssets["styles.css"]}
	},
		"ui_fixture_alias": func(c *ownerGatewayConfig) {
			c.UIAssets = map[string]ownerGatewayAsset{"index.html": c.Experiments[0].Input, "app.js": c.UIAssets["app.js"], "styles.css": c.UIAssets["styles.css"]}
		},
		"fixture_key_alias": func(c *ownerGatewayConfig) {
			c.Experiments = append([]ownerGatewayExperimentConfig(nil), c.Experiments...)
			c.Experiments[0].Input = c.Reviewers[0].TLSPrivateKey
		},
		"browser_host_mismatch": func(c *ownerGatewayConfig) { c.PublicOrigin = "https://127.0.0.2:8443" },
		"state_overlap":         func(c *ownerGatewayConfig) { c.StateDirectory = filepath.Dir(c.Reviewers[0].TLSPrivateKey.Path) }} {
		t.Run(name, func(t *testing.T) {
			bad := f.config
			mutate(&bad)
			ogWriteConfig(t, f.path, bad)
			if got, e := loadOwnerGatewayConfig(context.Background(), f.path); e == nil {
				ogCloseMaterial(got)
				t.Fatal("unsafe config accepted")
			}
		})
	}
	ogWriteConfig(t, f.path, f.config)
	raw, _ := json.Marshal(f.config)
	for name, bad := range map[string][]byte{"duplicate": []byte(strings.Replace(string(raw), `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1)), "case": []byte(strings.Replace(string(raw), `"schema_version"`, `"Schema_Version"`, 1)), "unknown": []byte(strings.Replace(string(raw), `"schema_version":1`, `"store_root":"/private","schema_version":1`, 1)), "null": []byte(strings.Replace(string(raw), `"ui_assets":{`, `"ui_assets":null,"discard":{`, 1)), "trailing": append(append([]byte(nil), raw...), []byte(" {}")...), "utf8": append(append([]byte(nil), raw...), 0xff)} {
		t.Run(name, func(t *testing.T) {
			os.WriteFile(f.path, bad, 0600)
			if got, e := loadOwnerGatewayConfig(context.Background(), f.path); e == nil {
				ogCloseMaterial(got)
				t.Fatal("open config grammar accepted")
			}
		})
	}
	ogWriteConfig(t, f.path, f.config)
	os.Chmod(f.path, 0640)
	if got, e := loadOwnerGatewayConfig(context.Background(), f.path); e == nil {
		ogCloseMaterial(got)
		t.Fatal("unsafe config mode accepted")
	}
	os.Chmod(f.path, 0600)
}

func TestOwnerGatewayContextPreservesOwnershipAcrossBrowserSettings(t *testing.T) {
	f := ogNewConfigFixture(t)
	first, e := loadOwnerGatewayConfig(context.Background(), f.path)
	if e != nil {
		t.Fatal(e)
	}
	defer ogCloseMaterial(first)
	changed := f.config
	changed.Reviewers = append([]ownerGatewayReviewerConfig(nil), changed.Reviewers...)
	changed.Reviewers[0].Enabled = false
	changed.Reviewers[0].Label = "Different display"
	changed.Reviewers[0].AccessCodeSHA256 = strings.Repeat("8", 64)
	changed.PublicOrigin = "https://127.0.0.1:8443"
	ogWriteConfig(t, f.path, changed)
	second, e := loadOwnerGatewayConfig(context.Background(), f.path)
	if e != nil {
		t.Fatal(e)
	}
	defer ogCloseMaterial(second)
	if first.ContextSHA256 != second.ContextSHA256 || first.ConfigSHA256 == second.ConfigSHA256 {
		t.Fatal("browser rotation erased owner history or source hash")
	}
	for _, field := range []string{"state", "results_origin", "scope", "input"} {
		t.Run(field, func(t *testing.T) {
			c := f.config
			switch field {
			case "state":
				c.StateDirectory = filepath.Join(f.root, "other-state")
			case "results_origin":
				c.ResultsURL = "https://127.0.0.1:9555"
			case "scope":
				c.ExpectedScope.PolicySHA256 = strings.Repeat("8", 64)
			case "input":
				c.Experiments = append([]ownerGatewayExperimentConfig(nil), c.Experiments...)
				path := filepath.Join(f.root, "other-input")
				body := []byte("@other\nACGT\n+\nIIII\n")
				os.WriteFile(path, body, 0600)
				c.Experiments[0].Input = ownerGatewayAsset{Path: path, SHA256: ogConfigDigest(body)}
			}
			ogWriteConfig(t, f.path, c)
			m, e := loadOwnerGatewayConfig(context.Background(), f.path)
			if e != nil {
				t.Fatal(e)
			}
			defer ogCloseMaterial(m)
			if m.ContextSHA256 == first.ContextSHA256 {
				t.Fatal("trusted run context changed invisibly")
			}
		})
	}
}

func TestOwnerGatewayMeasuredCacheOwnsUnmodifiedSnapshots(t *testing.T) {
	f := ogNewConfigFixture(t)
	cache := map[string]ogMeasuredAsset{}
	if _, _, err := ogReadPair(context.Background(), f.config.BrowserTLSCertificate, f.config.BrowserTLSPrivateKey, cache); err != nil {
		t.Fatal(err)
	}
	key := cache[f.config.BrowserTLSPrivateKey.Path]
	if ogConfigDigest(key.Raw) != f.config.BrowserTLSPrivateKey.SHA256 {
		t.Fatal("key parsing cleared the measured source snapshot")
	}
	asset := f.config.UIAssets["app.js"]
	first, err := ogReadAsset(context.Background(), asset, ogUILimit, cache)
	if err != nil {
		t.Fatal(err)
	}
	expected := append([]byte(nil), first...)
	if err := os.WriteFile(asset.Path, []byte("replacement after measured snapshot"), 0600); err != nil {
		t.Fatal(err)
	}
	second, err := ogReadAsset(context.Background(), asset, ogUILimit, cache)
	if err != nil || !bytes.Equal(second, expected) || ogConfigDigest(second) != asset.SHA256 {
		t.Fatal("asset was reread or its measured bytes changed", err)
	}
	clear(key.Raw)
}
