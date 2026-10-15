//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
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
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"math/big"
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

	ownership "biozero/ownership-authority"
)

type ownerTestPKI struct {
	ca, server, client                  *x509.Certificate
	serverKey, clientKey, encryptionKey *rsa.PrivateKey
	authority                           ed25519.PrivateKey
}

var ownerPKIOnce sync.Once
var ownerPKI ownerTestPKI
var ownerPKIErr error

func ownerTestKeys(t *testing.T) ownerTestPKI {
	t.Helper()
	ownerPKIOnce.Do(func() {
		fail := func(e error) bool {
			if e != nil {
				ownerPKIErr = e
				return true
			}
			return false
		}
		caKey, e := rsa.GenerateKey(rand.Reader, 2048)
		if fail(e) {
			return
		}
		server, e := rsa.GenerateKey(rand.Reader, 2048)
		if fail(e) {
			return
		}
		client, e := rsa.GenerateKey(rand.Reader, 2048)
		if fail(e) {
			return
		}
		enc, e := rsa.GenerateKey(rand.Reader, 2048)
		if fail(e) {
			return
		}
		_, authority, e := ed25519.GenerateKey(rand.Reader)
		if fail(e) {
			return
		}
		now := time.Now()
		caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-client-ca"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
		raw, e := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
		if fail(e) {
			return
		}
		ca, e := x509.ParseCertificate(raw)
		if fail(e) {
			return
		}
		issue := func(id int64, key *rsa.PrivateKey, usage x509.ExtKeyUsage) (*x509.Certificate, error) {
			c := &x509.Certificate{SerialNumber: big.NewInt(id), Subject: pkix.Name{CommonName: "test-owner"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, DNSNames: []string{"localhost"}}
			der, e := x509.CreateCertificate(rand.Reader, c, ca, &key.PublicKey, caKey)
			if e != nil {
				return nil, e
			}
			return x509.ParseCertificate(der)
		}
		sc, e := issue(2, server, x509.ExtKeyUsageServerAuth)
		if fail(e) {
			return
		}
		cc, e := issue(3, client, x509.ExtKeyUsageClientAuth)
		if fail(e) {
			return
		}
		ownerPKI = ownerTestPKI{ca, sc, cc, server, client, enc, authority}
	})
	if ownerPKIErr != nil {
		t.Fatal(ownerPKIErr)
	}
	return ownerPKI
}

type ownerCLIFixture struct {
	root, configPath, input string
	config                  ownerCLIConfig
	store                   *ownership.Store
	postCount, getCount     atomic.Int32
	drop                    atomic.Bool
	mu                      sync.Mutex
	receipts                map[string]ownership.OwnerUploadReceipt
}

func newOwnerCLIFixture(t *testing.T) *ownerCLIFixture {
	t.Helper()
	k := ownerTestKeys(t)
	root := t.TempDir()
	if os.Chmod(root, 0700) != nil {
		t.Fatal("private test root")
	}
	f := &ownerCLIFixture{root: root, receipts: map[string]ownership.OwnerUploadReceipt{}}
	pin := ownership.AuthorityPin{AuthorityID: strings.Repeat("1", 32), PublicKey: k.authority.Public().(ed25519.PublicKey), PipelineMode: "variants", ExecutionProfileSHA256: strings.Repeat("2", 64)}
	policy := ownership.DefaultStorePolicy()
	policy.MaxBodyBytes = 512
	store, err := ownership.CreateStore(ownership.StoreConfig{Directory: filepath.Join(root, "authority"), Namespace: "cli-test", Pin: pin, SigningKey: k.authority, Policy: policy})
	if err != nil {
		t.Fatal(err)
	}
	f.store = store
	t.Cleanup(func() { _ = store.Close() })
	handler, err := ownership.NewHTTPHandler(ownership.HTTPHandlerConfig{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(k.ca)
	start := func(h http.Handler) *httptest.Server {
		s := httptest.NewUnstartedServer(h)
		s.Config.ErrorLog = log.New(io.Discard, "", 0)
		s.Config.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){}
		s.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, Certificates: []tls.Certificate{{Certificate: [][]byte{k.server.Raw}, PrivateKey: k.serverKey}}, NextProtos: []string{"http/1.1"}}
		s.StartTLS()
		t.Cleanup(s.Close)
		return s
	}
	authority := start(handler)
	t.Cleanup(func() {
		handler.StopAdmission()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if handler.Wait(ctx) != nil {
			t.Error("authority handler pending")
		}
	})
	// This upload endpoint is a measuring test transport, not the production Store
	// or an execution/scientific authority. Root's integration exercises that Store.
	upload := start(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/uploads/") {
			f.getCount.Add(1)
			job := strings.TrimPrefix(r.URL.Path, "/v1/uploads/")
			f.mu.Lock()
			receipt, ok := f.receipts[job]
			f.mu.Unlock()
			if !ok {
				w.WriteHeader(404)
				return
			}
			json.NewEncoder(w).Encode(receipt)
			return
		}
		if r.Method != http.MethodPost || r.URL.Path != "/v1/uploads" {
			w.WriteHeader(404)
			return
		}
		f.postCount.Add(1)
		readPart := func(max uint32) ([]byte, bool) {
			var length uint32
			if binary.Read(r.Body, binary.BigEndian, &length) != nil || length == 0 || length > max {
				return nil, false
			}
			b := make([]byte, length)
			_, e := io.ReadFull(r.Body, b)
			return b, e == nil
		}
		raw, ok := readPart(ownership.MaxAcceptanceBytes)
		if !ok {
			w.WriteHeader(400)
			return
		}
		envelope, ok := readPart(512)
		if !ok {
			w.WriteHeader(400)
			return
		}
		accepted, e := ownership.VerifyAcceptance(raw, pin, store.Scope())
		if e != nil || r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			w.WriteHeader(403)
			return
		}
		binding := accepted.Binding()
		if binding.CredentialSHA256 != ownerDigest(r.TLS.PeerCertificates[0].Raw) || ownerDigest(envelope) != binding.KeyEnvelopeSHA256 {
			w.WriteHeader(403)
			return
		}
		body, e := io.ReadAll(io.LimitReader(r.Body, ownership.MaxCiphertextBytes+1))
		if e != nil || int64(len(body)) != binding.CiphertextBytes || ownerDigest(body) != binding.CiphertextSHA256 {
			w.WriteHeader(400)
			return
		}
		receipt := ownership.OwnerUploadReceipt{SchemaVersion: 1, JobID: binding.JobID, AcceptanceSHA256: accepted.SHA256(), CredentialSHA256: binding.CredentialSHA256, CiphertextSHA256: binding.CiphertextSHA256, CiphertextBytes: binding.CiphertextBytes, KeyEnvelopeSHA256: binding.KeyEnvelopeSHA256, State: "delivered"}
		f.mu.Lock()
		f.receipts[binding.JobID] = receipt
		f.mu.Unlock()
		if f.drop.CompareAndSwap(true, false) {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				conn.Close()
			}
			return
		}
		json.NewEncoder(w).Encode(receipt)
	}))
	asset := func(name string, b []byte) ownerAsset {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
		return ownerAsset{path, ownerDigest(b)}
	}
	public, e := x509.MarshalPKIXPublicKey(&k.encryptionKey.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	cfg := ownerCLIConfig{SchemaVersion: 1, AuthorityURL: authority.URL, AuthorityServerName: "localhost", UploadURL: upload.URL, UploadServerName: "localhost", TLSCertificate: asset("client.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: k.client.Raw})), TLSPrivateKey: asset("client.key", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k.clientKey)})), AuthorityID: pin.AuthorityID, PublicKeyHex: hex.EncodeToString(pin.PublicKey), PipelineMode: pin.PipelineMode, ExecutionProfileSHA256: pin.ExecutionProfileSHA256, ExpectedScope: store.Scope(), OriginalName: "sample.fastq"}
	cfg.AuthorityCA = asset("authority-ca.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: k.ca.Raw}))
	cfg.UploadCA = cfg.AuthorityCA
	cfg.EncryptionPublicKey = asset("encryption.pub", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public}))
	f.config = cfg
	f.configPath = filepath.Join(root, "client.json")
	f.writeConfig(t, cfg)
	f.input = filepath.Join(root, "input.fastq")
	if os.WriteFile(f.input, []byte("@r\nACGT\n+\nIIII\n"), 0600) != nil {
		t.Fatal("input fixture")
	}
	return f
}
func (f *ownerCLIFixture) writeConfig(t *testing.T, c ownerCLIConfig) {
	t.Helper()
	raw, _ := json.Marshal(c)
	if err := os.WriteFile(f.configPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
}
func (f *ownerCLIFixture) args(action, run string) []string {
	args := []string{"--protocol", "owner-v1", "--config", f.configPath, "--run-dir", run, "--action", action}
	if action == "submit" || action == "create" || action == "prepare" {
		args = append(args, "--file", f.input)
	}
	return args
}
func cliCall(args []string) (int, string, string) {
	var out, err bytes.Buffer
	code := runUploader(args, &out, &err)
	return code, out.String(), err.String()
}

func TestOwnerCLIRequiresExplicitProtocol(t *testing.T) {
	for _, args := range [][]string{nil, {"--file", "not-read"}, {"--protocol", "invalid"}, {"--protocol", "owner-v1", "--sign-key", "not-read"}, {"--protocol=owner-v1", "--client-id", "spoof"}} {
		code, out, err := cliCall(args)
		if code == 0 || out != "" || err == "" {
			t.Fatal("implicit protocol/fallback", code, out, err)
		}
	}
}

func TestOwnerCLISubmitActualMTLSAndSignedJob(t *testing.T) {
	f := newOwnerCLIFixture(t)
	run := filepath.Join(f.root, "run")
	code, out, err := cliCall(f.args("submit", run))
	if code != 0 {
		t.Fatal("submit", code, err)
	}
	var result map[string]any
	if json.Unmarshal([]byte(out), &result) != nil || result["protocol"] != "owner-v1" || result["phase"] != "delivered" {
		t.Fatal("transport result", out)
	}
	if f.postCount.Load() != 1 || f.getCount.Load() != 0 || f.store.Snapshot().Accepted != 1 {
		t.Fatal("wrong request/admission count")
	}
	raw, e := readOwnerFile(filepath.Join(run, "run.json"), 4096)
	if e != nil {
		t.Fatal(e)
	}
	var intent ownerRunIntent
	if decodeOwnerJSON(raw, &intent) != nil || intent.PlaintextSHA256 == "" || intent.ConfigSHA256 == "" {
		t.Fatal("missing pre-reservation input intent")
	}
	material, e := loadOwnerConfig(f.configPath)
	if e != nil {
		t.Fatal(e)
	}
	operation, e := ownership.OpenClientOperation(ownership.ClientOperationConfig{Directory: filepath.Join(run, "operation"), Client: material.authority, EncryptionKey: material.encryption, OriginalName: f.config.OriginalName})
	if e != nil {
		t.Fatal(e)
	}
	bundle, e := operation.AcceptedBundle()
	if e != nil {
		t.Fatal(e)
	}
	if operation.Close() != nil {
		t.Fatal("operation close")
	}
	accepted, e := ownership.VerifyAcceptance(bundle.Acceptance, material.authority.Pin, material.authority.Scope)
	if e != nil {
		t.Fatal(e)
	}
	plaintext, e := ownership.DecryptAcceptedPayload(accepted, bundle.Ciphertext, bundle.KeyEnvelope, ownerTestKeys(t).encryptionKey)
	if e != nil || ownerDigest(plaintext) != intent.PlaintextSHA256 {
		t.Fatal("actual GCM binding", e)
	}
	if strings.Contains(out, "succeeded") || strings.Contains(out, "approved") || strings.Contains(out, "scientific") || strings.Contains(out, f.root) {
		t.Fatal("transport claimed execution or disclosed paths")
	}
	posts, gets := f.postCount.Load(), f.getCount.Load()
	if code, status, statusErr := cliCall(f.args("status", run)); code != 0 || !strings.Contains(status, `"phase":"delivered"`) || !strings.Contains(status, accepted.SHA256()) {
		t.Fatal("local delivered status", code, status, statusErr)
	}
	phasePath := filepath.Join(run, "delivery", "02-delivered.json")
	phase, e := readOwnerFile(phasePath, 96<<10)
	if e != nil {
		t.Fatal(e)
	}
	if os.WriteFile(phasePath, append(phase, []byte(`{}`)...), 0600) != nil {
		t.Fatal("corrupt local delivery")
	}
	if code, status, _ := cliCall(f.args("status", run)); code == 0 || status != "" {
		t.Fatal("corrupted delivery reported success")
	}
	if f.postCount.Load() != posts || f.getCount.Load() != gets {
		t.Fatal("status performed network IO")
	}
}

func TestOwnerCLIResumeCannotChangeOriginalInput(t *testing.T) {
	f := newOwnerCLIFixture(t)
	run := filepath.Join(f.root, "run")
	for _, action := range []string{"create", "reserve"} {
		if code, _, err := cliCall(f.args(action, run)); code != 0 {
			t.Fatal(action, err)
		}
	}
	if f.store.Snapshot().Jobs != 1 || f.store.Snapshot().Accepted != 0 {
		t.Fatal("reservation state")
	}
	if os.WriteFile(f.input, []byte("different private input"), 0600) != nil {
		t.Fatal("mutate fixture")
	}
	if code, _, err := cliCall(f.args("prepare", run)); code == 0 || !strings.Contains(err, "owner_input_changed") {
		t.Fatal("changed input accepted", err)
	}
	if _, e := os.Stat(filepath.Join(run, "operation", "ciphertext.bin")); !os.IsNotExist(e) {
		t.Fatal("changed input encrypted")
	}
	if f.postCount.Load() != 0 || f.store.Snapshot().Accepted != 0 {
		t.Fatal("changed input submitted")
	}
	if code, _, err := cliCall(f.args("reserve", run)); code == 0 || !strings.Contains(err, "phase_invalid") {
		t.Fatal("automatic duplicate reserve", err)
	}
}

func TestOwnerCLIProcessHelper(t *testing.T) {
	if os.Getenv("BIOZERO_OWNER_CLI_HELPER") != "1" {
		t.Skip("owned CLI process helper")
	}
	var args []string
	if json.Unmarshal([]byte(os.Getenv("BIOZERO_OWNER_CLI_ARGS")), &args) != nil {
		os.Exit(97)
	}
	os.Exit(runUploader(args, os.Stdout, os.Stderr))
}
func cliProcess(t *testing.T, args []string) (int, []byte) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(args)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestOwnerCLIProcessHelper$")
	cmd.Env = append(os.Environ(), "BIOZERO_OWNER_CLI_HELPER=1", "BIOZERO_OWNER_CLI_ARGS="+string(raw))
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatal("child CLI deadline")
	}
	if err == nil {
		return 0, out
	}
	if exit, ok := err.(*exec.ExitError); ok {
		return exit.ExitCode(), out
	}
	t.Fatal(err)
	return 98, out
}

func TestOwnerCLILostDeliveryAckRecoversOnlyGetAcrossProcess(t *testing.T) {
	f := newOwnerCLIFixture(t)
	run := filepath.Join(f.root, "run")
	f.drop.Store(true)
	if code, out := cliProcess(t, f.args("submit", run)); code == 0 {
		t.Fatal("lost ack claimed delivered", string(out))
	}
	if f.postCount.Load() != 1 || f.store.Snapshot().Accepted != 1 {
		t.Fatal("missing causal delivery")
	}
	if code, out := cliProcess(t, f.args("status", run)); code != 2 || !bytes.Contains(out, []byte(`"phase":"delivery_pending"`)) {
		t.Fatal("pending local status", code, string(out))
	}
	if f.postCount.Load() != 1 || f.getCount.Load() != 0 {
		t.Fatal("pending status performed network IO")
	}
	before, err := readOwnerFile(filepath.Join(run, "run.json"), 4096)
	if err != nil {
		t.Fatal(err)
	}
	if code, out := cliProcess(t, f.args("recover-delivery", run)); code != 0 || !bytes.Contains(out, []byte(`"phase":"delivered"`)) {
		t.Fatal("Get recovery", code, string(out))
	}
	after, err := readOwnerFile(filepath.Join(run, "run.json"), 4096)
	if err != nil || !bytes.Equal(before, after) || f.postCount.Load() != 1 || f.getCount.Load() != 1 {
		t.Fatal("recovery changed input or repeated POST", err)
	}
}

func TestOwnerConfigStrictAndPrivateBeforeNetwork(t *testing.T) {
	f := newOwnerCLIFixture(t)
	original, _ := os.ReadFile(f.configPath)
	for _, kind := range []string{"duplicate", "alias", "null", "missing", "unknown", "trailing", "nested duplicate", "asset mismatch", "private mode", "symlink", "FIFO", "ancestor symlink"} {
		t.Run(kind, func(t *testing.T) {
			os.Remove(f.configPath)
			if os.WriteFile(f.configPath, original, 0600) != nil {
				t.Fatal("restore test config")
			}
			raw := append([]byte(nil), original...)
			switch kind {
			case "duplicate":
				raw = append([]byte(`{"schema_version":1,`), raw[1:]...)
			case "alias":
				raw = bytes.Replace(raw, []byte(`"authority_url"`), []byte(`"Authority_url"`), 1)
			case "null":
				raw = bytes.Replace(raw, []byte(`"schema_version":1`), []byte(`"schema_version":null`), 1)
			case "missing":
				raw = bytes.Replace(raw, []byte(`"schema_version":1,`), nil, 1)
			case "unknown":
				raw = append([]byte(`{"unknown":1,`), raw[1:]...)
			case "trailing":
				raw = append(raw, []byte(`{}`)...)
			case "nested duplicate":
				raw = bytes.Replace(raw, []byte(`"tls_certificate":{`), []byte(`"tls_certificate":{"sha256":"`+strings.Repeat("0", 64)+`",`), 1)
			case "asset mismatch":
				raw = bytes.Replace(raw, []byte(f.config.TLSPrivateKey.SHA256), []byte(strings.Repeat("0", 64)), 1)
			case "private mode":
				os.Chmod(f.configPath, 0644)
			case "symlink":
				os.Remove(f.configPath)
				os.Symlink(f.input, f.configPath)
			case "FIFO":
				os.Remove(f.configPath)
				if syscall.Mkfifo(f.configPath, 0600) != nil {
					t.Fatal("FIFO fixture")
				}
			case "ancestor symlink":
				linked := filepath.Join(f.root, "linked")
				os.Symlink(f.root, linked)
				if _, err := loadOwnerConfig(filepath.Join(linked, "client.json")); err == nil {
					t.Fatal("ancestor symlink followed")
				}
				return
			}
			if kind != "private mode" && kind != "symlink" && kind != "FIFO" {
				if os.WriteFile(f.configPath, raw, 0600) != nil {
					t.Fatal("mutate test config")
				}
			}
			run := filepath.Join(f.root, "unsafe-"+strings.ReplaceAll(kind, " ", "-"))
			args := f.args("submit", run)
			code, out, err := cliCall(args)
			if code == 0 || out != "" || err == "" || strings.Contains(err, f.root) || strings.Contains(err, "PRIVATE KEY") {
				t.Fatal("unsafe configuration accepted/exposed", code, err)
			}
			if _, err := os.Stat(run); !os.IsNotExist(err) {
				t.Fatal("unsafe configuration created run")
			}
		})
	}
	if f.store.Snapshot().Jobs != 0 || f.postCount.Load() != 0 {
		t.Fatal("invalid configuration reached authority/upload")
	}
}

func TestOwnerPrivateInputBoundsAndLinks(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "input")
	if os.WriteFile(path, bytes.Repeat([]byte{'x'}, 17), 0600) != nil {
		t.Fatal("fixture")
	}
	if raw, err := readOwnerFile(path, 17); err != nil || len(raw) != 17 {
		t.Fatal("exact limit", err)
	}
	if _, err := readOwnerFile(path, 16); err == nil {
		t.Fatal("limit+1 accepted")
	}
	os.Remove(path)
	if syscall.Mkfifo(path, 0600) != nil {
		t.Fatal("FIFO fixture")
	}
	if _, err := readOwnerFile(path, 17); err == nil {
		t.Fatal("FIFO accepted")
	}
	os.Remove(path)
	if os.WriteFile(path, []byte("private"), 0600) != nil {
		t.Fatal("fixture")
	}
	other := filepath.Join(root, "hardlink")
	if os.Link(path, other) != nil {
		t.Fatal("hardlink fixture")
	}
	if _, err := readOwnerFile(path, 17); err == nil {
		t.Fatal("multi-link input accepted")
	}
}
