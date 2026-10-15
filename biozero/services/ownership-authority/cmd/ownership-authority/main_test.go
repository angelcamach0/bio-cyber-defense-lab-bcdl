//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	ownership "biozero/ownership-authority"
)

var commandMaterialOnce sync.Once
var commandKey, commandCA, commandCertificate, commandTLSKey []byte

func commandFixture(t *testing.T) (ownership.AuthorityServiceConfig, string) {
	t.Helper()
	commandMaterialOnce.Do(func() {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		commandKey = key
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now()
		ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic-cli-ca"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
		caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &rsaKey.PublicKey, rsaKey)
		if err != nil {
			t.Fatal(err)
		}
		parent, err := x509.ParseCertificate(caDER)
		if err != nil {
			t.Fatal(err)
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"localhost"}, Subject: pkix.Name{CommonName: "synthetic-cli-server"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, err := x509.CreateCertificate(rand.Reader, leaf, parent, &rsaKey.PublicKey, rsaKey)
		if err != nil {
			t.Fatal(err)
		}
		commandCA = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
		commandCertificate = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		commandTLSKey = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)})
	})
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	asset := func(name string, raw []byte) ownership.AuthorityServiceAsset {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		sha := sha256.Sum256(raw)
		return ownership.AuthorityServiceAsset{Path: path, SHA256: hex.EncodeToString(sha[:])}
	}
	c := ownership.AuthorityServiceConfig{SchemaVersion: 1, ListenAddress: "127.0.0.1:0", StoreRoot: filepath.Join(root, "store"), Namespace: "command-test", AuthorityID: strings.Repeat("1", 32), PublicKeyHex: hex.EncodeToString(commandKey[32:]), PipelineMode: "stats", ExecutionProfileSHA256: strings.Repeat("2", 64), SigningKey: asset("signing.key", commandKey), TLSCertificate: asset("server.crt", commandCertificate), TLSPrivateKey: asset("server.key", commandTLSKey), ClientCA: asset("ca.crt", commandCA), Policy: ownership.DefaultStorePolicy()}
	path := filepath.Join(root, "service.json")
	commandWriteConfig(t, path, c)
	return c, path
}
func commandWriteConfig(t *testing.T, path string, c ownership.AuthorityServiceConfig) {
	t.Helper()
	raw, _ := json.Marshal(c)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}
func commandInitialized(t *testing.T) (ownership.AuthorityServiceConfig, string) {
	t.Helper()
	c, path := commandFixture(t)
	var out, errout bytes.Buffer
	if code, handle := run(context.Background(), []string{"--config", path, "--init-store"}, &out, &errout); code != 0 || handle != nil || errout.Len() != 0 {
		t.Fatal("init command failed", code, errout.String())
	}
	if err := json.Unmarshal(out.Bytes(), &c.ExpectedScope); err != nil {
		t.Fatal(err)
	}
	commandWriteConfig(t, path, c)
	return c, path
}

func TestOwnershipCommandArgumentsAndExplicitGenesis(t *testing.T) {
	for _, args := range [][]string{{}, {"--unknown"}, {"--config", "relative"}, {"--config", "/private/config", "extra"}} {
		var out, errout bytes.Buffer
		code, handle := run(context.Background(), args, &out, &errout)
		if code == 0 || handle != nil || out.Len() != 0 || strings.Contains(errout.String(), "/private/") {
			t.Fatal("invalid command accepted or leaked path")
		}
	}
	c, path := commandFixture(t)
	var out, errout bytes.Buffer
	if code, _ := run(context.Background(), []string{"--config", path}, &out, &errout); code != 1 || out.Len() != 0 || errout.String() != "ownership_service_start_failed\n" {
		t.Fatal("serve initialized missing external scope")
	}
	if _, err := os.Stat(c.StoreRoot); !os.IsNotExist(err) {
		t.Fatal("serve created genesis")
	}
	out.Reset()
	errout.Reset()
	if code, handle := run(context.Background(), []string{"--config", path, "--init-store"}, &out, &errout); code != 0 || handle != nil || errout.Len() != 0 {
		t.Fatal("init failed")
	}
	var scope ownership.AcceptanceScope
	if err := json.Unmarshal(out.Bytes(), &scope); err != nil || len(scope.StoreID) != 32 || len(scope.PolicySHA256) != 64 {
		t.Fatal("invalid external genesis output")
	}
	if bytes.Contains(out.Bytes(), []byte(c.StoreRoot)) || bytes.Contains(out.Bytes(), []byte(c.PublicKeyHex)) {
		t.Fatal("scope output exposed configuration")
	}
	out.Reset()
	errout.Reset()
	if code, _ := run(context.Background(), []string{"--config", path, "--init-store"}, &out, &errout); code != 1 || out.Len() != 0 {
		t.Fatal("second init adopted existing state")
	}
}

type commandShortWriter struct{}

func (commandShortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }
func TestOwnershipCommandScopeWriteFailurePreservesGenesis(t *testing.T) {
	c, path := commandFixture(t)
	var errout bytes.Buffer
	if code, _ := run(context.Background(), []string{"--config", path, "--init-store"}, commandShortWriter{}, &errout); code != 1 || errout.String() != "ownership_service_scope_delivery_failed\n" {
		t.Fatal("short scope write acknowledged")
	}
	if _, err := os.Stat(filepath.Join(c.StoreRoot, "ledger.json")); err != nil {
		t.Fatal("lost scope delivery erased store")
	}
	var out bytes.Buffer
	errout.Reset()
	if code, _ := run(context.Background(), []string{"--config", path, "--init-store"}, &out, &errout); code != 1 || out.Len() != 0 {
		t.Fatal("lost scope automatically regenerated")
	}
}

type commandReadyWriter struct {
	bytes.Buffer
	ready chan struct{}
	once  sync.Once
}

func (w *commandReadyWriter) Write(p []byte) (int, error) {
	n, err := w.Buffer.Write(p)
	if bytes.Contains(p, []byte("ownership_service_ready")) {
		w.once.Do(func() { close(w.ready) })
	}
	return n, err
}
func TestOwnershipCommandContextShutdownReleasesHealthyStore(t *testing.T) {
	_, path := commandInitialized(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := &commandReadyWriter{ready: make(chan struct{})}
	var errout bytes.Buffer
	done := make(chan int, 1)
	go func() { code, _ := run(ctx, []string{"--config", path}, out, &errout); done <- code }()
	select {
	case <-out.ready:
	case <-time.After(3 * time.Second):
		t.Fatal("service did not start")
	}
	cancel()
	select {
	case code := <-done:
		if code != 0 || errout.Len() != 0 {
			t.Fatal("cancelled command failed", code, errout.String())
		}
	case <-time.After(6 * time.Second):
		t.Fatal("shutdown hung")
	}
	c, err := ownership.LoadAuthorityServiceConfig(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	service, err := ownership.OpenAuthorityService(context.Background(), c)
	if err != nil {
		t.Fatal("healthy command retained custody")
	}
	if err = service.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestOwnershipCommandSignalHelper(t *testing.T) {
	path := os.Getenv("BIOZERO_OWNERSHIP_COMMAND_TEST_HELPER")
	if path == "" {
		t.Skip("subprocess signal helper")
	}
	os.Args = []string{"ownership-authority", "--config", path}
	main()
}
func TestOwnershipCommandActualSIGTERM(t *testing.T) {
	_, path := commandInitialized(t)
	cmd := exec.Command(os.Args[0], "-test.run=^TestOwnershipCommandSignalHelper$")
	cmd.Env = append(os.Environ(), "BIOZERO_OWNERSHIP_COMMAND_TEST_HELPER="+path)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	waited := false
	defer func() {
		if !waited {
			cmd.Process.Kill()
			<-done
		}
	}()
	ready := make(chan string, 1)
	go func() { line, _ := bufio.NewReader(stdout).ReadString('\n'); ready <- line }()
	select {
	case line := <-ready:
		if line != "ownership_service_ready\n" {
			t.Fatal("invalid readiness")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("process readiness timeout")
	}
	if err = syscall.Kill(cmd.Process.Pid, syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-done:
		waited = true
		if err != nil || cmd.ProcessState.ExitCode() != 0 || stderr.Len() != 0 {
			t.Fatal("SIGTERM process did not close cleanly", err, stderr.String())
		}
	case <-time.After(6 * time.Second):
		t.Fatal("SIGTERM shutdown timeout")
	}
	_, _ = io.Copy(io.Discard, stdout)
}
