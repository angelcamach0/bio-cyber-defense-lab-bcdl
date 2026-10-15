//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package ownership

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"
)

func authorityProcessWrite(t *testing.T, path string, raw []byte) {
	t.Helper()
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		t.Fatal(e)
	}
	n, e := f.Write(raw)
	if e == nil && n != len(raw) {
		e = io.ErrShortWrite
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		t.Fatal(e)
	}
	d, e := os.Open(filepath.Dir(path))
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	if d.Sync() != nil {
		t.Fatal("private parent sync failed")
	}
}
func authorityProcessJSON(t *testing.T, path string, v any) {
	t.Helper()
	raw, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	authorityProcessWrite(t, path, raw)
}
func authorityProcessRead(t *testing.T, path string) []byte {
	t.Helper()
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func authorityProcessHistory(t *testing.T, root string) map[string]string {
	t.Helper()
	entries, e := os.ReadDir(root)
	if e != nil {
		t.Fatal(e)
	}
	out := map[string]string{}
	for _, x := range entries {
		p := filepath.Join(root, x.Name())
		st, e := os.Lstat(p)
		if e != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 {
			t.Fatal("unsafe retained history")
		}
		out[x.Name()] = digest(authorityProcessRead(t, p))
	}
	return out
}
func authorityProcessConfig(t *testing.T, dir string) (AuthorityServiceConfig, string) {
	t.Helper()
	f := fixture(t)
	asset := func(name string, b []byte) AuthorityServiceAsset {
		p := filepath.Join(dir, name)
		authorityProcessWrite(t, p, b)
		return AuthorityServiceAsset{p, digest(b)}
	}
	ca := f.stateA.VerifiedChains[0][len(f.stateA.VerifiedChains[0])-1]
	p := DefaultStorePolicy()
	p.MaxBodyBytes = 64
	c := AuthorityServiceConfig{SchemaVersion: 1, ListenAddress: "127.0.0.1:0", StoreRoot: filepath.Join(dir, "store"), Namespace: "process-authority-test", AuthorityID: f.pin.AuthorityID, PublicKeyHex: hex.EncodeToString(f.pin.PublicKey), PipelineMode: f.pin.PipelineMode, ExecutionProfileSHA256: f.pin.ExecutionProfileSHA256, Policy: p,
		SigningKey: asset("authority.key", f.private), TLSCertificate: asset("server.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.certA.Raw})), TLSPrivateKey: asset("server.key", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(f.keyA)})), ClientCA: asset("ca.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}))}
	scope, e := InitializeAuthorityStore(context.Background(), c)
	if e != nil {
		t.Fatal(e)
	}
	c.ExpectedScope = scope
	authorityProcessJSON(t, filepath.Join(dir, "trusted-scope.json"), scope)
	path := filepath.Join(dir, "service.json")
	authorityProcessJSON(t, path, c)
	return c, path
}

type authorityOwnedChild struct {
	cmd      *exec.Cmd
	done     chan error
	log      *os.File
	terminal bool
}

func startAuthorityOwnedChild(t *testing.T, config, mode string) *authorityOwnedChild {
	t.Helper()
	log, e := os.OpenFile(filepath.Join(filepath.Dir(config), mode+".log"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestAuthorityHTTPProcessHelper$", "-test.v")
	cmd.Env = append(os.Environ(), "BIOZERO_AUTHORITY_CHILD_CONFIG="+config, "BIOZERO_AUTHORITY_CHILD_MODE="+mode)
	cmd.Stdout = log
	cmd.Stderr = log
	if e = cmd.Start(); e != nil {
		log.Close()
		t.Fatal(e)
	}
	child := &authorityOwnedChild{cmd: cmd, done: make(chan error, 1), log: log}
	go func() { child.done <- cmd.Wait() }()
	t.Cleanup(func() {
		if !child.terminal {
			cmd.Process.Kill()
			<-child.done
			child.terminal = true
		}
		log.Sync()
		log.Close()
	})
	return child
}
func (c *authorityOwnedChild) wait(t *testing.T, kill bool) {
	t.Helper()
	select {
	case e := <-c.done:
		c.terminal = true
		if kill {
			ex, ok := e.(*exec.ExitError)
			if !ok {
				t.Fatal("own SIGKILL not observed", e)
			}
			s, ok := ex.Sys().(syscall.WaitStatus)
			if !ok || !s.Signaled() || s.Signal() != syscall.SIGKILL {
				t.Fatal("wrong owned termination")
			}
		} else if e != nil {
			t.Fatal("owned child did not exit successfully", e)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("owned process wait deadline")
	}
}
func (c *authorityOwnedChild) awaitFile(t *testing.T, path string) []byte {
	t.Helper()
	timer := time.NewTimer(8 * time.Second)
	defer timer.Stop()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case e := <-c.done:
			c.terminal = true
			t.Fatal("owned process exited before barrier", e)
		case <-timer.C:
			t.Fatal("owned barrier deadline")
		case <-tick.C:
			if b, e := os.ReadFile(path); e == nil {
				return b
			}
		}
	}
}

func TestAuthorityHTTPProcessHelper(t *testing.T) {
	config := os.Getenv("BIOZERO_AUTHORITY_CHILD_CONFIG")
	mode := os.Getenv("BIOZERO_AUTHORITY_CHILD_MODE")
	if config == "" {
		t.Skip("owned authority process helper")
	}
	c, e := LoadAuthorityServiceConfig(context.Background(), config)
	if e != nil {
		t.Fatal(e)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer stop()
	service, e := OpenAuthorityService(ctx, c)
	if mode == "locked" {
		if e == nil {
			service.Shutdown(context.Background())
			t.Fatal("uncertain live writer lock bypassed")
		}
		if e.Error() != "ownership_instance_locked" {
			t.Fatal("wrong live lock error", e)
		}
		authorityProcessJSON(t, filepath.Join(filepath.Dir(config), "locked-verified.json"), map[string]bool{"denied": true})
		return
	}
	if e != nil {
		t.Fatal(e)
	}
	dir := filepath.Dir(config)
	var gate *rstGate
	if mode == "rst" {
		gate = &rstGate{entered: make(chan struct{}), release: make(chan struct{}), observed: make(chan rstWriteObservation, 1)}
		service.listener.Listener = rstListener{service.listener.Listener, gate}
		original := service.server.Handler
		service.server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/finalizations" {
				gate.armed.Store(true)
			}
			original.ServeHTTP(w, r)
		})
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- service.Serve(ctx) }()
	authorityProcessJSON(t, filepath.Join(dir, mode+".ready"), map[string]string{"address": service.Addr().String()})
	if mode == "rst" {
		select {
		case <-gate.entered:
		case <-time.After(10 * time.Second):
			t.Fatal("RST response barrier not reached")
		}
		before := authorityProcessRead(t, filepath.Join(c.StoreRoot, "ledger.json"))
		authorityProcessJSON(t, filepath.Join(dir, "commit-before-write.json"), map[string]string{"ledger_sha256": digest(before)})
		deadline := time.Now().Add(10 * time.Second)
		for {
			if _, e := os.Stat(filepath.Join(dir, "release-write")); e == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("RST release deadline")
			}
			time.Sleep(5 * time.Millisecond)
		}
		close(gate.release)
		var actual rstWriteObservation
		select {
		case actual = <-gate.observed:
		case <-time.After(3 * time.Second):
			t.Fatal("actual TCP write not joined")
		}
		if actual.err == nil {
			t.Fatal("RST did not produce actual delegated write error")
		}
		state := waitHTTPState(t, service.store, func(s StoreSnapshot) bool { return s.Sticky })
		if state.Accepted != 1 || state.ChargedBytes != 64+StoreMetadataHeadroom {
			t.Fatal("delivery failure lost durable reservation")
		}
		if service.Shutdown(context.Background()) == nil {
			t.Fatal("uncertain shutdown returned success")
		}
		if service.Shutdown(context.Background()) == nil {
			t.Fatal("second shutdown lost first failure")
		}
		after := authorityProcessRead(t, filepath.Join(c.StoreRoot, "ledger.json"))
		if !bytes.Equal(before, after) {
			t.Fatal("HTTP error changed committed history")
		}
		authorityProcessJSON(t, filepath.Join(dir, "actual-rst-observed.json"), struct {
			ActualWriteError bool          `json:"actual_write_error"`
			Bytes            int           `json:"write_bytes"`
			Snapshot         StoreSnapshot `json:"snapshot"`
			Before, After    string
			ShutdownDenied   bool `json:"shutdown_denied"`
		}{true, actual.n, state, digest(before), digest(after), true})
		// The parent proves the lock remains held, then kills only this live child.
		for {
			select {
			case <-ctx.Done():
				t.Fatal("expected parent SIGKILL after observed failure")
			case <-time.After(time.Hour):
			}
		}
	}
	if mode != "replay" {
		t.Fatal("unknown owned helper mode")
	}
	<-ctx.Done()
	if service.Shutdown(context.Background()) != nil {
		t.Fatal("clean replay shutdown failed")
	}
	if e := <-serveDone; e != nil {
		t.Fatal(e)
	}
	authorityProcessJSON(t, filepath.Join(dir, "replay-exited.json"), map[string]bool{"clean_shutdown": true})
}

func TestAuthorityHTTPProcessAcceptance(t *testing.T) {
	root := os.Getenv("BIOZERO_AUTHORITY_HTTP_ACCEPTANCE_ROOT")
	if root == "" {
		t.Skip("set fresh private BIOZERO_AUTHORITY_HTTP_ACCEPTANCE_ROOT")
	}
	st, e := os.Lstat(root)
	if e != nil || !filepath.IsAbs(root) || !st.IsDir() || st.Mode().Perm() != 0700 {
		t.Fatal("private absolute 0700 evidence root required")
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		t.Fatal("evidence owner mismatch")
	}
	t.Run("real_rst_signed_commit_cold_replay", func(t *testing.T) {
		dir := filepath.Join(root, "rst-cold-replay")
		if e := os.Mkdir(dir, 0700); e != nil {
			t.Fatal(e)
		}
		cfg, config := authorityProcessConfig(t, dir)
		f := fixture(t)
		pool := x509.NewCertPool()
		chain := f.stateA.VerifiedChains[0]
		pool.AddCert(chain[len(chain)-1])
		clientTLS := func(other bool) *tls.Config {
			pair := tls.Certificate{Certificate: [][]byte{f.certA.Raw}, PrivateKey: f.keyA}
			if other {
				pair = tls.Certificate{Certificate: [][]byte{f.certB.Raw}, PrivateKey: f.keyB}
			}
			return &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, NextProtos: []string{"http/1.1"}}
		}
		client := func(other bool) *http.Client {
			return &http.Client{Transport: &http.Transport{TLSClientConfig: clientTLS(other), DisableKeepAlives: true}, Timeout: 3 * time.Second}
		}
		rst := startAuthorityOwnedChild(t, config, "rst")
		var ready map[string]string
		json.Unmarshal(rst.awaitFile(t, filepath.Join(dir, "rst.ready")), &ready)
		url := "https://" + ready["address"]
		request, _ := json.Marshal(HTTPReserveRequest{1, storeRequest(1), "input.fastq"})
		status, ch := httpCall(t, client(false), "POST", url+"/v1/reservations", "application/json", request)
		if status != 200 {
			t.Fatal("process reserve failed")
		}
		body := bytes.Repeat([]byte("z"), 32)
		manifest := httpManifest(t, ch, body)
		wire := httpFraming(ch, manifest, body)
		conn, e := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", ready["address"], clientTLS(false))
		if e != nil {
			t.Fatal(e)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		rawFinalization(t, conn, wire, len(wire))
		rst.awaitFile(t, filepath.Join(dir, "commit-before-write.json"))
		rawLedger := authorityProcessRead(t, filepath.Join(cfg.StoreRoot, "ledger.json"))
		var ledger signedStoreLedger
		if decodeStoreJSON(rawLedger, &ledger) != nil || len(ledger.Ledger.Records) != 1 || ledger.Ledger.Records[0].State != "accepted" || ledger.Ledger.Records[0].ChargeBytes != 64+StoreMetadataHeadroom {
			t.Fatal("process barrier lacked accepted history")
		}
		canonical, _ := json.Marshal(ledger.Ledger)
		signature, _ := hex.DecodeString(ledger.Signature)
		if !ed25519.Verify(f.pin.PublicKey, canonical, signature) || ledger.Ledger.Records[0].CredentialSHA256 != digest(f.certA.Raw) {
			t.Fatal("physical authority ledger signature/owner invalid")
		}
		accepted := []byte(ledger.Ledger.Records[0].AcceptanceJSON)
		verified, e := VerifyAcceptance(accepted, f.pin, cfg.ExpectedScope)
		if e != nil {
			t.Fatal(e)
		}
		authorityProcessWrite(t, filepath.Join(dir, "original-acceptance.json"), accepted)
		tcp, ok := conn.NetConn().(*net.TCPConn)
		if !ok || tcp.SetLinger(0) != nil || tcp.Close() != nil {
			t.Fatal("owned client RST failed")
		}
		authorityProcessWrite(t, filepath.Join(dir, "release-write"), []byte("release"))
		observed := rst.awaitFile(t, filepath.Join(dir, "actual-rst-observed.json"))
		var verdict struct {
			ActualWriteError bool `json:"actual_write_error"`
			ShutdownDenied   bool `json:"shutdown_denied"`
		}
		if json.Unmarshal(observed, &verdict) != nil || !verdict.ActualWriteError || !verdict.ShutdownDenied {
			t.Fatal("actual RST uncertainty not observed")
		}
		locked := startAuthorityOwnedChild(t, config, "locked")
		locked.wait(t, false)
		before := authorityProcessHistory(t, cfg.StoreRoot)
		if rst.cmd.Process.Kill() != nil {
			t.Fatal("owned service kill failed")
		}
		rst.wait(t, true)
		authorityProcessJSON(t, filepath.Join(dir, "owned-death.json"), map[string]any{"signal": "SIGKILL", "wait_proven": true, "owned_pid": rst.cmd.Process.Pid})
		replay := startAuthorityOwnedChild(t, config, "replay")
		json.Unmarshal(replay.awaitFile(t, filepath.Join(dir, "replay.ready")), &ready)
		url = "https://" + ready["address"]
		status, result := httpCall(t, client(false), "GET", url+"/v1/jobs/"+verified.Binding().JobID, "", nil)
		var job HTTPJobResponse
		if status != 200 || json.Unmarshal(result, &job) != nil || job.Acceptance == nil {
			t.Fatal("cold owner readback failed")
		}
		got, _ := MarshalAcceptance(*job.Acceptance)
		if !bytes.Equal(accepted, got) {
			t.Fatal("cold acceptance changed")
		}
		status, _ = httpCall(t, client(true), "GET", url+"/v1/jobs/"+verified.Binding().JobID, "", nil)
		if status != 403 {
			t.Fatal("cold nonowner read permitted")
		}
		replayConn, e := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", ready["address"], clientTLS(false))
		if e != nil {
			t.Fatal(e)
		}
		replayConn.SetDeadline(time.Now().Add(3 * time.Second))
		meta := httpFraming(ch, manifest, nil)
		rawFinalization(t, replayConn, meta, len(meta)+32)
		response, e := http.ReadResponse(bufio.NewReader(replayConn), nil)
		if e != nil {
			t.Fatal("cold replay waited for ciphertext", e)
		}
		got, e = io.ReadAll(response.Body)
		response.Body.Close()
		replayConn.Close()
		if e != nil || response.StatusCode != 200 || !bytes.Equal(got, accepted) {
			t.Fatal("cold replay changed accepted bytes")
		}
		if replay.cmd.Process.Signal(syscall.SIGTERM) != nil {
			t.Fatal("own replay stop failed")
		}
		replay.wait(t, false)
		after := authorityProcessHistory(t, cfg.StoreRoot)
		if !reflect.DeepEqual(before, after) {
			t.Fatal("cold recovery changed charges/history")
		}
		authorityProcessJSON(t, filepath.Join(dir, "final-readback.json"), map[string]any{"same_acceptance": true, "ciphertext_resent": false, "nonowner_denied": true, "same_history": true, "before_sha256": before, "after_sha256": after, "retained_charge_bytes": 64 + StoreMetadataHeadroom, "same_job_count": 1, "actual_write_error": true, "live_second_writer_denied": true, "own_sigkill_wait_proven": true, "clean_replay_exit": true})
	})
}
