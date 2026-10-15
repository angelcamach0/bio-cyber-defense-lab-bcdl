//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package ownership

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"
)

type operationEndpoint struct {
	authority  *httpFixture
	proxy      *httptest.Server
	mu         sync.Mutex
	counts     map[string]int
	dropPath   string
	dropBefore bool
	dropped    bool
	hook       func(string)
}

// The proxy is a test-only downstream loss instrument. It uses real verified
// mTLS on both legs, with the same fixed A identity; it is NOT an identity relay.
// When dropping after forwarding it consumes the real authority response first,
// then closes only its downstream connection. No authority write error is faked.
func operationFixture(t *testing.T, dropPath string, before bool) (*operationEndpoint, ClientOperationConfig) {
	t.Helper()
	x := &operationEndpoint{counts: map[string]int{}, dropPath: dropPath, dropBefore: before}
	x.authority = newHTTPFixture(t, func(server *httptest.Server, h *AuthorityHTTPHandler) {
		server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			x.mu.Lock()
			x.counts[r.URL.Path]++
			hook := x.hook
			x.mu.Unlock()
			if hook != nil {
				hook(r.URL.Path)
			}
			h.ServeHTTP(w, r)
		})
	})
	front := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		x.mu.Lock()
		drop := r.URL.Path == x.dropPath && !x.dropped
		if drop {
			x.dropped = true
		}
		x.mu.Unlock()
		abort := func() {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error("test downstream hijack failed")
				return
			}
			conn.Close()
		}
		if drop && x.dropBefore {
			abort()
			return
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, 128<<10))
		if err != nil {
			t.Error("test proxy request read failed")
			http.Error(w, "fixture", 502)
			return
		}
		request, err := http.NewRequestWithContext(r.Context(), r.Method, x.authority.server.URL+r.URL.Path, bytes.NewReader(raw))
		if err != nil {
			t.Error(err)
			return
		}
		if r.Header.Get("Content-Type") != "" {
			request.Header.Set("Content-Type", r.Header.Get("Content-Type"))
		}
		response, err := x.authority.a.Do(request)
		if err != nil {
			t.Error("test authority forwarding failed", err)
			http.Error(w, "fixture", 502)
			return
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, HTTPResponseLimit+1))
		response.Body.Close()
		if err != nil || len(body) > HTTPResponseLimit {
			t.Error("test authority response invalid")
			return
		}
		if drop {
			if response.StatusCode != 200 {
				t.Error("loss barrier did not follow successful authority response")
			}
			abort()
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(response.StatusCode)
		w.Write(body)
	}))
	front.TLS = x.authority.server.TLS.Clone()
	front.Config.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){}
	front.StartTLS()
	x.proxy = front
	t.Cleanup(front.Close)
	f := fixture(t)
	cfg := ClientOperationConfig{Directory: filepath.Join(t.TempDir(), "operation"), OriginalName: "input.fastq", EncryptionKey: &payloadWorkerKey(t).PublicKey,
		Client: AuthorityClientConfig{BaseURL: front.URL, Certificate: tls.Certificate{Certificate: [][]byte{f.certA.Raw}, PrivateKey: f.keyA}, RootCAs: x.authority.tlsA.RootCAs.Clone(), ServerName: "localhost", Pin: f.pin, Scope: x.authority.cfg.ExpectedScope}}
	return x, cfg
}

func (x *operationEndpoint) snapshot() map[string]int {
	x.mu.Lock()
	defer x.mu.Unlock()
	out := map[string]int{}
	for k, v := range x.counts {
		out[k] = v
	}
	return out
}

func operationHistory(t *testing.T, dir string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		st, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().IsRegular() && st.Size() <= MaxCiphertextBytes {
			out[e.Name()] = digest(fileBytes(t, p))
		} else {
			out[e.Name()] = st.Mode().String()
		}
	}
	return out
}

func operationStep(t *testing.T, dir string, n int) clientOperationStep {
	t.Helper()
	var step clientOperationStep
	if strictJSON(fileBytes(t, filepath.Join(dir, clientStepNames[n])), &step, clientStepLimit) != nil {
		t.Fatal("invalid physical client step")
	}
	return step
}

func operationOpen(t *testing.T, cfg ClientOperationConfig, create bool) *ClientOperation {
	t.Helper()
	var o *ClientOperation
	var err error
	if create {
		o, err = CreateClientOperation(cfg)
	} else {
		o, err = OpenClientOperation(cfg)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if !o.closed && !o.sticky {
			if e := o.Close(); e != nil {
				t.Error(e)
			}
		}
	})
	return o
}

func operationPrepare(t *testing.T, o *ClientOperation) {
	t.Helper()
	if err := o.Reserve(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := o.Prepare(context.Background(), []byte("synthetic private input"), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
}

func TestClientOperationDurableCycleAndPreNetworkOrdering(t *testing.T) {
	x, cfg := operationFixture(t, "", false)
	var observationsMu sync.Mutex
	observed := map[string]bool{}
	x.hook = func(path string) {
		phase := -1
		if path == "/v1/reservations" {
			phase = 0
		}
		if path == "/v1/finalizations" {
			phase = 3
		}
		if phase < 0 {
			return
		}
		raw, err := os.ReadFile(filepath.Join(cfg.Directory, clientStepNames[phase]))
		var step clientOperationStep
		ok := err == nil && strictJSON(raw, &step, clientStepLimit) == nil && step.Sequence == phase && hexValue(step.RequestID, 32)
		_, markerErr := os.Lstat(filepath.Join(cfg.Directory, "client.intent"))
		ok = ok && os.IsNotExist(markerErr)
		if phase == 3 {
			ciphertext, e := os.ReadFile(filepath.Join(cfg.Directory, "ciphertext.bin"))
			ok = ok && e == nil && digest(ciphertext) == step.CiphertextSHA256 && int64(len(ciphertext)) == step.CiphertextBytes
		}
		observationsMu.Lock()
		observed[path] = ok
		observationsMu.Unlock()
	}
	o := operationOpen(t, cfg, true)
	if o.State() != "intent" || o.JobID() != "" || len(x.snapshot()) != 0 {
		t.Fatal("creation contacted authority")
	}
	before := operationHistory(t, cfg.Directory)
	if _, err := CreateClientOperation(cfg); err == nil || !reflect.DeepEqual(before, operationHistory(t, cfg.Directory)) {
		t.Fatal("fresh create adopted existing directory")
	}
	if err := o.Recover(context.Background()); err == nil || len(x.snapshot()) != 0 {
		t.Fatal("recovery invented a job")
	}
	operationPrepare(t, o)
	prepared := operationHistory(t, cfg.Directory)
	if o.State() != "prepared" || o.JobID() == "" {
		t.Fatal("preparation phase invalid")
	}
	if err := o.Prepare(context.Background(), []byte("different"), time.Now()); err == nil || !reflect.DeepEqual(prepared, operationHistory(t, cfg.Directory)) {
		t.Fatal("prepared input regenerated")
	}
	for name := range prepared {
		st, err := os.Lstat(filepath.Join(cfg.Directory, name))
		if err != nil || st.Mode().Perm() != 0600 || st.Sys().(*syscall.Stat_t).Nlink != 1 {
			t.Fatal("private client file permissions invalid")
		}
		if bytes.Contains(fileBytes(t, filepath.Join(cfg.Directory, name)), []byte("synthetic private input")) {
			t.Fatal("plaintext persisted in journal")
		}
	}
	if err := o.Finalize(context.Background()); err != nil {
		t.Fatal(err)
	}
	if o.State() != "accepted" {
		t.Fatal("accepted phase not committed")
	}
	observationsMu.Lock()
	ordered := observed["/v1/reservations"] && observed["/v1/finalizations"]
	observationsMu.Unlock()
	if !ordered {
		t.Fatal("network preceded durable intent or finalizing phase")
	}
	a, err := o.Acceptance()
	if err != nil {
		t.Fatal(err)
	}
	v, err := VerifyAcceptance(a, cfg.Client.Pin, cfg.Client.Scope)
	if err != nil {
		t.Fatal(err)
	}
	step := operationStep(t, cfg.Directory, 4)
	env, err := hex.DecodeString(step.EnvelopeHex)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := DecryptAcceptedPayload(v, fileBytes(t, filepath.Join(cfg.Directory, "ciphertext.bin")), env, payloadWorkerKey(t))
	if err != nil || string(plain) != "synthetic private input" {
		t.Fatal("retained payload does not match acceptance", err)
	}
	a[0] ^= 1
	again, err := o.Acceptance()
	if err != nil || bytes.Equal(a, again) {
		t.Fatal("acceptance aliases caller bytes")
	}
	if err = o.Close(); err != nil {
		t.Fatal(err)
	}
	counts := x.snapshot()
	reopened := operationOpen(t, cfg, false)
	if err = reopened.Recover(context.Background()); err != nil || !reflect.DeepEqual(counts, x.snapshot()) {
		t.Fatal("accepted open/recover contacted authority")
	}
	got, err := reopened.Acceptance()
	if err != nil || !bytes.Equal(got, again) {
		t.Fatal("cold acceptance changed")
	}
	s := x.authority.store.Snapshot()
	if s.Jobs != 1 || s.Accepted != 1 || s.ChargedBytes != 64+StoreMetadataHeadroom {
		t.Fatal("authority accounting changed")
	}
}

func TestClientOperationLostResponsesReuseOnlyOriginalOperation(t *testing.T) {
	for _, phase := range []string{"reserve", "finalize"} {
		t.Run(phase, func(t *testing.T) {
			path := "/v1/reservations"
			if phase == "finalize" {
				path = "/v1/finalizations"
			}
			x, cfg := operationFixture(t, path, false)
			o := operationOpen(t, cfg, true)
			intent := fileBytes(t, filepath.Join(cfg.Directory, clientStepNames[0]))
			if phase == "reserve" {
				if err := o.Reserve(context.Background()); err == nil || o.State() != "intent" {
					t.Fatal("lost reserve response was accepted")
				}
				if x.authority.store.Snapshot().Jobs != 1 {
					t.Fatal("loss did not follow real reservation")
				}
				if err := o.Close(); err != nil {
					t.Fatal(err)
				}
				counts := x.snapshot()
				o = operationOpen(t, cfg, false)
				if !reflect.DeepEqual(counts, x.snapshot()) {
					t.Fatal("open retried reservation")
				}
				if err := o.Reserve(context.Background()); err != nil {
					t.Fatal(err)
				}
				if err := o.Prepare(context.Background(), []byte("input"), time.Now()); err != nil {
					t.Fatal(err)
				}
			} else {
				operationPrepare(t, o)
			}
			cipher := fileBytes(t, filepath.Join(cfg.Directory, "ciphertext.bin"))
			err := o.Finalize(context.Background())
			if phase == "finalize" {
				if err == nil || o.State() != "finalizing" {
					t.Fatal("lost acceptance response did not retain uncertainty")
				}
				before := operationHistory(t, cfg.Directory)
				counts := x.snapshot()
				if o.Finalize(context.Background()) == nil || !reflect.DeepEqual(counts, x.snapshot()) {
					t.Fatal("unknown work resent")
				}
				if err = o.Close(); err != nil {
					t.Fatal(err)
				}
				o = operationOpen(t, cfg, false)
				if !reflect.DeepEqual(counts, x.snapshot()) || !reflect.DeepEqual(before, operationHistory(t, cfg.Directory)) {
					t.Fatal("open changed uncertain operation")
				}
				if err = o.Recover(context.Background()); err != nil {
					t.Fatal(err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if o.State() != "accepted" || !bytes.Equal(cipher, fileBytes(t, filepath.Join(cfg.Directory, "ciphertext.bin"))) || !bytes.Equal(intent, fileBytes(t, filepath.Join(cfg.Directory, clientStepNames[0]))) {
				t.Fatal("original bytes or operation changed")
			}
			counts := x.snapshot()
			wantReserve := 1
			if phase == "reserve" {
				wantReserve = 2
			}
			if counts["/v1/reservations"] != wantReserve || counts["/v1/finalizations"] != 1 || x.authority.store.Snapshot().Jobs != 1 {
				t.Fatal("loss created extra authority work")
			}
		})
	}
}

func TestClientOperationPendingRecoveryNeverResends(t *testing.T) {
	x, cfg := operationFixture(t, "/v1/finalizations", true)
	o := operationOpen(t, cfg, true)
	operationPrepare(t, o)
	if o.Finalize(context.Background()) == nil || o.State() != "finalizing" {
		t.Fatal("missing request delivery not retained")
	}
	before := operationHistory(t, cfg.Directory)
	for i := 0; i < 2; i++ {
		if err := o.Recover(context.Background()); err == nil || err.Error() != "ownership_client_authority_pending" {
			t.Fatal("pending authority silently retried", err)
		}
	}
	counts := x.snapshot()
	if counts["/v1/reservations"] != 1 || counts["/v1/finalizations"] != 0 || counts["/v1/jobs/"+o.JobID()] != 2 || !reflect.DeepEqual(before, operationHistory(t, cfg.Directory)) {
		t.Fatal("pending recovery mutated or submitted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if o.Recover(ctx) == nil || !reflect.DeepEqual(counts, x.snapshot()) {
		t.Fatal("canceled recovery contacted authority")
	}
}

func TestClientOperationUncertainIOKeepsLockAndHistory(t *testing.T) {
	for _, point := range []string{"file_sync", "directory_sync", "intent_unlink", "close_root", "close_lock"} {
		t.Run(point, func(t *testing.T) {
			x, cfg := operationFixture(t, "", false)
			o := operationOpen(t, cfg, true)
			o.fault = func(name string) error {
				if name == point {
					return errors.New("injected_io")
				}
				return nil
			}
			var err error
			if point == "close_root" || point == "close_lock" {
				err = o.Close()
			} else {
				err = o.Reserve(context.Background())
			}
			if err == nil || o.State() != "unavailable" {
				t.Fatal("uncertain IO acknowledged")
			}
			before := operationHistory(t, cfg.Directory)
			if o.Close() == nil {
				t.Fatal("uncertain close released custody")
			}
			if _, e := OpenClientOperation(cfg); e == nil || e.Error() != "ownership_client_locked" {
				t.Fatal("uncertain live writer not locked", e)
			}
			if !reflect.DeepEqual(before, operationHistory(t, cfg.Directory)) {
				t.Fatal("uncertain files cleaned or changed")
			}
			if point != "close_root" && point != "close_lock" && x.authority.store.Snapshot().Jobs != 1 {
				t.Fatal("reserve loss reset server charge")
			}
		})
	}
}

func TestClientOperationRejectsUnsafeOrChangedHistory(t *testing.T) {
	for _, name := range []string{"unknown", "prepare_intent", "client_intent", "missing_step", "duplicate", "trailing", "mode", "symlink", "FIFO", "changed_cipher", "changed_name", "changed_scope", "changed_recipient"} {
		t.Run(name, func(t *testing.T) {
			x, cfg := operationFixture(t, "", false)
			o := operationOpen(t, cfg, true)
			operationPrepare(t, o)
			if err := o.Close(); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(cfg.Directory, clientStepNames[1])
			write := func(path string, raw []byte) {
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			switch name {
			case "unknown":
				write(filepath.Join(cfg.Directory, "unrecognized"), []byte("retained"))
			case "prepare_intent":
				write(filepath.Join(cfg.Directory, "prepare.intent"), []byte("preparing"))
			case "client_intent":
				write(filepath.Join(cfg.Directory, "client.intent"), []byte("retained"))
			case "missing_step":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "duplicate":
				b := fileBytes(t, path)
				write(path, append([]byte(`{"schema_version":1,`), b[1:]...))
			case "trailing":
				write(path, append(fileBytes(t, path), []byte(" {}")...))
			case "mode":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("00-intent.json", path); err != nil {
					t.Fatal(err)
				}
			case "FIFO":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := syscall.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			case "changed_cipher":
				p := filepath.Join(cfg.Directory, "ciphertext.bin")
				b := fileBytes(t, p)
				b[0] ^= 1
				write(p, b)
			case "changed_name":
				cfg.OriginalName = "other.fastq"
			case "changed_scope":
				cfg.Client.Scope.StoreID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			case "changed_recipient":
				cfg.EncryptionKey = &fixture(t).keyB.PublicKey
			}
			before, counts := operationHistory(t, cfg.Directory), x.snapshot()
			done := make(chan error, 1)
			go func() {
				reopened, err := OpenClientOperation(cfg)
				if err == nil {
					reopened.Close()
				}
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("unsafe history adopted")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("unsafe metadata blocked open")
			}
			if !reflect.DeepEqual(counts, x.snapshot()) || !reflect.DeepEqual(before, operationHistory(t, cfg.Directory)) {
				t.Fatal("failed open contacted network or cleaned history")
			}
		})
	}
}

type operationChildConfig struct {
	Directory, Endpoint, Ready, Phase string
	Pin                               AuthorityPin
	Scope                             AcceptanceScope
	Leaf, Key, CA, WorkerPublic       []byte
}

func (c operationChildConfig) operation(t *testing.T) ClientOperationConfig {
	t.Helper()
	key, err := x509.ParsePKCS1PrivateKey(c.Key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(c.CA)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	pub, err := x509.ParsePKIXPublicKey(c.WorkerPublic)
	if err != nil {
		t.Fatal(err)
	}
	return ClientOperationConfig{Directory: c.Directory, OriginalName: "input.fastq", EncryptionKey: pub.(*rsa.PublicKey), Client: AuthorityClientConfig{BaseURL: c.Endpoint, Certificate: tls.Certificate{Certificate: [][]byte{c.Leaf}, PrivateKey: key}, RootCAs: pool, ServerName: "localhost", Pin: c.Pin, Scope: c.Scope}}
}

//go:noinline
func forgetUncertainClient(t *testing.T, cfg ClientOperationConfig) (int, int, int, syscall.Stat_t) {
	t.Helper()
	o, err := CreateClientOperation(cfg)
	if err != nil {
		t.Fatal(err)
	}
	o.fault = func(name string) error {
		if name == "file_sync" {
			return errors.New("injected")
		}
		return nil
	}
	if o.Reserve(context.Background()) == nil || o.Close() == nil {
		t.Fatal("uncertain client fixture did not fail")
	}
	var st syscall.Stat_t
	if syscall.Fstat(o.rawFD, &st) != nil {
		t.Fatal("raw client lock absent")
	}
	return int(o.root.Fd()), int(o.lock.Fd()), o.rawFD, st
}

func TestClientOperationProcessHelper(t *testing.T) {
	path := os.Getenv("BIOZERO_CLIENT_OPERATION_CHILD")
	if path == "" {
		t.Skip("owned client operation helper")
	}
	var c operationChildConfig
	if json.Unmarshal(fileBytes(t, path), &c) != nil {
		t.Fatal("invalid child configuration")
	}
	cfg := c.operation(t)
	if c.Phase == "uncertain" {
		a, b, raw, identity := forgetUncertainClient(t, cfg)
		deadline := time.Now().Add(5 * time.Second)
		for {
			runtime.GC()
			runtime.Gosched()
			_, ea := descriptorFlags(a)
			_, eb := descriptorFlags(b)
			if ea == syscall.EBADF && eb == syscall.EBADF {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("original client os.File descriptors not finalized")
			}
			time.Sleep(time.Millisecond)
		}
		flags, errno := descriptorFlags(raw)
		var now syscall.Stat_t
		if errno != 0 || flags&syscall.FD_CLOEXEC == 0 || raw == a || raw == b || syscall.Fstat(raw, &now) != nil || now.Dev != identity.Dev || now.Ino != identity.Ino {
			t.Fatal("raw client custody lost during GC")
		}
		if _, err := OpenClientOperation(cfg); err == nil || err.Error() != "ownership_client_locked" {
			t.Fatal("GC released uncertain client lock", err)
		}
		t.Log("GC closed both original os.File descriptors; separate raw CLOEXEC flock remains authoritative")
	} else {
		o, err := CreateClientOperation(cfg)
		if err != nil {
			t.Fatal(err)
		}
		operationPrepare(t, o)
		if c.Phase == "finalizing" {
			if o.Finalize(context.Background()) == nil {
				t.Fatal("expected downstream response loss")
			}
		}
		if o.State() != c.Phase {
			t.Fatal("owned client phase mismatch")
		}
	}
	f, err := os.OpenFile(c.Ready, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write([]byte("ready")); err != nil {
		t.Fatal(err)
	}
	if f.Sync() != nil || f.Close() != nil {
		t.Fatal("readiness not durable")
	}
	for {
		time.Sleep(time.Hour)
	}
}

func TestClientOperationOwnedSIGKILLAndColdReadback(t *testing.T) {
	for _, phase := range []string{"prepared", "finalizing", "uncertain"} {
		t.Run(phase, func(t *testing.T) {
			drop := ""
			if phase == "finalizing" {
				drop = "/v1/finalizations"
			}
			x, cfg := operationFixture(t, drop, false)
			f := fixture(t)
			pub, err := x509.MarshalPKIXPublicKey(cfg.EncryptionKey)
			if err != nil {
				t.Fatal(err)
			}
			parent := filepath.Dir(cfg.Directory)
			c := operationChildConfig{Directory: cfg.Directory, Endpoint: cfg.Client.BaseURL, Ready: filepath.Join(parent, "child.ready"), Phase: phase, Pin: cfg.Client.Pin, Scope: cfg.Client.Scope,
				Leaf: f.certA.Raw, Key: x509.MarshalPKCS1PrivateKey(f.keyA), CA: f.stateA.VerifiedChains[0][len(f.stateA.VerifiedChains[0])-1].Raw, WorkerPublic: pub}
			config := filepath.Join(parent, "child.json")
			raw, err := json.Marshal(c)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(config, raw, 0600); err != nil {
				t.Fatal(err)
			}
			log, err := os.OpenFile(filepath.Join(parent, "child.log"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestClientOperationProcessHelper$", "-test.v")
			cmd.Env = append(os.Environ(), "BIOZERO_CLIENT_OPERATION_CHILD="+config)
			cmd.Stdout, cmd.Stderr = log, log
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			terminal := false
			defer func() {
				if !terminal {
					cmd.Process.Kill()
					<-done
				}
				log.Sync()
				log.Close()
			}()
			deadline := time.Now().Add(10 * time.Second)
			for {
				if _, err = os.Stat(c.Ready); err == nil {
					break
				}
				select {
				case e := <-done:
					terminal = true
					t.Fatal("owned child exited before barrier", e, string(fileBytes(t, log.Name())))
				default:
				}
				if time.Now().After(deadline) {
					t.Fatal("owned client barrier expired", string(fileBytes(t, log.Name())))
				}
				time.Sleep(5 * time.Millisecond)
			}
			before, counts := operationHistory(t, cfg.Directory), x.snapshot()
			if _, err = OpenClientOperation(cfg); err == nil || err.Error() != "ownership_client_locked" {
				t.Fatal("live child custody not exclusive", err)
			}
			if err = cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			select {
			case e := <-done:
				terminal = true
				ex, ok := e.(*exec.ExitError)
				if !ok {
					t.Fatal("own SIGKILL not observed", e)
				}
				status, ok := ex.Sys().(syscall.WaitStatus)
				if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
					t.Fatal("wrong child termination")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("owned SIGKILL not joined")
			}
			if phase == "uncertain" {
				if _, err = OpenClientOperation(cfg); err == nil {
					t.Fatal("uncertain cold history adopted")
				}
				if !reflect.DeepEqual(before, operationHistory(t, cfg.Directory)) || !reflect.DeepEqual(counts, x.snapshot()) {
					t.Fatal("cold failure changed history or resent")
				}
			} else {
				o := operationOpen(t, cfg, false)
				if o.State() != phase || !reflect.DeepEqual(counts, x.snapshot()) || !reflect.DeepEqual(before, operationHistory(t, cfg.Directory)) {
					t.Fatal("cold open reexecuted or changed original bytes")
				}
				if phase == "prepared" {
					if o.Recover(context.Background()) == nil || !reflect.DeepEqual(counts, x.snapshot()) {
						t.Fatal("prepared recovery submitted unknown work")
					}
				} else {
					if err = o.Recover(context.Background()); err != nil {
						t.Fatal(err)
					}
					if x.snapshot()["/v1/finalizations"] != 1 || o.State() != "accepted" {
						t.Fatal("cold query replay resubmitted")
					}
					for name, hash := range before {
						if operationHistory(t, cfg.Directory)[name] != hash {
							t.Fatal("original append-only file changed")
						}
					}
				}
			}
			t.Logf("Owned SIGKILL WaitStatus verified for %s; original history preserved and no automatic Reserve/Finalize", phase)
			if phase == "uncertain" {
				t.Log(string(fileBytes(t, log.Name())))
			}
		})
	}
}
