//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package ownership_test

import (
	own "biozero/ownership-authority"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func hash(b []byte) string { x := sha256.Sum256(b); return hex.EncodeToString(x[:]) }

type peer struct {
	key       *rsa.PrivateKey
	cert      *x509.Certificate
	state     *tls.ConnectionState
	principal own.Principal
}

func actualPeers(t *testing.T) (peer, peer) {
	t.Helper()
	caKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(11), Subject: pkix.Name{CommonName: "crosscheck-ca"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if e != nil {
		t.Fatal(e)
	}
	ca, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	captures := make(chan peer, 2)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, e := own.PrincipalFromTLS(r.TLS)
		if e != nil {
			http.Error(w, "identity", 403)
			return
		}
		s := *r.TLS
		captures <- peer{state: &s, principal: p}
		w.WriteHeader(200)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	server.StartTLS()
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	makePeer := func(name string, serial int64) peer {
		key, e := rsa.GenerateKey(rand.Reader, 2048)
		if e != nil {
			t.Fatal(e)
		}
		c := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		raw, e := x509.CreateCertificate(rand.Reader, c, ca, &key.PublicKey, caKey)
		if e != nil {
			t.Fatal(e)
		}
		leaf, e := x509.ParseCertificate(raw)
		if e != nil {
			t.Fatal(e)
		}
		tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{{Certificate: [][]byte{raw}, PrivateKey: key}}}}
		defer tr.CloseIdleConnections()
		client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
		resp, e := client.Get(server.URL)
		if e != nil {
			t.Fatal(e)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatal("TLS identity rejected", resp.StatusCode)
		}
		p := <-captures
		p.key = key
		p.cert = leaf
		return p
	}
	return makePeer("crosscheck-a", 1), makePeer("crosscheck-b", 2)
}

type readProbe struct {
	reads int
	data  *bytes.Reader
}

func (p *readProbe) Read(b []byte) (int, error) { p.reads++; return p.data.Read(b) }

type diskFixture struct {
	Seed, CertA, KeyA, CertB, KeyB, CA string
	Scope                              own.AcceptanceScope
}

func writePrivate(t *testing.T, path string, b []byte) {
	t.Helper()
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.Write(b); e == nil {
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
	e = d.Sync()
	d.Close()
	if e != nil {
		t.Fatal(e)
	}
}
func writeJSONPrivate(t *testing.T, path string, v any) {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	writePrivate(t, path, b)
}
func readPrivate(t *testing.T, path string) []byte {
	t.Helper()
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, e := hex.DecodeString(s)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func persistedPeers(t *testing.T, f diskFixture) (peer, peer) {
	t.Helper()
	ca, e := x509.ParseCertificate(unhex(t, f.CA))
	if e != nil {
		t.Fatal(e)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	states := make(chan peer, 2)
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, e := own.PrincipalFromTLS(r.TLS)
		if e != nil {
			http.Error(w, "identity", 403)
			return
		}
		state := *r.TLS
		states <- peer{state: &state, principal: p}
		w.WriteHeader(204)
	}))
	s.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	s.StartTLS()
	t.Cleanup(s.Close)
	roots := x509.NewCertPool()
	roots.AddCert(s.Certificate())
	mk := func(certHex, keyHex string) peer {
		raw := unhex(t, certHex)
		leaf, e := x509.ParseCertificate(raw)
		if e != nil {
			t.Fatal(e)
		}
		key, e := x509.ParsePKCS1PrivateKey(unhex(t, keyHex))
		if e != nil {
			t.Fatal(e)
		}
		tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{{Certificate: [][]byte{raw}, PrivateKey: key}}}}
		defer tr.CloseIdleConnections()
		c := &http.Client{Transport: tr, Timeout: 5 * time.Second}
		res, e := c.Get(s.URL)
		if e != nil {
			t.Fatal(e)
		}
		res.Body.Close()
		if res.StatusCode != 204 {
			t.Fatal("real TLS failed", res.StatusCode)
		}
		p := <-states
		p.cert = leaf
		p.key = key
		return p
	}
	return mk(f.CertA, f.KeyA), mk(f.CertB, f.KeyB)
}
func storeConfig(t *testing.T, dir string, f diskFixture) own.StoreConfig {
	t.Helper()
	key := ed25519.NewKeyFromSeed(unhex(t, f.Seed))
	pin := own.AuthorityPin{AuthorityID: strings.Repeat("9", 32), PublicKey: key.Public().(ed25519.PublicKey), PipelineMode: "variants", ExecutionProfileSHA256: strings.Repeat("8", 64)}
	p := own.DefaultStorePolicy()
	p.MaxJobs = 4
	p.MaxPrincipalJobs = 2
	p.MaxBodyBytes = 64
	p.MaxBytes = 4 * (64 + own.StoreMetadataHeadroom)
	p.MaxPrincipalBytes = 2 * (64 + own.StoreMetadataHeadroom)
	return own.StoreConfig{Directory: filepath.Join(dir, "store"), Namespace: "external-authority-acceptance", Pin: pin, SigningKey: key, Policy: p, ExpectedScope: f.Scope}
}

type gatedCiphertext struct {
	t     *testing.T
	dir   string
	store *own.Store
}

func (g *gatedCiphertext) Read(b []byte) (int, error) {
	writeJSONPrivate(g.t, filepath.Join(g.dir, "reading.ready"), g.store.Snapshot())
	select {}
}
func TestOwnedStoreChild(t *testing.T) {
	mode := os.Getenv("BIOZERO_OWNERSHIP_CHILD_MODE")
	if mode == "" {
		t.Skip("owned subprocess helper")
	}
	dir := os.Getenv("BIOZERO_OWNERSHIP_CHILD_DIR")
	var f diskFixture
	if e := json.Unmarshal(readPrivate(t, filepath.Join(dir, "fixture.json")), &f); e != nil {
		t.Fatal(e)
	}
	a, b := persistedPeers(t, f)
	cfg := storeConfig(t, dir, f)
	if mode == "reserve" {
		s, e := own.CreateStore(cfg)
		if e != nil {
			t.Fatal(e)
		}
		scope := s.Scope()
		writeJSONPrivate(t, filepath.Join(dir, "scope.json"), scope)
		ch, e := s.Reserve(a.state, strings.Repeat("1", 32), "input.fastq", time.Now().UTC().Truncate(time.Second))
		if e != nil {
			t.Fatal(e)
		}
		raw, e := own.MarshalChallenge(ch)
		if e != nil {
			t.Fatal(e)
		}
		writePrivate(t, filepath.Join(dir, "challenge.json"), raw)
		writeJSONPrivate(t, filepath.Join(dir, "reserved.json"), s.Snapshot())
		if e = s.Close(); e != nil {
			t.Fatal(e)
		}
		return
	}
	if e := json.Unmarshal(readPrivate(t, filepath.Join(dir, "scope.json")), &cfg.ExpectedScope); e != nil {
		t.Fatal(e)
	}
	s, e := own.OpenStore(cfg)
	if mode == "pending" {
		if e == nil {
			if s != nil {
				s.Close()
			}
			t.Fatal("reading history was reopened")
		}
		if !strings.Contains(e.Error(), "pending") {
			t.Fatal("unexpected restart error", e)
		}
		writeJSONPrivate(t, filepath.Join(dir, "pending-verified.json"), map[string]any{"rejected": true, "error_code": e.Error()})
		return
	}
	if e != nil {
		t.Fatal(e)
	}
	raw := readPrivate(t, filepath.Join(dir, "challenge.json"))
	ch, e := own.VerifyChallengeForClient(raw, cfg.Pin, a.cert, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	body := bytes.Repeat([]byte("z"), 32)
	manifestPath := filepath.Join(dir, "manifest.json")
	if mode == "reading" || mode == "accept" {
		m, e := own.SignManifest(a.key, a.cert, ch, own.ManifestInput{CiphertextSHA256: hash(body), CiphertextBytes: int64(len(body)), KeyEnvelopeSHA256: strings.Repeat("3", 64)})
		if e != nil {
			t.Fatal(e)
		}
		rawM, e := own.MarshalManifest(m)
		if e != nil {
			t.Fatal(e)
		}
		writePrivate(t, manifestPath, rawM)
		if mode == "reading" {
			_, e = s.Finalize(context.Background(), a.state, raw, rawM, &gatedCiphertext{t, dir, s}, time.Now())
			t.Fatal("reading helper returned before kill", e)
		}
		accepted, e := s.Finalize(context.Background(), a.state, raw, rawM, bytes.NewReader(body), time.Now())
		if e != nil {
			t.Fatal(e)
		}
		out, e := own.MarshalAcceptance(accepted)
		if e != nil {
			t.Fatal(e)
		}
		writePrivate(t, filepath.Join(dir, "accepted.json"), out)
		writeJSONPrivate(t, filepath.Join(dir, "accepted.ready"), s.Snapshot())
		select {}
	}
	if mode == "replay" {
		rawM := readPrivate(t, manifestPath)
		prior := readPrivate(t, filepath.Join(dir, "accepted.json"))
		original, err := own.VerifyAcceptance(prior, cfg.Pin, cfg.ExpectedScope)
		if err != nil {
			t.Fatal(err)
		}
		probe := &readProbe{data: bytes.NewReader([]byte("unread replacement"))}
		again, e := s.Finalize(context.Background(), a.state, raw, rawM, probe, time.Now().Add(24*time.Hour))
		if e != nil || probe.reads != 0 {
			t.Fatal("accepted replay read new bytes or expired history", e, probe.reads)
		}
		got, e := own.MarshalAcceptance(again)
		if e != nil || !bytes.Equal(got, prior) {
			t.Fatal("replay changed accepted bytes", e)
		}
		record, e := s.Get(a.state, ch.Claims().JobID)
		if e != nil || record.State != "accepted" || record.Acceptance == nil {
			t.Fatal("owner readback failed", e)
		}
		got, e = own.MarshalAcceptance(*record.Acceptance)
		if e != nil || !bytes.Equal(got, prior) {
			t.Fatal("readback changed history", e)
		}
		if _, e = s.Get(b.state, ch.Claims().JobID); e == nil {
			t.Fatal("other owner read accepted history")
		}
		snapshot := s.Snapshot()
		if snapshot.Jobs != 1 || snapshot.Accepted != 1 || snapshot.ChargedBytes != 64+own.StoreMetadataHeadroom || snapshot.Active != 0 {
			t.Fatal("retained accounting changed")
		}
		if original.Claims().AcceptedAt != again.Record.AcceptedAt {
			t.Fatal("accepted time changed")
		}
		writeJSONPrivate(t, filepath.Join(dir, "replay-verified.json"), map[string]any{"same_acceptance": true, "reader_calls": probe.reads, "other_owner_denied": true, "snapshot": snapshot})
		if e = s.Close(); e != nil {
			t.Fatal(e)
		}
		return
	}
	t.Fatal("unknown child mode")
}
func executeStoreChild(t *testing.T, dir, mode, barrier string) {
	t.Helper()
	log, e := os.OpenFile(filepath.Join(dir, "child-"+mode+".log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	defer log.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestOwnedStoreChild$", "-test.v")
	cmd.Env = append(os.Environ(), "BIOZERO_OWNERSHIP_CHILD_MODE="+mode, "BIOZERO_OWNERSHIP_CHILD_DIR="+dir)
	cmd.Stdout = log
	cmd.Stderr = log
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	terminal := false
	defer func() {
		if !terminal {
			cmd.Process.Kill()
			<-done
		}
	}()
	if barrier == "" {
		select {
		case e := <-done:
			terminal = true
			if e != nil {
				t.Fatal("owned child failed", mode, e)
			}
		case <-time.After(15 * time.Second):
			t.Fatal("owned child timeout", mode)
		}
		return
	}
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case e := <-done:
			terminal = true
			t.Fatal("child exited before barrier", mode, e)
		case <-deadline.C:
			t.Fatal("owned child barrier timeout", mode)
		case <-tick.C:
			if _, e := os.Stat(filepath.Join(dir, barrier)); e != nil {
				continue
			}
			if e := cmd.Process.Kill(); e != nil {
				t.Fatal(e)
			}
			select {
			case e := <-done:
				terminal = true
				exit, ok := e.(*exec.ExitError)
				if !ok {
					t.Fatal("SIGKILL wait not proven", e)
				}
				status, ok := exit.Sys().(syscall.WaitStatus)
				if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
					t.Fatal("wrong child termination")
				}
				writeJSONPrivate(t, filepath.Join(dir, "kill-"+mode+".json"), map[string]any{"owned_child_pid": cmd.Process.Pid, "signal": "SIGKILL", "wait_proven": true})
				return
			case <-time.After(5 * time.Second):
				t.Fatal("owned SIGKILL wait timeout")
			}
		}
	}
}
func ledgerFiles(t *testing.T, dir string) map[string]string {
	t.Helper()
	entries, e := os.ReadDir(filepath.Join(dir, "store"))
	if e != nil {
		t.Fatal(e)
	}
	out := map[string]string{}
	for _, x := range entries {
		p := filepath.Join(dir, "store", x.Name())
		st, e := os.Lstat(p)
		if e != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 {
			t.Fatal("unsafe store file")
		}
		out[x.Name()] = hash(readPrivate(t, p))
	}
	return out
}
func assertPhysicalLedger(t *testing.T, dir, state string, f diskFixture) {
	t.Helper()
	raw := readPrivate(t, filepath.Join(dir, "store/ledger.json"))
	var signed struct {
		Ledger    json.RawMessage `json:"ledger"`
		Signature string          `json:"signature"`
	}
	if e := json.Unmarshal(raw, &signed); e != nil {
		t.Fatal(e)
	}
	key := ed25519.NewKeyFromSeed(unhex(t, f.Seed))
	if !ed25519.Verify(key.Public().(ed25519.PublicKey), signed.Ledger, unhex(t, signed.Signature)) {
		t.Fatal("actual ledger signature invalid")
	}
	var l struct {
		Records []struct {
			State      string `json:"state"`
			Charge     int64  `json:"charge_bytes"`
			Credential string `json:"credential_sha256"`
		} `json:"records"`
	}
	if e := json.Unmarshal(signed.Ledger, &l); e != nil {
		t.Fatal(e)
	}
	if len(l.Records) != 1 || l.Records[0].State != state || l.Records[0].Charge != 64+own.StoreMetadataHeadroom || l.Records[0].Credential != hash(unhex(t, f.CertA)) {
		t.Fatal("physical immutable state/charge mismatch")
	}
}
func TestOwnedStoreProcessAcceptance(t *testing.T) {
	root := os.Getenv("BIOZERO_OWNERSHIP_ACCEPTANCE_ROOT")
	if root == "" {
		t.Skip("set BIOZERO_OWNERSHIP_ACCEPTANCE_ROOT to a fresh private evidence directory")
	}
	info, err := os.Lstat(root)
	if err != nil || !filepath.IsAbs(root) || !info.IsDir() || info.Mode().Perm() != 0700 {
		t.Fatal("absolute private 0700 acceptance root required")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) {
		t.Fatal("acceptance root must belong to the current user")
	}
	a, b := actualPeers(t)
	_, authorityKey, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	chain := a.state.VerifiedChains[0]
	f := diskFixture{Seed: hex.EncodeToString(authorityKey.Seed()), CertA: hex.EncodeToString(a.cert.Raw), KeyA: hex.EncodeToString(x509.MarshalPKCS1PrivateKey(a.key)), CertB: hex.EncodeToString(b.cert.Raw), KeyB: hex.EncodeToString(x509.MarshalPKCS1PrivateKey(b.key)), CA: hex.EncodeToString(chain[len(chain)-1].Raw)}
	for _, tc := range []struct{ name, mode, barrier, state string }{{"accepted_then_sigkill", "accept", "accepted.ready", "accepted"}, {"reading_fenced", "reading", "reading.ready", "reading"}} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(root, tc.name)
			if e := os.Mkdir(dir, 0700); e != nil {
				t.Fatal(e)
			}
			writeJSONPrivate(t, filepath.Join(dir, "fixture.json"), f)
			executeStoreChild(t, dir, "reserve", "")
			assertPhysicalLedger(t, dir, "reserved", f)
			executeStoreChild(t, dir, tc.mode, tc.barrier)
			assertPhysicalLedger(t, dir, tc.state, f)
			before := ledgerFiles(t, dir)
			if tc.state == "accepted" {
				executeStoreChild(t, dir, "replay", "")
			} else {
				executeStoreChild(t, dir, "pending", "")
			}
			after := ledgerFiles(t, dir)
			left, _ := json.Marshal(before)
			right, _ := json.Marshal(after)
			if !bytes.Equal(left, right) {
				t.Fatal("readback changed original history")
			}
			writeJSONPrivate(t, filepath.Join(dir, "physical-readback.json"), map[string]any{"original_store_files_unchanged": true, "before_sha256": before, "after_sha256": after, "state": tc.state})
		})
	}
}
