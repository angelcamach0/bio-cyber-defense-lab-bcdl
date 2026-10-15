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
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ownership "biozero/ownership-authority"
)

type ownerWorkerTestFixture struct {
	root, uploads string
	trust         ownerWorkerTrust
	pin           ownership.AuthorityPin
	scope         ownership.AcceptanceScope
	workerKey     *rsa.PrivateKey
	keys          [2]*rsa.PrivateKey
	leafs         [2]*x509.Certificate
	clients       [2]*ownership.AuthorityClient
	store         *ownership.Store
}
type ownerWorkerTestBundle struct {
	Job                                         ownerWorkerJob
	Acceptance, Ciphertext, Envelope, Plaintext []byte
}

func newOwnerWorkerTestFixture(t *testing.T) *ownerWorkerTestFixture {
	t.Helper()
	ctx := context.Background()
	f := &ownerWorkerTestFixture{root: t.TempDir()}
	os.Chmod(f.root, 0700)
	f.uploads = filepath.Join(f.root, "uploads")
	if e := os.Mkdir(f.uploads, 0700); e != nil {
		t.Fatal(e)
	}
	generate := func() *rsa.PrivateKey {
		k, e := rsa.GenerateKey(rand.Reader, 2048)
		if e != nil {
			t.Fatal(e)
		}
		return k
	}
	caKey := generate()
	now := time.Now()
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "owner-worker-fixture-ca"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, e := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if e != nil {
		t.Fatal(e)
	}
	ca, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	makeLeaf := func(n int64, name string, key *rsa.PrivateKey, server bool) *x509.Certificate {
		c := &x509.Certificate{SerialNumber: big.NewInt(n), Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		if server {
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			c.DNSNames = []string{"localhost"}
		}
		d, e := x509.CreateCertificate(rand.Reader, c, ca, &key.PublicKey, caKey)
		if e != nil {
			t.Fatal(e)
		}
		leaf, e := x509.ParseCertificate(d)
		if e != nil {
			t.Fatal(e)
		}
		return leaf
	}
	serverKey := generate()
	serverLeaf := makeLeaf(2, "authority", serverKey, true)
	for i := range f.keys {
		f.keys[i] = generate()
		f.leafs[i] = makeLeaf(int64(i+3), []string{"owner-a", "owner-b"}[i], f.keys[i], false)
	}
	f.workerKey = generate()
	pub, signing, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	f.pin = ownership.AuthorityPin{AuthorityID: strings.Repeat("1", 32), PublicKey: pub, PipelineMode: "stats", ExecutionProfileSHA256: strings.Repeat("2", 64)}
	f.store, e = ownership.CreateStore(ownership.StoreConfig{Directory: filepath.Join(f.root, "authority"), Namespace: "owner-worker-fixture", Pin: f.pin, SigningKey: signing, Policy: ownership.DefaultStorePolicy()})
	if e != nil {
		t.Fatal(e)
	}
	f.scope = f.store.Scope()
	t.Cleanup(func() {
		if e := f.store.Close(); e != nil {
			t.Error("authority fixture close", e)
		}
	})
	handler, e := ownership.NewHTTPHandler(ownership.HTTPHandlerConfig{Store: f.store})
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewUnstartedServer(handler)
	server.Config.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){}
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{serverLeaf.Raw}, PrivateKey: serverKey}}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}}
	server.StartTLS()
	t.Cleanup(server.Close)
	for i := range f.clients {
		f.clients[i], e = ownership.NewAuthorityClient(ownership.AuthorityClientConfig{BaseURL: server.URL, Certificate: tls.Certificate{Certificate: [][]byte{f.leafs[i].Raw}, PrivateKey: f.keys[i]}, RootCAs: pool, ServerName: "localhost", Pin: f.pin, Scope: f.scope})
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(f.clients[i].CloseIdleConnections)
	}
	f.trust = ownerWorkerTrust{f.pin.AuthorityID, hex.EncodeToString(pub), f.pin.PipelineMode, f.pin.ExecutionProfileSHA256, f.scope, strings.Repeat("3", 64)}
	_ = ctx
	return f
}

// B's copied-cipher fixture receives a REAL new challenge and durable acceptance
// over this server's verified mTLS B connection. It uses B's real signing key;
// only ciphertext/envelope are copied. No mocked Principal or signature bypass.
func (f *ownerWorkerTestFixture) bundle(t *testing.T, other bool, copyFrom *ownerWorkerTestBundle) ownerWorkerTestBundle {
	t.Helper()
	i := 0
	if other {
		i = 1
	}
	ctx := context.Background()
	var token [16]byte
	if _, e := rand.Read(token[:]); e != nil {
		t.Fatal(e)
	}
	ch, e := f.clients[i].Reserve(ctx, ownership.HTTPReserveRequest{SchemaVersion: 1, RequestID: hex.EncodeToString(token[:]), OriginalName: "synthetic.fastq"})
	if e != nil {
		t.Fatal(e)
	}
	plain := []byte("@synthetic-owner-worker\nACGT\n+\nIIII\n")
	payload, e := ownership.EncryptForChallenge(ch, f.pin, f.leafs[i], f.keys[i], &f.workerKey.PublicKey, plain, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	if copyFrom != nil {
		payload.Ciphertext = append([]byte(nil), copyFrom.Ciphertext...)
		payload.KeyEnvelope = append([]byte(nil), copyFrom.Envelope...)
		v, e := ownership.VerifyChallengeForClient(ch, f.pin, f.leafs[i], time.Now())
		if e != nil {
			t.Fatal(e)
		}
		m, e := ownership.SignManifest(f.keys[i], f.leafs[i], v, ownership.ManifestInput{CiphertextSHA256: workerCustodyDigest(payload.Ciphertext), CiphertextBytes: int64(len(payload.Ciphertext)), KeyEnvelopeSHA256: workerCustodyDigest(payload.KeyEnvelope)})
		if e != nil {
			t.Fatal(e)
		}
		payload.Manifest, e = ownership.MarshalManifest(m)
		if e != nil {
			t.Fatal(e)
		}
	}
	raw, e := f.clients[i].Finalize(ctx, ch, payload.Manifest, bytes.NewReader(payload.Ciphertext), int64(len(payload.Ciphertext)))
	if e != nil {
		t.Fatal(e)
	}
	accepted, e := ownership.VerifyAcceptance(raw, f.pin, f.scope)
	if e != nil {
		t.Fatal(e)
	}
	canonical, e := ownerWorkerCanonical(raw, accepted)
	if e != nil {
		t.Fatal(e)
	}
	b := accepted.Binding()
	j := ownerWorkerJob{b.JobID, "uploaded", accepted.Claims().AcceptedAt, b.OriginalName, b.CiphertextBytes, b.CiphertextSHA256, "", ownership.EncryptionAlgorithm, hex.EncodeToString(payload.KeyEnvelope), 1, accepted.SHA256()}
	if e = os.WriteFile(filepath.Join(f.uploads, j.JobID+"_"+j.OriginalName), payload.Ciphertext, 0600); e != nil {
		t.Fatal(e)
	}
	return ownerWorkerTestBundle{j, canonical, payload.Ciphertext, payload.KeyEnvelope, plain}
}
