// SPDX-License-Identifier: AGPL-3.0-only
package ownership

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
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
	"strings"
	"sync"
	"testing"
	"time"
)

var fixtureOnce sync.Once
var fixtureData *testFixture

type testFixture struct {
	keyA, keyB     *rsa.PrivateKey
	certA, certB   *x509.Certificate
	stateA, stateB tls.ConnectionState
	private        ed25519.PrivateKey
	pin            AuthorityPin
	now            time.Time
}

func fixture(t *testing.T) *testFixture {
	t.Helper()
	fixtureOnce.Do(func() {
		f := &testFixture{now: time.Now().UTC().Truncate(time.Second)}
		caKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"}, NotBefore: f.now.Add(-time.Hour), NotAfter: f.now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
		caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		ca, err := x509.ParseCertificate(caDER)
		if err != nil {
			t.Fatal(err)
		}
		pool := x509.NewCertPool()
		pool.AddCert(ca)
		makeLeaf := func() (*rsa.PrivateKey, *x509.Certificate, tls.Certificate) {
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}
			// Deliberately identical CN and serial: identity must use the actual DER.
			template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "same-cn"}, DNSNames: []string{"localhost"}, NotBefore: f.now.Add(-time.Hour), NotAfter: f.now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
			der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
			if err != nil {
				t.Fatal(err)
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			return key, cert, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}
		}
		var tlsA, tlsB tls.Certificate
		f.keyA, f.certA, tlsA = makeLeaf()
		f.keyB, f.certB, tlsB = makeLeaf()
		states := make(chan tls.ConnectionState, 2)
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { states <- *r.TLS; w.WriteHeader(204) }))
		server.TLS = &tls.Config{Certificates: []tls.Certificate{tlsA}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS13}
		server.StartTLS()
		defer server.Close()
		for _, clientCert := range []tls.Certificate{tlsA, tlsB} {
			transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "localhost", Certificates: []tls.Certificate{clientCert}, MinVersion: tls.VersionTLS13}}
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			response, err := client.Get(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			transport.CloseIdleConnections()
		}
		f.stateA = <-states
		f.stateB = <-states
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		f.private = private
		f.pin = AuthorityPin{strings.Repeat("1", 32), public, "variants", strings.Repeat("2", 64)}
		fixtureData = f
	})
	if fixtureData == nil {
		t.Fatal("fixture initialization failed")
	}
	return fixtureData
}

func signed(t *testing.T, f *testFixture, body []byte) ([]byte, []byte, VerifiedChallenge) {
	t.Helper()
	owner, err := PrincipalFromTLS(&f.stateA)
	if err != nil {
		t.Fatal(err)
	}
	c, err := SignChallenge(f.private, f.pin, owner, ChallengeInput{"1234567890abcdef", strings.Repeat("3", 64), "sample.fastq", f.now, f.now.Add(5 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalChallenge(c)
	if err != nil {
		t.Fatal(err)
	}
	v, err := VerifyChallengeForClient(raw, f.pin, f.certA, f.now)
	if err != nil {
		t.Fatal(err)
	}
	m, err := SignManifest(f.keyA, f.certA, v, ManifestInput{digest(body), int64(len(body)), strings.Repeat("4", 64)})
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := MarshalManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	return raw, manifest, v
}

func TestRealTLSFinalizeAndClientKeyBinding(t *testing.T) {
	f := fixture(t)
	body := bytes.Repeat([]byte("cipher"), 17)
	raw, manifest, v := signed(t, f, body)
	binding, err := Finalize(context.Background(), &f.stateA, raw, manifest, f.pin, bytes.NewReader(body), f.now)
	if err != nil {
		t.Fatal(err)
	}
	if binding.CiphertextSHA256 != digest(body) || binding.CiphertextBytes != int64(len(body)) || binding.CredentialSHA256 != digest(f.certA.Raw) || binding.ExecutionProfileSHA256 != f.pin.ExecutionProfileSHA256 {
		t.Fatal("binding mismatch")
	}
	if _, err := VerifyChallengeForClient(raw, f.pin, f.certB, f.now); err == nil {
		t.Fatal("same CN/serial different DER accepted")
	}
	if _, err := SignManifest(f.keyB, f.certA, v, ManifestInput{digest(body), int64(len(body)), strings.Repeat("4", 64)}); err == nil {
		t.Fatal("mismatched private key accepted")
	}
	if _, err := SignChallenge(f.private, f.pin, Principal{}, ChallengeInput{}); err == nil {
		t.Fatal("zero Principal accepted")
	}
	if _, err := CanonicalAAD(VerifiedChallenge{}); err == nil {
		t.Fatal("unverified challenge accepted")
	}
	claims := v.Claims()
	claims.JobID = "ffffffffffffffff"
	if v.Claims().JobID == claims.JobID {
		t.Fatal("claims getter mutated verified challenge")
	}
}

type observedReader struct {
	r     io.Reader
	calls int
	bytes int
}

func (r *observedReader) Read(p []byte) (int, error) {
	r.calls++
	n, e := r.r.Read(p)
	r.bytes += n
	return n, e
}

func TestInvalidAuthenticationNeverReadsCiphertext(t *testing.T) {
	f := fixture(t)
	body := bytes.Repeat([]byte("x"), 32)
	raw, manifest, _ := signed(t, f, body)
	missingChains := f.stateA
	missingChains.VerifiedChains = nil
	mismatch := f.stateA
	mismatch.VerifiedChains = [][]*x509.Certificate{{f.certB}}
	incomplete := f.stateA
	incomplete.HandshakeComplete = false
	wrongPin := f.pin
	wrongPin.PublicKey = append(ed25519.PublicKey(nil), wrongPin.PublicKey...)
	wrongPin.PublicKey[0] ^= 1
	wrongMode := f.pin
	wrongMode.PipelineMode = "stats"
	wrongProfile := f.pin
	wrongProfile.ExecutionProfileSHA256 = strings.Repeat("f", 64)
	for _, tc := range []struct {
		name                string
		state               *tls.ConnectionState
		challenge, manifest []byte
		pin                 AuthorityPin
		now                 time.Time
	}{
		{"nil TLS", nil, raw, manifest, f.pin, f.now}, {"unverified", &missingChains, raw, manifest, f.pin, f.now}, {"incoherent chain", &mismatch, raw, manifest, f.pin, f.now}, {"incomplete handshake", &incomplete, raw, manifest, f.pin, f.now},
		{"other leaf", &f.stateB, raw, manifest, f.pin, f.now}, {"external pin", &f.stateA, raw, manifest, wrongPin, f.now}, {"mode", &f.stateA, raw, manifest, wrongMode, f.now}, {"profile", &f.stateA, raw, manifest, wrongProfile, f.now},
		{"expiry exact", &f.stateA, raw, manifest, f.pin, f.now.Add(5 * time.Minute)}, {"not yet issued", &f.stateA, raw, manifest, f.pin, f.now.Add(-time.Second)},
		{"bad claim", &f.stateA, bytes.Replace(raw, []byte("sample.fastq"), []byte("other.fastq"), 1), manifest, f.pin, f.now},
		{"bad manifest signature", &f.stateA, raw, bytes.Replace(manifest, []byte(`"signature":"`), []byte(`"signature":"0`), 1), f.pin, f.now},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &observedReader{r: bytes.NewReader(body)}
			if _, err := Finalize(context.Background(), tc.state, tc.challenge, tc.manifest, tc.pin, r, tc.now); err == nil {
				t.Fatal("accepted invalid authentication")
			}
			if r.calls != 0 {
				t.Fatal("read occurred before successful authentication")
			}
		})
	}
}

func TestAADPreventsRebinding(t *testing.T) {
	f := fixture(t)
	_, _, v := signed(t, f, bytes.Repeat([]byte("x"), 32))
	aad, err := CanonicalAAD(v)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(make([]byte, 32))
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	sealed := gcm.Seal(nil, nonce, []byte("synthetic control"), aad)
	if _, err := gcm.Open(nil, nonce, sealed, aad); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"AuthorityID", "JobID", "Nonce", "CredentialSHA256", "OriginalName", "EncryptionAlgorithm", "PipelineMode", "ExecutionProfileSHA256"} {
		t.Run(field, func(t *testing.T) {
			other := v
			switch field {
			case "AuthorityID":
				other.claim.AuthorityID = strings.Repeat("5", 32)
			case "JobID":
				other.claim.JobID = "fedcba0987654321"
			case "Nonce":
				other.claim.Nonce = strings.Repeat("6", 64)
			case "CredentialSHA256":
				other.claim.CredentialSHA256 = digest(f.certB.Raw)
			case "OriginalName":
				other.claim.OriginalName = "different.fastq"
			case "EncryptionAlgorithm":
				other.claim.EncryptionAlgorithm = "other"
			case "PipelineMode":
				other.claim.PipelineMode = "stats"
			case "ExecutionProfileSHA256":
				other.claim.ExecutionProfileSHA256 = strings.Repeat("7", 64)
			}
			changed, _ := CanonicalAAD(other)
			if _, err := gcm.Open(nil, nonce, sealed, changed); err == nil {
				t.Fatal("AAD rebinding accepted")
			}
		})
	}
}

func TestStrictWireJSON(t *testing.T) {
	f := fixture(t)
	raw, manifest, v := signed(t, f, bytes.Repeat([]byte("x"), 32))
	owner, _ := PrincipalFromTLS(&f.stateA)
	for _, target := range []struct {
		name   string
		raw    []byte
		verify func([]byte) error
	}{
		{"challenge", raw, func(b []byte) error { _, e := VerifyChallenge(b, f.pin, owner, f.now); return e }},
		{"manifest", manifest, func(b []byte) error { _, e := VerifyManifest(b, v, owner); return e }},
	} {
		t.Run(target.name, func(t *testing.T) {
			for name, mutate := range map[string]func([]byte) []byte{
				"duplicate outer": func(b []byte) []byte { return append([]byte(`{"signature":"x",`), b[1:]...) },
				"case alias":      func(b []byte) []byte { return bytes.Replace(b, []byte(`"signature"`), []byte(`"Signature"`), 1) },
				"unknown":         func(b []byte) []byte { return append([]byte(`{"extra":1,`), b[1:]...) },
				"null outer":      func(b []byte) []byte { return []byte(`null`) },
				"nested null": func(b []byte) []byte {
					return bytes.Replace(b, []byte(`"schema_version":1`), []byte(`"schema_version":null`), 1)
				},
				"duplicate nested": func(b []byte) []byte {
					return bytes.Replace(b, []byte(`"schema_version":1`), []byte(`"schema_version":1,"schema_version":1`), 1)
				},
				"nested alias": func(b []byte) []byte {
					return bytes.Replace(b, []byte(`"schema_version"`), []byte(`"Schema_Version"`), 1)
				},
				"missing nested": func(b []byte) []byte { return bytes.Replace(b, []byte(`"schema_version":1,`), nil, 1) },
				"wrong number": func(b []byte) []byte {
					return bytes.Replace(b, []byte(`"schema_version":1`), []byte(`"schema_version":1.0`), 1)
				},
				"trailing":     func(b []byte) []byte { return append(b, []byte(` {}`)...) },
				"oversize":     func(b []byte) []byte { return bytes.Repeat([]byte(" "), MaxChallengeBytes+1) },
				"invalid UTF8": func(b []byte) []byte { return append(b, 0xff) },
				"deep": func(b []byte) []byte {
					return []byte(`{"signature":` + strings.Repeat("[", 65) + `0` + strings.Repeat("]", 65) + `}`)
				},
			} {
				t.Run(name, func(t *testing.T) {
					if err := target.verify(mutate(append([]byte(nil), target.raw...))); err == nil {
						t.Fatal("invalid JSON accepted")
					}
				})
			}
		})
	}
}

func TestChallengePolicyAndTimes(t *testing.T) {
	f := fixture(t)
	owner, _ := PrincipalFromTLS(&f.stateA)
	base := ChallengeInput{"1234567890abcdef", strings.Repeat("3", 64), "file.fastq", f.now, f.now.Add(time.Minute)}
	for _, name := range []string{"job", "nonce", "filename", "zero time", "fraction", "lifetime", "reversed"} {
		t.Run(name, func(t *testing.T) {
			in := base
			switch name {
			case "job":
				in.JobID = strings.Repeat("A", 16)
			case "nonce":
				in.Nonce = "short"
			case "filename":
				in.OriginalName = "../secret"
			case "zero time":
				in.IssuedAt = time.Time{}
			case "fraction":
				in.IssuedAt = in.IssuedAt.Add(time.Nanosecond)
			case "lifetime":
				in.ExpiresAt = in.IssuedAt.Add(5*time.Minute + time.Second)
			case "reversed":
				in.ExpiresAt = in.IssuedAt
			}
			if _, err := SignChallenge(f.private, f.pin, owner, in); err == nil {
				t.Fatal("invalid input accepted")
			}
		})
	}
	for _, raw := range []string{"2026-10-15T00:00:00+00:00", "2026-10-15T00:00:00.0Z", "2026-10-15T00:00:00z"} {
		if _, e := canonicalTime(raw); e == nil {
			t.Fatal("noncanonical timestamp accepted")
		}
	}
	badPrivate := append(ed25519.PrivateKey(nil), f.private...)
	badPrivate[63] ^= 1
	if _, err := SignChallenge(badPrivate, f.pin, owner, base); err == nil {
		t.Fatal("inconsistent private key accepted")
	}
}

func TestPSSRequiresExactSaltAndRejectsPKCS1(t *testing.T) {
	f := fixture(t)
	_, manifest, v := signed(t, f, bytes.Repeat([]byte("x"), 32))
	owner, _ := PrincipalFromTLS(&f.stateA)
	var sm SignedManifest
	if err := json.Unmarshal(manifest, &sm); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(sm.Manifest)
	sum := sha256.Sum256(raw)
	for _, mode := range []string{"pkcs1", "maximum salt"} {
		t.Run(mode, func(t *testing.T) {
			var sig []byte
			var err error
			if mode == "pkcs1" {
				sig, err = rsa.SignPKCS1v15(rand.Reader, f.keyA, crypto.SHA256, sum[:])
			} else {
				sig, err = rsa.SignPSS(rand.Reader, f.keyA, crypto.SHA256, sum[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: crypto.SHA256})
			}
			if err != nil {
				t.Fatal(err)
			}
			changed := sm
			changed.Signature = hex.EncodeToString(sig)
			wire, _ := MarshalManifest(changed)
			if _, err := VerifyManifest(wire, v, owner); err == nil {
				t.Fatal("noncontract signature accepted")
			}
		})
	}
}
