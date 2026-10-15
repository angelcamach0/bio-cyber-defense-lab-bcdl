//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package ownership

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"testing"
)

var payloadKeyOnce sync.Once
var payloadKey *rsa.PrivateKey

func payloadWorkerKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	payloadKeyOnce.Do(func() {
		var err error
		payloadKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
	})
	if payloadKey == nil {
		t.Fatal("worker key unavailable")
	}
	return payloadKey
}

func payloadChallenge(t *testing.T, other bool) []byte {
	t.Helper()
	f := fixture(t)
	state := &f.stateA
	if other {
		state = &f.stateB
	}
	owner, err := PrincipalFromTLS(state)
	if err != nil {
		t.Fatal(err)
	}
	job, err := storeRandom(8)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := storeRandom(32)
	if err != nil {
		t.Fatal(err)
	}
	ch, err := SignChallenge(f.private, f.pin, owner, ChallengeInput{job, nonce, "input.fastq", f.now, f.now.Add(MaxChallengeLifetime)})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalChallenge(ch)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// This exercises the pure measured/signature boundary, not Store durability.
func payloadAcceptance(t *testing.T, ch []byte, body, envelope []byte, other bool) VerifiedAcceptance {
	t.Helper()
	f := fixture(t)
	leaf, key, state := f.certA, f.keyA, &f.stateA
	if other {
		leaf, key, state = f.certB, f.keyB, &f.stateB
	}
	v, err := VerifyChallengeForClient(ch, f.pin, leaf, f.now)
	if err != nil {
		t.Fatal(err)
	}
	m, err := SignManifest(key, leaf, v, ManifestInput{digest(body), int64(len(body)), digest(envelope)})
	if err != nil {
		t.Fatal(err)
	}
	rawManifest, err := MarshalManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := Finalize(context.Background(), state, ch, rawManifest, f.pin, bytes.NewReader(body), f.now)
	if err != nil {
		t.Fatal(err)
	}
	scope := AcceptanceScope{StoreID: "11111111111111111111111111111111", PolicySHA256: "2222222222222222222222222222222222222222222222222222222222222222"}
	a, err := sealAcceptance(f.private, f.pin, scope, state, ch, rawManifest, binding, f.now)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalAcceptance(a)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := VerifyAcceptance(raw, f.pin, scope)
	if err != nil {
		t.Fatal(err)
	}
	return accepted
}

func TestPayloadActualOAEPAndMandatoryAAD(t *testing.T) {
	f := fixture(t)
	worker := payloadWorkerKey(t)
	for _, tc := range []struct {
		name  string
		plain []byte
	}{{"empty", nil}, {"one_byte", []byte{0}}, {"text", []byte("synthetic private input")}} {
		t.Run(tc.name, func(t *testing.T) {
			plain := tc.plain
			ch := payloadChallenge(t, false)
			p, err := EncryptForChallenge(ch, f.pin, f.certA, f.keyA, &worker.PublicKey, plain, f.now)
			if err != nil {
				t.Fatal(err)
			}
			if len(p.Ciphertext) != len(plain)+16 || len(p.KeyEnvelope) != worker.Size() {
				t.Fatal("wire sizes changed")
			}
			material, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, worker, p.KeyEnvelope, nil)
			if err != nil || len(material) != 44 {
				t.Fatal("actual OAEP material invalid", err)
			}
			defer clear(material)
			v, err := VerifyChallengeForClient(ch, f.pin, f.certA, f.now)
			if err != nil {
				t.Fatal(err)
			}
			aad, err := CanonicalAAD(v)
			if err != nil {
				t.Fatal(err)
			}
			block, err := aes.NewCipher(material[:32])
			if err != nil {
				t.Fatal(err)
			}
			gcm, err := cipher.NewGCM(block)
			if err != nil {
				t.Fatal(err)
			}
			got, err := gcm.Open(nil, material[32:], p.Ciphertext, aad)
			if err != nil || !bytes.Equal(got, plain) {
				t.Fatal("independent GCM read failed", err)
			}
			if _, err = gcm.Open(nil, material[32:], p.Ciphertext, nil); err == nil {
				t.Fatal("nil AAD authenticated")
			}
			var m SignedManifest
			if strictJSON(p.Manifest, &m, MaxManifestBytes) != nil || m.Manifest.KeyEnvelopeSHA256 != digest(p.KeyEnvelope) || m.Manifest.KeyEnvelopeSHA256 == digest([]byte(hex.EncodeToString(p.KeyEnvelope))) {
				t.Fatal("envelope digest is not decoded OAEP bytes")
			}
			a := payloadAcceptance(t, ch, p.Ciphertext, p.KeyEnvelope, false)
			got, err = DecryptAcceptedPayload(a, p.Ciphertext, p.KeyEnvelope, worker)
			if err != nil || !bytes.Equal(got, plain) {
				t.Fatal("accepted decrypt failed", err)
			}
		})
	}
}

func TestPayloadOtherLeafResigningCannotRebindCiphertext(t *testing.T) {
	f := fixture(t)
	worker := payloadWorkerKey(t)
	chA, chB := payloadChallenge(t, false), payloadChallenge(t, true)
	p, err := EncryptForChallenge(chA, f.pin, f.certA, f.keyA, &worker.PublicKey, []byte("synthetic transfer"), f.now)
	if err != nil {
		t.Fatal(err)
	}
	a := payloadAcceptance(t, chA, p.Ciphertext, p.KeyEnvelope, false)
	if _, err = DecryptAcceptedPayload(a, p.Ciphertext, p.KeyEnvelope, worker); err != nil {
		t.Fatal(err)
	}
	// B really signs and the authority really measures/accepts the copied bytes.
	// Only GCM under B's distinct signed AAD rejects; an authority rejection here
	// would hide the required downstream gate.
	b := payloadAcceptance(t, chB, p.Ciphertext, p.KeyEnvelope, true)
	got, err := DecryptAcceptedPayload(b, p.Ciphertext, p.KeyEnvelope, worker)
	if err == nil || err.Error() != "ownership_payload_authentication_failed" || got != nil {
		t.Fatal("copied ciphertext authenticated for other leaf/job", err)
	}
}

func TestPayloadRejectsChangedBytesBeforeUnwrap(t *testing.T) {
	f := fixture(t)
	worker := payloadWorkerKey(t)
	ch := payloadChallenge(t, false)
	p, err := EncryptForChallenge(ch, f.pin, f.certA, f.keyA, &worker.PublicKey, []byte("synthetic"), f.now)
	if err != nil {
		t.Fatal(err)
	}
	a := payloadAcceptance(t, ch, p.Ciphertext, p.KeyEnvelope, false)
	for _, name := range []string{"unverified", "cipher_changed", "cipher_short", "cipher_extra", "envelope_changed", "envelope_short", "envelope_extra", "no_key", "wrong_key"} {
		t.Run(name, func(t *testing.T) {
			body, env := bytes.Clone(p.Ciphertext), bytes.Clone(p.KeyEnvelope)
			accepted, key := a, worker
			want := "ownership_ciphertext_mismatch"
			switch name {
			case "unverified":
				accepted = VerifiedAcceptance{}
				want = "ownership_acceptance_unverified"
			case "cipher_changed":
				body[0] ^= 1
			case "cipher_short":
				body = body[:len(body)-1]
			case "cipher_extra":
				body = append(body, 1)
			case "envelope_changed":
				env[0] ^= 1
				want = "ownership_envelope_mismatch"
			case "envelope_short":
				env = env[:len(env)-1]
				want = "ownership_envelope_mismatch"
			case "envelope_extra":
				env = append(env, 1)
				want = "ownership_envelope_mismatch"
			case "no_key":
				key = nil
				want = "ownership_envelope_key_invalid"
			case "wrong_key":
				key = f.keyB
				want = "ownership_envelope_failed"
			}
			plain, e := DecryptAcceptedPayload(accepted, body, env, key)
			if e == nil || e.Error() != want || plain != nil {
				t.Fatal("unsafe payload released", e)
			}
		})
	}
}

func TestPayloadAuthenticatedMalformedEnvelopeFails(t *testing.T) {
	f := fixture(t)
	worker := payloadWorkerKey(t)
	ch := payloadChallenge(t, false)
	p, err := EncryptForChallenge(ch, f.pin, f.certA, f.keyA, &worker.PublicKey, []byte("synthetic"), f.now)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"short_material", "wrong_label", "invalid_oaep"} {
		t.Run(name, func(t *testing.T) {
			var env []byte
			want := "ownership_envelope_failed"
			switch name {
			case "short_material":
				env, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, &worker.PublicKey, make([]byte, 43), nil)
				want = "ownership_envelope_material_invalid"
			case "wrong_label":
				env, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, &worker.PublicKey, make([]byte, 44), []byte("different"))
			case "invalid_oaep":
				env = make([]byte, worker.Size())
			}
			if err != nil {
				t.Fatal(err)
			}
			accepted := payloadAcceptance(t, ch, p.Ciphertext, env, false)
			plain, e := DecryptAcceptedPayload(accepted, p.Ciphertext, env, worker)
			if e == nil || e.Error() != want || plain != nil {
				t.Fatal("malformed authenticated envelope released plaintext", e)
			}
		})
	}
}

func TestPayloadEncryptionPreconditions(t *testing.T) {
	f := fixture(t)
	worker := payloadWorkerKey(t)
	ch := payloadChallenge(t, false)
	for _, name := range []string{"wrong_leaf", "wrong_signing_key", "recipient_is_client", "nil_recipient", "changed_pin", "expired", "oversize"} {
		t.Run(name, func(t *testing.T) {
			leaf, sign, recipient, pin, now, plain := f.certA, f.keyA, &worker.PublicKey, f.pin, f.now, []byte("input")
			switch name {
			case "wrong_leaf":
				leaf = f.certB
				sign = f.keyB
			case "wrong_signing_key":
				sign = f.keyB
			case "recipient_is_client":
				recipient = &f.keyA.PublicKey
			case "nil_recipient":
				recipient = nil
			case "changed_pin":
				pin.ExecutionProfileSHA256 = digest([]byte("another profile"))
			case "expired":
				now = now.Add(MaxChallengeLifetime)
			case "oversize":
				plain = make([]byte, MaxPlaintextBytes+1)
			}
			p, e := EncryptForChallenge(ch, pin, leaf, sign, recipient, plain, now)
			if e == nil || p.Ciphertext != nil || p.KeyEnvelope != nil || p.Manifest != nil {
				t.Fatal("invalid encryption request produced payload")
			}
		})
	}
}
