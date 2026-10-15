// SPDX-License-Identifier: AGPL-3.0-only
package ownership

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"time"
)

// Owner-v1 carries only GCM ciphertext and its 16-byte tag in the body. The
// decoded OAEP-SHA256 envelope contains key[32] || nonce[12], with an empty label.
// The independently verified challenge supplies the mandatory canonical GCM AAD.
const MaxPlaintextBytes = MaxCiphertextBytes - 16

// EncryptedPayload is a mutable transport DTO, not a verified capability. Keep
// its original bytes in the client's durable workspace before Finalize. It does
// not contain the unwrapped symmetric key or nonce.
type EncryptedPayload struct {
	Ciphertext  []byte
	KeyEnvelope []byte
	Manifest    []byte
}

func payloadPublicKey(key *rsa.PublicKey) bool {
	return key != nil && key.N != nil && key.N.Sign() > 0 && key.N.BitLen() >= 2048 && key.N.BitLen() <= 4096 && key.E == 65537
}

func payloadPrivateKey(key *rsa.PrivateKey) bool {
	if key == nil || !payloadPublicKey(&key.PublicKey) || key.D == nil || key.D.Sign() <= 0 || key.D.BitLen() > 4096 || len(key.Primes) < 2 || len(key.Primes) > 5 {
		return false
	}
	for _, prime := range key.Primes {
		if prime == nil || prime.Sign() <= 0 || prime.BitLen() > 4096 {
			return false
		}
	}
	return key.Validate() == nil
}

// EncryptForChallenge verifies the external authority pin and local client leaf,
// then encrypts once with the signed context and signs with that same leaf key.
// EncryptionKey is a separately trusted worker encryption key, never learned from
// the authority's TLS certificate or from an incoming challenge. This function
// does no network/file publication or retry; its caller owns durable pre-network intent and retention.
func EncryptForChallenge(rawChallenge []byte, pin AuthorityPin, clientLeaf *x509.Certificate, signingKey *rsa.PrivateKey, encryptionKey *rsa.PublicKey, plaintext []byte, now time.Time) (EncryptedPayload, error) {
	var zero EncryptedPayload
	if int64(len(plaintext)) > MaxPlaintextBytes || !payloadPublicKey(encryptionKey) {
		return zero, fail("ownership_payload_invalid")
	}
	challenge, err := VerifyChallengeForClient(rawChallenge, pin, clientLeaf, now)
	if err != nil {
		return zero, err
	}
	leaf, pub, err := rsaLeaf(clientLeaf)
	if err != nil {
		return zero, err
	}
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return zero, fail("ownership_certificate_expired")
	}
	if !payloadPrivateKey(signingKey) || signingKey.N.Cmp(pub.N) != 0 || signingKey.E != pub.E {
		return zero, fail("ownership_client_key_mismatch")
	}
	// A separate configured key is required; using the client signing key as the
	// encryption recipient accidentally grants that client another role's custody.
	if encryptionKey.N.Cmp(pub.N) == 0 && encryptionKey.E == pub.E {
		return zero, fail("ownership_encryption_key_not_separate")
	}
	material := make([]byte, 44)
	if _, err = rand.Read(material); err != nil {
		return zero, fail("ownership_payload_random_failed")
	}
	defer clear(material)
	block, err := aes.NewCipher(material[:32])
	if err != nil {
		return zero, fail("ownership_payload_invalid")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return zero, fail("ownership_payload_invalid")
	}
	aad, err := CanonicalAAD(challenge)
	if err != nil {
		return zero, err
	}
	ciphertext := gcm.Seal(nil, material[32:], plaintext, aad)
	envelope, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, encryptionKey, material, nil)
	if err != nil {
		return zero, fail("ownership_envelope_failed")
	}
	signed, err := SignManifest(signingKey, leaf, challenge, ManifestInput{digest(ciphertext), int64(len(ciphertext)), digest(envelope)})
	if err != nil {
		return zero, err
	}
	manifest, err := MarshalManifest(signed)
	if err != nil {
		return zero, err
	}
	return EncryptedPayload{ciphertext, envelope, manifest}, nil
}

// DecryptAcceptedPayload measures the actual body AND decoded envelope against a
// previously verified authority record before OAEP/GCM. Callers must additionally
// match that record to their trusted job/profile/receipt and enforce resource and
// release policy. This helper does not admit execution, authorize a live reader,
// certify science or migrate the old worker path.
func DecryptAcceptedPayload(accepted VerifiedAcceptance, ciphertext, envelope []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	if !accepted.valid {
		return nil, fail("ownership_acceptance_unverified")
	}
	binding := accepted.Binding()
	if int64(len(ciphertext)) != binding.CiphertextBytes || int64(len(ciphertext)) > MaxCiphertextBytes || len(ciphertext) < 16 || digest(ciphertext) != binding.CiphertextSHA256 {
		return nil, fail("ownership_ciphertext_mismatch")
	}
	if len(envelope) < 256 || len(envelope) > 512 || digest(envelope) != binding.KeyEnvelopeSHA256 {
		return nil, fail("ownership_envelope_mismatch")
	}
	if !payloadPrivateKey(privateKey) || len(envelope) != privateKey.Size() {
		return nil, fail("ownership_envelope_key_invalid")
	}
	aad, err := CanonicalAADFromAcceptance(accepted)
	if err != nil {
		return nil, err
	}
	material, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, envelope, nil)
	if err != nil {
		return nil, fail("ownership_envelope_failed")
	}
	defer clear(material)
	if len(material) != 44 {
		return nil, fail("ownership_envelope_material_invalid")
	}
	block, err := aes.NewCipher(material[:32])
	if err != nil {
		return nil, fail("ownership_payload_invalid")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fail("ownership_payload_invalid")
	}
	plaintext, err := gcm.Open(nil, material[32:], ciphertext, aad)
	if err != nil {
		return nil, fail("ownership_payload_authentication_failed")
	}
	return plaintext, nil
}
