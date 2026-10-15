// SPDX-License-Identifier: AGPL-3.0-only
package ownership

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"time"
)

const AcceptanceDomain = "biozero.ownership.acceptance.v1"
const MaxAcceptanceBytes = 64 << 10

// AcceptanceScope is an external expected store/policy identity. It must come
// from trusted genesis/configuration, never from the object being verified.
type AcceptanceScope struct {
	StoreID      string `json:"store_id"`
	PolicySHA256 string `json:"policy_sha256"`
}

func (s AcceptanceScope) validate() error {
	if !hexValue(s.StoreID, 32) || !hexValue(s.PolicySHA256, 64) {
		return fail("ownership_acceptance_scope_invalid")
	}
	return nil
}

// AcceptanceRecord authenticates a completed verification decision. AcceptedAt
// is sampled after all ciphertext checks, within the challenge window. Signing
// and durable persistence follow that decision; this timestamp is not proof of
// a filesystem commit deadline. Raw certificate/claim values remain private.
type AcceptanceRecord struct {
	SchemaVersion int             `json:"schema_version"`
	Domain        string          `json:"domain"`
	AuthorityID   string          `json:"authority_id"`
	KeyID         string          `json:"key_id"`
	StoreID       string          `json:"store_id"`
	PolicySHA256  string          `json:"policy_sha256"`
	AcceptedAt    string          `json:"accepted_at"`
	Challenge     SignedChallenge `json:"challenge"`
	Manifest      SignedManifest  `json:"manifest"`
	CredentialDER string          `json:"credential_der"`
	Binding       Binding         `json:"binding"`
}

type SignedAcceptance struct {
	Record    AcceptanceRecord `json:"record"`
	Signature string           `json:"signature"`
}

// VerifiedAcceptance is signature-checked historical data, not evidence that a
// particular Store is currently healthy or a guarantee of rollback resistance.
// Its constructor rechecks authority, exact external scope, TLS-leaf fingerprint,
// both original signatures, timing and binding. No caller-selected clock is used.
type VerifiedAcceptance struct {
	record    AcceptanceRecord
	challenge VerifiedChallenge
	canonical []byte
	valid     bool
}

func (v VerifiedAcceptance) Claims() AcceptanceRecord { return v.record }
func (v VerifiedAcceptance) Binding() Binding {
	if !v.valid {
		return Binding{}
	}
	return v.record.Binding
}
func (v VerifiedAcceptance) SHA256() string {
	if !v.valid {
		return ""
	}
	return digest(v.canonical)
}
func CanonicalAADFromAcceptance(v VerifiedAcceptance) ([]byte, error) {
	if !v.valid {
		return nil, fail("ownership_acceptance_unverified")
	}
	return CanonicalAAD(v.challenge)
}
func MarshalAcceptance(a SignedAcceptance) ([]byte, error) { return boundedJSON(a, MaxAcceptanceBytes) }

func acceptanceTime(raw string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil || t.IsZero() || len(raw) < 20 || len(raw) > 30 || t.UTC().Format(time.RFC3339Nano) != raw {
		return time.Time{}, fail("ownership_acceptance_time_invalid")
	}
	return t, nil
}

func bindingFor(challenge VerifiedChallenge, manifest VerifiedManifest) Binding {
	c, m := challenge.claim, manifest.manifest
	return Binding{c.AuthorityID, c.JobID, c.Nonce, c.CredentialSHA256, c.OriginalName, c.EncryptionAlgorithm, c.PipelineMode, c.ExecutionProfileSHA256,
		m.ChallengeSHA256, m.AADSHA256, digest(manifest.canonical), m.CiphertextSHA256, m.CiphertextBytes, m.KeyEnvelopeSHA256}
}

// verifyAcceptedFacts validates original facts against the signed historical
// decision time. It does not construct a fresh authenticated Principal from an
// old certificate: only a live verified TLS connection may create that capability.
func verifyAcceptedFacts(record AcceptanceRecord, pin AuthorityPin, scope AcceptanceScope) (VerifiedChallenge, error) {
	var zero VerifiedChallenge
	if err := pin.validate(); err != nil {
		return zero, err
	}
	if err := scope.validate(); err != nil {
		return zero, err
	}
	if record.SchemaVersion != 1 || record.Domain != AcceptanceDomain || record.AuthorityID != pin.AuthorityID || record.KeyID != digest(pin.PublicKey) ||
		record.StoreID != scope.StoreID || record.PolicySHA256 != scope.PolicySHA256 {
		return zero, fail("ownership_acceptance_invalid")
	}
	acceptedAt, err := acceptanceTime(record.AcceptedAt)
	if err != nil {
		return zero, err
	}
	if len(record.CredentialDER) == 0 || len(record.CredentialDER) > 2*(16<<10) || !hexValue(record.CredentialDER, len(record.CredentialDER)) || len(record.CredentialDER)%2 != 0 {
		return zero, fail("ownership_certificate_invalid")
	}
	der, err := hex.DecodeString(record.CredentialDER)
	if err != nil {
		return zero, fail("ownership_certificate_invalid")
	}
	// rsaLeaf parses DER itself and checks usage/key bounds. No current-time
	// chain check can retroactively invalidate a previously accepted decision.
	leaf, key, err := rsaLeaf(&x509.Certificate{Raw: der})
	if err != nil {
		return zero, err
	}
	if acceptedAt.Before(leaf.NotBefore) || !acceptedAt.Before(leaf.NotAfter) {
		return zero, fail("ownership_acceptance_time_invalid")
	}
	rawChallenge, err := MarshalChallenge(record.Challenge)
	if err != nil {
		return zero, err
	}
	challenge, err := verifyChallenge(rawChallenge, pin, digest(leaf.Raw), acceptedAt)
	if err != nil {
		return zero, err
	}
	rawManifest, err := MarshalManifest(record.Manifest)
	if err != nil {
		return zero, err
	}
	if err = validateManifest(record.Manifest.Manifest, challenge); err != nil {
		return zero, err
	}
	if !hexValue(record.Manifest.Signature, key.Size()*2) {
		return zero, fail("ownership_signature_invalid")
	}
	sig, _ := hex.DecodeString(record.Manifest.Signature)
	claim, err := boundedJSON(record.Manifest.Manifest, MaxManifestBytes)
	if err != nil {
		return zero, err
	}
	hash := sha256.Sum256(claim)
	if rsa.VerifyPSS(key, crypto.SHA256, hash[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}) != nil {
		return zero, fail("ownership_signature_invalid")
	}
	manifest := VerifiedManifest{record.Manifest.Manifest, rawManifest, true}
	if record.Binding != bindingFor(challenge, manifest) {
		return zero, fail("ownership_acceptance_binding_invalid")
	}
	return challenge, nil
}

// VerifyAcceptance has no now parameter. The externally pinned authority attests
// the original time and leaf identity; consumers still need trusted store health,
// enrollment/revocation policy and an authoritative delivery channel.
func VerifyAcceptance(raw []byte, pin AuthorityPin, scope AcceptanceScope) (VerifiedAcceptance, error) {
	var zero VerifiedAcceptance
	if err := pin.validate(); err != nil {
		return zero, err
	}
	if err := scope.validate(); err != nil {
		return zero, err
	}
	var signed SignedAcceptance
	if err := strictJSON(raw, &signed, MaxAcceptanceBytes); err != nil {
		return zero, err
	}
	if !hexValue(signed.Signature, ed25519.SignatureSize*2) {
		return zero, fail("ownership_signature_invalid")
	}
	sig, _ := hex.DecodeString(signed.Signature)
	record, err := boundedJSON(signed.Record, MaxAcceptanceBytes)
	if err != nil {
		return zero, err
	}
	if !ed25519.Verify(pin.PublicKey, record, sig) {
		return zero, fail("ownership_signature_invalid")
	}
	challenge, err := verifyAcceptedFacts(signed.Record, pin, scope)
	if err != nil {
		return zero, err
	}
	canonical, err := MarshalAcceptance(signed)
	if err != nil {
		return zero, err
	}
	return VerifiedAcceptance{signed.Record, challenge, canonical, true}, nil
}

// sealAcceptance is package-private. Only the authority Store may call it after
// Finalize measured the real bytes; no public API signs a caller-created Binding.
func sealAcceptance(key ed25519.PrivateKey, pin AuthorityPin, scope AcceptanceScope, state *tls.ConnectionState, rawChallenge, rawManifest []byte, measured Binding, acceptedAt time.Time) (SignedAcceptance, error) {
	var zero SignedAcceptance
	if err := pin.validate(); err != nil {
		return zero, err
	}
	if err := scope.validate(); err != nil {
		return zero, err
	}
	if len(key) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(key[:ed25519.SeedSize]), key) || !bytes.Equal(key.Public().(ed25519.PublicKey), pin.PublicKey) {
		return zero, fail("ownership_signing_key_invalid")
	}
	owner, err := PrincipalFromTLS(state)
	if err != nil {
		return zero, err
	}
	if acceptedAt.IsZero() {
		return zero, fail("ownership_acceptance_time_invalid")
	}
	challenge, err := VerifyChallenge(rawChallenge, pin, owner, acceptedAt)
	if err != nil {
		return zero, err
	}
	manifest, err := VerifyManifest(rawManifest, challenge, owner)
	if err != nil {
		return zero, err
	}
	if measured != bindingFor(challenge, manifest) {
		return zero, fail("ownership_acceptance_binding_invalid")
	}
	var signedChallenge SignedChallenge
	var signedManifest SignedManifest
	if err = strictJSON(rawChallenge, &signedChallenge, MaxChallengeBytes); err != nil {
		return zero, err
	}
	if err = strictJSON(rawManifest, &signedManifest, MaxManifestBytes); err != nil {
		return zero, err
	}
	record := AcceptanceRecord{1, AcceptanceDomain, pin.AuthorityID, digest(pin.PublicKey), scope.StoreID, scope.PolicySHA256,
		acceptedAt.UTC().Format(time.RFC3339Nano), signedChallenge, signedManifest, hex.EncodeToString(owner.leaf.Raw), measured}
	if _, err = verifyAcceptedFacts(record, pin, scope); err != nil {
		return zero, err
	}
	data, err := boundedJSON(record, MaxAcceptanceBytes)
	if err != nil {
		return zero, err
	}
	signed := SignedAcceptance{record, hex.EncodeToString(ed25519.Sign(key, data))}
	if _, err = MarshalAcceptance(signed); err != nil {
		return zero, err
	}
	return signed, nil
}
