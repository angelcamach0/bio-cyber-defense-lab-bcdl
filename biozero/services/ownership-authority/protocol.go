// SPDX-License-Identifier: AGPL-3.0-only
package ownership

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"time"
)

const (
	ChallengeDomain            = "biozero.ownership.challenge.v1"
	AADDomain                  = "biozero.ownership.aad.v1"
	ManifestDomain             = "biozero.ownership.manifest.v1"
	EncryptionAlgorithm        = "aes-256-gcm+rsa-oaep-sha256+owner-v1"
	MaxChallengeBytes          = 4096
	MaxManifestBytes           = 4096
	MaxCiphertextBytes   int64 = 25 << 20
	MaxChallengeLifetime       = 5 * time.Minute
)

func fail(code string) error   { return errors.New(code) }
func digest(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func hexValue(value string, size int) bool {
	if len(value) != size {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// AuthorityPin is trusted configuration, never obtained from the signed claim.
// Its mode/profile are fixed authority policy, not caller-selected fallbacks.
type AuthorityPin struct {
	AuthorityID            string
	PublicKey              ed25519.PublicKey
	PipelineMode           string
	ExecutionProfileSHA256 string
}

func (p AuthorityPin) validate() error {
	if !hexValue(p.AuthorityID, 32) || len(p.PublicKey) != ed25519.PublicKeySize ||
		(p.PipelineMode != "stats" && p.PipelineMode != "variants") || !hexValue(p.ExecutionProfileSHA256, 64) {
		return fail("ownership_pin_invalid")
	}
	return nil
}

// Principal is created only from an already-verified server-side TLS connection.
// An application fabricating ConnectionState is outside this transport boundary.
type Principal struct {
	leaf          *x509.Certificate
	credential    string
	authenticated bool
}

func (p Principal) CredentialSHA256() string { return p.credential }
func (p Principal) CommonName() string {
	if p.leaf == nil {
		return ""
	}
	return p.leaf.Subject.CommonName
}
func (p Principal) validate() error {
	if !p.authenticated || p.leaf == nil || digest(p.leaf.Raw) != p.credential {
		return fail("ownership_principal_invalid")
	}
	return nil
}

func rsaLeaf(cert *x509.Certificate) (*x509.Certificate, *rsa.PublicKey, error) {
	if cert == nil || len(cert.Raw) == 0 || len(cert.Raw) > 16<<10 {
		return nil, nil, fail("ownership_certificate_invalid")
	}
	leaf, err := x509.ParseCertificate(cert.Raw)
	if err != nil {
		return nil, nil, fail("ownership_certificate_invalid")
	}
	key, ok := leaf.PublicKey.(*rsa.PublicKey)
	if !ok || key.N == nil || key.N.BitLen() < 2048 || key.N.BitLen() > 4096 || key.E != 65537 ||
		leaf.IsCA || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return nil, nil, fail("ownership_certificate_invalid")
	}
	clientAuth := false
	for _, usage := range leaf.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			clientAuth = true
		}
	}
	if !clientAuth {
		return nil, nil, fail("ownership_certificate_invalid")
	}
	return leaf, key, nil
}

func PrincipalFromTLS(state *tls.ConnectionState) (Principal, error) {
	var zero Principal
	if state == nil || !state.HandshakeComplete || len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 ||
		state.PeerCertificates[0] == nil || state.VerifiedChains[0][0] == nil ||
		!bytes.Equal(state.PeerCertificates[0].Raw, state.VerifiedChains[0][0].Raw) {
		return zero, fail("ownership_tls_identity_invalid")
	}
	leaf, _, err := rsaLeaf(state.PeerCertificates[0])
	if err != nil {
		return zero, err
	}
	return Principal{leaf, digest(leaf.Raw), true}, nil
}

type ChallengeInput struct {
	JobID        string
	Nonce        string
	OriginalName string
	IssuedAt     time.Time
	ExpiresAt    time.Time
}
type Challenge struct {
	SchemaVersion          int    `json:"schema_version"`
	Domain                 string `json:"domain"`
	AuthorityID            string `json:"authority_id"`
	KeyID                  string `json:"key_id"`
	JobID                  string `json:"job_id"`
	Nonce                  string `json:"nonce"`
	CredentialSHA256       string `json:"credential_sha256"`
	OriginalName           string `json:"original_name"`
	EncryptionAlgorithm    string `json:"enc_alg"`
	PipelineMode           string `json:"pipeline_mode"`
	ExecutionProfileSHA256 string `json:"execution_profile_sha256"`
	IssuedAt               string `json:"issued_at"`
	ExpiresAt              string `json:"expires_at"`
}
type SignedChallenge struct {
	Claim     Challenge `json:"claim"`
	Signature string    `json:"signature"`
}
type VerifiedChallenge struct {
	claim     Challenge
	canonical []byte
	valid     bool
}

func (v VerifiedChallenge) Claims() Challenge { return v.claim }
func (v VerifiedChallenge) SHA256() string {
	if !v.valid {
		return ""
	}
	return digest(v.canonical)
}

func nameValid(name string) bool {
	if len(name) < 1 || len(name) > 128 || name == "." || name == ".." {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
func canonicalTime(raw string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil || len(raw) != 20 || t.UTC().Format(time.RFC3339) != raw {
		return time.Time{}, fail("ownership_time_invalid")
	}
	return t, nil
}
func validateClaim(c Challenge, p AuthorityPin, credential string) error {
	if err := p.validate(); err != nil {
		return err
	}
	if c.SchemaVersion != 1 || c.Domain != ChallengeDomain || c.AuthorityID != p.AuthorityID || c.KeyID != digest(p.PublicKey) ||
		!hexValue(c.JobID, 16) || !hexValue(c.Nonce, 64) || !hexValue(c.CredentialSHA256, 64) || c.CredentialSHA256 != credential ||
		!nameValid(c.OriginalName) || c.EncryptionAlgorithm != EncryptionAlgorithm || c.PipelineMode != p.PipelineMode ||
		c.ExecutionProfileSHA256 != p.ExecutionProfileSHA256 {
		return fail("ownership_challenge_invalid")
	}
	issued, err := canonicalTime(c.IssuedAt)
	if err != nil {
		return err
	}
	expires, err := canonicalTime(c.ExpiresAt)
	if err != nil {
		return err
	}
	if !expires.After(issued) || expires.Sub(issued) > MaxChallengeLifetime {
		return fail("ownership_time_invalid")
	}
	return nil
}
func MarshalChallenge(c SignedChallenge) ([]byte, error) { return boundedJSON(c, MaxChallengeBytes) }

func SignChallenge(key ed25519.PrivateKey, p AuthorityPin, owner Principal, input ChallengeInput) (SignedChallenge, error) {
	var zero SignedChallenge
	if err := owner.validate(); err != nil {
		return zero, err
	}
	if err := p.validate(); err != nil {
		return zero, err
	}
	if len(key) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(key[:ed25519.SeedSize]), key) ||
		!bytes.Equal(key.Public().(ed25519.PublicKey), p.PublicKey) {
		return zero, fail("ownership_signing_key_invalid")
	}
	if input.IssuedAt.IsZero() || input.ExpiresAt.IsZero() || input.IssuedAt.Nanosecond() != 0 || input.ExpiresAt.Nanosecond() != 0 {
		return zero, fail("ownership_time_invalid")
	}
	c := Challenge{1, ChallengeDomain, p.AuthorityID, digest(p.PublicKey), input.JobID, input.Nonce, owner.credential, input.OriginalName,
		EncryptionAlgorithm, p.PipelineMode, p.ExecutionProfileSHA256, input.IssuedAt.UTC().Format(time.RFC3339), input.ExpiresAt.UTC().Format(time.RFC3339)}
	if err := validateClaim(c, p, owner.credential); err != nil {
		return zero, err
	}
	raw, err := boundedJSON(c, MaxChallengeBytes)
	if err != nil {
		return zero, err
	}
	return SignedChallenge{c, hex.EncodeToString(ed25519.Sign(key, raw))}, nil
}

func verifyChallenge(raw []byte, p AuthorityPin, credential string, now time.Time) (VerifiedChallenge, error) {
	var zero VerifiedChallenge
	if err := p.validate(); err != nil {
		return zero, err
	}
	var signed SignedChallenge
	if err := strictJSON(raw, &signed, MaxChallengeBytes); err != nil {
		return zero, err
	}
	if err := validateClaim(signed.Claim, p, credential); err != nil {
		return zero, err
	}
	if !hexValue(signed.Signature, ed25519.SignatureSize*2) {
		return zero, fail("ownership_signature_invalid")
	}
	sig, _ := hex.DecodeString(signed.Signature)
	claim, _ := boundedJSON(signed.Claim, MaxChallengeBytes)
	if !ed25519.Verify(p.PublicKey, claim, sig) {
		return zero, fail("ownership_signature_invalid")
	}
	issued, _ := canonicalTime(signed.Claim.IssuedAt)
	expires, _ := canonicalTime(signed.Claim.ExpiresAt)
	if now.IsZero() || now.Before(issued) || !now.Before(expires) {
		return zero, fail("ownership_challenge_expired")
	}
	canonical, err := MarshalChallenge(signed)
	if err != nil {
		return zero, err
	}
	return VerifiedChallenge{signed.Claim, canonical, true}, nil
}
func VerifyChallenge(raw []byte, p AuthorityPin, owner Principal, now time.Time) (VerifiedChallenge, error) {
	if err := owner.validate(); err != nil {
		return VerifiedChallenge{}, err
	}
	return verifyChallenge(raw, p, owner.credential, now)
}

// VerifyChallengeForClient uses the client's local certificate, not its TLS
// PeerCertificates (which describe the server). It cannot create a Principal.
func VerifyChallengeForClient(raw []byte, p AuthorityPin, clientLeaf *x509.Certificate, now time.Time) (VerifiedChallenge, error) {
	leaf, _, err := rsaLeaf(clientLeaf)
	if err != nil {
		return VerifiedChallenge{}, err
	}
	return verifyChallenge(raw, p, digest(leaf.Raw), now)
}

// CanonicalAAD returns the exact UTF-8 bytes for GCM Seal/Open. All facts derive
// from the pinned authority challenge, including mode and execution profile.
func CanonicalAAD(v VerifiedChallenge) ([]byte, error) {
	if !v.valid {
		return nil, fail("ownership_challenge_unverified")
	}
	c := v.claim
	aad := struct {
		SchemaVersion          int    `json:"schema_version"`
		Domain                 string `json:"domain"`
		AuthorityID            string `json:"authority_id"`
		JobID                  string `json:"job_id"`
		Nonce                  string `json:"nonce"`
		CredentialSHA256       string `json:"credential_sha256"`
		OriginalName           string `json:"original_name"`
		EncryptionAlgorithm    string `json:"enc_alg"`
		PipelineMode           string `json:"pipeline_mode"`
		ExecutionProfileSHA256 string `json:"execution_profile_sha256"`
	}{1, AADDomain, c.AuthorityID, c.JobID, c.Nonce, c.CredentialSHA256, c.OriginalName, c.EncryptionAlgorithm, c.PipelineMode, c.ExecutionProfileSHA256}
	return boundedJSON(aad, MaxChallengeBytes)
}

type ManifestInput struct {
	CiphertextSHA256  string
	CiphertextBytes   int64
	KeyEnvelopeSHA256 string
}
type Manifest struct {
	SchemaVersion      int    `json:"schema_version"`
	Domain             string `json:"domain"`
	SignatureAlgorithm string `json:"sig_alg"`
	ChallengeSHA256    string `json:"challenge_sha256"`
	AADSHA256          string `json:"aad_sha256"`
	CiphertextSHA256   string `json:"ciphertext_sha256"`
	CiphertextBytes    int64  `json:"ciphertext_bytes"`
	KeyEnvelopeSHA256  string `json:"key_envelope_sha256"`
}
type SignedManifest struct {
	Manifest  Manifest `json:"manifest"`
	Signature string   `json:"signature"`
}
type VerifiedManifest struct {
	manifest  Manifest
	canonical []byte
	valid     bool
}

func (v VerifiedManifest) Claims() Manifest            { return v.manifest }
func MarshalManifest(m SignedManifest) ([]byte, error) { return boundedJSON(m, MaxManifestBytes) }
func validateManifest(m Manifest, v VerifiedChallenge) error {
	if !v.valid {
		return fail("ownership_challenge_unverified")
	}
	aad, err := CanonicalAAD(v)
	if err != nil {
		return err
	}
	if m.SchemaVersion != 1 || m.Domain != ManifestDomain || m.SignatureAlgorithm != "rsa-pss-sha256" || m.ChallengeSHA256 != v.SHA256() || m.AADSHA256 != digest(aad) ||
		!hexValue(m.CiphertextSHA256, 64) || m.CiphertextBytes < 16 || m.CiphertextBytes > MaxCiphertextBytes || !hexValue(m.KeyEnvelopeSHA256, 64) {
		return fail("ownership_manifest_invalid")
	}
	return nil
}
func SignManifest(key *rsa.PrivateKey, clientLeaf *x509.Certificate, v VerifiedChallenge, input ManifestInput) (SignedManifest, error) {
	var zero SignedManifest
	leaf, pub, err := rsaLeaf(clientLeaf)
	if err != nil {
		return zero, err
	}
	if !v.valid || digest(leaf.Raw) != v.claim.CredentialSHA256 || key == nil || key.N == nil || key.N.Cmp(pub.N) != 0 || key.E != pub.E || key.Validate() != nil {
		return zero, fail("ownership_client_key_mismatch")
	}
	aad, err := CanonicalAAD(v)
	if err != nil {
		return zero, err
	}
	m := Manifest{1, ManifestDomain, "rsa-pss-sha256", v.SHA256(), digest(aad), input.CiphertextSHA256, input.CiphertextBytes, input.KeyEnvelopeSHA256}
	if err := validateManifest(m, v); err != nil {
		return zero, err
	}
	raw, err := boundedJSON(m, MaxManifestBytes)
	if err != nil {
		return zero, err
	}
	hash := sha256.Sum256(raw)
	sig, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, hash[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	if err != nil {
		return zero, fail("ownership_client_sign_failed")
	}
	return SignedManifest{m, hex.EncodeToString(sig)}, nil
}
func VerifyManifest(raw []byte, v VerifiedChallenge, owner Principal) (VerifiedManifest, error) {
	var zero VerifiedManifest
	if err := owner.validate(); err != nil {
		return zero, err
	}
	if !v.valid || owner.credential != v.claim.CredentialSHA256 {
		return zero, fail("ownership_manifest_owner_mismatch")
	}
	var signed SignedManifest
	if err := strictJSON(raw, &signed, MaxManifestBytes); err != nil {
		return zero, err
	}
	if err := validateManifest(signed.Manifest, v); err != nil {
		return zero, err
	}
	key := owner.leaf.PublicKey.(*rsa.PublicKey)
	if !hexValue(signed.Signature, key.Size()*2) {
		return zero, fail("ownership_signature_invalid")
	}
	sig, _ := hex.DecodeString(signed.Signature)
	manifest, _ := boundedJSON(signed.Manifest, MaxManifestBytes)
	hash := sha256.Sum256(manifest)
	if rsa.VerifyPSS(key, crypto.SHA256, hash[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}) != nil {
		return zero, fail("ownership_signature_invalid")
	}
	canonical, err := MarshalManifest(signed)
	if err != nil {
		return zero, err
	}
	return VerifiedManifest{signed.Manifest, canonical, true}, nil
}
