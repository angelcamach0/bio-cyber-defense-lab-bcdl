// SPDX-License-Identifier: AGPL-3.0-only
package ownership

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"io"
	"time"
)

// Binding is verified protocol data, not an authority signature or a durable
// acceptance record. The future authority store must persist acceptance itself.
type Binding struct {
	AuthorityID            string `json:"authority_id"`
	JobID                  string `json:"job_id"`
	Nonce                  string `json:"nonce"`
	CredentialSHA256       string `json:"credential_sha256"`
	OriginalName           string `json:"original_name"`
	EncryptionAlgorithm    string `json:"enc_alg"`
	PipelineMode           string `json:"pipeline_mode"`
	ExecutionProfileSHA256 string `json:"execution_profile_sha256"`
	ChallengeSHA256        string `json:"challenge_sha256"`
	AADSHA256              string `json:"aad_sha256"`
	ManifestSHA256         string `json:"manifest_sha256"`
	CiphertextSHA256       string `json:"ciphertext_sha256"`
	CiphertextBytes        int64  `json:"ciphertext_bytes"`
	KeyEnvelopeSHA256      string `json:"key_envelope_sha256"`
}

// Finalize authenticates TLS and both signatures before the first ciphertext
// Read. now is a trusted authority clock sample, not client input. Elapsed
// verification/read time also counts against the challenge acceptance window.
// Context is checked between reads; it cannot interrupt a blocking io.Reader.
func Finalize(ctx context.Context, state *tls.ConnectionState, rawChallenge, rawManifest []byte, pin AuthorityPin, ciphertext io.Reader, now time.Time) (Binding, error) {
	var zero Binding
	started := time.Now()
	if ctx == nil || ctx.Err() != nil {
		return zero, fail("ownership_cancelled")
	}
	owner, err := PrincipalFromTLS(state)
	if err != nil {
		return zero, err
	}
	challenge, err := VerifyChallenge(rawChallenge, pin, owner, now)
	if err != nil {
		return zero, err
	}
	manifest, err := VerifyManifest(rawManifest, challenge, owner)
	if err != nil {
		return zero, err
	}
	if ciphertext == nil {
		return zero, fail("ownership_ciphertext_reader_invalid")
	}
	m := manifest.manifest
	hash := sha256.New()
	remaining := m.CiphertextBytes
	buffer := make([]byte, 64<<10)
	ended := false
	for remaining > 0 {
		if ctx.Err() != nil {
			return zero, fail("ownership_cancelled")
		}
		want := int64(len(buffer))
		if remaining < want {
			want = remaining
		}
		n, readErr := ciphertext.Read(buffer[:want])
		if n < 0 || int64(n) > want {
			return zero, fail("ownership_ciphertext_read_failed")
		}
		if n > 0 {
			_, _ = hash.Write(buffer[:n])
			remaining -= int64(n)
		}
		if readErr == io.EOF {
			ended = true
			break
		}
		if readErr != nil || n == 0 {
			return zero, fail("ownership_ciphertext_read_failed")
		}
	}
	if remaining != 0 {
		return zero, fail("ownership_ciphertext_size_mismatch")
	}
	if !ended {
		if ctx.Err() != nil {
			return zero, fail("ownership_cancelled")
		}
		n, readErr := ciphertext.Read(buffer[:1])
		if n > 0 {
			return zero, fail("ownership_ciphertext_size_mismatch")
		}
		if n != 0 || readErr != io.EOF {
			return zero, fail("ownership_ciphertext_read_failed")
		}
	}
	if ctx.Err() != nil {
		return zero, fail("ownership_cancelled")
	}
	if hex.EncodeToString(hash.Sum(nil)) != m.CiphertextSHA256 {
		return zero, fail("ownership_ciphertext_hash_mismatch")
	}
	expires, _ := canonicalTime(challenge.claim.ExpiresAt)
	if !now.Add(time.Since(started)).Before(expires) {
		return zero, fail("ownership_challenge_expired")
	}
	c := challenge.claim
	return Binding{c.AuthorityID, c.JobID, c.Nonce, c.CredentialSHA256, c.OriginalName, c.EncryptionAlgorithm, c.PipelineMode, c.ExecutionProfileSHA256,
		m.ChallengeSHA256, m.AADSHA256, digest(manifest.canonical), m.CiphertextSHA256, m.CiphertextBytes, m.KeyEnvelopeSHA256}, nil
}
