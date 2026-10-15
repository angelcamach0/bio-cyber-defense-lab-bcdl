//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package ownership

import "encoding/hex"

// AcceptedBundle contains private transport bytes, not execution authority.
// Its SignedAcceptance must still be verified with external pin/scope by every
// consumer; delivery receipts never replace that verification.
type AcceptedBundle struct{ Acceptance, KeyEnvelope, Ciphertext []byte }

// OwnerUploadReceipt acknowledges only this upload service's claimed transport
// delivery over its authenticated channel. A compromised upload can fabricate
// it; it is neither an authority signature nor a broker/scientific receipt.
type OwnerUploadReceipt struct {
	SchemaVersion     int    `json:"schema_version"`
	JobID             string `json:"job_id"`
	AcceptanceSHA256  string `json:"acceptance_sha256"`
	CredentialSHA256  string `json:"credential_sha256"`
	CiphertextSHA256  string `json:"ciphertext_sha256"`
	CiphertextBytes   int64  `json:"ciphertext_bytes"`
	KeyEnvelopeSHA256 string `json:"key_envelope_sha256"`
	State             string `json:"state"`
}

func (o *ClientOperation) AcceptedBundle() (AcceptedBundle, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := o.preflight(); err != nil {
		return AcceptedBundle{}, err
	}
	if o.step.Sequence != 4 {
		return AcceptedBundle{}, fail("ownership_client_phase_invalid")
	}
	if err := o.matchAcceptance([]byte(o.step.AcceptanceJSON), o.step); err != nil {
		return AcceptedBundle{}, err
	}
	body, err := storeRead(o.root, "ciphertext.bin", MaxCiphertextBytes)
	if err != nil {
		return AcceptedBundle{}, o.latch()
	}
	envelope, err := hex.DecodeString(o.step.EnvelopeHex)
	if err != nil || digest(body) != o.step.CiphertextSHA256 || int64(len(body)) != o.step.CiphertextBytes {
		return AcceptedBundle{}, o.latch()
	}
	return AcceptedBundle{[]byte(o.step.AcceptanceJSON), envelope, body}, nil
}
