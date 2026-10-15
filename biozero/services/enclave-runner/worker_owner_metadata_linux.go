//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"reflect"
	"unicode/utf8"

	ownership "biozero/ownership-authority"
)

type ownerWorkerTrust struct {
	AuthorityID   string                    `json:"authority_id"`
	PublicKeyHex  string                    `json:"public_key_hex"`
	PipelineMode  string                    `json:"pipeline_mode"`
	ProfileSHA256 string                    `json:"profile_sha256"`
	Scope         ownership.AcceptanceScope `json:"scope"`
	ContextSHA256 string                    `json:"context_sha256"`
}

func (t ownerWorkerTrust) pin() ownership.AuthorityPin {
	b, _ := hex.DecodeString(t.PublicKeyHex)
	return ownership.AuthorityPin{AuthorityID: t.AuthorityID, PublicKey: ed25519.PublicKey(b), PipelineMode: t.PipelineMode, ExecutionProfileSHA256: t.ProfileSHA256}
}
func (t ownerWorkerTrust) valid() bool {
	return workerCustodyHex(t.AuthorityID, 32) && workerCustodyHex(t.PublicKeyHex, 64) && workerCustodyHex(t.ProfileSHA256, 64) && workerCustodyHex(t.ContextSHA256, 64) && workerCustodyHex(t.Scope.StoreID, 32) && workerCustodyHex(t.Scope.PolicySHA256, 64) && (t.PipelineMode == "stats" || t.PipelineMode == "variants")
}
func ownerWorkerError(s string) error { return errors.New(s) }
func ownerWorkerDecode(raw []byte, out any, limit int64) error {
	if int64(len(raw)) > limit || !utf8.Valid(raw) || reflect.TypeOf(out).Kind() != reflect.Pointer {
		return ownerWorkerError("owner_worker_json_invalid")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v, e := workerCustodyScanJSON(d, 0)
	if e != nil || !workerCustodyTypedJSON(v, reflect.TypeOf(out).Elem()) {
		return ownerWorkerError("owner_worker_json_invalid")
	}
	if _, e = d.Token(); e != io.EOF || json.Unmarshal(raw, out) != nil {
		return ownerWorkerError("owner_worker_json_invalid")
	}
	return nil
}

type ownerWorkerJob struct {
	JobID                     string `json:"job_id"`
	Status                    string `json:"status"`
	UploadedAt                string `json:"uploaded_at"`
	OriginalName              string `json:"original_name"`
	SizeBytes                 int64  `json:"size_bytes"`
	SHA256                    string `json:"sha256"`
	ClientID                  string `json:"client_id"`
	EncAlg                    string `json:"enc_alg"`
	EncKey                    string `json:"enc_key"`
	OwnershipVersion          int    `json:"ownership_version"`
	OwnershipAcceptanceSHA256 string `json:"ownership_acceptance_sha256"`
}

// Signed fields decide the payload path and crypto. Job lifecycle and owner
// strings never establish authorization or completed execution.
func readOwnerWorkerJob(ctx context.Context, path string) (ownerWorkerJob, error) {
	var j ownerWorkerJob
	raw, e := readWorkerSnapshot(ctx, path, maxJobMetadataBytes, true)
	if e != nil || ownerWorkerDecode(raw, &j, maxJobMetadataBytes) != nil || !workerCustodyHex(j.JobID, 16) || filepath.Base(path) != j.JobID+".json" || j.OwnershipVersion != 1 || j.EncAlg != ownership.EncryptionAlgorithm || j.ClientID != "" || !workerCustodyHex(j.SHA256, 64) || !workerCustodyHex(j.OwnershipAcceptanceSHA256, 64) || j.SizeBytes < 16 || j.SizeBytes > ownership.MaxCiphertextBytes || j.Status != "uploaded" {
		return ownerWorkerJob{}, ownerWorkerError("owner_worker_job_invalid")
	}
	return j, nil
}

type verifiedOwnerInput struct {
	Acceptance          ownership.VerifiedAcceptance
	CanonicalAcceptance []byte
	Plaintext           []byte
	Envelope            []byte
}

func ownerWorkerCanonical(raw []byte, v ownership.VerifiedAcceptance) ([]byte, error) {
	var signed ownership.SignedAcceptance
	if json.Unmarshal(raw, &signed) != nil {
		return nil, ownerWorkerError("owner_worker_acceptance_invalid")
	}
	canonical, e := ownership.MarshalAcceptance(signed)
	if e != nil || workerCustodyDigest(canonical) != v.SHA256() {
		return nil, ownerWorkerError("owner_worker_acceptance_invalid")
	}
	return canonical, nil
}

// Verification completes before staging, verified custody, Submit or Reserve.
// A historical certificate is not fabricated into a live TLS Principal here.
func verifyOwnerWorkerInput(ctx context.Context, j ownerWorkerJob, raw []byte, pin ownership.AuthorityPin, scope ownership.AcceptanceScope, key *rsa.PrivateKey, uploadDir string) (verifiedOwnerInput, error) {
	var z verifiedOwnerInput
	if ctx == nil || ctx.Err() != nil {
		return z, ownerWorkerError("owner_worker_cancelled")
	}
	v, e := ownership.VerifyAcceptance(raw, pin, scope)
	if e != nil {
		return z, ownerWorkerError("owner_worker_acceptance_invalid")
	}
	b := v.Binding()
	if j.OwnershipVersion != 1 || j.EncAlg != ownership.EncryptionAlgorithm || j.JobID != b.JobID || j.OwnershipAcceptanceSHA256 != v.SHA256() || j.SHA256 != b.CiphertextSHA256 || j.SizeBytes != b.CiphertextBytes || j.OriginalName != b.OriginalName || j.ClientID != "" {
		return z, ownerWorkerError("owner_worker_binding_mismatch")
	}
	envelope, e := hex.DecodeString(j.EncKey)
	if e != nil || len(envelope) < 256 || len(envelope) > 512 || workerCustodyDigest(envelope) != b.KeyEnvelopeSHA256 {
		return z, ownerWorkerError("owner_worker_envelope_invalid")
	}
	canonical, e := ownerWorkerCanonical(raw, v)
	if e != nil {
		return z, e
	}
	cipher, e := readWorkerSnapshot(ctx, filepath.Join(uploadDir, b.JobID+"_"+b.OriginalName), ownership.MaxCiphertextBytes, true)
	if e != nil {
		return z, ownerWorkerError("owner_worker_ciphertext_invalid")
	}
	plain, e := ownership.DecryptAcceptedPayload(v, cipher, envelope, key)
	if e != nil {
		return z, ownerWorkerError("owner_worker_payload_authentication_failed")
	}
	if ctx.Err() != nil {
		clear(plain)
		return z, ownerWorkerError("owner_worker_cancelled")
	}
	return verifiedOwnerInput{v, canonical, plain, envelope}, nil
}
