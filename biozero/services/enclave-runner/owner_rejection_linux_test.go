//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	artifact "biozero/artifact-executor"
)

// This gate deliberately uses the existing legacy fixture. It is not owner-v1
// decryption acceptance: a real new owner job carries no legacy signature, and
// even an adversarial legacy signer cannot select the owner algorithm to reach
// the legacy nil-AAD decryptor or the execution broker.
func TestOwnerAlgorithmCannotEnterLegacyWorkerCustody(t *testing.T) {
	for _, tc := range []struct {
		name, code string
		signed     bool
	}{
		{"owner_has_no_legacy_signature", "signature_required", false},
		{"adversarial_valid_legacy_signature", "encryption_metadata_invalid", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := backendProtectedFixture(t)
			f.job.EncAlg = "aes-256-gcm+rsa-oaep-sha256+owner-v1"
			if !tc.signed {
				f.job.Sig = ""
				f.job.SigAlg = ""
			}
			c, _ := workerCustodyTestOpen(t)
			calls := 0
			b := &workerCapsuleBackend{custody: c, policy: workerProjectionPolicy{PipelineMode: "variants"}, pending: map[string]WorkerCustodyBinding{}, stages: map[string]*VerifiedPlaintextStage{}, call: func(context.Context, string, artifact.BridgeRequestV2, *os.File) (artifact.BridgeResponse, *os.File, error) {
				calls++
				return artifact.BridgeResponse{}, nil, errors.New("unexpected broker call")
			}}
			result := resultRecord{SecurityMode: "protected", PipelineMode: "variants", ReleaseStatus: "withheld"}
			if !b.process(context.Background(), f.job, false, &result, f.uploads, f.decrypted, f.private, f.cert, "", time.Second) || result.Status != "rejected" || result.ErrorCode != tc.code || result.ReleaseStatus != "withheld" || result.Decrypted || result.ArtifactExecution != nil || calls != 0 {
				t.Fatal("owner algorithm reached legacy execution", result.ErrorCode, calls)
			}
			if result.SignatureValid != tc.signed {
				t.Fatal("rejection did not reach the intended signature gate")
			}
			bindings, err := c.Bindings()
			if err != nil || len(bindings) != 0 {
				t.Fatal("rejection consumed custody", err)
			}
			entries, err := os.ReadDir(f.decrypted)
			if err != nil || len(entries) != 0 {
				t.Fatal("rejection persisted plaintext", err)
			}
			if _, err = os.Stat(filepath.Join(f.root, "called")); !os.IsNotExist(err) {
				t.Fatal("rejection invoked pipeline")
			}
		})
	}
}
