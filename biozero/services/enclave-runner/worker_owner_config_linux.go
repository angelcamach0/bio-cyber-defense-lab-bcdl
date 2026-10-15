//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"path/filepath"
	"strings"

	ownership "biozero/ownership-authority"
)

type ownerWorkerAsset struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}
type ownerWorkerConfig struct {
	SchemaVersion          int              `json:"schema_version"`
	Protocol               string           `json:"protocol"`
	Socket                 string           `json:"socket"`
	JobsDirectory          string           `json:"jobs_directory"`
	UploadsDirectory       string           `json:"uploads_directory"`
	AcceptancesDirectory   string           `json:"acceptances_directory"`
	ResultsDirectory       string           `json:"results_directory"`
	StageDirectory         string           `json:"stage_directory"`
	CustodyDirectory       string           `json:"custody_directory"`
	AuthorityID            string           `json:"authority_id"`
	PublicKeyHex           string           `json:"public_key_hex"`
	PipelineMode           string           `json:"pipeline_mode"`
	ExecutionProfileSHA256 string           `json:"execution_profile_sha256"`
	ExpectedScope          ownerWorkerScope `json:"expected_scope"`
	DecryptionKey          ownerWorkerAsset `json:"decryption_key"`
	ProjectionPolicy       ownerWorkerAsset `json:"projection_policy"`
	PollMilliseconds       int64            `json:"poll_milliseconds"`
	TimeoutSeconds         int64            `json:"timeout_seconds"`
}

type ownerWorkerScope = ownership.AcceptanceScope

type ownerWorkerMaterial struct {
	config ownerWorkerConfig
	trust  ownerWorkerTrust
	key    *rsa.PrivateKey
	policy workerProjectionPolicy
}

func ownerWorkerPath(p string) bool {
	return filepath.IsAbs(p) && filepath.Clean(p) == p && p != "/" && !strings.ContainsAny(p, "\x00\r\n")
}
func ownerWorkerOverlap(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}
func loadOwnerWorkerConfig(ctx context.Context, path string) (ownerWorkerMaterial, error) {
	var z ownerWorkerMaterial
	if ctx == nil || ctx.Err() != nil || !ownerWorkerPath(path) {
		return z, ownerWorkerError("owner_worker_config_invalid")
	}
	raw, e := readWorkerSnapshot(ctx, path, 64<<10, true)
	var c ownerWorkerConfig
	if e != nil || ownerWorkerDecode(raw, &c, 64<<10) != nil || c.SchemaVersion != 1 || c.Protocol != "owner-v1" || c.PollMilliseconds < 100 || c.PollMilliseconds > 60000 || c.TimeoutSeconds < 1 || c.TimeoutSeconds > 600 {
		return z, ownerWorkerError("owner_worker_config_invalid")
	}
	trust := ownerWorkerTrust{c.AuthorityID, c.PublicKeyHex, c.PipelineMode, c.ExecutionProfileSHA256, c.ExpectedScope, workerCustodyDigest(raw)}
	if !trust.valid() {
		return z, ownerWorkerError("owner_worker_config_invalid")
	}
	roots := []string{c.JobsDirectory, c.UploadsDirectory, c.AcceptancesDirectory, c.ResultsDirectory, c.StageDirectory, c.CustodyDirectory}
	for i, a := range roots {
		if !ownerWorkerPath(a) {
			return z, ownerWorkerError("owner_worker_config_invalid")
		}
		for _, b := range roots[:i] {
			if ownerWorkerOverlap(a, b) {
				return z, ownerWorkerError("owner_worker_config_overlap")
			}
		}
		for _, asset := range []string{path, c.Socket, c.DecryptionKey.Path, c.ProjectionPolicy.Path} {
			if ownerWorkerOverlap(a, asset) {
				return z, ownerWorkerError("owner_worker_config_overlap")
			}
		}
	}
	if !ownerWorkerPath(c.Socket) {
		return z, ownerWorkerError("owner_worker_config_invalid")
	}
	readAsset := func(a ownerWorkerAsset) ([]byte, error) {
		if !ownerWorkerPath(a.Path) || !workerCustodyHex(a.SHA256, 64) {
			return nil, ownerWorkerError("owner_worker_config_invalid")
		}
		b, e := readWorkerSnapshot(ctx, a.Path, 64<<10, true)
		if e != nil || workerCustodyDigest(b) != a.SHA256 {
			clear(b)
			return nil, ownerWorkerError("owner_worker_asset_invalid")
		}
		return b, nil
	}
	keyRaw, e := readAsset(c.DecryptionKey)
	if e != nil {
		return z, e
	}
	defer clear(keyRaw)
	block, rest := pem.Decode(keyRaw)
	if block == nil || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 || !bytes.HasPrefix(bytes.TrimSpace(keyRaw), []byte("-----BEGIN "+block.Type+"-----")) {
		return z, ownerWorkerError("owner_worker_decryption_key_invalid")
	}
	defer clear(block.Bytes)
	var key *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, e = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		var parsed any
		parsed, e = x509.ParsePKCS8PrivateKey(block.Bytes)
		if e == nil {
			key, _ = parsed.(*rsa.PrivateKey)
		}
	default:
		return z, ownerWorkerError("owner_worker_decryption_key_invalid")
	}
	if e != nil || key == nil || key.N == nil || key.N.BitLen() < 2048 || key.N.BitLen() > 4096 || key.E != 65537 || key.Validate() != nil {
		return z, ownerWorkerError("owner_worker_decryption_key_invalid")
	}
	policyRaw, e := readAsset(c.ProjectionPolicy)
	if e != nil {
		return z, e
	}
	policy, e := decodeWorkerProjectionPolicy(ctx, policyRaw, c.ExecutionProfileSHA256, c.PipelineMode)
	if e != nil {
		return z, ownerWorkerError("owner_worker_projection_policy_invalid")
	}
	if ctx.Err() != nil {
		return z, ownerWorkerError("owner_worker_cancelled")
	}
	return ownerWorkerMaterial{c, trust, key, policy}, nil
}
