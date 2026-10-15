//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"

	projection "biozero/enclave-runner/receiptprojection"
	ownership "biozero/ownership-authority"
)

const ownerGatewayDomain = "biozero.gateway.owner.v1"
const ownerGatewayResponseLimit = 16 << 20
const ownerGatewayRegistryLimit = 1 << 20
const ownerGatewayRunLimit = 64
const ownerGatewayReviewerRunLimit = 20

// Retained promise includes both encrypted copies, all bounded client journal
// steps and a signed acceptance. This is a logical promise, not a filesystem cap.
const ownerGatewayRunCharge int64 = 2*(maxFixtureBytes+16) + 8*(96<<10) + (64 << 10)

type ownerGatewayAsset struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}
type ownerGatewayReviewerConfig struct {
	ID               string            `json:"id"`
	Label            string            `json:"label"`
	Enabled          bool              `json:"enabled"`
	AccessCodeSHA256 string            `json:"access_code_sha256"`
	CredentialSHA256 string            `json:"credential_sha256"`
	TLSCertificate   ownerGatewayAsset `json:"tls_certificate"`
	TLSPrivateKey    ownerGatewayAsset `json:"tls_private_key"`
}
type ownerGatewayExperimentConfig struct {
	ID           string            `json:"id"`
	Label        string            `json:"label"`
	Scope        string            `json:"scope"`
	OriginalName string            `json:"original_name"`
	Input        ownerGatewayAsset `json:"input"`
	Reference    ownerGatewayAsset `json:"reference"`
}
type ownerGatewayConfig struct {
	SchemaVersion             int                            `json:"schema_version"`
	Protocol                  string                         `json:"protocol"`
	ListenAddress             string                         `json:"listen_address"`
	PublicOrigin              string                         `json:"public_origin"`
	StateDirectory            string                         `json:"state_directory"`
	ExpectedUID               uint32                         `json:"expected_uid"`
	AuthorityURL              string                         `json:"authority_url"`
	UploadURL                 string                         `json:"upload_url"`
	ResultsURL                string                         `json:"results_url"`
	AuthorityServerName       string                         `json:"authority_server_name"`
	UploadServerName          string                         `json:"upload_server_name"`
	ResultsServerName         string                         `json:"results_server_name"`
	AuthorityID               string                         `json:"authority_id"`
	PublicKeyHex              string                         `json:"public_key_hex"`
	PipelineMode              string                         `json:"pipeline_mode"`
	ExecutionProfileSHA256    string                         `json:"execution_profile_sha256"`
	ExpectedScope             ownership.AcceptanceScope      `json:"expected_scope"`
	BrowserTLSCertificate     ownerGatewayAsset              `json:"browser_tls_certificate"`
	BrowserTLSPrivateKey      ownerGatewayAsset              `json:"browser_tls_private_key"`
	AuthorityCA               ownerGatewayAsset              `json:"authority_ca"`
	UploadCA                  ownerGatewayAsset              `json:"upload_ca"`
	ResultsCA                 ownerGatewayAsset              `json:"results_ca"`
	WorkerEncryptionPublicKey ownerGatewayAsset              `json:"worker_encryption_public_key"`
	ProjectionPolicy          ownerGatewayAsset              `json:"projection_policy"`
	UIAssets                  map[string]ownerGatewayAsset   `json:"ui_assets"`
	Reviewers                 []ownerGatewayReviewerConfig   `json:"reviewers"`
	Experiments               []ownerGatewayExperimentConfig `json:"experiments"`
}

// Material is constructed once from measured private snapshots. Browser access
// codes and display labels are not cryptographic ownership capabilities.
type ownerGatewayMaterial struct {
	Config                      ownerGatewayConfig
	ConfigSHA256, ContextSHA256 string
	Pin                         ownership.AuthorityPin
	Policy                      projection.Policy
	BrowserTLS                  *tls.Config
	EncryptionKey               *rsa.PublicKey
	Reviewers                   map[string]ownerGatewayReviewer
	Experiments                 map[string]ownerGatewayExperiment
	UI                          map[string][]byte
}
type ownerGatewayReviewer struct {
	Config                        ownerGatewayReviewerConfig
	CredentialSHA256              string
	AccessSHA256                  [32]byte
	AuthorityConfig, UploadConfig ownership.AuthorityClientConfig
	Results                       *ownerGatewayResultsClient
}
type ownerGatewayExperiment struct {
	Config          ownerGatewayExperimentConfig
	Input           []byte
	InputSHA256     string
	InputBytes      int64
	ReferenceSHA256 string
	ReferenceBytes  int64
}

// This type is the closed upstream Results protocol, not the legacy report DTO.
// The Results adapter validates it before the registry observes a commit.
type ownerGatewayResult struct {
	SchemaVersion        int                           `json:"schema_version"`
	Domain               string                        `json:"domain"`
	JobID                string                        `json:"job_id"`
	AcceptanceSHA256     string                        `json:"acceptance_sha256"`
	ExecutionState       string                        `json:"execution_state"`
	Status               string                        `json:"status"`
	ReleaseStatus        string                        `json:"release_status"`
	ErrorCode            string                        `json:"error_code"`
	UploadSHA256         string                        `json:"upload_sha256"`
	ProcessedSHA256      string                        `json:"processed_sha256"`
	PipelineMode         string                        `json:"pipeline_mode"`
	PipelineOutput       json.RawMessage               `json:"pipeline_output"`
	ScientificEvaluation json.RawMessage               `json:"scientific_evaluation"`
	Detection            *projection.Detection         `json:"detection"`
	ArtifactExecution    *projection.ArtifactExecution `json:"artifact_execution"`
}
type ownerGatewayCommit struct {
	ResultSHA256  string                       `json:"result_sha256"`
	Status        string                       `json:"status"`
	ReleaseStatus string                       `json:"release_status"`
	Artifact      projection.ArtifactExecution `json:"artifact_execution"`
}

// Run is private durable metadata. HTTP constructs a smaller browser view; it
// must never serialize this internal record or an acceptance/key bundle as-is.
type ownerGatewayRun struct {
	SchemaVersion     int                 `json:"schema_version"`
	RunID             string              `json:"run_id"`
	RequestID         string              `json:"request_id"`
	ReviewerID        string              `json:"reviewer_id"`
	CredentialSHA256  string              `json:"credential_sha256"`
	ExperimentID      string              `json:"experiment_id"`
	ContextSHA256     string              `json:"context_sha256"`
	InputSHA256       string              `json:"input_sha256"`
	InputBytes        int64               `json:"input_bytes"`
	ReferenceSHA256   string              `json:"reference_sha256"`
	ReferenceBytes    int64               `json:"reference_bytes"`
	OriginalName      string              `json:"original_name"`
	CreatedAt         string              `json:"created_at"`
	Phase             string              `json:"phase"`
	ErrorCode         string              `json:"error_code"`
	JobID             string              `json:"job_id"`
	AcceptanceSHA256  string              `json:"acceptance_sha256"`
	CiphertextSHA256  string              `json:"ciphertext_sha256"`
	CiphertextBytes   int64               `json:"ciphertext_bytes"`
	KeyEnvelopeSHA256 string              `json:"key_envelope_sha256"`
	ChargeBytes       int64               `json:"charge_bytes"`
	Commit            *ownerGatewayCommit `json:"commit"`
}
