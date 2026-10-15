//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package artifactexecutor

import (
	"reflect"
	"unicode/utf8"
)

// Bridge protocol is separate from v1 run/status/cancel. Every field is required;
// unused fields are empty, never null. Profile configuration is trusted-host only.
type BridgeRequest struct {
	SchemaVersion         int    `json:"schema_version"`
	Operation             string `json:"operation"`
	JobID                 string `json:"job_id"`
	UploadSHA256          string `json:"upload_sha256"`
	ExpectedProfileSHA256 string `json:"expected_profile_sha256"`
	ProcessedSHA256       string `json:"processed_sha256"`
	ProcessedBytes        int64  `json:"processed_bytes"`
	OriginalName          string `json:"original_name"`
}

// Manifest is a value with an empty Files object when HasManifest is false.
// Opaque input references and private paths never leave the broker.
type BridgeResponse struct {
	SchemaVersion   int      `json:"schema_version"`
	JobID           string   `json:"job_id"`
	UploadSHA256    string   `json:"upload_sha256"`
	ProfileSHA256   string   `json:"profile_sha256"`
	StoreID         string   `json:"store_id"`
	LeaseID         string   `json:"lease_id"`
	State           string   `json:"state"`
	ManifestSHA256  string   `json:"manifest_sha256"`
	HasManifest     bool     `json:"has_manifest"`
	Manifest        Manifest `json:"manifest"`
	ReceiptSHA256   string   `json:"receipt_sha256"`
	ReceiptBytes    int64    `json:"receipt_bytes"`
	CancelRequested bool     `json:"cancel_requested"`
	ErrorCode       string   `json:"error_code"`
}

const MaxBridgeReceiptBytes int64 = 16 << 20
const bridgeJournalLimit int64 = 1 << 20

func emptyBridgeManifest() Manifest { return Manifest{Files: map[string]FileRecord{}} }
func bridgeErrorResponse(code string) BridgeResponse {
	if !artifactCode.MatchString(code) {
		code = "artifact_bridge_failed"
	}
	return BridgeResponse{SchemaVersion: 1, Manifest: emptyBridgeManifest(), ErrorCode: code}
}
func validateBridgeRequest(q BridgeRequest) error {
	if q.SchemaVersion != 1 || !hexID(q.JobID, 16) || !hexID(q.UploadSHA256, 64) || !hexID(q.ExpectedProfileSHA256, 64) {
		return fail("artifact_bridge_request_invalid")
	}
	switch q.Operation {
	case "submit":
		if !hexID(q.ProcessedSHA256, 64) || q.ProcessedBytes < 0 || q.ProcessedBytes > MaxInputBytes || len(q.OriginalName) > 4096 || !utf8.ValidString(q.OriginalName) {
			return fail("artifact_bridge_request_invalid")
		}
	case "status", "cancel", "receipt":
		if q.ProcessedSHA256 != "" || q.ProcessedBytes != 0 || q.OriginalName != "" {
			return fail("artifact_bridge_request_invalid")
		}
	default:
		return fail("artifact_bridge_request_invalid")
	}
	return nil
}
func validateBridgeResponse(q BridgeRequest, r BridgeResponse) error {
	invalid := func() error { return fail("artifact_bridge_response_invalid") }
	if r.SchemaVersion != 1 {
		return invalid()
	}
	if r.ErrorCode != "" {
		if !artifactCode.MatchString(r.ErrorCode) || !reflect.DeepEqual(r, bridgeErrorResponse(r.ErrorCode)) {
			return invalid()
		}
		return nil
	}
	if r.JobID != q.JobID || r.UploadSHA256 != q.UploadSHA256 || r.ProfileSHA256 != q.ExpectedProfileSHA256 || !hexID(r.StoreID, 32) || !hexID(r.LeaseID, 32) || (r.CancelRequested && q.Operation != "cancel") {
		return invalid()
	}
	switch r.State {
	case "reserved", "executing", "prepared", "committed":
	default:
		return invalid()
	}
	if r.State != "committed" {
		if r.HasManifest || r.ManifestSHA256 != "" || r.ReceiptSHA256 != "" || r.ReceiptBytes != 0 || !reflect.DeepEqual(r.Manifest, emptyBridgeManifest()) || q.Operation == "receipt" {
			return invalid()
		}
		return nil
	}
	m := r.Manifest
	if !r.HasManifest || m.SchemaVersion != 1 || m.JobID != r.JobID || m.InputSHA256 != r.UploadSHA256 || m.StoreID != r.StoreID || m.LeaseID != r.LeaseID || !hexID(m.PolicySHA256, 64) || m.Files == nil || len(m.Files) > 16 || !hexID(r.ManifestSHA256, 64) {
		return invalid()
	}
	b, e := jsonBytes(m)
	if e != nil || int64(len(b)) > manifestLimit || digest(b) != r.ManifestSHA256 {
		return invalid()
	}
	var total int64
	for name, f := range m.Files {
		if !artifactName.MatchString(name) || f.State != "verified" || !hexID(f.SHA256, 64) || f.Bytes < 0 || f.Bytes > 64<<20 || total > (64<<20)-f.Bytes {
			return invalid()
		}
		total += f.Bytes
	}
	switch m.ExecutionStatus {
	case "succeeded", "incomplete", "failed":
	default:
		return invalid()
	}
	switch m.ReleaseStatus {
	case "evaluated_passed", "withheld", "unassessed":
	default:
		return invalid()
	}
	if m.ErrorCode != "" && !artifactCode.MatchString(m.ErrorCode) {
		return invalid()
	}
	if (m.ExecutionStatus != "succeeded" || m.ReleaseStatus == "withheld") && m.ErrorCode == "" {
		return invalid()
	}
	if f, ok := m.Files["normalized_vcf"]; ok {
		if !hexID(m.ObservedSHA256, 64) || m.ObservedSHA256 != f.SHA256 {
			return invalid()
		}
	} else if m.ObservedSHA256 != "" {
		return invalid()
	}
	if m.EvaluatedSHA256 != "" && (!hexID(m.EvaluatedSHA256, 64) || m.EvaluatedSHA256 != m.ObservedSHA256) {
		return invalid()
	}
	if m.ReleaseStatus == "evaluated_passed" && (m.ExecutionStatus != "succeeded" || m.ErrorCode != "" || !hexID(m.ObservedSHA256, 64) || m.ObservedSHA256 != m.EvaluatedSHA256) {
		return invalid()
	}
	if f, ok := m.Files["execution_receipt"]; ok {
		if f.Bytes > MaxBridgeReceiptBytes || r.ReceiptSHA256 != f.SHA256 || r.ReceiptBytes != f.Bytes {
			return invalid()
		}
	} else if q.Operation == "receipt" || r.ReceiptSHA256 != "" || r.ReceiptBytes != 0 {
		return invalid()
	}
	return nil
}

// BridgeRequestV2 adds fixed verifier facts to the separately selected v2
// protocol. All fields, including every AnalysisContext field, are required.
// Queries carry a complete zero-valued context; they cannot replace job facts.
type BridgeRequestV2 struct {
	SchemaVersion         int             `json:"schema_version"`
	Operation             string          `json:"operation"`
	JobID                 string          `json:"job_id"`
	UploadSHA256          string          `json:"upload_sha256"`
	ExpectedProfileSHA256 string          `json:"expected_profile_sha256"`
	ProcessedSHA256       string          `json:"processed_sha256"`
	ProcessedBytes        int64           `json:"processed_bytes"`
	OriginalName          string          `json:"original_name"`
	AnalysisContext       AnalysisContext `json:"analysis_context"`
}

func (q BridgeRequestV2) legacy() BridgeRequest {
	return BridgeRequest{1, q.Operation, q.JobID, q.UploadSHA256, q.ExpectedProfileSHA256, q.ProcessedSHA256, q.ProcessedBytes, q.OriginalName}
}
func validateBridgeRequestV2(q BridgeRequestV2) error {
	if q.SchemaVersion != 2 || validateBridgeRequest(q.legacy()) != nil {
		return fail("artifact_bridge_request_invalid")
	}
	if q.Operation == "submit" {
		if validateAnalysisContext(q.AnalysisContext, q.ProcessedBytes) != nil || q.AnalysisContext.OriginalName != q.OriginalName {
			return fail("artifact_bridge_request_invalid")
		}
	} else if q.AnalysisContext != (AnalysisContext{}) {
		return fail("artifact_bridge_request_invalid")
	}
	return nil
}
func bridgeErrorResponseV2(code string) BridgeResponse {
	r := bridgeErrorResponse(code)
	r.SchemaVersion = 2
	return r
}
func validateBridgeResponseV2(q BridgeRequestV2, r BridgeResponse) error {
	if validateBridgeRequestV2(q) != nil || r.SchemaVersion != 2 {
		return fail("artifact_bridge_response_invalid")
	}
	r.SchemaVersion = 1
	return validateBridgeResponse(q.legacy(), r)
}
