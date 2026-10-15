//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package artifactexecutor

import (
	"reflect"

	ownership "biozero/ownership-authority"
)

// V3 is a separately selected protocol. Acceptance bytes travel in a second
// read-only FD, never in the bounded RPC JSON. Queries require acceptance SHA.
type BridgeRequestV3 struct {
	SchemaVersion         int             `json:"schema_version"`
	Operation             string          `json:"operation"`
	JobID                 string          `json:"job_id"`
	UploadSHA256          string          `json:"upload_sha256"`
	ExpectedProfileSHA256 string          `json:"expected_profile_sha256"`
	ProcessedSHA256       string          `json:"processed_sha256"`
	ProcessedBytes        int64           `json:"processed_bytes"`
	OriginalName          string          `json:"original_name"`
	AnalysisContext       AnalysisContext `json:"analysis_context"`
	AcceptanceSHA256      string          `json:"acceptance_sha256"`
	AcceptanceBytes       int64           `json:"acceptance_bytes"`
}
type BridgeResponseV3 struct {
	SchemaVersion    int                       `json:"schema_version"`
	AcceptanceSHA256 string                    `json:"acceptance_sha256"`
	CredentialSHA256 string                    `json:"credential_sha256"`
	AuthorityScope   ownership.AcceptanceScope `json:"authority_scope"`
	ProcessedSHA256  string                    `json:"processed_sha256"`
	ProcessedBytes   int64                     `json:"processed_bytes"`
	AnalysisContext  AnalysisContext           `json:"analysis_context"`
	Execution        BridgeResponse            `json:"execution"`
}

func (q BridgeRequestV3) analysisRequest() BridgeRequestV2 {
	return BridgeRequestV2{2, q.Operation, q.JobID, q.UploadSHA256, q.ExpectedProfileSHA256, q.ProcessedSHA256, q.ProcessedBytes, q.OriginalName, q.AnalysisContext}
}
func validateBridgeRequestV3(q BridgeRequestV3) error {
	if q.SchemaVersion != 3 || !hexID(q.AcceptanceSHA256, 64) || validateBridgeRequestV2(q.analysisRequest()) != nil {
		return fail("artifact_bridge_request_invalid")
	}
	if q.Operation == "submit" {
		c := q.AnalysisContext
		if q.AcceptanceBytes < 1 || q.AcceptanceBytes > ownership.MaxAcceptanceBytes || !c.Decrypted || !c.SignatureValid || c.DecryptionError != "" || c.SignatureError != "" {
			return fail("artifact_bridge_request_invalid")
		}
	} else if q.AcceptanceBytes != 0 {
		return fail("artifact_bridge_request_invalid")
	}
	return nil
}
func bridgeErrorResponseV3(code string) BridgeResponseV3 {
	return BridgeResponseV3{SchemaVersion: 3, Execution: bridgeErrorResponseV2(code)}
}
func validateBridgeResponseV3(q BridgeRequestV3, r BridgeResponseV3) error {
	bad := func() error { return fail("artifact_bridge_response_invalid") }
	if validateBridgeRequestV3(q) != nil || r.SchemaVersion != 3 || validateBridgeResponseV2(q.analysisRequest(), r.Execution) != nil {
		return bad()
	}
	if r.Execution.ErrorCode != "" {
		if !reflect.DeepEqual(r, bridgeErrorResponseV3(r.Execution.ErrorCode)) {
			return bad()
		}
		return nil
	}
	if r.AcceptanceSHA256 != q.AcceptanceSHA256 || !hexID(r.CredentialSHA256, 64) || !hexID(r.AuthorityScope.StoreID, 32) || !hexID(r.AuthorityScope.PolicySHA256, 64) || !hexID(r.ProcessedSHA256, 64) || validateAnalysisContext(r.AnalysisContext, r.ProcessedBytes) != nil || !r.AnalysisContext.Decrypted || !r.AnalysisContext.SignatureValid || r.AnalysisContext.DecryptionError != "" || r.AnalysisContext.SignatureError != "" {
		return bad()
	}
	if q.Operation == "submit" && (r.ProcessedSHA256 != q.ProcessedSHA256 || r.ProcessedBytes != q.ProcessedBytes || r.AnalysisContext != q.AnalysisContext) {
		return bad()
	}
	return nil
}
