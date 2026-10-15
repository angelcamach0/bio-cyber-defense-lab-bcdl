//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package artifactexecutor

import (
	"reflect"

	ownership "biozero/ownership-authority"
)

const OwnerReadRequestDomain = "biozero.artifact.owner-reader.request.v1"
const OwnerReadResponseDomain = "biozero.artifact.owner-reader.response.v1"

// OwnerReadRequest carries only an already authorized historical binding. It
// cannot create, cancel, acknowledge or discover a worker reservation.
type OwnerReadRequest struct {
	SchemaVersion         int                       `json:"schema_version"`
	Domain                string                    `json:"domain"`
	Operation             string                    `json:"operation"`
	JobID                 string                    `json:"job_id"`
	AcceptanceSHA256      string                    `json:"acceptance_sha256"`
	CredentialSHA256      string                    `json:"credential_sha256"`
	UploadSHA256          string                    `json:"upload_sha256"`
	ExpectedProfileSHA256 string                    `json:"expected_profile_sha256"`
	AuthorityScope        ownership.AcceptanceScope `json:"authority_scope"`
}

type OwnerReadResponse struct {
	SchemaVersion int              `json:"schema_version"`
	Domain        string           `json:"domain"`
	ErrorCode     string           `json:"error_code"`
	HasReceipt    bool             `json:"has_receipt"`
	Binding       BridgeResponseV3 `json:"binding"`
}

func ValidateOwnerReadRequest(q OwnerReadRequest) error {
	if q.SchemaVersion != 1 || q.Domain != OwnerReadRequestDomain || (q.Operation != "status" && q.Operation != "receipt") || !hexID(q.JobID, 16) || !hexID(q.AcceptanceSHA256, 64) || !hexID(q.CredentialSHA256, 64) || !hexID(q.UploadSHA256, 64) || !hexID(q.ExpectedProfileSHA256, 64) || !hexID(q.AuthorityScope.StoreID, 32) || !hexID(q.AuthorityScope.PolicySHA256, 64) {
		return fail("artifact_owner_read_request_invalid")
	}
	return nil
}

func emptyOwnerReadBinding() BridgeResponseV3 {
	return BridgeResponseV3{SchemaVersion: 3, Execution: BridgeResponse{SchemaVersion: 2, Manifest: emptyBridgeManifest()}}
}

// NewOwnerReadError has one closed, empty binding shape, including a non-null
// files object. Error responses reveal no historical identity or execution facts.
func NewOwnerReadError(code string) OwnerReadResponse {
	if !artifactCode.MatchString(code) {
		code = "artifact_owner_read_failed"
	}
	return OwnerReadResponse{SchemaVersion: 1, Domain: OwnerReadResponseDomain, ErrorCode: code, Binding: emptyOwnerReadBinding()}
}

func NewOwnerReadSuccess(q OwnerReadRequest, binding BridgeResponseV3) (OwnerReadResponse, error) {
	_, receipt := binding.Execution.Manifest.Files["execution_receipt"]
	r := OwnerReadResponse{SchemaVersion: 1, Domain: OwnerReadResponseDomain, HasReceipt: q.Operation == "receipt" && receipt, Binding: binding}
	if err := ValidateOwnerReadResponse(q, r); err != nil {
		return OwnerReadResponse{}, err
	}
	return r, nil
}

func ValidateOwnerReadResponse(q OwnerReadRequest, r OwnerReadResponse) error {
	bad := func() error { return fail("artifact_owner_read_response_invalid") }
	if ValidateOwnerReadRequest(q) != nil || r.SchemaVersion != 1 || r.Domain != OwnerReadResponseDomain {
		return bad()
	}
	if r.ErrorCode != "" {
		if !artifactCode.MatchString(r.ErrorCode) || !reflect.DeepEqual(r, NewOwnerReadError(r.ErrorCode)) {
			return bad()
		}
		return nil
	}
	// The reader permits a noncommitted snapshot and legitimate failed commits
	// without execution_receipt. Worker receipt semantics remain unchanged.
	query := BridgeRequestV3{SchemaVersion: 3, Operation: "status", JobID: q.JobID, UploadSHA256: q.UploadSHA256, ExpectedProfileSHA256: q.ExpectedProfileSHA256, AcceptanceSHA256: q.AcceptanceSHA256}
	b := r.Binding
	if validateBridgeResponseV3(query, b) != nil || b.Execution.ErrorCode != "" || b.AcceptanceSHA256 != q.AcceptanceSHA256 || b.CredentialSHA256 != q.CredentialSHA256 || b.AuthorityScope != q.AuthorityScope {
		return bad()
	}
	_, receipt := b.Execution.Manifest.Files["execution_receipt"]
	if r.HasReceipt != (q.Operation == "receipt" && receipt) {
		return bad()
	}
	if b.Execution.State == "committed" && !receipt && (b.Execution.Manifest.ExecutionStatus != "failed" || b.Execution.Manifest.ReleaseStatus != "withheld") {
		return bad()
	}
	return nil
}
