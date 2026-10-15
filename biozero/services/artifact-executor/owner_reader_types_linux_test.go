//go:build linux

package artifactexecutor

import (
	"encoding/json"
	"strings"
	"testing"

	ownership "biozero/ownership-authority"
)

func ownerReadTestRequest(op string) OwnerReadRequest {
	return OwnerReadRequest{SchemaVersion: 1, Domain: OwnerReadRequestDomain, Operation: op, JobID: strings.Repeat("a", 16), AcceptanceSHA256: strings.Repeat("b", 64), CredentialSHA256: strings.Repeat("c", 64), UploadSHA256: strings.Repeat("d", 64), ExpectedProfileSHA256: strings.Repeat("e", 64), AuthorityScope: ownership.AcceptanceScope{StoreID: strings.Repeat("f", 32), PolicySHA256: strings.Repeat("1", 64)}}
}

func ownerReadTestBinding(q OwnerReadRequest) BridgeResponseV3 {
	return BridgeResponseV3{SchemaVersion: 3, AcceptanceSHA256: q.AcceptanceSHA256, CredentialSHA256: q.CredentialSHA256, AuthorityScope: q.AuthorityScope, ProcessedSHA256: strings.Repeat("2", 64), ProcessedBytes: 1, AnalysisContext: AnalysisContext{OriginalName: "fixture.fastq", ProcessedSizeBytes: 1, Decrypted: true, SignatureValid: true}, Execution: BridgeResponse{SchemaVersion: 2, JobID: q.JobID, UploadSHA256: q.UploadSHA256, ProfileSHA256: q.ExpectedProfileSHA256, StoreID: strings.Repeat("3", 32), LeaseID: strings.Repeat("4", 32), State: "executing", Manifest: emptyBridgeManifest()}}
}

func TestOwnerReadStrictClosedJSON(t *testing.T) {
	q := ownerReadTestRequest("status")
	raw, _ := json.Marshal(q)
	var parsed OwnerReadRequest
	if strictJSON(raw, &parsed) != nil || ValidateOwnerReadRequest(parsed) != nil {
		t.Fatal("valid request rejected")
	}
	for name, bad := range map[string]string{
		"duplicate": strings.Replace(string(raw), `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1),
		"case":      strings.Replace(string(raw), `"job_id"`, `"Job_ID"`, 1),
		"unknown":   strings.Replace(string(raw), `"schema_version":1`, `"extra":1,"schema_version":1`, 1),
		"null":      strings.Replace(string(raw), `"authority_scope":{`, `"authority_scope":null,"discard":{`, 1),
		"missing":   strings.Replace(string(raw), `"schema_version":1,`, "", 1),
		"trailing":  string(raw) + " {}",
		"depth":     `{"a":` + strings.Repeat("[", 66) + "0" + strings.Repeat("]", 66) + "}",
	} {
		t.Run(name, func(t *testing.T) {
			if strictJSON([]byte(bad), &parsed) == nil {
				t.Fatal("accepted malformed request")
			}
		})
	}
	for _, op := range []string{"submit", "cancel", "STATUS", ""} {
		q.Operation = op
		if ValidateOwnerReadRequest(q) == nil {
			t.Fatal("accepted operation", op)
		}
	}
}

func TestOwnerReadResponseBindingAndAbsentReceipt(t *testing.T) {
	q := ownerReadTestRequest("receipt")
	b := ownerReadTestBinding(q)
	r, err := NewOwnerReadSuccess(q, b)
	if err != nil || r.HasReceipt {
		t.Fatal("noncommitted status requires no descriptor", err)
	}
	for name, mutate := range map[string]func(*OwnerReadResponse){
		"credential": func(r *OwnerReadResponse) { r.Binding.CredentialSHA256 = strings.Repeat("9", 64) },
		"acceptance": func(r *OwnerReadResponse) { r.Binding.AcceptanceSHA256 = strings.Repeat("9", 64) },
		"scope":      func(r *OwnerReadResponse) { r.Binding.AuthorityScope.StoreID = strings.Repeat("9", 32) },
		"profile":    func(r *OwnerReadResponse) { r.Binding.Execution.ProfileSHA256 = strings.Repeat("9", 64) },
		"job":        func(r *OwnerReadResponse) { r.Binding.Execution.JobID = strings.Repeat("9", 16) },
		"upload":     func(r *OwnerReadResponse) { r.Binding.Execution.UploadSHA256 = strings.Repeat("9", 64) },
		"context":    func(r *OwnerReadResponse) { r.Binding.AnalysisContext.Decrypted = false },
		"receipt":    func(r *OwnerReadResponse) { r.HasReceipt = true },
	} {
		t.Run(name, func(t *testing.T) {
			bad := r
			mutate(&bad)
			if ValidateOwnerReadResponse(q, bad) == nil {
				t.Fatal("accepted crossed binding")
			}
		})
	}
	b.Execution.State = "committed"
	b.Execution.HasManifest = true
	b.Execution.Manifest = Manifest{SchemaVersion: 1, JobID: q.JobID, InputSHA256: q.UploadSHA256, StoreID: b.Execution.StoreID, LeaseID: b.Execution.LeaseID, PolicySHA256: strings.Repeat("5", 64), ExecutionStatus: "failed", ReleaseStatus: "withheld", ErrorCode: "artifact_cancelled", Files: map[string]FileRecord{}}
	manifest, _ := jsonBytes(b.Execution.Manifest)
	b.Execution.ManifestSHA256 = digest(manifest)
	if r, err = NewOwnerReadSuccess(q, b); err != nil || r.HasReceipt {
		t.Fatal("legitimate failed/withheld without execution receipt rejected", err)
	}
	b.Execution.Manifest.ExecutionStatus = "succeeded"
	manifest, _ = jsonBytes(b.Execution.Manifest)
	b.Execution.ManifestSHA256 = digest(manifest)
	if _, err = NewOwnerReadSuccess(q, b); err == nil {
		t.Fatal("successful commit without execution receipt accepted")
	}
	denied := NewOwnerReadError("artifact_owner_read_unavailable")
	encoded, _ := json.Marshal(denied)
	var decoded OwnerReadResponse
	if strings.Contains(string(encoded), "null") || strictJSON(encoded, &decoded) != nil || ValidateOwnerReadResponse(q, decoded) != nil {
		t.Fatal("error response is not closed and canonical")
	}
	denied.Binding.CredentialSHA256 = q.CredentialSHA256
	if ValidateOwnerReadResponse(q, denied) == nil {
		t.Fatal("error response leaked identity")
	}
}
