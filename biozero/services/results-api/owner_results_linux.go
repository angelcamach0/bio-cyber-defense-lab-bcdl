//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"

	artifact "biozero/artifact-executor"
	projection "biozero/enclave-runner/receiptprojection"
	ownership "biozero/ownership-authority"
)

const ownerResultsDomain = "biozero.results.owner.v1"

// Optional projected sections are explicit nulls. No certificate, upload bytes,
// capsule namespace, raw receipt or mutable spool record enters this DTO.
type ownerResultsResponse struct {
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

type ownerResultsConnectionKey struct{}

type ownerResultsHandler struct {
	material  ownerResultsMaterial
	inbox     *os.File
	active    chan struct{}
	query     func(context.Context, artifact.OwnerReadClientConfig, artifact.OwnerReadRequest) (artifact.OwnerReadResponse, error)
	receipt   func(context.Context, artifact.OwnerReadClientConfig, artifact.OwnerReadRequest) (artifact.OwnerReadResponse, *os.File, error)
	closeOnce sync.Once
	closeErr  error
}

func newOwnerResultsHandler(m ownerResultsMaterial) (*ownerResultsHandler, error) {
	dir, err := ownerResultsDirectory(m.config.AcceptancesDirectory, m.config.ExpectedAcceptancesUID)
	if err != nil {
		return nil, err
	}
	return &ownerResultsHandler{material: m, inbox: dir, active: make(chan struct{}, 2), query: artifact.QueryOwnerStatus, receipt: artifact.ReadOwnerReceipt}, nil
}

func (h *ownerResultsHandler) Close() error {
	h.closeOnce.Do(func() { h.closeErr = h.inbox.Close() })
	return h.closeErr
}

func ownerResultsLivePrincipal(r *http.Request) (ownership.Principal, error) {
	var zero ownership.Principal
	conn, ok := r.Context().Value(ownerResultsConnectionKey{}).(*tls.Conn)
	if !ok || conn == nil || r.TLS == nil {
		return zero, ownerResultsError("owner_results_tls_invalid")
	}
	live := conn.ConnectionState()
	if !live.HandshakeComplete || live.Version != tls.VersionTLS13 || !r.TLS.HandshakeComplete || r.TLS.Version != live.Version || len(live.PeerCertificates) == 0 || len(r.TLS.PeerCertificates) == 0 || live.PeerCertificates[0] == nil || r.TLS.PeerCertificates[0] == nil || !bytes.Equal(live.PeerCertificates[0].Raw, r.TLS.PeerCertificates[0].Raw) {
		return zero, ownerResultsError("owner_results_tls_invalid")
	}
	// Verify current validity even on a kept-alive connection. Historical
	// acceptance timestamps remain historical and are not re-expired here.
	now := time.Now()
	for _, chain := range live.VerifiedChains {
		for _, cert := range chain {
			if cert == nil || now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
				return zero, ownerResultsError("owner_results_tls_invalid")
			}
		}
	}
	return ownership.PrincipalFromTLS(&live)
}

func ownerResultsRequestShape(r *http.Request) (string, bool) {
	if r.Method != http.MethodGet || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" || r.ContentLength != 0 || len(r.TransferEncoding) > 0 {
		return "", false
	}
	const prefix = "/v1/results/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		return "", false
	}
	job := strings.TrimPrefix(r.URL.Path, prefix)
	return job, projection.ArtifactHex(job, 16)
}

func (h *ownerResultsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	isHealth := r.Method == http.MethodGet && r.URL.Path == "/healthz" && r.URL.RawQuery == "" && !r.URL.ForceQuery && r.URL.RawPath == "" && r.ContentLength == 0 && len(r.TransferEncoding) == 0
	job, ok := ownerResultsRequestShape(r)
	if !ok && !isHealth {
		writeJSONError(w, http.StatusBadRequest, "owner_results_request_invalid", "invalid request")
		return
	}
	principal, err := ownerResultsLivePrincipal(r)
	if err != nil {
		writeJSONError(w, http.StatusForbidden, "owner_results_forbidden", "forbidden")
		return
	}
	if isHealth {
		if http.NewResponseController(w).SetWriteDeadline(time.Now().Add(5*time.Second)) != nil {
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
		return
	}
	select {
	case h.active <- struct{}{}:
		defer func() { <-h.active }()
	default:
		writeJSONError(w, http.StatusServiceUnavailable, "owner_results_busy", "unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	// This signed authorization metadata is the only filesystem read permitted
	// before leaf ownership is established. No broker query is a fallback.
	raw, err := ownerResultsReadAt(ctx, h.inbox, job+".json", h.material.config.ExpectedAcceptancesUID)
	if err != nil {
		writeJSONError(w, http.StatusForbidden, "owner_results_forbidden", "forbidden")
		return
	}
	v, err := ownership.VerifyAcceptance(raw, h.material.pin, h.material.config.ExpectedScope)
	if err != nil {
		writeJSONError(w, http.StatusForbidden, "owner_results_forbidden", "forbidden")
		return
	}
	binding := v.Binding()
	c := h.material.config
	if binding.JobID != job || binding.ExecutionProfileSHA256 != c.ExecutionProfileSHA256 || binding.PipelineMode != c.PipelineMode || binding.CredentialSHA256 != principal.CredentialSHA256() {
		writeJSONError(w, http.StatusForbidden, "owner_results_forbidden", "forbidden")
		return
	}
	q := artifact.OwnerReadRequest{SchemaVersion: 1, Domain: artifact.OwnerReadRequestDomain, Operation: "status", JobID: job, AcceptanceSHA256: v.SHA256(), CredentialSHA256: principal.CredentialSHA256(), UploadSHA256: binding.CiphertextSHA256, ExpectedProfileSHA256: c.ExecutionProfileSHA256, AuthorityScope: c.ExpectedScope}
	client := artifact.OwnerReadClientConfig{SocketPath: c.ReaderSocket, ExpectedBrokerUID: c.ExpectedBrokerUID}
	status, err := h.query(ctx, client, q)
	if err != nil || artifact.ValidateOwnerReadResponse(q, status) != nil || status.ErrorCode != "" || status.Binding.AnalysisContext.OriginalName != binding.OriginalName {
		writeJSONError(w, http.StatusServiceUnavailable, "owner_results_execution_unavailable", "unavailable")
		return
	}
	response := ownerResultsResponse{SchemaVersion: 1, Domain: ownerResultsDomain, JobID: job, AcceptanceSHA256: v.SHA256(), ExecutionState: status.Binding.Execution.State, Status: "pending", ReleaseStatus: "withheld", UploadSHA256: binding.CiphertextSHA256, ProcessedSHA256: status.Binding.ProcessedSHA256, PipelineMode: c.PipelineMode, PipelineOutput: json.RawMessage("null"), ScientificEvaluation: json.RawMessage("null")}
	if status.Binding.Execution.State == "committed" {
		var reader io.Reader
		chosen := status.Binding
		if _, has := chosen.Execution.Manifest.Files["execution_receipt"]; has {
			q.Operation = "receipt"
			rr, fd, readErr := h.receipt(ctx, client, q)
			if fd != nil {
				defer fd.Close()
			}
			// Compare every binding fact, including full manifest, processed context,
			// owner/scope and commit tuple. A second snapshot cannot relabel science.
			if readErr != nil || artifact.ValidateOwnerReadResponse(q, rr) != nil || rr.ErrorCode != "" || !rr.HasReceipt || fd == nil || !reflect.DeepEqual(chosen, rr.Binding) {
				writeJSONError(w, http.StatusServiceUnavailable, "owner_results_receipt_unavailable", "unavailable")
				return
			}
			chosen = rr.Binding
			reader = io.NewSectionReader(fd, 0, chosen.Execution.ReceiptBytes+1)
		}
		p := h.material.policy
		facts := projection.Facts{JobID: job, UploadSHA256: binding.CiphertextSHA256, ProfileSHA256: p.ProfileSHA256, ProcessedSHA256: chosen.ProcessedSHA256, ProcessedBytes: chosen.ProcessedBytes, AnalysisContext: chosen.AnalysisContext, Mode: p.PipelineMode, CapsuleKind: p.CapsuleKind, ExpectedSourcePins: p.SourcePins}
		projected, e := projection.ProjectCapsuleReceipt(ctx, reader, chosen.Execution, facts)
		if e != nil {
			writeJSONError(w, http.StatusServiceUnavailable, "owner_results_projection_invalid", "unavailable")
			return
		}
		response.Status = projected.Status
		response.ReleaseStatus = projected.ReleaseStatus
		response.ErrorCode = projected.PipelineError
		response.ArtifactExecution = projected.ArtifactExecution
		response.Detection = projected.Detection
		if projected.PipelineOutput != nil {
			response.PipelineOutput = projected.PipelineOutput
		}
		if projected.ScientificEvaluation != nil {
			response.ScientificEvaluation = projected.ScientificEvaluation
		}
	}
	encoded, err := encodeOwnerResultsResponse(ctx, response)
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "owner_results_response_invalid", "unavailable")
		return
	}
	// Bound the actual HTTPS write after complete projection and serialization.
	// A failed/partial write closes only this response; no ACK or mutation RPC exists.
	if http.NewResponseController(w).SetWriteDeadline(time.Now().Add(5*time.Second)) != nil {
		return
	}
	w.WriteHeader(http.StatusOK)
	if n, err := w.Write(encoded); err != nil || n != len(encoded) {
		return
	}
	http.NewResponseController(w).Flush()
}

func encodeOwnerResultsResponse(ctx context.Context, response ownerResultsResponse) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ownerResultsError("owner_results_response_invalid")
	}
	raw, err := json.Marshal(response)
	if err != nil || len(raw) > ownerResultsResponseLimit || ctx.Err() != nil {
		return nil, ownerResultsError("owner_results_response_invalid")
	}
	return raw, nil
}
