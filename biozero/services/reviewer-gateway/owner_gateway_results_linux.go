//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"regexp"
	"sync"
	"time"

	"biozero/enclave-runner/analysis"
	projection "biozero/enclave-runner/receiptprojection"
	ownership "biozero/ownership-authority"
)

const ogResultsDomain = "biozero.results.owner.v1"

type ogResultsExperiment struct {
	Name, InputSHA256, ReferenceSHA256 string
	InputBytes, ReferenceBytes         int64
}

// This client is read-only. Its only wire operation is one owner Results GET;
// browser errors cannot reach Reserve, Finalize, upload, worker or broker ACK.
type ownerGatewayResultsClient struct {
	client                 *http.Client
	base                   string
	pin                    ownership.AuthorityPin
	scope                  ownership.AcceptanceScope
	policy                 projection.Policy
	credential             string
	contextSHA, reviewerID string
	experiments            map[string]ogResultsExperiment
	ctx                    context.Context
	cancel                 context.CancelFunc
	closeOnce              sync.Once
}

func newOwnerGatewayResultsClient(cfg ownership.AuthorityClientConfig, policy projection.Policy, credential string) (*ownerGatewayResultsClient, error) {
	if _, err := ogGatewayOrigin(cfg.BaseURL, true); err != nil {
		return nil, err
	}
	checked, err := ownership.NewAuthorityClient(cfg)
	if err != nil {
		return nil, ogConfigError("owner_gateway_results_config_invalid")
	}
	checked.CloseIdleConnections()
	if len(cfg.Certificate.Certificate) == 0 || ogConfigDigest(cfg.Certificate.Certificate[0]) != credential || !projection.ArtifactHex(credential, 64) || policy.ProfileSHA256 != cfg.Pin.ExecutionProfileSHA256 || policy.PipelineMode != cfg.Pin.PipelineMode {
		return nil, ogConfigError("owner_gateway_results_config_invalid")
	}
	key, ok := cfg.Certificate.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, ogConfigError("owner_gateway_results_config_invalid")
	}
	copyKey, err := x509.ParsePKCS1PrivateKey(x509.MarshalPKCS1PrivateKey(key))
	if err != nil {
		return nil, ogConfigError("owner_gateway_results_config_invalid")
	}
	pair := tls.Certificate{PrivateKey: copyKey, Certificate: make([][]byte, len(cfg.Certificate.Certificate))}
	for i, der := range cfg.Certificate.Certificate {
		pair.Certificate[i] = append([]byte(nil), der...)
	}
	copyPolicy := policy
	copyPolicy.SourcePins = map[string]projection.SourcePin{}
	for name, pin := range policy.SourcePins {
		copyPolicy.SourcePins[name] = pin
	}
	pin := cfg.Pin
	pin.PublicKey = append(ed25519.PublicKey(nil), cfg.Pin.PublicKey...)
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: cfg.RootCAs.Clone(), ServerName: cfg.ServerName, Certificates: []tls.Certificate{pair}, NextProtos: []string{"http/1.1"}, SessionTicketsDisabled: true}
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, TLSClientConfig: tlsConfig, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second, MaxResponseHeaderBytes: 16 << 10, DisableKeepAlives: true, DisableCompression: true, MaxConnsPerHost: 2, ForceAttemptHTTP2: false, TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}}
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return ogConfigError("owner_gateway_results_redirect_denied")
	}}
	ctx, cancel := context.WithCancel(context.Background())
	return &ownerGatewayResultsClient{client: client, base: cfg.BaseURL, pin: pin, scope: cfg.Scope, policy: copyPolicy, credential: credential, ctx: ctx, cancel: cancel, experiments: map[string]ogResultsExperiment{}}, nil
}

func (c *ownerGatewayResultsClient) Close() error {
	if c == nil {
		return nil
	}
	c.closeOnce.Do(func() { c.cancel(); c.client.CloseIdleConnections() })
	return nil
}

func (c *ownerGatewayResultsClient) authorize(run ownerGatewayRun, v ownership.VerifiedAcceptance) error {
	bad := func() error { return ogConfigError("owner_gateway_results_binding_invalid") }
	if c == nil || c.ctx.Err() != nil || !projection.ArtifactHex(c.contextSHA, 64) || run.SchemaVersion != 1 || run.ContextSHA256 != c.contextSHA || run.ReviewerID != c.reviewerID || run.CredentialSHA256 != c.credential || !projection.ArtifactHex(run.JobID, 16) || !projection.ArtifactHex(run.AcceptanceSHA256, 64) || v.SHA256() != run.AcceptanceSHA256 {
		return bad()
	}
	experiment, ok := c.experiments[run.ExperimentID]
	if !ok || run.InputSHA256 != experiment.InputSHA256 || run.InputBytes != experiment.InputBytes || run.ReferenceSHA256 != experiment.ReferenceSHA256 || run.ReferenceBytes != experiment.ReferenceBytes || run.OriginalName != experiment.Name {
		return bad()
	}
	b := v.Binding()
	claim := v.Claims()
	if claim.SchemaVersion != 1 || claim.Domain != ownership.AcceptanceDomain || claim.AuthorityID != c.pin.AuthorityID || claim.KeyID != ogConfigDigest(c.pin.PublicKey) || claim.StoreID != c.scope.StoreID || claim.PolicySHA256 != c.scope.PolicySHA256 || b.AuthorityID != c.pin.AuthorityID || b.JobID != run.JobID || b.CredentialSHA256 != c.credential || b.ExecutionProfileSHA256 != c.pin.ExecutionProfileSHA256 || b.PipelineMode != c.pin.PipelineMode || b.OriginalName != run.OriginalName || b.CiphertextSHA256 != run.CiphertextSHA256 || b.CiphertextBytes != run.CiphertextBytes || b.KeyEnvelopeSHA256 != run.KeyEnvelopeSHA256 {
		return bad()
	}
	return nil
}

func (c *ownerGatewayResultsClient) Query(ctx context.Context, run ownerGatewayRun, v ownership.VerifiedAcceptance) (ownerGatewayResult, error) {
	var zero ownerGatewayResult
	if ctx == nil || ctx.Err() != nil {
		return zero, ogConfigError("owner_gateway_results_cancelled")
	}
	if err := c.authorize(run, v); err != nil {
		return zero, err
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	stop := context.AfterFunc(c.ctx, cancel)
	defer stop()
	request, err := http.NewRequestWithContext(bounded, http.MethodGet, c.base+"/v1/results/"+run.JobID, nil)
	if err != nil {
		return zero, ogConfigError("owner_gateway_results_request_invalid")
	}
	response, err := c.client.Do(request)
	if err != nil {
		if response != nil && response.Body != nil {
			response.Body.Close()
		}
		return zero, ogConfigError("owner_gateway_results_unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/json" || response.Header.Get("Content-Encoding") != "" || response.Uncompressed || response.ContentLength > ownerGatewayResponseLimit {
		return zero, ogConfigError("owner_gateway_results_unavailable")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, ownerGatewayResponseLimit+1))
	if err != nil || len(raw) == 0 || len(raw) > ownerGatewayResponseLimit || bounded.Err() != nil {
		return zero, ogConfigError("owner_gateway_results_body_invalid")
	}
	var result ownerGatewayResult
	if projection.DecodeClosedJSON(bounded, raw, &result) != nil || c.validate(bounded, run, result) != nil {
		return zero, ogConfigError("owner_gateway_results_protocol_invalid")
	}
	return result, nil
}

var ogResultCode = regexp.MustCompile(projection.ErrorCodePattern)

func ogJSONNull(raw []byte) bool { return bytes.Equal(bytes.TrimSpace(raw), []byte("null")) }

func (c *ownerGatewayResultsClient) validate(ctx context.Context, run ownerGatewayRun, r ownerGatewayResult) error {
	bad := func() error { return ogConfigError("owner_gateway_results_protocol_invalid") }
	if r.SchemaVersion != 1 || r.Domain != ogResultsDomain || r.JobID != run.JobID || r.AcceptanceSHA256 != run.AcceptanceSHA256 || r.UploadSHA256 != run.CiphertextSHA256 || r.ProcessedSHA256 != run.InputSHA256 || r.PipelineMode != c.pin.PipelineMode || (r.ErrorCode != "" && !ogResultCode.MatchString(r.ErrorCode)) {
		return bad()
	}
	if r.ExecutionState != "committed" {
		if (r.ExecutionState != "reserved" && r.ExecutionState != "executing" && r.ExecutionState != "prepared") || r.Status != "pending" || r.ReleaseStatus != "withheld" || r.ErrorCode != "" || r.ArtifactExecution != nil || r.Detection != nil || !ogJSONNull(r.PipelineOutput) || !ogJSONNull(r.ScientificEvaluation) {
			return bad()
		}
		return nil
	}
	if r.ArtifactExecution == nil || r.ArtifactExecution.ProfileSHA256 != c.pin.ExecutionProfileSHA256 {
		return bad()
	}
	artifactJSON, err := json.Marshal(r.ArtifactExecution)
	if err != nil {
		return bad()
	}
	if _, err = projection.ValidateArtifactExecution(artifactJSON, r.Status, r.ReleaseStatus); err != nil {
		return bad()
	}
	if r.Status != "succeeded" && r.ErrorCode == "" || r.ReleaseStatus == "withheld" && r.ErrorCode == "" || r.ReleaseStatus != "withheld" && r.ErrorCode != "" {
		return bad()
	}
	_, hasReceipt := r.ArtifactExecution.Files["execution_receipt"]
	if !hasReceipt {
		if r.Status != "failed" || r.ReleaseStatus != "withheld" || !ogJSONNull(r.PipelineOutput) || !ogJSONNull(r.ScientificEvaluation) || r.Detection != nil {
			return bad()
		}
		return nil
	}
	if ogJSONNull(r.PipelineOutput) || c.validatePipeline(ctx, run, r) != nil || c.validateEvaluation(ctx, r) != nil || c.validateDetection(ctx, r) != nil {
		return bad()
	}
	return nil
}

func ogResultsObject(raw json.RawMessage, required, optional []string) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || object == nil {
		return nil, ogConfigError("owner_gateway_results_protocol_invalid")
	}
	allowed := map[string]bool{}
	for _, name := range required {
		allowed[name] = true
		if _, ok := object[name]; !ok {
			return nil, ogConfigError("owner_gateway_results_protocol_invalid")
		}
	}
	for _, name := range optional {
		allowed[name] = true
	}
	for name := range object {
		if !allowed[name] {
			return nil, ogConfigError("owner_gateway_results_protocol_invalid")
		}
	}
	return object, nil
}

type ogPipelineStage struct {
	Name       string `json:"name"`
	Status     string `json:"status"`
	Returncode *int   `json:"returncode,omitempty"`
	ErrorCode  string `json:"error_code,omitempty"`
}
type ogPipelineFault struct {
	Stage   string `json:"stage"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (c *ownerGatewayResultsClient) validatePipeline(ctx context.Context, run ownerGatewayRun, r ownerGatewayResult) error {
	bad := func() error { return ogConfigError("owner_gateway_results_pipeline_invalid") }
	if len(r.PipelineOutput) > 1<<20 {
		return bad()
	}
	fields, err := ogResultsObject(r.PipelineOutput, []string{"schema_version", "pipeline", "mode", "pipeline_status", "timestamp", "stages", "outputs", "errors", "warnings", "tools"}, []string{"resource_budget", "read_count", "avg_read_length", "line_count", "byte_count", "sha256", "reference_sha256", "variant_count", "error", "versions", "fastp"})
	if err != nil {
		return bad()
	}
	var version int
	var name, mode, status, timestamp string
	if json.Unmarshal(fields["schema_version"], &version) != nil || version != 1 || json.Unmarshal(fields["pipeline"], &name) != nil || name != "python-wrapper" || json.Unmarshal(fields["mode"], &mode) != nil || mode != c.policy.PipelineMode || json.Unmarshal(fields["pipeline_status"], &status) != nil || (status != "succeeded" && status != "failed" && status != "incomplete") || json.Unmarshal(fields["timestamp"], &timestamp) != nil || len(timestamp) > 256 {
		return bad()
	}
	if r.Status == "succeeded" && status != "succeeded" || r.Status == "incomplete" && status != "incomplete" || r.Status == "failed" && status == "succeeded" && (!ogAnalysisFailure(r.ErrorCode) || r.Detection != nil) {
		return bad()
	}
	for _, field := range []string{"read_count", "avg_read_length", "line_count", "byte_count", "variant_count"} {
		value, present := fields[field]
		if status == "succeeded" && field != "variant_count" && !present {
			return bad()
		}
		if status == "succeeded" && mode == "variants" && field == "variant_count" && !present {
			return bad()
		}
		if present {
			var count int64
			if ogJSONNull(value) || json.Unmarshal(value, &count) != nil || count < 0 || count > 1000000000 || field == "byte_count" && count != run.InputBytes {
				return bad()
			}
		}
	}
	for field, wanted := range map[string]string{"sha256": run.InputSHA256, "reference_sha256": run.ReferenceSHA256} {
		value, present := fields[field]
		if status == "succeeded" && (field == "sha256" || mode == "variants") && !present {
			return bad()
		}
		if present {
			var hash string
			if json.Unmarshal(value, &hash) != nil || !projection.ArtifactHex(hash, 64) || hash != wanted {
				return bad()
			}
		}
	}
	var stages []ogPipelineStage
	if projection.DecodeClosedJSON(ctx, fields["stages"], &stages) != nil || len(stages) > 4096 {
		return bad()
	}
	seen := map[string]bool{}
	for _, stage := range stages {
		if stage.Name == "" || len(stage.Name) > 128 || seen[stage.Name] || (stage.Status != "succeeded" && stage.Status != "failed" && stage.Status != "incomplete") || stage.ErrorCode != "" && !ogResultCode.MatchString(stage.ErrorCode) {
			return bad()
		}
		if status == "succeeded" && (stage.Status != "succeeded" || stage.Returncode != nil && *stage.Returncode != 0) {
			return bad()
		}
		seen[stage.Name] = true
	}
	if status == "succeeded" && (!seen["validate_fastq"] || mode == "variants" && !seen["vcf_check"] || mode == "stats" && !seen["fastq_stats"]) {
		return bad()
	}
	var faults []ogPipelineFault
	var warnings []string
	var tools map[string]bool
	if projection.DecodeClosedJSON(ctx, fields["errors"], &faults) != nil || len(faults) > 4096 || status == "succeeded" && len(faults) > 0 || projection.DecodeClosedJSON(ctx, fields["warnings"], &warnings) != nil || projection.DecodeClosedJSON(ctx, fields["tools"], &tools) != nil || len(tools) > 64 {
		return bad()
	}
	for _, fault := range faults {
		if len(fault.Stage) > 128 || !ogResultCode.MatchString(fault.Code) || len(fault.Message) > 64<<10 {
			return bad()
		}
	}
	outputs, err := ogResultsObject(fields["outputs"], nil, []string{"normalized_vcf", "variants_vcf", "variants_vcf_index", "fastp_summary"})
	if err != nil {
		return bad()
	}
	for id, value := range outputs {
		if id == "fastp_summary" {
			var summary map[string]json.RawMessage
			if json.Unmarshal(value, &summary) != nil || summary == nil {
				return bad()
			}
			continue
		}
		var label string
		if json.Unmarshal(value, &label) != nil || label != id {
			return bad()
		}
		if _, retained := r.ArtifactExecution.Files[id]; !retained {
			return bad()
		}
	}
	if status != "succeeded" && len(r.ArtifactExecution.Files) != 1 {
		return bad()
	}
	if mode == "stats" {
		if _, has := r.ArtifactExecution.Files["normalized_vcf"]; has {
			return bad()
		}
	}
	if status == "succeeded" && mode == "variants" {
		for _, id := range []string{"normalized_vcf", "variants_vcf", "variants_vcf_index"} {
			if _, ok := outputs[id]; !ok {
				return bad()
			}
		}
	}
	return nil
}

type ogEvaluationCounts struct {
	Status     string   `json:"evaluation_status"`
	TP         int64    `json:"tp"`
	FP         int64    `json:"fp"`
	FN         int64    `json:"fn"`
	Precision  *float64 `json:"precision"`
	Recall     *float64 `json:"recall"`
	Unexpected int64    `json:"unexpected_count"`
	Missing    int64    `json:"missing_count"`
	Scope      string   `json:"scope"`
}

func (c *ownerGatewayResultsClient) validateEvaluation(ctx context.Context, r ownerGatewayResult) error {
	bad := func() error { return ogConfigError("owner_gateway_results_evaluation_invalid") }
	var pipeline map[string]json.RawMessage
	json.Unmarshal(r.PipelineOutput, &pipeline)
	var pipelineStatus string
	json.Unmarshal(pipeline["pipeline_status"], &pipelineStatus)
	_, hasEvaluator := c.policy.SourcePins["evaluator"]
	expected := c.policy.PipelineMode == "variants" && pipelineStatus == "succeeded" && hasEvaluator
	if !expected {
		if !ogJSONNull(r.ScientificEvaluation) || r.ReleaseStatus == "evaluated_passed" || r.Status == "succeeded" && r.ReleaseStatus != "unassessed" {
			return bad()
		}
		return nil
	}
	if ogJSONNull(r.ScientificEvaluation) || len(r.ScientificEvaluation) > 1<<20 {
		return bad()
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(r.ScientificEvaluation, &object) != nil || object == nil {
		return bad()
	}
	if _, hasError := object["error"]; hasError {
		var fault struct {
			Status string `json:"evaluation_status"`
			Error  string `json:"error"`
		}
		if projection.DecodeClosedJSON(ctx, r.ScientificEvaluation, &fault) != nil || fault.Status != "failed" || r.ReleaseStatus != "withheld" {
			return bad()
		}
		return nil
	}
	var e ogEvaluationCounts
	if projection.DecodeClosedJSON(ctx, r.ScientificEvaluation, &e) != nil || (e.Status != "passed" && e.Status != "failed") || e.TP < 0 || e.FP < 0 || e.FN < 0 || e.TP > 10000000 || e.FP > 10000000 || e.FN > 10000000 || e.Unexpected != e.FP || e.Missing != e.FN || e.Scope != "normalized allele presence; no genotype or clinical validation" {
		return bad()
	}
	for _, metric := range []struct {
		value *float64
		den   int64
	}{{e.Precision, e.TP + e.FP}, {e.Recall, e.TP + e.FN}} {
		if metric.den == 0 && metric.value != nil || metric.den > 0 && (metric.value == nil || *metric.value != float64(e.TP)/float64(metric.den)) {
			return bad()
		}
	}
	if e.Status == "passed" && (e.TP <= 0 || e.FP != 0 || e.FN != 0) {
		return bad()
	}
	if r.ReleaseStatus == "evaluated_passed" && (e.Status != "passed" || r.Status != "succeeded") {
		return bad()
	}
	if e.Status == "failed" && r.ReleaseStatus != "withheld" || e.Status == "passed" && r.Status == "succeeded" && r.ReleaseStatus != "evaluated_passed" {
		return bad()
	}
	return nil
}

func (c *ownerGatewayResultsClient) validateDetection(ctx context.Context, r ownerGatewayResult) error {
	bad := func() error { return ogConfigError("owner_gateway_results_detection_invalid") }
	if r.Detection == nil {
		if r.Status != "failed" || !ogAnalysisFailure(r.ErrorCode) {
			return bad()
		}
		return nil
	}
	raw, err := json.Marshal(r.Detection)
	if err != nil {
		return bad()
	}
	var d analysis.Result
	if projection.DecodeClosedJSON(ctx, raw, &d) != nil || d.Score < 0 || d.Score > 1 || (d.Verdict != "low" && d.Verdict != "medium" && d.Verdict != "high") || len(d.Reasons) > 7 {
		return bad()
	}
	allowed := map[string]bool{"suspicious_filename": true, "file_size_exceeded": true, "decryption_failed": true, "signature_invalid": true, "critical_pipeline_warnings": true, "low_quality_reads": true, "threat_panel_hit": true}
	seen := map[string]bool{}
	for _, reason := range d.Reasons {
		if !allowed[reason] || seen[reason] {
			return bad()
		}
		seen[reason] = true
	}
	reason := "no suspicious indicators"
	if len(d.Reasons) > 0 {
		reason = d.Reasons[0]
	}
	if d.Reason != reason {
		return bad()
	}
	s := d.Signals
	if !s.Integrity.SignatureValid || !s.Integrity.Decrypted || s.Pipeline.ReadCount < 0 || s.Pipeline.AvgReadLength < 0 || s.Warnings.Critical < 0 || s.Warnings.Warn < 0 || s.Warnings.Info < 0 || s.Warnings.Critical > 1<<20 || s.Warnings.Warn > 1<<20 || s.Warnings.Info > 1<<20 || s.Fastp != nil && (s.Fastp.Q30Rate < 0 || s.Fastp.Q30Rate > 1) {
		return bad()
	}
	var pipeline map[string]json.RawMessage
	json.Unmarshal(r.PipelineOutput, &pipeline)
	var reads, length int
	json.Unmarshal(pipeline["read_count"], &reads)
	json.Unmarshal(pipeline["avg_read_length"], &length)
	if s.Pipeline.ReadCount != reads || s.Pipeline.AvgReadLength != length {
		return bad()
	}
	_, panel := c.policy.SourcePins["analysis_panel"]
	if panel != (s.Alignment != nil) {
		return bad()
	}
	if a := s.Alignment; a != nil {
		if a.TotalReads < 0 || a.TotalReads > 1000000 || a.MappedReads < 0 || a.MappedReads > a.TotalReads || len(a.Targets) > 128 {
			return bad()
		}
		fraction := 0.0
		if a.TotalReads > 0 {
			fraction = float64(a.MappedReads) / float64(a.TotalReads)
		}
		if a.Fraction != fraction {
			return bad()
		}
		total := 0
		for name, count := range a.Targets {
			if name == "" || len(name) > 128 || count <= 0 || count > a.MappedReads {
				return bad()
			}
			for _, ch := range name {
				if ch < 33 || ch > 126 {
					return bad()
				}
			}
			total += count
		}
		if total != a.MappedReads {
			return bad()
		}
	}
	return nil
}

// These are the exact non-integrity analysis outcomes accepted by the shared
// receipt projector, including capture failures whose names have no analysis prefix.
func ogAnalysisFailure(code string) bool {
	switch code {
	case "capsule_analysis_request_limit", "capsule_capture_limit", "capsule_json_invalid", "capsule_analysis_stdin_failed", "capsule_analysis_start_failed", "capsule_analysis_invalid", "capsule_analysis_failed":
		return true
	}
	return false
}
