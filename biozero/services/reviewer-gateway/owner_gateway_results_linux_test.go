//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	projection "biozero/enclave-runner/receiptprojection"
	ownership "biozero/ownership-authority"
)

// All Results calls in the wire test use actual TLS/mTLS. The returned metrics
// below are explicit protocol fixtures, never evidence of scientific execution.
func ogAcceptedRun(t *testing.T, m ownerGatewayMaterial, id string) (ownerGatewayRun, ownership.VerifiedAcceptance) {
	t.Helper()
	reviewer := m.Reviewers[id]
	experiment := m.Experiments["synthetic"]
	client, e := ownership.NewAuthorityClient(reviewer.AuthorityConfig)
	if e != nil {
		t.Fatal(e)
	}
	defer client.CloseIdleConnections()
	var token [16]byte
	rand.Read(token[:])
	challenge, e := client.Reserve(context.Background(), ownership.HTTPReserveRequest{SchemaVersion: 1, RequestID: hex.EncodeToString(token[:]), OriginalName: experiment.Config.OriginalName})
	if e != nil {
		t.Fatal(e)
	}
	leaf := reviewer.AuthorityConfig.Certificate.Leaf
	if leaf == nil {
		t.Fatal("fixture requires parsed measured leaf")
	}
	key := reviewer.AuthorityConfig.Certificate.PrivateKey
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		t.Fatal("fixture RSA key")
	}
	payload, e := ownership.EncryptForChallenge(challenge, m.Pin, leaf, rsaKey, m.EncryptionKey, experiment.Input, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	raw, e := client.Finalize(context.Background(), challenge, payload.Manifest, bytes.NewReader(payload.Ciphertext), int64(len(payload.Ciphertext)))
	if e != nil {
		t.Fatal(e)
	}
	v, e := ownership.VerifyAcceptance(raw, m.Pin, m.Config.ExpectedScope)
	if e != nil {
		t.Fatal(e)
	}
	b := v.Binding()
	row := ownerGatewayRun{SchemaVersion: 1, RunID: strings.Repeat("9", 16), RequestID: hex.EncodeToString(token[:]), ReviewerID: id, CredentialSHA256: reviewer.CredentialSHA256, ExperimentID: "synthetic", ContextSHA256: m.ContextSHA256, InputSHA256: experiment.InputSHA256, InputBytes: experiment.InputBytes, ReferenceSHA256: experiment.ReferenceSHA256, ReferenceBytes: experiment.ReferenceBytes, OriginalName: experiment.Config.OriginalName, Phase: "delivered", JobID: b.JobID, AcceptanceSHA256: v.SHA256(), CiphertextSHA256: b.CiphertextSHA256, CiphertextBytes: b.CiphertextBytes, KeyEnvelopeSHA256: b.KeyEnvelopeSHA256, ChargeBytes: ownerGatewayRunCharge}
	return row, v
}

func ogPendingResult(row ownerGatewayRun) ownerGatewayResult {
	return ownerGatewayResult{SchemaVersion: 1, Domain: ogResultsDomain, JobID: row.JobID, AcceptanceSHA256: row.AcceptanceSHA256, ExecutionState: "executing", Status: "pending", ReleaseStatus: "withheld", UploadSHA256: row.CiphertextSHA256, ProcessedSHA256: row.InputSHA256, PipelineMode: "variants", PipelineOutput: json.RawMessage("null"), ScientificEvaluation: json.RawMessage("null")}
}

func ogProtocolResult(row ownerGatewayRun) ownerGatewayResult {
	r := ogPendingResult(row)
	r.ExecutionState = "committed"
	r.Status = "succeeded"
	r.ReleaseStatus = "evaluated_passed"
	r.ArtifactExecution = &projection.ArtifactExecution{SchemaVersion: 1, ProfileSHA256: strings.Repeat("2", 64), StoreID: strings.Repeat("4", 32), LeaseID: strings.Repeat("5", 32), ManifestSHA256: strings.Repeat("6", 64), ReceiptSHA256: strings.Repeat("7", 64), ReceiptBytes: 1, Files: map[string]projection.ArtifactFile{}}
	for _, name := range []string{"execution_receipt", "normalized_vcf", "variants_vcf", "variants_vcf_index"} {
		r.ArtifactExecution.Files[name] = projection.ArtifactFile{SHA256: strings.Repeat("7", 64), Bytes: 1}
	}
	pipe := map[string]any{"schema_version": 1, "pipeline": "python-wrapper", "mode": "variants", "pipeline_status": "succeeded", "timestamp": "synthetic-fixture", "stages": []any{map[string]any{"name": "validate_fastq", "status": "succeeded", "returncode": 0}, map[string]any{"name": "vcf_check", "status": "succeeded", "returncode": 0}}, "outputs": map[string]string{"normalized_vcf": "normalized_vcf", "variants_vcf": "variants_vcf", "variants_vcf_index": "variants_vcf_index"}, "errors": []any{}, "warnings": []string{}, "tools": map[string]bool{}, "read_count": 1, "avg_read_length": 4, "line_count": 4, "byte_count": row.InputBytes, "sha256": row.InputSHA256, "reference_sha256": row.ReferenceSHA256, "variant_count": 3}
	r.PipelineOutput, _ = json.Marshal(pipe)
	r.ScientificEvaluation = json.RawMessage(`{"evaluation_status":"passed","tp":3,"fp":0,"fn":0,"precision":1,"recall":1,"unexpected_count":0,"missing_count":0,"scope":"normalized allele presence; no genotype or clinical validation"}`)
	r.Detection = &projection.Detection{Score: 0, Reason: "no suspicious indicators", Verdict: "low", Signals: map[string]any{"warnings": map[string]any{"critical": 0, "warn": 0, "info": 0}, "integrity": map[string]any{"signature_valid": true, "decrypted": true}, "pipeline": map[string]any{"read_count": 1, "avg_read_length": 4}}}
	return r
}

func ogChangeProtocolPipeline(t *testing.T, r *ownerGatewayResult, change func(map[string]any)) {
	t.Helper()
	var pipeline map[string]any
	if e := json.Unmarshal(r.PipelineOutput, &pipeline); e != nil {
		t.Fatal(e)
	}
	change(pipeline)
	var e error
	r.PipelineOutput, e = json.Marshal(pipeline)
	if e != nil {
		t.Fatal(e)
	}
}

type ogResultWireState struct {
	mu       sync.Mutex
	raw      []byte
	redirect string
	peers    []string
	calls    int
}

func ogResultsWire(t *testing.T, f *ogConfigTestFixture) (*ogResultWireState, *httptest.Server) {
	t.Helper()
	state := &ogResultWireState{}
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state.mu.Lock()
		state.calls++
		state.peers = append(state.peers, ogConfigDigest(r.TLS.PeerCertificates[0].Raw))
		raw := append([]byte(nil), state.raw...)
		redirect := state.redirect
		state.mu.Unlock()
		if r.Method != "GET" || !strings.HasPrefix(r.URL.Path, "/v1/results/") || r.URL.RawQuery != "" || r.ContentLength != 0 || r.Header.Get("X-Client-Id") != "" {
			t.Error("unexpected Results wire request")
		}
		if redirect != "" {
			http.Redirect(w, r, redirect, http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(raw)
	}))
	s.Config.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){}
	s.TLS = f.serverTLS.Clone()
	s.StartTLS()
	t.Cleanup(s.Close)
	return state, s
}

func TestOwnerGatewayResultsRealTLSAndZeroCallBindingGuards(t *testing.T) {
	f := ogNewConfigFixture(t)
	state, server := ogResultsWire(t, f)
	cfg := f.config
	cfg.ResultsURL = server.URL
	ogWriteConfig(t, f.path, cfg)
	m, e := loadOwnerGatewayConfig(context.Background(), f.path)
	if e != nil {
		t.Fatal(e)
	}
	defer ogCloseMaterial(m)
	a, acceptedA := ogAcceptedRun(t, m, "a")
	b, acceptedB := ogAcceptedRun(t, m, "b")
	state.raw, _ = json.Marshal(ogPendingResult(a))
	if r, e := m.Reviewers["a"].Results.Query(context.Background(), a, acceptedA); e != nil || r.Status != "pending" {
		t.Fatal("matching actual mTLS", e)
	}
	state.mu.Lock()
	if state.calls != 1 || len(state.peers) != 1 || state.peers[0] != m.Reviewers["a"].CredentialSHA256 {
		t.Fatal("wrong TLS reviewer identity")
	}
	state.mu.Unlock()
	for name, mutate := range map[string]func(*ownerGatewayRun){"reviewer": func(r *ownerGatewayRun) { r.ReviewerID = "b" }, "credential": func(r *ownerGatewayRun) { r.CredentialSHA256 = b.CredentialSHA256 }, "context": func(r *ownerGatewayRun) { r.ContextSHA256 = strings.Repeat("8", 64) }, "job": func(r *ownerGatewayRun) { r.JobID = b.JobID }, "acceptance": func(r *ownerGatewayRun) { r.AcceptanceSHA256 = b.AcceptanceSHA256 }, "input": func(r *ownerGatewayRun) { r.InputSHA256 = strings.Repeat("8", 64) }, "reference": func(r *ownerGatewayRun) { r.ReferenceSHA256 = strings.Repeat("8", 64) }, "bytes": func(r *ownerGatewayRun) { r.InputBytes++ }, "upload": func(r *ownerGatewayRun) { r.CiphertextSHA256 = strings.Repeat("8", 64) }, "envelope": func(r *ownerGatewayRun) { r.KeyEnvelopeSHA256 = strings.Repeat("8", 64) }} {
		t.Run(name, func(t *testing.T) {
			bad := a
			mutate(&bad)
			if _, e := m.Reviewers["a"].Results.Query(context.Background(), bad, acceptedA); e == nil {
				t.Fatal("crossed authorization accepted")
			}
		})
	}
	if _, e := m.Reviewers["a"].Results.Query(context.Background(), b, acceptedB); e == nil {
		t.Fatal("A client acquired B accepted job")
	}
	if _, e := m.Reviewers["a"].Results.Query(context.Background(), a, ownership.VerifiedAcceptance{}); e == nil {
		t.Fatal("unverified acceptance accepted")
	}
	state.mu.Lock()
	if state.calls != 1 {
		t.Fatal("unauthorized binding reached network", state.calls)
	}
	state.raw, _ = json.Marshal(ogPendingResult(b))
	state.mu.Unlock()
	if _, e := m.Reviewers["b"].Results.Query(context.Background(), b, acceptedB); e != nil {
		t.Fatal("matching B TLS", e)
	}
	state.mu.Lock()
	if state.peers[len(state.peers)-1] != m.Reviewers["b"].CredentialSHA256 {
		t.Fatal("shared TLS identity substituted")
	}
	state.mu.Unlock()
	var followed atomic.Int32
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { followed.Add(1) }))
	target.TLS = f.serverTLS.Clone()
	target.StartTLS()
	t.Cleanup(target.Close)
	state.mu.Lock()
	state.redirect = target.URL
	state.mu.Unlock()
	if _, e := m.Reviewers["b"].Results.Query(context.Background(), b, acceptedB); e == nil || followed.Load() != 0 {
		t.Fatal("redirect followed")
	}
	if e := m.Reviewers["a"].Results.Close(); e != nil {
		t.Fatal(e)
	}
	state.mu.Lock()
	before := state.calls
	state.mu.Unlock()
	if _, e := m.Reviewers["a"].Results.Query(context.Background(), a, acceptedA); e == nil {
		t.Fatal("closed client queried")
	}
	state.mu.Lock()
	if state.calls != before {
		t.Fatal("close failed to stop admission")
	}
	state.mu.Unlock()
}

type ogRoundTripFunc func(*http.Request) (*http.Response, error)

func (f ogRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type ogTrackedBody struct {
	io.Reader
	closed atomic.Bool
}

func (b *ogTrackedBody) Close() error { b.closed.Store(true); return nil }

func TestOwnerGatewayResultsStrictBodyAndClosure(t *testing.T) {
	f := ogNewConfigFixture(t)
	m, e := loadOwnerGatewayConfig(context.Background(), f.path)
	if e != nil {
		t.Fatal(e)
	}
	defer ogCloseMaterial(m)
	row, v := ogAcceptedRun(t, m, "a")
	client := m.Reviewers["a"].Results
	valid, _ := json.Marshal(ogPendingResult(row))
	for name, body := range map[string][]byte{"positive": valid, "duplicate": []byte(strings.Replace(string(valid), `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1)), "case": []byte(strings.Replace(string(valid), `"domain"`, `"Domain"`, 1)), "unknown": []byte(strings.Replace(string(valid), `"schema_version":1`, `"private_path":"/private","schema_version":1`, 1)), "trailing": append(append([]byte(nil), valid...), []byte(` {}`)...), "invalid_utf8": append(append([]byte(nil), valid...), 0xff), "null_status": []byte(strings.Replace(string(valid), `"status":"pending"`, `"status":null`, 1)), "oversize": bytes.Repeat([]byte{'x'}, ownerGatewayResponseLimit+1)} {
		t.Run(name, func(t *testing.T) {
			tracked := &ogTrackedBody{Reader: bytes.NewReader(body)}
			var calls atomic.Int32
			client.client.Transport = ogRoundTripFunc(func(*http.Request) (*http.Response, error) {
				calls.Add(1)
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: tracked, ContentLength: -1}, nil
			})
			_, e := client.Query(context.Background(), row, v)
			if name == "positive" && e != nil || name != "positive" && e == nil {
				t.Fatal("body boundary", e)
			}
			if !tracked.closed.Load() || calls.Load() != 1 {
				t.Fatal("body leak or retry")
			}
		})
	}
}

func TestOwnerGatewayResultsProjectedScienceCoherence(t *testing.T) {
	f := ogNewConfigFixture(t)
	m, e := loadOwnerGatewayConfig(context.Background(), f.path)
	if e != nil {
		t.Fatal(e)
	}
	defer ogCloseMaterial(m)
	row, _ := ogAcceptedRun(t, m, "a")
	client := m.Reviewers["a"].Results
	baseline := ogProtocolResult(row)
	if e := client.validate(context.Background(), row, baseline); e != nil {
		t.Fatal("matching typed projected protocol", e)
	}
	for _, status := range []string{"failed", "incomplete"} {
		t.Run("receipt_only_pipeline_"+status, func(t *testing.T) {
			r := ogProtocolResult(row)
			r.Status = status
			r.ReleaseStatus = "withheld"
			r.ErrorCode = "capsule_pipeline_" + status
			r.ScientificEvaluation = json.RawMessage("null")
			r.ArtifactExecution.Files = map[string]projection.ArtifactFile{"execution_receipt": r.ArtifactExecution.Files["execution_receipt"]}
			ogChangeProtocolPipeline(t, &r, func(p map[string]any) {
				p["pipeline_status"] = status
				p["outputs"] = map[string]any{}
				p["stages"] = []any{map[string]any{"name": "validate_fastq", "status": "succeeded", "returncode": 0}, map[string]any{"name": "vcf_check", "status": status, "error_code": "fixture_stage_failed"}}
				p["errors"] = []any{map[string]any{"stage": "vcf_check", "code": "fixture_stage_failed", "message": "synthetic protocol failure"}}
			})
			if e := client.validate(context.Background(), row, r); e != nil {
				t.Fatal("legitimate receipt-only pipeline with coherent detection rejected", e)
			}
		})
	}
	for name, evaluation := range map[string]string{
		"counts":     `{"evaluation_status":"failed","tp":2,"fp":1,"fn":1,"precision":0.6666666666666666,"recall":0.6666666666666666,"unexpected_count":1,"missing_count":1,"scope":"normalized allele presence; no genotype or clinical validation"}`,
		"error_only": `{"evaluation_status":"failed","error":"synthetic evaluator failure"}`,
	} {
		t.Run("evaluation_failed_"+name, func(t *testing.T) {
			r := ogProtocolResult(row)
			r.ReleaseStatus = "withheld"
			r.ErrorCode = "capsule_science_failed"
			r.ScientificEvaluation = json.RawMessage(evaluation)
			if e := client.validate(context.Background(), row, r); e != nil {
				t.Fatal("legitimate failed evaluation with succeeded execution rejected", e)
			}
		})
	}
	for _, code := range []string{"capsule_analysis_request_limit", "capsule_capture_limit", "capsule_json_invalid", "capsule_analysis_stdin_failed", "capsule_analysis_start_failed", "capsule_analysis_invalid", "capsule_analysis_failed"} {
		t.Run(code, func(t *testing.T) {
			r := ogProtocolResult(row)
			r.Status = "failed"
			r.ReleaseStatus = "withheld"
			r.ErrorCode = code
			r.Detection = nil
			if e := client.validate(context.Background(), row, r); e != nil {
				t.Fatal("legitimate projected analysis failure rejected", e)
			}
		})
	}
	for name, mutate := range map[string]func(*ownerGatewayResult){"acceptance": func(r *ownerGatewayResult) { r.AcceptanceSHA256 = strings.Repeat("8", 64) }, "processed": func(r *ownerGatewayResult) { r.ProcessedSHA256 = strings.Repeat("8", 64) }, "profile": func(r *ownerGatewayResult) { r.ArtifactExecution.ProfileSHA256 = strings.Repeat("8", 64) }, "unapproved_status": func(r *ownerGatewayResult) { r.Status = "failed" }, "false_precision": func(r *ownerGatewayResult) {
		r.ScientificEvaluation = bytes.Replace(r.ScientificEvaluation, []byte(`"precision":1`), []byte(`"precision":0.5`), 1)
	}, "false_count": func(r *ownerGatewayResult) {
		r.ScientificEvaluation = bytes.Replace(r.ScientificEvaluation, []byte(`"fp":0`), []byte(`"fp":1`), 1)
	}, "arbitrary_analysis_error": func(r *ownerGatewayResult) {
		r.Status = "failed"
		r.ReleaseStatus = "withheld"
		r.ErrorCode = "capsule_analysis_made_up"
		r.Detection = nil
	}, "failed_pipeline_with_exports": func(r *ownerGatewayResult) {
		r.Status = "failed"
		r.ReleaseStatus = "withheld"
		r.ErrorCode = "capsule_pipeline_failed"
		r.PipelineOutput = bytes.Replace(r.PipelineOutput, []byte(`"pipeline_status":"succeeded"`), []byte(`"pipeline_status":"failed"`), 1)
		r.ScientificEvaluation = json.RawMessage("null")
	}} {
		t.Run(name, func(t *testing.T) {
			r := ogProtocolResult(row)
			mutate(&r)
			if e := client.validate(context.Background(), row, r); e == nil {
				t.Fatal("incoherent projected protocol accepted")
			}
		})
	}
	without := ogPendingResult(row)
	without.ExecutionState = "committed"
	without.Status = "failed"
	without.ReleaseStatus = "withheld"
	without.ErrorCode = "artifact_cancelled"
	without.ArtifactExecution = &projection.ArtifactExecution{SchemaVersion: 1, ProfileSHA256: m.Config.ExecutionProfileSHA256, StoreID: strings.Repeat("4", 32), LeaseID: strings.Repeat("5", 32), ManifestSHA256: strings.Repeat("6", 64), Files: map[string]projection.ArtifactFile{}}
	if e := client.validate(context.Background(), row, without); e != nil {
		t.Fatal("legitimate committed failed with no receipt", e)
	}
}

// This exercises the typed protocol boundary with its own stats profile/policy.
// It neither executes stats nor supplies native/HTTPS acceptance evidence.
func TestOwnerGatewayResultsStatsSucceededUnassessedProtocol(t *testing.T) {
	profile := strings.Repeat("8", 64)
	row := ownerGatewayRun{JobID: strings.Repeat("9", 16), AcceptanceSHA256: strings.Repeat("a", 64), CiphertextSHA256: strings.Repeat("b", 64), InputSHA256: strings.Repeat("c", 64), InputBytes: 24, ReferenceSHA256: strings.Repeat("d", 64)}
	pins := map[string]projection.SourcePin{}
	for _, name := range []string{"pipeline", "resource_budget", "analysis_executable", "analysis_rules"} {
		pins[name] = projection.SourcePin{SHA256: strings.Repeat("e", 64), Bytes: 1}
	}
	pins["reference"] = projection.SourcePin{SHA256: row.ReferenceSHA256, Bytes: 16}
	raw, e := json.Marshal(projection.Policy{SchemaVersion: 1, ProfileSHA256: profile, PipelineMode: "stats", CapsuleKind: "native", SourcePins: pins})
	if e != nil {
		t.Fatal(e)
	}
	policy, e := projection.ParsePolicy(context.Background(), raw, profile, "stats")
	if e != nil {
		t.Fatal(e)
	}
	client := &ownerGatewayResultsClient{pin: ownership.AuthorityPin{PipelineMode: "stats", ExecutionProfileSHA256: profile}, policy: policy}
	r := ogProtocolResult(row)
	r.PipelineMode = "stats"
	r.ReleaseStatus = "unassessed"
	r.ScientificEvaluation = json.RawMessage("null")
	r.ArtifactExecution.ProfileSHA256 = profile
	r.ArtifactExecution.Files = map[string]projection.ArtifactFile{"execution_receipt": r.ArtifactExecution.Files["execution_receipt"]}
	ogChangeProtocolPipeline(t, &r, func(p map[string]any) {
		p["mode"] = "stats"
		p["stages"] = []any{map[string]any{"name": "validate_fastq", "status": "succeeded", "returncode": 0}, map[string]any{"name": "fastq_stats", "status": "succeeded", "returncode": 0}}
		p["outputs"] = map[string]any{}
		delete(p, "variant_count")
	})
	if e := client.validate(context.Background(), row, r); e != nil {
		t.Fatal("legitimate stats succeeded/unassessed protocol rejected", e)
	}
}
