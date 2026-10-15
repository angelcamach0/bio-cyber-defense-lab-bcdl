//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	artifact "biozero/artifact-executor"
)

func receiptTestCapture(payload any, code int) map[string]any {
	b, _ := json.Marshal(payload)
	return map[string]any{"returncode": code, "payload": payload, "raw_stdout": string(b), "raw_stderr": "private stderr /workspace/secret.fastq"}
}
func receiptTestFixture(mode string, panel bool) (map[string]any, capsuleReceiptFacts) {
	pins := map[string]capsuleSourcePin{}
	for _, key := range []string{"pipeline", "resource_budget", "analysis_executable", "analysis_rules"} {
		pins[key] = capsuleSourcePin{strings.Repeat("a", 64), 1}
	}
	if mode == "variants" {
		for _, key := range []string{"reference", "evaluator", "truth"} {
			pins[key] = capsuleSourcePin{strings.Repeat("b", 64), 1}
		}
	}
	if panel {
		pins["analysis_panel"] = capsuleSourcePin{strings.Repeat("c", 64), 1}
	}
	facts := capsuleReceiptFacts{JobID: strings.Repeat("1", 16), UploadSHA256: strings.Repeat("2", 64), ProfileSHA256: strings.Repeat("3", 64), ProcessedSHA256: strings.Repeat("4", 64), ProcessedBytes: 10, AnalysisContext: artifact.AnalysisContext{OriginalName: "private.fastq", ProcessedSizeBytes: 10, Decrypted: true, SignatureValid: true}, Mode: mode, CapsuleKind: "native", ExpectedSourcePins: pins}
	state := map[string]any{"pid": 1, "uid": 0, "gid": 0, "rlimit_fsize": []int{64 << 20, 64 << 20}, "NoNewPrivs": "1", "namespaces": map[string]string{"user": "user:[1]", "mnt": "mnt:[2]", "pid": "pid:[3]", "net": "net:[4]"}}
	for _, key := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		state[key] = "0000000000000000"
	}
	pipeline := map[string]any{"schema_version": 1, "mode": mode, "pipeline_status": "succeeded", "pipeline": "python-wrapper", "timestamp": "2026-10-15T00:00:00+00:00", "line_count": 8, "read_count": 2, "avg_read_length": 5, "byte_count": 10, "sha256": facts.ProcessedSHA256, "input": "/workspace/private.fastq", "output_dir": nil, "warnings": []string{"INFO: /workspace/private.fastq validated"}, "stages": []any{map[string]any{"name": "validate_fastq", "status": "succeeded"}, map[string]any{"name": "fastq_stats", "status": "succeeded"}}, "errors": []any{}, "tools": map[string]bool{}, "versions": map[string]string{"minimap2": "2.31"}, "outputs": map[string]any{"fastp_summary": map[string]any{"summary": map[string]any{"after_filtering": map[string]any{"q30_rate": 0.9}}}}}
	signals := map[string]any{"warnings": map[string]int{"critical": 0, "warn": 0, "info": 1}, "integrity": map[string]bool{"signature_valid": true, "decrypted": true}, "pipeline": map[string]int{"read_count": 2, "avg_read_length": 5}, "fastp": map[string]any{"q30_rate": 0.9}}
	reasons := []string{}
	reason := "no suspicious indicators"
	score := 0.1
	verdict := "low"
	if panel {
		signals["alignment"] = map[string]any{"mapped_reads": 2, "total_reads": 2, "fraction": 1.0, "targets": map[string]int{"PRIVATE_TARGET": 2}}
		reasons = []string{"threat_panel_hit"}
		reason = reasons[0]
		score = 0.7
		verdict = "medium"
	}
	detection := map[string]any{"score": score, "reason": reason, "verdict": verdict, "reasons": reasons, "signals": signals}
	outcome := map[string]any{"execution_status": "succeeded", "release_status": "unassessed", "error_code": "", "observed_sha256": "", "evaluated_sha256": ""}
	var evaluation any
	if mode == "variants" {
		pipeline["stages"] = append(pipeline["stages"].([]any), map[string]any{"name": "vcf_check", "status": "succeeded", "returncode": 0})
		pipeline["reference_sha256"] = pins["reference"].SHA256
		pipeline["variant_count"] = 3
		pipeline["output_dir"] = "/workspace/biozero-run-secret"
		outputs := pipeline["outputs"].(map[string]any)
		for id, name := range map[string]string{"normalized_vcf": "variants.vcf", "variants_vcf": "variants.vcf.gz", "variants_vcf_index": "variants.vcf.gz.csi", "alignment_sam": "alignment.sam"} {
			outputs[id] = "/workspace/biozero-run-secret/" + name
		}
		outcome["release_status"] = "evaluated_passed"
		outcome["observed_sha256"] = strings.Repeat("5", 64)
		outcome["evaluated_sha256"] = strings.Repeat("5", 64)
		evaluation = receiptTestCapture(map[string]any{"evaluation_status": "passed", "tp": 3, "fp": 0, "fn": 0, "precision": 1.0, "recall": 1.0, "unexpected": []any{}, "missing": []any{}, "scope": "normalized allele presence; no genotype or clinical validation"}, 0)
	}
	return map[string]any{"schema_version": 2, "input_sha256": facts.ProcessedSHA256, "input_bytes": 10, "source_pins": pins, "mode": mode, "capsule_state": state, "workspace_policy": map[string]any{"filesystem": "tmpfs", "bytes": 128 << 20, "nr_inodes": 4096, "file_bytes": 64 << 20}, "outcome": outcome, "pipeline": receiptTestCapture(pipeline, 0), "evaluation": evaluation, "scope": "synthetic normalized allele presence; no biological accuracy claim", "analysis_capture": receiptTestCapture(map[string]any{"schema_version": 1, "status": "succeeded", "error_code": "", "warnings": []string{}, "detection": detection}, 0), "analysis_context": facts.AnalysisContext}, facts
}
func receiptTestResponse(raw []byte, f capsuleReceiptFacts, outcome map[string]any) artifact.BridgeResponse {
	files := map[string]artifact.FileRecord{"execution_receipt": {State: "verified", SHA256: receiptDigest(raw), Bytes: int64(len(raw))}}
	if observed, _ := outcome["observed_sha256"].(string); observed != "" {
		for _, id := range []string{"normalized_vcf", "variants_vcf", "variants_vcf_index"} {
			files[id] = artifact.FileRecord{State: "verified", SHA256: observed, Bytes: 2}
		}
	}
	m := artifact.Manifest{SchemaVersion: 1, StoreID: strings.Repeat("6", 32), PolicySHA256: strings.Repeat("7", 64), LeaseID: strings.Repeat("8", 32), JobID: f.JobID, InputSHA256: f.UploadSHA256, Files: files, ExecutionStatus: outcome["execution_status"].(string), ReleaseStatus: outcome["release_status"].(string), ErrorCode: outcome["error_code"].(string), ObservedSHA256: outcome["observed_sha256"].(string), EvaluatedSHA256: outcome["evaluated_sha256"].(string)}
	b, _ := json.Marshal(m)
	return artifact.BridgeResponse{SchemaVersion: 2, JobID: f.JobID, UploadSHA256: f.UploadSHA256, ProfileSHA256: f.ProfileSHA256, StoreID: m.StoreID, LeaseID: m.LeaseID, State: "committed", HasManifest: true, Manifest: m, ManifestSHA256: receiptDigest(b), ReceiptSHA256: receiptDigest(raw), ReceiptBytes: int64(len(raw))}
}
func receiptTestProject(t *testing.T, receipt map[string]any, f capsuleReceiptFacts) (capsuleReceiptProjection, error) {
	t.Helper()
	raw, e := json.Marshal(receipt)
	if e != nil {
		t.Fatal(e)
	}
	r := receiptTestResponse(raw, f, receipt["outcome"].(map[string]any))
	return ProjectCapsuleReceipt(context.Background(), bytes.NewReader(raw), r, f)
}
func TestCapsuleReceiptProjectionPrivateMetricsAndOpaqueArtifacts(t *testing.T) {
	for _, mode := range []string{"stats", "variants"} {
		t.Run(mode, func(t *testing.T) {
			receipt, f := receiptTestFixture(mode, true)
			out, e := receiptTestProject(t, receipt, f)
			if e != nil {
				t.Fatal(e)
			}
			if out.Detection == nil || out.Detection.Score != 0.7 || out.ArtifactExecution == nil || out.ArtifactExecution.ReceiptBytes == 0 {
				t.Fatal("projection lost detection or custody binding")
			}
			raw, _ := json.Marshal(out)
			for _, secret := range []string{"/workspace", "private.fastq", "raw_stdout", "raw_stderr", "private stderr", "alignment.sam"} {
				if bytes.Contains(raw, []byte(secret)) {
					t.Fatalf("private capsule detail escaped: %s", secret)
				}
			}
			if !bytes.Contains(raw, []byte("PRIVATE_TARGET")) || !bytes.Contains(raw, []byte("fastp_summary")) || !bytes.Contains(raw, []byte("2.31")) {
				t.Fatal("private owner metrics/targets/versions lost")
			}
			if mode == "stats" && out.ReleaseStatus != "unassessed" {
				t.Fatal("stats acquired science approval")
			}
			if mode == "variants" {
				if out.ReleaseStatus != "evaluated_passed" || !bytes.Contains(out.PipelineOutput, []byte(`"normalized_vcf":"normalized_vcf"`)) {
					t.Fatal("retained reference or evaluation lost")
				}
			}
		})
	}
}
func TestCapsuleReceiptRejectsSemanticMutationAfterRehash(t *testing.T) {
	mutations := map[string]func(map[string]any){
		"schema_bool":    func(r map[string]any) { r["schema_version"] = true },
		"root_extra":     func(r map[string]any) { r["future"] = 1 },
		"root_alias":     func(r map[string]any) { r["Mode"] = r["mode"]; delete(r, "mode") },
		"source_missing": func(r map[string]any) { delete(r["source_pins"].(map[string]capsuleSourcePin), "analysis_rules") },
		"source_alias": func(r map[string]any) {
			r["source_pins"] = map[string]any{"Pipeline": map[string]any{"sha256": strings.Repeat("a", 64), "bytes": 1}}
		},
		"input_hash":       func(r map[string]any) { r["input_sha256"] = strings.Repeat("f", 64) },
		"input_bytes_bool": func(r map[string]any) { r["input_bytes"] = true },
		"context_size": func(r map[string]any) {
			c := r["analysis_context"].(artifact.AnalysisContext)
			c.ProcessedSizeBytes++
			r["analysis_context"] = c
		},
		"context_crypto": func(r map[string]any) {
			c := r["analysis_context"].(artifact.AnalysisContext)
			c.SignatureValid = false
			r["analysis_context"] = c
		},
		"caps_nonzero":             func(r map[string]any) { r["capsule_state"].(map[string]any)["CapEff"] = "0000000000000001" },
		"kernel_alias":             func(r map[string]any) { r["capsule_state"].(map[string]any)["PID"] = 1 },
		"quota":                    func(r map[string]any) { r["workspace_policy"].(map[string]any)["bytes"] = 64 << 20 },
		"payload_stdout_disagrees": func(r map[string]any) { r["pipeline"].(map[string]any)["raw_stdout"] = `{"different":true}` },
		"pipeline_code":            func(r map[string]any) { r["pipeline"].(map[string]any)["returncode"] = 1 },
		"evaluation_null":          func(r map[string]any) { r["evaluation"] = nil },
		"evaluation_tp_zero": func(r map[string]any) {
			p := r["evaluation"].(map[string]any)["payload"].(map[string]any)
			p["tp"] = 0
			r["evaluation"] = receiptTestCapture(p, 0)
		},
		"evaluation_fp": func(r map[string]any) {
			p := r["evaluation"].(map[string]any)["payload"].(map[string]any)
			p["fp"] = 1
			r["evaluation"] = receiptTestCapture(p, 0)
		},
		"analysis_no_detection": func(r map[string]any) {
			p := r["analysis_capture"].(map[string]any)["payload"].(map[string]any)
			p["detection"] = nil
			r["analysis_capture"] = receiptTestCapture(p, 0)
		},
		"analysis_signal_alias": func(r map[string]any) {
			p := r["analysis_capture"].(map[string]any)["payload"].(map[string]any)
			d := p["detection"].(map[string]any)
			d["Score"] = 0.1
			r["analysis_capture"] = receiptTestCapture(p, 0)
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			receipt, f := receiptTestFixture("variants", true)
			pins := map[string]capsuleSourcePin{}
			for k, v := range f.ExpectedSourcePins {
				pins[k] = v
			}
			f.ExpectedSourcePins = pins
			mutate(receipt)
			if _, e := receiptTestProject(t, receipt, f); e == nil {
				t.Fatal("mutated receipt accepted")
			}
		})
	}
}
func TestCapsuleReceiptAnalysisFailureNeverApproves(t *testing.T) {
	for _, kind := range []string{"rules_failure", "incomplete_capture", "invalid_payload"} {
		t.Run(kind, func(t *testing.T) {
			receipt, f := receiptTestFixture("variants", true)
			code := "capsule_analysis_failed"
			switch kind {
			case "rules_failure":
				receipt["analysis_capture"] = receiptTestCapture(map[string]any{"schema_version": 1, "status": "failed", "error_code": "rules_parse_error", "warnings": []string{}, "detection": nil}, 1)
			case "incomplete_capture":
				code = "capsule_analysis_request_limit"
				receipt["analysis_capture"] = map[string]any{"returncode": nil, "payload": nil, "raw_stdout": "", "raw_stderr": "", "error_code": code}
			case "invalid_payload":
				code = "capsule_analysis_invalid"
				receipt["analysis_capture"] = receiptTestCapture(map[string]any{"unknown": true}, 0)
			}
			o := receipt["outcome"].(map[string]any)
			o["execution_status"] = "failed"
			o["release_status"] = "withheld"
			o["error_code"] = code
			out, e := receiptTestProject(t, receipt, f)
			if e != nil {
				t.Fatal(e)
			}
			if out.Status != "failed" || out.ReleaseStatus != "withheld" || out.Detection != nil || out.PipelineError != code || len(out.ArtifactExecution.Files) != 4 {
				t.Fatal("analysis failure promoted or lost retained evaluation")
			}
		})
	}
}
func TestCapsuleReceiptFailedEmptyCommit(t *testing.T) {
	_, f := receiptTestFixture("stats", false)
	o := map[string]any{"execution_status": "failed", "release_status": "withheld", "error_code": "capsule_cancelled", "observed_sha256": "", "evaluated_sha256": ""}
	r := receiptTestResponse(nil, f, o)
	r.Manifest.Files = map[string]artifact.FileRecord{}
	r.ReceiptSHA256 = ""
	r.ReceiptBytes = 0
	b, _ := json.Marshal(r.Manifest)
	r.ManifestSHA256 = receiptDigest(b)
	out, e := ProjectCapsuleReceipt(context.Background(), nil, r, f)
	if e != nil || out.Detection != nil || out.PipelineOutput != nil || out.ScientificEvaluation != nil || out.ReleaseStatus != "withheld" {
		t.Fatal("empty failed commit fabricated results", e)
	}
	r.Manifest.ExecutionStatus = "succeeded"
	r.Manifest.ReleaseStatus = "unassessed"
	b, _ = json.Marshal(r.Manifest)
	r.ManifestSHA256 = receiptDigest(b)
	if _, e := ProjectCapsuleReceipt(context.Background(), nil, r, f); e == nil {
		t.Fatal("successful no-receipt commit accepted")
	}
}

type receiptFailReader struct{}

func (receiptFailReader) Read([]byte) (int, error) { return 0, errors.New("private /secret/path") }
func TestCapsuleReceiptBindingsFramingAndCancellation(t *testing.T) {
	receipt, f := receiptTestFixture("stats", false)
	raw, _ := json.Marshal(receipt)
	base := receiptTestResponse(raw, f, receipt["outcome"].(map[string]any))
	for _, name := range []string{"profile", "upload", "job", "processed", "manifest", "size", "digest", "noncommitted", "nil_reader", "read_error", "trailing", "duplicate", "overflow", "depth"} {
		t.Run(name, func(t *testing.T) {
			r := base
			facts := f
			body := raw
			var reader io.Reader
			switch name {
			case "profile":
				r.ProfileSHA256 = strings.Repeat("a", 64)
			case "upload":
				r.UploadSHA256 = strings.Repeat("a", 64)
			case "job":
				r.JobID = strings.Repeat("a", 16)
			case "processed":
				facts.ProcessedSHA256 = strings.Repeat("a", 64)
			case "manifest":
				r.ManifestSHA256 = strings.Repeat("a", 64)
			case "size":
				r.ReceiptBytes--
			case "digest":
				r.ReceiptSHA256 = strings.Repeat("a", 64)
			case "noncommitted":
				r.State = "executing"
			case "trailing":
				body = append(append([]byte{}, raw...), []byte(` {}`)...)
			case "duplicate":
				body = bytes.Replace(raw, []byte(`"schema_version":2`), []byte(`"schema_version":2,"schema_version":2`), 1)
			case "overflow":
				body = bytes.Replace(raw, []byte(`"input_bytes":10`), []byte(`"input_bytes":1e999`), 1)
			case "depth":
				body = bytes.Replace(raw, []byte(`"input_bytes":10`), []byte(`"input_bytes":`+strings.Repeat("[", 65)+`0`+strings.Repeat("]", 65)), 1)
			}
			if name == "trailing" || name == "duplicate" || name == "overflow" || name == "depth" {
				r = receiptTestResponse(body, f, receipt["outcome"].(map[string]any))
			}
			reader = bytes.NewReader(body)
			if name == "nil_reader" {
				reader = nil
			}
			if name == "read_error" {
				reader = receiptFailReader{}
			}
			out, e := ProjectCapsuleReceipt(context.Background(), reader, r, facts)
			if e == nil || !reflectReceiptZero(out) || strings.Contains(e.Error(), "/secret") {
				t.Fatal("bad binding/frame accepted or private error leaked", e)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := ProjectCapsuleReceipt(ctx, bytes.NewReader(raw), base, f); e == nil || e.Error() != "capsule_receipt_cancelled" {
		t.Fatal("cancel ignored", e)
	}
}
func reflectReceiptZero(out capsuleReceiptProjection) bool {
	return out.ArtifactExecution == nil && out.Detection == nil && out.PipelineOutput == nil && out.ScientificEvaluation == nil && out.Status == ""
}
func receiptTestDocker(receipt map[string]any, f *capsuleReceiptFacts) {
	f.CapsuleKind = "docker"
	receipt["capsule_kind"] = "docker"
	receipt["native_helper_sha256"] = strings.Repeat("9", 64)
	receipt["keeper_monitor"] = "active; EOF/error is cancellation, never proof"
	state := receipt["capsule_state"].(map[string]any)
	for _, k := range []string{"uid", "gid", "euid", "egid"} {
		state[k] = 1000
	}
	state["interfaces"] = []string{"lo"}
	state["mounts"] = []any{map[string]any{"mountpoint": "/", "options": []string{"ro"}, "filesystem": "overlay", "super_options": []string{"ro"}, "optional": []string{}}}
	fs := map[string]any{"filesystem_magic": 0x1021994, "block_bytes": 4096, "capacity_bytes": 128 << 20, "inode_units": 4096, "free_inode_units": 4096, "flags": 0}
	state["workspace_statfs"] = fs
	root := map[string]any{}
	for k, v := range fs {
		root[k] = v
	}
	root["flags"] = 1
	state["root_statfs"] = root
	state["workspace_directory"] = map[string]any{"uid": 1000, "gid": 1000, "mode": 0700, "empty": true}
	state["cgroup"] = map[string]string{"membership": "0::/", "namespace": "cgroup:[5]", "memory.max": "536870912", "memory.swap.max": "0", "pids.max": "128", "cpu.max": "100000 100000"}
}
func TestCapsuleReceiptDockerShapeAndLimits(t *testing.T) {
	receipt, f := receiptTestFixture("variants", true)
	receiptTestDocker(receipt, &f)
	if _, e := receiptTestProject(t, receipt, f); e != nil {
		t.Fatal("Docker receipt rejected", e)
	}
	for _, name := range []string{"missing_kind", "native_kind", "helper_pin", "swap", "uid", "network", "readonly", "workspace"} {
		t.Run(name, func(t *testing.T) {
			receipt, f := receiptTestFixture("variants", true)
			receiptTestDocker(receipt, &f)
			state := receipt["capsule_state"].(map[string]any)
			switch name {
			case "missing_kind":
				delete(receipt, "capsule_kind")
			case "native_kind":
				receipt["capsule_kind"] = "native"
			case "helper_pin":
				receipt["native_helper_sha256"] = "bad"
			case "swap":
				state["cgroup"].(map[string]string)["memory.swap.max"] = "1"
			case "uid":
				state["euid"] = 0
			case "network":
				state["interfaces"] = []string{"lo", "eth0"}
			case "readonly":
				state["root_statfs"].(map[string]any)["flags"] = 0
			case "workspace":
				state["workspace_statfs"].(map[string]any)["capacity_bytes"] = 64 << 20
			}
			if _, e := receiptTestProject(t, receipt, f); e == nil {
				t.Fatal("Docker predicate mismatch accepted")
			}
		})
	}
}
func TestCapsuleReceiptDetectionCannotDisagreeWithPipeline(t *testing.T) {
	for _, key := range []string{"read_count", "avg_read_length", "warnings", "fastp_summary"} {
		t.Run(key, func(t *testing.T) {
			receipt, f := receiptTestFixture("stats", false)
			p := receipt["pipeline"].(map[string]any)["payload"].(map[string]any)
			switch key {
			case "read_count", "avg_read_length":
				p[key] = 99
			case "warnings":
				p[key] = []string{"fatal synthetic failure"}
			case "fastp_summary":
				delete(p["outputs"].(map[string]any), key)
			}
			receipt["pipeline"] = receiptTestCapture(p, 0)
			if _, e := receiptTestProject(t, receipt, f); e == nil {
				t.Fatal("detection/pipeline disagreement accepted")
			}
		})
	}
}

func TestCapsuleReceiptSuccessfulPipelineRequiresCompletedStages(t *testing.T) {
	for _, kind := range []string{"missing", "failed", "null_exit", "nonzero_exit", "duplicate", "errors"} {
		t.Run(kind, func(t *testing.T) {
			r, f := receiptTestFixture("variants", true)
			p := r["pipeline"].(map[string]any)["payload"].(map[string]any)
			stages := p["stages"].([]any)
			switch kind {
			case "missing":
				p["stages"] = []any{}
			case "failed":
				stages[0].(map[string]any)["status"] = "failed"
			case "null_exit":
				stages[0].(map[string]any)["returncode"] = nil
			case "nonzero_exit":
				stages[0].(map[string]any)["returncode"] = 1
			case "duplicate":
				p["stages"] = append(stages, stages[0])
			case "errors":
				p["errors"] = []any{map[string]any{"stage": "synthetic", "code": "failed", "message": "failed"}}
			}
			r["pipeline"] = receiptTestCapture(p, 0)
			if _, e := receiptTestProject(t, r, f); e == nil {
				t.Fatal("unfinished/failed pipeline approved")
			}
		})
	}
}

func TestCapsuleReceiptStatsOptionalReferenceWithoutScience(t *testing.T) {
	for _, kind := range []string{"reference", "reference_at_limit", "reference_oversized", "evaluator", "truth", "evaluator_and_truth"} {
		t.Run(kind, func(t *testing.T) {
			receipt, facts := receiptTestFixture("stats", false)
			pins := receipt["source_pins"].(map[string]capsuleSourcePin)
			size := int64(1)
			if kind == "reference_at_limit" {
				size = 32 << 20
			}
			if kind == "reference_oversized" {
				size = (32 << 20) + 1
			}
			pins["reference"] = capsuleSourcePin{SHA256: strings.Repeat("b", 64), Bytes: size}
			if kind == "evaluator" || kind == "evaluator_and_truth" {
				pins["evaluator"] = capsuleSourcePin{SHA256: strings.Repeat("c", 64), Bytes: 1}
			}
			if kind == "truth" || kind == "evaluator_and_truth" {
				pins["truth"] = capsuleSourcePin{SHA256: strings.Repeat("d", 64), Bytes: 1}
			}
			out, err := receiptTestProject(t, receipt, facts)
			valid := kind == "reference" || kind == "reference_at_limit"
			if (err == nil) != valid {
				t.Fatal("stats reference/evaluator policy disagrees", err)
			}
			if valid && (out.Status != "succeeded" || out.ReleaseStatus != "unassessed" || len(out.ArtifactExecution.Files) != 1 || out.ScientificEvaluation != nil) {
				t.Fatal("stats reference acquired VCF/evaluation/release")
			}
		})
	}
}
