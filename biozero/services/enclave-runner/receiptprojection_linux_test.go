//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"testing"

	artifact "biozero/artifact-executor"
	"biozero/enclave-runner/receiptprojection"
)

// The existing receipt fixture/corpus remains in capsule_receipt_linux_test.go.
// Both public entry points consume those same bytes; no second science evaluator
// or independent reimplementation of projection rules is used for comparison.
func TestSharedReceiptProjectionPreservesExistingFixtures(t *testing.T) {
	for _, kind := range []string{"stats", "variants", "analysis_failed", "empty_failed"} {
		t.Run(kind, func(t *testing.T) {
			mode := "variants"
			if kind == "stats" || kind == "empty_failed" {
				mode = "stats"
			}
			receipt, facts := receiptTestFixture(mode, true)
			outcome := receipt["outcome"].(map[string]any)
			if kind == "analysis_failed" {
				receipt["analysis_capture"] = receiptTestCapture(map[string]any{"schema_version": 1, "status": "failed", "error_code": "rules_parse_error", "warnings": []string{}, "detection": nil}, 1)
				outcome["execution_status"], outcome["release_status"], outcome["error_code"] = "failed", "withheld", "capsule_analysis_failed"
			}
			raw, err := json.Marshal(receipt)
			if err != nil {
				t.Fatal(err)
			}
			response := receiptTestResponse(raw, facts, outcome)
			var readerLegacy, readerShared io.Reader = bytes.NewReader(raw), bytes.NewReader(raw)
			if kind == "empty_failed" {
				response.Manifest.Files = map[string]artifact.FileRecord{}
				response.Manifest.ExecutionStatus, response.Manifest.ReleaseStatus, response.Manifest.ErrorCode = "failed", "withheld", "capsule_cancelled"
				response.ReceiptSHA256, response.ReceiptBytes = "", 0
				manifestRaw, _ := json.Marshal(response.Manifest)
				response.ManifestSHA256 = receiptDigest(manifestRaw)
				readerLegacy, readerShared = nil, nil
			}
			legacy, err := ProjectCapsuleReceipt(context.Background(), readerLegacy, response, facts)
			if err != nil {
				t.Fatal(err)
			}
			shared, err := receiptprojection.ProjectCapsuleReceipt(context.Background(), readerShared, response, facts)
			if err != nil || !reflect.DeepEqual(legacy, shared) {
				t.Fatal("exported projection differs from worker wrapper", err)
			}
			legacyRaw, err := json.Marshal(legacy)
			if err != nil {
				t.Fatal(err)
			}
			sharedRaw, err := json.Marshal(shared)
			if err != nil || !bytes.Equal(legacyRaw, sharedRaw) {
				t.Fatal("serialization changed", err)
			}
			for _, secret := range []string{"/workspace", "private.fastq", "raw_stdout", "raw_stderr", "private stderr", "alignment.sam"} {
				if bytes.Contains(sharedRaw, []byte(secret)) {
					t.Fatal("private capture/path escaped", secret)
				}
			}
			switch kind {
			case "stats":
				if shared.Status != "succeeded" || shared.ReleaseStatus != "unassessed" || shared.ScientificEvaluation != nil || shared.Detection == nil || shared.Detection.Score != 0.7 || len(shared.ArtifactExecution.Files) != 1 {
					t.Fatal("stats semantics changed")
				}
			case "variants":
				if shared.Status != "succeeded" || shared.ReleaseStatus != "evaluated_passed" || shared.Detection == nil || shared.Detection.Score != 0.7 || len(shared.ArtifactExecution.Files) != 4 {
					t.Fatal("variants semantics changed")
				}
				var evaluation map[string]any
				if json.Unmarshal(shared.ScientificEvaluation, &evaluation) != nil || evaluation["tp"] != float64(3) || evaluation["fp"] != float64(0) || evaluation["fn"] != float64(0) || evaluation["unexpected_count"] != float64(0) || evaluation["missing_count"] != float64(0) {
					t.Fatal("evaluation projection changed")
				}
			case "analysis_failed":
				if shared.Status != "failed" || shared.ReleaseStatus != "withheld" || shared.PipelineError != "capsule_analysis_failed" || shared.Detection != nil || shared.ScientificEvaluation == nil || len(shared.ArtifactExecution.Files) != 4 {
					t.Fatal("analysis failure became approval or lost evidence")
				}
			case "empty_failed":
				if shared.Status != "failed" || shared.ReleaseStatus != "withheld" || shared.PipelineError != "capsule_cancelled" || shared.Detection != nil || shared.PipelineOutput != nil || shared.ScientificEvaluation != nil || len(shared.ArtifactExecution.Files) != 0 {
					t.Fatal("empty failed commit fabricated output")
				}
			}
		})
	}
}

func TestSharedReceiptProjectionRejectsAmbiguousAndNonfiniteBytes(t *testing.T) {
	for _, kind := range []string{"duplicate", "case alias", "null", "nonfinite", "trailing", "depth"} {
		t.Run(kind, func(t *testing.T) {
			receipt, facts := receiptTestFixture("variants", true)
			raw, _ := json.Marshal(receipt)
			switch kind {
			case "duplicate":
				raw = bytes.Replace(raw, []byte(`"schema_version":2`), []byte(`"schema_version":2,"schema_version":2`), 1)
			case "case alias":
				raw = bytes.Replace(raw, []byte(`"input_bytes":10`), []byte(`"Input_bytes":10`), 1)
			case "null":
				raw = bytes.Replace(raw, []byte(`"input_bytes":10`), []byte(`"input_bytes":null`), 1)
			case "nonfinite":
				raw = bytes.Replace(raw, []byte(`"input_bytes":10`), []byte(`"input_bytes":1e999`), 1)
			case "trailing":
				raw = append(raw, []byte(`{}`)...)
			case "depth":
				raw = bytes.Replace(raw, []byte(`"input_bytes":10`), []byte(`"input_bytes":`+strings.Repeat("[", 65)+`0`+strings.Repeat("]", 65)), 1)
			}
			// Rehash the fixture so rejection exercises semantic parsing rather than
			// being accidentally shadowed by the transport SHA/length check.
			response := receiptTestResponse(raw, facts, receipt["outcome"].(map[string]any))
			out, err := receiptprojection.ProjectCapsuleReceipt(context.Background(), bytes.NewReader(raw), response, facts)
			if err == nil || !reflectReceiptZero(out) {
				t.Fatal("bad receipt accepted")
			}
		})
	}
}
