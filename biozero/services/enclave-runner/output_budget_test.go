// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestOutputCaptureExactAndOneOver(t *testing.T) {
	for _, maximum := range []int{maxPipelineStdoutBytes, maxCommandStderrBytes} {
		t.Run(fmt.Sprint(maximum), func(t *testing.T) {
			var cancellations atomic.Int32
			capture := newOutputCapture(maximum, func() { cancellations.Add(1) })
			data := []byte(strings.Repeat("x", maximum))
			if n, err := capture.Write(data); n != maximum || err != nil || capture.Exceeded() {
				t.Fatal("exact limit refused", n, err)
			}
			if n, err := capture.Write([]byte("x")); n != 0 || !errors.Is(err, errCommandOutputLimit) {
				t.Fatal("one over accepted", n, err)
			}
			if len(capture.Bytes()) != maximum || cancellations.Load() != 1 || !capture.Exceeded() {
				t.Fatal("capture grew or cancellation missing")
			}
			capture.Write(data)
			if cancellations.Load() != 1 || len(capture.Bytes()) != maximum {
				t.Fatal("overflow latch reset")
			}
		})
	}
}

func TestOutputCaptureConcurrentOverflow(t *testing.T) {
	var cancellations atomic.Int32
	capture := newOutputCapture(64, func() { cancellations.Add(1) })
	var group sync.WaitGroup
	for i := 0; i < 16; i++ {
		group.Add(1)
		go func() { defer group.Done(); capture.Write([]byte("12345678")) }()
	}
	group.Wait()
	if len(capture.Bytes()) != 64 || cancellations.Load() != 1 || !capture.Exceeded() {
		t.Fatal("concurrent overflow lost or grew")
	}
}

func TestPipelineOutputLimitAfterLeaderExitKillsDescendant(t *testing.T) {
	root := t.TempDir()
	path, marker := filepath.Join(root, "pipeline.sh"), filepath.Join(root, "escaped")
	// The shell leader exits before the background child overflows its inherited
	// stdout pipe. The child intentionally continues after head's broken pipe.
	script := fmt.Sprintf("#!/bin/sh\n(sleep 0.05; head -c %d /dev/zero; sleep 0.3; touch '%s') &\nexit 0\n", maxPipelineStdoutBytes+1, marker)
	if err := os.WriteFile(path, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	output, _, code := runPipeline(path, "unused", "", root, "stats", 3*time.Second)
	if code != "pipeline_output_limit" || len(output) != 0 || time.Since(started) > 2*time.Second {
		t.Fatal("output limit not reported promptly", code)
	}
	time.Sleep(500 * time.Millisecond)
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("descendant survived output limit after leader exit")
	}
}

func TestPipelineOutputLimitWithholdsValidJSONPrefix(t *testing.T) {
	for _, stream := range []string{"stdout", "stderr"} {
		t.Run(stream, func(t *testing.T) {
			f := newTestJob(t, "", 0)
			t.Setenv("BIOZERO_SECURITY_MODE", "demo")
			redirect, count := "", maxPipelineStdoutBytes+1
			if stream == "stderr" {
				redirect, count = " >&2", maxCommandStderrBytes+1
			}
			script := fmt.Sprintf("#!/bin/sh\nprintf '%%s' '{\"schema_version\":1,\"mode\":\"stats\",\"pipeline_status\":\"succeeded\"}'\nhead -c %d /dev/zero | tr '\\000' ' '%s\nexit 0\n", count, redirect)
			if err := os.WriteFile(f.pipeline, []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			result := f.run(t, 3*time.Second)
			if result.Status != "failed" || result.ReleaseStatus != "withheld" || result.ErrorCode != "pipeline_output_limit" || len(result.PipelineOutput) != 0 {
				t.Fatal("oversized output released", result.Status, result.ErrorCode)
			}
			parsed, err := readResultContext(context.Background(), filepath.Join(f.results, f.job.JobID+".json"))
			if err != nil || parsed.Status != "failed" {
				t.Fatal("failure metadata unreadable", err)
			}
		})
	}
}

func TestScientificOutputLimitAlwaysWithheld(t *testing.T) {
	for _, stream := range []string{"stdout", "stderr"} {
		t.Run(stream, func(t *testing.T) {
			result, reference, root := scientificFixture(t, "", 0)
			count := maxEvaluatorStdoutBytes + 1
			if stream == "stderr" {
				count = maxCommandStderrBytes + 1
			}
			script := fmt.Sprintf("import sys\nprint('{\"evaluation_status\":\"passed\",\"tp\":3,\"fp\":0,\"fn\":0,\"precision\":1,\"recall\":1}', flush=True)\nsys.%s.write('x' * %d)\nsys.%s.flush()\n", stream, count, stream)
			if err := os.WriteFile(filepath.Join(root, "evaluate.py"), []byte(script), 0600); err != nil {
				t.Fatal(err)
			}
			assessScientificRelease(context.Background(), result, reference)
			if result.ReleaseStatus != "withheld" {
				t.Fatal("oversized passed evaluator released")
			}
			var report map[string]any
			if json.Unmarshal(result.ScientificEvaluation, &report) != nil || report["evaluation_error_code"] != "evaluation_output_limit" {
				t.Fatal("wrong evaluator overflow code")
			}
		})
	}
}

func TestPipelineCommandExactOutputBudgets(t *testing.T) {
	for _, stream := range []string{"stdout", "stderr"} {
		t.Run(stream, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "pipeline.sh")
			valid := `{"schema_version":1,"mode":"stats","pipeline_status":"succeeded"}`
			count, redirect := maxPipelineStdoutBytes-len(valid), ""
			if stream == "stderr" {
				count, redirect = maxCommandStderrBytes, " >&2"
			}
			script := fmt.Sprintf("#!/bin/sh\nprintf '%%s' '%s'\nhead -c %d /dev/zero | tr '\\000' ' '%s\nexit 0\n", valid, count, redirect)
			if err := os.WriteFile(path, []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			out, message, code := runPipeline(path, "unused", "", root, "stats", time.Second)
			if code != "" || message != "" || string(out) != valid {
				t.Fatal("exact budget rejected", code, message)
			}
		})
	}
}

func TestAlignmentLimitsStopDescendants(t *testing.T) {
	for _, cause := range []string{"long_sam_line", "stderr"} {
		t.Run(cause, func(t *testing.T) {
			root := t.TempDir()
			path, marker := filepath.Join(root, "minimap2"), filepath.Join(root, "escaped")
			fasta, fastq := filepath.Join(root, "ref.fa"), filepath.Join(root, "reads.fastq")
			for _, input := range []string{fasta, fastq} {
				if err := os.WriteFile(input, []byte("fixture"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			count, redirect := 1024*1024+1, ""
			if cause == "stderr" {
				count, redirect = maxCommandStderrBytes+1, " >&2"
			}
			script := fmt.Sprintf("#!/bin/sh\n(sleep 0.05; head -c %d /dev/zero%s; sleep 0.3; touch '%s') &\nexit 0\n", count, redirect, marker)
			if err := os.WriteFile(path, []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", root+string(os.PathListSeparator)+os.Getenv("PATH"))
			started := time.Now()
			stats, warning := threatPanelAlignment(context.Background(), fasta, fastq)
			if warning == "" || stats.TotalReads != 0 || len(stats.Targets) != 0 || time.Since(started) > 2*time.Second {
				t.Fatal("alignment resource failure not bounded", warning)
			}
			time.Sleep(500 * time.Millisecond)
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("alignment descendant survived", cause)
			}
		})
	}
}

func TestResultSerializedBudgetExactAndOneOver(t *testing.T) {
	base := resultRecord{SchemaVersion: 1, JobID: "abcdef1234567890", Status: "succeeded", SecurityMode: "protected", PipelineMode: "variants",
		ProcessedAt: "2026-10-14T00:00:00Z", UploadSHA256: strings.Repeat("a", 64), ProcessedSHA256: strings.Repeat("b", 64),
		SizeBytes: 42, Decrypted: true, SignatureValid: true, ClientCertSerial: "42", ReleaseStatus: "evaluated_passed", ErrorMessage: "x"}
	base.ArtifactExecution = &artifactExecution{SchemaVersion: 1, ProfileSHA256: strings.Repeat("c", 64), StoreID: strings.Repeat("d", 32), LeaseID: strings.Repeat("e", 32), ManifestSHA256: strings.Repeat("f", 64), ReceiptSHA256: strings.Repeat("a", 64), ReceiptBytes: 1, Files: map[string]artifactFile{
		"execution_receipt":  {SHA256: strings.Repeat("a", 64), Bytes: 1},
		"normalized_vcf":     {SHA256: strings.Repeat("b", 64), Bytes: 1},
		"variants_vcf":       {SHA256: strings.Repeat("c", 64), Bytes: 1},
		"variants_vcf_index": {SHA256: strings.Repeat("d", 64), Bytes: 1},
	}}
	skeleton, err := json.MarshalIndent(base, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	for _, extra := range []int{0, 1} {
		result := base
		result.ErrorMessage += strings.Repeat("x", int(maxResultMetadataBytes)-len(skeleton)+extra)
		final, data, err := boundedResultRecord(result)
		if err != nil || len(data) > int(maxResultMetadataBytes) {
			t.Fatal("budget failure", err)
		}
		if extra == 0 {
			if len(data) != int(maxResultMetadataBytes) || final.ReleaseStatus != "evaluated_passed" || final.ErrorMessage != result.ErrorMessage {
				t.Fatal("exact result changed")
			}
		} else {
			if final.Status != "failed" || final.ReleaseStatus != "withheld" || final.ErrorCode != "result_metadata_too_large" || len(final.PipelineOutput) != 0 || len(final.ScientificEvaluation) != 0 {
				t.Fatal("oversized result approved")
			}
			if final.JobID != base.JobID || final.ProcessedAt != base.ProcessedAt || final.UploadSHA256 != base.UploadSHA256 || final.ProcessedSHA256 != base.ProcessedSHA256 || final.ClientCertSerial != base.ClientCertSerial || final.SizeBytes != base.SizeBytes || !final.Decrypted || !final.SignatureValid {
				t.Fatal("provenance changed")
			}
			if final.ArtifactExecution == nil || final.ArtifactExecution.ManifestSHA256 != base.ArtifactExecution.ManifestSHA256 || final.ArtifactExecution.ReceiptSHA256 != base.ArtifactExecution.ReceiptSHA256 {
				t.Fatal("oversized result lost retained artifact binding")
			}
		}
		path := filepath.Join(t.TempDir(), "record.json")
		if err := writeJSONBytes(path, data); err != nil {
			t.Fatal(err)
		}
		if _, err := readResultContext(context.Background(), path); err != nil {
			t.Fatal("reader rejects bounded producer", err)
		}
	}
}
