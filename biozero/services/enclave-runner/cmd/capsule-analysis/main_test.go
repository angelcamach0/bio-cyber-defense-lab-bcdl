// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"biozero/enclave-runner/analysis"
)

const request = `{"schema_version":1,"context":{"original_name":"BAD-private-name.fastq","processed_size_bytes":17,"decrypted":true,"decryption_error":"private secret string","signature_valid":true,"signature_error":""},"pipeline":{"read_count":3,"avg_read_length":100,"warnings":["a warning"]}}`

func TestCLIContractSuccessAndPrivacy(t *testing.T) {
	root := t.TempDir()
	rules := filepath.Join(root, "rules.json")
	content := filepath.Join(root, "private-input.fastq")
	if err := os.WriteFile(rules, []byte(`{"suspicious_name_patterns":["bad"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"--rules", rules, "--panel", "", "--content", content}
	var out bytes.Buffer
	if code := run(context.Background(), args, strings.NewReader(request), &out); code != 0 {
		t.Fatal("CLI failed", out.String())
	}
	var response analysis.Response
	if json.Unmarshal(out.Bytes(), &response) != nil || response.Status != "succeeded" || response.ErrorCode != "" || response.Detection == nil || math.Abs(response.Detection.Score-.3) > 1e-12 || response.Detection.Signals.Pipeline.ReadCount != 3 {
		t.Fatal("CLI result changed")
	}
	for _, secret := range []string{root, "BAD-private-name.fastq", "private secret string", "/host/path"} {
		if strings.Contains(out.String(), secret) {
			t.Fatal("private context/path escaped")
		}
	}
	if response.Detection.Signals.Alignment != nil {
		t.Fatal("unconfigured alignment unexpectedly ran")
	}
}

func TestCLIRejectsBeforeToolsAndReturnsStableJSON(t *testing.T) {
	root := t.TempDir()
	rules := filepath.Join(root, "rules.json")
	args := []string{"--rules", rules, "--panel", "", "--content", filepath.Join(root, "input")}
	for _, tc := range []struct {
		name, rule, stdin, code string
		arguments               []string
	}{
		{"missing_rules", "", request, "rules_read_error", nil},
		{"malformed_rules", "{", request, "rules_parse_error", nil},
		{"duplicate_rules", `{"low_score":0.1,"low_score":0.9}`, request, "rules_parse_error", nil},
		{"invalid_request", "{}", `{"content_path":"/escape"}`, "analysis_request_invalid", nil},
		{"oversized_request", "{}", strings.Repeat("x", analysis.MaxJSONBytes+1), "analysis_request_limit", nil},
		{"panel_missing", `{"threat_panel_fasta":"/host/panel"}`, request, "alignment_panel_missing", []string{"--rules", rules, "--panel", "/missing-panel", "--content", filepath.Join(root, "input")}},
		{"bad_argv", "{}", request, "analysis_config_invalid", []string{"--rules", "relative"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.rule != "" {
				if err := os.WriteFile(rules, []byte(tc.rule), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				_ = os.Remove(rules)
			}
			a := args
			if tc.arguments != nil {
				a = tc.arguments
			}
			var out bytes.Buffer
			if run(context.Background(), a, strings.NewReader(tc.stdin), &out) != 1 {
				t.Fatal("failure exited zero")
			}
			var got analysis.Response
			if len(out.Bytes()) > analysis.MaxJSONBytes || json.Unmarshal(out.Bytes(), &got) != nil || got.SchemaVersion != 1 || got.Status != "failed" || got.ErrorCode != tc.code || got.Detection != nil {
				t.Fatal("wrong stable failure envelope", out.String())
			}
			if strings.Contains(out.String(), root) || strings.Contains(out.String(), "/escape") {
				t.Fatal("private path emitted")
			}
		})
	}
}

func TestCLIPanelPresencePolicyAndNonemptyRemapping(t *testing.T) {
	root := t.TempDir()
	rules := filepath.Join(root, "rules.json")
	panel := filepath.Join(root, "capsule-panel.fa")
	content := filepath.Join(root, "capsule-input.fastq")
	for _, p := range []string{panel, content} {
		if err := os.WriteFile(p, []byte("synthetic fixture metadata only\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	tool := filepath.Join(root, "minimap2")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\nprintf 'q\\t0\\tsynthetic_target\\n'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", root)
	for _, tc := range []struct {
		name, rule, panelArg, status, code string
	}{
		{"both_empty", `{}`, "", "succeeded", ""},
		{"rules_panel_without_asset", `{"threat_panel_fasta":"/host/panel-not-mounted"}`, "", "failed", "analysis_panel_config_mismatch"},
		{"asset_without_rules_panel", `{}`, panel, "failed", "analysis_panel_config_mismatch"},
		{"nonempty_host_to_capsule_remap", `{"threat_panel_fasta":"/host/panel-not-mounted","threat_min_reads":1}`, panel, "succeeded", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(rules, []byte(tc.rule), 0600); err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			exit := run(context.Background(), []string{"--rules", rules, "--panel", tc.panelArg, "--content", content}, strings.NewReader(request), &out)
			var got analysis.Response
			if json.Unmarshal(out.Bytes(), &got) != nil || got.Status != tc.status || got.ErrorCode != tc.code {
				t.Fatal("panel presence policy changed", out.String())
			}
			if tc.status == "failed" {
				if exit != 1 || got.Detection != nil {
					t.Fatal("panel mismatch produced usable detection")
				}
			} else if exit != 0 || got.Detection == nil {
				t.Fatal("coherent panel configuration failed")
			} else if tc.panelArg != "" {
				a := got.Detection.Signals.Alignment
				if a == nil || a.TotalReads != 1 || a.MappedReads != 1 || a.Targets["synthetic_target"] != 1 || math.Abs(got.Detection.Score-.7) > 1e-12 || got.Detection.Reasons[0] != "threat_panel_hit" {
					t.Fatal("nonempty panel mapping lost configured detection")
				}
			} else if got.Detection.Signals.Alignment != nil {
				t.Fatal("empty configuration enabled alignment")
			}
			for _, private := range []string{root, "/host/panel-not-mounted"} {
				if strings.Contains(out.String(), private) {
					t.Fatal("panel source path escaped")
				}
			}
		})
	}
}

type shortWriter struct{}

func (shortWriter) Write(b []byte) (int, error) { return len(b) - 1, nil }
func TestCLIOutputFailureIsNonzero(t *testing.T) {
	if emit(shortWriter{}, analysis.Response{SchemaVersion: 1, Status: "failed", Warnings: []string{}}, 0) != 1 {
		t.Fatal("short write exited zero")
	}
}
