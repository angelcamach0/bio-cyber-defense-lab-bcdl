// SPDX-License-Identifier: AGPL-3.0-only
package analysis

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestLegacyScoringSignalsAndReasonOrder(t *testing.T) {
	r := DefaultRules()
	r.MaxSizeBytes = 10
	r.SuspiciousNameTokens = []string{"", "Virus", "virus"}
	r.ThreatPanelFasta = "host-configured"
	facts := Context{OriginalName: "VIRUS.fastq", ProcessedSizeBytes: 11, DecryptionError: "private decryption text", SignatureError: "private signature text"}
	p := json.RawMessage(`{"read_count":"1000","avg_read_length":101.9,"warnings":["warning","fatal error","note",17],"outputs":{"fastp_summary":{"summary":{"after_filtering":{"q30_rate":"0.5"},"before_filtering":{"q30_rate":0.99}}}}}`)
	a := AlignmentStats{MappedReads: 50, TotalReads: 1000, Targets: map[string]int{"synthetic_target": 50}}
	got, err := Score(facts, r, p, &a)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"suspicious_filename", "file_size_exceeded", "decryption_failed", "signature_invalid", "critical_pipeline_warnings", "low_quality_reads", "threat_panel_hit"}
	if got.Score != 1 || got.Verdict != "high" || got.Reason != want[0] || !reflect.DeepEqual(got.Reasons, want) {
		t.Fatalf("scoring mismatch: %#v", got)
	}
	if got.Signals.Warnings != (WarningSummary{1, 1, 1}) || got.Signals.Pipeline != (PipelineMetrics{1000, 101}) || got.Signals.Fastp.Q30Rate != .5 || got.Signals.Alignment.Fraction != .05 {
		t.Fatal("metrics changed")
	}
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{facts.OriginalName, facts.DecryptionError, facts.SignatureError, r.ThreatPanelFasta} {
		if strings.Contains(string(b), private) {
			t.Fatal("context text escaped into result")
		}
	}
	a.Targets["synthetic_target"] = 1
	if got.Signals.Alignment.Targets["synthetic_target"] != 50 {
		t.Fatal("result aliases source map")
	}
}

func TestLegacyThresholdsAndFallbacks(t *testing.T) {
	for _, tc := range []struct {
		name    string
		score   float64
		verdict string
	}{{"low", .1, "low"}, {"medium", .5, "medium"}, {"high", .8, "high"}, {"clamp_high", 2, "high"}, {"clamp_low", -.5, "low"}} {
		t.Run(tc.name, func(t *testing.T) {
			r := DefaultRules()
			r.LowScore = tc.score
			r.HighScore = .001
			got, err := Score(Context{}, r, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			expected := math.Max(0, math.Min(1, tc.score))
			if got.Score != expected || got.Verdict != tc.verdict || got.Reason != "no suspicious indicators" {
				t.Fatal("threshold or unused HighScore changed")
			}
		})
	}
	r := DefaultRules()
	r.ThreatPanelFasta = "trusted"
	a := AlignmentStats{MappedReads: 50, TotalReads: 100, Targets: map[string]int{"target": 50}}
	fallback, err := Score(Context{}, r, json.RawMessage(`{}`), &a)
	if err != nil || len(fallback.Reasons) != 1 || fallback.Reasons[0] != "threat_panel_hit" {
		t.Fatal("alignment denominator fallback changed")
	}
	blocked, err := Score(Context{}, r, json.RawMessage(`{"read_count":10000}`), &a)
	if err != nil || len(blocked.Reasons) != 0 {
		t.Fatal("pipeline denominator lost priority")
	}
	zeroQ := json.RawMessage(`{"outputs":{"fastp_summary":{"summary":{"after_filtering":{"q30_rate":0},"before_filtering":{"q30_rate":0.1}}}}}`)
	got, err := Score(Context{}, DefaultRules(), zeroQ, nil)
	if err != nil || got.Signals.Fastp == nil || got.Signals.Fastp.Q30Rate != 0 || len(got.Reasons) != 0 {
		t.Fatal("zero/after-filtering Q30 semantics changed")
	}
	before := json.RawMessage(`{"outputs":{"fastp_summary":{"summary":{"before_filtering":{"q30_rate":0.4}}}}}`)
	got, err = Score(Context{}, DefaultRules(), before, nil)
	if err != nil || got.Signals.Fastp.Q30Rate != .4 || got.Reasons[0] != "low_quality_reads" {
		t.Fatal("before-filtering fallback changed")
	}
}

func TestDefaultRulesAndStrictFailure(t *testing.T) {
	if !reflect.DeepEqual(ApplyRuleDefaults(Rules{}), DefaultRules()) {
		t.Fatal("defaults changed")
	}
	root := t.TempDir()
	path := filepath.Join(root, "rules.json")
	r, w := LoadRules(path)
	if w != "rules_read_error" || !reflect.DeepEqual(r, DefaultRules()) {
		t.Fatal("legacy read fallback changed")
	}
	if _, err := LoadRulesStrict(path); err != Code("rules_read_error") {
		t.Fatal("strict missing rules accepted")
	}
	for _, raw := range []string{"{", `{"low_score":true}`, `{"low_score":0.1,"low_score":0.9}`, `{"LowScore":0.2}`, `{"low_score":null}`, `null`, strings.Repeat(" ", MaxJSONBytes+1)} {
		if os.WriteFile(path, []byte(raw), 0600) != nil {
			t.Fatal("fixture write")
		}
		if _, err := LoadRulesStrict(path); err == nil {
			t.Fatal("invalid rules accepted")
		}
	}
	if err := os.WriteFile(path, []byte(`{"max_size_bytes":123,"suspicious_name_patterns":["bad"],"low_score":0}`), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := LoadRulesStrict(path)
	if err != nil || r.LowScore != .1 || r.MaxSizeBytes != 123 || r.SuspiciousNameTokens[0] != "bad" {
		t.Fatal("valid defaults changed")
	}
}

func TestInvalidMetricsNeverRunAlignment(t *testing.T) {
	r := DefaultRules()
	r.ThreatPanelFasta = "/nonexistent-panel"
	for _, q := range []string{"NaN", "+Inf", "-Inf"} {
		p := json.RawMessage(`{"outputs":{"fastp_summary":{"summary":{"after_filtering":{"q30_rate":"` + q + `"}}}}}`)
		if _, err := Evaluate(context.Background(), Context{}, r, p, "/nonexistent-content"); err != Code("pipeline_metric_invalid") {
			t.Fatal("invalid metric reached alignment", err)
		}
	}
	if _, err := Evaluate(context.Background(), Context{ProcessedSizeBytes: -1}, r, nil, ""); err != Code("analysis_context_invalid") {
		t.Fatal("invalid context reached alignment")
	}
	r.LowScore = math.NaN()
	if _, err := Score(Context{}, r, nil, nil); err == nil {
		t.Fatal("nonfinite rules accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Evaluate(ctx, Context{}, DefaultRules(), nil, ""); err != Code("analysis_canceled") {
		t.Fatal("cancellation lost")
	}
}
