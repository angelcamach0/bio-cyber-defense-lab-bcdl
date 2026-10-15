// SPDX-License-Identifier: AGPL-3.0-only
package analysis

import (
	"context"
	"encoding/json"
	"math"
	"strconv"
	"strings"
)

// Code is deliberately safe to return across the capsule boundary.
type Code string

func (c Code) Error() string { return string(c) }

type pipelineInfo struct {
	ReadCount     int
	AvgReadLength int
	Warnings      []string
	FastpQ30      float64
	HasFastp      bool
}

// Evaluate uses the established processed content solely for optional alignment.
// It does not authenticate Context. The host's protected crypto barrier must do so.
func Evaluate(ctx context.Context, facts Context, rules Rules, pipeline json.RawMessage, privateFASTQPath string) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, Code("analysis_canceled")
	}
	if err := validateContext(facts); err != nil {
		return Result{}, err
	}
	if !finiteRules(rules) {
		return Result{}, Code("analysis_context_invalid")
	}
	if _, err := parsePipelineInfo(pipeline); err != nil {
		return Result{}, err
	}
	var alignment *AlignmentStats
	if rules.ThreatPanelFasta != "" {
		stats, err := (Supervisor{}).Align(ctx, rules.ThreatPanelFasta, privateFASTQPath)
		if err != nil {
			return Result{}, err
		}
		alignment = &stats
	}
	result, err := Score(facts, rules, pipeline, alignment)
	if ctx.Err() != nil {
		return Result{}, Code("analysis_canceled")
	}
	return result, err
}

// Score is the deterministic part of Evaluate. A supplied alignment is trusted
// completed data, not evidence of process completion or of scientific release.
func Score(facts Context, rules Rules, pipeline json.RawMessage, alignment *AlignmentStats) (Result, error) {
	if validateContext(facts) != nil || !finiteRules(rules) {
		return Result{}, Code("analysis_context_invalid")
	}
	rules = ApplyRuleDefaults(rules)
	info, err := parsePipelineInfo(pipeline)
	if err != nil {
		return Result{}, err
	}
	warnings := classifyWarnings(info.Warnings)
	signals := Signals{Warnings: warnings, Integrity: Integrity{SignatureValid: facts.SignatureValid, Decrypted: facts.Decrypted}, Pipeline: PipelineMetrics{ReadCount: info.ReadCount, AvgReadLength: info.AvgReadLength}}
	if info.HasFastp {
		signals.Fastp = &FastpMetrics{Q30Rate: info.FastpQ30}
	}
	var a AlignmentStats
	if rules.ThreatPanelFasta != "" {
		if alignment == nil || !validAlignment(*alignment) {
			return Result{}, Code("alignment_invalid")
		}
		a = *alignment
		a.Targets = make(map[string]int, len(alignment.Targets))
		for k, v := range alignment.Targets {
			a.Targets[k] = v
		}
		if a.TotalReads > 0 {
			a.Fraction = float64(a.MappedReads) / float64(a.TotalReads)
		}
		signals.Alignment = &a
	}
	score := rules.LowScore
	reasons := []string{}
	lowerName := strings.ToLower(facts.OriginalName)
	for _, token := range rules.SuspiciousNameTokens {
		if token != "" && strings.Contains(lowerName, strings.ToLower(token)) {
			score += .2
			reasons = append(reasons, "suspicious_filename")
			break
		}
	}
	if rules.MaxSizeBytes > 0 && facts.ProcessedSizeBytes > rules.MaxSizeBytes {
		score += .2
		reasons = append(reasons, "file_size_exceeded")
	}
	if facts.DecryptionError != "" && !facts.Decrypted {
		score += .1
		reasons = append(reasons, "decryption_failed")
	}
	if facts.SignatureError != "" && !facts.SignatureValid {
		score += .2
		reasons = append(reasons, "signature_invalid")
	}
	if warnings.Critical > 0 {
		score += rules.CriticalWarningScoreBoost
		reasons = append(reasons, "critical_pipeline_warnings")
	}
	if info.HasFastp && rules.FastpMinQ30 > 0 && info.FastpQ30 > 0 && info.FastpQ30 < rules.FastpMinQ30 {
		score += .1
		reasons = append(reasons, "low_quality_reads")
	}
	totalReads := info.ReadCount
	if totalReads == 0 {
		totalReads = a.TotalReads
	}
	if rules.ThreatMinReads > 0 && totalReads > 0 && a.MappedReads >= rules.ThreatMinReads && float64(a.MappedReads)/float64(totalReads) >= rules.ThreatMinFraction {
		score += .6
		reasons = append(reasons, "threat_panel_hit")
	}
	if score > 1 {
		score = 1
	}
	if score < 0 {
		score = 0
	}
	verdict := "low"
	if score >= rules.HighThreshold {
		verdict = "high"
	} else if score >= rules.MediumThreshold {
		verdict = "medium"
	}
	reason := "no suspicious indicators"
	if len(reasons) > 0 {
		reason = reasons[0]
	}
	return Result{Score: score, Reason: reason, Verdict: verdict, Reasons: reasons, Signals: signals}, nil
}

func parsePipelineInfo(raw json.RawMessage) (pipelineInfo, error) {
	info := pipelineInfo{}
	if len(raw) > 1<<20 {
		return info, Code("pipeline_output_limit")
	}
	if len(raw) == 0 {
		return info, nil
	}
	var p map[string]any
	// Legacy best-effort behavior: malformed pipeline JSON supplies no metrics.
	if json.Unmarshal(raw, &p) != nil {
		return info, nil
	}
	info.ReadCount = toInt(p["read_count"])
	info.AvgReadLength = toInt(p["avg_read_length"])
	if values, ok := p["warnings"].([]any); ok {
		for _, v := range values {
			if s, ok := v.(string); ok {
				info.Warnings = append(info.Warnings, s)
			}
		}
	}
	outputs, _ := p["outputs"].(map[string]any)
	fastp, _ := outputs["fastp_summary"].(map[string]any)
	summary, _ := fastp["summary"].(map[string]any)
	for _, key := range []string{"after_filtering", "before_filtering"} {
		part, _ := summary[key].(map[string]any)
		if q, ok := toFloat(part["q30_rate"]); ok {
			if math.IsNaN(q) || math.IsInf(q, 0) {
				return pipelineInfo{}, Code("pipeline_metric_invalid")
			}
			info.FastpQ30 = q
			info.HasFastp = true
			break
		}
	}
	return info, nil
}

func classifyWarnings(warnings []string) WarningSummary {
	var s WarningSummary
	for _, w := range warnings {
		w = strings.ToLower(w)
		switch {
		case strings.Contains(w, "error"), strings.Contains(w, "failed"), strings.Contains(w, "fatal"):
			s.Critical++
		case strings.Contains(w, "warn"):
			s.Warn++
		default:
			s.Info++
		}
	}
	return s
}

func toInt(value any) int {
	switch v := value.(type) {
	case float64:
		return int(v)
	case int:
		return v
	case int64:
		return int(v)
	case string:
		n, err := strconv.Atoi(v)
		if err == nil {
			return n
		}
	}
	return 0
}
func toFloat(value any) (float64, bool) {
	switch v := value.(type) {
	case float64:
		return v, true
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case string:
		n, err := strconv.ParseFloat(v, 64)
		if err == nil {
			return n, true
		}
	}
	return 0, false
}
