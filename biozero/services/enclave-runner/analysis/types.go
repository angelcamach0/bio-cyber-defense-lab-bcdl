// SPDX-License-Identifier: AGPL-3.0-only
// Package analysis extracts the worker's detection scoring. It neither verifies
// cryptography nor grants scientific release; callers supply established facts.
package analysis

import "encoding/json"

type Rules struct {
	MaxSizeBytes              int64    `json:"max_size_bytes"`
	SuspiciousNameTokens      []string `json:"suspicious_name_patterns"`
	HighScore                 float64  `json:"high_score"`
	LowScore                  float64  `json:"low_score"`
	ThreatPanelFasta          string   `json:"threat_panel_fasta,omitempty"`
	ThreatMinReads            int      `json:"threat_min_reads,omitempty"`
	ThreatMinFraction         float64  `json:"threat_min_fraction,omitempty"`
	FastpMinQ30               float64  `json:"fastp_min_q30,omitempty"`
	CriticalWarningScoreBoost float64  `json:"critical_warning_score_boost,omitempty"`
	HighThreshold             float64  `json:"high_threshold,omitempty"`
	MediumThreshold           float64  `json:"medium_threshold,omitempty"`
}

type Context struct {
	OriginalName       string `json:"original_name"`
	ProcessedSizeBytes int64  `json:"processed_size_bytes"`
	Decrypted          bool   `json:"decrypted"`
	DecryptionError    string `json:"decryption_error"`
	SignatureValid     bool   `json:"signature_valid"`
	SignatureError     string `json:"signature_error"`
}

type Result struct {
	Score   float64  `json:"score"`
	Reason  string   `json:"reason"`
	Verdict string   `json:"verdict,omitempty"`
	Reasons []string `json:"reasons,omitempty"`
	Signals Signals  `json:"signals"`
}

type Signals struct {
	Warnings  WarningSummary  `json:"warnings"`
	Integrity Integrity       `json:"integrity"`
	Pipeline  PipelineMetrics `json:"pipeline"`
	Fastp     *FastpMetrics   `json:"fastp,omitempty"`
	Alignment *AlignmentStats `json:"alignment,omitempty"`
}
type Integrity struct {
	SignatureValid bool `json:"signature_valid"`
	Decrypted      bool `json:"decrypted"`
}
type PipelineMetrics struct {
	ReadCount     int `json:"read_count"`
	AvgReadLength int `json:"avg_read_length"`
}
type FastpMetrics struct {
	Q30Rate float64 `json:"q30_rate"`
}
type WarningSummary struct {
	Critical int `json:"critical"`
	Warn     int `json:"warn"`
	Info     int `json:"info"`
}
type AlignmentStats struct {
	MappedReads int            `json:"mapped_reads"`
	TotalReads  int            `json:"total_reads"`
	Fraction    float64        `json:"fraction"`
	Targets     map[string]int `json:"targets,omitempty"`
}

// Request is a local capsule boundary, not an RPC or source of executable paths.
type Request struct {
	SchemaVersion int             `json:"schema_version"`
	Context       Context         `json:"context"`
	Pipeline      json.RawMessage `json:"pipeline"`
}
type Response struct {
	SchemaVersion int      `json:"schema_version"`
	Status        string   `json:"status"`
	ErrorCode     string   `json:"error_code"`
	Warnings      []string `json:"warnings"`
	Detection     *Result  `json:"detection"`
}
