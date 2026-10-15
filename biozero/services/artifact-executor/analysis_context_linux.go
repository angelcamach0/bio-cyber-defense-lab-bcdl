//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package artifactexecutor

import "unicode/utf8"

// AnalysisContext contains facts supplied by the trusted protected-entry
// verifier. It grants no cryptographic or scientific authority by itself and
// cannot choose executable paths, rules or reference assets.
type AnalysisContext struct {
	OriginalName       string `json:"original_name"`
	ProcessedSizeBytes int64  `json:"processed_size_bytes"`
	Decrypted          bool   `json:"decrypted"`
	DecryptionError    string `json:"decryption_error"`
	SignatureValid     bool   `json:"signature_valid"`
	SignatureError     string `json:"signature_error"`
}

func validateAnalysisContext(c AnalysisContext, processedBytes int64) error {
	if processedBytes < 0 || processedBytes > MaxInputBytes || c.ProcessedSizeBytes != processedBytes ||
		len(c.OriginalName) > 4096 || !utf8.ValidString(c.OriginalName) ||
		len(c.DecryptionError) > 128 || !utf8.ValidString(c.DecryptionError) ||
		len(c.SignatureError) > 128 || !utf8.ValidString(c.SignatureError) ||
		(c.Decrypted && c.DecryptionError != "") || (c.SignatureValid && c.SignatureError != "") {
		return fail("artifact_analysis_context_invalid")
	}
	return nil
}
