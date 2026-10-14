// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"encoding/json"
	"strings"
	"unicode/utf8"
)

const maxJobErrorCodeBytes = 64
const maxJobErrorMessageBytes = 512

// Limit only the job's diagnostic copy; the result retains its full diagnostics.
// Normalize invalid UTF-8, then stop at a rune boundary within decoded byte cap.
func jobDiagnostic(value string, maximum int) string {
	value = strings.ToValidUTF8(value, "\uFFFD")
	if len(value) <= maximum {
		return value
	}
	cut := maximum
	for cut > 0 && !utf8.RuneStart(value[cut]) {
		cut--
	}
	return value[:cut]
}

// Every worker job write uses this boundary. Immutable upload, signature, size,
// certificate and encryption metadata are copied verbatim. Legacy records without
// admission reserve fail closed if the next state cannot fit; never overwrite
// them with an unreadable JSON record or silently truncate submitted metadata.
func writeJobRecord(path string, job jobRecord) error {
	job.ErrorCode = jobDiagnostic(job.ErrorCode, maxJobErrorCodeBytes)
	job.ErrorMessage = jobDiagnostic(job.ErrorMessage, maxJobErrorMessageBytes)
	data, err := json.MarshalIndent(job, "", "  ")
	if err != nil {
		return metadataError("metadata_job_encode_failed")
	}
	if len(data) > maxJobMetadataBytes {
		return metadataError("metadata_job_lifecycle_size_exceeded")
	}
	return writeJSONBytes(path, data)
}
