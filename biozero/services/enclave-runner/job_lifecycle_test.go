// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func projectedBoundaryJob(t *testing.T, job jobRecord) jobRecord {
	t.Helper()
	job.Sig = "x"
	worst := job
	worst.Status, worst.StartedAt = "incomplete", "2000-01-01T00:00:00Z"
	worst.ErrorCode = strings.Repeat("\x00", maxJobErrorCodeBytes)
	worst.ErrorMessage = strings.Repeat("\x00", maxJobErrorMessageBytes)
	data, err := json.MarshalIndent(worst, "", "  ")
	if err != nil || len(data) >= maxJobMetadataBytes {
		t.Fatal("boundary fixture cannot fit", err)
	}
	job.Sig += strings.Repeat("x", maxJobMetadataBytes-len(data))
	return job
}

func withoutJobMutableFields(job jobRecord) jobRecord {
	job.Status, job.StartedAt, job.ErrorCode, job.ErrorMessage = "", "", "", ""
	return job
}

func TestJobLifecycleBoundaryFitsAllStatesAndPreservesImmutableFields(t *testing.T) {
	f := newTestJob(t, `{}`, 0)
	job := projectedBoundaryJob(t, f.job)
	job.EncAlg, job.EncKey = "", "" // Immutable fields remain whatever was admitted.
	path := filepath.Join(f.jobs, job.JobID+".json")
	for _, state := range []string{"uploaded", "running", "succeeded", "incomplete", "rejected", "failed", "timed_out", "processed"} {
		candidate := job
		candidate.Status, candidate.StartedAt = state, "2000-01-01T00:00:00Z"
		candidate.ErrorCode, candidate.ErrorMessage = strings.Repeat("\x00", 64), strings.Repeat("\x00", 512)
		if err := writeJobRecord(path, candidate); err != nil {
			t.Fatal("admitted boundary failed lifecycle", state, err)
		}
		data, err := os.ReadFile(path)
		if err != nil || len(data) > maxJobMetadataBytes || (state == "incomplete" && len(data) != maxJobMetadataBytes) {
			t.Fatal("wrong serialized lifecycle boundary", state, len(data), err)
		}
		stored, err := readJobContext(context.Background(), path)
		if err != nil || withoutJobMutableFields(stored) != withoutJobMutableFields(job) || len(stored.ErrorCode) != 64 || len(stored.ErrorMessage) != 512 {
			t.Fatal("immutable field changed or lifecycle unreadable", state, err)
		}
	}
}

func TestJobDiagnosticsDecodedByteLimitsAreUTF8Safe(t *testing.T) {
	for _, maximum := range []int{64, 512} {
		for _, text := range []string{strings.Repeat("é", 600), strings.Repeat("🌱", 600), strings.Repeat("<\x00\n", 600),
			strings.Repeat("x", maximum-1) + "🌱suffix", strings.Repeat("\xff", 600)} {
			got := jobDiagnostic(text, maximum)
			if len(got) > maximum || !utf8.ValidString(got) {
				t.Fatal("diagnostic cap split a rune or exceeded bytes")
			}
		}
	}
}

func TestOversizedLegacyJobWriteDoesNotOverwriteOrTruncateSignature(t *testing.T) {
	f := newTestJob(t, `{}`, 0)
	job := f.job
	job.Sig = "x"
	base, _ := json.MarshalIndent(job, "", "  ")
	job.Sig += strings.Repeat("x", maxJobMetadataBytes-len(base))
	path := filepath.Join(f.jobs, job.JobID+".json")
	if err := writeJSON(path, job); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	job.Status, job.StartedAt = "running", "2000-01-01T00:00:00Z"
	if err := writeJobRecord(path, job); err == nil || err.Error() != "metadata_job_lifecycle_size_exceeded" {
		t.Fatal("oversized lifecycle write accepted", err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("unreserved legacy job overwritten or signature truncated")
	}
}

func TestLifecycleRecoveryCapsOnlyJobCopyAndRetainsFullResult(t *testing.T) {
	f := newTestJob(t, `{}`, 0)
	job := projectedBoundaryJob(t, f.job)
	path := filepath.Join(f.jobs, job.JobID+".json")
	writeJSON(path, job)
	result := resultRecord{SchemaVersion: 1, JobID: job.JobID, Status: "failed", SecurityMode: "protected",
		ErrorCode: strings.Repeat("é", 500), ErrorMessage: strings.Repeat("🌱\x00<", 1000)}
	resultPath := filepath.Join(f.results, job.JobID+".json")
	writeJSON(resultPath, result)
	before, _ := os.ReadFile(resultPath)
	processJobs(f.jobs, f.uploads, f.results, f.decrypted, defaultRules(), "", "", f.pipeline, "", "", time.Second)
	stored, err := readJobContext(context.Background(), path)
	if err != nil || stored.Status != "failed" || !utf8.ValidString(stored.ErrorCode) || len(stored.ErrorCode) > 64 ||
		!utf8.ValidString(stored.ErrorMessage) || len(stored.ErrorMessage) > 512 || withoutJobMutableFields(stored) != withoutJobMutableFields(job) {
		t.Fatal("recovery diagnostic/immutable contract violated", err)
	}
	after, _ := os.ReadFile(resultPath)
	if !bytes.Equal(before, after) {
		t.Fatal("full private result rewritten by job diagnostic cap")
	}
	if _, err := os.Stat(filepath.Join(f.root, "called")); !os.IsNotExist(err) {
		t.Fatal("recovery re-executed pipeline")
	}
}

func TestLifecycleRunningAndTerminalUseGuardWithoutChangingUpload(t *testing.T) {
	t.Setenv("BIOZERO_SECURITY_MODE", "protected")
	f := newTestJob(t, `{}`, 0)
	f.job = projectedBoundaryJob(t, f.job)
	f.job.SigAlg = "rsa-pss-sha256"
	// Adding a previously omitted immutable field requires recalculating reserve.
	f.job = projectedBoundaryJob(t, f.job)
	result := f.run(t, time.Second)
	stored, err := readJobContext(context.Background(), filepath.Join(f.jobs, f.job.JobID+".json"))
	if err != nil || stored.Status != "rejected" || result.ErrorCode != "signature_invalid" || len(stored.StartedAt) != 20 ||
		withoutJobMutableFields(stored) != withoutJobMutableFields(f.job) {
		t.Fatal("running/terminal lifecycle did not remain readable", err)
	}
	if _, err := os.Stat(filepath.Join(f.root, "called")); !os.IsNotExist(err) {
		t.Fatal("protected boundary rejection invoked pipeline")
	}
}
