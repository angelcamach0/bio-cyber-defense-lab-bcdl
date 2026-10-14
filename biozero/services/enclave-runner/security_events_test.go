// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func rejectionFixture() resultRecord {
	return resultRecord{SchemaVersion: 1, SecurityMode: "protected", Status: "rejected", JobID: "abcd1234",
		ErrorCode: "signature_required", ProcessedAt: "2026-10-14T12:00:00Z", ErrorMessage: "PRIVATE free error",
		PipelineError: "PRIVATE path /private/raw.fastq", ClientCertSerial: "PRIVATE certificate",
		ScientificEvaluation: json.RawMessage(`{"private":"PRIVATE genome"}`)}
}

func eventFiles(t *testing.T, directory string) []os.DirEntry {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	return entries
}

func privateSpool(t *testing.T) string {
	t.Helper()
	path := t.TempDir()
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSecurityEventContractAllAllowlistedRejections(t *testing.T) {
	for _, code := range []string{"upload_integrity_failed", "signature_required", "signature_algorithm_invalid", "signature_invalid",
		"encryption_required", "encryption_metadata_invalid", "key_unwrap_failed", "decryption_failed"} {
		t.Run(code, func(t *testing.T) {
			result := rejectionFixture()
			result.ErrorCode = code
			event, applicable, err := protectedRejectionEvent(result)
			if err != nil || !applicable {
				t.Fatalf("event eligibility: %v %v", applicable, err)
			}
			expected := sha256.Sum256([]byte("enclave-runner/abcd1234/" + code))
			if event.AlertID != "evt-"+hex.EncodeToString(expected[:]) || event.Timestamp != result.ProcessedAt || event.SchemaVersion != 1 ||
				event.Source != "enclave-runner" || event.EventCode != code || event.Severity != "high" ||
				event.Indicators.JobID != result.JobID || len(event.Actions) != 1 || event.Actions[0] != "quarantine" {
				t.Fatalf("wrong contract: %+v", event)
			}
			encoded, _ := json.Marshal(event)
			if strings.Contains(string(encoded), "PRIVATE") || strings.Contains(string(encoded), "/private/") {
				t.Fatal("private source metadata leaked")
			}
		})
	}
}

func TestSecurityEventExcludesSuccessDemoLegacyAndUnlistedErrors(t *testing.T) {
	for _, mutate := range []func(*resultRecord){func(r *resultRecord) { r.Status = "succeeded" },
		func(r *resultRecord) { r.Status = "failed" }, func(r *resultRecord) { r.Status = "processed" },
		func(r *resultRecord) { r.SecurityMode = "demo" }, func(r *resultRecord) { r.SecurityMode = "" },
		func(r *resultRecord) { r.SchemaVersion = 0 }, func(r *resultRecord) { r.ErrorCode = "pipeline_json_invalid" }} {
		result := rejectionFixture()
		mutate(&result)
		if _, applicable, err := protectedRejectionEvent(result); err != nil || applicable {
			t.Fatalf("unexpected event for %+v: %v", result, err)
		}
	}
	for _, mutate := range []func(*resultRecord){func(r *resultRecord) { r.JobID = "../private" },
		func(r *resultRecord) { r.ProcessedAt = "PRIVATE timestamp" },
		func(r *resultRecord) { r.ProcessedAt = "2026-10-14T12:00:00.1Z" },
		func(r *resultRecord) { r.ProcessedAt = "2026-10-14T12:00:00+00:00" },
		func(r *resultRecord) { r.ProcessedAt = "2026-10-14T13:00:00+01:00" }} {
		result := rejectionFixture()
		mutate(&result)
		if _, _, err := protectedRejectionEvent(result); err == nil || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatal("invalid event metadata accepted or reflected in error")
		}
	}
}

func TestSecurityEventPublicationPrivateAtomicAndIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "outbox")
	t.Setenv("BIOZERO_SECURITY_EVENTS_DIR", path)
	result := rejectionFixture()
	if err := emitPersistedSecurityEvent(result); err != nil {
		t.Fatal(err)
	}
	event, _, _ := protectedRejectionEvent(result)
	target := filepath.Join(path, event.AlertID+".json")
	before, _ := os.Stat(target)
	dirInfo, _ := os.Stat(path)
	if before.Mode().Perm() != 0600 || dirInfo.Mode().Perm() != 0700 {
		t.Fatal("outbox permissions")
	}
	if err := emitPersistedSecurityEvent(result); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(target)
	if !os.SameFile(before, after) || len(eventFiles(t, path)) != 1 {
		t.Fatal("duplicate event or existing file overwritten")
	}
	data, _ := os.ReadFile(target)
	if !exactSecurityEvent(data, event) || bytes.Contains(data, []byte("PRIVATE")) {
		t.Fatal("wrong event or private fields")
	}
}

func TestSecurityEventExistingConflictNeverOverwritten(t *testing.T) {
	for name, transform := range map[string]func([]byte) []byte{
		"changed_timestamp": func(data []byte) []byte { return bytes.ReplaceAll(data, []byte("12:00:00Z"), []byte("13:00:00Z")) },
		"extra_field":       func(data []byte) []byte { return append([]byte(`{"private":"SECRET",`), data[1:]...) },
		"duplicate_key":     func(data []byte) []byte { return append([]byte(`{"severity":"high",`), data[1:]...) },
		"nested_duplicate": func(data []byte) []byte {
			return bytes.Replace(data, []byte(`"job_id": "abcd1234"`), []byte(`"job_id": "abcd1234", "job_id": "abcd1234"`), 1)
		},
		"trailing_document": func(data []byte) []byte { return append(data, []byte(` {}`)...) },
		"over_limit":        func(unused []byte) []byte { return bytes.Repeat([]byte(" "), maxSecurityEventBytes+1) },
	} {
		t.Run(name, func(t *testing.T) {
			path := privateSpool(t)
			t.Setenv("BIOZERO_SECURITY_EVENTS_DIR", path)
			result := rejectionFixture()
			event, _, _ := protectedRejectionEvent(result)
			encoded, _ := json.MarshalIndent(event, "", "  ")
			conflicting := transform(encoded)
			target := filepath.Join(path, event.AlertID+".json")
			if err := os.WriteFile(target, conflicting, 0600); err != nil {
				t.Fatal(err)
			}
			if err := emitPersistedSecurityEvent(result); err == nil || (err.Error() != "event_existing_conflict" && err.Error() != "event_existing_unsafe") {
				t.Fatal("conflict acknowledged")
			}
			after, _ := os.ReadFile(target)
			if !bytes.Equal(after, conflicting) || len(eventFiles(t, path)) != 1 {
				t.Fatal("conflict overwritten or temporary leaked")
			}
		})
	}
}

func TestConcurrentSecurityEventPublicationDoesNotClobber(t *testing.T) {
	path := privateSpool(t)
	t.Setenv("BIOZERO_SECURITY_EVENTS_DIR", path)
	first := rejectionFixture()
	second := first
	second.ProcessedAt = "2026-10-14T13:00:00Z"
	start := make(chan struct{})
	errors := make(chan error, 2)
	var wait sync.WaitGroup
	for _, result := range []resultRecord{first, second} {
		wait.Add(1)
		go func(result resultRecord) {
			defer wait.Done()
			<-start
			errors <- emitPersistedSecurityEvent(result)
		}(result)
	}
	close(start)
	wait.Wait()
	close(errors)
	successes, conflicts := 0, 0
	for err := range errors {
		if err == nil {
			successes++
		} else if err.Error() == "event_existing_conflict" {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if successes != 1 || conflicts != 1 || len(eventFiles(t, path)) != 1 {
		t.Fatalf("concurrent publication: success=%d conflicts=%d", successes, conflicts)
	}
	event, _, _ := protectedRejectionEvent(first)
	data, _ := os.ReadFile(filepath.Join(path, event.AlertID+".json"))
	other, _, _ := protectedRejectionEvent(second)
	if !exactSecurityEvent(data, event) && !exactSecurityEvent(data, other) {
		t.Fatal("torn or changed concurrent event")
	}
}

func TestSecurityEventExistingUnsafeFilesAndDirectoryRejected(t *testing.T) {
	for _, kind := range []string{"symlink", "fifo", "permissions"} {
		t.Run(kind, func(t *testing.T) {
			path := privateSpool(t)
			t.Setenv("BIOZERO_SECURITY_EVENTS_DIR", path)
			result := rejectionFixture()
			event, _, _ := protectedRejectionEvent(result)
			target := filepath.Join(path, event.AlertID+".json")
			switch kind {
			case "symlink":
				secret := filepath.Join(t.TempDir(), "PRIVATE-target")
				os.WriteFile(secret, []byte("PRIVATE content"), 0600)
				os.Symlink(secret, target)
			case "fifo":
				if err := syscall.Mkfifo(target, 0600); err != nil {
					t.Fatal(err)
				}
			case "permissions":
				encoded, _ := json.Marshal(event)
				os.WriteFile(target, encoded, 0644)
			}
			if err := emitPersistedSecurityEvent(result); err == nil || err.Error() != "event_existing_unsafe" {
				t.Fatal("unsafe existing event accepted")
			}
		})
	}
	path := t.TempDir()
	os.Chmod(path, 0755)
	t.Setenv("BIOZERO_SECURITY_EVENTS_DIR", path)
	if err := emitPersistedSecurityEvent(rejectionFixture()); err == nil {
		t.Fatal("nonprivate outbox accepted")
	}
	link := filepath.Join(t.TempDir(), "alias")
	os.Symlink(t.TempDir(), link)
	t.Setenv("BIOZERO_SECURITY_EVENTS_DIR", filepath.Join(link, "outbox"))
	if err := emitPersistedSecurityEvent(rejectionFixture()); err == nil {
		t.Fatal("ancestor symlink accepted")
	}
}

func TestProtectedRejectionSpoolsOnlyAfterResultPersistence(t *testing.T) {
	t.Setenv("BIOZERO_SECURITY_MODE", "protected")
	f := newTestJob(t, `{}`, 0)
	spool := filepath.Join(f.root, "outbox")
	t.Setenv("BIOZERO_SECURITY_EVENTS_DIR", spool)
	result := f.run(t, time.Second)
	if result.Status != "rejected" || result.ErrorCode != "signature_required" {
		t.Fatalf("unexpected rejection: %+v", result)
	}
	entries := eventFiles(t, spool)
	if len(entries) != 1 {
		t.Fatal("rejection did not publish one event")
	}
	data, _ := os.ReadFile(filepath.Join(spool, entries[0].Name()))
	event, _, _ := protectedRejectionEvent(result)
	if !exactSecurityEvent(data, event) {
		t.Fatal("event mismatched persisted result")
	}
	if _, err := os.Stat(filepath.Join(f.root, "called")); !os.IsNotExist(err) {
		t.Fatal("pipeline called for rejection")
	}
	// A failure to persist the result cannot publish an unverifiable event.
	second := newTestJob(t, `{}`, 0)
	secondSpool := filepath.Join(second.root, "outbox")
	t.Setenv("BIOZERO_SECURITY_EVENTS_DIR", secondSpool)
	writeJSON(filepath.Join(second.jobs, second.job.JobID+".json"), second.job)
	if err := os.Remove(second.results); err != nil {
		t.Fatal(err)
	}
	processJobs(second.jobs, second.uploads, second.results, second.decrypted, defaultRules(), "", "", second.pipeline, "", "", time.Second)
	if len(eventFiles(t, secondSpool)) != 0 {
		t.Fatal("event published without persisted result")
	}
	job, err := readJob(filepath.Join(second.jobs, second.job.JobID+".json"))
	if err != nil || job.Status != "running" {
		t.Fatal("test did not reach execution and failed result persistence")
	}
}

func TestProtectedSuccessfulExecutionDoesNotSpoolEvent(t *testing.T) {
	t.Setenv("BIOZERO_SECURITY_MODE", "protected")
	f := newTestJob(t, `{"schema_version":1,"mode":"stats","pipeline_status":"succeeded","stages":[{"name":"validate_fastq","status":"succeeded"},{"name":"fastq_stats","status":"succeeded"}],"outputs":{},"errors":[]}`, 0)
	f.protect(t)
	spool := filepath.Join(f.root, "outbox")
	t.Setenv("BIOZERO_SECURITY_EVENTS_DIR", spool)
	result := f.run(t, time.Second)
	if result.Status != "succeeded" || len(eventFiles(t, spool)) != 0 {
		t.Fatal("protected success emitted rejection event")
	}
	if _, err := os.Stat(filepath.Join(f.root, "called")); err != nil {
		t.Fatal("test did not complete pipeline fixture")
	}
}

func TestSecurityOutboxStorageFailureRecoversTerminalJobWithoutPipeline(t *testing.T) {
	t.Setenv("BIOZERO_SECURITY_MODE", "protected")
	f := newTestJob(t, `{}`, 0)
	blocked := filepath.Join(f.root, "PRIVATE-blocked-path")
	os.WriteFile(blocked, []byte("private"), 0600)
	spool := filepath.Join(blocked, "outbox")
	t.Setenv("BIOZERO_SECURITY_EVENTS_DIR", spool)
	var logs bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(previous) })
	result := f.run(t, time.Second)
	job, _ := readJob(filepath.Join(f.jobs, f.job.JobID+".json"))
	if job.Status != "rejected" || result.Status != "rejected" || !strings.Contains(logs.String(), "security outbox error:") {
		t.Fatal("storage failure must retain terminal result and visible failure")
	}
	if strings.Contains(logs.String(), blocked) || strings.Contains(logs.String(), "private") {
		t.Fatal("outbox log exposed path or data")
	}
	os.Remove(blocked)
	os.Mkdir(blocked, 0700)
	// Simulate a fresh runner cycle, where this job is already terminal.
	processJobs(f.jobs, f.uploads, f.results, f.decrypted, defaultRules(), "", "", f.pipeline, "", "", time.Second)
	entries := eventFiles(t, spool)
	if len(entries) != 1 {
		t.Fatal("terminal rejection not recovered")
	}
	data, _ := os.ReadFile(filepath.Join(spool, entries[0].Name()))
	event, _, _ := protectedRejectionEvent(result)
	if !exactSecurityEvent(data, event) {
		t.Fatal("recovery changed original timestamp/event")
	}
	if _, err := os.Stat(filepath.Join(f.root, "called")); !os.IsNotExist(err) {
		t.Fatal("pipeline re-executed during event recovery")
	}
}

func TestSecurityOutboxRecoveryWithoutJobAndSuccessNoEvent(t *testing.T) {
	root := t.TempDir()
	results := filepath.Join(root, "results")
	os.Mkdir(results, 0700)
	spool := filepath.Join(root, "events")
	t.Setenv("BIOZERO_SECURITY_EVENTS_DIR", spool)
	result := rejectionFixture()
	writeJSON(filepath.Join(results, result.JobID+".json"), result)
	reconcileSecurityEvents(context.Background(), results)
	if len(eventFiles(t, spool)) != 1 {
		t.Fatal("persisted orphan result was not reconciled")
	}
	success := result
	success.JobID, success.Status = "abcdef00", "succeeded"
	writeJSON(filepath.Join(results, success.JobID+".json"), success)
	reconcileSecurityEvents(context.Background(), results)
	if len(eventFiles(t, spool)) != 1 {
		t.Fatal("successful result produced security event")
	}
}

func TestSecurityOutboxOptionalAndCancelled(t *testing.T) {
	t.Setenv("BIOZERO_SECURITY_EVENTS_DIR", "")
	if err := emitPersistedSecurityEvent(rejectionFixture()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "events")
	t.Setenv("BIOZERO_SECURITY_EVENTS_DIR", path)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	reconcileSecurityEvents(ctx, t.TempDir())
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("cancelled reconciliation performed IO")
	}
}

func TestSecurityOutboxRecoveryRejectsUnsafeResultFiles(t *testing.T) {
	for _, kind := range []string{"symlink", "fifo", "mismatched_job_id", "invalid_json"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			results, spool := filepath.Join(root, "results"), filepath.Join(root, "events")
			os.Mkdir(results, 0700)
			t.Setenv("BIOZERO_SECURITY_EVENTS_DIR", spool)
			result := rejectionFixture()
			target := filepath.Join(results, result.JobID+".json")
			switch kind {
			case "symlink":
				outside := filepath.Join(t.TempDir(), "PRIVATE-result")
				writeJSON(outside, result)
				os.Symlink(outside, target)
			case "fifo":
				if err := syscall.Mkfifo(target, 0600); err != nil {
					t.Fatal(err)
				}
			case "mismatched_job_id":
				result.JobID = "abcdef99"
				writeJSON(target, result)
			case "invalid_json":
				os.WriteFile(target, []byte(`{"PRIVATE":`), 0600)
			}
			var output bytes.Buffer
			previous := log.Writer()
			log.SetOutput(&output)
			t.Cleanup(func() { log.SetOutput(previous) })
			reconcileSecurityEvents(context.Background(), results)
			if len(eventFiles(t, spool)) != 0 || !strings.Contains(output.String(), "security outbox error:") || strings.Contains(output.String(), "PRIVATE") {
				t.Fatal("unsafe result emitted event or leaked metadata")
			}
		})
	}
}
