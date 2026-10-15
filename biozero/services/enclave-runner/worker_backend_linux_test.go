//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	artifact "biozero/artifact-executor"
)

func backendProtectedFixture(t *testing.T) *testJob {
	t.Helper()
	f := newTestJob(t, `{}`, 0)
	old := f.uploadPath()
	f.job.JobID = "0123456789abcdef"
	if err := os.Rename(old, f.uploadPath()); err != nil {
		t.Fatal(err)
	}
	f.protect(t)
	return f
}

func TestWorkerBackendSnapshotCryptoUsesOriginalAndPlaintextSeparately(t *testing.T) {
	f := backendProtectedFixture(t)
	original := f.job
	result := resultRecord{SecurityMode: "protected", PipelineMode: "variants", ReleaseStatus: "withheld"}
	plain, ok := verifyProtectedJobSnapshot(context.Background(), f.job, &result, f.uploads, f.private, f.cert, "")
	if !ok || string(plain) != "@read\nACGT\n+\nIIII\n" || result.ProcessedSHA256 != workerCustodyDigest(plain) || result.SizeBytes != int64(len(plain)) || !result.Decrypted || !result.SignatureValid || result.ProcessedSHA256 == f.job.SHA256 {
		t.Fatal("protected snapshot lost crypto or input provenance", result.ErrorCode)
	}
	clearWorkerBytes(plain)
	if f.job != original {
		t.Fatal("immutable upload metadata changed")
	}
	entries, err := os.ReadDir(f.decrypted)
	if err != nil || len(entries) != 0 {
		t.Fatal("verification persisted plaintext", err)
	}
}

func TestWorkerBackendCryptoRejectsBeforeAnyCustodyOrRPC(t *testing.T) {
	f := backendProtectedFixture(t)
	cases := map[string]func(*jobRecord){
		"unsigned":            func(j *jobRecord) { j.Sig = "" },
		"bad_signature":       func(j *jobRecord) { j.Sig = strings.Repeat("00", 256) },
		"bad_sha":             func(j *jobRecord) { j.SHA256 = strings.Repeat("f", 64) },
		"bad_size":            func(j *jobRecord) { j.SizeBytes++ },
		"plain_metadata":      func(j *jobRecord) { j.EncAlg = ""; j.EncKey = "" },
		"wrong_algorithm":     func(j *jobRecord) { j.EncAlg = "aes-128-gcm" },
		"bad_envelope":        func(j *jobRecord) { j.EncKey = "00" },
		"wrapped_without_key": func(j *jobRecord) { j.EncKeyWrapped = true; j.EncKeyWrapAlg = "aes-256-gcm" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			job := f.job
			mutate(&job)
			c, _ := workerCustodyTestOpen(t)
			calls := 0
			b := &workerCapsuleBackend{custody: c, policy: workerProjectionPolicy{PipelineMode: "variants"}, pending: map[string]WorkerCustodyBinding{}, stages: map[string]*VerifiedPlaintextStage{}, call: func(context.Context, string, artifact.BridgeRequestV2, *os.File) (artifact.BridgeResponse, *os.File, error) {
				calls++
				return artifact.BridgeResponse{}, nil, errors.New("unexpected RPC")
			}}
			result := resultRecord{SecurityMode: "protected", PipelineMode: "variants", ReleaseStatus: "withheld"}
			if !b.process(context.Background(), job, false, &result, f.uploads, f.decrypted, f.private, f.cert, "", time.Second) || result.Status != "rejected" || result.ReleaseStatus != "withheld" || result.ArtifactExecution != nil || calls != 0 {
				t.Fatal("crypto rejection entered capsule custody", result.Status, result.ErrorCode, calls)
			}
			bindings, err := c.Bindings()
			if err != nil || len(bindings) != 0 {
				t.Fatal("crypto rejection consumed custody", err)
			}
		})
	}
}

func TestWorkerBackendSnapshotRejectsSymlinkHardlinkPermissionsAndOversize(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "payload")
	if err := os.WriteFile(file, []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readWorkerSnapshot(context.Background(), file, 7, true); err != nil {
		t.Fatal("exact snapshot failed", err)
	}
	if _, err := readWorkerSnapshot(context.Background(), file, 6, true); err == nil {
		t.Fatal("oversize snapshot accepted")
	}
	symlink := filepath.Join(root, "symlink")
	if err := os.Symlink(file, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readWorkerSnapshot(context.Background(), symlink, 7, true); err == nil {
		t.Fatal("symlink payload accepted")
	}
	hardlink := filepath.Join(root, "hardlink")
	if err := os.Link(file, hardlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readWorkerSnapshot(context.Background(), file, 7, true); err == nil {
		t.Fatal("hardlinked payload accepted")
	}
	if err := os.Remove(hardlink); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readWorkerSnapshot(context.Background(), file, 7, true); err == nil {
		t.Fatal("public-readable payload accepted")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := readWorkerSnapshot(canceled, file, 7, false); err == nil {
		t.Fatal("canceled snapshot accepted")
	}
}

func TestWorkerBackendFingerprintIgnoresOnlyLifecycle(t *testing.T) {
	job := jobRecord{JobID: "0123456789abcdef", SHA256: strings.Repeat("a", 64), OriginalName: "private.fastq", ClientID: "owner-a", Sig: "abc", EncKey: "def", SizeBytes: 12}
	base, _ := workerJobFingerprint(job)
	changed := job
	changed.Status = "failed"
	changed.StartedAt = "later"
	changed.ErrorCode = "failure"
	changed.ErrorMessage = "bounded"
	if got, _ := workerJobFingerprint(changed); got != base {
		t.Fatal("lifecycle changed fingerprint")
	}
	for name, mutate := range map[string]func(*jobRecord){"owner": func(j *jobRecord) { j.ClientID = "owner-b" }, "cert": func(j *jobRecord) { j.ClientCertSerial = "other" }, "signature": func(j *jobRecord) { j.Sig += "x" }, "key": func(j *jobRecord) { j.EncKey += "x" }, "name": func(j *jobRecord) { j.OriginalName += "x" }, "upload_time": func(j *jobRecord) { j.UploadedAt = "other" }, "size": func(j *jobRecord) { j.SizeBytes++ }, "hash": func(j *jobRecord) { j.SHA256 = strings.Repeat("b", 64) }} {
		t.Run(name, func(t *testing.T) {
			changed := job
			mutate(&changed)
			if got, _ := workerJobFingerprint(changed); got == base {
				t.Fatal("immutable fact not bound")
			}
		})
	}
}

func backendReceiptFixture(t *testing.T) (*workerCapsuleBackend, jobRecord, artifact.BridgeResponse, []byte, *[]string) {
	t.Helper()
	receipt, facts := receiptTestFixture("variants", true)
	raw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	response := receiptTestResponse(raw, facts, receipt["outcome"].(map[string]any))
	job := jobRecord{JobID: facts.JobID, Status: "running", SHA256: facts.UploadSHA256, OriginalName: facts.AnalysisContext.OriginalName, ClientID: "owner-a"}
	fingerprint, _ := workerJobFingerprint(job)
	v := WorkerCustodyBinding{JobID: job.JobID, JobFingerprint: fingerprint, UploadSHA256: job.SHA256, ProcessedSHA256: facts.ProcessedSHA256, ProcessedBytes: facts.ProcessedBytes, AnalysisContext: facts.AnalysisContext}
	c, err := NewWorkerCustody(context.Background(), filepath.Join(t.TempDir(), "custody"), facts.ProfileSHA256, "variants")
	if err != nil {
		t.Fatal(err)
	}
	workerCustodyTestOwn(t, c)
	if err := c.PutVerified(context.Background(), v); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "receipt")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	operations := []string{}
	b := &workerCapsuleBackend{socket: "/unused/socket", custody: c, policy: workerProjectionPolicy{SchemaVersion: 1, ProfileSHA256: facts.ProfileSHA256, PipelineMode: "variants", CapsuleKind: "native", SourcePins: facts.ExpectedSourcePins}, pending: map[string]WorkerCustodyBinding{job.JobID: v}, stages: map[string]*VerifiedPlaintextStage{}}
	b.call = func(_ context.Context, _ string, q artifact.BridgeRequestV2, input *os.File) (artifact.BridgeResponse, *os.File, error) {
		operations = append(operations, q.Operation)
		if input != nil || q.Operation == "submit" {
			t.Fatal("recovery submitted input")
		}
		if q.ProcessedSHA256 != "" || q.ProcessedBytes != 0 || q.AnalysisContext != (artifact.AnalysisContext{}) {
			t.Fatal("query replaced verifier facts")
		}
		if q.Operation == "receipt" {
			fd, err := os.Open(path)
			return response, fd, err
		}
		return response, nil, nil
	}
	return b, job, response, raw, &operations
}

func TestWorkerBackendCommittedRecoveryNeverDecryptsOrSubmits(t *testing.T) {
	b, job, _, _, operations := backendReceiptFixture(t)
	for i := 0; i < 2; i++ {
		result := resultRecord{SchemaVersion: 1, SecurityMode: "protected", PipelineMode: "variants", JobID: job.JobID, UploadSHA256: job.SHA256, ReleaseStatus: "withheld"}
		if !b.process(context.Background(), job, true, &result, "/missing/uploads", "/missing/stage", "/missing/key", "/missing/cert", "", time.Second) || result.Status != "succeeded" || result.ReleaseStatus != "evaluated_passed" || result.ArtifactExecution == nil || len(b.pending) != 0 || !result.SignatureValid || !result.Decrypted {
			t.Fatal("committed recovery failed", result.Status, result.ErrorCode)
		}
		if !bytes.Contains(result.ScientificEvaluation, []byte(`"tp":3`)) {
			t.Fatal("science lost during receipt projection")
		}
	}
	if strings.Join(*operations, ",") != "status,receipt,status,receipt" {
		t.Fatal("recovery changed execution", *operations)
	}
}

func TestWorkerBackendUnknownRPCAndChangedFactsNeverResubmit(t *testing.T) {
	for _, kind := range []string{"transport", "generic_handler", "executing", "changed_owner", "changed_upload", "missing_running_facts"} {
		t.Run(kind, func(t *testing.T) {
			b, job, response, _, operations := backendReceiptFixture(t)
			if kind == "changed_owner" {
				job.ClientID = "owner-b"
			}
			if kind == "changed_upload" {
				job.SHA256 = strings.Repeat("f", 64)
			}
			if kind == "missing_running_facts" {
				job.JobID = "fedcba9876543210"
			}
			b.call = func(context.Context, string, artifact.BridgeRequestV2, *os.File) (artifact.BridgeResponse, *os.File, error) {
				*operations = append(*operations, "query")
				switch kind {
				case "transport":
					return artifact.BridgeResponse{}, nil, errors.New("lost ACK")
				case "generic_handler":
					return artifact.BridgeResponse{SchemaVersion: 2, ErrorCode: "artifact_bridge_handler_failed"}, nil, nil
				default:
					response.State = "executing"
					return response, nil, nil
				}
			}
			result := resultRecord{ReleaseStatus: "withheld"}
			if b.process(context.Background(), job, true, &result, "/no-upload", "/no-stage", "/no-key", "/no-cert", "", time.Second) || result.Status != "" || result.ArtifactExecution != nil {
				t.Fatal("uncertain work became terminal or approved")
			}
		})
	}
}

func TestWorkerBackendResultWriteFailureRecoversWithoutTools(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission failure requires an unprivileged test process")
	}
	t.Setenv("BIOZERO_SECURITY_MODE", "protected")
	t.Setenv("BIOZERO_PIPELINE_MODE", "variants")
	b, job, _, _, operations := backendReceiptFixture(t)
	root := t.TempDir()
	jobs := filepath.Join(root, "jobs")
	results := filepath.Join(root, "results")
	if err := os.Mkdir(jobs, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(results, 0700); err != nil {
		t.Fatal(err)
	}
	jobPath := filepath.Join(jobs, job.JobID+".json")
	if err := writeJobRecord(jobPath, job); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(results, 0500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(results, 0700)
	ctx := context.WithValue(context.Background(), workerBackendContextKey{}, b)
	processJobsContext(ctx, jobs, "/missing-upload", results, "/missing-stage", detectionRules{}, "/missing-key", "/missing-cert", "/never-execute", "", "", time.Second)
	stored, err := readJobContext(ctx, jobPath)
	if err != nil || stored.Status != "running" {
		t.Fatal("failed publication lost recoverable job", err)
	}
	if err := os.Chmod(results, 0700); err != nil {
		t.Fatal(err)
	}
	processJobsContext(ctx, jobs, "/missing-upload", results, "/missing-stage", detectionRules{}, "/missing-key", "/missing-cert", "/never-execute", "", "", time.Second)
	result, err := readResultContext(ctx, filepath.Join(results, job.JobID+".json"))
	if err != nil || result.Status != "succeeded" || result.ArtifactExecution == nil {
		t.Fatal("publication recovery failed", err)
	}
	for _, operation := range *operations {
		if operation != "status" && operation != "receipt" {
			t.Fatal("publication retry repeated execution")
		}
	}
}

func TestWorkerBackendPendingAdmissionLeavesNewJobUploaded(t *testing.T) {
	b, _, _, _, _ := backendReceiptFixture(t)
	b.call = func(context.Context, string, artifact.BridgeRequestV2, *os.File) (artifact.BridgeResponse, *os.File, error) {
		return artifact.BridgeResponse{}, nil, errors.New("unknown")
	}
	root := t.TempDir()
	jobs := filepath.Join(root, "jobs")
	results := filepath.Join(root, "results")
	if err := os.Mkdir(jobs, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(results, 0700); err != nil {
		t.Fatal(err)
	}
	job := jobRecord{JobID: "0000000000000000", Status: "uploaded", OriginalName: "waiting.fastq", SHA256: strings.Repeat("e", 64)}
	path := filepath.Join(jobs, job.JobID+".json")
	if err := writeJobRecord(path, job); err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), workerBackendContextKey{}, b)
	processJobsContext(ctx, jobs, "/missing", results, "/missing", detectionRules{}, "", "", "/never-run", "", "", time.Second)
	stored, err := readJobContext(ctx, path)
	if err != nil || stored != job {
		t.Fatal("pending custody admitted an untracked running job", err)
	}
	entries, err := os.ReadDir(results)
	if err != nil || len(entries) != 0 {
		t.Fatal("pending custody fabricated result", err)
	}
}

func TestWorkerBackendUntrackedRunningFencesEarlierNewUpload(t *testing.T) {
	c, _ := workerCustodyTestOpen(t)
	b := &workerCapsuleBackend{custody: c, pending: map[string]WorkerCustodyBinding{}, stages: map[string]*VerifiedPlaintextStage{}}
	root := t.TempDir()
	jobs := filepath.Join(root, "jobs")
	results := filepath.Join(root, "results")
	if err := os.Mkdir(jobs, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(results, 0700); err != nil {
		t.Fatal(err)
	}
	waiting := jobRecord{JobID: "0000000000000000", Status: "uploaded", OriginalName: "waiting.fastq", SHA256: strings.Repeat("e", 64)}
	running := jobRecord{JobID: "ffffffffffffffff", Status: "running", OriginalName: "uncertain.fastq", SHA256: strings.Repeat("f", 64)}
	for _, job := range []jobRecord{waiting, running} {
		if err := writeJobRecord(filepath.Join(jobs, job.JobID+".json"), job); err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.WithValue(context.Background(), workerBackendContextKey{}, b)
	processJobsContext(ctx, jobs, "/missing", results, "/missing", detectionRules{}, "", "", "/never-run", "", "", time.Second)
	stored, err := readJobContext(ctx, filepath.Join(jobs, waiting.JobID+".json"))
	if err != nil || stored != waiting || !b.admissionBlocked {
		t.Fatal("directory order admitted new input before uncertain running job", err)
	}
	entries, err := os.ReadDir(results)
	if err != nil || len(entries) != 0 {
		t.Fatal("uncertain running history fabricated terminal result", err)
	}
}

func TestWorkerBackendAmbiguousMetadataFencesAdmissionButRecoversKnownReceipt(t *testing.T) {
	t.Setenv("BIOZERO_SECURITY_MODE", "protected")
	t.Setenv("BIOZERO_PIPELINE_MODE", "variants")
	for _, kind := range []string{"fifo", "symlink", "corrupt", "identity_mismatch"} {
		t.Run(kind, func(t *testing.T) {
			b, known, _, _, operations := backendReceiptFixture(t)
			root := t.TempDir()
			jobs := filepath.Join(root, "jobs")
			results := filepath.Join(root, "results")
			if err := os.Mkdir(jobs, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(results, 0700); err != nil {
				t.Fatal(err)
			}
			waiting := jobRecord{JobID: "0000000000000000", Status: "uploaded", OriginalName: "waiting.fastq", SHA256: strings.Repeat("e", 64)}
			for _, job := range []jobRecord{waiting, known} {
				if err := writeJobRecord(filepath.Join(jobs, job.JobID+".json"), job); err != nil {
					t.Fatal(err)
				}
			}
			ambiguous := filepath.Join(jobs, "ffffffffffffffff.json")
			switch kind {
			case "fifo":
				if err := syscall.Mkfifo(ambiguous, 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(filepath.Join(root, "missing"), ambiguous); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				if err := os.WriteFile(ambiguous, []byte(`{"status":"running"`), 0600); err != nil {
					t.Fatal(err)
				}
			case "identity_mismatch":
				if err := writeJobRecord(ambiguous, jobRecord{JobID: "eeeeeeeeeeeeeeee", Status: "running"}); err != nil {
					t.Fatal(err)
				}
			}
			ctx := context.WithValue(context.Background(), workerBackendContextKey{}, b)
			processJobsContext(ctx, jobs, "/missing", results, "/missing", detectionRules{}, "", "", "/never-run", "", "", time.Second)
			stored, err := readJobContext(ctx, filepath.Join(jobs, waiting.JobID+".json"))
			if err != nil || stored != waiting || !b.admissionBlocked || b.sticky {
				t.Fatal("ambiguous history admitted input or blocked known recovery", err)
			}
			recovered, err := readResultContext(ctx, filepath.Join(results, known.JobID+".json"))
			if err != nil || recovered.Status != "succeeded" || recovered.ArtifactExecution == nil {
				t.Fatal("known committed receipt did not recover", err)
			}
			if _, err := os.Lstat(ambiguous); err != nil {
				t.Fatal("ambiguous history was removed", err)
			}
			for _, operation := range *operations {
				if operation != "status" && operation != "receipt" {
					t.Fatal("ambiguous history caused execution")
				}
			}
		})
	}
}

func TestWorkerBackendProjectionPolicyExactShapeAndBounds(t *testing.T) {
	_, facts := receiptTestFixture("variants", true)
	p := workerProjectionPolicy{1, facts.ProfileSHA256, "variants", "native", facts.ExpectedSourcePins}
	raw, _ := json.Marshal(p)
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadWorkerProjectionPolicy(context.Background(), path, p.ProfileSHA256, "variants"); err != nil {
		t.Fatal("valid policy refused", err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"profile":  func(m map[string]any) { m["profile_sha256"] = strings.Repeat("f", 64) },
		"mode":     func(m map[string]any) { m["pipeline_mode"] = "stats" },
		"provider": func(m map[string]any) { m["capsule_kind"] = "unknown" },
		"extra":    func(m map[string]any) { m["docker_command"] = "forbidden" },
		"missing":  func(m map[string]any) { delete(m, "schema_version") },
		"unknown_pin": func(m map[string]any) {
			m["source_pins"].(map[string]any)["unknown"] = map[string]any{"sha256": strings.Repeat("a", 64), "bytes": 1}
		},
		"oversize_pin": func(m map[string]any) {
			m["source_pins"].(map[string]any)["analysis_rules"].(map[string]any)["bytes"] = 65537
		},
		"missing_pin_bytes": func(m map[string]any) {
			delete(m["source_pins"].(map[string]any)["analysis_rules"].(map[string]any), "bytes")
		},
	} {
		t.Run(name, func(t *testing.T) {
			var m map[string]any
			json.Unmarshal(raw, &m)
			mutate(m)
			changed, _ := json.Marshal(m)
			if err := os.WriteFile(path, changed, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadWorkerProjectionPolicy(context.Background(), path, p.ProfileSHA256, "variants"); err == nil {
				t.Fatal("invalid projection policy accepted")
			}
		})
	}
}

func TestWorkerBackendSelectionCannotFallBackToHostExecution(t *testing.T) {
	t.Setenv("BIOZERO_ARTIFACT_PROFILE_SHA256", strings.Repeat("a", 64))
	f := newTestJob(t, `{}`, 0)
	result := resultRecord{SecurityMode: "protected", PipelineMode: "stats", ReleaseStatus: "withheld"}
	executeJob(context.Background(), f.job, &result, f.uploads, f.decrypted, defaultRules(), "", "", f.pipeline, "", "", time.Second)
	if result.ErrorCode != "worker_artifact_backend_required" {
		t.Fatal("configured backend fell back to host pipeline")
	}
	if _, err := os.Stat(filepath.Join(f.root, "called")); !os.IsNotExist(err) {
		t.Fatal("host pipeline executed")
	}
	if b, err := newWorkerCapsuleBackend(context.Background(), f.root, f.decrypted); err == nil || b != nil {
		t.Fatal("incomplete backend config accepted")
	}
}

func TestWorkerBackendStartupRequiresExplicitLegacyOrCapsule(t *testing.T) {
	for _, name := range []string{"BIOZERO_EXECUTION_BACKEND", "BIOZERO_ARTIFACT_SOCKET", "BIOZERO_ARTIFACT_PROFILE_SHA256", "BIOZERO_ARTIFACT_PROJECTION_POLICY", "BIOZERO_WORKER_CUSTODY_DIR"} {
		t.Setenv(name, "")
	}
	if err := validateWorkerExecutionSelection(); err == nil {
		t.Fatal("missing capsule configuration silently chose legacy")
	}
	t.Setenv("BIOZERO_EXECUTION_BACKEND", "legacy")
	if err := validateWorkerExecutionSelection(); err != nil {
		t.Fatal("explicit legacy profile refused", err)
	}
	t.Setenv("BIOZERO_ARTIFACT_SOCKET", "/private/socket")
	if err := validateWorkerExecutionSelection(); err == nil {
		t.Fatal("mixed legacy/capsule configuration accepted")
	}
	t.Setenv("BIOZERO_EXECUTION_BACKEND", "capsule")
	if err := validateWorkerExecutionSelection(); err != nil {
		t.Fatal("capsule selector refused before detailed config", err)
	}
	t.Setenv("BIOZERO_EXECUTION_BACKEND", "unknown")
	if err := validateWorkerExecutionSelection(); err == nil {
		t.Fatal("unknown execution profile accepted")
	}
}
