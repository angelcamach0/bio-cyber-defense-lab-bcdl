//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"syscall"
	"time"

	artifact "biozero/artifact-executor"
)

type ownerWorkerCustodyAPI interface {
	PutVerified(context.Context, OwnerWorkerBinding, []byte) error
	Lookup(string) (OwnerWorkerBinding, bool, error)
	Bindings() ([]OwnerWorkerBinding, error)
	Acceptance(context.Context, string) ([]byte, error)
	AcceptanceFile(context.Context, string) (*os.File, error)
	Close() error
}
type ownerWorkerCall func(context.Context, string, artifact.BridgeRequestV3, *os.File, *os.File) (artifact.BridgeResponseV3, *os.File, error)
type ownerWorkerStage func(context.Context, string, string, []byte) (*VerifiedPlaintextStage, error)

type ownerWorkerCache struct {
	SchemaVersion        int                `json:"schema_version"`
	Protocol             string             `json:"protocol"`
	JobID                string             `json:"job_id"`
	AcceptanceSHA256     string             `json:"acceptance_sha256"`
	Status               string             `json:"status"`
	ReleaseStatus        string             `json:"release_status"`
	ErrorCode            string             `json:"error_code"`
	PipelineOutput       json.RawMessage    `json:"pipeline_output"`
	ScientificEvaluation json.RawMessage    `json:"scientific_evaluation"`
	Detection            *detectionResult   `json:"detection"`
	ArtifactExecution    *artifactExecution `json:"artifact_execution"`
}

// These private caches are observability only. Neither their existence nor their
// status is consulted to authorize submission/recovery or result release.
func ownerWorkerWriteCache(ctx context.Context, dir string, c ownerWorkerCache) error {
	if ctx == nil || ctx.Err() != nil {
		return ownerWorkerError("owner_worker_cancelled")
	}
	raw, e := json.Marshal(c)
	if e != nil || len(raw) > maxResultMetadataBytes {
		return ownerWorkerError("owner_worker_cache_invalid")
	}
	d, e := openWorkerStageDir(dir)
	if e != nil {
		return ownerWorkerError("owner_worker_cache_unavailable")
	}
	defer d.Close()
	name := c.JobID + ".json"
	if !workerCustodyHex(c.JobID, 16) {
		return ownerWorkerError("owner_worker_cache_invalid")
	}
	old, e := readWorkerSnapshot(ctx, filepath.Join(dir, name), maxResultMetadataBytes, true)
	if e == nil {
		if !bytes.Equal(old, raw) {
			return ownerWorkerError("owner_worker_cache_conflict")
		}
		return nil
	}
	// Do not replace or remove an unsafe/unknown existing cache. Only true ENOENT
	// permits publication; snapshot deliberately sanitizes errors, so stat anchored.
	f, e := ownerWorkerCreateExclusive(d, name, raw)
	if f != nil {
		_ = f.Close()
	}
	return e
}

type ownerWorkerBackend struct {
	material                 ownerWorkerMaterial
	custody                  ownerWorkerCustodyAPI
	call                     ownerWorkerCall
	stage                    ownerWorkerStage
	publish                  func(context.Context, ownerWorkerCache) error
	pending                  map[string]OwnerWorkerBinding
	stages                   map[string]*VerifiedPlaintextStage
	rejected                 map[string]bool
	admissionBlocked, sticky bool
	cursor                   string
}

func (b *ownerWorkerBackend) bindInput(v verifiedOwnerInput) OwnerWorkerBinding {
	x := v.Acceptance.Binding()
	size := int64(len(v.Plaintext))
	return OwnerWorkerBinding{JobID: x.JobID, AcceptanceSHA256: v.Acceptance.SHA256(), CredentialSHA256: x.CredentialSHA256, UploadSHA256: x.CiphertextSHA256, EnvelopeSHA256: x.KeyEnvelopeSHA256, OriginalName: x.OriginalName, ProcessedSHA256: workerCustodyDigest(v.Plaintext), ProcessedBytes: size, AnalysisContext: artifact.AnalysisContext{OriginalName: x.OriginalName, ProcessedSizeBytes: size, Decrypted: true, SignatureValid: true}, AcceptanceBytes: int64(len(v.CanonicalAcceptance))}
}
func (b *ownerWorkerBackend) query(ctx context.Context, v OwnerWorkerBinding, op string) (artifact.BridgeResponseV3, *os.File, error) {
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return b.call(bounded, b.material.config.Socket, artifact.BridgeRequestV3{SchemaVersion: 3, Operation: op, JobID: v.JobID, UploadSHA256: v.UploadSHA256, ExpectedProfileSHA256: b.material.trust.ProfileSHA256, AcceptanceSHA256: v.AcceptanceSHA256}, nil, nil)
}
func (b *ownerWorkerBackend) responseMatches(v OwnerWorkerBinding, r artifact.BridgeResponseV3) bool {
	e := r.Execution
	return r.SchemaVersion == 3 && r.AcceptanceSHA256 == v.AcceptanceSHA256 && r.CredentialSHA256 == v.CredentialSHA256 && r.AuthorityScope == b.material.trust.Scope && r.ProcessedSHA256 == v.ProcessedSHA256 && r.ProcessedBytes == v.ProcessedBytes && r.AnalysisContext == v.AnalysisContext && e.SchemaVersion == 2 && e.ErrorCode == "" && e.JobID == v.JobID && e.UploadSHA256 == v.UploadSHA256 && e.ProfileSHA256 == b.material.trust.ProfileSHA256
}
func (b *ownerWorkerBackend) facts(v OwnerWorkerBinding) capsuleReceiptFacts {
	p := b.material.policy
	return capsuleReceiptFacts{JobID: v.JobID, UploadSHA256: v.UploadSHA256, ProfileSHA256: p.ProfileSHA256, ProcessedSHA256: v.ProcessedSHA256, ProcessedBytes: v.ProcessedBytes, AnalysisContext: v.AnalysisContext, Mode: p.PipelineMode, CapsuleKind: p.CapsuleKind, ExpectedSourcePins: p.SourcePins}
}
func (b *ownerWorkerBackend) projection(ctx context.Context, v OwnerWorkerBinding) (capsuleReceiptProjection, error) {
	var z capsuleReceiptProjection
	r, fd, e := b.query(ctx, v, "status")
	if fd != nil {
		fd.Close()
		return z, ownerWorkerError("owner_worker_status_unexpected_fd")
	}
	if e != nil || !b.responseMatches(v, r) || r.Execution.State != "committed" {
		return z, ownerWorkerError("owner_worker_execution_pending")
	}
	if _, ok := r.Execution.Manifest.Files["execution_receipt"]; !ok {
		return ProjectCapsuleReceipt(ctx, nil, r.Execution, b.facts(v))
	}
	rr, fd, e := b.query(ctx, v, "receipt")
	if fd != nil {
		defer fd.Close()
	}
	if e != nil || fd == nil || !b.responseMatches(v, rr) || !reflect.DeepEqual(r.Execution, rr.Execution) {
		return z, ownerWorkerError("owner_worker_receipt_unavailable")
	}
	return ProjectCapsuleReceipt(ctx, fd, rr.Execution, b.facts(v))
}
func (b *ownerWorkerBackend) finish(ctx context.Context, v OwnerWorkerBinding) error {
	p, e := b.projection(ctx, v)
	if e != nil {
		return e
	}
	// Actual receipt projection must precede release of this process's named
	// plaintext. We never adopt/delete a predecessor process's unknown stage.
	if stage := b.stages[v.JobID]; stage != nil {
		if stage.ReleaseConfirmed() != nil || stage.Close() != nil {
			b.sticky = true
			return ownerWorkerError("owner_worker_stage_release_uncertain")
		}
		delete(b.stages, v.JobID)
	}
	code := ""
	if p.Status != "succeeded" || p.ReleaseStatus == "withheld" {
		code = "owner_execution_withheld"
		if receiptCode.MatchString(p.PipelineError) {
			code = p.PipelineError
		}
	}
	cache := ownerWorkerCache{1, "owner-v1", v.JobID, v.AcceptanceSHA256, p.Status, p.ReleaseStatus, code, p.PipelineOutput, p.ScientificEvaluation, p.Detection, p.ArtifactExecution}
	if e = b.publish(ctx, cache); e != nil {
		b.sticky = true
		return e
	}
	delete(b.pending, v.JobID)
	return nil
}
func (b *ownerWorkerBackend) refresh(ctx context.Context) {
	if b.sticky || len(b.pending) == 0 {
		return
	}
	jobs := make([]string, 0, len(b.pending))
	for k := range b.pending {
		jobs = append(jobs, k)
	}
	sort.Strings(jobs)
	i := sort.SearchStrings(jobs, b.cursor)
	if i < len(jobs) && jobs[i] == b.cursor {
		i++
	}
	if i >= len(jobs) {
		i = 0
	}
	job := jobs[i]
	b.cursor = job
	_ = b.finish(ctx, b.pending[job])
}

// A known custody binding always uses query-only recovery. In particular, no
// mutable job/result terminal shortcut can precede this lookup.
func (b *ownerWorkerBackend) process(ctx context.Context, j ownerWorkerJob, acceptance []byte) error {
	if ctx == nil || ctx.Err() != nil {
		return ownerWorkerError("owner_worker_cancelled")
	}
	if b.sticky {
		return ownerWorkerError("owner_worker_unavailable")
	}
	v, found, e := b.custody.Lookup(j.JobID)
	if e != nil {
		b.sticky = true
		return e
	}
	if found {
		b.pending[v.JobID] = v
		return b.finish(ctx, v)
	}
	// A hostile spool can rotate filenames between bounded scans. Cardinality
	// must remain bounded across the whole process, not only within one scan.
	if !b.rejected[j.JobID] && len(b.rejected) >= 64 {
		b.admissionBlocked = true
		return ownerWorkerError("owner_worker_rejection_budget")
	}
	if b.rejected[j.JobID] || b.admissionBlocked || len(b.pending) > 0 {
		return ownerWorkerError("owner_worker_admission_pending")
	}
	input, e := verifyOwnerWorkerInput(ctx, j, acceptance, b.material.trust.pin(), b.material.trust.Scope, b.material.key, b.material.config.UploadsDirectory)
	if e != nil {
		b.rejected[j.JobID] = true
		return e
	}
	defer clear(input.Plaintext)
	stage, e := b.stage(ctx, b.material.config.StageDirectory, j.JobID, input.Plaintext)
	if e != nil {
		b.admissionBlocked = true
		return ownerWorkerError("owner_worker_stage_unavailable")
	}
	v = b.bindInput(input)
	if stage.SHA256 != v.ProcessedSHA256 || stage.Bytes != v.ProcessedBytes {
		b.sticky = true
		_ = stage.Close()
		return ownerWorkerError("owner_worker_stage_binding_invalid")
	}
	b.stages[v.JobID] = stage
	if e = b.custody.PutVerified(ctx, v, input.CanonicalAcceptance); e != nil {
		// Unknown custody durability retains the actual named stage. No speculative
		// cleanup or fresh identity is permitted, even though Submit has not started.
		b.sticky = true
		return e
	}
	b.pending[v.JobID] = v
	acceptanceFD, e := b.custody.AcceptanceFile(ctx, v.JobID)
	if e != nil {
		b.sticky = true
		return e
	}
	defer acceptanceFD.Close()
	if e = stage.MarkSubmitStarted(); e != nil {
		b.sticky = true
		return e
	}
	run, cancel := context.WithTimeout(ctx, time.Duration(b.material.config.TimeoutSeconds)*time.Second)
	defer cancel()
	r, fd, e := b.call(run, b.material.config.Socket, artifact.BridgeRequestV3{SchemaVersion: 3, Operation: "submit", JobID: v.JobID, UploadSHA256: v.UploadSHA256, ExpectedProfileSHA256: b.material.trust.ProfileSHA256, ProcessedSHA256: v.ProcessedSHA256, ProcessedBytes: v.ProcessedBytes, OriginalName: v.OriginalName, AnalysisContext: v.AnalysisContext, AcceptanceSHA256: v.AcceptanceSHA256, AcceptanceBytes: v.AcceptanceBytes}, stage.File, acceptanceFD)
	if fd != nil {
		fd.Close()
		b.sticky = true
		return ownerWorkerError("owner_worker_submit_unexpected_fd")
	}
	if e != nil || !b.responseMatches(v, r) {
		return ownerWorkerError("owner_worker_execution_pending")
	}
	return b.finish(ctx, v)
}
func (b *ownerWorkerBackend) Close() error {
	var first error
	for _, s := range b.stages {
		if e := s.Close(); e != nil && first == nil {
			first = e
		}
	}
	if b.custody != nil {
		if e := b.custody.Close(); e != nil && first == nil {
			first = e
		}
	}
	if first == nil && (b.sticky || len(b.pending) > 0 || b.admissionBlocked) {
		first = ownerWorkerError("owner_worker_history_pending")
	}
	return first
}

// ownerWorkerCreateExclusive performs one bounded, no-overwrite cache write.
// An incomplete publication is retained and subsequent attempts fail closed.
func ownerWorkerCreateExclusive(dir *os.File, name string, raw []byte) (*os.File, error) {
	file, e := ownerWorkerExclusiveFile(dir, name)
	if e != nil {
		return nil, e
	}
	n, e := file.Write(raw)
	if e == nil && n != len(raw) {
		e = io.ErrShortWrite
	}
	if e == nil {
		e = file.Sync()
	}
	ce := file.Close()
	if e == nil {
		e = ce
	}
	if e == nil {
		e = dir.Sync()
	}
	if e != nil {
		return nil, ownerWorkerError("owner_worker_cache_uncertain")
	}
	return nil, nil
}

func ownerWorkerExclusiveFile(dir *os.File, name string) (*os.File, error) {
	fd, e := syscall.Openat(int(dir.Fd()), name, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0600)
	if e != nil {
		return nil, ownerWorkerError("owner_worker_cache_conflict")
	}
	f := os.NewFile(uintptr(fd), "owner-worker-cache")
	if !workerCustodySafeFD(fd, false) {
		f.Close()
		return nil, ownerWorkerError("owner_worker_cache_unsafe")
	}
	return f, nil
}
