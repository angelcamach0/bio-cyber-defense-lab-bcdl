//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"time"

	artifact "biozero/artifact-executor"
)

// This document is fixed operator configuration, mounted read-only to the
// worker. It contains no Store paths, provider commands or Docker authority.
// Its pins must describe the same profile selected by the broker operator.
type workerProjectionPolicy struct {
	SchemaVersion int                         `json:"schema_version"`
	ProfileSHA256 string                      `json:"profile_sha256"`
	PipelineMode  string                      `json:"pipeline_mode"`
	CapsuleKind   string                      `json:"capsule_kind"`
	SourcePins    map[string]capsuleSourcePin `json:"source_pins"`
}

type workerBridgeCall func(context.Context, string, artifact.BridgeRequestV2, *os.File) (artifact.BridgeResponse, *os.File, error)

// One instance is owned by the sequential worker loop. Custody is durable;
// pending and stages only fence new plaintext admission within this process.
// Every retained binding is treated as pending again on restart, until verified
// readback. No query error permits a second Submit.
type workerCapsuleBackend struct {
	socket           string
	policy           workerProjectionPolicy
	custody          *WorkerCustody
	call             workerBridgeCall
	pending          map[string]WorkerCustodyBinding
	stages           map[string]*VerifiedPlaintextStage
	sticky           bool
	admissionBlocked bool
	cursor           string
}

type workerBackendContextKey struct{}

func capsuleBackendFromContext(ctx context.Context) *workerCapsuleBackend {
	b, _ := ctx.Value(workerBackendContextKey{}).(*workerCapsuleBackend)
	return b
}

func workerBackendSelected() bool {
	return os.Getenv("BIOZERO_EXECUTION_BACKEND") == "capsule" || os.Getenv("BIOZERO_ARTIFACT_SOCKET") != "" || os.Getenv("BIOZERO_ARTIFACT_PROFILE_SHA256") != "" || os.Getenv("BIOZERO_ARTIFACT_PROJECTION_POLICY") != "" || os.Getenv("BIOZERO_WORKER_CUSTODY_DIR") != ""
}

// Production entry defaults to the bounded path. The earlier harness remains
// available only as an explicitly named legacy profile, never as fallback from
// absent or broken capsule configuration.
func validateWorkerExecutionSelection() error {
	switch envOr("BIOZERO_EXECUTION_BACKEND", "capsule") {
	case "capsule":
		if !workerBackendSelected() {
			return errors.New("worker_artifact_configuration_required")
		}
	case "legacy":
		if workerBackendSelected() {
			return errors.New("worker_execution_configuration_conflict")
		}
	default:
		return errors.New("worker_execution_backend_invalid")
	}
	return nil
}

func loadWorkerProjectionPolicy(ctx context.Context, path, profile, mode string) (workerProjectionPolicy, error) {
	var p workerProjectionPolicy
	invalid := errors.New("worker_projection_policy_invalid")
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !workerCustodyHex(profile, 64) {
		return p, invalid
	}
	raw, err := readWorkerSnapshot(ctx, path, 64<<10, true)
	if err != nil {
		return p, invalid
	}
	seen, err := validateMetadataJSON(ctx, raw, reflect.TypeOf(p))
	if err != nil || len(seen) != 5 || json.Unmarshal(raw, &p) != nil || p.SchemaVersion != 1 || p.ProfileSHA256 != profile || p.PipelineMode != mode || (mode != "stats" && mode != "variants") || (p.CapsuleKind != "native" && p.CapsuleKind != "docker") || p.SourcePins == nil {
		return p, invalid
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return p, invalid
	}
	var pins map[string]json.RawMessage
	if json.Unmarshal(fields["source_pins"], &pins) != nil {
		return p, invalid
	}
	required := map[string]int64{"pipeline": 1 << 20, "resource_budget": 1 << 20, "analysis_executable": 4 << 20, "analysis_rules": 64 << 10}
	optional := map[string]int64{"reference": 32 << 20, "analysis_panel": 32 << 20}
	if mode == "variants" {
		required["reference"], required["evaluator"], required["truth"] = 32<<20, 1<<20, 8<<20
	}
	for name, pin := range p.SourcePins {
		limit, ok := required[name]
		if !ok {
			limit, ok = optional[name]
		}
		if !ok || !workerCustodyHex(pin.SHA256, 64) || pin.Bytes < 0 || pin.Bytes > limit {
			return p, invalid
		}
		if _, ok := artifactObject(pins[name], "sha256", "bytes"); !ok {
			return p, invalid
		}
	}
	for name := range required {
		if _, ok := p.SourcePins[name]; !ok {
			return p, invalid
		}
	}
	return p, nil
}

func newWorkerCapsuleBackend(ctx context.Context, dataDir, stageDir string) (*workerCapsuleBackend, error) {
	if !workerBackendSelected() {
		return nil, nil
	}
	if envOr("BIOZERO_SECURITY_MODE", "protected") != "protected" {
		return nil, errors.New("worker_capsule_requires_protected_mode")
	}
	socket, profile := os.Getenv("BIOZERO_ARTIFACT_SOCKET"), os.Getenv("BIOZERO_ARTIFACT_PROFILE_SHA256")
	if !filepath.IsAbs(socket) || filepath.Clean(socket) != socket || filepath.Base(socket) == "." || socket == "/" || strings.ContainsAny(socket, "\x00\r\n") {
		return nil, errors.New("worker_artifact_configuration_invalid")
	}
	p, err := loadWorkerProjectionPolicy(ctx, os.Getenv("BIOZERO_ARTIFACT_PROJECTION_POLICY"), profile, envOr("BIOZERO_PIPELINE_MODE", "stats"))
	if err != nil {
		return nil, err
	}
	if err := ValidateWorkerStageDirectory(ctx, stageDir); err != nil {
		return nil, err
	}
	root := envOr("BIOZERO_WORKER_CUSTODY_DIR", filepath.Join(dataDir, "worker-custody"))
	root, err = filepath.Abs(root)
	if err != nil {
		return nil, errors.New("worker_custody_root_invalid")
	}
	b := &workerCapsuleBackend{socket: socket, policy: p, call: artifact.CallBridgeUnixV2, pending: map[string]WorkerCustodyBinding{}, stages: map[string]*VerifiedPlaintextStage{}}
	stageDirectory, err := openWorkerStageDir(stageDir)
	if err != nil {
		return nil, err
	}
	entries, scanErr := stageDirectory.ReadDir(1)
	closeErr := stageDirectory.Close()
	if (scanErr != nil && scanErr != io.EOF) || closeErr != nil {
		return nil, errors.New("worker_plaintext_history_unreadable")
	}
	b.admissionBlocked = len(entries) != 0
	b.custody, err = NewWorkerCustody(ctx, root, profile, p.PipelineMode)
	if err != nil {
		return b, err
	}
	bindings, err := b.custody.Bindings()
	if err != nil {
		return b, err
	}
	for _, v := range bindings {
		b.pending[v.JobID] = v
	}
	return b, nil
}

func (b *workerCapsuleBackend) Close() error {
	var first error
	for _, stage := range b.stages {
		// An unconfirmed input remains linked; descriptor close is not proof of
		// provider termination. Nothing here deletes, adopts or refunds history.
		if err := stage.Close(); err != nil && first == nil {
			first = err
		}
	}
	if b.custody != nil {
		if err := b.custody.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// Lifecycle fields are excluded. The fingerprint stores only a digest of the
// immutable upload/identity/crypto metadata, never key envelopes or signatures.
func workerJobFingerprint(job jobRecord) (string, error) {
	job.Status, job.StartedAt, job.ErrorCode, job.ErrorMessage = "", "", "", ""
	raw, err := json.Marshal(job)
	if err != nil {
		return "", errors.New("worker_job_fingerprint_invalid")
	}
	return workerCustodyDigest(raw), nil
}

func (b *workerCapsuleBackend) facts(v WorkerCustodyBinding) capsuleReceiptFacts {
	return capsuleReceiptFacts{JobID: v.JobID, UploadSHA256: v.UploadSHA256, ProfileSHA256: b.policy.ProfileSHA256, ProcessedSHA256: v.ProcessedSHA256, ProcessedBytes: v.ProcessedBytes, AnalysisContext: v.AnalysisContext, Mode: b.policy.PipelineMode, CapsuleKind: b.policy.CapsuleKind, ExpectedSourcePins: b.policy.SourcePins}
}

func (b *workerCapsuleBackend) query(ctx context.Context, v WorkerCustodyBinding, operation string) (artifact.BridgeResponse, *os.File, error) {
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return b.call(bounded, b.socket, artifact.BridgeRequestV2{SchemaVersion: 2, Operation: operation, JobID: v.JobID, UploadSHA256: v.UploadSHA256, ExpectedProfileSHA256: b.policy.ProfileSHA256}, nil)
}

func (b *workerCapsuleBackend) projection(ctx context.Context, v WorkerCustodyBinding) (capsuleReceiptProjection, error) {
	r, fd, err := b.query(ctx, v, "status")
	if fd != nil {
		fd.Close()
		return capsuleReceiptProjection{}, errors.New("worker_status_unexpected_fd")
	}
	if err != nil || r.ErrorCode != "" || r.State != "committed" {
		return capsuleReceiptProjection{}, errors.New("worker_artifact_pending")
	}
	if _, has := r.Manifest.Files["execution_receipt"]; !has {
		return ProjectCapsuleReceipt(ctx, nil, r, b.facts(v))
	}
	receipt, fd, err := b.query(ctx, v, "receipt")
	if fd != nil {
		defer fd.Close()
	}
	if err != nil || receipt.ErrorCode != "" || fd == nil || receipt.ManifestSHA256 != r.ManifestSHA256 || receipt.LeaseID != r.LeaseID || receipt.StoreID != r.StoreID {
		return capsuleReceiptProjection{}, errors.New("worker_receipt_unavailable")
	}
	return ProjectCapsuleReceipt(ctx, fd, receipt, b.facts(v))
}

func (b *workerCapsuleBackend) releaseConfirmed(v WorkerCustodyBinding) error {
	if stage := b.stages[v.JobID]; stage != nil {
		if err := stage.ReleaseConfirmed(); err != nil {
			b.sticky = true
			return err
		}
		if err := stage.Close(); err != nil {
			b.sticky = true
			return err
		}
		delete(b.stages, v.JobID)
	}
	delete(b.pending, v.JobID)
	return nil
}

// One old binding per poll prevents a large retained journal from monopolizing
// the worker. A lost ACK and generic handler errors retain the admission fence.
func (b *workerCapsuleBackend) refreshPending(ctx context.Context) {
	if ctx.Err() != nil || b.sticky || len(b.pending) == 0 {
		return
	}
	ids := make([]string, 0, len(b.pending))
	for id := range b.pending {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	i := sort.SearchStrings(ids, b.cursor)
	if i < len(ids) && ids[i] == b.cursor {
		i++
	}
	if i >= len(ids) {
		i = 0
	}
	b.cursor = ids[i]
	v := b.pending[ids[i]]
	if _, err := b.projection(ctx, v); err == nil {
		_ = b.releaseConfirmed(v)
	}
}

// Inspect all readable running jobs before admitting any new plaintext. A
// lexically earlier upload must not cross an unresolved running job merely
// because the directory scan encounters that older job later. Terminal results
// can still be recovered without decrypting or submitting anything.
func (b *workerCapsuleBackend) fenceUntrackedRunning(ctx context.Context, entries []os.DirEntry, jobsDir, resultsDir string) {
	for _, entry := range entries {
		if ctx.Err() != nil || b.sticky {
			return
		}
		if !strings.HasSuffix(entry.Name(), ".json") || !isValidJobID(strings.TrimSuffix(entry.Name(), ".json")) {
			continue
		}
		job, err := readJobContext(ctx, filepath.Join(jobsDir, entry.Name()))
		if err != nil || entry.IsDir() || entry.Name() != job.JobID+".json" {
			// A safe-shaped job name with unreadable/unsafe/mismatched contents
			// cannot establish whether running history is absent. Preserve it
			// and fence only new admission, while known bindings can recover.
			b.admissionBlocked = true
			continue
		}
		if job.Status != "running" {
			continue
		}
		if previous, err := readResultContext(ctx, filepath.Join(resultsDir, job.JobID+".json")); err == nil && previous.JobID == job.JobID && terminalStatus(previous.Status) {
			continue
		}
		if !workerCustodyHex(job.JobID, 16) {
			b.admissionBlocked = true
			continue
		}
		_, found, err := b.custody.Lookup(job.JobID)
		if err != nil {
			b.sticky = true
			return
		}
		if !found {
			b.admissionBlocked = true
		}
	}
}

func applyCapsuleProjection(result *resultRecord, v WorkerCustodyBinding, p capsuleReceiptProjection) {
	result.ProcessedSHA256, result.SizeBytes = v.ProcessedSHA256, v.ProcessedBytes
	result.Decrypted, result.DecryptionError = v.AnalysisContext.Decrypted, v.AnalysisContext.DecryptionError
	result.SignatureValid, result.SignatureError = v.AnalysisContext.SignatureValid, v.AnalysisContext.SignatureError
	result.PipelineOutput, result.ScientificEvaluation = p.PipelineOutput, p.ScientificEvaluation
	result.PipelineError, result.Status, result.ReleaseStatus = p.PipelineError, p.Status, p.ReleaseStatus
	result.ArtifactExecution = p.ArtifactExecution
	result.Detection = detectionResult{Reason: "detection_unavailable"}
	if p.Detection != nil {
		result.Detection = *p.Detection
	}
	if p.Status != "succeeded" || p.ReleaseStatus == "withheld" {
		result.ErrorCode = "capsule_result_withheld"
		if receiptCode.MatchString(p.PipelineError) {
			result.ErrorCode = p.PipelineError
		}
		result.ErrorMessage = "retained capsule execution did not approve result release"
	}
}

// Returning false leaves the job running and does not publish a terminal result.
// Recovery never submits, decrypts or opens a namespace-produced output path.
func (b *workerCapsuleBackend) process(ctx context.Context, job jobRecord, wasRunning bool, result *resultRecord, uploadDir, stageDir, privateKeyPath, signerCertPath, jobKey string, timeout time.Duration) bool {
	if b.sticky {
		return false
	}
	v, found, err := b.custody.Lookup(job.JobID)
	if err != nil {
		b.sticky = true
		return false
	}
	fingerprint, err := workerJobFingerprint(job)
	if err != nil {
		b.sticky = true
		return false
	}
	if found {
		if v.JobFingerprint != fingerprint || v.UploadSHA256 != job.SHA256 || v.AnalysisContext.OriginalName != job.OriginalName {
			b.sticky = true
			return false
		}
		b.pending[job.JobID] = v
		p, err := b.projection(ctx, v)
		if err != nil {
			return false
		}
		if err := b.releaseConfirmed(v); err != nil {
			return false
		}
		applyCapsuleProjection(result, v, p)
		return true
	}
	if wasRunning {
		// The process may have stopped before durable verifier facts. Neither an
		// absent local binding nor a generic broker error authorizes resubmission.
		b.admissionBlocked = true
		return false
	}
	if b.admissionBlocked || len(b.pending) > 0 {
		return false
	}
	plain, ok := verifyProtectedJobSnapshot(ctx, job, result, uploadDir, privateKeyPath, signerCertPath, jobKey)
	if !ok {
		return true
	}
	defer clearWorkerBytes(plain)
	stage, err := StageVerifiedPlaintext(ctx, stageDir, job.JobID, plain)
	if err != nil {
		result.Status, result.ErrorCode, result.ErrorMessage = "failed", "worker_plaintext_stage_failed", "verified bounded plaintext workspace unavailable"
		return true
	}
	v = WorkerCustodyBinding{JobID: job.JobID, JobFingerprint: fingerprint, UploadSHA256: job.SHA256, ProcessedSHA256: stage.SHA256, ProcessedBytes: stage.Bytes, AnalysisContext: artifact.AnalysisContext{OriginalName: job.OriginalName, ProcessedSizeBytes: stage.Bytes, Decrypted: true, SignatureValid: true}}
	if err := b.custody.PutVerified(ctx, v); err != nil {
		// No Submit was attempted, so the known stage can be discarded. Unknown
		// journal durability remains fenced; no retry or implicit repair follows.
		_ = stage.DiscardUnsubmitted()
		_ = stage.Close()
		b.sticky = true
		return false
	}
	b.pending[job.JobID], b.stages[job.JobID] = v, stage
	if err := stage.MarkSubmitStarted(); err != nil {
		b.sticky = true
		return false
	}
	execution, cancel := context.WithTimeout(ctx, timeout)
	r, fd, err := b.call(execution, b.socket, artifact.BridgeRequestV2{SchemaVersion: 2, Operation: "submit", JobID: job.JobID, UploadSHA256: job.SHA256, ExpectedProfileSHA256: b.policy.ProfileSHA256, ProcessedSHA256: v.ProcessedSHA256, ProcessedBytes: v.ProcessedBytes, OriginalName: job.OriginalName, AnalysisContext: v.AnalysisContext}, stage.File)
	cancel()
	if fd != nil {
		fd.Close()
		b.sticky = true
		return false
	}
	if err != nil || r.ErrorCode != "" {
		if ctx.Err() != nil {
			// Best effort request, never a cleanup proof. Query recovery still
			// requires the committed Store receipt and retains the named stage.
			stopCtx, stop := context.WithTimeout(context.Background(), 2*time.Second)
			_, f, _ := b.query(stopCtx, v, "cancel")
			if f != nil {
				f.Close()
			}
			stop()
		}
		return false
	}
	p, err := b.projection(ctx, v)
	if err != nil {
		return false
	}
	if err := b.releaseConfirmed(v); err != nil {
		return false
	}
	applyCapsuleProjection(result, v, p)
	return true
}

func clearWorkerBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

// One anchored snapshot supplies hash, signature and authenticated decryption.
// No plaintext is persisted here, and no payload pathname is reopened between
// verification and decryption. StageVerifiedPlaintext owns the bounded tmpfs copy.
func readWorkerSnapshot(ctx context.Context, path string, limit int64, private bool) ([]byte, error) {
	dir, err := openMetadataDirectory(ctx, filepath.Dir(path))
	if err != nil {
		return nil, errors.New("worker_snapshot_unavailable")
	}
	defer dir.Close()
	fd, err := syscall.Openat(int(dir.Fd()), filepath.Base(path), syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("worker_snapshot_unavailable")
	}
	f := os.NewFile(uintptr(fd), "worker-input-snapshot")
	defer f.Close()
	var before, after syscall.Stat_t
	if syscall.Fstat(fd, &before) != nil || before.Mode&syscall.S_IFMT != syscall.S_IFREG || before.Nlink != 1 || before.Size < 0 || before.Size > limit || before.Mode&07022 != 0 || (before.Uid != uint32(os.Geteuid()) && (!private && before.Uid != 0)) || (private && (before.Uid != uint32(os.Geteuid()) || before.Mode&07777 != 0600)) {
		return nil, errors.New("worker_snapshot_unsafe")
	}
	var out bytes.Buffer
	block := make([]byte, 32<<10)
	for {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		n, e := f.Read(block)
		out.Write(block[:n])
		if int64(out.Len()) > limit {
			return nil, errors.New("worker_snapshot_too_large")
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, errors.New("worker_snapshot_unreadable")
		}
	}
	if syscall.Fstat(fd, &after) != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Mode != after.Mode || before.Uid != after.Uid || before.Gid != after.Gid || before.Nlink != after.Nlink || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim || int64(out.Len()) != before.Size {
		return nil, errors.New("worker_snapshot_changed")
	}
	return out.Bytes(), nil
}

func workerPublicKey(ctx context.Context, path string) (*rsa.PublicKey, error) {
	raw, err := readWorkerSnapshot(ctx, path, 64<<10, false)
	if err != nil {
		return nil, err
	}
	for {
		block, rest := pem.Decode(raw)
		if block == nil {
			return nil, errors.New("worker_signer_invalid")
		}
		raw = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("worker_signer_invalid")
		}
		return pub, nil
	}
}

func workerPrivateKey(ctx context.Context, path string) (*rsa.PrivateKey, error) {
	raw, err := readWorkerSnapshot(ctx, path, 64<<10, true)
	if err != nil {
		return nil, err
	}
	defer clearWorkerBytes(raw)
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("worker_decrypt_key_invalid")
	}
	if block.Type == "RSA PRIVATE KEY" {
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	}
	if block.Type == "PRIVATE KEY" {
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if ok {
			return rsaKey, nil
		}
	}
	return nil, errors.New("worker_decrypt_key_invalid")
}

func verifyProtectedJobSnapshot(ctx context.Context, job jobRecord, result *resultRecord, uploadDir, privateKeyPath, signerCertPath, jobKey string) ([]byte, bool) {
	fail := func(status, code, message string) ([]byte, bool) {
		result.Status, result.ErrorCode, result.ErrorMessage = status, code, message
		result.ReleaseStatus = "withheld"
		return nil, false
	}
	if !workerCustodyHex(job.JobID, 16) || !workerCustodyHex(job.SHA256, 64) || job.SizeBytes < 0 || job.SizeBytes > artifact.MaxInputBytes {
		return fail("rejected", "upload_metadata_invalid", "protected capsule input metadata invalid")
	}
	if result.SecurityMode != "protected" || (result.PipelineMode != "stats" && result.PipelineMode != "variants") {
		return fail("failed", "worker_artifact_configuration_invalid", "protected capsule mode required")
	}
	data, err := readWorkerSnapshot(ctx, filepath.Join(uploadDir, job.JobID+"_"+sanitizeFilename(job.OriginalName)), artifact.MaxInputBytes, true)
	if err != nil {
		return fail("failed", "upload_unreadable", "upload cannot be read")
	}
	defer clearWorkerBytes(data)
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != job.SHA256 || int64(len(data)) != job.SizeBytes {
		return fail("rejected", "upload_integrity_failed", "stored payload does not match immutable upload metadata")
	}
	if job.Sig == "" {
		return fail("rejected", "signature_required", "a coherent signed payload is required")
	}
	if job.SigAlg != "rsa-pss-sha256" {
		return fail("rejected", "signature_algorithm_invalid", "unsupported signature algorithm")
	}
	pub, err := workerPublicKey(ctx, signerCertPath)
	sig, decodeErr := hex.DecodeString(job.Sig)
	if err != nil || decodeErr != nil || rsa.VerifyPSS(pub, crypto.SHA256, sum[:], sig, nil) != nil {
		result.SignatureError = "signature_verification_failed"
		return fail("rejected", "signature_invalid", "payload signature verification failed")
	}
	result.SignatureValid = true
	if job.EncAlg == "" && job.EncKey == "" && !job.EncKeyWrapped && job.EncKeyWrapAlg == "" {
		return fail("rejected", "encryption_required", "encrypted payload is required")
	}
	if job.EncAlg != "aes-256-gcm+rsa-oaep-sha256" || job.EncKey == "" || (!job.EncKeyWrapped && job.EncKeyWrapAlg != "") {
		return fail("rejected", "encryption_metadata_invalid", "unsupported or incomplete encryption metadata")
	}
	encKey := job.EncKey
	if job.EncKeyWrapped {
		if job.EncKeyWrapAlg != "aes-256-gcm" || jobKey == "" {
			return fail("rejected", "key_unwrap_failed", "wrapped key configuration invalid")
		}
		encKey, err = unwrapSensitiveValue(encKey, jobKey)
		if err != nil {
			result.DecryptionError = "key_unwrap_failed"
			return fail("rejected", "key_unwrap_failed", "payload key could not be unwrapped")
		}
	}
	if privateKeyPath == "" {
		return fail("failed", "decrypt_key_missing", "decryption key not configured")
	}
	priv, err := workerPrivateKey(ctx, privateKeyPath)
	if err != nil {
		return fail("failed", "decrypt_key_unavailable", "decryption key unavailable")
	}
	envelope, err := hex.DecodeString(encKey)
	if err != nil {
		result.DecryptionError = "decryption_failed"
		return fail("rejected", "decryption_failed", "payload authentication/decryption failed")
	}
	material, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, envelope, nil)
	if err != nil || len(material) != 44 {
		clearWorkerBytes(material)
		result.DecryptionError = "decryption_failed"
		return fail("rejected", "decryption_failed", "payload authentication/decryption failed")
	}
	defer clearWorkerBytes(material)
	block, err := aes.NewCipher(material[:32])
	if err != nil {
		return fail("failed", "decrypt_configuration_invalid", "payload decryption configuration invalid")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fail("failed", "decrypt_configuration_invalid", "payload decryption configuration invalid")
	}
	plain, err := gcm.Open(nil, material[32:], data, nil)
	if err != nil {
		result.DecryptionError = "decryption_failed"
		return fail("rejected", "decryption_failed", "payload authentication/decryption failed")
	}
	result.Decrypted = true
	result.ProcessedSHA256 = workerCustodyDigest(plain)
	result.SizeBytes = int64(len(plain))
	return plain, true
}
