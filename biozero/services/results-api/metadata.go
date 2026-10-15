// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
)

const maxJobBytes int64 = 64 << 10
const maxResultBytes int64 = 16 << 20
const maxJSONDepth = 64

var errRecordInvalid = errors.New("record invalid")

// This mirrors Upload API and worker tags without adding ownership semantics.
type jobRecord struct {
	JobID             string `json:"job_id"`
	Status            string `json:"status"`
	StartedAt         string `json:"started_at,omitempty"`
	ErrorCode         string `json:"error_code,omitempty"`
	ErrorMessage      string `json:"error_message,omitempty"`
	UploadedAt        string `json:"uploaded_at"`
	OriginalName      string `json:"original_name"`
	SizeBytes         int64  `json:"size_bytes"`
	SHA256            string `json:"sha256"`
	ClientID          string `json:"client_id"`
	EncAlg            string `json:"enc_alg,omitempty"`
	EncKey            string `json:"enc_key,omitempty"`
	EncKeyWrapped     bool   `json:"enc_key_wrapped,omitempty"`
	EncKeyWrapAlg     string `json:"enc_key_wrap_alg,omitempty"`
	SigAlg            string `json:"sig_alg,omitempty"`
	Sig               string `json:"sig,omitempty"`
	ClientCertSubject string `json:"client_cert_subject,omitempty"`
	ClientCertIssuer  string `json:"client_cert_issuer,omitempty"`
	ClientCertSerial  string `json:"client_cert_serial,omitempty"`
}
type resultRecord struct {
	SchemaVersion        int                `json:"schema_version"`
	ErrorCode            string             `json:"error_code,omitempty"`
	ErrorMessage         string             `json:"error_message,omitempty"`
	SecurityMode         string             `json:"security_mode"`
	PipelineMode         string             `json:"pipeline_mode"`
	JobID                string             `json:"job_id"`
	Status               string             `json:"status"`
	ProcessedAt          string             `json:"processed_at"`
	UploadSHA256         string             `json:"upload_sha256"`
	ProcessedSHA256      string             `json:"processed_sha256"`
	SizeBytes            int64              `json:"size_bytes"`
	Decrypted            bool               `json:"decrypted"`
	DecryptionError      string             `json:"decryption_error,omitempty"`
	SignatureValid       bool               `json:"signature_valid"`
	SignatureError       string             `json:"signature_error,omitempty"`
	PipelineOutput       json.RawMessage    `json:"pipeline_output,omitempty"`
	PipelineError        string             `json:"pipeline_error,omitempty"`
	ScientificEvaluation json.RawMessage    `json:"scientific_evaluation,omitempty"`
	ReleaseStatus        string             `json:"release_status"`
	Detection            detectionResult    `json:"detection"`
	ClientCertSerial     string             `json:"client_cert_serial,omitempty"`
	ArtifactExecution    *artifactExecution `json:"artifact_execution,omitempty"`
}
type detectionResult struct {
	Score   float64        `json:"score"`
	Reason  string         `json:"reason"`
	Verdict string         `json:"verdict,omitempty"`
	Reasons []string       `json:"reasons,omitempty"`
	Signals map[string]any `json:"signals,omitempty"`
}

// Every component is opened relative to the previous directory descriptor.
// Symlinks in configured ancestors are deliberately unsupported. Nonblocking
// final open prevents a FIFO from waiting for a writer before fstat rejects it.
func readRecord(path string, limit int64) ([]byte, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.TrimPrefix(absolute, "/"), "/")
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	for _, part := range parts[:len(parts)-1] {
		next, openErr := syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		syscall.Close(fd)
		if openErr != nil {
			return nil, openErr
		}
		fd = next
	}
	final, err := syscall.Openat(fd, parts[len(parts)-1], syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	syscall.Close(fd)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(final), "metadata")
	defer file.Close()
	var stat syscall.Stat_t
	if err := syscall.Fstat(final, &stat); err != nil {
		return nil, err
	}
	if stat.Mode&syscall.S_IFMT != syscall.S_IFREG || stat.Mode&07777 != 0600 || stat.Uid != uint32(os.Geteuid()) || stat.Size < 0 || stat.Size > limit {
		return nil, fmt.Errorf("unsafe metadata file")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("metadata too large")
	}
	return data, nil
}
func isMissingRecord(err error) bool { return errors.Is(err, syscall.ENOENT) }
func writeRecordError(w http.ResponseWriter, kind string, err error) {
	if errors.Is(err, errRecordInvalid) {
		writeJSONError(w, 500, kind+"_record_invalid", kind+" record invalid")
		return
	}
	writeJSONError(w, 500, kind+"_read_failed", kind+" record cannot be read")
}

// Token traversal rejects duplicates even inside arbitrary scientific payloads,
// with a stack bounded before recursion. Arbitrary maps remain case sensitive.
func scanJSON(d *json.Decoder, depth int) error {
	token, err := d.Token()
	if err != nil {
		return err
	}
	delim, container := token.(json.Delim)
	if !container {
		return nil
	}
	if depth >= maxJSONDepth {
		return errRecordInvalid
	}
	switch delim {
	case '{':
		keys := make(map[string]bool)
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || keys[name] {
				return errRecordInvalid
			}
			keys[name] = true
			if err := scanJSON(d, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err := scanJSON(d, depth+1); err != nil {
				return err
			}
		}
	default:
		return errRecordInvalid
	}
	end, err := d.Token()
	if err != nil {
		return err
	}
	if (delim == '{' && end != json.Delim('}')) || (delim == '[' && end != json.Delim(']')) {
		return errRecordInvalid
	}
	return nil
}
func strictObject(data []byte, prototype any) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := scanJSON(d, 0); err != nil {
		return nil, errRecordInvalid
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errRecordInvalid
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil || fields == nil {
		return nil, errRecordInvalid
	}
	typ := reflect.TypeOf(prototype)
	allowed := make(map[string]reflect.Type)
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		allowed[strings.Split(f.Tag.Get("json"), ",")[0]] = f.Type
	}
	rawType := reflect.TypeOf(json.RawMessage{})
	for key, value := range fields {
		fieldType, ok := allowed[key]
		if !ok {
			return nil, errRecordInvalid
		}
		if fieldType != rawType && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, errRecordInvalid
		}
	}
	return fields, nil
}
func parseJob(data []byte) (jobRecord, error) {
	var job jobRecord
	if _, err := strictObject(data, job); err != nil {
		return job, err
	}
	if json.Unmarshal(data, &job) != nil || !isValidJobID(job.JobID) || !knownJobStatus(job.Status) {
		return jobRecord{}, errRecordInvalid
	}
	return job, nil
}
func parseResult(data []byte) (resultRecord, error) {
	var result resultRecord
	fields, err := strictObject(data, result)
	if err != nil {
		return result, err
	}
	if detection, present := fields["detection"]; present {
		nested, err := strictObject(detection, detectionResult{})
		if err != nil {
			return result, err
		}
		if reasons, ok := nested["reasons"]; ok {
			var values []json.RawMessage
			if json.Unmarshal(reasons, &values) != nil {
				return result, errRecordInvalid
			}
			for _, value := range values {
				if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
					return result, errRecordInvalid
				}
			}
		}
	}
	if json.Unmarshal(data, &result) != nil || !isValidJobID(result.JobID) || !knownTerminal(result.Status) {
		return resultRecord{}, errRecordInvalid
	}
	if _, present := fields["schema_version"]; present {
		if result.SchemaVersion != 1 {
			return resultRecord{}, errRecordInvalid
		}
		for _, required := range []string{"schema_version", "security_mode", "pipeline_mode", "job_id", "status", "processed_at", "upload_sha256", "processed_sha256", "size_bytes", "decrypted", "signature_valid", "release_status", "detection"} {
			if _, present := fields[required]; !present {
				return resultRecord{}, errRecordInvalid
			}
		}
		var detection map[string]json.RawMessage
		if json.Unmarshal(fields["detection"], &detection) != nil {
			return resultRecord{}, errRecordInvalid
		}
		for _, required := range []string{"score", "reason"} {
			if _, present := detection[required]; !present {
				return resultRecord{}, errRecordInvalid
			}
		}
	} else if result.Status != "processed" {
		return resultRecord{}, errRecordInvalid
	}
	if raw, ok := fields["artifact_execution"]; ok {
		if result.SchemaVersion != 1 {
			return resultRecord{}, errRecordInvalid
		}
		if _, err := validateArtifactExecution(raw, result.Status, result.ReleaseStatus); err != nil {
			return resultRecord{}, errRecordInvalid
		}
		if validateArtifactResultEnvelope(result) != nil {
			return resultRecord{}, errRecordInvalid
		}
	}
	return result, nil
}
func knownJobStatus(status string) bool {
	return status == "uploaded" || status == "running" || knownTerminal(status)
}

// artifactExecution binds a projected private result to retained broker objects.
// It is not authority to open files and is not a scientific-release proof.
type artifactExecution struct {
	SchemaVersion  int                     `json:"schema_version"`
	ProfileSHA256  string                  `json:"profile_sha256"`
	StoreID        string                  `json:"store_id"`
	LeaseID        string                  `json:"lease_id"`
	ManifestSHA256 string                  `json:"manifest_sha256"`
	ReceiptSHA256  string                  `json:"receipt_sha256"`
	ReceiptBytes   int64                   `json:"receipt_bytes"`
	Files          map[string]artifactFile `json:"files"`
}
type artifactFile struct {
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

func artifactHex(value string, size int) bool {
	if len(value) != size {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func artifactObject(raw []byte, keys ...string) (map[string]json.RawMessage, bool) {
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || object == nil || len(object) != len(keys) {
		return nil, false
	}
	for _, key := range keys {
		value, ok := object[key]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, false
		}
	}
	return object, true
}

// The caller's duplicate/depth pass precedes this exact nested shape check.
func validateArtifactExecution(raw []byte, status, release string) (*artifactExecution, error) {
	invalid := func() (*artifactExecution, error) { return nil, errors.New("metadata_artifact_execution_invalid") }
	object, ok := artifactObject(raw, "schema_version", "profile_sha256", "store_id", "lease_id", "manifest_sha256", "receipt_sha256", "receipt_bytes", "files")
	if !ok {
		return invalid()
	}
	var binding artifactExecution
	if json.Unmarshal(raw, &binding) != nil || binding.SchemaVersion != 1 || !artifactHex(binding.ProfileSHA256, 64) || !artifactHex(binding.StoreID, 32) || !artifactHex(binding.LeaseID, 32) || !artifactHex(binding.ManifestSHA256, 64) || binding.Files == nil || len(binding.Files) > 4 || binding.ReceiptBytes < 0 || binding.ReceiptBytes > 16<<20 {
		return invalid()
	}
	var entries map[string]json.RawMessage
	if json.Unmarshal(object["files"], &entries) != nil || entries == nil {
		return invalid()
	}
	var total int64
	for id, entry := range entries {
		switch id {
		case "execution_receipt", "normalized_vcf", "variants_vcf", "variants_vcf_index":
		default:
			return invalid()
		}
		if _, ok := artifactObject(entry, "sha256", "bytes"); !ok {
			return invalid()
		}
		file := binding.Files[id]
		if !artifactHex(file.SHA256, 64) || file.Bytes < 0 || file.Bytes > 64<<20 || total > (64<<20)-file.Bytes {
			return invalid()
		}
		total += file.Bytes
	}
	receipt, hasReceipt := binding.Files["execution_receipt"]
	if !hasReceipt {
		if binding.ReceiptSHA256 != "" || binding.ReceiptBytes != 0 || len(binding.Files) != 0 || status != "failed" || release != "withheld" {
			return invalid()
		}
	} else if !artifactHex(binding.ReceiptSHA256, 64) || binding.ReceiptBytes <= 0 || receipt.Bytes != binding.ReceiptBytes || receipt.SHA256 != binding.ReceiptSHA256 {
		return invalid()
	}
	_, normalized := binding.Files["normalized_vcf"]
	_, variants := binding.Files["variants_vcf"]
	_, index := binding.Files["variants_vcf_index"]
	if normalized != variants || variants != index {
		return invalid()
	}
	switch status {
	case "succeeded", "incomplete", "failed":
	default:
		return invalid()
	}
	switch release {
	case "evaluated_passed":
		if status != "succeeded" || !normalized || !hasReceipt {
			return invalid()
		}
	case "unassessed":
		if status != "succeeded" {
			return invalid()
		}
	case "withheld":
	default:
		return invalid()
	}
	if status != "succeeded" && release != "withheld" {
		return invalid()
	}
	return &binding, nil
}

// These verifier facts are coherent metadata, not cryptographic proof. The
// capsule path is selected only after the protected entry verified the upload.
func validateArtifactResultEnvelope(result resultRecord) error {
	invalid := errors.New("metadata_artifact_result_invalid")
	if result.SecurityMode != "protected" || !result.Decrypted || !result.SignatureValid || result.DecryptionError != "" || result.SignatureError != "" || !artifactHex(result.UploadSHA256, 64) || !artifactHex(result.ProcessedSHA256, 64) || result.SizeBytes < 0 || result.SizeBytes > 25<<20 || (result.PipelineMode != "stats" && result.PipelineMode != "variants") {
		return invalid
	}
	if result.PipelineMode == "stats" {
		if result.ReleaseStatus == "evaluated_passed" {
			return invalid
		}
		if _, ok := result.ArtifactExecution.Files["normalized_vcf"]; ok {
			return invalid
		}
	}
	if len(result.PipelineOutput) != 0 && !bytes.Equal(bytes.TrimSpace(result.PipelineOutput), []byte("null")) {
		var pipeline map[string]json.RawMessage
		if json.Unmarshal(result.PipelineOutput, &pipeline) != nil || pipeline == nil {
			return invalid
		}
		if raw, ok := pipeline["byte_count"]; ok {
			var count int64
			if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, &count) != nil || count != result.SizeBytes {
				return invalid
			}
		}
		if raw, ok := pipeline["sha256"]; ok {
			var sha string
			if json.Unmarshal(raw, &sha) != nil || sha != result.ProcessedSHA256 {
				return invalid
			}
		}
	}
	return nil
}
