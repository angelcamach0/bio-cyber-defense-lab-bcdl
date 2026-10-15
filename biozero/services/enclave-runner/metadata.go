// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"

	"biozero/enclave-runner/receiptprojection"
)

const maxJobMetadataBytes = 64 << 10
const maxResultMetadataBytes = 16 << 20
const maxMetadataDepth = receiptprojection.MaxMetadataDepth

func metadataError(code string) error { return errors.New(code) }

func metadataOpenError(err error) error {
	if err == syscall.ENOENT {
		return os.ErrNotExist
	}
	return metadataError("metadata_path_unsafe_or_unavailable")
}

// Every ancestor is opened relative to an already-held descriptor. No pathname
// check followed by a pathname open, and no symlink traversal. This restricts
// metadata inputs, not payload/config/PKI or the underlying filesystem's IO.
func openMetadataDirectory(ctx context.Context, path string) (*os.File, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, metadataError("metadata_path_invalid")
	}
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, metadataOpenError(err)
	}
	for _, component := range strings.Split(strings.TrimPrefix(absolute, "/"), "/") {
		if component == "" {
			continue
		}
		if err := ctx.Err(); err != nil {
			syscall.Close(fd)
			return nil, err
		}
		child, err := syscall.Openat(fd, component, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
		syscall.Close(fd)
		if err != nil {
			return nil, metadataOpenError(err)
		}
		fd = child
	}
	return os.NewFile(uintptr(fd), "metadata-directory"), nil
}

func metadataEntries(ctx context.Context, path string) ([]os.DirEntry, error) {
	dir, err := openMetadataDirectory(ctx, path)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return nil, metadataError("metadata_directory_read_failed")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	return entries, nil
}

func readMetadataFile(ctx context.Context, path string, maximum int64) ([]byte, error) {
	dir, err := openMetadataDirectory(ctx, filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fd, err := syscall.Openat(int(dir.Fd()), filepath.Base(path), syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, metadataOpenError(err)
	}
	file := os.NewFile(uintptr(fd), "metadata-file")
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, metadataError("metadata_file_not_regular")
	}
	if info.Mode().Perm() != 0600 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return nil, metadataError("metadata_file_permissions_invalid")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Uid != uint32(os.Geteuid()) {
		return nil, metadataError("metadata_file_owner_invalid")
	}
	if info.Size() > maximum {
		return nil, metadataError("metadata_file_size_exceeded")
	}
	buffer := bytes.Buffer{}
	block := make([]byte, 32<<10)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		remaining := maximum + 1 - int64(buffer.Len())
		if remaining < int64(len(block)) {
			block = block[:remaining]
		}
		n, err := file.Read(block)
		buffer.Write(block[:n])
		if int64(buffer.Len()) > maximum {
			return nil, metadataError("metadata_file_size_exceeded")
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, metadataError("metadata_file_read_failed")
		}
	}
	return buffer.Bytes(), nil
}

// Shared token validation preserves TM03 behavior for job/result metadata and
// receipt projection without maintaining a second parser implementation.
func validateMetadataJSON(ctx context.Context, data []byte, recordType reflect.Type) (map[string]bool, error) {
	return receiptprojection.ValidateMetadataJSON(ctx, data, recordType)
}

func knownMetadataStatus(status string) bool {
	return status == "uploaded" || status == "running" || terminalStatus(status)
}

func readJobContext(ctx context.Context, path string) (jobRecord, error) {
	var job jobRecord
	data, err := readMetadataFile(ctx, path, maxJobMetadataBytes)
	if err != nil {
		return job, err
	}
	seen, err := validateMetadataJSON(ctx, data, reflect.TypeOf(job))
	if err != nil {
		return job, err
	}
	if json.Unmarshal(data, &job) != nil {
		return job, metadataError("metadata_job_field_type_invalid")
	}
	if !seen["job_id"] || !seen["status"] || !isValidJobID(job.JobID) || !knownMetadataStatus(job.Status) {
		return job, metadataError("metadata_job_core_invalid")
	}
	return job, nil
}

func readResultContext(ctx context.Context, path string) (resultRecord, error) {
	var result resultRecord
	data, err := readMetadataFile(ctx, path, maxResultMetadataBytes)
	if err != nil {
		return result, err
	}
	seen, err := validateMetadataJSON(ctx, data, reflect.TypeOf(result))
	if err != nil {
		return result, err
	}
	if json.Unmarshal(data, &result) != nil {
		return result, metadataError("metadata_result_field_type_invalid")
	}
	if !seen["job_id"] || !seen["status"] || !isValidJobID(result.JobID) || !terminalStatus(result.Status) {
		return result, metadataError("metadata_result_core_invalid")
	}
	if !seen["schema_version"] && result.Status == "processed" && !seen["artifact_execution"] {
		return result, nil // Explicit historical recovery remains incomplete/unverified.
	}
	if !seen["schema_version"] || result.SchemaVersion != 1 {
		return result, metadataError("metadata_result_schema_invalid")
	}
	for i := 0; i < reflect.TypeOf(result).NumField(); i++ {
		field := reflect.TypeOf(result).Field(i)
		tag := field.Tag.Get("json")
		if !strings.Contains(tag, ",omitempty") && !seen[tag] {
			return result, metadataError("metadata_result_required_field_missing")
		}
	}
	var fields map[string]json.RawMessage
	json.Unmarshal(data, &fields)
	var detection map[string]json.RawMessage
	json.Unmarshal(fields["detection"], &detection)
	if _, ok := detection["score"]; !ok {
		return result, metadataError("metadata_detection_required_field_missing")
	}
	if _, ok := detection["reason"]; !ok {
		return result, metadataError("metadata_detection_required_field_missing")
	}
	if raw, ok := fields["artifact_execution"]; ok {
		if _, err := validateArtifactExecution(raw, result.Status, result.ReleaseStatus); err != nil {
			return result, err
		}
		if err := validateArtifactResultEnvelope(result); err != nil {
			return result, err
		}
	}
	return result, nil
}

// Aliases retain the current worker metadata schema and validator entry points.
type artifactExecution = receiptprojection.ArtifactExecution
type artifactFile = receiptprojection.ArtifactFile

func artifactHex(value string, size int) bool { return receiptprojection.ArtifactHex(value, size) }
func artifactObject(raw []byte, keys ...string) (map[string]json.RawMessage, bool) {
	return receiptprojection.ArtifactObject(raw, keys...)
}
func validateArtifactExecution(raw []byte, status, release string) (*artifactExecution, error) {
	return receiptprojection.ValidateArtifactExecution(raw, status, release)
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
