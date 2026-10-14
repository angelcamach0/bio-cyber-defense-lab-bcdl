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
	SchemaVersion        int             `json:"schema_version"`
	ErrorCode            string          `json:"error_code,omitempty"`
	ErrorMessage         string          `json:"error_message,omitempty"`
	SecurityMode         string          `json:"security_mode"`
	PipelineMode         string          `json:"pipeline_mode"`
	JobID                string          `json:"job_id"`
	Status               string          `json:"status"`
	ProcessedAt          string          `json:"processed_at"`
	UploadSHA256         string          `json:"upload_sha256"`
	ProcessedSHA256      string          `json:"processed_sha256"`
	SizeBytes            int64           `json:"size_bytes"`
	Decrypted            bool            `json:"decrypted"`
	DecryptionError      string          `json:"decryption_error,omitempty"`
	SignatureValid       bool            `json:"signature_valid"`
	SignatureError       string          `json:"signature_error,omitempty"`
	PipelineOutput       json.RawMessage `json:"pipeline_output,omitempty"`
	PipelineError        string          `json:"pipeline_error,omitempty"`
	ScientificEvaluation json.RawMessage `json:"scientific_evaluation,omitempty"`
	ReleaseStatus        string          `json:"release_status"`
	Detection            detectionResult `json:"detection"`
	ClientCertSerial     string          `json:"client_cert_serial,omitempty"`
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
	return result, nil
}
func knownJobStatus(status string) bool {
	return status == "uploaded" || status == "running" || knownTerminal(status)
}
