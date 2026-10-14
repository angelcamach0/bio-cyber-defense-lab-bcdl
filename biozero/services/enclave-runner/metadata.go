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
)

const maxJobMetadataBytes = 64 << 10
const maxResultMetadataBytes = 16 << 20
const maxMetadataDepth = 64

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

func jsonFields(recordType reflect.Type) map[string]reflect.Type {
	fields := map[string]reflect.Type{}
	for i := 0; i < recordType.NumField(); i++ {
		field := recordType.Field(i)
		fields[strings.Split(field.Tag.Get("json"), ",")[0]] = field.Type
	}
	return fields
}

// Scientific maps remain case-sensitive and extensible. Exact duplicate keys
// and excessive depth are rejected everywhere, including RawMessage payloads.
// Known structs require exact field names, closing encoding/json's alias path.
func scanMetadataJSON(ctx context.Context, decoder *json.Decoder, depth int, recordType reflect.Type) (map[string]bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, metadataError("metadata_json_invalid")
	}
	structured := recordType != nil && recordType.Kind() == reflect.Struct
	if structured && token != json.Delim('{') {
		return nil, metadataError("metadata_json_type_invalid")
	}
	rawMessage := recordType == reflect.TypeOf(json.RawMessage{})
	if token == nil && recordType != nil && !rawMessage {
		switch recordType.Kind() {
		case reflect.String, reflect.Bool, reflect.Int, reflect.Int64, reflect.Float64, reflect.Slice, reflect.Map:
			return nil, metadataError("metadata_json_scalar_null")
		}
	}
	if token != json.Delim('{') && token != json.Delim('[') {
		return nil, nil
	}
	if depth >= maxMetadataDepth {
		return nil, metadataError("metadata_json_depth_exceeded")
	}
	if token == json.Delim('[') {
		var elementType reflect.Type
		if recordType != nil && recordType.Kind() == reflect.Slice && !rawMessage {
			elementType = recordType.Elem()
		}
		for decoder.More() {
			if _, err := scanMetadataJSON(ctx, decoder, depth+1, elementType); err != nil {
				return nil, err
			}
		}
		if _, err := decoder.Token(); err != nil {
			return nil, metadataError("metadata_json_invalid")
		}
		return nil, nil
	}
	seen := map[string]bool{}
	var fields map[string]reflect.Type
	if structured {
		fields = jsonFields(recordType)
	}
	for decoder.More() {
		keyToken, err := decoder.Token()
		key, ok := keyToken.(string)
		if err != nil || !ok {
			return nil, metadataError("metadata_json_invalid")
		}
		if seen[key] {
			return nil, metadataError("metadata_json_duplicate_key")
		}
		seen[key] = true
		fieldType := fields[key]
		if recordType != nil && recordType.Kind() == reflect.Map {
			fieldType = recordType.Elem()
		}
		if structured && fieldType == nil {
			return nil, metadataError("metadata_json_unknown_or_aliased_field")
		}
		if _, err := scanMetadataJSON(ctx, decoder, depth+1, fieldType); err != nil {
			return nil, err
		}
	}
	if _, err := decoder.Token(); err != nil {
		return nil, metadataError("metadata_json_invalid")
	}
	return seen, nil
}

func validateMetadataJSON(ctx context.Context, data []byte, recordType reflect.Type) (map[string]bool, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	seen, err := scanMetadataJSON(ctx, decoder, 0, recordType)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, metadataError("metadata_json_trailing_or_invalid")
	}
	return seen, nil
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
	if !seen["schema_version"] && result.Status == "processed" {
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
	return result, nil
}
