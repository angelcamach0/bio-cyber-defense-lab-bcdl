//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package receiptprojection

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
)

const MaxMetadataDepth = 64

func metadataError(code string) error { return errors.New(code) }

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
	if recordType != nil && recordType.Kind() == reflect.Ptr {
		if token == nil {
			return nil, metadataError("metadata_json_scalar_null")
		}
		recordType = recordType.Elem()
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
	if depth >= MaxMetadataDepth {
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

func ValidateMetadataJSON(ctx context.Context, data []byte, recordType reflect.Type) (map[string]bool, error) {
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

// ArtifactExecution binds a projected private result to retained broker objects.
// It is not authority to open files and is not a scientific-release proof.
type ArtifactExecution struct {
	SchemaVersion  int                     `json:"schema_version"`
	ProfileSHA256  string                  `json:"profile_sha256"`
	StoreID        string                  `json:"store_id"`
	LeaseID        string                  `json:"lease_id"`
	ManifestSHA256 string                  `json:"manifest_sha256"`
	ReceiptSHA256  string                  `json:"receipt_sha256"`
	ReceiptBytes   int64                   `json:"receipt_bytes"`
	Files          map[string]ArtifactFile `json:"files"`
}
type ArtifactFile struct {
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

func ArtifactHex(value string, size int) bool {
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
func ArtifactObject(raw []byte, keys ...string) (map[string]json.RawMessage, bool) {
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
func ValidateArtifactExecution(raw []byte, status, release string) (*ArtifactExecution, error) {
	invalid := func() (*ArtifactExecution, error) { return nil, errors.New("metadata_artifact_execution_invalid") }
	object, ok := ArtifactObject(raw, "schema_version", "profile_sha256", "store_id", "lease_id", "manifest_sha256", "receipt_sha256", "receipt_bytes", "files")
	if !ok {
		return invalid()
	}
	var binding ArtifactExecution
	if json.Unmarshal(raw, &binding) != nil || binding.SchemaVersion != 1 || !ArtifactHex(binding.ProfileSHA256, 64) || !ArtifactHex(binding.StoreID, 32) || !ArtifactHex(binding.LeaseID, 32) || !ArtifactHex(binding.ManifestSHA256, 64) || binding.Files == nil || len(binding.Files) > 4 || binding.ReceiptBytes < 0 || binding.ReceiptBytes > 16<<20 {
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
		if _, ok := ArtifactObject(entry, "sha256", "bytes"); !ok {
			return invalid()
		}
		file := binding.Files[id]
		if !ArtifactHex(file.SHA256, 64) || file.Bytes < 0 || file.Bytes > 64<<20 || total > (64<<20)-file.Bytes {
			return invalid()
		}
		total += file.Bytes
	}
	receipt, hasReceipt := binding.Files["execution_receipt"]
	if !hasReceipt {
		if binding.ReceiptSHA256 != "" || binding.ReceiptBytes != 0 || len(binding.Files) != 0 || status != "failed" || release != "withheld" {
			return invalid()
		}
	} else if !ArtifactHex(binding.ReceiptSHA256, 64) || binding.ReceiptBytes <= 0 || receipt.Bytes != binding.ReceiptBytes || receipt.SHA256 != binding.ReceiptSHA256 {
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
