// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const maxSecurityEventBytes = 64 << 10
const maxSecurityResultBytes = 16 << 20

// securityEvent is a minimal, local quarantine intent. Publication is not an
// acknowledgement of relay delivery or execution of a response action.
type securityEvent struct {
	SchemaVersion int                     `json:"schema_version"`
	AlertID       string                  `json:"alert_id"`
	Source        string                  `json:"source"`
	EventCode     string                  `json:"event_code"`
	Severity      string                  `json:"severity"`
	Timestamp     string                  `json:"timestamp"`
	Indicators    securityEventIndicators `json:"indicators"`
	Actions       []string                `json:"actions"`
}

type securityEventIndicators struct {
	JobID string `json:"job_id"`
}

func securityEventError(code string) error { return errors.New(code) }

func protectedRejectionEvent(result resultRecord) (securityEvent, bool, error) {
	if result.SchemaVersion != 1 || result.SecurityMode != "protected" || result.Status != "rejected" {
		return securityEvent{}, false, nil
	}
	switch result.ErrorCode {
	case "upload_integrity_failed", "signature_required", "signature_algorithm_invalid", "signature_invalid",
		"encryption_required", "encryption_metadata_invalid", "key_unwrap_failed", "decryption_failed":
	default:
		return securityEvent{}, false, nil
	}
	if !isValidJobID(result.JobID) {
		return securityEvent{}, false, securityEventError("event_result_job_id_invalid")
	}
	parsed, err := time.Parse(time.RFC3339, result.ProcessedAt)
	if err != nil || len(result.ProcessedAt) != 20 || parsed.UTC().Format(time.RFC3339) != result.ProcessedAt {
		return securityEvent{}, false, securityEventError("event_result_timestamp_invalid")
	}
	id := sha256.Sum256([]byte("enclave-runner/" + result.JobID + "/" + result.ErrorCode))
	return securityEvent{SchemaVersion: 1, AlertID: "evt-" + hex.EncodeToString(id[:]), Source: "enclave-runner",
		EventCode: result.ErrorCode, Severity: "high", Timestamp: result.ProcessedAt,
		Indicators: securityEventIndicators{JobID: result.JobID}, Actions: []string{"quarantine"}}, true, nil
}

// openSecurityEventsDirectory rejects symlinks and nonprivate permissions. The
// returned descriptor anchors publication to this directory even if renamed.
// Linux /proc/self/fd and same-filesystem hard links are required; this worker
// deliberately has a single writer. No network calls or delivery receipts here.
func openSecurityEventsDirectory(path string) (*os.File, error) {
	if strings.TrimSpace(path) == "" {
		return nil, securityEventError("event_directory_invalid")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, securityEventError("event_directory_invalid")
	}
	descriptor, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, securityEventError("event_directory_open_failed")
	}
	for _, component := range strings.Split(strings.TrimPrefix(absolute, string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" {
			continue
		}
		child, openErr := syscall.Openat(descriptor, component, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if openErr == syscall.ENOENT {
			if err := syscall.Mkdirat(descriptor, component, 0700); err != nil && err != syscall.EEXIST {
				syscall.Close(descriptor)
				return nil, securityEventError("event_directory_create_failed")
			}
			child, openErr = syscall.Openat(descriptor, component, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		}
		if openErr != nil {
			syscall.Close(descriptor)
			return nil, securityEventError("event_directory_unsafe")
		}
		// Persist ancestor entries, including a directory created by a prior
		// attempt whose parent sync failed. Presence alone is insufficient.
		if err := syscall.Fsync(descriptor); err != nil {
			syscall.Close(child)
			syscall.Close(descriptor)
			return nil, securityEventError("event_directory_parent_sync_failed")
		}
		syscall.Close(descriptor)
		descriptor = child
	}
	dir := os.NewFile(uintptr(descriptor), absolute)
	info, err := dir.Stat()
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		dir.Close()
		return nil, securityEventError("event_directory_permissions_invalid")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Uid != uint32(os.Geteuid()) {
		dir.Close()
		return nil, securityEventError("event_directory_owner_invalid")
	}
	return dir, nil
}

func openBoundedSecurityFile(path string, maximum int64, private bool) (*os.File, []byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maximum {
		file.Close()
		return nil, nil, securityEventError("event_file_unsafe")
	}
	if private && (info.Mode().Perm() != 0600 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0) {
		file.Close()
		return nil, nil, securityEventError("event_file_permissions_invalid")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); private && (!ok || stat.Uid != uint32(os.Geteuid())) {
		file.Close()
		return nil, nil, securityEventError("event_file_owner_invalid")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) > maximum {
		file.Close()
		return nil, nil, securityEventError("event_file_read_failed")
	}
	return file, data, nil
}

// uniqueJSON rejects ambiguous duplicate keys in either the envelope or nested
// indicators. Equality below also rejects extra fields, nulls and altered data.
func uniqueJSON(decoder *json.Decoder) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	switch token {
	case json.Delim('{'):
		object := map[string]any{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			key, ok := keyToken.(string)
			if err != nil || !ok {
				return nil, securityEventError("event_json_invalid")
			}
			if _, duplicate := object[key]; duplicate {
				return nil, securityEventError("event_json_duplicate_key")
			}
			value, err := uniqueJSON(decoder)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		_, err = decoder.Token()
		return object, err
	case json.Delim('['):
		array := []any{}
		for decoder.More() {
			value, err := uniqueJSON(decoder)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		_, err = decoder.Token()
		return array, err
	default:
		return token, nil
	}
}

func exactSecurityEvent(data []byte, expected securityEvent) bool {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	value, err := uniqueJSON(decoder)
	if err != nil {
		return false
	}
	if _, err := decoder.Token(); err != io.EOF {
		return false
	}
	want, err := json.Marshal(expected)
	if err != nil {
		return false
	}
	wantDecoder := json.NewDecoder(bytes.NewReader(want))
	wantDecoder.UseNumber()
	wantValue, err := uniqueJSON(wantDecoder)
	return err == nil && reflect.DeepEqual(value, wantValue)
}

func validateExistingSecurityEvent(path string, expected securityEvent, dir *os.File) error {
	file, data, err := openBoundedSecurityFile(path, maxSecurityEventBytes, true)
	if err != nil {
		return securityEventError("event_existing_unsafe")
	}
	defer file.Close()
	if !exactSecurityEvent(data, expected) {
		return securityEventError("event_existing_conflict")
	}
	// An earlier publish may have linked successfully but failed fsync. Retry
	// durability, rather than treating mere presence as an acknowledgement.
	if err := file.Sync(); err != nil {
		return securityEventError("event_existing_sync_failed")
	}
	if err := dir.Sync(); err != nil {
		return securityEventError("event_directory_sync_failed")
	}
	return nil
}

func publishSecurityEvent(dir *os.File, event securityEvent) error {
	base := "/proc/self/fd/" + strconv.FormatUint(uint64(dir.Fd()), 10)
	target := filepath.Join(base, event.AlertID+".json")
	if _, err := os.Lstat(target); err == nil {
		return validateExistingSecurityEvent(target, event, dir)
	} else if !os.IsNotExist(err) {
		return securityEventError("event_existing_stat_failed")
	}
	data, err := json.MarshalIndent(event, "", "  ")
	if err != nil {
		return securityEventError("event_encode_failed")
	}
	file, err := os.CreateTemp(base, ".security-event-*.tmp")
	if err != nil {
		return securityEventError("event_temp_create_failed")
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write(data)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return securityEventError("event_temp_write_or_sync_failed")
	}
	// Link publishes atomically and refuses an existing target. Rename alone
	// would overwrite conflicting evidence. Both names remain on one filesystem.
	if err := os.Link(temporary, target); err != nil {
		if os.IsExist(err) {
			return validateExistingSecurityEvent(target, event, dir)
		}
		return securityEventError("event_publish_failed")
	}
	if err := os.Remove(temporary); err != nil {
		return securityEventError("event_temp_cleanup_failed")
	}
	if err := dir.Sync(); err != nil {
		return securityEventError("event_directory_sync_failed")
	}
	return nil
}

func emitPersistedSecurityEvent(result resultRecord) error {
	path := os.Getenv("BIOZERO_SECURITY_EVENTS_DIR")
	if path == "" {
		return nil
	}
	event, applicable, err := protectedRejectionEvent(result)
	if err != nil || !applicable {
		return err
	}
	dir, err := openSecurityEventsDirectory(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return publishSecurityEvent(dir, event)
}

// Reconcile independent of job status, including after restart, unavailable
// outbox storage, or a crash between result persistence and event publication.
// Persisted results remain the retry source; no pipeline is re-executed.
func reconcileSecurityEvents(ctx context.Context, resultsDir string) {
	path := os.Getenv("BIOZERO_SECURITY_EVENTS_DIR")
	if path == "" || ctx.Err() != nil {
		return
	}
	dir, err := openSecurityEventsDirectory(path)
	if err != nil {
		log.Printf("security outbox error: %s", err)
		return
	}
	defer dir.Close()
	entries, err := os.ReadDir(resultsDir)
	if err != nil {
		log.Print("security outbox error: event_results_scan_failed")
		return
	}
	for _, entry := range entries {
		if ctx.Err() != nil {
			return
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		jobID := strings.TrimSuffix(entry.Name(), ".json")
		if !isValidJobID(jobID) {
			continue
		}
		file, data, err := openBoundedSecurityFile(filepath.Join(resultsDir, entry.Name()), maxSecurityResultBytes, false)
		if err != nil {
			log.Print("security outbox error: event_result_read_failed")
			continue
		}
		file.Close()
		var result resultRecord
		if json.Unmarshal(data, &result) != nil || result.JobID != jobID {
			log.Print("security outbox error: event_result_invalid")
			continue
		}
		event, applicable, err := protectedRejectionEvent(result)
		if err == nil && applicable {
			err = publishSecurityEvent(dir, event)
		}
		if err != nil {
			log.Printf("security outbox error: %s", err)
		}
	}
}
