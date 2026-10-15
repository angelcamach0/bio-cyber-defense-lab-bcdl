// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"sync"
)

const maxPipelineStdoutBytes = 1 << 20
const maxEvaluatorStdoutBytes = 1 << 20
const maxCommandStderrBytes = 64 << 10

var errCommandOutputLimit = errors.New("command_output_limit")

// Cmd's context watcher may already have finished after the leader exits while
// descendants still own its output pipes. Also kill the retained group directly.
func outputLimitCancellation(command *exec.Cmd, cancel context.CancelFunc) context.CancelFunc {
	return func() {
		cancel()
		if command.Process != nil && command.Cancel != nil {
			_ = command.Cancel()
		}
	}
}

// Each exec copy goroutine gets its own bounded capture. Crossing the limit
// cancels the command context, whose Cancel kills the entire process group.
// A truncated JSON prefix is never returned as an accepted pipeline/evaluation.
type outputCapture struct {
	mu       sync.Mutex
	data     []byte
	maximum  int
	exceeded bool
	cancel   context.CancelFunc
}

func newOutputCapture(maximum int, cancel context.CancelFunc) *outputCapture {
	return &outputCapture{maximum: maximum, cancel: cancel}
}

func (capture *outputCapture) Write(data []byte) (int, error) {
	capture.mu.Lock()
	if capture.exceeded {
		capture.mu.Unlock()
		return 0, errCommandOutputLimit
	}
	remaining := capture.maximum - len(capture.data)
	if len(data) <= remaining {
		capture.data = append(capture.data, data...)
		capture.mu.Unlock()
		return len(data), nil
	}
	capture.data = append(capture.data, data[:remaining]...)
	capture.exceeded = true
	capture.mu.Unlock()
	if capture.cancel != nil {
		capture.cancel()
	}
	return remaining, errCommandOutputLimit
}

func (capture *outputCapture) Exceeded() bool {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return capture.exceeded
}

func (capture *outputCapture) Bytes() []byte {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return append([]byte(nil), capture.data...)
}

func (capture *outputCapture) String() string {
	return string(capture.Bytes())
}

// The producer and Results API share the 16 MiB result size contract. A resource
// failure produces an explicit small terminal envelope, never truncated JSON or
// a scientifically approved record with missing output. Input provenance and
// established crypto flags survive; oversized derived fields are not persisted.
func boundedResultRecord(result resultRecord) (resultRecord, []byte, error) {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return result, nil, metadataError("metadata_result_encode_failed")
	}
	if len(data) <= maxResultMetadataBytes {
		return result, data, nil
	}
	failure := resultRecord{
		SchemaVersion: 1, SecurityMode: result.SecurityMode, PipelineMode: result.PipelineMode,
		JobID: result.JobID, Status: "failed", ProcessedAt: result.ProcessedAt,
		UploadSHA256: result.UploadSHA256, ProcessedSHA256: result.ProcessedSHA256,
		SizeBytes: result.SizeBytes, Decrypted: result.Decrypted,
		SignatureValid: result.SignatureValid, ClientCertSerial: result.ClientCertSerial,
		ArtifactExecution: result.ArtifactExecution,
		ReleaseStatus:     "withheld", ErrorCode: "result_metadata_too_large",
		ErrorMessage: "derived result exceeds the supported metadata size",
		Detection:    detectionResult{Reason: "result withheld after metadata size failure"},
	}
	data, err = json.MarshalIndent(failure, "", "  ")
	if err != nil || len(data) > maxResultMetadataBytes {
		return failure, nil, metadataError("metadata_result_failure_encode_failed")
	}
	return failure, data, nil
}
