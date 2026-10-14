// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

var uploadTestPayload = []byte("@r\nACGT\n+\nIIII\n")

func uploadTestCert() *x509.Certificate {
	return &x509.Certificate{Subject: pkix.Name{CommonName: "researcher-a"}, SerialNumber: big.NewInt(1)}
}

func multipartUpload(t *testing.T, fields map[string]string) *http.Request {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", "reads.fastq")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(uploadTestPayload); err != nil {
		t.Fatal(err)
	}
	for name, value := range fields {
		if err := writer.WriteField(name, value); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/upload", &body)
	r.Header.Set("Content-Type", writer.FormDataContentType())
	cert := uploadTestCert()
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
	return r
}

func uploadHandlerFixture(t *testing.T, jobKey string) (http.Handler, string, string) {
	t.Helper()
	t.Setenv("BIOZERO_SECURITY_MODE", "protected")
	root := t.TempDir()
	uploads, jobs := filepath.Join(root, "uploads"), filepath.Join(root, "jobs")
	if err := os.Mkdir(uploads, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(jobs, 0700); err != nil {
		t.Fatal(err)
	}
	return newUploadHandler(uploads, jobs, 8<<20, jobKey, newRateLimiter(1000, time.Minute)), uploads, jobs
}

func expectedUploadJob(fields map[string]string, wrapped string) jobRecord {
	cert := uploadTestCert()
	hash := sha256.Sum256(uploadTestPayload)
	job := jobRecord{JobID: "abcdef0123456789", Status: "uploaded", UploadedAt: "2026-10-14T00:00:00Z",
		OriginalName: "reads.fastq", SizeBytes: int64(len(uploadTestPayload)), SHA256: hex.EncodeToString(hash[:]),
		ClientID: "researcher-a", ClientCertSubject: cert.Subject.String(), ClientCertIssuer: cert.Issuer.String(),
		ClientCertSerial: "1", EncAlg: fields["enc_alg"], EncKey: fields["enc_key"], SigAlg: fields["sig_alg"], Sig: fields["sig"]}
	if wrapped != "" {
		job.EncKey, job.EncKeyWrapped, job.EncKeyWrapAlg = wrapped, true, "aes-256-gcm"
	}
	return job
}

func assertUploadEntries(t *testing.T, path string, expected int) {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) != expected {
		t.Fatalf("entries=%d expected=%d err=%v", len(entries), expected, err)
	}
}

func TestUploadProjectedLifecycleMetadataExactBoundary(t *testing.T) {
	for _, variant := range []string{"ascii", "escaped", "wrapped"} {
		for _, target := range []int{maxJobMetadataBytes, maxJobMetadataBytes + 1} {
			t.Run(variant+"/"+string(rune(target-maxJobMetadataBytes+'0')), func(t *testing.T) {
				fields := map[string]string{"sig": "x", "sig_alg": "rsa-pss-sha256"}
				jobKey, wrapped := "", ""
				if variant == "escaped" {
					fields["sig"] = strings.Repeat("<&>\"\\\n", 128)
				}
				if variant == "wrapped" {
					jobKey = strings.Repeat("01", 32)
					fields["enc_key"], fields["enc_alg"] = strings.Repeat("K", 45000), "aes-256-gcm+rsa-oaep-sha256"
					var err error
					wrapped, err = wrapSensitiveValue(fields["enc_key"], jobKey)
					if err != nil {
						t.Fatal(err)
					}
				}
				baseline, _ := projectedJobJSON(expectedUploadJob(fields, wrapped))
				if len(baseline) >= target {
					t.Fatal("boundary fixture baseline too large")
				}
				fields["sig"] += strings.Repeat("x", target-len(baseline))
				expected, _ := projectedJobJSON(expectedUploadJob(fields, wrapped))
				if len(expected) != target {
					t.Fatalf("fixture bytes=%d target=%d", len(expected), target)
				}
				handler, uploads, jobs := uploadHandlerFixture(t, jobKey)
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, multipartUpload(t, fields))
				if target > maxJobMetadataBytes {
					var errorBody errorResponse
					json.Unmarshal(response.Body.Bytes(), &errorBody)
					if response.Code != http.StatusRequestEntityTooLarge || errorBody.Code != "metadata_too_large" {
						t.Fatalf("oversize response=%d %s", response.Code, response.Body.String())
					}
					assertUploadEntries(t, uploads, 0)
					assertUploadEntries(t, jobs, 0)
					// Rejected metadata must not poison the next ordinary upload.
					next := httptest.NewRecorder()
					handler.ServeHTTP(next, multipartUpload(t, nil))
					if next.Code != http.StatusOK {
						t.Fatal("next valid request failed", next.Code)
					}
					assertUploadEntries(t, uploads, 1)
					assertUploadEntries(t, jobs, 1)
					return
				}
				if response.Code != http.StatusOK {
					t.Fatalf("exact limit rejected=%d %s", response.Code, response.Body.String())
				}
				var acknowledgement map[string]string
				json.Unmarshal(response.Body.Bytes(), &acknowledgement)
				data, err := os.ReadFile(filepath.Join(jobs, acknowledgement["job_id"]+".json"))
				actualInput, _ := json.MarshalIndent(expectedUploadJob(fields, wrapped), "", "  ")
				if err != nil || len(data) != len(actualInput) || len(data) >= target {
					t.Fatalf("persisted bytes=%d expected input=%d projected=%d err=%v", len(data), len(actualInput), target, err)
				}
				var persisted jobRecord
				if err := json.Unmarshal(data, &persisted); err != nil || persisted.ClientID != "researcher-a" || persisted.Sig != fields["sig"] {
					t.Fatal("metadata fields or owner changed", err)
				}
				if variant == "wrapped" && (!persisted.EncKeyWrapped || len(persisted.EncKey) != len(wrapped)) {
					t.Fatal("wrapped expansion absent")
				}
				worst, err := projectedJobJSON(persisted)
				if err != nil || len(worst) != maxJobMetadataBytes {
					t.Fatal("accepted boundary does not reserve exact lifecycle budget", len(worst), err)
				}
				info, _ := os.Stat(filepath.Join(jobs, acknowledgement["job_id"]+".json"))
				if info.Mode().Perm() != 0600 {
					t.Fatal("job permissions")
				}
				assertUploadEntries(t, uploads, 1)
				assertUploadEntries(t, jobs, 1)
			})
		}
	}
}

func TestUploadMetadataExpansionAndWrappingFailureLeaveNoPayload(t *testing.T) {
	for _, scenario := range []struct {
		name, key, field, value, code string
		status                        int
	}{
		{"signature", "", "sig", strings.Repeat("x", 65536), "metadata_too_large", 413},
		{"algorithm", "", "enc_alg", strings.Repeat("x", 65536), "metadata_too_large", 413},
		{"plain_key", "", "enc_key", strings.Repeat("x", 65536), "metadata_too_large", 413},
		{"escaped_growth", "", "sig", strings.Repeat("<", 12000), "metadata_too_large", 413},
		{"wrapped_growth", strings.Repeat("01", 32), "enc_key", strings.Repeat("K", 50000), "metadata_too_large", 413},
		{"wrap_error", "not-a-key", "enc_key", "PRIVATE key material", "enc_key_wrap_failed", 500},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			handler, uploads, jobs := uploadHandlerFixture(t, scenario.key)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, multipartUpload(t, map[string]string{scenario.field: scenario.value}))
			var result errorResponse
			json.Unmarshal(response.Body.Bytes(), &result)
			if response.Code != scenario.status || result.Code != scenario.code || strings.Contains(response.Body.String(), "PRIVATE") {
				t.Fatalf("response=%d %s", response.Code, response.Body.String())
			}
			assertUploadEntries(t, uploads, 0)
			assertUploadEntries(t, jobs, 0)
		})
	}
}

func TestUploadPersistenceErrorDoesNotBroadlyDeletePayload(t *testing.T) {
	handler, uploads, jobs := uploadHandlerFixture(t, "")
	if err := os.Remove(jobs); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, multipartUpload(t, nil))
	var result errorResponse
	json.Unmarshal(response.Body.Bytes(), &result)
	if response.Code != http.StatusInternalServerError || result.Code != "job_write_failed" {
		t.Fatal("persistence failure did not fail acknowledgement")
	}
	assertUploadEntries(t, uploads, 1)
}

func TestAcceptedLifecycleBoundaryProcessesInActualWorker(t *testing.T) {
	fields := map[string]string{"sig": "x", "sig_alg": "rsa-pss-sha256"}
	base, _ := projectedJobJSON(expectedUploadJob(fields, ""))
	fields["sig"] += strings.Repeat("x", maxJobMetadataBytes-len(base))
	handler, uploads, jobs := uploadHandlerFixture(t, "")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, multipartUpload(t, fields))
	if response.Code != http.StatusOK {
		t.Fatal("projected boundary admission failed", response.Code)
	}
	var ack map[string]string
	json.Unmarshal(response.Body.Bytes(), &ack)
	jobPath := filepath.Join(jobs, ack["job_id"]+".json")
	before, err := os.ReadFile(jobPath)
	if err != nil {
		t.Fatal(err)
	}
	var admitted jobRecord
	json.Unmarshal(before, &admitted)
	projected, _ := projectedJobJSON(admitted)
	if len(projected) != maxJobMetadataBytes || admitted.Sig != fields["sig"] {
		t.Fatal("admission projection or signature changed")
	}
	binary := filepath.Join(t.TempDir(), "worker")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	build := exec.CommandContext(ctx, "go", "build", "-o", binary, ".")
	build.Dir = "../enclave-runner"
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatal("actual worker build failed", err, string(output))
	}
	root := filepath.Dir(uploads)
	marker := filepath.Join(root, "pipeline-called")
	pipeline := filepath.Join(root, "pipeline.sh")
	if err := os.WriteFile(pipeline, []byte("#!/bin/sh\ntouch '"+marker+"'\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	worker := exec.Command(binary)
	worker.Env = append(os.Environ(), "BIOZERO_DATA_DIR="+root, "BIOZERO_SECURITY_MODE=protected",
		"BIOZERO_SECURITY_EVENTS_DIR=", "BIOZERO_POLL_SECONDS=0.01", "BIOZERO_PIPELINE_PATH="+pipeline,
		"BIOZERO_RULES_PATH="+filepath.Join(root, "absent-rules"), "BIOZERO_SIGNER_CERT="+filepath.Join(root, "absent-signer"))
	if err := worker.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if worker.ProcessState == nil {
			worker.Process.Kill()
			worker.Wait()
		}
	}()
	var terminal []byte
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(jobPath)
		var record struct {
			Status string `json:"status"`
		}
		if err == nil && json.Unmarshal(data, &record) == nil && record.Status == "rejected" {
			terminal = data
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if terminal == nil || len(terminal) > maxJobMetadataBytes {
		t.Fatal("accepted boundary grew unreadable or failed to reach terminal")
	}
	var jobState struct {
		jobRecord
		StartedAt string `json:"started_at"`
		ErrorCode string `json:"error_code"`
	}
	if err := json.Unmarshal(terminal, &jobState); err != nil || jobState.ErrorCode != "signature_invalid" || len(jobState.StartedAt) != 20 ||
		jobState.Sig != admitted.Sig || jobState.SHA256 != admitted.SHA256 || jobState.SizeBytes != admitted.SizeBytes {
		t.Fatal("terminal job changed immutable upload/signature/size", err)
	}
	resultPath := filepath.Join(root, "results", admitted.JobID+".json")
	var result struct {
		Status    string `json:"status"`
		ErrorCode string `json:"error_code"`
	}
	resultJSON, err := os.ReadFile(resultPath)
	if err != nil || json.Unmarshal(resultJSON, &result) != nil || result.Status != "rejected" || result.ErrorCode != "signature_invalid" {
		t.Fatal("full persisted result missing", err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("boundary rejection invoked pipeline")
	}
	if err := worker.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- worker.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal("worker did not exit cleanly", err)
		}
	case <-time.After(3 * time.Second):
		worker.Process.Kill()
		<-done
		t.Fatal("worker did not stop after lifecycle boundary test")
	}
}
