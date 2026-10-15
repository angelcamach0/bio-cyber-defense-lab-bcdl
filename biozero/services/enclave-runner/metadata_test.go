// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func metadataFixture(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "metadata.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func validResultBytes(t *testing.T) []byte {
	t.Helper()
	result := rejectionFixture()
	result.ErrorCode = "signature_required"
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestMetadataFilesRejectFIFOFinalAndAncestorSymlinks(t *testing.T) {
	valid := []byte(`{"job_id":"abcd1234","status":"uploaded"}`)
	for _, kind := range []string{"fifo", "final_symlink", "ancestor_symlink", "directory", "bad_mode", "bad_owner"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "record.json")
			switch kind {
			case "fifo":
				if err := syscall.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			case "final_symlink":
				target := metadataFixture(t, valid)
				os.Symlink(target, path)
			case "ancestor_symlink":
				target := metadataFixture(t, valid)
				link := filepath.Join(root, "alias")
				os.Symlink(filepath.Dir(target), link)
				path = filepath.Join(link, filepath.Base(target))
			case "directory":
				os.Mkdir(path, 0700)
			case "bad_mode":
				os.WriteFile(path, valid, 0644)
			case "bad_owner":
				os.WriteFile(path, valid, 0600)
				if os.Geteuid() != 0 {
					t.Skip("Changing a fixture owner requires root; owner check reviewed statically on nonroot host")
				}
				if err := os.Chown(path, 65534, -1); err != nil {
					t.Fatal(err)
				}
			}
			start := time.Now()
			_, err := readJobContext(context.Background(), path)
			if err == nil || os.IsNotExist(err) || time.Since(start) > time.Second {
				t.Fatalf("unsafe metadata accepted or blocked: %v", err)
			}
			if strings.Contains(err.Error(), root) {
				t.Fatal("private path reflected in metadata error")
			}
		})
	}
}

func TestMetadataSparseOversizeAndExactBounds(t *testing.T) {
	for _, maximum := range []int64{maxJobMetadataBytes, maxResultMetadataBytes} {
		path := filepath.Join(t.TempDir(), "sparse.json")
		file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Truncate(maximum + 1); err != nil {
			t.Fatal(err)
		}
		file.Close()
		if _, err := readMetadataFile(context.Background(), path, maximum); err == nil || err.Error() != "metadata_file_size_exceeded" {
			t.Fatal("sparse oversized metadata accepted", err)
		}
	}
	body := []byte(`{"job_id":"abcd1234","status":"uploaded"}`)
	body = append(body, bytes.Repeat([]byte(" "), maxJobMetadataBytes-len(body))...)
	if _, err := readJobContext(context.Background(), metadataFixture(t, body)); err != nil {
		t.Fatal("exactly bounded valid metadata rejected", err)
	}
}

func TestMetadataJobStrictJSONContract(t *testing.T) {
	for _, body := range []string{
		`{"job_id":"abcd1234","status":"uploaded","status":"failed"}`,
		`{"job_id":"abcd1234","status":"uploaded","client_id":"a","client_id":"b"}`,
		`{"job_id":"abcd1234","status":"uploaded","Status":"failed"}`,
		`{"job_id":"abcd1234","status":"uploaded","CLIENT_ID":"b"}`,
		`{"job_id":"abcd1234","status":"uploaded","future_unknown":true}`,
		`{"job_id":"abcd1234","status":"uploaded"} {}`,
		`{"job_id":"abcd1234","status":null}`,
		`{"job_id":"abcd1234","status":"uploaded","sha256":null}`,
		`{"job_id":"abcd1234","status":"uploaded","size_bytes":"large"}`,
		`{"job_id":"abcd1234","status":"unknown"}`,
		`{"status":"uploaded"}`, `{"job_id":"../private","status":"uploaded"}`, `null`, `[]`,
	} {
		if _, err := readJobContext(context.Background(), metadataFixture(t, []byte(body))); err == nil {
			t.Fatal("ambiguous/invalid job accepted", body)
		}
	}
	job, err := readJobContext(context.Background(), metadataFixture(t, []byte(`{"job_id":"abcd1234","status":"uploaded","enc_key":"wrapped:v1","enc_key_wrapped":true,"client_id":"researcher-a","client_cert_serial":"001"}`)))
	if err != nil || job.EncKey != "wrapped:v1" || !job.EncKeyWrapped || job.ClientCertSerial != "001" {
		t.Fatal("known fields changed or dropped", err)
	}
}

func TestMetadataResultRequiredFieldsAndExplicitLegacy(t *testing.T) {
	valid := validResultBytes(t)
	var fields map[string]json.RawMessage
	json.Unmarshal(valid, &fields)
	for _, name := range []string{"schema_version", "security_mode", "pipeline_mode", "processed_at", "upload_sha256", "processed_sha256",
		"size_bytes", "decrypted", "signature_valid", "release_status", "detection"} {
		copyFields := map[string]json.RawMessage{}
		for key, value := range fields {
			if key != name {
				copyFields[key] = value
			}
		}
		body, _ := json.Marshal(copyFields)
		if _, err := readResultContext(context.Background(), metadataFixture(t, body)); err == nil {
			t.Fatal("schema1 missing required field accepted", name)
		}
	}
	for _, body := range []string{`{"job_id":"abcd1234","status":"succeeded"}`, `{"job_id":"abcd1234","status":"failed"}`,
		`{"schema_version":0,"job_id":"abcd1234","status":"processed"}`} {
		if _, err := readResultContext(context.Background(), metadataFixture(t, []byte(body))); err == nil {
			t.Fatal("unversioned nonlegacy/unsupported schema accepted")
		}
	}
	for _, status := range []string{"uploaded", "running"} {
		body := bytes.Replace(valid, []byte(`"status":"rejected"`), []byte(`"status":"`+status+`"`), 1)
		if _, err := readResultContext(context.Background(), metadataFixture(t, body)); err == nil {
			t.Fatal("nonterminal result accepted", status)
		}
	}
	legacy, err := readResultContext(context.Background(), metadataFixture(t, []byte(`{"job_id":"abcd1234","status":"processed"}`)))
	if err != nil || legacy.Status != "processed" || legacy.SchemaVersion != 0 {
		t.Fatal("explicit legacy processed compatibility lost", err)
	}
	for _, body := range [][]byte{bytes.Replace(valid, []byte(`"status":"rejected"`), []byte(`"status":"processed"`), 1), valid} {
		if _, err := readResultContext(context.Background(), metadataFixture(t, body)); err != nil {
			t.Fatal("complete schema1 rejected/legacy result rejected", err)
		}
	}
}

func TestMetadataScientificRawPayloadPreservedAndDuplicatesRejected(t *testing.T) {
	result := rejectionFixture()
	raw := json.RawMessage(`{ "output_dir" : null, "A":1, "a":2, "stages" : [] }`)
	result.PipelineOutput = raw
	result.ScientificEvaluation = json.RawMessage(`{ "value":null, "verdict":"failed" }`)
	data, _ := json.Marshal(result)
	// Replace the compact raw value with whitespace-bearing original bytes.
	compact := bytes.Buffer{}
	json.Compact(&compact, raw)
	data = bytes.Replace(data, compact.Bytes(), raw, 1)
	decoded, err := readResultContext(context.Background(), metadataFixture(t, data))
	if err != nil || !bytes.Equal(decoded.PipelineOutput, raw) {
		t.Fatal("raw payload bytes/null/case-sensitive scientific keys changed", err)
	}
	for _, mutation := range []func([]byte) []byte{
		func(body []byte) []byte { return append([]byte(`{"status":"rejected",`), body[1:]...) },
		func(body []byte) []byte { return append([]byte(`{"Client_cert_serial":"wrong",`), body[1:]...) },
		func(body []byte) []byte {
			return bytes.Replace(body, []byte(`"score":0`), []byte(`"score":0,"Score":1`), 1)
		},
		func(body []byte) []byte {
			return bytes.Replace(body, []byte(`"score":0`), []byte(`"score":0,"score":1`), 1)
		},
		func(body []byte) []byte { return bytes.Replace(body, []byte(`"score":0`), []byte(`"score":null`), 1) },
		func(body []byte) []byte {
			return bytes.Replace(body, []byte(`"score":0`), []byte(`"score":0,"signals":null`), 1)
		},
		func(body []byte) []byte {
			return bytes.Replace(body, []byte(`"score":0`), []byte(`"score":0,"reasons":null`), 1)
		},
		func(body []byte) []byte {
			return bytes.Replace(body, []byte(`"score":0`), []byte(`"score":0,"reasons":[null]`), 1)
		},
		func(body []byte) []byte {
			return bytes.Replace(body, []byte(`"output_dir" : null`), []byte(`"output_dir":null,"output_dir":null`), 1)
		},
		func(body []byte) []byte { return append(body, []byte(` null`)...) },
	} {
		if _, err := readResultContext(context.Background(), metadataFixture(t, mutation(data))); err == nil {
			t.Fatal("duplicate/alias/trailing scientific metadata accepted")
		}
	}
}

func TestMetadataDepthBoundAcrossRawScientificPayload(t *testing.T) {
	for _, arrays := range []int{63, 64} {
		result := rejectionFixture()
		result.PipelineOutput = json.RawMessage(strings.Repeat("[", arrays) + "0" + strings.Repeat("]", arrays))
		data, _ := json.Marshal(result)
		_, err := readResultContext(context.Background(), metadataFixture(t, data))
		if (arrays == 63 && err != nil) || (arrays == 64 && (err == nil || err.Error() != "metadata_json_depth_exceeded")) {
			t.Fatalf("wrong depth boundary %d: %v", arrays+1, err)
		}
	}
}

func TestMetadataMissingAndCancellationRemainDistinct(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.json")
	if _, err := readJobContext(context.Background(), path); !os.IsNotExist(err) {
		t.Fatal("missing metadata is not IsNotExist", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := readJobContext(ctx, path); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled read performed IO", err)
	}
	if _, err := validateMetadataJSON(ctx, []byte(`{}`), nil); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled parser continued", err)
	}
}

func TestCorruptOrUnsafeResultBlocksOnlyItsJobAndDoesNotOverwrite(t *testing.T) {
	for _, fault := range []string{"fifo_job", "fifo_result", "result_duplicate", "result_symlink"} {
		t.Run(fault, func(t *testing.T) {
			t.Setenv("BIOZERO_SECURITY_MODE", "protected")
			f := newTestJob(t, `{}`, 0)
			badJob := f.job
			badJob.JobID = "aaaabbbb"
			badJobPath := filepath.Join(f.jobs, badJob.JobID+".json")
			badResultPath := filepath.Join(f.results, badJob.JobID+".json")
			var original []byte
			if fault == "fifo_job" {
				syscall.Mkfifo(badJobPath, 0600)
			} else {
				writeJSON(badJobPath, badJob)
				switch fault {
				case "fifo_result":
					syscall.Mkfifo(badResultPath, 0600)
				case "result_duplicate":
					original = []byte(`{"job_id":"aaaabbbb","status":"processed","status":"succeeded"}`)
					os.WriteFile(badResultPath, original, 0600)
				case "result_symlink":
					outside := metadataFixture(t, []byte(`{"job_id":"aaaabbbb","status":"processed"}`))
					os.Symlink(outside, badResultPath)
				}
			}
			spool := filepath.Join(f.root, "events")
			t.Setenv("BIOZERO_SECURITY_EVENTS_DIR", spool)
			start := time.Now()
			good := f.run(t, time.Second)
			if good.Status != "rejected" || good.ErrorCode != "signature_required" || time.Since(start) > 2*time.Second {
				t.Fatal("unsafe job prevented distinct valid job progress")
			}
			if fault != "fifo_job" {
				job, err := readJob(badJobPath)
				if err != nil || job.Status != "uploaded" {
					t.Fatal("corrupt result caused reexecution/job mutation", err)
				}
			}
			if original != nil {
				after, _ := os.ReadFile(badResultPath)
				if !bytes.Equal(after, original) {
					t.Fatal("corrupt result overwritten")
				}
			}
			if _, err := os.Stat(filepath.Join(f.root, "called")); !os.IsNotExist(err) {
				t.Fatal("unsafe result caused pipeline invocation")
			}
			if len(eventFiles(t, spool)) != 1 {
				t.Fatal("SOC redecoding accepted unsafe result or missed valid rejection")
			}
		})
	}
}

func TestLegacyResultRecoveryRemainsIncompleteWithoutExecution(t *testing.T) {
	f := newTestJob(t, `{}`, 0)
	writeJSON(filepath.Join(f.jobs, f.job.JobID+".json"), f.job)
	os.WriteFile(filepath.Join(f.results, f.job.JobID+".json"), []byte(`{"job_id":"abcd1234","status":"processed"}`), 0600)
	processJobs(f.jobs, f.uploads, f.results, f.decrypted, defaultRules(), "", "", f.pipeline, "", "", time.Second)
	job, err := readJob(filepath.Join(f.jobs, f.job.JobID+".json"))
	if err != nil || job.Status != "incomplete" || job.ErrorCode != "legacy_result_unverified" {
		t.Fatal("legacy processed became approved or was not recovered", err)
	}
	if _, err := os.Stat(filepath.Join(f.root, "called")); !os.IsNotExist(err) {
		t.Fatal("legacy result reran pipeline")
	}
}

func TestWorkerSignalExitsWithFIFOJobMetadata(t *testing.T) {
	f := newTestJob(t, `{}`, 0)
	if err := syscall.Mkfifo(filepath.Join(f.jobs, f.job.JobID+".json"), 0600); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	worker := exec.Command(executable, "-test.run=^TestWorkerSignalHelper$")
	worker.Env = append(os.Environ(), "BIOZERO_TEST_WORKER_HELPER=1", "BIOZERO_DATA_DIR="+f.root,
		"BIOZERO_PIPELINE_PATH="+f.pipeline, "BIOZERO_RULES_PATH="+filepath.Join(f.root, "absent-rules"),
		"BIOZERO_SECURITY_MODE=protected", "BIOZERO_EXECUTION_BACKEND=legacy", "BIOZERO_SECURITY_EVENTS_DIR=", "BIOZERO_POLL_SECONDS=0.01")
	stderr, err := worker.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if worker.ProcessState == nil {
			worker.Process.Kill()
			worker.Wait()
		}
	}()
	ready, drained := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(drained)
		scanner, notified := bufio.NewScanner(stderr), false
		for scanner.Scan() {
			if !notified && strings.Contains(scanner.Text(), "metadata_job_read_failed") {
				close(ready)
				notified = true
			}
		}
	}()
	select {
	case <-ready:
	case <-time.After(3 * time.Second):
		worker.Process.Kill()
		worker.Wait()
		<-drained
		t.Fatal("FIFO metadata blocked the actual worker")
	}
	if err := worker.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- worker.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal("worker did not stop gracefully", err)
		}
	case <-time.After(3 * time.Second):
		worker.Process.Kill()
		<-done
		<-drained
		t.Fatal("worker ignored cancellation after unsafe metadata")
	}
	<-drained
	if _, err := os.Stat(filepath.Join(f.root, "called")); !os.IsNotExist(err) {
		t.Fatal("FIFO job invoked pipeline")
	}
}

func TestSharedMetadataContract(t *testing.T) {
	data, err := os.ReadFile("../../docs/security/metadata-cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		SchemaVersion int `json:"schema_version"`
		Cases         []struct {
			Name  string `json:"name"`
			Kind  string `json:"kind"`
			JSON  string `json:"json"`
			Valid bool   `json:"valid"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &corpus); err != nil || corpus.SchemaVersion != 1 || len(corpus.Cases) != 114 {
		t.Fatal("shared authoritative corpus unavailable or invalid", err)
	}
	for _, entry := range corpus.Cases {
		t.Run(entry.Name, func(t *testing.T) {
			path := metadataFixture(t, []byte(entry.JSON))
			var err error
			switch entry.Kind {
			case "job":
				_, err = readJobContext(context.Background(), path)
			case "result":
				_, err = readResultContext(context.Background(), path)
			default:
				t.Fatal("unsupported corpus kind")
			}
			if (err == nil) != entry.Valid {
				t.Fatalf("valid=%v expected=%v error=%v", err == nil, entry.Valid, err)
			}
		})
	}
}

func TestMetadataArtifactBindingRoundTripAndAbsentCompatibility(t *testing.T) {
	before := validResultBytes(t)
	original, err := readResultContext(context.Background(), metadataFixture(t, before))
	if err != nil {
		t.Fatal(err)
	}
	after, err := json.Marshal(original)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("binding-absent v1 serialization changed", err)
	}
	binding := artifactExecution{SchemaVersion: 1, ProfileSHA256: strings.Repeat("a", 64), StoreID: strings.Repeat("b", 32), LeaseID: strings.Repeat("c", 32), ManifestSHA256: strings.Repeat("d", 64), ReceiptSHA256: strings.Repeat("e", 64), ReceiptBytes: 5, Files: map[string]artifactFile{"execution_receipt": {SHA256: strings.Repeat("e", 64), Bytes: 5}}}
	original.ArtifactExecution = &binding
	original.Status = "failed"
	original.ReleaseStatus = "withheld"
	original.SecurityMode = "protected"
	original.PipelineMode = "stats"
	original.Decrypted = true
	original.SignatureValid = true
	original.DecryptionError = ""
	original.SignatureError = ""
	original.UploadSHA256 = strings.Repeat("1", 64)
	original.ProcessedSHA256 = strings.Repeat("2", 64)
	original.SizeBytes = 0
	raw, _ := json.Marshal(original)
	parsed, err := readResultContext(context.Background(), metadataFixture(t, raw))
	if err != nil || parsed.ArtifactExecution == nil || parsed.ArtifactExecution.ReceiptSHA256 != binding.ReceiptSHA256 {
		t.Fatal("valid binding lost", err)
	}
	// Typed pointer recursion must not allow encoding/json's case-insensitive path.
	bad := bytes.Replace(raw, []byte(`"profile_sha256"`), []byte(`"Profile_SHA256"`), 1)
	if _, err := readResultContext(context.Background(), metadataFixture(t, bad)); err == nil {
		t.Fatal("pointer struct alias accepted")
	}
}
