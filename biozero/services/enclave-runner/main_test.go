package main

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

type testJob struct {
	root, jobs, uploads, results, decrypted, pipeline, cert, private string
	job                                                              jobRecord
	signing                                                          *rsa.PrivateKey
}

func newTestJob(t *testing.T, body string, exit int) *testJob {
	t.Helper()
	f := &testJob{root: t.TempDir()}
	for _, name := range []string{"jobs", "uploads", "results", "decrypted"} {
		if err := os.Mkdir(filepath.Join(f.root, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	f.jobs = filepath.Join(f.root, "jobs")
	f.uploads = filepath.Join(f.root, "uploads")
	f.results = filepath.Join(f.root, "results")
	f.decrypted = filepath.Join(f.root, "decrypted")
	f.pipeline = filepath.Join(f.root, "pipeline.sh")
	script := "#!/bin/sh\ntouch '" + filepath.Join(f.root, "called") + "'\nprintf '%s\\n' '" + body + "'\nexit " + string(rune('0'+exit)) + "\n"
	if err := os.WriteFile(f.pipeline, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	f.job = jobRecord{JobID: "abcd1234", Status: "uploaded", OriginalName: "reads.fastq", ClientID: "researcher-a"}
	payload := []byte("@read\nACGT\n+\nIIII\n")
	if err := os.WriteFile(f.uploadPath(), payload, 0600); err != nil {
		t.Fatal(err)
	}
	f.job.SHA256, f.job.SizeBytes, _ = hashFile(f.uploadPath())
	return f
}
func (f *testJob) uploadPath() string {
	return filepath.Join(f.uploads, f.job.JobID+"_"+f.job.OriginalName)
}
func (f *testJob) protect(t *testing.T) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f.signing = key
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	f.cert = filepath.Join(f.root, "signer.crt")
	f.private = filepath.Join(f.root, "decrypt.key")
	if err = os.WriteFile(f.cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(f.private, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0600); err != nil {
		t.Fatal(err)
	}
	aesKey := make([]byte, 32)
	iv := make([]byte, 12)
	rand.Read(aesKey)
	rand.Read(iv)
	block, _ := aes.NewCipher(aesKey)
	gcm, _ := cipher.NewGCM(block)
	plaintext, _ := os.ReadFile(f.uploadPath())
	if err = os.WriteFile(f.uploadPath(), gcm.Seal(nil, iv, plaintext, nil), 0600); err != nil {
		t.Fatal(err)
	}
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &key.PublicKey, append(aesKey, iv...), nil)
	if err != nil {
		t.Fatal(err)
	}
	f.job.EncKey = hex.EncodeToString(wrapped)
	f.job.EncAlg = "aes-256-gcm+rsa-oaep-sha256"
	f.resign(t)
}
func (f *testJob) resign(t *testing.T) {
	t.Helper()
	f.job.SHA256, f.job.SizeBytes, _ = hashFile(f.uploadPath())
	digest, _ := fileSHA256Bytes(f.uploadPath())
	sig, err := rsa.SignPSS(rand.Reader, f.signing, crypto.SHA256, digest, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.job.Sig = hex.EncodeToString(sig)
	f.job.SigAlg = "rsa-pss-sha256"
}
func (f *testJob) run(t *testing.T, timeout time.Duration) resultRecord {
	t.Helper()
	if err := writeJSON(filepath.Join(f.jobs, f.job.JobID+".json"), f.job); err != nil {
		t.Fatal(err)
	}
	processJobs(f.jobs, f.uploads, f.results, f.decrypted, defaultRules(), f.private, f.cert, f.pipeline, "", "", timeout)
	data, err := os.ReadFile(filepath.Join(f.results, f.job.JobID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var result resultRecord
	if err = json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	return result
}
func TestProtectedRejectsBeforePipeline(t *testing.T) {
	cases := []struct {
		name, code string
		mutate     func(*testJob)
	}{
		{"unsigned", "signature_required", func(f *testJob) { f.job.Sig = ""; f.job.SigAlg = "" }},
		{"invalid_signature", "signature_invalid", func(f *testJob) { f.job.Sig = "00" }},
		{"missing_encryption", "encryption_metadata_invalid", func(f *testJob) { f.job.EncKey = "" }},
		{"unsupported_cipher", "encryption_metadata_invalid", func(f *testJob) { f.job.EncAlg = "rsa" }},
		{"bad_ciphertext", "decryption_failed", func(f *testJob) { os.WriteFile(f.uploadPath(), []byte("broken"), 0600); f.resign(t) }},
		{"changed_upload", "upload_integrity_failed", func(f *testJob) { os.WriteFile(f.uploadPath(), []byte("tampered"), 0600) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("BIOZERO_SECURITY_MODE", "protected")
			f := newTestJob(t, `{"schema_version":1,"mode":"stats","pipeline_status":"succeeded","stages":[{"name":"validate_fastq","status":"succeeded"},{"name":"fastq_stats","status":"succeeded"}],"outputs":{},"errors":[]}`, 0)
			f.protect(t)
			tc.mutate(f)
			r := f.run(t, time.Second)
			if r.Status != "rejected" || r.ErrorCode != tc.code {
				t.Fatalf("got %+v", r)
			}
			if _, err := os.Stat(filepath.Join(f.root, "called")); !os.IsNotExist(err) {
				t.Fatal("pipeline called for rejected input")
			}
		})
	}
}
func TestProtectedSuccessPreservesUploadAndCleansPlaintext(t *testing.T) {
	t.Setenv("BIOZERO_SECURITY_MODE", "protected")
	f := newTestJob(t, `{"schema_version":1,"mode":"stats","pipeline_status":"succeeded","stages":[{"name":"validate_fastq","status":"succeeded"},{"name":"fastq_stats","status":"succeeded"}],"outputs":{},"errors":[]}`, 0)
	f.protect(t)
	original := f.job.SHA256
	r := f.run(t, time.Second)
	if r.Status != "succeeded" || !r.Decrypted || !r.SignatureValid || r.UploadSHA256 != original || r.ProcessedSHA256 == original {
		t.Fatalf("got %+v", r)
	}
	job, err := readJob(filepath.Join(f.jobs, f.job.JobID+".json"))
	if err != nil || job.SHA256 != original || job.SizeBytes != f.job.SizeBytes {
		t.Fatalf("upload metadata changed: %+v %v", job, err)
	}
	entries, _ := os.ReadDir(f.decrypted)
	if len(entries) != 0 {
		t.Fatal("plaintext left behind")
	}
}
func TestPipelineContractStatuses(t *testing.T) {
	cases := []struct {
		name, body, status, code string
		exit                     int
	}{
		{"incomplete", `{"schema_version":1,"mode":"stats","pipeline_status":"incomplete"}`, "incomplete", "pipeline_incomplete", 2},
		{"failed", `{"schema_version":1,"mode":"stats","pipeline_status":"failed"}`, "failed", "pipeline_failed", 1},
		{"stage_timeout", `{"schema_version":1,"mode":"stats","pipeline_status":"failed","errors":[{"code":"timeout"}]}`, "timed_out", "pipeline_timed_out", 1},
		{"invalid_json", "not json", "failed", "pipeline_json_invalid", 0},
		{"exit_disagrees", `{"schema_version":1,"mode":"stats","pipeline_status":"succeeded","stages":[{"name":"validate_fastq","status":"succeeded"},{"name":"fastq_stats","status":"succeeded"}],"outputs":{},"errors":[]}`, "failed", "pipeline_process_failed", 1},
		{"legacy_pipeline", `{"read_count":1}`, "failed", "pipeline_contract_invalid", 0},
		{"mode_disagrees", `{"schema_version":1,"mode":"variants","pipeline_status":"succeeded","stages":[{"name":"validate_fastq","status":"succeeded"},{"name":"fastq_stats","status":"succeeded"}],"outputs":{},"errors":[]}`, "failed", "pipeline_contract_invalid", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("BIOZERO_SECURITY_MODE", "demo")
			f := newTestJob(t, tc.body, tc.exit)
			r := f.run(t, time.Second)
			if r.Status != tc.status || r.ErrorCode != tc.code {
				t.Fatalf("got %+v", r)
			}
		})
	}
}
func TestPipelineDeadlineKillsDescendant(t *testing.T) {
	t.Setenv("BIOZERO_SECURITY_MODE", "demo")
	f := newTestJob(t, "", 0)
	escaped := filepath.Join(f.root, "escaped")
	script := "#!/bin/sh\n(sleep 0.5; touch '" + escaped + "') &\nwait\n"
	os.WriteFile(f.pipeline, []byte(script), 0700)
	r := f.run(t, 50*time.Millisecond)
	if r.Status != "timed_out" {
		t.Fatalf("got %+v", r)
	}
	time.Sleep(600 * time.Millisecond)
	if _, err := os.Stat(escaped); !os.IsNotExist(err) {
		t.Fatal("descendant survived pipeline timeout")
	}
}
func TestInterruptedJobIsTerminal(t *testing.T) {
	f := newTestJob(t, "", 0)
	f.job.Status = "running"
	r := f.run(t, time.Second)
	if r.Status != "failed" || r.ErrorCode != "runner_interrupted" {
		t.Fatalf("got %+v", r)
	}
}
func TestAtomicJSONDoesNotReplaceOnMarshalFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "record.json")
	writeJSON(path, map[string]string{"state": "old"})
	if err := writeJSON(path, make(chan int)); err == nil {
		t.Fatal("expected marshal error")
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "old") {
		t.Fatal("previous record corrupted")
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatal("temporary artifact leaked")
	}
}
func TestVariantSuccessRequiresArtifactsInJobWorkspace(t *testing.T) {
	root := t.TempDir()
	other := t.TempDir()
	base := map[string]any{"stages": []map[string]string{{"name": "validate_fastq", "status": "succeeded"}, {"name": "vcf_check", "status": "succeeded"}}, "outputs": map[string]string{}, "errors": []string{}}
	output, _ := json.Marshal(base)
	if validatePipelineSuccess(output, "variants", root) == "" {
		t.Fatal("missing VCF accepted")
	}
	outputs := base["outputs"].(map[string]string)
	for _, name := range []string{"variants_vcf", "variants_vcf_index", "normalized_vcf"} {
		path := filepath.Join(root, name)
		os.WriteFile(path, []byte("data"), 0600)
		outputs[name] = path
	}
	output, _ = json.Marshal(base)
	if err := validatePipelineSuccess(output, "variants", root); err != "" {
		t.Fatal(err)
	}
	outside := filepath.Join(other, "vcf")
	os.WriteFile(outside, []byte("data"), 0600)
	outputs["normalized_vcf"] = outside
	output, _ = json.Marshal(base)
	if validatePipelineSuccess(output, "variants", root) == "" {
		t.Fatal("artifact from other workspace accepted")
	}
}
func TestPipelineStartFailureIsDistinct(t *testing.T) {
	f := newTestJob(t, "", 0)
	if err := os.Chmod(f.pipeline, 0600); err != nil {
		t.Fatal(err)
	}
	output, message, code := runPipeline(f.pipeline, f.uploadPath(), "", filepath.Join(f.root, "artifacts"), "stats", time.Second)
	if output != nil || code != "pipeline_start_failed" || message != "pipeline process could not start" {
		t.Fatal(string(output), message, code)
	}
}
func TestWorkerSignalHelper(t *testing.T) {
	if os.Getenv("BIOZERO_TEST_WORKER_HELPER") != "1" {
		return
	}
	main()
}
func TestWorkerSignalsCancelPipelineDescendants(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGINT} {
		t.Run(sig.String(), func(t *testing.T) {
			f := newTestJob(t, "", 0)
			entered := filepath.Join(f.root, "entered")
			escaped := filepath.Join(f.root, "escaped")
			script := "#!/bin/sh\n(sleep 1; touch '" + escaped + "') &\ntouch '" + entered + "'\nwait\n"
			if err := os.WriteFile(f.pipeline, []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			if err := writeJSON(filepath.Join(f.jobs, f.job.JobID+".json"), f.job); err != nil {
				t.Fatal(err)
			}
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			worker := exec.Command(executable, "-test.run=^TestWorkerSignalHelper$")
			worker.Env = append(os.Environ(), "BIOZERO_TEST_WORKER_HELPER=1", "BIOZERO_EXECUTION_BACKEND=legacy", "BIOZERO_DATA_DIR="+f.root, "BIOZERO_PIPELINE_PATH="+f.pipeline, "BIOZERO_SECURITY_MODE=demo", "BIOZERO_PIPELINE_MODE=stats", "BIOZERO_POLL_SECONDS=0.01", "BIOZERO_PIPELINE_TIMEOUT=30s", "BIOZERO_RULES_PATH="+filepath.Join(f.root, "absent-rules"))
			if err := worker.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if worker.ProcessState == nil {
					worker.Process.Kill()
					worker.Wait()
				}
			}()
			ready := false
			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) {
				if _, err := os.Stat(entered); err == nil {
					ready = true
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if !ready {
				t.Fatal("pipeline did not start")
			}
			if err := worker.Process.Signal(sig); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- worker.Wait() }()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal("worker did not exit gracefully", err)
				}
			case <-time.After(3 * time.Second):
				worker.Process.Kill()
				<-done
				t.Fatal("worker did not stop")
			}
			data, err := os.ReadFile(filepath.Join(f.results, f.job.JobID+".json"))
			if err != nil {
				t.Fatal(err)
			}
			var result resultRecord
			json.Unmarshal(data, &result)
			if result.Status != "failed" || result.ErrorCode != "pipeline_cancelled" {
				t.Fatalf("shutdown not recorded: %+v", result)
			}
			time.Sleep(1100 * time.Millisecond)
			if _, err := os.Stat(escaped); !os.IsNotExist(err) {
				t.Fatal("pipeline descendant survived worker shutdown")
			}
		})
	}
}
func scientificFixture(t *testing.T, body string, exit int) (*resultRecord, string, string) {
	t.Helper()
	root := t.TempDir()
	reference := filepath.Join(root, "reference.fa")
	truth := filepath.Join(root, "truth.vcf")
	observed := filepath.Join(root, "observed.vcf")
	evaluator := filepath.Join(root, "evaluate.py")
	for _, path := range []string{reference, truth, observed} {
		if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	script := "import sys\nprint(" + stringMustJSON(t, body) + ")\nsys.exit(" + string(rune('0'+exit)) + ")\n"
	if err := os.WriteFile(evaluator, []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BIOZERO_EVALUATOR_PATH", evaluator)
	t.Setenv("BIOZERO_TRUTH_PATH", truth)
	output, _ := json.Marshal(map[string]any{"outputs": map[string]string{"normalized_vcf": observed}})
	return &resultRecord{Status: "succeeded", PipelineMode: "variants", PipelineOutput: output}, reference, root
}
func stringMustJSON(t *testing.T, value string) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
func TestScientificReleaseContract(t *testing.T) {
	cases := []struct {
		name, body, release, code string
		exit                      int
	}{
		{"passed", `{"evaluation_status":"passed","tp":3,"fp":0,"fn":0,"precision":1,"recall":1}`, "evaluated_passed", "", 0},
		{"failed", `{"evaluation_status":"failed","tp":2,"fp":0,"fn":1,"precision":1,"recall":0.6666666667}`, "withheld", "evaluation_failed", 1},
		{"failed_input", `{"evaluation_status":"failed","error":"VCF invalid"}`, "withheld", "evaluation_failed", 1},
		{"corrupt_json", `not JSON`, "withheld", "evaluation_json_invalid", 0},
		{"missing_metrics", `{"evaluation_status":"passed"}`, "withheld", "evaluation_contract_invalid", 0},
		{"exit_disagrees", `{"evaluation_status":"passed","tp":3,"fp":0,"fn":0,"precision":1,"recall":1}`, "withheld", "evaluation_contract_invalid", 1},
		{"failed_exit_disagrees", `{"evaluation_status":"failed","tp":0,"fp":3,"fn":3}`, "withheld", "evaluation_contract_invalid", 0},
		{"false_pass_metrics", `{"evaluation_status":"passed","tp":2,"fp":0,"fn":1,"precision":1,"recall":1}`, "withheld", "evaluation_metrics_failed", 0},
		{"empty_callsets", `{"evaluation_status":"passed","tp":0,"fp":0,"fn":0,"precision":1,"recall":1}`, "withheld", "evaluation_no_truth_matches", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, reference, _ := scientificFixture(t, tc.body, tc.exit)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			assessScientificRelease(ctx, result, reference)
			if result.Status != "succeeded" || result.ReleaseStatus != tc.release {
				t.Fatalf("got %+v", result)
			}
			var report map[string]any
			json.Unmarshal(result.ScientificEvaluation, &report)
			if tc.code != "" && report["evaluation_error_code"] != tc.code {
				t.Fatal(report)
			}
			if tc.release == "evaluated_passed" && (report["evaluation_status"] != "passed" || report["evaluator_returncode"] != float64(0) || report["truth_sha256"] == nil) {
				t.Fatal(report)
			}
		})
	}
}
func TestScientificReleaseConfigurationAndMissingTruth(t *testing.T) {
	result, reference, _ := scientificFixture(t, `{"evaluation_status":"passed"}`, 0)
	t.Setenv("BIOZERO_EVALUATOR_PATH", "")
	t.Setenv("BIOZERO_TRUTH_PATH", "")
	assessScientificRelease(context.Background(), result, reference)
	if result.ReleaseStatus != "unassessed" || result.Status != "succeeded" || result.ScientificEvaluation != nil {
		t.Fatalf("unconfigured evaluator changed execution: %+v", result)
	}
	t.Setenv("BIOZERO_EVALUATOR_PATH", "/missing/evaluator")
	assessScientificRelease(context.Background(), result, reference)
	if result.ReleaseStatus != "withheld" || !strings.Contains(string(result.ScientificEvaluation), "evaluation_config_incomplete") {
		t.Fatal(string(result.ScientificEvaluation))
	}
	result, reference, root := scientificFixture(t, `{"evaluation_status":"passed"}`, 0)
	t.Setenv("BIOZERO_TRUTH_PATH", filepath.Join(root, "absent"))
	assessScientificRelease(context.Background(), result, reference)
	if result.ReleaseStatus != "withheld" || result.Status != "succeeded" || !strings.Contains(string(result.ScientificEvaluation), "evaluation_truth_missing") {
		t.Fatalf("got %+v", result)
	}
}
func TestScientificReleaseRealFixturePassAndFail(t *testing.T) {
	evaluator, err := filepath.Abs("../../bio/benchmarks/evaluate_variants.py")
	if err != nil {
		t.Fatal(err)
	}
	reference, _ := filepath.Abs("../../bio/fixtures/variant-smoke/reference.fa")
	truth, _ := filepath.Abs("../../bio/fixtures/variant-smoke/expected.vcf")
	t.Setenv("BIOZERO_EVALUATOR_PATH", evaluator)
	t.Setenv("BIOZERO_TRUTH_PATH", truth)
	for _, matching := range []bool{true, false} {
		t.Run(fmt.Sprint(matching), func(t *testing.T) {
			data, err := os.ReadFile(truth)
			if err != nil {
				t.Fatal(err)
			}
			if !matching {
				lines := strings.Split(string(data), "\n")
				for i, line := range lines {
					if line != "" && !strings.HasPrefix(line, "#") {
						lines = append(lines[:i], lines[i+1:]...)
						break
					}
				}
				data = []byte(strings.Join(lines, "\n"))
			}
			observed := filepath.Join(t.TempDir(), "observed.vcf")
			os.WriteFile(observed, data, 0600)
			output, _ := json.Marshal(map[string]any{"outputs": map[string]string{"normalized_vcf": observed}})
			result := &resultRecord{Status: "succeeded", PipelineMode: "variants", PipelineOutput: output}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			assessScientificRelease(ctx, result, reference)
			expected := "withheld"
			if matching {
				expected = "evaluated_passed"
			}
			if result.Status != "succeeded" || result.ReleaseStatus != expected {
				t.Fatalf("got %+v %s", result, result.ScientificEvaluation)
			}
		})
	}
}
func TestScientificReleaseCancellationKillsDescendants(t *testing.T) {
	result, reference, root := scientificFixture(t, "", 0)
	entered := filepath.Join(root, "entered")
	escaped := filepath.Join(root, "escaped")
	childCode := "import time,pathlib;time.sleep(1);pathlib.Path(" + stringMustJSON(t, escaped) + ").write_text('escaped')"
	script := "import pathlib,subprocess,time,sys\nsubprocess.Popen([sys.executable,'-c'," + stringMustJSON(t, childCode) + "])\npathlib.Path(" + stringMustJSON(t, entered) + ").write_text('entered')\ntime.sleep(10)\n"
	os.WriteFile(os.Getenv("BIOZERO_EVALUATOR_PATH"), []byte(script), 0600)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() { assessScientificRelease(ctx, result, reference); close(done) }()
	deadline := time.Now().Add(2 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		if _, err := os.Stat(entered); err == nil {
			ready = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !ready {
		cancel()
		<-done
		t.Fatal("evaluator did not start")
	}
	cancel()
	<-done
	if result.Status != "succeeded" || result.ReleaseStatus != "withheld" || !strings.Contains(string(result.ScientificEvaluation), "evaluation_cancelled") {
		t.Fatalf("got %+v %s", result, result.ScientificEvaluation)
	}
	time.Sleep(1100 * time.Millisecond)
	if _, err := os.Stat(escaped); !os.IsNotExist(err) {
		t.Fatal("evaluator descendant survived cancellation")
	}
}
