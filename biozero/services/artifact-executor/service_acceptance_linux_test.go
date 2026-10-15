//go:build linux

package artifactexecutor

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// This runs the separately compiled host service and both actual providers. The
// verified-input facts remain synthetic; the protected worker is not exercised.
func TestBrokerServiceActualNativeAndDocker(t *testing.T) {
	if os.Getenv("BIOZERO_RUN_BROKER_SERVICE_ACCEPTANCE") != "1" {
		t.Skip("opt-in compiled host broker service and actual native/Docker analysis")
	}
	repo, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	executable := os.Getenv("BIOZERO_ARTIFACT_BROKER_BINARY")
	analysisBinary := os.Getenv("BIOZERO_CAPSULE_ANALYSIS_BINARY")
	if !filepath.IsAbs(executable) || !filepath.IsAbs(analysisBinary) {
		t.Fatal("explicit compiled broker/analysis binaries required")
	}
	root := os.Getenv("BIOZERO_BROKER_SERVICE_EVIDENCE_ROOT")
	if root == "" {
		root = filepath.Join(repo, ".biozero", "broker-service-"+time.Now().UTC().Format("20060102T150405.000000000Z"))
	}
	if !filepath.IsAbs(root) || os.Mkdir(root, 0700) != nil {
		t.Fatal("service evidence root must be new and absolute; parent must exist")
	}
	asset := func(path string) BrokerServiceAsset {
		t.Helper()
		if !filepath.IsAbs(path) {
			path = filepath.Join(repo, path)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return BrokerServiceAsset{Path: path, SHA256: digest(raw)}
	}
	for _, kind := range []string{"native", "docker"} {
		t.Run(kind, func(t *testing.T) {
			base := filepath.Join(root, kind)
			if err := os.Mkdir(base, 0700); err != nil {
				t.Fatal(err)
			}
			reference := asset("biozero/bio/fixtures/variant-smoke/reference.fa")
			rulesPath := filepath.Join(base, "rules.json")
			raw, err := json.Marshal(map[string]any{"max_size_bytes": MaxInputBytes, "suspicious_name_patterns": []string{}, "threat_panel_fasta": reference.Path})
			if err != nil || os.WriteFile(rulesPath, raw, 0600) != nil {
				t.Fatal("cannot create private synthetic rules")
			}
			config := BrokerServiceConfig{SchemaVersion: 1, Provider: kind, Mode: "variants", StoreRoot: filepath.Join(base, "store"), JournalRoot: filepath.Join(base, "journal"), WorkspaceRoot: filepath.Join(base, "workspace"), SocketPath: filepath.Join(base, "channel", "worker.sock"), AllowedUID: uint32(os.Geteuid()), TimeoutSeconds: 120, DockerCommand: []string{}, NativeHelper: asset("biozero/services/artifact-executor/capsule/native_capsule.py"), Pipeline: asset("biozero/bio/pipeline/pipeline.py"), ResourceBudget: asset("biozero/bio/pipeline/resource_budget.py"), Reference: reference, Evaluator: asset("biozero/bio/benchmarks/evaluate_variants.py"), Truth: asset("biozero/bio/fixtures/variant-smoke/expected.vcf"), AnalysisExecutable: asset(analysisBinary), AnalysisRules: asset(rulesPath), AnalysisPanel: reference}
			if kind == "native" {
				config.PythonPath, err = filepath.EvalSymlinks("/usr/bin/python3")
				if err != nil {
					t.Fatal(err)
				}
				config.ToolPath = "/tmp/biozero-bio-tools-locked/bin:/usr/bin"
			} else {
				config.DockerCommand = []string{"/usr/bin/sudo", "-n", "/usr/bin/docker", "--host=unix:///var/run/docker.sock"}
				config.ImageID = "sha256:1ca8e95c2f5679ab2001f856549c634f0b9daeeeb1492b8610814b96cf30fa7d"
				config.ContainerHelper = asset("biozero/services/artifact-executor/capsule/container_capsule.py")
			}
			configPath := filepath.Join(base, "service-config.json")
			raw, err = json.Marshal(config)
			if err != nil || os.WriteFile(configPath, raw, 0600) != nil {
				t.Fatal("cannot create private host config")
			}
			profileBytes, err := exec.Command(executable, "--config", configPath, "--print-profile").Output()
			profile := strings.TrimSpace(string(profileBytes))
			if err != nil || !hexID(profile, 64) || string(profileBytes) != profile+"\n" {
				t.Fatal("compiled service profile command failed", err)
			}
			for _, p := range []string{config.StoreRoot, config.JournalRoot, config.WorkspaceRoot, filepath.Dir(config.SocketPath)} {
				if _, err := os.Lstat(p); !os.IsNotExist(err) {
					t.Fatal("profile command created state or socket", err)
				}
			}
			logFile, err := os.OpenFile(filepath.Join(base, "service.log"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				t.Fatal(err)
			}
			defer logFile.Close()
			command := exec.Command(executable, "--config", configPath)
			command.Stdout, command.Stderr = logFile, logFile
			command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
			// Linux Pdeathsig follows the creator thread. Keep that exact thread
			// alive through the command's authoritative Wait, as the native keeper does.
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- command.Wait() }()
			stopped := false
			shutdown := func() {
				if stopped {
					return
				}
				select {
				case err := <-done:
					stopped = true
					if err != nil {
						t.Error("service exited before requested clean shutdown", err)
					}
					return
				default:
				}
				if err := command.Process.Signal(syscall.SIGTERM); err != nil {
					t.Error("service signal failed", err)
				}
				select {
				case err := <-done:
					stopped = true
					if err != nil {
						t.Error("service did not shut down cleanly", err)
					}
				case <-time.After(45 * time.Second):
					analysisUncertainCustody.Lock()
					analysisUncertainCustody.objects = append(analysisUncertainCustody.objects, command)
					analysisUncertainCustody.Unlock()
					t.Error("service still pending; evidence and exact process custody retained")
				}
			}
			defer shutdown()
			readyDeadline := time.Now().Add(10 * time.Second)
			for {
				select {
				case err := <-done:
					stopped = true
					t.Fatal("service exited during startup", err)
				default:
				}
				if info, err := os.Lstat(config.SocketPath); err == nil && info.Mode()&os.ModeSocket != 0 {
					break
				}
				if time.Now().After(readyDeadline) {
					t.Fatal("service did not establish its private socket")
				}
				time.Sleep(10 * time.Millisecond)
			}
			plaintext, err := os.ReadFile(filepath.Join(repo, "biozero/bio/fixtures/variant-smoke/reads.fastq"))
			if err != nil {
				t.Fatal(err)
			}
			inputPath := filepath.Join(base, "verified.fastq")
			if err := os.WriteFile(inputPath, plaintext, 0600); err != nil {
				t.Fatal(err)
			}
			input, err := os.Open(inputPath)
			if err != nil {
				t.Fatal(err)
			}
			defer input.Close()
			facts := AnalysisContext{OriginalName: "public-synthetic.fastq", ProcessedSizeBytes: int64(len(plaintext)), Decrypted: true, SignatureValid: true}
			q := BridgeRequestV2{SchemaVersion: 2, Operation: "submit", JobID: "0000000000000009", UploadSHA256: digest([]byte("synthetic ciphertext placeholder")), ExpectedProfileSHA256: profile, ProcessedSHA256: digest(plaintext), ProcessedBytes: int64(len(plaintext)), OriginalName: facts.OriginalName, AnalysisContext: facts}
			ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
			defer cancel()
			r, extra, err := CallBridgeUnixV2(ctx, config.SocketPath, q, input)
			if extra != nil {
				extra.Close()
				t.Fatal("submit exposed receipt")
			}
			if err != nil || r.ErrorCode != "" || r.State != "committed" || !r.HasManifest || r.Manifest.ExecutionStatus != "succeeded" || r.Manifest.ReleaseStatus != "evaluated_passed" || len(r.Manifest.Files) != 4 || r.Manifest.ObservedSHA256 != r.Manifest.EvaluatedSHA256 || r.Manifest.ObservedSHA256 != r.Manifest.Files["normalized_vcf"].SHA256 {
				t.Fatal("actual compiled service did not commit synthetic science", err, r.ErrorCode)
			}
			query := q
			query.Operation = "receipt"
			query.ProcessedSHA256 = ""
			query.ProcessedBytes = 0
			query.OriginalName = ""
			query.AnalysisContext = AnalysisContext{}
			readback, fd, err := CallBridgeUnixV2(ctx, config.SocketPath, query, nil)
			if err != nil || readback.ErrorCode != "" || fd == nil || readback.ManifestSHA256 != r.ManifestSHA256 {
				t.Fatal("service receipt unavailable", err)
			}
			receipt, err := io.ReadAll(io.NewSectionReader(fd, 0, MaxBridgeReceiptBytes+1))
			fd.Close()
			if err != nil || digest(receipt) != r.ReceiptSHA256 {
				t.Fatal("service receipt binding invalid", err)
			}
			var observed struct {
				SchemaVersion   int             `json:"schema_version"`
				AnalysisContext AnalysisContext `json:"analysis_context"`
				AnalysisCapture struct {
					Returncode int `json:"returncode"`
					Payload    struct {
						Status    string `json:"status"`
						Detection struct {
							Score   float64 `json:"score"`
							Signals struct {
								Alignment struct {
									Mapped int `json:"mapped_reads"`
									Total  int `json:"total_reads"`
								} `json:"alignment"`
							} `json:"signals"`
						} `json:"detection"`
					} `json:"payload"`
				} `json:"analysis_capture"`
				Evaluation struct {
					Payload struct {
						TP int `json:"tp"`
						FP int `json:"fp"`
						FN int `json:"fn"`
					} `json:"payload"`
				} `json:"evaluation"`
			}
			if json.Unmarshal(receipt, &observed) != nil || observed.SchemaVersion != 2 || observed.AnalysisContext != facts || observed.AnalysisCapture.Returncode != 0 || observed.AnalysisCapture.Payload.Status != "succeeded" || observed.AnalysisCapture.Payload.Detection.Score != .7 || observed.AnalysisCapture.Payload.Detection.Signals.Alignment.Mapped != 1171 || observed.AnalysisCapture.Payload.Detection.Signals.Alignment.Total != 1171 || observed.Evaluation.Payload.TP != 3 || observed.Evaluation.Payload.FP != 0 || observed.Evaluation.Payload.FN != 0 {
				t.Fatal("compiled service receipt lost evaluator/detection results")
			}
			shutdown()
			if !stopped {
				return
			}
			if _, err := os.Lstat(config.SocketPath); !os.IsNotExist(err) {
				t.Fatal("clean service shutdown retained socket", err)
			}
			store, err := Open(context.Background(), config.StoreRoot, NativeArtifactPolicy())
			if err != nil {
				t.Fatal("service shutdown did not release verified Store custody", err)
			}
			if !store.Snapshot().Healthy || store.Snapshot().RetainedOrReservedJobs != 1 || store.Snapshot().ChargedBytes <= 0 {
				store.Close()
				t.Fatal("service shutdown changed retained accounting")
			}
			accounting := store.Snapshot()
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			ledgerBefore, err := os.ReadFile(filepath.Join(config.StoreRoot, "ledger.json"))
			if err != nil {
				t.Fatal(err)
			}
			journalBefore, err := os.ReadFile(filepath.Join(config.JournalRoot, "journal.json"))
			if err != nil {
				t.Fatal(err)
			}
			restartLog, err := os.OpenFile(filepath.Join(base, "service-restart.log"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				t.Fatal(err)
			}
			defer restartLog.Close()
			restart := exec.Command(executable, "--config", configPath)
			restart.Stdout, restart.Stderr = restartLog, restartLog
			restart.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
			if err := restart.Start(); err != nil {
				t.Fatal(err)
			}
			restartedDone := make(chan error, 1)
			go func() { restartedDone <- restart.Wait() }()
			restartedStopped := false
			defer func() {
				if restartedStopped {
					return
				}
				_ = restart.Process.Signal(syscall.SIGTERM)
				select {
				case <-restartedDone:
					restartedStopped = true
				case <-time.After(45 * time.Second):
					analysisUncertainCustody.Lock()
					analysisUncertainCustody.objects = append(analysisUncertainCustody.objects, restart)
					analysisUncertainCustody.Unlock()
					t.Error("restarted service remains pending; exact process custody retained")
				}
			}()
			readyDeadline = time.Now().Add(10 * time.Second)
			for {
				select {
				case err := <-restartedDone:
					restartedStopped = true
					t.Fatal("committed-history service restart failed", err)
				default:
				}
				if info, err := os.Lstat(config.SocketPath); err == nil && info.Mode()&os.ModeSocket != 0 {
					break
				}
				if time.Now().After(readyDeadline) {
					t.Fatal("restarted service did not establish socket")
				}
				time.Sleep(10 * time.Millisecond)
			}
			recovered, recoveredFD, err := CallBridgeUnixV2(ctx, config.SocketPath, query, nil)
			if err != nil || recoveredFD == nil || recovered.ErrorCode != "" || recovered.LeaseID != r.LeaseID || recovered.ManifestSHA256 != r.ManifestSHA256 {
				t.Fatal("committed service restart lost exact receipt binding", err)
			}
			recoveredBytes, err := io.ReadAll(io.NewSectionReader(recoveredFD, 0, MaxBridgeReceiptBytes+1))
			recoveredFD.Close()
			if err != nil || digest(recoveredBytes) != digest(receipt) {
				t.Fatal("restarted service returned different receipt bytes", err)
			}
			// Alter only this fresh test's socket pathname. Never erase the replacement
			// or report clean exit when its anchored socket cleanup cannot be proven.
			marker := []byte("synthetic socket replacement marker\n")
			if err := os.Remove(config.SocketPath); err != nil {
				t.Fatal(err)
			}
			markerFile, err := os.OpenFile(config.SocketPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := markerFile.Write(marker); err != nil {
				markerFile.Close()
				t.Fatal(err)
			}
			if err := markerFile.Close(); err != nil {
				t.Fatal(err)
			}
			if err := restart.Process.Signal(syscall.SIGTERM); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-restartedDone:
				restartedStopped = true
				if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 1 {
					t.Fatal("socket cleanup uncertainty did not produce explicit failure", err)
				}
			case <-time.After(45 * time.Second):
				t.Fatal("uncertain socket cleanup service failed to terminate")
			}
			retainedMarker, err := os.ReadFile(config.SocketPath)
			if err != nil || string(retainedMarker) != string(marker) {
				t.Fatal("service removed or changed unknown socket replacement", err)
			}
			ledgerAfter, err := os.ReadFile(filepath.Join(config.StoreRoot, "ledger.json"))
			if err != nil || digest(ledgerAfter) != digest(ledgerBefore) {
				t.Fatal("service restart/cleanup changed retained ledger", err)
			}
			journalAfter, err := os.ReadFile(filepath.Join(config.JournalRoot, "journal.json"))
			if err != nil || digest(journalAfter) != digest(journalBefore) {
				t.Fatal("service restart/cleanup changed journal", err)
			}
			verified, err := Open(context.Background(), config.StoreRoot, NativeArtifactPolicy())
			if err != nil {
				t.Fatal("committed Store failed verification after socket failure", err)
			}
			if verified.Snapshot() != accounting {
				verified.Close()
				t.Fatal("committed restart added work or changed charge")
			}
			verified.Close()
			t.Log("compiled fixed-profile service, actual capsule science/analysis, receipt, clean stop, committed restart without rerun and visible socket-cleanup failure verified; protected worker remains pending")
		})
	}
}
