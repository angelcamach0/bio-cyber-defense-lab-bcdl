//go:build linux

package artifactexecutor

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type analysisBridgeAudit struct {
	*Broker
	storeRoot, journalRoot string
	submitWrites           atomic.Int32
}

// Test-only lifetime custody for an uncertain real provider. Do not let Go's
// finalizers release keeper locks while a capsule or persistence remains pending.
var analysisUncertainCustody struct {
	sync.Mutex
	objects []any
}

func (a *analysisBridgeAudit) AcknowledgeBridgeV2(ctx context.Context, q BridgeRequestV2, write func() error) error {
	return a.Broker.AcknowledgeBridgeV2(ctx, q, func() error {
		if q.Operation == "submit" {
			raw, err := os.ReadFile(filepath.Join(a.journalRoot, "journal.json"))
			var journal bridgeJournalV2
			if err != nil || strictJSON(raw, &journal) != nil {
				return fail("acceptance_journal_unreadable_at_ack")
			}
			binding, ok := journal.Records[q.JobID]
			if !ok || binding.Stage != "committed" || journal.AnalysisContexts[q.JobID] != q.AnalysisContext {
				return fail("acceptance_analysis_not_sealed_at_ack")
			}
			raw, err = os.ReadFile(filepath.Join(a.storeRoot, "ledger.json"))
			var history ledger
			if err != nil || strictJSON(raw, &history) != nil {
				return fail("acceptance_ledger_unreadable_at_ack")
			}
			record, ok := history.Records[binding.LeaseID]
			if !ok || record.State != "committed" || record.Charge <= 0 || len(record.Files) != 4 || record.ManifestSHA256 != binding.ManifestSHA256 {
				return fail("acceptance_storage_not_committed_at_ack")
			}
			root := filepath.Join(a.storeRoot, "objects", binding.LeaseID)
			manifest, err := os.ReadFile(filepath.Join(root, "manifest.json"))
			if err != nil || digest(manifest) != record.ManifestSHA256 {
				return fail("acceptance_manifest_not_retained_at_ack")
			}
			raw, err = os.ReadFile(filepath.Join(root, "proof.json"))
			var proof Proof
			if err != nil || digest(raw) != record.ProofSHA256 || strictJSON(raw, &proof) != nil || !proof.CapsuleWaitFinished || !proof.ExportAuthorityClosed {
				return fail("acceptance_quiescence_not_retained_at_ack")
			}
			a.submitWrites.Add(1)
		}
		return write()
	})
}

type analysisAcceptanceObserver struct {
	provider   Provider
	mu         sync.Mutex
	calls      int
	completion ProviderCompletion
}

func (p *analysisAcceptanceObserver) Execute(ctx context.Context, input *ScopedInput, exporter *Exporter) ProviderCompletion {
	done := p.provider.Execute(ctx, input, exporter)
	p.mu.Lock()
	p.calls++
	p.completion = done
	p.mu.Unlock()
	return done
}

func TestNativeCapsuleCompleteAnalysis(t *testing.T) {
	actualCapsuleCompleteAnalysis(t, "native")
}

func TestContainerCapsuleCompleteAnalysis(t *testing.T) {
	actualCapsuleCompleteAnalysis(t, "docker")
}

// The public fixture and caller crypto facts are synthetic. This composes the
// actual FD broker, registry, provider, capsule, analysis executable, evaluator,
// Store and Unix ACK; it does not exercise the protected crypto worker.
func actualCapsuleCompleteAnalysis(t *testing.T, kind string) {
	t.Helper()
	if os.Getenv("BIOZERO_RUN_CAPSULE_ANALYSIS_ACCEPTANCE") != "1" {
		t.Skip("opt-in actual namespace/Docker, pinned analysis and synthetic science")
	}
	repo, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	root := os.Getenv("BIOZERO_CAPSULE_ANALYSIS_EVIDENCE_ROOT")
	if root == "" {
		root = filepath.Join(repo, ".biozero", "complete-analysis-"+time.Now().UTC().Format("20060102T150405.000000000Z"))
	}
	base := filepath.Join(root, kind)
	if !filepath.IsAbs(root) {
		t.Fatal("evidence root must be absolute")
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(base, 0700); err != nil {
		t.Fatal("evidence directory must be fresh", err)
	}
	asset := func(path string) PinnedAsset {
		t.Helper()
		if !filepath.IsAbs(path) {
			path = filepath.Join(repo, path)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return PinnedAsset{Path: path, SHA256: digest(raw)}
	}
	executable := os.Getenv("BIOZERO_CAPSULE_ANALYSIS_BINARY")
	if !filepath.IsAbs(executable) {
		t.Fatal("explicit compiled analysis binary required")
	}
	executablePin := asset(executable)
	reference := asset("biozero/bio/fixtures/variant-smoke/reference.fa")
	for _, scenario := range []string{"panel_success", "invalid_rules_withheld"} {
		t.Run(scenario, func(t *testing.T) {
			runRoot := filepath.Join(base, scenario)
			if err := os.Mkdir(runRoot, 0700); err != nil {
				t.Fatal(err)
			}
			rulesPath := filepath.Join(runRoot, "rules.json")
			rules, err := json.Marshal(map[string]any{"max_size_bytes": MaxInputBytes, "suspicious_name_patterns": []string{}, "threat_panel_fasta": reference.Path})
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "invalid_rules_withheld" {
				rules, err = json.Marshal(map[string]any{"threat_panel_fasta": reference.Path, "unrecognized_rule": 1})
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(rulesPath, rules, 0600); err != nil {
				t.Fatal(err)
			}
			analysis := &CapsuleAnalysisConfig{Executable: executablePin, Rules: asset(rulesPath), Panel: reference}
			var provider Provider
			var closeProvider func() error
			var workspace string
			if kind == "native" {
				python, err := filepath.EvalSymlinks("/usr/bin/python3")
				if err != nil {
					t.Fatal(err)
				}
				workspace = filepath.Join(runRoot, "workspaces")
				p, err := NewNativeProvider(context.Background(), NativeProviderConfig{
					WorkspaceRoot: workspace, PythonPath: python, ToolPath: "/tmp/biozero-bio-tools-locked/bin:/usr/bin", Mode: "variants",
					Helper: asset("biozero/services/artifact-executor/capsule/native_capsule.py"), Pipeline: asset("biozero/bio/pipeline/pipeline.py"),
					ResourceBudgetSHA256: asset("biozero/bio/pipeline/resource_budget.py").SHA256, Reference: reference,
					Evaluator: asset("biozero/bio/benchmarks/evaluate_variants.py"), Truth: asset("biozero/bio/fixtures/variant-smoke/expected.vcf"),
					Analysis: analysis, TimeoutSeconds: 120,
				})
				if err != nil {
					t.Fatal(err)
				}
				provider, closeProvider = p, p.Close
			} else {
				workspace = filepath.Join(runRoot, "controls")
				p, err := NewContainerProvider(context.Background(), ContainerProviderConfig{
					WorkspaceRoot: workspace, DockerCommand: []string{"/usr/bin/sudo", "-n", "/usr/bin/docker", "--host=unix:///var/run/docker.sock"},
					ImageID: "sha256:1ca8e95c2f5679ab2001f856549c634f0b9daeeeb1492b8610814b96cf30fa7d", Mode: "variants",
					Helper: asset("biozero/services/artifact-executor/capsule/container_capsule.py"), NativeHelper: asset("biozero/services/artifact-executor/capsule/native_capsule.py"),
					Pipeline: asset("biozero/bio/pipeline/pipeline.py"), ResourceBudgetSHA256: asset("biozero/bio/pipeline/resource_budget.py").SHA256,
					Reference: reference, Evaluator: asset("biozero/bio/benchmarks/evaluate_variants.py"), Truth: asset("biozero/bio/fixtures/variant-smoke/expected.vcf"),
					Analysis: analysis, TimeoutSeconds: 120,
				})
				if err != nil {
					t.Fatal(err)
				}
				provider, closeProvider = p, p.Close
			}
			storeRoot := filepath.Join(runRoot, "store")
			store, err := Open(context.Background(), storeRoot, NativeArtifactPolicy())
			if err != nil {
				t.Fatal(err)
			}
			registry, err := NewInputRegistry(store)
			if err != nil {
				t.Fatal(err)
			}
			observed := &analysisAcceptanceObserver{provider: provider}
			coordinator, err := NewCoordinator(store, registry, observed)
			if err != nil {
				t.Fatal(err)
			}
			journalRoot := filepath.Join(runRoot, "journal")
			profile := digest([]byte("synthetic capsule analysis acceptance profile"))
			broker, err := NewBrokerV2(context.Background(), BrokerConfig{JournalRoot: journalRoot, ProfileSHA256: profile}, coordinator)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				broker.Close()
				retain := func() {
					analysisUncertainCustody.Lock()
					analysisUncertainCustody.objects = append(analysisUncertainCustody.objects, broker, coordinator, registry, provider, store)
					analysisUncertainCustody.Unlock()
				}
				ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
				defer cancel()
				if broker.Wait(ctx) != nil {
					retain()
					t.Error("provider remains pending; preserve private history")
					return
				}
				store.mu.Lock()
				health := store.ready()
				store.mu.Unlock()
				if health != nil {
					retain()
					return
				} // Never turn uncertain history into release.
				registry.Close()
				closeProvider()
				store.Close()
			})
			plaintext, err := os.ReadFile(filepath.Join(repo, "biozero/bio/fixtures/variant-smoke/reads.fastq"))
			if err != nil {
				t.Fatal(err)
			}
			inputPath := filepath.Join(runRoot, "verified.fastq")
			if err := os.WriteFile(inputPath, plaintext, 0600); err != nil {
				t.Fatal(err)
			}
			input, err := os.Open(inputPath)
			if err != nil {
				t.Fatal(err)
			}
			defer input.Close()
			facts := AnalysisContext{OriginalName: "public-synthetic.fastq", ProcessedSizeBytes: int64(len(plaintext)), Decrypted: true, SignatureValid: true}
			request := BridgeRequestV2{SchemaVersion: 2, Operation: "submit", JobID: "0000000000000007", UploadSHA256: digest([]byte("synthetic ciphertext placeholder")), ExpectedProfileSHA256: profile, ProcessedSHA256: digest(plaintext), ProcessedBytes: int64(len(plaintext)), OriginalName: facts.OriginalName, AnalysisContext: facts}
			audit := &analysisBridgeAudit{Broker: broker, storeRoot: storeRoot, journalRoot: journalRoot}
			socket := filepath.Join(runRoot, "channel", "bridge.sock")
			uid := uint32(os.Geteuid())
			server, err := ListenBridgeUnixV2(UnixServerConfig{SocketPath: socket, AllowedUID: &uid}, audit)
			if err != nil {
				t.Fatal(err)
			}
			serverCtx, stop := context.WithCancel(context.Background())
			serverDone := make(chan error, 1)
			go func() { serverDone <- server.Serve(serverCtx) }()
			t.Cleanup(func() {
				stop()
				server.Close()
				if err := <-serverDone; err != nil {
					t.Error(err)
				}
			})
			ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
			defer cancel()
			response, output, err := CallBridgeUnixV2(ctx, socket, request, input)
			if output != nil {
				output.Close()
				t.Fatal("submit exposed receipt FD")
			}
			if err != nil || response.ErrorCode != "" || !response.HasManifest {
				observed.mu.Lock()
				completion := observed.completion
				observed.mu.Unlock()
				t.Fatalf("capsule/commit/Unix failure: transport=%v bridge=%s provider=%v quiescent=%v", err, response.ErrorCode, completion.Err, completion.Quiescent)
			}
			m := response.Manifest
			if response.State != "committed" || len(m.Files) != 4 || m.ObservedSHA256 != m.EvaluatedSHA256 || m.ObservedSHA256 != m.Files["normalized_vcf"].SHA256 || audit.submitWrites.Load() != 1 {
				t.Fatal("analysis changed exact custody or commit-before-ACK")
			}
			receiptRaw, err := os.ReadFile(filepath.Join(storeRoot, "objects", response.LeaseID, "execution_receipt"))
			if err != nil || digest(receiptRaw) != m.Files["execution_receipt"].SHA256 {
				t.Fatal("receipt custody mismatch", err)
			}
			query := request
			query.Operation, query.ProcessedSHA256, query.OriginalName, query.ProcessedBytes, query.AnalysisContext = "receipt", "", "", 0, AnalysisContext{}
			readback, receiptFD, err := CallBridgeUnixV2(ctx, socket, query, nil)
			if err != nil || receiptFD == nil || readback.ErrorCode != "" || readback.ManifestSHA256 != response.ManifestSHA256 {
				t.Fatal("committed receipt FD readback failed", err)
			}
			wireReceipt, err := io.ReadAll(io.NewSectionReader(receiptFD, 0, MaxBridgeReceiptBytes+1))
			receiptFD.Close()
			if err != nil || !bytes.Equal(wireReceipt, receiptRaw) {
				t.Fatal("received FD bytes differ from committed custody", err)
			}
			var receipt struct {
				SchemaVersion   int             `json:"schema_version"`
				InputSHA256     string          `json:"input_sha256"`
				AnalysisContext AnalysisContext `json:"analysis_context"`
				SourcePins      map[string]struct {
					SHA256 string `json:"sha256"`
					Bytes  int64  `json:"bytes"`
				} `json:"source_pins"`
				AnalysisCapture struct {
					Returncode int `json:"returncode"`
					Payload    struct {
						Status    string `json:"status"`
						ErrorCode string `json:"error_code"`
						Detection *struct {
							Score   float64  `json:"score"`
							Verdict string   `json:"verdict"`
							Reason  string   `json:"reason"`
							Reasons []string `json:"reasons"`
							Signals struct {
								Alignment struct {
									MappedReads int            `json:"mapped_reads"`
									TotalReads  int            `json:"total_reads"`
									Targets     map[string]int `json:"targets"`
								} `json:"alignment"`
							} `json:"signals"`
						} `json:"detection"`
					} `json:"payload"`
				} `json:"analysis_capture"`
				Evaluation struct {
					Returncode int `json:"returncode"`
					Payload    struct {
						TP        int     `json:"tp"`
						FP        int     `json:"fp"`
						FN        int     `json:"fn"`
						Status    string  `json:"evaluation_status"`
						Precision float64 `json:"precision"`
						Recall    float64 `json:"recall"`
					} `json:"payload"`
				} `json:"evaluation"`
			}
			if json.Unmarshal(receiptRaw, &receipt) != nil || receipt.SchemaVersion != 2 || receipt.AnalysisContext != facts || receipt.InputSHA256 != digest(plaintext) {
				t.Fatal("receipt failed analysis context/plaintext binding")
			}
			for name, expected := range map[string]PinnedAsset{"analysis_executable": executablePin, "analysis_rules": analysis.Rules, "analysis_panel": reference} {
				info, err := os.Stat(expected.Path)
				pin, ok := receipt.SourcePins[name]
				if err != nil || !ok || pin.SHA256 != expected.SHA256 || pin.Bytes != info.Size() {
					t.Fatal("receipt missing exact verified analysis asset binding")
				}
			}
			if receipt.Evaluation.Returncode != 0 || receipt.Evaluation.Payload.TP != 3 || receipt.Evaluation.Payload.FP != 0 || receipt.Evaluation.Payload.FN != 0 || receipt.Evaluation.Payload.Status != "passed" || receipt.Evaluation.Payload.Precision != 1 || receipt.Evaluation.Payload.Recall != 1 {
				t.Fatal("three-SNP evaluator did not run successfully inside capsule")
			}
			if scenario == "panel_success" {
				a := receipt.AnalysisCapture
				if m.ExecutionStatus != "succeeded" || m.ReleaseStatus != "evaluated_passed" || a.Returncode != 0 || a.Payload.Status != "succeeded" || a.Payload.Detection == nil {
					t.Fatal("analysis did not succeed or withheld valid synthetic science")
				}
				d := a.Payload.Detection
				if d.Score != .7 || d.Verdict != "medium" || d.Reason != "threat_panel_hit" || len(d.Reasons) != 1 || d.Reasons[0] != "threat_panel_hit" || d.Signals.Alignment.MappedReads != 1171 || d.Signals.Alignment.TotalReads != 1171 || len(d.Signals.Alignment.Targets) != 1 {
					t.Fatal("actual in-capsule minimap2 detection metrics changed")
				}
			} else {
				if m.ExecutionStatus != "failed" || m.ReleaseStatus != "withheld" || m.ErrorCode != "capsule_analysis_failed" || receipt.AnalysisCapture.Returncode != 1 || receipt.AnalysisCapture.Payload.Status != "failed" || receipt.AnalysisCapture.Payload.ErrorCode != "rules_parse_error" || receipt.AnalysisCapture.Payload.Detection != nil {
					t.Fatal("analysis failure released or fabricated successful detection")
				}
			}
			// Repeat queries must retain the exact lease, bytes and charge without
			// executing an analysis or scientific tool a second time.
			before := store.Snapshot()
			query.Operation = "status"
			statusResponse, extra, err := CallBridgeUnixV2(ctx, socket, query, nil)
			if extra != nil {
				extra.Close()
				t.Fatal("status exposed receipt FD")
			}
			if err != nil || statusResponse.ErrorCode != "" || statusResponse.ManifestSHA256 != response.ManifestSHA256 {
				t.Fatal("status changed committed binding")
			}
			duplicate, extra, err := CallBridgeUnixV2(ctx, socket, request, input)
			if extra != nil {
				extra.Close()
				t.Fatal("duplicate exposed receipt FD")
			}
			if err != nil || duplicate.ErrorCode != "" || duplicate.LeaseID != response.LeaseID || duplicate.ManifestSHA256 != response.ManifestSHA256 {
				t.Fatal("exact duplicate changed custody", err)
			}
			changed := request
			changed.AnalysisContext.SignatureValid = false
			conflict, extra, err := CallBridgeUnixV2(ctx, socket, changed, input)
			if extra != nil {
				extra.Close()
				t.Fatal("conflict exposed receipt FD")
			}
			if err != nil || conflict.ErrorCode != "artifact_bridge_handler_failed" {
				t.Fatal("changed verifier facts did not conflict", err)
			}
			_, extra, conflictErr := broker.HandleBridgeV2(ctx, changed, input)
			if extra != nil {
				extra.Close()
				t.Fatal("local conflict exposed receipt FD")
			}
			if conflictErr == nil || conflictErr.Error() != "artifact_bridge_conflict" {
				t.Fatal("local broker did not reject changed context identity", conflictErr)
			}
			observed.mu.Lock()
			calls := observed.calls
			observed.mu.Unlock()
			after := store.Snapshot()
			if calls != 1 || before.ChargedBytes != after.ChargedBytes || before.RetainedOrReservedJobs != after.RetainedOrReservedJobs {
				t.Fatal("query/replay changed execution or charge")
			}
			anchors, err := os.ReadDir(workspace)
			if err != nil || len(anchors) != 0 {
				t.Fatal("workspace/control anchors not cleaned after proven completion", err)
			}
			t.Log("actual v2 FD broker, capsule analysis/evaluation, committed private receipt, duplicate custody and Unix ACK verified; protected crypto worker remains untested here")
		})
	}
}
