//go:build linux

package artifactexecutor

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func nativeChannelFixture(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	fd, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	connections := make([]*net.UnixConn, 2)
	for index, descriptor := range fd {
		file := os.NewFile(uintptr(descriptor), "native-fixture-channel")
		conn, err := net.FileConn(file)
		file.Close()
		if err != nil {
			t.Fatal(err)
		}
		connections[index] = conn.(*net.UnixConn)
		t.Cleanup(func() { conn.Close() })
	}
	return connections[0], connections[1]
}

func TestNativeRightsTransportIsReadonlyAndCloseOnExec(t *testing.T) {
	parent, child := nativeChannelFixture(t)
	data := []byte("private synthetic execution receipt\n")
	path := filepath.Join(t.TempDir(), "receipt")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	response := nativeResponse{SchemaVersion: 1, Outcome: nativeOutcome{ExecutionStatus: "succeeded", ReleaseStatus: "unassessed"}, Files: []nativeFile{{ID: "execution_receipt", SHA256: digest(data), Bytes: int64(len(data))}}}
	raw, err := jsonBytes(response)
	if err != nil {
		t.Fatal(err)
	}
	frame := append([]byte{0, 0, byte(len(raw) >> 8), byte(len(raw))}, raw...)
	if n, _, err := child.WriteMsgUnix(frame, syscall.UnixRights(int(source.Fd())), nil); err != nil || n != len(frame) {
		t.Fatal("rights send failed", err)
	}
	child.Close()
	got, files, err := readNativeResponse(parent)
	for _, f := range files {
		defer f.Close()
	}
	if err != nil || validateNativeResponse(got, files) != nil || len(files) != 1 {
		t.Fatal("rights response failed", err)
	}
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, files[0].Fd(), syscall.F_GETFD, 0)
	if errno != 0 || flags&syscall.FD_CLOEXEC == 0 {
		t.Fatal("received FD inherited by exec")
	}
	retained, err := os.ReadFile(fdPath(files[0]))
	if err != nil || string(retained) != string(data) {
		t.Fatal("rights bytes mismatch", err)
	}
}

func TestNativeMetadataRejectsWritableUnknownMissingAndOversizedFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receipt")
	data := []byte("synthetic receipt")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	ro, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	rw, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer rw.Close()
	base := nativeResponse{SchemaVersion: 1, Outcome: nativeOutcome{ExecutionStatus: "succeeded", ReleaseStatus: "unassessed"}, Files: []nativeFile{{ID: "execution_receipt", SHA256: digest(data), Bytes: int64(len(data))}}}
	for _, name := range []string{"writable", "unknown", "size", "missing", "digest"} {
		t.Run(name, func(t *testing.T) {
			candidate := base
			candidate.Files = append([]nativeFile{}, base.Files...)
			fds := []*os.File{ro}
			switch name {
			case "writable":
				fds[0] = rw
			case "unknown":
				candidate.Files[0].ID = "arbitrary_file"
			case "size":
				candidate.Files[0].Bytes = 64<<20 + 1
			case "missing":
				fds = nil
			case "digest":
				candidate.Files[0].SHA256 = "invalid"
			}
			if err := validateNativeResponse(candidate, fds); err == nil {
				t.Fatal("invalid FD metadata accepted")
			}
		})
	}
}

func TestNativeFrameRejectsTrailingAndMissingRights(t *testing.T) {
	parent, child := nativeChannelFixture(t)
	raw := []byte(`{"schema_version":1,"outcome":{"execution_status":"failed","release_status":"withheld","error_code":"capsule_failed","observed_sha256":"","evaluated_sha256":""},"files":[]}`)
	frame := append([]byte{0, 0, byte(len(raw) >> 8), byte(len(raw))}, raw...)
	frame = append(frame, 'x')
	if _, err := child.Write(frame); err != nil {
		t.Fatal(err)
	}
	child.Close()
	_, files, err := readNativeResponse(parent)
	for _, f := range files {
		f.Close()
	}
	if err == nil {
		t.Fatal("extra native frame bytes accepted")
	}
}

func TestNativeProviderActualSyntheticVariants(t *testing.T) {
	if os.Getenv("BIOZERO_RUN_NATIVE_PROVIDER_ACCEPTANCE") != "1" {
		t.Skip("opt-in kernel/provider/scientific acceptance")
	}
	repo, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	asset := func(path string) PinnedAsset {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return PinnedAsset{Path: path, SHA256: digest(b)}
	}
	base := t.TempDir()
	if evidence := os.Getenv("BIOZERO_NATIVE_PROVIDER_EVIDENCE_DIR"); evidence != "" {
		if !filepath.IsAbs(evidence) || os.Mkdir(evidence, 0700) != nil {
			t.Fatal("native evidence directory must be new and absolute")
		}
		base = evidence // Operator-selected private evidence is preserved on failure.
	}
	helper := asset(filepath.Join(repo, "biozero/services/artifact-executor/capsule/native_capsule.py"))
	pipeline := asset(filepath.Join(repo, "biozero/bio/pipeline/pipeline.py"))
	budget := asset(filepath.Join(repo, "biozero/bio/pipeline/resource_budget.py"))
	python, err := filepath.EvalSymlinks("/usr/bin/python3")
	if err != nil {
		t.Fatal(err)
	}
	config := NativeProviderConfig{WorkspaceRoot: filepath.Join(base, "workspaces"), PythonPath: python,
		ToolPath: "/tmp/biozero-bio-tools-locked/bin:/usr/bin", Mode: "variants", Helper: helper, Pipeline: pipeline,
		Reference: asset(filepath.Join(repo, "biozero/bio/fixtures/variant-smoke/reference.fa")),
		Evaluator: asset(filepath.Join(repo, "biozero/bio/benchmarks/evaluate_variants.py")),
		Truth:     asset(filepath.Join(repo, "biozero/bio/fixtures/variant-smoke/expected.vcf")), ResourceBudgetSHA256: budget.SHA256, TimeoutSeconds: 120}
	provider, err := NewNativeProvider(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	s, err := Open(context.Background(), filepath.Join(base, "store"), NativeArtifactPolicy())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	r, err := NewInputRegistry(s)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	c, err := NewCoordinator(s, r, provider)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	plaintext, err := os.ReadFile(filepath.Join(repo, "biozero/bio/fixtures/variant-smoke/reads.fastq"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(base, "verified.fastq")
	if err := os.WriteFile(path, plaintext, 0600); err != nil {
		t.Fatal(err)
	}
	input, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	registered, err := c.RegisterInput(context.Background(), "0000000000000001", digest([]byte("synthetic original upload fixture")), digest(plaintext), int64(len(plaintext)), input)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := c.Handle(context.Background(), runRequest(registered))
	if err != nil {
		t.Fatal(err)
	}
	var response ExecutionResponse
	if json.Unmarshal(raw, &response) != nil || response.Manifest == nil || response.Manifest.ExecutionStatus != "succeeded" || response.Manifest.ReleaseStatus != "evaluated_passed" || len(response.Manifest.Files) != 4 {
		if response.Manifest != nil {
			t.Fatalf("native capsule failed: execution=%s release=%s code=%s exports=%d", response.Manifest.ExecutionStatus, response.Manifest.ReleaseStatus, response.Manifest.ErrorCode, len(response.Manifest.Files))
		}
		t.Fatal("actual native capsule did not demonstrate passed synthetic science")
	}
	if response.Manifest.ObservedSHA256 != response.Manifest.EvaluatedSHA256 || response.Manifest.ObservedSHA256 != response.Manifest.Files["normalized_vcf"].SHA256 {
		t.Fatal("actual observed/evaluated/retained VCF mismatch")
	}
	if err := c.Acknowledge(context.Background(), runRequest(registered), func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	list, err := os.ReadDir(config.WorkspaceRoot)
	if err != nil || len(list) != 0 {
		t.Fatal("host workspace anchors remain", err)
	}
	t.Log("actual native provider: PID1 wait, four retained exports, exact synthetic scientific release; protected-entry TLS/crypto not exercised by this module test")
}

func analysisPinnedFixture(t *testing.T, rules string) (*CapsuleAnalysisConfig, string) {
	t.Helper()
	base := t.TempDir()
	write := func(name, content string, mode os.FileMode) PinnedAsset {
		path := filepath.Join(base, name)
		if err := os.WriteFile(path, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		return PinnedAsset{path, digest([]byte(content))}
	}
	return &CapsuleAnalysisConfig{Executable: write("capsule-analysis", "synthetic pinned executable\n", 0755), Rules: write("rules.json", rules, 0600)}, filepath.Join(base, "workspaces")
}

func TestNativeAnalysisVersionedWireAndContextIsolation(t *testing.T) {
	cfg, _ := analysisPinnedFixture(t, `{}`)
	facts := &AnalysisContext{OriginalName: "synthetic.fastq", ProcessedSizeBytes: 3, Decrypted: true, SignatureValid: true}
	v1 := nativeSpec{SchemaVersion: 1, Workspace: "/private/workspace", InputBytes: 3}
	raw, err := json.Marshal(v1)
	if err != nil {
		t.Fatal(err)
	}
	// The original wire has exactly these fields in this order and no analysis.
	want := `{"schema_version":1,"workspace":"/private/workspace","input_bytes":3,"input_sha256":"","mode":"","pipeline_path":"","pipeline_sha256":"","resource_budget_sha256":"","reference_path":"","reference_sha256":"","evaluator_path":"","evaluator_sha256":"","truth_path":"","truth_sha256":"","python_path":"","tool_path":"","timeout_seconds":0}`
	if string(raw) != want {
		t.Fatal("legacy wire changed")
	}
	for _, container := range []bool{false, true} {
		spec, err := analysisForInput(cfg, facts, 3, container)
		if err != nil {
			t.Fatal(err)
		}
		v2 := v1
		v2.SchemaVersion = 2
		v2.Analysis = spec
		raw, err = json.Marshal(v2)
		if err != nil {
			t.Fatal(err)
		}
		var obj map[string]json.RawMessage
		if json.Unmarshal(raw, &obj) != nil || len(obj) != 18 || string(obj["schema_version"]) != "2" {
			t.Fatal("invalid v2 shape")
		}
		var analysis map[string]json.RawMessage
		if json.Unmarshal(obj["analysis"], &analysis) != nil || len(analysis) != 7 {
			t.Fatal("analysis shape changed")
		}
		var contextObj map[string]json.RawMessage
		if json.Unmarshal(analysis["context"], &contextObj) != nil || len(contextObj) != 6 {
			t.Fatal("context shape changed")
		}
		if spec.Context != *facts {
			t.Fatal("context changed in projection")
		}
		if container {
			if spec.ExecutablePath != "/run/biozero/analysis/capsule-analysis" || spec.RulesPath != "/run/biozero/analysis/rules.json" || spec.PanelPath != "" {
				t.Fatal("container paths not fixed")
			}
		} else if spec.ExecutablePath != cfg.Executable.Path || spec.RulesPath != cfg.Rules.Path {
			t.Fatal("native paths changed")
		}
		facts.OriginalName = "changed.fastq"
		if spec.Context.OriginalName == facts.OriginalName {
			t.Fatal("context alias retained")
		}
		facts.OriginalName = "synthetic.fastq"
	}
	clone := copyCapsuleAnalysis(cfg)
	clone.Executable.Path = "changed"
	if clone == cfg || cfg.Executable.Path == clone.Executable.Path {
		t.Fatal("configuration aliases caller memory")
	}
	if copyCapsuleAnalysis(nil) != nil {
		t.Fatal("legacy config enabled analysis")
	}
}

func TestNativeAnalysisCannotDowngradeOrInventContext(t *testing.T) {
	cfg, _ := analysisPinnedFixture(t, `{}`)
	good := AnalysisContext{OriginalName: "fixture.fastq", ProcessedSizeBytes: 7}
	tests := []struct {
		name  string
		cfg   *CapsuleAnalysisConfig
		facts *AnalysisContext
		bytes int64
		valid bool
	}{
		{"legacy", nil, nil, 7, true}, {"enabled", cfg, &good, 7, true},
		{"missing_context", cfg, nil, 7, false}, {"unexpected_context", nil, &good, 7, false}, {"size_mismatch", cfg, &good, 8, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := analysisForInput(tt.cfg, tt.facts, tt.bytes, false)
			if (err == nil) != tt.valid {
				t.Fatal("incorrect context gate", err)
			}
		})
	}
}

func TestNativeAnalysisPinsPermissionsAndSourceBounds(t *testing.T) {
	for _, name := range []string{"valid_0755", "no_execute", "group_write", "symlink", "hardlink", "digest", "oversize", "missing_executable", "missing_rules", "inside_workspace", "container_csv"} {
		t.Run(name, func(t *testing.T) {
			cfg, root := analysisPinnedFixture(t, `{}`)
			switch name {
			case "no_execute":
				if err := os.Chmod(cfg.Executable.Path, 0600); err != nil {
					t.Fatal(err)
				}
			case "group_write":
				if err := os.Chmod(cfg.Executable.Path, 0775); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				link := cfg.Executable.Path + ".link"
				if err := os.Symlink(cfg.Executable.Path, link); err != nil {
					t.Fatal(err)
				}
				cfg.Executable.Path = link
			case "hardlink":
				if err := os.Link(cfg.Executable.Path, cfg.Executable.Path+".link"); err != nil {
					t.Fatal(err)
				}
			case "digest":
				cfg.Executable.SHA256 = strings.Repeat("0", 64)
			case "oversize":
				if err := os.Truncate(cfg.Executable.Path, (4<<20)+1); err != nil {
					t.Fatal(err)
				}
			case "missing_executable":
				cfg.Executable = PinnedAsset{}
			case "missing_rules":
				cfg.Rules = PinnedAsset{}
			case "inside_workspace":
				root = filepath.Dir(cfg.Executable.Path)
			case "container_csv":
				path := cfg.Executable.Path + ",readonly=false"
				if err := os.Rename(cfg.Executable.Path, path); err != nil {
					t.Fatal(err)
				}
				cfg.Executable.Path = path
			}
			err := verifyCapsuleAnalysis(context.Background(), cfg, root, true)
			if (err == nil) != (name == "valid_0755") {
				t.Fatal("incorrect source gate", err)
			}
		})
	}
}

func TestNativeAnalysisPanelPresenceDoesNotReplaceStrictCLI(t *testing.T) {
	tests := []struct {
		name, rules  string
		panel, valid bool
	}{
		{"disabled", `{}`, false, true}, {"disabled_explicit", `{"threat_panel_fasta":""}`, false, true},
		{"enabled", `{"threat_panel_fasta":"/trusted/host/panel.fa"}`, true, true},
		{"enabled_missing_asset", `{"threat_panel_fasta":"/trusted/panel.fa"}`, false, false},
		{"asset_without_rules", `{}`, true, false}, {"null_panel", `{"threat_panel_fasta":null}`, false, false},
		{"duplicate", `{"threat_panel_fasta":"","threat_panel_fasta":""}`, false, false},
		{"trailing", `{} {}`, false, false}, {"unknown_deferred_to_cli", `{"unknownfield1":true}`, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, root := analysisPinnedFixture(t, tt.rules)
			if tt.panel {
				raw := []byte(">synthetic\nACGT\n")
				p := filepath.Join(filepath.Dir(cfg.Rules.Path), "panel.fa")
				if err := os.WriteFile(p, raw, 0600); err != nil {
					t.Fatal(err)
				}
				cfg.Panel = PinnedAsset{p, digest(raw)}
			}
			err := verifyCapsuleAnalysis(context.Background(), cfg, root, false)
			if (err == nil) != tt.valid {
				t.Fatal("incorrect panel gate", err)
			}
			if tt.panel && tt.valid {
				a, err := analysisForInput(cfg, &AnalysisContext{}, 0, true)
				if err != nil || a.PanelPath != "/run/biozero/analysis/panel.fa" || a.PanelSHA256 != cfg.Panel.SHA256 {
					t.Fatal("panel projection failed", err)
				}
			}
		})
	}
}

func TestNativeAnalysisRejectsBeforeWorkspaceOrProducer(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "context_without_config", true: "config_without_context"}[enabled], func(t *testing.T) {
			cfg, root := analysisPinnedFixture(t, `{}`)
			assets := filepath.Dir(cfg.Rules.Path)
			write := func(name string) PinnedAsset {
				raw := []byte("synthetic source\n")
				p := filepath.Join(assets, name)
				if err := os.WriteFile(p, raw, 0600); err != nil {
					t.Fatal(err)
				}
				return PinnedAsset{p, digest(raw)}
			}
			helper, pipeline, budget := write("helper.py"), write("pipeline.py"), write("resource_budget.py")
			store, err := Open(context.Background(), filepath.Join(assets, "store"), NativeArtifactPolicy())
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			inputAsset := write("input.fastq")
			file, err := os.Open(inputAsset.Path)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			info, err := file.Stat()
			if err != nil {
				t.Fatal(err)
			}
			input := &ScopedInput{file: file, Bytes: info.Size(), ProcessedSHA256: inputAsset.SHA256}
			config := NativeProviderConfig{WorkspaceRoot: root, Helper: helper, Pipeline: pipeline, ResourceBudgetSHA256: budget.SHA256, TimeoutSeconds: 5}
			if enabled {
				config.Analysis = cfg
			} else {
				input.AnalysisContext = &AnalysisContext{ProcessedSizeBytes: info.Size()}
			}
			// No workspace FD or executable is supplied: only the pre-execution gate may run.
			provider := &NativeProvider{config: config}
			done := provider.Execute(context.Background(), input, &Exporter{store: store})
			if done.Err == nil || done.Outcome.ErrorCode != "artifact_analysis_context_invalid" || !done.Quiescent || done.Outcome.ReleaseStatus != "withheld" {
				t.Fatal("invalid context reached producer", done)
			}
			if _, err := os.Lstat(root); !os.IsNotExist(err) {
				t.Fatal("workspace created before context validation")
			}
			if len(store.data.Records) != 0 {
				t.Fatal("context rejection changed accounting")
			}
		})
	}
}
