//go:build linux

package artifactexecutor

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
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
