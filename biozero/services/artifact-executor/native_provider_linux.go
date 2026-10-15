//go:build linux

package artifactexecutor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

type PinnedAsset struct {
	Path   string
	SHA256 string
}

// CapsuleAnalysisConfig is fixed host configuration, never an RPC surface.
// Optional Panel must agree in presence with the pinned rules before execution.
type CapsuleAnalysisConfig struct {
	Executable, Rules, Panel PinnedAsset
}

type nativeAnalysisSpec struct {
	ExecutablePath   string          `json:"executable_path"`
	ExecutableSHA256 string          `json:"executable_sha256"`
	RulesPath        string          `json:"rules_path"`
	RulesSHA256      string          `json:"rules_sha256"`
	PanelPath        string          `json:"panel_path"`
	PanelSHA256      string          `json:"panel_sha256"`
	Context          AnalysisContext `json:"context"`
}

func copyCapsuleAnalysis(config *CapsuleAnalysisConfig) *CapsuleAnalysisConfig {
	if config == nil {
		return nil
	}
	copy := *config
	return &copy
}

// Verify pinned metadata before any workspace/producer exists. Rules are parsed
// here only to preserve panel presence; the strict CLI still validates all rule
// fields inside the capsule, and can fail without approving prior pipeline work.
func verifyCapsuleAnalysis(ctx context.Context, config *CapsuleAnalysisConfig, workspaceRoot string, container bool) error {
	if config == nil {
		return nil
	}
	root, err := filepath.Abs(workspaceRoot)
	if err != nil {
		return fail("artifact_analysis_config_invalid")
	}
	for _, entry := range []struct {
		asset      PinnedAsset
		limit      int64
		executable bool
		optional   bool
	}{
		{config.Executable, 4 << 20, true, false}, {config.Rules, 64 << 10, false, false}, {config.Panel, 32 << 20, false, true},
	} {
		a := entry.asset
		if a.Path == "" && a.SHA256 == "" && entry.optional {
			continue
		}
		if a.Path == "" || !hexID(a.SHA256, 64) || a.Path == root || strings.HasPrefix(a.Path, root+"/") || (container && !safeContainerSource(a.Path)) {
			return fail("artifact_analysis_config_invalid")
		}
		f, err := openPinnedAsset(ctx, a, entry.limit)
		if err != nil {
			return fail("artifact_analysis_asset_invalid")
		}
		if entry.executable {
			info, e := f.Stat()
			if e != nil {
				f.Close()
				return fail("artifact_analysis_asset_invalid")
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			// Capsule UID maps this host UID; a private root-owned executable would not
			// have the same permission/owner interpretation in the native namespace.
			if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0100 == 0 {
				f.Close()
				return fail("artifact_analysis_executable_invalid")
			}
		}
		f.Close()
	}
	rules, err := openPinnedAsset(ctx, config.Rules, 64<<10)
	if err != nil {
		return fail("artifact_analysis_asset_invalid")
	}
	defer rules.Close()
	raw, err := io.ReadAll(io.NewSectionReader(rules, 0, (64<<10)+1))
	if err != nil || len(raw) > 64<<10 || digest(raw) != config.Rules.SHA256 {
		return fail("artifact_analysis_asset_invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, err := scanJSON(decoder, 0)
	if err != nil {
		return fail("artifact_analysis_rules_invalid")
	}
	if _, err = decoder.Token(); err != io.EOF {
		return fail("artifact_analysis_rules_invalid")
	}
	object, ok := value.(map[string]any)
	if !ok {
		return fail("artifact_analysis_rules_invalid")
	}
	enabled := false
	if field, exists := object["threat_panel_fasta"]; exists {
		path, ok := field.(string)
		if !ok {
			return fail("artifact_analysis_rules_invalid")
		}
		enabled = path != ""
	}
	if enabled != (config.Panel.Path != "") {
		return fail("artifact_analysis_panel_mismatch")
	}
	return nil
}

func analysisForInput(config *CapsuleAnalysisConfig, facts *AnalysisContext, bytes int64, container bool) (*nativeAnalysisSpec, error) {
	if (config == nil) != (facts == nil) {
		return nil, fail("artifact_analysis_context_invalid")
	}
	if config == nil {
		return nil, nil
	}
	if validateAnalysisContext(*facts, bytes) != nil {
		return nil, fail("artifact_analysis_context_invalid")
	}
	a := &nativeAnalysisSpec{ExecutablePath: config.Executable.Path, ExecutableSHA256: config.Executable.SHA256, RulesPath: config.Rules.Path, RulesSHA256: config.Rules.SHA256, PanelPath: config.Panel.Path, PanelSHA256: config.Panel.SHA256, Context: *facts}
	if container {
		a.ExecutablePath = "/run/biozero/analysis/capsule-analysis"
		a.RulesPath = "/run/biozero/analysis/rules.json"
		if a.PanelPath != "" {
			a.PanelPath = "/run/biozero/analysis/panel.fa"
		}
	}
	return a, nil
}

// NativeProviderConfig is trusted host configuration. None of its paths, tool
// selection, policy or limits are accepted through run/status/cancel RPC.
type NativeProviderConfig struct {
	WorkspaceRoot               string
	PythonPath, ToolPath, Mode  string
	Helper, Pipeline, Reference PinnedAsset
	Evaluator, Truth            PinnedAsset
	ResourceBudgetSHA256        string
	TimeoutSeconds              int
	Analysis                    *CapsuleAnalysisConfig
}

type NativeProvider struct {
	mu     sync.Mutex
	config NativeProviderConfig
	root   *os.File
	closed bool
}

type nativeSpec struct {
	SchemaVersion        int                 `json:"schema_version"`
	Workspace            string              `json:"workspace"`
	InputBytes           int64               `json:"input_bytes"`
	InputSHA256          string              `json:"input_sha256"`
	Mode                 string              `json:"mode"`
	PipelinePath         string              `json:"pipeline_path"`
	PipelineSHA256       string              `json:"pipeline_sha256"`
	ResourceBudgetSHA256 string              `json:"resource_budget_sha256"`
	ReferencePath        string              `json:"reference_path"`
	ReferenceSHA256      string              `json:"reference_sha256"`
	EvaluatorPath        string              `json:"evaluator_path"`
	EvaluatorSHA256      string              `json:"evaluator_sha256"`
	TruthPath            string              `json:"truth_path"`
	TruthSHA256          string              `json:"truth_sha256"`
	PythonPath           string              `json:"python_path"`
	ToolPath             string              `json:"tool_path"`
	TimeoutSeconds       int                 `json:"timeout_seconds"`
	Analysis             *nativeAnalysisSpec `json:"analysis,omitempty"`
}

type nativeFile struct {
	ID     string `json:"id"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

type nativeOutcome struct {
	ExecutionStatus string `json:"execution_status"`
	ReleaseStatus   string `json:"release_status"`
	ErrorCode       string `json:"error_code"`
	ObservedSHA256  string `json:"observed_sha256"`
	EvaluatedSHA256 string `json:"evaluated_sha256"`
}

type nativeResponse struct {
	SchemaVersion int           `json:"schema_version"`
	Outcome       nativeOutcome `json:"outcome"`
	Files         []nativeFile  `json:"files"`
}

// NativeArtifactPolicy is explicit rather than a silent change to older store
// history. The private execution receipt shares the existing 64MiB export budget.
// Opening an old store with this changed policy still requires reviewed migration.
func NativeArtifactPolicy() Policy {
	p := DefaultPolicy()
	p.ArtifactIDs = []string{"execution_receipt", "normalized_vcf", "variants_vcf", "variants_vcf_index"}
	return p
}

func openPinnedAsset(ctx context.Context, asset PinnedAsset, maximum int64) (*os.File, error) {
	if !filepath.IsAbs(asset.Path) || filepath.Clean(asset.Path) != asset.Path || !hexID(asset.SHA256, 64) {
		return nil, fail("artifact_native_asset_invalid")
	}
	dir, err := unixExistingDirectoryLoose(filepath.Dir(asset.Path))
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	fd, err := syscall.Openat(int(dir.Fd()), filepath.Base(asset.Path), syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fail("artifact_native_asset_unsafe")
	}
	f := os.NewFile(uintptr(fd), "artifact-pinned-asset")
	accepted := false
	defer func() {
		if !accepted {
			f.Close()
		}
	}()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maximum {
		return nil, fail("artifact_native_asset_unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 || stat.Mode&0022 != 0 || stat.Mode&07000 != 0 || (stat.Uid != uint32(os.Geteuid()) && stat.Uid != 0) {
		return nil, fail("artifact_native_asset_unsafe")
	}
	h := sha256.New()
	reader := io.NewSectionReader(f, 0, maximum+1)
	buf := make([]byte, 65536)
	var total int64
	for {
		if ctx.Err() != nil {
			return nil, fail("artifact_cancelled")
		}
		n, err := reader.Read(buf)
		total += int64(n)
		h.Write(buf[:n])
		if total > maximum {
			return nil, fail("artifact_native_asset_oversized")
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fail("artifact_native_asset_unreadable")
		}
	}
	if hex.EncodeToString(h.Sum(nil)) != asset.SHA256 {
		return nil, fail("artifact_native_asset_digest_mismatch")
	}
	accepted = true
	return f, nil
}

// Source code/public references need not be mode0600. Ancestors still reject
// symlinks through openat; their privileged/shared-UID writers remain trusted.
func unixExistingDirectoryLoose(path string) (*os.File, error) {
	if !filepath.IsAbs(path) {
		return nil, fail("artifact_native_asset_unsafe")
	}
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fail("artifact_native_asset_unsafe")
	}
	for _, name := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if name == "" {
			continue
		}
		next, err := syscall.Openat(fd, name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		syscall.Close(fd)
		if err != nil {
			return nil, fail("artifact_native_asset_unsafe")
		}
		fd = next
	}
	return os.NewFile(uintptr(fd), "artifact-source-directory"), nil
}

func (p *NativeProvider) verifyAssets(ctx context.Context) error {
	assets := []struct {
		asset PinnedAsset
		limit int64
	}{{p.config.Helper, 1 << 20}, {p.config.Pipeline, 1 << 20},
		{PinnedAsset{filepath.Join(filepath.Dir(p.config.Pipeline.Path), "resource_budget.py"), p.config.ResourceBudgetSHA256}, 1 << 20}}
	for _, item := range []struct {
		asset PinnedAsset
		limit int64
	}{{p.config.Reference, 32 << 20}, {p.config.Evaluator, 1 << 20}, {p.config.Truth, 8 << 20}} {
		if item.asset.Path != "" {
			assets = append(assets, item)
		}
	}
	for _, item := range assets {
		f, err := openPinnedAsset(ctx, item.asset, item.limit)
		if err != nil {
			return err
		}
		f.Close()
	}
	return verifyCapsuleAnalysis(ctx, p.config.Analysis, p.config.WorkspaceRoot, false)
}

func NewNativeProvider(ctx context.Context, config NativeProviderConfig) (*NativeProvider, error) {
	if os.Getuid() != 1000 || os.Geteuid() != 1000 || os.Getgid() != 1000 || os.Getegid() != 1000 || config.Mode != "stats" && config.Mode != "variants" || config.TimeoutSeconds < 1 || config.TimeoutSeconds > 600 || !filepath.IsAbs(config.PythonPath) || config.ToolPath == "" || config.WorkspaceRoot == "" {
		return nil, fail("artifact_native_config_invalid")
	}
	for _, directory := range strings.Split(config.ToolPath, ":") {
		f, err := unixExistingDirectoryLoose(directory)
		if err != nil {
			return nil, fail("artifact_native_config_invalid")
		}
		f.Close()
	}
	python, err := filepath.EvalSymlinks(config.PythonPath)
	if err != nil || python != config.PythonPath {
		return nil, fail("artifact_native_config_invalid")
	}
	if config.Mode == "variants" && config.Reference.Path == "" {
		return nil, fail("artifact_native_config_invalid")
	}
	if (config.Evaluator.Path == "") != (config.Truth.Path == "") {
		return nil, fail("artifact_native_config_invalid")
	}
	for _, asset := range []PinnedAsset{config.Reference, config.Evaluator, config.Truth} {
		if (asset.Path == "") != (asset.SHA256 == "") {
			return nil, fail("artifact_native_config_invalid")
		}
	}
	config.WorkspaceRoot, err = filepath.Abs(config.WorkspaceRoot)
	if err != nil {
		return nil, fail("artifact_native_config_invalid")
	}
	config.Analysis = copyCapsuleAnalysis(config.Analysis)
	provider := &NativeProvider{config: config}
	if err := provider.verifyAssets(ctx); err != nil {
		return nil, err
	}
	root, err := openRoot(config.WorkspaceRoot)
	if err != nil {
		return nil, err
	}
	list, err := entries(root)
	if err != nil || len(list) != 0 {
		root.Close()
		return nil, fail("artifact_native_workspace_history_unknown")
	}
	provider.root = root
	return provider, nil
}

type nativeCapture struct {
	mu       sync.Mutex
	bytes    int
	exceeded bool
	cancel   context.CancelFunc
}

func (w *nativeCapture) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(data) > 65536-w.bytes {
		w.exceeded = true
		w.cancel()
		return 0, fail("artifact_native_output_limit")
	}
	w.bytes += len(data)
	// Helper output is intentionally discarded; raw upstream diagnostics never
	// become a wire response. The full pipeline verdict is a private export.
	return len(data), nil
}
func (w *nativeCapture) overflowed() bool { w.mu.Lock(); defer w.mu.Unlock(); return w.exceeded }

func nativeFailure(code string, quiescent bool) ProviderCompletion {
	return ProviderCompletion{Outcome: Outcome{"failed", "withheld", code, "", ""}, Quiescent: quiescent, Err: fail(code)}
}

func (p *NativeProvider) Execute(parent context.Context, input *ScopedInput, exporter *Exporter) (result ProviderCompletion) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || input == nil || exporter == nil || parent.Err() != nil {
		return nativeFailure("artifact_native_unavailable", true)
	}
	ctx, cancel := context.WithTimeout(parent, time.Duration(p.config.TimeoutSeconds)*time.Second)
	defer cancel()
	if err := p.verifyAssets(ctx); err != nil {
		return nativeFailure("artifact_native_asset_invalid", true)
	}
	exporter.store.mu.Lock()
	allowed := false
	for _, id := range exporter.store.data.Policy.ArtifactIDs {
		if id == "execution_receipt" {
			allowed = true
		}
	}
	exporter.store.mu.Unlock()
	if !allowed {
		return nativeFailure("artifact_native_policy_incomplete", true)
	}
	input.mu.Lock()
	file, err := duplicateReadOnly(input.file)
	inputBytes, sha := input.Bytes, input.ProcessedSHA256
	var facts *AnalysisContext
	if input.AnalysisContext != nil {
		copy := *input.AnalysisContext
		facts = &copy
	}
	input.mu.Unlock()
	if err != nil {
		return nativeFailure("artifact_native_input_unavailable", true)
	}
	defer file.Close()
	analysis, err := analysisForInput(p.config.Analysis, facts, inputBytes, false)
	if err != nil {
		return nativeFailure("artifact_analysis_context_invalid", true)
	}
	name, err := token()
	if err != nil {
		return nativeFailure("artifact_native_unavailable", true)
	}
	name = "capsule-" + name
	if err := syscall.Mkdirat(int(p.root.Fd()), name, 0700); err != nil {
		return nativeFailure("artifact_native_workspace_unavailable", true)
	}
	workspace := filepath.Join(p.config.WorkspaceRoot, name)
	defer func() {
		if !result.Quiescent {
			return
		} // An unproven Wait retains its workspace anchor.
		if os.Remove(fdPath(p.root)+"/"+name) != nil || p.root.Sync() != nil {
			exporter.store.mu.Lock()
			exporter.store.latch("artifact_native_workspace_cleanup_failed")
			exporter.store.mu.Unlock()
			result = nativeFailure("artifact_native_workspace_cleanup_failed", result.Quiescent)
		}
	}()
	if p.root.Sync() != nil {
		return nativeFailure("artifact_native_workspace_unavailable", true)
	}
	spec := nativeSpec{SchemaVersion: 1, Workspace: workspace, InputBytes: inputBytes, InputSHA256: sha, Mode: p.config.Mode,
		PipelinePath: p.config.Pipeline.Path, PipelineSHA256: p.config.Pipeline.SHA256, ResourceBudgetSHA256: p.config.ResourceBudgetSHA256,
		ReferencePath: p.config.Reference.Path, ReferenceSHA256: p.config.Reference.SHA256, EvaluatorPath: p.config.Evaluator.Path, EvaluatorSHA256: p.config.Evaluator.SHA256,
		TruthPath: p.config.Truth.Path, TruthSHA256: p.config.Truth.SHA256, PythonPath: p.config.PythonPath, ToolPath: p.config.ToolPath, TimeoutSeconds: p.config.TimeoutSeconds, Analysis: analysis}
	if analysis != nil {
		spec.SchemaVersion = 2
	}
	raw, err := jsonBytes(spec)
	if err != nil || len(raw) > MaxFrameBytes {
		return nativeFailure("artifact_native_config_invalid", true)
	}
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nativeFailure("artifact_native_unavailable", true)
	}
	parentFile, childFile := os.NewFile(uintptr(pair[0]), "artifact-native-parent"), os.NewFile(uintptr(pair[1]), "artifact-native-child")
	defer parentFile.Close()
	defer childFile.Close()
	connection, err := net.FileConn(parentFile)
	if err != nil {
		return nativeFailure("artifact_native_unavailable", true)
	}
	defer connection.Close()
	channel, ok := connection.(*net.UnixConn)
	if !ok {
		return nativeFailure("artifact_native_unavailable", true)
	}
	deadline, _ := ctx.Deadline()
	channel.SetDeadline(deadline)
	cmd := exec.CommandContext(ctx, p.config.PythonPath, "-I", "-B", "-S", p.config.Helper.Path)
	// This offline capsule intentionally receives no host credential or interpreter
	// hooks. Parent runtime/SDK authentication remains unchanged. Helper is stdlib
	// only; trusted tool paths are configured separately rather than inherited.
	cmd.Env = []string{"PATH=" + p.config.ToolPath, "LANG=C", "LC_ALL=C", "PYTHONDONTWRITEBYTECODE=1"}
	cmd.Stdin = bytes.NewReader(raw)
	cmd.ExtraFiles = []*os.File{childFile, file} // control3/input4; never Store's flock.
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWPID | syscall.CLONE_NEWNET,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}}, GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		GidMappingsEnableSetgroups: false, Credential: &syscall.Credential{Uid: 0, Gid: 0, NoSetGroups: true}, Setpgid: true, Pdeathsig: syscall.SIGKILL}
	stdout, stderr := &nativeCapture{cancel: cancel}, &nativeCapture{cancel: cancel}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.WaitDelay = time.Second
	// Linux Pdeathsig follows the creator OS thread, so it must remain alive
	// across Start and Wait. Killing PID1 tears down the private PID namespace.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := cmd.Start(); err != nil {
		return nativeFailure("artifact_native_provider_unavailable", true)
	}
	childFile.Close()
	stopChannel := context.AfterFunc(ctx, func() { channel.Close() })
	defer stopChannel()
	response, descriptors, readErr := readNativeResponse(channel)
	defer func() {
		for _, f := range descriptors {
			f.Close()
		}
	}()
	if readErr != nil {
		cancel()
	}
	waitErr := cmd.Wait() // Export never precedes actual PID1/namespace completion.
	if cmd.ProcessState == nil {
		return nativeFailure("artifact_native_wait_unproven", false)
	}
	waitStatus, validWait := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if !validWait || !waitStatus.Exited() && !waitStatus.Signaled() {
		return nativeFailure("artifact_native_wait_unproven", false)
	}
	if readErr != nil || ctx.Err() != nil || stdout.overflowed() || stderr.overflowed() {
		return nativeFailure("artifact_native_execution_failed", true)
	}
	expectedExit := 1
	if response.Outcome.ExecutionStatus == "succeeded" {
		expectedExit = 0
	}
	if !waitStatus.Exited() || waitStatus.ExitStatus() != expectedExit || (waitErr == nil) != (expectedExit == 0) {
		return nativeFailure("artifact_native_exit_contract_invalid", true)
	}
	if err := validateNativeResponse(response, descriptors); err != nil {
		return nativeFailure("artifact_native_report_invalid", true)
	}
	for index, item := range response.Files {
		f := descriptors[index]
		if err := exporter.Export(item.ID, item.SHA256, io.NewSectionReader(f, 0, item.Bytes+1)); err != nil {
			return nativeFailure("artifact_native_export_failed", true)
		}
	}
	o := response.Outcome
	return ProviderCompletion{Outcome: Outcome{o.ExecutionStatus, o.ReleaseStatus, o.ErrorCode, o.ObservedSHA256, o.EvaluatedSHA256}, Quiescent: true}
}

func readNativeResponse(channel *net.UnixConn) (nativeResponse, []*os.File, error) {
	var response nativeResponse
	buffer, control := make([]byte, MaxFrameBytes+4), make([]byte, syscall.CmsgSpace(4*4))
	n, count, flags, _, err := channel.ReadMsgUnix(buffer, control)
	var files []*os.File
	messages, parseErr := syscall.ParseSocketControlMessage(control[:count])
	for _, message := range messages {
		fds, fdErr := syscall.ParseUnixRights(&message)
		if fdErr != nil {
			parseErr = fdErr
			continue
		}
		for _, fd := range fds {
			files = append(files, os.NewFile(uintptr(fd), "artifact-native-export"))
		}
	}
	failure := func() (nativeResponse, []*os.File, error) {
		return response, files, fail("artifact_native_frame_invalid")
	}
	if err != nil || parseErr != nil || flags&(syscall.MSG_CTRUNC|syscall.MSG_TRUNC) != 0 || len(files) > 4 {
		return failure()
	}
	data := buffer[:n]
	if n < 4 {
		remainder := make([]byte, 4-n)
		if _, err := io.ReadFull(channel, remainder); err != nil {
			return failure()
		}
		data = append(data, remainder...)
	}
	length := int(binary.BigEndian.Uint32(data[:4]))
	if length < 1 || length > MaxFrameBytes || len(data) > length+4 {
		return failure()
	}
	if len(data) < length+4 {
		remainder := make([]byte, length+4-len(data))
		if _, err := io.ReadFull(channel, remainder); err != nil {
			return failure()
		}
		data = append(data, remainder...)
	}
	if strictJSON(data[4:], &response) != nil {
		return failure()
	}
	var extra [1]byte
	if n, err := channel.Read(extra[:]); n != 0 || err != io.EOF {
		return failure()
	}
	return response, files, nil
}

func validateNativeResponse(response nativeResponse, files []*os.File) error {
	if response.SchemaVersion != 1 || len(response.Files) != len(files) || len(files) > 4 {
		return fail("artifact_native_report_invalid")
	}
	allowed := map[string]int{"execution_receipt": 0, "normalized_vcf": 1, "variants_vcf": 2, "variants_vcf_index": 3}
	previous, total := -1, int64(0)
	for index, item := range response.Files {
		order, exists := allowed[item.ID]
		if !exists || order <= previous || !hexID(item.SHA256, 64) || item.Bytes < 0 || item.Bytes > 64<<20 || total > (64<<20)-item.Bytes || !safeInfo(files[index], false) {
			return fail("artifact_native_export_invalid")
		}
		flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, files[index].Fd(), syscall.F_GETFL, 0)
		info, err := files[index].Stat()
		if errno != 0 || flags&syscall.O_ACCMODE != syscall.O_RDONLY || err != nil || info.Size() != item.Bytes {
			return fail("artifact_native_export_invalid")
		}
		previous, total = order, total+item.Bytes
	}
	if response.Outcome.ExecutionStatus == "succeeded" && (len(response.Files) == 0 || response.Files[0].ID != "execution_receipt") {
		return fail("artifact_native_receipt_missing")
	}
	return nil
}

func (p *NativeProvider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	return p.root.Close()
}
