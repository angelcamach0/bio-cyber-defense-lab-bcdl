//go:build linux

package artifactexecutor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
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

// NativeProviderConfig is trusted host configuration. None of its paths, tool
// selection, policy or limits are accepted through run/status/cancel RPC.
type NativeProviderConfig struct {
	WorkspaceRoot               string
	PythonPath, ToolPath, Mode  string
	Helper, Pipeline, Reference PinnedAsset
	Evaluator, Truth            PinnedAsset
	ResourceBudgetSHA256        string
	TimeoutSeconds              int
}

type NativeProvider struct {
	mu     sync.Mutex
	config NativeProviderConfig
	root   *os.File
	closed bool
}

type nativeSpec struct {
	SchemaVersion        int    `json:"schema_version"`
	Workspace            string `json:"workspace"`
	InputBytes           int64  `json:"input_bytes"`
	InputSHA256          string `json:"input_sha256"`
	Mode                 string `json:"mode"`
	PipelinePath         string `json:"pipeline_path"`
	PipelineSHA256       string `json:"pipeline_sha256"`
	ResourceBudgetSHA256 string `json:"resource_budget_sha256"`
	ReferencePath        string `json:"reference_path"`
	ReferenceSHA256      string `json:"reference_sha256"`
	EvaluatorPath        string `json:"evaluator_path"`
	EvaluatorSHA256      string `json:"evaluator_sha256"`
	TruthPath            string `json:"truth_path"`
	TruthSHA256          string `json:"truth_sha256"`
	PythonPath           string `json:"python_path"`
	ToolPath             string `json:"tool_path"`
	TimeoutSeconds       int    `json:"timeout_seconds"`
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
	return nil
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
	input.mu.Unlock()
	if err != nil {
		return nativeFailure("artifact_native_input_unavailable", true)
	}
	defer file.Close()
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
	spec := nativeSpec{1, workspace, inputBytes, sha, p.config.Mode, p.config.Pipeline.Path, p.config.Pipeline.SHA256,
		p.config.ResourceBudgetSHA256, p.config.Reference.Path, p.config.Reference.SHA256,
		p.config.Evaluator.Path, p.config.Evaluator.SHA256, p.config.Truth.Path, p.config.Truth.SHA256,
		p.config.PythonPath, p.config.ToolPath, p.config.TimeoutSeconds}
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
