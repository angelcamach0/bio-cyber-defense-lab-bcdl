//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package artifactexecutor

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ContainerProviderConfig is fixed trusted host configuration, never an RPC DTO.
// DockerCommand must select the local managed daemon; image pulls are forbidden.
type ContainerProviderConfig struct {
	WorkspaceRoot                                               string
	DockerCommand                                               []string
	ImageID                                                     string
	Mode                                                        string
	Helper, NativeHelper, Pipeline, Reference, Evaluator, Truth PinnedAsset
	ResourceBudgetSHA256                                        string
	TimeoutSeconds                                              int
	Analysis                                                    *CapsuleAnalysisConfig
}

type ContainerProvider struct {
	mu                sync.Mutex
	config            ContainerProviderConfig
	root              *os.File
	closed, uncertain bool
}

type containerSpec struct {
	SchemaVersion      int        `json:"schema_version"`
	NativeHelperSHA256 string     `json:"native_helper_sha256"`
	Execution          nativeSpec `json:"execution"`
}

type containerMount struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Type        string `json:"type"`
	RW          bool   `json:"rw"`
	Propagation string `json:"propagation"`
}

type containerUlimit struct {
	Name string `json:"name"`
	Soft int64  `json:"soft"`
	Hard int64  `json:"hard"`
}

type containerInspection struct {
	ID             string            `json:"id"`
	Image          string            `json:"image"`
	Nonce          string            `json:"nonce"`
	Store          string            `json:"store"`
	Lease          string            `json:"lease"`
	Status         string            `json:"status"`
	Running        bool              `json:"running"`
	Paused         bool              `json:"paused"`
	Restarting     bool              `json:"restarting"`
	Dead           bool              `json:"dead"`
	PID            int64             `json:"pid"`
	ExitCode       int64             `json:"exit_code"`
	User           string            `json:"user"`
	WorkingDir     string            `json:"working_dir"`
	Entrypoint     []string          `json:"entrypoint"`
	Cmd            []string          `json:"cmd"`
	Env            []string          `json:"env"`
	ReadonlyRootfs bool              `json:"readonly_rootfs"`
	Privileged     bool              `json:"privileged"`
	CapDrop        []string          `json:"cap_drop"`
	CapAddCount    int64             `json:"cap_add_count"`
	SecurityOpt    []string          `json:"security_opt"`
	NetworkMode    string            `json:"network_mode"`
	PIDMode        string            `json:"pid_mode"`
	IPCMode        string            `json:"ipc_mode"`
	UsernsMode     string            `json:"userns_mode"`
	CgroupnsMode   string            `json:"cgroupns_mode"`
	RestartPolicy  string            `json:"restart_policy"`
	Memory         int64             `json:"memory"`
	MemorySwap     int64             `json:"memory_swap"`
	PidsLimit      int64             `json:"pids_limit"`
	NanoCPUs       int64             `json:"nano_cpus"`
	DeviceCount    int64             `json:"device_count"`
	PortCount      int64             `json:"port_count"`
	ShmSize        int64             `json:"shm_size"`
	VolumeCount    int64             `json:"volume_count"`
	Mounts         []containerMount  `json:"mounts"`
	Tmpfs          map[string]string `json:"tmpfs"`
	Ulimits        []containerUlimit `json:"ulimits"`
}

// Only selected fields are serialized: CLI/daemon diagnostics and credentials
// never become responses. The trusted Docker daemon is the capsule authority.
const containerInspectFormat = `{"id":{{json .Id}},"image":{{json .Image}},"nonce":{{json (index .Config.Labels "biozero.artifact.nonce")}},"store":{{json (index .Config.Labels "biozero.artifact.store")}},"lease":{{json (index .Config.Labels "biozero.artifact.lease")}},"status":{{json .State.Status}},"running":{{json .State.Running}},"paused":{{json .State.Paused}},"restarting":{{json .State.Restarting}},"dead":{{json .State.Dead}},"pid":{{json .State.Pid}},"exit_code":{{json .State.ExitCode}},"user":{{json .Config.User}},"working_dir":{{json .Config.WorkingDir}},"entrypoint":{{json .Config.Entrypoint}},"cmd":{{json .Config.Cmd}},"env":{{json .Config.Env}},"readonly_rootfs":{{json .HostConfig.ReadonlyRootfs}},"privileged":{{json .HostConfig.Privileged}},"cap_drop":{{json .HostConfig.CapDrop}},"cap_add_count":{{if (index .HostConfig "CapAdd")}}{{len (index .HostConfig "CapAdd")}}{{else}}0{{end}},"security_opt":{{json .HostConfig.SecurityOpt}},"network_mode":{{json .HostConfig.NetworkMode}},"pid_mode":{{json .HostConfig.PidMode}},"ipc_mode":{{json .HostConfig.IpcMode}},"userns_mode":{{json .HostConfig.UsernsMode}},"cgroupns_mode":{{json .HostConfig.CgroupnsMode}},"restart_policy":{{json .HostConfig.RestartPolicy.Name}},"memory":{{json .HostConfig.Memory}},"memory_swap":{{json .HostConfig.MemorySwap}},"pids_limit":{{json .HostConfig.PidsLimit}},"nano_cpus":{{json .HostConfig.NanoCpus}},"device_count":{{if (index .HostConfig "Devices")}}{{len (index .HostConfig "Devices")}}{{else}}0{{end}},"port_count":{{if (index .HostConfig "PortBindings")}}{{len (index .HostConfig "PortBindings")}}{{else}}0{{end}},"shm_size":{{json .HostConfig.ShmSize}},"volume_count":{{if (index .Config "Volumes")}}{{len (index .Config "Volumes")}}{{else}}0{{end}},"mounts":[{{range $i,$m := .Mounts}}{{if $i}},{{end}}{"source":{{json $m.Source}},"destination":{{json $m.Destination}},"type":{{json $m.Type}},"rw":{{json $m.RW}},"propagation":{{json $m.Propagation}}}{{end}}],"tmpfs":{{json .HostConfig.Tmpfs}},"ulimits":[{{range $i,$u := .HostConfig.Ulimits}}{{if $i}},{{end}}{"name":{{json $u.Name}},"soft":{{json $u.Soft}},"hard":{{json $u.Hard}}}{{end}}]}`

const containerTmpfs = "rw,noexec,nosuid,nodev,size=134217728,nr_inodes=4096,mode=0700,uid=1000,gid=1000"

func containerEnvironment() []string {
	return []string{"PATH=/usr/bin", "LANG=C", "LC_ALL=C", "PYTHONDONTWRITEBYTECODE=1", "HTTP_PROXY=", "HTTPS_PROXY=", "NO_PROXY=", "ALL_PROXY=", "http_proxy=", "https_proxy=", "no_proxy=", "all_proxy="}
}

func validDockerCommand(command []string) bool {
	a := []string{"/usr/bin/docker", "--host=unix:///var/run/docker.sock"}
	b := []string{"/usr/bin/sudo", "-n", "/usr/bin/docker", "--host=unix:///var/run/docker.sock"}
	return equalStrings(command, a) || equalStrings(command, b)
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func safeContainerSource(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsAny(path, ",\"\x00\r\n")
}

func (p *ContainerProvider) verifyAssets(ctx context.Context) error {
	assets := []struct {
		asset PinnedAsset
		limit int64
	}{
		{p.config.Helper, 1 << 20}, {p.config.NativeHelper, 1 << 20}, {p.config.Pipeline, 1 << 20},
		{PinnedAsset{filepath.Join(filepath.Dir(p.config.Pipeline.Path), "resource_budget.py"), p.config.ResourceBudgetSHA256}, 1 << 20},
	}
	for _, x := range []struct {
		asset PinnedAsset
		limit int64
	}{{p.config.Reference, 32 << 20}, {p.config.Evaluator, 1 << 20}, {p.config.Truth, 8 << 20}} {
		if x.asset.Path != "" {
			assets = append(assets, x)
		}
	}
	for _, x := range assets {
		if !safeContainerSource(x.asset.Path) {
			return fail("artifact_container_asset_invalid")
		}
		f, err := openPinnedAsset(ctx, x.asset, x.limit)
		if err != nil {
			return fail("artifact_container_asset_invalid")
		}
		f.Close()
	}
	return verifyCapsuleAnalysis(ctx, p.config.Analysis, p.config.WorkspaceRoot, true)
}

func NewContainerProvider(ctx context.Context, cfg ContainerProviderConfig) (*ContainerProvider, error) {
	if os.Getuid() != 1000 || os.Geteuid() != 1000 || os.Getgid() != 1000 || os.Getegid() != 1000 || !validDockerCommand(cfg.DockerCommand) || !strings.HasPrefix(cfg.ImageID, "sha256:") || !hexID(strings.TrimPrefix(cfg.ImageID, "sha256:"), 64) || cfg.TimeoutSeconds < 1 || cfg.TimeoutSeconds > 600 || (cfg.Mode != "stats" && cfg.Mode != "variants") || !safeContainerSource(cfg.WorkspaceRoot) {
		return nil, fail("artifact_container_config_invalid")
	}
	if filepath.Base(cfg.Helper.Path) != "container_capsule.py" || filepath.Base(cfg.NativeHelper.Path) != "native_capsule.py" || filepath.Dir(cfg.Helper.Path) != filepath.Dir(cfg.NativeHelper.Path) || filepath.Base(cfg.Pipeline.Path) != "pipeline.py" || (cfg.Evaluator.Path != "" && filepath.Base(cfg.Evaluator.Path) != "evaluate_variants.py") || (cfg.Evaluator.Path == "") != (cfg.Truth.Path == "") || (cfg.Mode == "variants" && cfg.Reference.Path == "") || (cfg.Evaluator.Path != "" && cfg.Reference.Path == "") {
		return nil, fail("artifact_container_config_invalid")
	}
	for _, a := range []PinnedAsset{cfg.Reference, cfg.Evaluator, cfg.Truth} {
		if (a.Path == "") != (a.SHA256 == "") {
			return nil, fail("artifact_container_config_invalid")
		}
	}
	for _, dir := range []string{filepath.Dir(cfg.Helper.Path), filepath.Dir(cfg.Pipeline.Path), filepath.Dir(cfg.Evaluator.Path)} {
		if dir == "." {
			continue
		}
		if dir == "/" || strings.HasPrefix(dir, "/proc/") || dir == cfg.WorkspaceRoot || strings.HasPrefix(cfg.WorkspaceRoot, dir+"/") || strings.HasPrefix(dir, cfg.WorkspaceRoot+"/") {
			return nil, fail("artifact_container_config_invalid")
		}
	}
	cfg.DockerCommand = append([]string{}, cfg.DockerCommand...)
	cfg.Analysis = copyCapsuleAnalysis(cfg.Analysis)
	p := &ContainerProvider{config: cfg}
	if err := p.verifyAssets(ctx); err != nil {
		return nil, err
	}
	root, err := openRoot(cfg.WorkspaceRoot)
	if err != nil {
		return nil, err
	}
	list, err := root.Readdirnames(1)
	if err != io.EOF || len(list) != 0 {
		root.Close()
		return nil, fail("artifact_container_workspace_history_unknown")
	}
	p.root = root
	image, err := p.docker(ctx, "image", "inspect", "--format", "{{.Id}}", cfg.ImageID)
	if err != nil || strings.TrimSpace(string(image)) != cfg.ImageID {
		root.Close()
		return nil, fail("artifact_container_image_unavailable")
	}
	return p, nil
}

type containerCapture struct {
	mu       sync.Mutex
	data     []byte
	exceeded bool
	cancel   context.CancelFunc
}

func (w *containerCapture) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(data) > MaxFrameBytes-len(w.data) {
		w.exceeded = true
		w.cancel()
		return 0, fail("artifact_container_cli_output_limit")
	}
	w.data = append(w.data, data...)
	return len(data), nil
}
func (w *containerCapture) result() ([]byte, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte{}, w.data...), w.exceeded
}

func (p *ContainerProvider) command(ctx context.Context, args ...string) (*exec.Cmd, *containerCapture, *containerCapture, context.CancelFunc) {
	return p.commandWithLimit(ctx, 30*time.Second, args...)
}
func (p *ContainerProvider) commandWithLimit(ctx context.Context, limit time.Duration, args ...string) (*exec.Cmd, *containerCapture, *containerCapture, context.CancelFunc) {
	bounded, cancel := context.WithTimeout(ctx, limit)
	cmd := exec.CommandContext(bounded, p.config.DockerCommand[0], append(append([]string{}, p.config.DockerCommand[1:]...), args...)...)
	for _, item := range os.Environ() {
		key := strings.SplitN(item, "=", 2)[0]
		switch key {
		case "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH":
			continue
		}
		cmd.Env = append(cmd.Env, item)
	}
	// Preserve configured Docker credentials/proxy selectors for the host CLI.
	// Only offline capsule Env is explicitly reduced; host SDK auth is untouched.
	out, stderr := &containerCapture{cancel: cancel}, &containerCapture{cancel: cancel}
	cmd.Stdout = out
	cmd.Stderr = stderr
	cmd.WaitDelay = time.Second
	return cmd, out, stderr, cancel
}

func (p *ContainerProvider) docker(ctx context.Context, args ...string) ([]byte, error) {
	cmd, out, stderr, cancel := p.command(ctx, args...)
	defer cancel()
	err := cmd.Run()
	data, overflow := out.result()
	_, extra := stderr.result()
	if err != nil || overflow || extra {
		return nil, fail("artifact_container_daemon_unavailable")
	}
	return data, nil
}

func (p *ContainerProvider) mounts(control string) []containerMount {
	m := []containerMount{
		{p.config.Helper.Path, "/run/biozero/helpers/container_capsule.py", "bind", false, "rprivate"},
		{p.config.NativeHelper.Path, "/run/biozero/helpers/native_capsule.py", "bind", false, "rprivate"},
		{p.config.Pipeline.Path, "/run/biozero/pipeline/pipeline.py", "bind", false, "rprivate"},
		{filepath.Join(filepath.Dir(p.config.Pipeline.Path), "resource_budget.py"), "/run/biozero/pipeline/resource_budget.py", "bind", false, "rprivate"},
		{control, "/run/biozero/channel", "bind", false, "rprivate"},
	}
	for _, x := range []struct{ path, dest string }{{p.config.Reference.Path, "/run/biozero/reference.fa"}, {p.config.Truth.Path, "/run/biozero/truth.vcf"}, {p.config.Evaluator.Path, "/run/biozero/evaluator/evaluate_variants.py"}} {
		if x.path != "" {
			m = append(m, containerMount{x.path, x.dest, "bind", false, "rprivate"})
		}
	}
	if p.config.Analysis != nil {
		m = append(m, containerMount{p.config.Analysis.Executable.Path, "/run/biozero/analysis/capsule-analysis", "bind", false, "rprivate"}, containerMount{p.config.Analysis.Rules.Path, "/run/biozero/analysis/rules.json", "bind", false, "rprivate"})
		if p.config.Analysis.Panel.Path != "" {
			m = append(m, containerMount{p.config.Analysis.Panel.Path, "/run/biozero/analysis/panel.fa", "bind", false, "rprivate"})
		}
	}
	return m
}

func (p *ContainerProvider) createArgs(nonce, store, lease, control string) []string {
	a := []string{"create", "--pull=never", "--name", "biozero-artifact-" + nonce, "--label", "biozero.artifact.nonce=" + nonce, "--label", "biozero.artifact.store=" + store, "--label", "biozero.artifact.lease=" + lease, "--user", "1000:1000", "--workdir", "/workspace", "--entrypoint", "/usr/bin/python3.12", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--network=none", "--ipc=private", "--cgroupns=private", "--init=false", "--restart=no", "--memory=536870912", "--memory-swap=536870912", "--pids-limit=128", "--cpus=1", "--shm-size=65536", "--ulimit", "fsize=67108864:67108864", "--tmpfs", "/workspace:" + containerTmpfs, "--log-driver=none", "-i"}
	for _, env := range containerEnvironment() {
		a = append(a, "--env", env)
	}
	for _, m := range p.mounts(control) {
		a = append(a, "--mount", "type=bind,src="+m.Source+",dst="+m.Destination+",readonly,bind-propagation=rprivate")
	}
	return append(a, p.config.ImageID, "-I", "-B", "-S", "/run/biozero/helpers/container_capsule.py")
}

func (p *ContainerProvider) inspect(ctx context.Context, id string) (containerInspection, error) {
	var v containerInspection
	raw, err := p.docker(ctx, "inspect", "--format", containerInspectFormat, id)
	if err != nil || strictJSON(raw, &v) != nil {
		return v, fail("artifact_container_identity_unproven")
	}
	return v, nil
}

func (p *ContainerProvider) validInspection(v containerInspection, id, nonce, store, lease, control string) bool {
	if v.ID != id || v.Image != p.config.ImageID || v.Nonce != nonce || v.Store != store || v.Lease != lease || v.User != "1000:1000" || v.WorkingDir != "/workspace" || !equalStrings(v.Entrypoint, []string{"/usr/bin/python3.12"}) || !equalStrings(v.Cmd, []string{"-I", "-B", "-S", "/run/biozero/helpers/container_capsule.py"}) || !v.ReadonlyRootfs || v.Privileged || !equalStrings(v.CapDrop, []string{"ALL"}) || v.CapAddCount != 0 || !equalStrings(v.SecurityOpt, []string{"no-new-privileges"}) || v.NetworkMode != "none" || v.PIDMode != "" || v.IPCMode != "private" || v.UsernsMode != "" || v.CgroupnsMode != "private" || v.RestartPolicy != "no" || v.Memory != 536870912 || v.MemorySwap != v.Memory || v.PidsLimit != 128 || v.NanoCPUs != 1000000000 || v.DeviceCount != 0 || v.PortCount != 0 || v.ShmSize != 65536 || v.VolumeCount != 0 || len(v.Tmpfs) != 1 || v.Tmpfs["/workspace"] != containerTmpfs {
		return false
	}
	env := map[string]bool{}
	for _, x := range containerEnvironment() {
		env[x] = true
	}
	if len(v.Env) != len(env) {
		return false
	}
	for _, x := range v.Env {
		if !env[x] {
			return false
		}
		delete(env, x)
	}
	expected := p.mounts(control)
	seen := map[string]bool{}
	for _, m := range v.Mounts {
		if m.Type == "tmpfs" && m.Destination == "/workspace" {
			continue
		}
		ok := false
		for _, want := range expected {
			if m == want && !seen[m.Destination] {
				ok = true
				seen[m.Destination] = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(seen) != len(expected) {
		return false
	}
	fsize := 0
	for _, u := range v.Ulimits {
		if u.Name == "fsize" {
			fsize++
			if u.Soft != 64<<20 || u.Hard != 64<<20 {
				return false
			}
		}
	}
	return fsize == 1
}

func (p *ContainerProvider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	if p.root != nil {
		err := p.root.Close()
		p.root = nil
		return err
	}
	return nil
}

// A partial private identity file is retained on uncertainty, never interpreted
// as quiescence. Startup refuses every old anchor; no retry/adoption is implied.
func writeContainerRecord(dir *os.File, name string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > 4096 {
		return fail("artifact_container_record_invalid")
	}
	file, err := regular(dir, name, true)
	if err != nil {
		return err
	}
	defer file.Close()
	if n, err := file.Write(raw); err != nil || n != len(raw) {
		return fail("artifact_container_record_failed")
	}
	if file.Sync() != nil || dir.Sync() != nil {
		return fail("artifact_container_record_failed")
	}
	return nil
}

func (p *ContainerProvider) Execute(parent context.Context, input *ScopedInput, exporter *Exporter) (result ProviderCompletion) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.uncertain || input == nil || exporter == nil || parent.Err() != nil {
		return nativeFailure("artifact_container_unavailable", true)
	}
	if err := p.verifyAssets(parent); err != nil {
		return nativeFailure("artifact_container_asset_invalid", true)
	}
	input.mu.Lock()
	file, err := duplicateReadOnly(input.file)
	size, sha := input.Bytes, input.ProcessedSHA256
	var facts *AnalysisContext
	if input.AnalysisContext != nil {
		copy := *input.AnalysisContext
		facts = &copy
	}
	input.mu.Unlock()
	if err != nil {
		return nativeFailure("artifact_container_input_unavailable", true)
	}
	defer file.Close()
	analysis, err := analysisForInput(p.config.Analysis, facts, size, true)
	if err != nil {
		return nativeFailure("artifact_analysis_context_invalid", true)
	}
	exporter.store.mu.Lock()
	store := exporter.store.data.StoreID
	allowed := false
	for _, id := range exporter.store.data.Policy.ArtifactIDs {
		if id == "execution_receipt" {
			allowed = true
		}
	}
	exporter.store.mu.Unlock()
	if !allowed {
		return nativeFailure("artifact_container_policy_incomplete", true)
	}
	nonce, err := token()
	if err != nil {
		return nativeFailure("artifact_container_unavailable", true)
	}
	anchor, err := childDir(p.root, "capsule-"+nonce, true)
	if err != nil {
		return nativeFailure("artifact_container_workspace_unavailable", true)
	}
	defer anchor.Close()
	started, verifiedWait, removed := false, false, false
	defer func() {
		if started && (!verifiedWait || !removed) {
			p.uncertain = true
			return
		}
		for _, name := range []string{"control.sock", "intent.json", "container.json"} {
			err := syscall.Unlinkat(int(anchor.Fd()), name)
			if err != nil && err != syscall.ENOENT {
				p.uncertain = true
				exporter.store.mu.Lock()
				exporter.store.latch("artifact_container_workspace_cleanup_failed")
				exporter.store.mu.Unlock()
				result = nativeFailure("artifact_container_workspace_cleanup_failed", result.Quiescent)
				return
			}
		}
		if anchor.Sync() != nil || os.Remove(fdPath(p.root)+"/capsule-"+nonce) != nil || p.root.Sync() != nil {
			p.uncertain = true
			exporter.store.mu.Lock()
			exporter.store.latch("artifact_container_workspace_cleanup_failed")
			exporter.store.mu.Unlock()
			result = nativeFailure("artifact_container_workspace_cleanup_failed", result.Quiescent)
		}
	}()
	control := filepath.Join(p.config.WorkspaceRoot, "capsule-"+nonce)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: fdPath(anchor) + "/control.sock", Net: "unix"})
	if err != nil {
		return nativeFailure("artifact_container_channel_unavailable", true)
	}
	listener.SetUnlinkOnClose(false)
	defer listener.Close()
	if os.Chmod(fdPath(anchor)+"/control.sock", 0600) != nil || anchor.Sync() != nil {
		return nativeFailure("artifact_container_channel_unavailable", true)
	}
	ctx, cancel := context.WithTimeout(parent, time.Duration(p.config.TimeoutSeconds)*time.Second)
	defer cancel()
	// Once create is attempted, ambiguous daemon/CLI state is durable uncertainty.
	started = true
	intent := map[string]any{"schema_version": 1, "nonce": nonce, "store": store, "lease": exporter.lease, "image": p.config.ImageID}
	if err := writeContainerRecord(anchor, "intent.json", intent); err != nil {
		return nativeFailure("artifact_container_intent_unproven", false)
	}
	raw, err := p.docker(ctx, p.createArgs(nonce, store, exporter.lease, control)...)
	id := strings.TrimSpace(string(raw))
	if err != nil || !hexID(id, 64) {
		return nativeFailure("artifact_container_creation_unproven", false)
	}
	identity := map[string]any{"schema_version": 1, "nonce": nonce, "store": store, "lease": exporter.lease, "image": p.config.ImageID, "container_id": id}
	if err := writeContainerRecord(anchor, "container.json", identity); err != nil {
		return nativeFailure("artifact_container_identity_unproven", false)
	}
	v, err := p.inspect(ctx, id)
	if err != nil || !p.validInspection(v, id, nonce, store, exporter.lease, control) || v.Status != "created" || v.Running || v.PID != 0 {
		return nativeFailure("artifact_container_identity_unproven", false)
	}
	execution := nativeSpec{SchemaVersion: 1, Workspace: "/workspace", InputBytes: size, InputSHA256: sha, Mode: p.config.Mode, PipelinePath: "/run/biozero/pipeline/pipeline.py", PipelineSHA256: p.config.Pipeline.SHA256, ResourceBudgetSHA256: p.config.ResourceBudgetSHA256, PythonPath: "/usr/bin/python3.12", ToolPath: "/usr/bin", TimeoutSeconds: p.config.TimeoutSeconds, Analysis: analysis}
	if analysis != nil {
		execution.SchemaVersion = 2
	}
	if p.config.Reference.Path != "" {
		execution.ReferencePath = "/run/biozero/reference.fa"
		execution.ReferenceSHA256 = p.config.Reference.SHA256
	}
	if p.config.Truth.Path != "" {
		execution.TruthPath = "/run/biozero/truth.vcf"
		execution.TruthSHA256 = p.config.Truth.SHA256
		execution.EvaluatorPath = "/run/biozero/evaluator/evaluate_variants.py"
		execution.EvaluatorSHA256 = p.config.Evaluator.SHA256
	}
	spec, err := json.Marshal(containerSpec{1, p.config.NativeHelper.SHA256, execution})
	if err != nil || len(spec) > MaxFrameBytes {
		return nativeFailure("artifact_container_config_invalid", false)
	}
	// Attach transport is not quiescence authority. Docker wait/inspect below is.
	cmd, out, stderr, stopAttach := p.commandWithLimit(context.Background(), time.Duration(p.config.TimeoutSeconds+30)*time.Second, "start", "--attach", "--interactive", id)
	defer stopAttach()
	cmd.Stdin = bytes.NewReader(spec)
	if err := cmd.Start(); err != nil {
		return nativeFailure("artifact_container_start_unproven", false)
	}
	attached := make(chan error, 1)
	go func() { attached <- cmd.Wait() }()
	stopOnCancel := context.AfterFunc(ctx, func() {
		listener.Close()
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		p.docker(cleanup, "kill", "--signal=KILL", id)
	})
	defer stopOnCancel()
	deadline, _ := ctx.Deadline()
	listener.SetDeadline(deadline)
	channel, channelErr := listener.AcceptUnix()
	var response nativeResponse
	var files []*os.File
	if channelErr == nil {
		defer channel.Close()
		stopChannel := context.AfterFunc(ctx, func() { channel.Close() })
		defer stopChannel()
		channel.SetDeadline(deadline)
		credErr := error(nil)
		var cred *syscall.Ucred
		socket, _ := channel.SyscallConn()
		if socket == nil {
			credErr = fail("artifact_container_peer_unverified")
		} else {
			err := socket.Control(func(fd uintptr) {
				cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
			})
			if err != nil {
				credErr = err
			}
		}
		live, inspectErr := p.inspect(ctx, id)
		if credErr != nil || cred == nil || cred.Uid != 1000 || cred.Gid != 1000 || inspectErr != nil || !p.validInspection(live, id, nonce, store, exporter.lease, control) || live.Status != "running" || !live.Running || live.PID != int64(cred.Pid) {
			channelErr = fail("artifact_container_peer_unverified")
		} else {
			n, _, sendErr := channel.WriteMsgUnix([]byte{'I'}, syscall.UnixRights(int(file.Fd())), nil)
			if sendErr != nil || n != 1 {
				channelErr = fail("artifact_container_input_transfer_failed")
			} else {
				response, files, channelErr = readNativeResponse(channel)
			}
		}
	}
	for _, f := range files {
		defer f.Close()
	}
	if channelErr != nil || ctx.Err() != nil {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		p.docker(cleanup, "kill", "--signal=KILL", id)
		stop()
	}
	cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
	defer stop()
	waitRaw, waitErr := p.docker(cleanup, "wait", id)
	code, parseErr := strconv.ParseInt(strings.TrimSpace(string(waitRaw)), 10, 64)
	final, inspectErr := p.inspect(cleanup, id)
	if waitErr != nil || parseErr != nil || inspectErr != nil || !p.validInspection(final, id, nonce, store, exporter.lease, control) || final.Status != "exited" || final.Running || final.Paused || final.Restarting || final.Dead || final.PID != 0 || final.ExitCode != code {
		return nativeFailure("artifact_container_quiescence_unproven", false)
	}
	verifiedWait = true
	select {
	case <-attached:
	case <-cleanup.Done():
		stopAttach()
		exporter.store.mu.Lock()
		exporter.store.latch("artifact_container_attach_unfinished")
		exporter.store.mu.Unlock()
		return nativeFailure("artifact_container_attach_unfinished", true)
	}
	_, overflow := out.result()
	_, extra := stderr.result()
	// Removal follows authoritative wait; it is never used to manufacture proof.
	if _, err := p.docker(cleanup, "rm", id); err != nil {
		exporter.store.mu.Lock()
		exporter.store.latch("artifact_container_cleanup_unproven")
		exporter.store.mu.Unlock()
		return nativeFailure("artifact_container_cleanup_unproven", true)
	}
	removed = true
	if channelErr != nil || ctx.Err() != nil || overflow || extra || validateNativeResponse(response, files) != nil || response.Outcome.ExecutionStatus == "succeeded" && code != 0 || response.Outcome.ExecutionStatus != "succeeded" && code != 1 {
		return nativeFailure("artifact_container_execution_failed", true)
	}
	for i, metadata := range response.Files {
		if err := exporter.Export(metadata.ID, metadata.SHA256, io.NewSectionReader(files[i], 0, metadata.Bytes+1)); err != nil {
			return nativeFailure("artifact_container_export_failed", true)
		}
	}
	return ProviderCompletion{Outcome: Outcome{response.Outcome.ExecutionStatus, response.Outcome.ReleaseStatus, response.Outcome.ErrorCode, response.Outcome.ObservedSHA256, response.Outcome.EvaluatedSHA256}, Quiescent: true}
}
