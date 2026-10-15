//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package artifactexecutor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"
)

const brokerServiceConfigLimit int64 = 64 << 10
const brokerServiceExecutableLimit int64 = 32 << 20

// BrokerServiceAsset is a fixed trusted-host asset, never a request field. The
// empty pair is required for an unused asset; null and absent fields are invalid.
type BrokerServiceAsset struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

func (a BrokerServiceAsset) pinned() PinnedAsset { return PinnedAsset{a.Path, a.SHA256} }

// BrokerServiceConfig has an exact bounded JSON shape. There are no caller policy,
// quota, shell command or network options. All analysis stays in the capsule.
type BrokerServiceConfig struct {
	SchemaVersion      int                `json:"schema_version"`
	Provider           string             `json:"provider"`
	Mode               string             `json:"mode"`
	StoreRoot          string             `json:"store_root"`
	JournalRoot        string             `json:"journal_root"`
	WorkspaceRoot      string             `json:"workspace_root"`
	SocketPath         string             `json:"socket_path"`
	AllowedUID         uint32             `json:"allowed_uid"`
	TimeoutSeconds     int                `json:"timeout_seconds"`
	PythonPath         string             `json:"python_path"`
	ToolPath           string             `json:"tool_path"`
	DockerCommand      []string           `json:"docker_command"`
	ImageID            string             `json:"image_id"`
	NativeHelper       BrokerServiceAsset `json:"native_helper"`
	ContainerHelper    BrokerServiceAsset `json:"container_helper"`
	Pipeline           BrokerServiceAsset `json:"pipeline"`
	ResourceBudget     BrokerServiceAsset `json:"resource_budget"`
	Reference          BrokerServiceAsset `json:"reference"`
	Evaluator          BrokerServiceAsset `json:"evaluator"`
	Truth              BrokerServiceAsset `json:"truth"`
	AnalysisExecutable BrokerServiceAsset `json:"analysis_executable"`
	AnalysisRules      BrokerServiceAsset `json:"analysis_rules"`
	AnalysisPanel      BrokerServiceAsset `json:"analysis_panel"`
}

func servicePath(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path && path != "/" && utf8.ValidString(path) && !strings.ContainsAny(path, "\x00\r\n")
}

// Metadata only: never execute or read an arbitrary interpreter during profile
// inspection. Descriptor traversal/open is nofollow and NONBLOCK rejects FIFOs.
func verifyServicePython(path string) error {
	dir, e := unixExistingDirectoryLoose(filepath.Dir(path))
	if e != nil {
		return fail("artifact_service_python_invalid")
	}
	defer dir.Close()
	fd, e := syscall.Openat(int(dir.Fd()), filepath.Base(path), syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if e != nil {
		return fail("artifact_service_python_invalid")
	}
	f := os.NewFile(uintptr(fd), "artifact-service-python")
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() {
		return fail("artifact_service_python_invalid")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) || stat.Mode&0022 != 0 || stat.Mode&07000 != 0 {
		return fail("artifact_service_python_invalid")
	}
	execMask := uint32(0001)
	if stat.Uid == uint32(os.Geteuid()) {
		execMask = 0100
	} else {
		groups, e := os.Getgroups()
		if e != nil {
			return fail("artifact_service_python_invalid")
		}
		if stat.Gid == uint32(os.Getegid()) {
			execMask = 0010
		}
		for _, group := range groups {
			if stat.Gid == uint32(group) {
				execMask = 0010
			}
		}
	}
	if stat.Mode&execMask == 0 {
		return fail("artifact_service_python_invalid")
	}
	return nil
}
func serviceOverlap(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}
func (c BrokerServiceConfig) shape() error {
	if c.SchemaVersion != 1 || (c.Provider != "native" && c.Provider != "docker") || (c.Mode != "stats" && c.Mode != "variants") || c.TimeoutSeconds < 1 || c.TimeoutSeconds > 600 || c.DockerCommand == nil {
		return fail("artifact_service_config_invalid")
	}
	roots := []string{c.StoreRoot, c.JournalRoot, c.WorkspaceRoot, filepath.Dir(c.SocketPath)}
	if !servicePath(c.SocketPath) {
		return fail("artifact_service_config_invalid")
	}
	for i, p := range roots {
		if !servicePath(p) {
			return fail("artifact_service_config_invalid")
		}
		for _, q := range roots[:i] {
			if serviceOverlap(p, q) {
				return fail("artifact_service_roots_overlap")
			}
		}
	}
	if _, _, e := unixName(c.SocketPath); e != nil {
		return fail("artifact_service_config_invalid")
	}
	if c.Provider == "native" {
		if !servicePath(c.PythonPath) || c.ToolPath == "" || len(c.DockerCommand) != 0 || c.ImageID != "" || c.ContainerHelper != (BrokerServiceAsset{}) {
			return fail("artifact_service_config_invalid")
		}
		python, e := filepath.EvalSymlinks(c.PythonPath)
		if e != nil || python != c.PythonPath || verifyServicePython(c.PythonPath) != nil {
			return fail("artifact_service_config_invalid")
		}
		for _, p := range append(strings.Split(c.ToolPath, ":"), c.PythonPath) {
			if !servicePath(p) {
				return fail("artifact_service_config_invalid")
			}
			for _, r := range roots {
				if serviceOverlap(p, r) {
					return fail("artifact_service_roots_overlap")
				}
			}
		}
		for _, p := range strings.Split(c.ToolPath, ":") {
			f, e := unixExistingDirectoryLoose(p)
			if e != nil {
				return fail("artifact_service_config_invalid")
			}
			f.Close()
		}
	} else {
		if c.PythonPath != "" || c.ToolPath != "" || !validDockerCommand(c.DockerCommand) || !strings.HasPrefix(c.ImageID, "sha256:") || !hexID(strings.TrimPrefix(c.ImageID, "sha256:"), 64) {
			return fail("artifact_service_config_invalid")
		}
		if filepath.Base(c.ContainerHelper.Path) != "container_capsule.py" || filepath.Dir(c.ContainerHelper.Path) != filepath.Dir(c.NativeHelper.Path) {
			return fail("artifact_service_config_invalid")
		}
	}
	if filepath.Base(c.NativeHelper.Path) != "native_capsule.py" || filepath.Base(c.Pipeline.Path) != "pipeline.py" || c.ResourceBudget.Path != filepath.Join(filepath.Dir(c.Pipeline.Path), "resource_budget.py") {
		return fail("artifact_service_config_invalid")
	}
	if c.Mode == "variants" {
		if c.Reference.Path == "" || c.Evaluator.Path == "" || c.Truth.Path == "" || filepath.Base(c.Evaluator.Path) != "evaluate_variants.py" {
			return fail("artifact_service_config_invalid")
		}
	} else if c.Evaluator != (BrokerServiceAsset{}) || c.Truth != (BrokerServiceAsset{}) {
		return fail("artifact_service_config_invalid")
	}
	for _, a := range c.assets() {
		if a.optional && a.asset == (BrokerServiceAsset{}) {
			continue
		}
		if !servicePath(a.asset.Path) || !hexID(a.asset.SHA256, 64) || (c.Provider == "docker" && !safeContainerSource(a.asset.Path)) {
			return fail("artifact_service_config_invalid")
		}
		for _, r := range roots {
			if serviceOverlap(a.asset.Path, r) {
				return fail("artifact_service_roots_overlap")
			}
		}
	}
	policy := NativeArtifactPolicy()
	if policy.validate() != nil {
		return fail("artifact_service_policy_invalid")
	}
	return nil
}

type brokerServiceAssetLimit struct {
	asset    BrokerServiceAsset
	limit    int64
	optional bool
}

func (c BrokerServiceConfig) assets() []brokerServiceAssetLimit {
	return []brokerServiceAssetLimit{{c.NativeHelper, 1 << 20, false}, {c.ContainerHelper, 1 << 20, c.Provider == "native"}, {c.Pipeline, 1 << 20, false}, {c.ResourceBudget, 1 << 20, false}, {c.Reference, 32 << 20, c.Mode == "stats"}, {c.Evaluator, 1 << 20, c.Mode == "stats"}, {c.Truth, 8 << 20, c.Mode == "stats"}, {c.AnalysisExecutable, 4 << 20, false}, {c.AnalysisRules, 64 << 10, false}, {c.AnalysisPanel, 32 << 20, true}}
}
func (c BrokerServiceConfig) analysis() *CapsuleAnalysisConfig {
	return &CapsuleAnalysisConfig{Executable: c.AnalysisExecutable.pinned(), Rules: c.AnalysisRules.pinned(), Panel: c.AnalysisPanel.pinned()}
}
func (c BrokerServiceConfig) verify(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return fail("artifact_service_context_invalid")
	}
	if e := c.shape(); e != nil {
		return e
	}
	for _, a := range c.assets() {
		if a.optional && a.asset == (BrokerServiceAsset{}) {
			continue
		}
		f, e := openPinnedAsset(ctx, a.asset.pinned(), a.limit)
		if e != nil {
			return fail("artifact_service_asset_invalid")
		}
		f.Close()
	}
	if e := verifyCapsuleAnalysis(ctx, c.analysis(), c.WorkspaceRoot, c.Provider == "docker"); e != nil {
		return e
	}
	return nil
}

// LoadBrokerServiceConfig reads an existing private regular current-UID 0600
// single-link config with descriptor-anchored nofollow ancestors. It creates no
// state directory, socket, provider or Docker connection.
func LoadBrokerServiceConfig(ctx context.Context, path string) (BrokerServiceConfig, error) {
	var config BrokerServiceConfig
	if ctx == nil || ctx.Err() != nil || !servicePath(path) {
		return config, fail("artifact_service_config_invalid")
	}
	dir, e := unixExistingDirectoryLoose(filepath.Dir(path))
	if e != nil {
		return config, fail("artifact_service_config_unsafe")
	}
	defer dir.Close()
	file, e := regular(dir, filepath.Base(path), false)
	if e != nil {
		return config, fail("artifact_service_config_unsafe")
	}
	defer file.Close()
	before, e := file.Stat()
	if e != nil || before.Size() < 1 || before.Size() > brokerServiceConfigLimit {
		return config, fail("artifact_service_config_oversized")
	}
	raw, e := io.ReadAll(io.NewSectionReader(file, 0, brokerServiceConfigLimit+1))
	if e != nil || len(raw) > int(brokerServiceConfigLimit) || !utf8.Valid(raw) || !safeInfo(file, false) {
		return config, fail("artifact_service_config_invalid")
	}
	after, e := file.Stat()
	if e != nil || after.Size() != before.Size() || len(raw) != int(after.Size()) || strictJSON(raw, &config) != nil {
		return config, fail("artifact_service_config_invalid")
	}
	if e = config.verify(ctx); e != nil {
		return BrokerServiceConfig{}, e
	}
	for _, r := range []string{config.StoreRoot, config.JournalRoot, config.WorkspaceRoot, filepath.Dir(config.SocketPath)} {
		if serviceOverlap(path, r) {
			return BrokerServiceConfig{}, fail("artifact_service_roots_overlap")
		}
	}
	return config, nil
}

// BrokerServiceProfile identifies verified fixed configuration, policy and the
// exact running broker executable. /proc/self/exe is the kernel's own executable
// reference, not an accepted request path. This is neither attestation nor a
// native tool/dependency reproducibility claim. It starts no provider or daemon.
func BrokerServiceProfile(ctx context.Context, config BrokerServiceConfig) (string, error) {
	if e := config.verify(ctx); e != nil {
		return "", e
	}
	executable, e := os.Open("/proc/self/exe")
	if e != nil {
		return "", fail("artifact_service_executable_unavailable")
	}
	defer executable.Close()
	info, e := executable.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > brokerServiceExecutableLimit {
		return "", fail("artifact_service_executable_invalid")
	}
	h := sha256.New()
	buf := make([]byte, 65536)
	var total int64
	reader := io.NewSectionReader(executable, 0, brokerServiceExecutableLimit+1)
	for {
		if ctx.Err() != nil {
			return "", fail("artifact_cancelled")
		}
		n, e := reader.Read(buf)
		total += int64(n)
		if total > brokerServiceExecutableLimit {
			return "", fail("artifact_service_executable_invalid")
		}
		if n > 0 {
			h.Write(buf[:n])
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return "", fail("artifact_service_executable_invalid")
		}
	}
	if total != info.Size() {
		return "", fail("artifact_service_executable_changed")
	}
	payload := struct {
		SchemaVersion    int                 `json:"schema_version"`
		ProtocolVersion  int                 `json:"protocol_version"`
		Config           BrokerServiceConfig `json:"config"`
		Policy           Policy              `json:"policy"`
		ExecutableSHA256 string              `json:"executable_sha256"`
	}{1, 2, config, NativeArtifactPolicy(), hex.EncodeToString(h.Sum(nil))}
	raw, e := json.Marshal(payload)
	if e != nil {
		return "", fail("artifact_service_profile_invalid")
	}
	return digest(raw), nil
}

type brokerServiceProviderFactory func(context.Context, BrokerServiceConfig) (Provider, func() error, error)

func makeBrokerServiceProvider(ctx context.Context, c BrokerServiceConfig) (Provider, func() error, error) {
	if c.Provider == "native" {
		p, e := NewNativeProvider(ctx, NativeProviderConfig{WorkspaceRoot: c.WorkspaceRoot, PythonPath: c.PythonPath, ToolPath: c.ToolPath, Mode: c.Mode, Helper: c.NativeHelper.pinned(), Pipeline: c.Pipeline.pinned(), ResourceBudgetSHA256: c.ResourceBudget.SHA256, Reference: c.Reference.pinned(), Evaluator: c.Evaluator.pinned(), Truth: c.Truth.pinned(), TimeoutSeconds: c.TimeoutSeconds, Analysis: c.analysis()})
		if e != nil {
			return nil, nil, e
		}
		return p, p.Close, nil
	}
	p, e := NewContainerProvider(ctx, ContainerProviderConfig{WorkspaceRoot: c.WorkspaceRoot, DockerCommand: c.DockerCommand, ImageID: c.ImageID, Mode: c.Mode, Helper: c.ContainerHelper.pinned(), NativeHelper: c.NativeHelper.pinned(), Pipeline: c.Pipeline.pinned(), ResourceBudgetSHA256: c.ResourceBudget.SHA256, Reference: c.Reference.pinned(), Evaluator: c.Evaluator.pinned(), Truth: c.Truth.pinned(), TimeoutSeconds: c.TimeoutSeconds, Analysis: c.analysis()})
	if e != nil {
		return nil, nil, e
	}
	return p, p.Close, nil
}

// BrokerService owns lifetime custody. On uncertain failure its handle must stay
// reachable until process exit; Shutdown never closes uncertain authority.
type BrokerService struct {
	mu              sync.Mutex
	profile         string
	store           *Store
	registry        *InputRegistry
	broker          *Broker
	server          *BridgeUnixServer
	provider        Provider
	closeProvider   func() error
	closed          bool
	serverCloseOnce sync.Once
	serverCloseErr  error
	terminalErr     error
}

func (s *BrokerService) ProfileSHA256() string { return s.profile }

// OpenBrokerService validates every asset before creating a provider or socket.
// A non-nil handle returned with an error retains any uncertain startup custody;
// callers must keep it reachable until process exit and must not retry/adopt it.
func OpenBrokerService(ctx context.Context, c BrokerServiceConfig) (*BrokerService, error) {
	return openBrokerService(ctx, c, makeBrokerServiceProvider)
}
func openBrokerService(ctx context.Context, c BrokerServiceConfig, factory brokerServiceProviderFactory) (*BrokerService, error) {
	profile, e := BrokerServiceProfile(ctx, c)
	if e != nil {
		return nil, e
	}
	s := &BrokerService{profile: profile}
	s.provider, s.closeProvider, e = factory(ctx, c)
	if e != nil {
		return nil, e
	}
	cleanup := func(e error) (*BrokerService, error) {
		if s.broker != nil {
			s.broker.Close()
			if s.broker.Wait(ctx) != nil {
				return s, e
			}
		}
		if s.store != nil && !s.store.Snapshot().Healthy {
			return s, e
		}
		if s.closeProvider != nil && s.closeProvider() != nil {
			return s, e
		}
		if s.registry != nil {
			s.registry.Close()
		}
		if s.store != nil {
			s.store.Close()
		}
		s.closed = true
		return nil, e
	}
	s.store, e = Open(ctx, c.StoreRoot, NativeArtifactPolicy())
	if e != nil {
		return cleanup(e)
	}
	s.registry, e = NewInputRegistry(s.store)
	if e != nil {
		return cleanup(e)
	}
	coordinator, e := NewCoordinator(s.store, s.registry, s.provider)
	if e != nil {
		return cleanup(e)
	}
	s.broker, e = NewBrokerV2(ctx, BrokerConfig{c.JournalRoot, profile}, coordinator)
	if e != nil {
		coordinator.Close()
		return cleanup(e)
	}
	uid := c.AllowedUID
	s.server, e = ListenBridgeUnixV2(UnixServerConfig{SocketPath: c.SocketPath, AllowedUID: &uid, MaxConnections: 8, RequestTimeout: 5 * time.Second, RunTimeout: 15 * time.Minute, WriteTimeout: 5 * time.Second}, s.broker)
	if e != nil {
		return cleanup(e)
	}
	return s, nil
}

// closeServer caches the first actual socket cleanup result. sync.Once also
// synchronizes cancellation and explicit shutdown callers through that result.
func (s *BrokerService) closeServer() error {
	s.serverCloseOnce.Do(func() {
		if s.server != nil {
			s.serverCloseErr = s.server.Close()
		}
	})
	return s.serverCloseErr
}
func (s *BrokerService) Serve(ctx context.Context) error {
	if s == nil || s.server == nil || ctx == nil {
		return fail("artifact_service_unavailable")
	}
	// The service owns cancellation/cleanup rather than letting the transport's
	// AfterFunc consume a socket cleanup failure before Shutdown can inspect it.
	stop := context.AfterFunc(ctx, func() { s.closeServer() })
	defer stop()
	return s.server.Serve(context.WithoutCancel(ctx))
}

// Shutdown first stops channels and requests cancellation, then requires broker
// Wait and healthy Store before closing provider/registry/Store. Uncertain
// descriptors stay in this handle. Socket cleanup failures remain errors after
// healthy custody closes and across repeated Shutdown calls; no history resets.
func (s *BrokerService) Shutdown(ctx context.Context) error {
	if s == nil || ctx == nil {
		return fail("artifact_service_context_invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return s.terminalErr
	}
	remember := func(e error) error {
		if s.terminalErr == nil {
			s.terminalErr = e
		}
		return s.terminalErr
	}
	// A socket cleanup error does not bypass cancellation or provider Wait.
	if e := s.closeServer(); e != nil {
		remember(e)
	}
	if s.broker != nil {
		if e := s.broker.Close(); e != nil {
			return remember(e)
		}
		if e := s.broker.Wait(ctx); e != nil {
			return remember(e)
		}
	}
	if s.store != nil && !s.store.Snapshot().Healthy {
		return remember(fail("artifact_service_pending"))
	}
	if s.closeProvider != nil {
		if e := s.closeProvider(); e != nil {
			return remember(fail("artifact_service_close_failed"))
		}
	}
	if s.registry != nil {
		if e := s.registry.Close(); e != nil {
			return remember(fail("artifact_service_close_failed"))
		}
	}
	if s.store != nil {
		if e := s.store.Close(); e != nil {
			return remember(fail("artifact_service_close_failed"))
		}
	}
	s.closed = true
	return s.terminalErr
}
