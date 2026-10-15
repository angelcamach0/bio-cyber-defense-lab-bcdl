//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package artifactexecutor

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

type OwnerReaderServiceConfig struct {
	SocketPath        string `json:"socket_path"`
	AllowedResultsUID uint32 `json:"allowed_results_uid"`
}
type OwnerReadBrokerServiceConfig struct {
	SchemaVersion int                      `json:"schema_version"`
	Owner         OwnerBrokerServiceConfig `json:"owner"`
	Reader        OwnerReaderServiceConfig `json:"reader"`
}

func (c OwnerReadBrokerServiceConfig) verify(ctx context.Context) error {
	if c.SchemaVersion != 1 || c.Owner.verify(ctx) != nil || !servicePath(c.Reader.SocketPath) || c.Reader.AllowedResultsUID != uint32(os.Geteuid()) {
		return fail("artifact_owner_read_service_config_invalid")
	}
	if _, _, e := unixName(c.Reader.SocketPath); e != nil {
		return fail("artifact_owner_read_service_config_invalid")
	}
	root := filepath.Dir(c.Reader.SocketPath)
	e := c.Owner.Execution
	for _, p := range []string{e.StoreRoot, e.JournalRoot, e.WorkspaceRoot, filepath.Dir(e.SocketPath), e.PythonPath, e.NativeHelper.Path, e.ContainerHelper.Path, e.Pipeline.Path, e.ResourceBudget.Path, e.Reference.Path, e.Evaluator.Path, e.Truth.Path, e.AnalysisExecutable.Path, e.AnalysisRules.Path, e.AnalysisPanel.Path} {
		if p != "" && serviceOverlap(root, p) {
			return fail("artifact_owner_read_service_roots_overlap")
		}
	}
	for _, p := range strings.Split(e.ToolPath, ":") {
		if p != "" && serviceOverlap(root, p) {
			return fail("artifact_owner_read_service_roots_overlap")
		}
	}
	return nil
}
func LoadOwnerReadBrokerServiceConfig(ctx context.Context, path string) (OwnerReadBrokerServiceConfig, error) {
	var c OwnerReadBrokerServiceConfig
	if ctx == nil || ctx.Err() != nil || !servicePath(path) {
		return c, fail("artifact_owner_read_service_config_invalid")
	}
	dir, e := unixExistingDirectory(filepath.Dir(path))
	if e != nil {
		return c, e
	}
	defer dir.Close()
	f, e := regular(dir, filepath.Base(path), false)
	if e != nil {
		return c, e
	}
	defer f.Close()
	before, e := f.Stat()
	if e != nil || before.Size() < 1 || before.Size() > brokerServiceConfigLimit {
		return c, fail("artifact_owner_read_service_config_invalid")
	}
	raw, e := io.ReadAll(io.NewSectionReader(f, 0, brokerServiceConfigLimit+1))
	after, se := f.Stat()
	if e != nil || se != nil || !ownerInfoEqual(before, after) || !safeInfo(f, false) || int64(len(raw)) != before.Size() || !utf8.Valid(raw) || strictJSON(raw, &c) != nil || c.verify(ctx) != nil {
		return OwnerReadBrokerServiceConfig{}, fail("artifact_owner_read_service_config_invalid")
	}
	for _, p := range []string{c.Owner.Execution.StoreRoot, c.Owner.Execution.JournalRoot, c.Owner.Execution.WorkspaceRoot, filepath.Dir(c.Owner.Execution.SocketPath), filepath.Dir(c.Reader.SocketPath)} {
		if serviceOverlap(path, p) {
			return OwnerReadBrokerServiceConfig{}, fail("artifact_owner_read_service_roots_overlap")
		}
	}
	return c, nil
}
func OwnerReadBrokerServiceProfile(ctx context.Context, c OwnerReadBrokerServiceConfig) (string, error) {
	if e := c.verify(ctx); e != nil {
		return "", e
	}
	owner, e := OwnerBrokerServiceProfile(ctx, c.Owner)
	if e != nil {
		return "", e
	}
	raw, e := json.Marshal(struct {
		Domain                                          string                   `json:"domain"`
		OwnerProfileSHA256                              string                   `json:"owner_profile_sha256"`
		Reader                                          OwnerReaderServiceConfig `json:"reader"`
		Protocol                                        string                   `json:"protocol"`
		Connections, Handlers, FrameBytes, ReceiptBytes int
		RequestSeconds, ReadSeconds, WriteSeconds       int
	}{"biozero.owner-read-broker.profile.v1", owner, c.Reader, OwnerReadRequestDomain, 4, 2, MaxFrameBytes, int(MaxBridgeReceiptBytes), 5, 30, 5})
	if e != nil {
		return "", fail("artifact_owner_read_service_profile_invalid")
	}
	return digest(raw), nil
}

// OwnerReadBrokerService owns both listeners and the single writer custody.
// Same-UID private sockets are the initial native policy, not role isolation.
type OwnerReadBrokerService struct {
	mu          sync.Mutex
	engine      *BrokerService
	reader      *OwnerReadUnixServer
	started     bool
	serveDone   chan struct{}
	closed      bool
	terminalErr error
	closeOnce   sync.Once
	closeErr    error
}

func (s *OwnerReadBrokerService) ProfileSHA256() string {
	if s == nil || s.engine == nil {
		return ""
	}
	return s.engine.ProfileSHA256()
}
func InitializeOwnerReadBrokerService(ctx context.Context, c OwnerReadBrokerServiceConfig) (*OwnerReadBrokerService, error) {
	return openOwnerReadBrokerService(ctx, c, true, makeBrokerServiceProvider)
}
func OpenOwnerReadBrokerService(ctx context.Context, c OwnerReadBrokerServiceConfig) (*OwnerReadBrokerService, error) {
	return openOwnerReadBrokerService(ctx, c, false, makeBrokerServiceProvider)
}
func openOwnerReadBrokerService(ctx context.Context, c OwnerReadBrokerServiceConfig, create bool, factory brokerServiceProviderFactory) (*OwnerReadBrokerService, error) {
	profile, e := OwnerReadBrokerServiceProfile(ctx, c)
	if e != nil {
		return nil, e
	}
	engine, e := openOwnerBrokerServiceWithProfile(ctx, c.Owner, create, factory, profile)
	if engine == nil {
		return nil, e
	}
	s := &OwnerReadBrokerService{engine: engine, serveDone: make(chan struct{})}
	if e != nil {
		return s, e
	}
	if create {
		return s, nil
	}
	r, e := NewOwnerReader(engine.broker)
	if e == nil {
		uid := c.Reader.AllowedResultsUID
		s.reader, e = ListenOwnerReadUnix(UnixServerConfig{SocketPath: c.Reader.SocketPath, AllowedUID: &uid, MaxConnections: 4, RequestTimeout: 5 * time.Second, RunTimeout: 30 * time.Second, WriteTimeout: 5 * time.Second}, r)
	}
	if e != nil {
		if s.Shutdown(ctx) == nil {
			return nil, e
		}
		return s, e
	}
	return s, nil
}
func (s *OwnerReadBrokerService) closeListeners() error {
	s.closeOnce.Do(func() {
		if s.reader != nil {
			s.closeErr = s.reader.Close()
		}
		if e := s.engine.closeServer(); s.closeErr == nil {
			s.closeErr = e
		}
	})
	return s.closeErr
}
func (s *OwnerReadBrokerService) Serve(ctx context.Context) error {
	if s == nil || ctx == nil {
		return fail("artifact_owner_read_service_unavailable")
	}
	s.mu.Lock()
	if s.started || s.closed || s.reader == nil {
		s.mu.Unlock()
		return fail("artifact_owner_read_service_unavailable")
	}
	s.started = true
	s.mu.Unlock()
	defer close(s.serveDone)
	stop := context.AfterFunc(ctx, func() { s.closeListeners() })
	defer stop()
	results := make(chan error, 2)
	go func() {
		err := s.engine.Serve(context.WithoutCancel(ctx))
		// Close may win before the worker Serve goroutine enters its old
		// transport. This wrapper is its only starter, so closed+never-started
		// means our own early shutdown, not an accept failure to hide.
		base := s.engine.server.base
		base.mu.Lock()
		stoppedBeforeStart := base.closed && !base.started
		base.mu.Unlock()
		if stoppedBeforeStart {
			err = nil
		}
		results <- err
	}()
	go func() { results <- s.reader.Serve(context.WithoutCancel(ctx)) }()
	first := <-results
	s.closeListeners()
	second := <-results
	if e := s.closeListeners(); e != nil {
		return e
	}
	if first != nil {
		return first
	}
	return second
}
func (s *OwnerReadBrokerService) Shutdown(ctx context.Context) error {
	if s == nil || ctx == nil {
		return fail("artifact_owner_read_service_context_invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return s.terminalErr
	}
	remember := func(e error) {
		if s.terminalErr == nil {
			s.terminalErr = e
		}
	}
	remember(s.closeListeners())
	if s.started {
		select {
		case <-s.serveDone:
		case <-ctx.Done():
			remember(fail("artifact_owner_read_service_pending"))
			return s.terminalErr
		}
	}
	// Serve joins reader handlers; before Serve starts there can be none.
	// Worker transport predates Wait: drain its tracked connections explicitly.
	if s.engine.server != nil {
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			s.engine.server.base.mu.Lock()
			n := len(s.engine.server.base.connections)
			s.engine.server.base.mu.Unlock()
			if n == 0 {
				break
			}
			select {
			case <-ticker.C:
			case <-ctx.Done():
				remember(fail("artifact_owner_read_service_pending"))
				return s.terminalErr
			}
		}
	}
	remember(s.engine.Shutdown(ctx))
	if s.engine.closed {
		s.closed = true
	}
	return s.terminalErr
}
