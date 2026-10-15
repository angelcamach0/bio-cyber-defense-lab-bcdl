//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package artifactexecutor

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"path/filepath"
	"syscall"
	"time"
	"unicode/utf8"

	ownership "biozero/ownership-authority"
)

// The owner service has a separate closed config. The execution object keeps
// the existing engine asset/policy contract; scope is deliberately outside the
// profile digest to avoid authority-policy/profile circularity at genesis.
type OwnerBrokerServiceConfig struct {
	SchemaVersion int                       `json:"schema_version"`
	Execution     BrokerServiceConfig       `json:"execution"`
	AuthorityID   string                    `json:"authority_id"`
	PublicKeyHex  string                    `json:"public_key_hex"`
	ExpectedScope ownership.AcceptanceScope `json:"expected_scope"`
}

func (c OwnerBrokerServiceConfig) verify(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || c.SchemaVersion != 1 || !hexID(c.AuthorityID, 32) || !hexID(c.PublicKeyHex, 64) || c.Execution.verify(ctx) != nil {
		return fail("artifact_owner_service_config_invalid")
	}
	if c.ExpectedScope != (ownership.AcceptanceScope{}) && (!hexID(c.ExpectedScope.StoreID, 32) || !hexID(c.ExpectedScope.PolicySHA256, 64)) {
		return fail("artifact_owner_service_scope_invalid")
	}
	return nil
}

// Load creates no state, provider or listener. Zero scope is for print-profile
// only; serving and initialization require independently provisioned genesis.
func LoadOwnerBrokerServiceConfig(ctx context.Context, path string) (OwnerBrokerServiceConfig, error) {
	var c OwnerBrokerServiceConfig
	if ctx == nil || ctx.Err() != nil || !servicePath(path) {
		return c, fail("artifact_owner_service_config_invalid")
	}
	dir, e := unixExistingDirectoryLoose(filepath.Dir(path))
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
		return c, fail("artifact_owner_service_config_invalid")
	}
	raw, e := io.ReadAll(io.NewSectionReader(f, 0, brokerServiceConfigLimit+1))
	after, se := f.Stat()
	if e != nil || se != nil || !ownerInfoEqual(before, after) || !safeInfo(f, false) || int64(len(raw)) != before.Size() || !utf8.Valid(raw) || strictJSON(raw, &c) != nil || c.verify(ctx) != nil {
		return OwnerBrokerServiceConfig{}, fail("artifact_owner_service_config_invalid")
	}
	for _, root := range []string{c.Execution.StoreRoot, c.Execution.JournalRoot, c.Execution.WorkspaceRoot, filepath.Dir(c.Execution.SocketPath)} {
		if serviceOverlap(path, root) {
			return OwnerBrokerServiceConfig{}, fail("artifact_service_roots_overlap")
		}
	}
	return c, nil
}
func OwnerBrokerServiceProfile(ctx context.Context, c OwnerBrokerServiceConfig) (string, error) {
	if e := c.verify(ctx); e != nil {
		return "", e
	}
	engine, e := BrokerServiceProfile(ctx, c.Execution)
	if e != nil {
		return "", e
	}
	raw, e := json.Marshal(struct {
		Domain          string `json:"domain"`
		ProtocolVersion int    `json:"protocol_version"`
		EngineSHA256    string `json:"engine_sha256"`
		AuthorityID     string `json:"authority_id"`
		PublicKeyHex    string `json:"public_key_hex"`
	}{"biozero.owner-broker.profile.v1", 3, engine, c.AuthorityID, c.PublicKeyHex})
	if e != nil {
		return "", fail("artifact_owner_service_profile_invalid")
	}
	return digest(raw), nil
}

type ownerInitializationProvider struct{}

func (ownerInitializationProvider) Execute(context.Context, *ScopedInput, *Exporter) ProviderCompletion {
	return nativeFailure("artifact_owner_initialization_only", true)
}

func InitializeOwnerBrokerService(ctx context.Context, c OwnerBrokerServiceConfig) (*BrokerService, error) {
	return openOwnerBrokerService(ctx, c, true, makeBrokerServiceProvider)
}
func OpenOwnerBrokerService(ctx context.Context, c OwnerBrokerServiceConfig) (*BrokerService, error) {
	return openOwnerBrokerService(ctx, c, false, makeBrokerServiceProvider)
}
func ownerExistingState(ctx context.Context, path, name string) error {
	d, e := unixExistingDirectory(path)
	if e != nil {
		return fail("artifact_owner_service_history_required")
	}
	defer d.Close()
	raw, e := boundedRead(ctx, d, name, bridgeJournalLimit)
	if e != nil || len(raw) == 0 {
		return fail("artifact_owner_service_history_required")
	}
	return nil
}
func openOwnerBrokerService(ctx context.Context, c OwnerBrokerServiceConfig, create bool, factory brokerServiceProviderFactory) (*BrokerService, error) {
	profile, e := OwnerBrokerServiceProfile(ctx, c)
	if e != nil {
		return nil, e
	}
	return openOwnerBrokerServiceWithProfile(ctx, c, create, factory, profile)
}

// The closed reader service computes its own profile before explicit genesis.
// The ordinary owner service continues to use its original profile unchanged.
func openOwnerBrokerServiceWithProfile(ctx context.Context, c OwnerBrokerServiceConfig, create bool, factory brokerServiceProviderFactory, profile string) (*BrokerService, error) {
	if c.verify(ctx) != nil || !hexID(profile, 64) {
		return nil, fail("artifact_owner_service_config_invalid")
	}
	var e error
	if !hexID(c.ExpectedScope.StoreID, 32) || !hexID(c.ExpectedScope.PolicySHA256, 64) {
		return nil, fail("artifact_owner_service_scope_invalid")
	}
	engine := c.Execution
	if create {
		parent, e := unixExistingDirectory(filepath.Dir(engine.StoreRoot))
		if e != nil {
			return nil, e
		}
		e = syscall.Mkdirat(int(parent.Fd()), filepath.Base(engine.StoreRoot), 0700)
		if e == nil {
			e = parent.Sync()
		}
		parent.Close()
		if e != nil {
			return nil, fail("artifact_owner_service_root_not_new")
		}
	} else {
		if e = ownerExistingState(ctx, engine.StoreRoot, "ledger.json"); e != nil {
			return nil, e
		}
		if e = ownerExistingState(ctx, engine.JournalRoot, "journal.json"); e != nil {
			return nil, e
		}
	}
	s := &BrokerService{profile: profile}
	cleanup := func(cause error) (*BrokerService, error) {
		if s.broker != nil {
			s.broker.Close()
			if s.broker.Wait(ctx) != nil {
				return s, cause
			}
		}
		if s.store != nil && !s.store.Snapshot().Healthy {
			return s, cause
		}
		if s.closeProvider != nil && s.closeProvider() != nil {
			return s, cause
		}
		if s.registry != nil && s.registry.Close() != nil {
			return s, cause
		}
		if s.store != nil && s.store.Close() != nil {
			return s, cause
		}
		s.closed = true
		return nil, cause
	}
	if create {
		s.provider = ownerInitializationProvider{}
	} else {
		s.provider, s.closeProvider, e = factory(ctx, engine)
		if e != nil {
			return nil, e
		}
	}
	s.store, e = Open(ctx, engine.StoreRoot, NativeArtifactPolicy())
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
	public, _ := hex.DecodeString(c.PublicKeyHex)
	config := OwnerBrokerConfig{engine.JournalRoot, profile, ownership.AuthorityPin{AuthorityID: c.AuthorityID, PublicKey: public, PipelineMode: engine.Mode, ExecutionProfileSHA256: profile}, c.ExpectedScope}
	if create {
		s.broker, e = CreateBrokerV3(ctx, config, coordinator)
	} else {
		s.broker, e = OpenBrokerV3(ctx, config, coordinator)
	}
	if e != nil {
		coordinator.Close()
		return cleanup(e)
	}
	if create {
		return s, nil
	}
	uid := engine.AllowedUID
	s.server, e = ListenBridgeUnixV3(UnixServerConfig{SocketPath: engine.SocketPath, AllowedUID: &uid, MaxConnections: 8, RequestTimeout: 5 * time.Second, RunTimeout: 15 * time.Minute, WriteTimeout: 5 * time.Second}, s.broker)
	if e != nil {
		return cleanup(e)
	}
	return s, nil
}
