//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func ogRegistryFixture(t *testing.T) ownerGatewayMaterial {
	t.Helper()
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	m := ownerGatewayMaterial{Config: ownerGatewayConfig{StateDirectory: filepath.Join(parent, "state"), ExecutionProfileSHA256: strings.Repeat("e", 64)}, ContextSHA256: strings.Repeat("c", 64), Reviewers: map[string]ownerGatewayReviewer{}, Experiments: map[string]ownerGatewayExperiment{}}
	for _, id := range []string{"a", "b"} {
		m.Reviewers[id] = ownerGatewayReviewer{Config: ownerGatewayReviewerConfig{ID: id, Enabled: true}, CredentialSHA256: strings.Repeat(id, 64)}
	}
	m.Experiments["snp"] = ownerGatewayExperiment{Config: ownerGatewayExperimentConfig{ID: "snp", OriginalName: "input.fastq"}, Input: []byte("abc"), InputSHA256: ogConfigDigest([]byte("abc")), InputBytes: 3, ReferenceSHA256: strings.Repeat("f", 64), ReferenceBytes: 6}
	return m
}
func ogRegistryOpen(t *testing.T, m ownerGatewayMaterial) *ownerGatewayStore {
	t.Helper()
	ctx := context.Background()
	if err := initializeOwnerGatewayStore(ctx, m); err != nil {
		t.Fatal(err)
	}
	s, err := openOwnerGatewayStore(ctx, m)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if !s.closed {
			_ = s.Close()
		}
		ogRegistryReleaseTestHandles(s)
	})
	return s
}

// Explicit test-only simulation of process descriptor death. Production never
// exposes a release/reset operation for sticky or pending custody.
func ogRegistryReleaseTestHandles(s *ownerGatewayStore) {
	if s == nil {
		return
	}
	if s.rawHeld {
		_ = syscall.Close(s.rawFD)
		s.rawHeld = false
	}
	if s.operations != nil {
		_ = s.operations.Close()
	}
	if s.lock != nil {
		_ = s.lock.Close()
	}
	if s.root != nil {
		_ = s.root.Close()
	}
}
func TestOwnerGatewayRegistryExplicitInitAndColdNoDispatch(t *testing.T) {
	ctx := context.Background()
	m := ogRegistryFixture(t)
	if _, err := openOwnerGatewayStore(ctx, m); err == nil {
		t.Fatal("Open created absent state")
	}
	if _, err := os.Stat(m.Config.StateDirectory); !os.IsNotExist(err) {
		t.Fatal("Open mutated missing root")
	}
	s := ogRegistryOpen(t, m)
	if err := initializeOwnerGatewayStore(ctx, m); err == nil {
		t.Fatal("reinitialized existing root")
	}
	r, newIntent, err := s.Intent(ctx, "a", "snp", strings.Repeat("1", 32))
	if err != nil || !newIntent {
		t.Fatalf("Intent: %v", err)
	}
	if _, err := openOwnerGatewayStore(ctx, m); err == nil {
		t.Fatal("second writer acquired live root")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	cold, err := openOwnerGatewayStore(ctx, m)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cold.Close(); ogRegistryReleaseTestHandles(cold) }()
	runs, err := cold.Runs(ctx, "a")
	if err != nil || len(runs) != 1 || runs[0].RunID != r.RunID || runs[0].ErrorCode != "owner_gateway_needs_operator" {
		t.Fatalf("cold history: %#v %v", runs, err)
	}
	if err = cold.Execute(ctx, r.RunID); err == nil {
		t.Fatal("cold intent dispatched")
	}
	if cold.ledger.RetainedBytes != ownerGatewayRunCharge {
		t.Fatal("cold restart reset logical retention")
	}
	if _, err = os.Stat(filepath.Join(m.Config.StateDirectory, "operations", r.RunID, "authority")); !os.IsNotExist(err) {
		t.Fatal("cold query created authority operation")
	}
}
func TestOwnerGatewayRegistryIdempotencyAndNoRefund(t *testing.T) {
	ctx := context.Background()
	m := ogRegistryFixture(t)
	s := ogRegistryOpen(t, m)
	r, _, err := s.Intent(ctx, "a", "snp", strings.Repeat("1", 32))
	if err != nil {
		t.Fatal(err)
	}
	again, fresh, err := s.Intent(ctx, "a", "snp", r.RequestID)
	if err != nil || fresh || again.RunID != r.RunID {
		t.Fatal("idempotent request admitted a second intent", err)
	}
	if _, _, err = s.Intent(ctx, "a", "snp", strings.Repeat("2", 32)); err == nil {
		t.Fatal("per-reviewer active admission bypass")
	}
	if _, _, err = s.Intent(ctx, "b", "snp", strings.Repeat("3", 32)); err != nil {
		t.Fatal("second distinct reviewer rejected", err)
	}
	if _, err = s.Run(ctx, "b", r.RunID); err == nil {
		t.Fatal("cross-reviewer run disclosed")
	}
	rows, err := s.Runs(ctx, "b")
	if err != nil || len(rows) != 1 || rows[0].RunID == r.RunID {
		t.Fatal("cross-reviewer history disclosed")
	}
	if s.ledger.RetainedBytes != 2*ownerGatewayRunCharge || len(s.ledger.Runs) != 2 {
		t.Fatal("duplicate or denial changed retained charges")
	}
	m.ContextSHA256 = strings.Repeat("d", 64)
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if bad, err := openOwnerGatewayStore(ctx, m); err == nil {
		ogRegistryReleaseTestHandles(bad)
		t.Fatal("different context adopted history")
	}
}
func TestOwnerGatewayRegistryGuardFencesChangedStorage(t *testing.T) {
	ctx := context.Background()
	s := ogRegistryOpen(t, ogRegistryFixture(t))
	r, _, err := s.Intent(ctx, "a", "snp", strings.Repeat("1", 32))
	if err != nil {
		t.Fatal(err)
	}
	called := 0
	writeFailure := errors.New("browser disconnected")
	if err = s.GuardRun(ctx, "a", r, func() error { called++; return writeFailure }); !errors.Is(err, writeFailure) {
		t.Fatal("callback error changed", err)
	}
	if err = s.Guard(ctx, func() error { called++; return nil }); err != nil || called != 2 {
		t.Fatal("browser failure poisoned custody", err)
	}
	path := filepath.Join(s.material.Config.StateDirectory, "operations", r.RunID, "intent.json")
	if err = os.WriteFile(path, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = s.GuardRun(ctx, "a", r, func() error { called++; return nil }); err == nil || called != 2 {
		t.Fatal("stale snapshot released after durable corruption")
	}
	if err = s.Close(); err == nil {
		t.Fatal("unhealthy close hid error")
	}
	if _, err = openOwnerGatewayStore(ctx, s.material); err == nil {
		t.Fatal("sticky lock released")
	}
}
func TestOwnerGatewayRegistryInterruptedPublicationRetainsEvidence(t *testing.T) {
	for _, point := range []string{"intent_write", "intent_dir_sync", "run_mkdir", "ledger_write", "ledger_rename", "ledger_dir_sync", "intent_unlink", "final_dir_sync"} {
		t.Run(point, func(t *testing.T) {
			ctx := context.Background()
			m := ogRegistryFixture(t)
			s := ogRegistryOpen(t, m)
			s.fault = func(name string) error {
				if name == point {
					return errors.New("injected durable boundary failure")
				}
				return nil
			}
			if _, _, err := s.Intent(ctx, "a", "snp", strings.Repeat("1", 32)); err == nil {
				t.Fatal("fault admitted operation")
			}
			if !s.sticky {
				t.Fatal("fault did not latch")
			}
			if _, err := openOwnerGatewayStore(ctx, m); err == nil {
				t.Fatal("uncertain writer lock lost")
			}
			if err := s.Close(); err == nil {
				t.Fatal("Close reported healthy")
			}
			if _, err := os.Stat(m.Config.StateDirectory); err != nil {
				t.Fatal("failed root removed", err)
			}
			// A pre-mutation failure can leave an unchanged empty root. Later phases
			// leave a marker/partial history; neither case is silently repaired.
			ogRegistryReleaseTestHandles(s)
			cold, err := openOwnerGatewayStore(ctx, m)
			if point == "intent_write" {
				if err != nil {
					t.Fatal("unchanged root became corrupt", err)
				}
				_ = cold.Close()
				ogRegistryReleaseTestHandles(cold)
			} else if point == "final_dir_sync" {
				if err == nil {
					rows, e := cold.Runs(ctx, "a")
					if e != nil || len(rows) != 1 || cold.ledger.RetainedBytes != ownerGatewayRunCharge {
						t.Fatal("published history erased")
					}
					_ = cold.Close()
					ogRegistryReleaseTestHandles(cold)
				}
			} else if err == nil {
				ogRegistryReleaseTestHandles(cold)
				t.Fatal("partial transaction adopted")
			}
		})
	}
}
