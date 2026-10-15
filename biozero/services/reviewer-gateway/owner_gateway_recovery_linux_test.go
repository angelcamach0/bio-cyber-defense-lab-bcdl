//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	projection "biozero/enclave-runner/receiptprojection"
)

// The child exits without calling custody Close, so kernel process death (not a
// production reset API) releases every actual raw lifetime flock. Its observation
// uses the explicitly synthetic protocol fixture, never real scientific receipt.
func TestOwnerGatewayRegistryColdProcessHelper(t *testing.T) {
	path := os.Getenv("BIOZERO_GATEWAY_COLD_TEST_CONFIG")
	if path == "" {
		t.Skip("subprocess helper")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	m, err := loadOwnerGatewayConfig(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("BIOZERO_GATEWAY_COLD_TEST_ACTION") == "reject" {
		_, err = openOwnerGatewayStore(ctx, m)
		if err == nil || err.Error() != "owner_gateway_storage_unhealthy" {
			t.Fatal("malformed cold history did not fence before adoption", err)
		}
		os.Stdout.WriteString("malformed_history_refused\n")
		os.Exit(0)
	}
	if err = initializeOwnerGatewayStore(ctx, m); err != nil {
		t.Fatal(err)
	}
	s, err := openOwnerGatewayStore(ctx, m)
	if err != nil {
		t.Fatal(err)
	}
	r, _, err := s.Intent(ctx, "a", "synthetic", strings.Repeat("1", 32))
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Execute(ctx, r.RunID); err == nil {
		t.Fatal("fixture upload failure reported success")
	}
	r, err = s.Run(ctx, "a", r.RunID)
	if err != nil || r.Phase != "delivering" || r.AcceptanceSHA256 == "" {
		t.Fatal("uncertain accepted delivery missing", err)
	}
	if _, err = s.ObserveResult(ctx, r.RunID, ogProtocolResult(r)); err != nil {
		t.Fatal(err)
	}
	os.Stdout.WriteString("uncertain_history_retained\n")
	os.Exit(0)
}

func ogColdChild(t *testing.T, path, action string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, binary, "-test.run=^TestOwnerGatewayRegistryColdProcessHelper$")
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "BIOZERO_") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	cmd.Env = append(cmd.Env, "BIOZERO_GATEWAY_COLD_TEST_CONFIG="+path, "BIOZERO_GATEWAY_COLD_TEST_ACTION="+action)
	raw, err := cmd.CombinedOutput()
	if err != nil || ctx.Err() != nil {
		t.Fatalf("cold process fixture failed: %v %s", err, raw)
	}
	return raw
}

func TestOwnerGatewayRegistryColdUncertaintyAndMalformedBindings(t *testing.T) {
	f := ogNewConfigFixture(t)
	var posts atomic.Int32
	upload := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/v1/uploads" {
			http.Error(w, "fixture", 404)
			return
		}
		posts.Add(1)
		http.Error(w, "fixture unavailable after attempted delivery", 503)
	}))
	upload.TLS = f.serverTLS.Clone()
	upload.Config.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){}
	upload.StartTLS()
	defer upload.Close()
	f.config.UploadURL = upload.URL
	ogWriteConfig(t, f.path, f.config)
	if raw := ogColdChild(t, f.path, "create"); string(raw) != "uncertain_history_retained\n" {
		t.Fatal("unexpected creation control")
	}
	if posts.Load() != 1 {
		t.Fatal("fixture delivery did not attempt exactly once")
	}
	ledgerPath := filepath.Join(f.config.StateDirectory, "ledger.json")
	original, err := os.ReadFile(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	var ledger ownerGatewayLedger
	if err = json.Unmarshal(original, &ledger); err != nil || len(ledger.Runs) != 1 {
		t.Fatal("missing retained row", err)
	}
	run := ledger.Runs[0]
	intentPath := filepath.Join(f.config.StateDirectory, "operations", run.RunID, "intent.json")
	intentRaw, err := os.ReadFile(intentPath)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*ownerGatewayLedger){
		"terminal_status": func(l *ownerGatewayLedger) { l.Runs[0].Commit.Status = "pending" },
		"release_state":   func(l *ownerGatewayLedger) { l.Runs[0].Commit.ReleaseStatus = "approved" },
		"receipt_size":    func(l *ownerGatewayLedger) { l.Runs[0].Commit.Artifact.ReceiptBytes++ },
		"receipt_hash":    func(l *ownerGatewayLedger) { l.Runs[0].Commit.Artifact.ReceiptSHA256 = strings.Repeat("a", 64) },
		"invalid_store":   func(l *ownerGatewayLedger) { l.Runs[0].Commit.Artifact.StoreID = "unknown" },
		"invalid_lease":   func(l *ownerGatewayLedger) { l.Runs[0].Commit.Artifact.LeaseID = "unknown" },
		"unknown_export": func(l *ownerGatewayLedger) {
			l.Runs[0].Commit.Artifact.Files["private_file"] = projection.ArtifactFile{SHA256: strings.Repeat("a", 64), Bytes: 1}
		},
		"changed_profile": func(l *ownerGatewayLedger) { l.Runs[0].Commit.Artifact.ProfileSHA256 = strings.Repeat("a", 64) },
		"changed_owner_labels": func(l *ownerGatewayLedger) {
			l.Runs[0].ReviewerID = "b"
			l.Runs[0].CredentialSHA256 = ogConfigDigest(f.leaves["b"].Raw)
		},
	} {
		t.Run(name, func(t *testing.T) {
			var changed ownerGatewayLedger
			if err := json.Unmarshal(original, &changed); err != nil {
				t.Fatal(err)
			}
			mutate(&changed)
			raw, err := json.Marshal(changed)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(ledgerPath, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if name == "changed_owner_labels" {
				raw, err = json.Marshal(ogImmutableRun(changed.Runs[0]))
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(intentPath, raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if got := ogColdChild(t, f.path, "reject"); string(got) != "malformed_history_refused\n" {
				t.Fatal("unknown child verdict")
			}
			// Restore only the exact measured positive-control bytes in this ordinary
			// TempDir fixture; no retained acceptance workspace is repaired or erased.
			if err = os.WriteFile(ledgerPath, original, 0600); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(intentPath, intentRaw, 0600); err != nil {
				t.Fatal(err)
			}
		})
	}
	m, err := loadOwnerGatewayConfig(context.Background(), f.path)
	if err != nil {
		t.Fatal(err)
	}
	defer ogCloseMaterial(m)
	s, err := openOwnerGatewayStore(context.Background(), m)
	if err != nil {
		t.Fatal("known retained custody did not cold-open", err)
	}
	defer ogRegistryReleaseTestHandles(s)
	rows, err := s.Runs(context.Background(), "a")
	if err != nil || len(rows) != 1 || rows[0].Phase != "delivering" || rows[0].ErrorCode != "owner_gateway_operation_uncertain" || rows[0].Commit == nil {
		t.Fatal("cold Open changed uncertainty or terminal observation", err)
	}
	if err = s.Execute(context.Background(), run.RunID); err == nil {
		t.Fatal("cold Open resubmitted retained operation")
	}
	if posts.Load() != 1 {
		t.Fatal("cold inspection performed network mutation")
	}
	unchanged, err := os.ReadFile(ledgerPath)
	if err != nil || !bytes.Equal(unchanged, original) {
		t.Fatal("cold Open changed history bytes", err)
	}
	if first := s.Close(); first == nil || first.Error() != "ownership_delivery_pending" {
		t.Fatal("cold uncertainty reported healthy Close", first)
	}
}
