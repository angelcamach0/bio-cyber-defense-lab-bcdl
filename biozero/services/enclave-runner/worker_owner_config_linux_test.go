//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func ownerWorkerConfigFixture(t *testing.T) (*ownerWorkerTestFixture, ownerWorkerConfig, string) {
	t.Helper()
	f := newOwnerWorkerTestFixture(t)
	keyPath := filepath.Join(f.root, "worker-decrypt.key")
	keyRaw := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(f.workerKey)})
	if e := os.WriteFile(keyPath, keyRaw, 0600); e != nil {
		t.Fatal(e)
	}
	policy := workerProjectionPolicy{SchemaVersion: 1, ProfileSHA256: f.pin.ExecutionProfileSHA256, PipelineMode: "stats", CapsuleKind: "native", SourcePins: map[string]capsuleSourcePin{}}
	for _, n := range []string{"pipeline", "resource_budget", "analysis_executable", "analysis_rules"} {
		policy.SourcePins[n] = capsuleSourcePin{SHA256: strings.Repeat("4", 64), Bytes: 1}
	}
	policyRaw, e := json.Marshal(policy)
	if e != nil {
		t.Fatal(e)
	}
	policyPath := filepath.Join(f.root, "projection.json")
	if e = os.WriteFile(policyPath, policyRaw, 0600); e != nil {
		t.Fatal(e)
	}
	c := ownerWorkerConfig{SchemaVersion: 1, Protocol: "owner-v1", Socket: filepath.Join(f.root, "socket", "broker.sock"), JobsDirectory: filepath.Join(f.root, "jobs"), UploadsDirectory: f.uploads, AcceptancesDirectory: filepath.Join(f.root, "acceptances"), ResultsDirectory: filepath.Join(f.root, "results"), StageDirectory: filepath.Join(f.root, "stage"), CustodyDirectory: filepath.Join(f.root, "custody-new"), AuthorityID: f.trust.AuthorityID, PublicKeyHex: f.trust.PublicKeyHex, PipelineMode: f.trust.PipelineMode, ExecutionProfileSHA256: f.trust.ProfileSHA256, ExpectedScope: f.scope, DecryptionKey: ownerWorkerAsset{keyPath, workerCustodyDigest(keyRaw)}, ProjectionPolicy: ownerWorkerAsset{policyPath, workerCustodyDigest(policyRaw)}, PollMilliseconds: 100, TimeoutSeconds: 10}
	path := filepath.Join(f.root, "worker.json")
	writeOwnerWorkerConfigFixture(t, path, c)
	return f, c, path
}
func writeOwnerWorkerConfigFixture(t *testing.T, path string, c ownerWorkerConfig) {
	t.Helper()
	raw, e := json.Marshal(c)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
}
func TestOwnerWorkerConfigPinsExactParsedMaterialAndClosedShape(t *testing.T) {
	f, c, path := ownerWorkerConfigFixture(t)
	m, e := loadOwnerWorkerConfig(context.Background(), path)
	if e != nil || m.key.N.Cmp(f.workerKey.N) != 0 || m.trust.Scope != f.scope || m.policy.ProfileSHA256 != f.pin.ExecutionProfileSHA256 {
		t.Fatal("valid config/material control failed", e)
	}
	if _, e = os.Stat(c.CustodyDirectory); !os.IsNotExist(e) {
		t.Fatal("load created custody")
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	bad := [][]byte{append(append([]byte(nil), raw...), []byte(" {}")...), bytes.Replace(raw, []byte(`"protocol":"owner-v1"`), []byte(`"protocol":"owner-v1","protocol":"owner-v1"`), 1), bytes.Replace(raw, []byte(`"protocol"`), []byte(`"Protocol"`), 1), bytes.Replace(raw, []byte(`"timeout_seconds":10`), []byte(`"timeout_seconds":null`), 1), bytes.Replace(raw, []byte(`"schema_version":1`), []byte(`"schema_version":1,"unknown":0`), 1)}
	for i, v := range bad {
		if e = os.WriteFile(path, v, 0600); e != nil {
			t.Fatal(e)
		}
		if _, e = loadOwnerWorkerConfig(context.Background(), path); e == nil {
			t.Fatal("ambiguous config accepted", i)
		}
	}
	writeOwnerWorkerConfigFixture(t, path, c)
	if e = os.Chmod(path, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e = loadOwnerWorkerConfig(context.Background(), path); e == nil {
		t.Fatal("unsafe config accepted")
	}
}
func TestOwnerWorkerConfigRejectsChangedAssetScopeOverlapAndLimits(t *testing.T) {
	f, c, path := ownerWorkerConfigFixture(t)
	cases := map[string]func(*ownerWorkerConfig){
		"missing_scope":    func(c *ownerWorkerConfig) { c.ExpectedScope = ownerWorkerScope{} },
		"bad_pin":          func(c *ownerWorkerConfig) { c.PublicKeyHex = "00" },
		"mode":             func(c *ownerWorkerConfig) { c.PipelineMode = "other" },
		"old_protocol":     func(c *ownerWorkerConfig) { c.Protocol = "legacy" },
		"key_pin":          func(c *ownerWorkerConfig) { c.DecryptionKey.SHA256 = strings.Repeat("9", 64) },
		"projection_pin":   func(c *ownerWorkerConfig) { c.ProjectionPolicy.SHA256 = strings.Repeat("9", 64) },
		"overlap":          func(c *ownerWorkerConfig) { c.CustodyDirectory = c.UploadsDirectory },
		"nested_assets":    func(c *ownerWorkerConfig) { c.DecryptionKey.Path = filepath.Join(c.CustodyDirectory, "key") },
		"oversize_timeout": func(c *ownerWorkerConfig) { c.TimeoutSeconds = 601 },
		"tiny_poll":        func(c *ownerWorkerConfig) { c.PollMilliseconds = 1 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			v := c
			mutate(&v)
			writeOwnerWorkerConfigFixture(t, path, v)
			if _, e := loadOwnerWorkerConfig(context.Background(), path); e == nil || strings.Contains(e.Error(), f.root) {
				t.Fatal("unsafe config admitted or path exposed", e)
			}
			if _, e := os.Stat(c.CustodyDirectory); !os.IsNotExist(e) {
				t.Fatal("negative config initialized custody")
			}
		})
	}
}
func TestOwnerWorkerRuntimeGenesisIsExplicitAndCannotBeRepeated(t *testing.T) {
	_, c, path := ownerWorkerConfigFixture(t)
	var out, stderr bytes.Buffer
	code, b := runOwnerWorker(context.Background(), path, []string{"--init-owner-worker"}, &out, &stderr)
	if code != 0 || b != nil || out.String() != "{\"schema_version\":1,\"state\":\"initialized\"}\n" || stderr.Len() != 0 {
		t.Fatal("explicit worker genesis failed", code, stderr.String())
	}
	before, e := os.ReadFile(filepath.Join(c.CustodyDirectory, "journal.json"))
	if e != nil {
		t.Fatal(e)
	}
	out.Reset()
	stderr.Reset()
	code, b = runOwnerWorker(context.Background(), path, []string{"--init-owner-worker"}, &out, &stderr)
	if code == 0 || out.Len() != 0 {
		t.Fatal("reinitialization adopted history")
	}
	if b != nil && b.custody != nil {
		_ = b.custody.Close()
	}
	after, e := os.ReadFile(filepath.Join(c.CustodyDirectory, "journal.json"))
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("failed genesis changed existing history")
	}
}
func TestOwnerWorkerSelectorPrecedesLegacyRuntimeAndFailsClosed(t *testing.T) {
	dir := t.TempDir()
	legacy := filepath.Join(dir, "must-not-create")
	t.Setenv("BIOZERO_DATA_DIR", legacy)
	t.Setenv("BIOZERO_OWNER_WORKER_CONFIG", "")
	t.Setenv("BIOZERO_WORKER_PROTOCOL", "unexpected")
	if e := runWorker(); e == nil {
		t.Fatal("unknown protocol entered legacy")
	}
	if _, e := os.Stat(legacy); !os.IsNotExist(e) {
		t.Fatal("unknown protocol created legacy state")
	}
	t.Setenv("BIOZERO_WORKER_PROTOCOL", "legacy")
	t.Setenv("BIOZERO_OWNER_WORKER_CONFIG", filepath.Join(dir, "missing.json"))
	if handled, e := runOwnerWorkerSelected(); !handled || e == nil {
		t.Fatal("mixed owner configuration entered legacy")
	}
	t.Setenv("BIOZERO_WORKER_PROTOCOL", "owner-v1")
	if e := runWorker(); e == nil {
		t.Fatal("invalid owner config fell back")
	}
	if _, e := os.Stat(legacy); !os.IsNotExist(e) {
		t.Fatal("owner error created legacy state")
	}
}

func TestOwnerWorkerLauncherStageSelectionRejectsBeforeCustody(t *testing.T) {
	_, c, path := ownerWorkerConfigFixture(t)
	m, e := loadOwnerWorkerConfig(context.Background(), path)
	if e != nil {
		t.Fatal(e)
	}
	t.Setenv("BIOZERO_DECRYPT_DIR", filepath.Join(filepath.Dir(c.StageDirectory), "different-stage"))
	b, e := newOwnerWorkerBackend(context.Background(), m)
	if b != nil || e == nil || e.Error() != "owner_worker_stage_selection_invalid" {
		t.Fatal("launcher/config staging mismatch reached filesystem or custody", e)
	}
	if _, e := os.Stat(c.CustodyDirectory); !os.IsNotExist(e) {
		t.Fatal("stage mismatch created custody")
	}
}
