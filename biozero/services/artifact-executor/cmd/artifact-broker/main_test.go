//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	artifact "biozero/artifact-executor"
)

func commandConfig(t *testing.T) (artifact.BrokerServiceConfig, string) {
	t.Helper()
	root := t.TempDir()
	assets := filepath.Join(root, "assets")
	if e := os.Mkdir(assets, 0700); e != nil {
		t.Fatal(e)
	}
	pin := func(name, content string, mode os.FileMode) artifact.BrokerServiceAsset {
		path := filepath.Join(assets, name)
		if e := os.WriteFile(path, []byte(content), mode); e != nil {
			t.Fatal(e)
		}
		sum := sha256.Sum256([]byte(content))
		return artifact.BrokerServiceAsset{Path: path, SHA256: hex.EncodeToString(sum[:])}
	}
	python, e := filepath.EvalSymlinks("/usr/bin/true")
	if e != nil {
		t.Fatal(e)
	}
	c := artifact.BrokerServiceConfig{SchemaVersion: 1, Provider: "native", Mode: "stats", StoreRoot: filepath.Join(root, "store"), JournalRoot: filepath.Join(root, "journal"), WorkspaceRoot: filepath.Join(root, "workspaces"), SocketPath: filepath.Join(root, "channel", "bridge.sock"), AllowedUID: uint32(os.Geteuid()), TimeoutSeconds: 60, PythonPath: python, ToolPath: "/usr/bin", DockerCommand: []string{}, NativeHelper: pin("native_capsule.py", "# synthetic, never executed\n", 0600), Pipeline: pin("pipeline.py", "# synthetic, never executed\n", 0600), ResourceBudget: pin("resource_budget.py", "# synthetic\n", 0600), AnalysisExecutable: pin("capsule-analysis", "synthetic executable fixture, never executed\n", 0700), AnalysisRules: pin("rules.json", "{}\n", 0600)}
	raw, e := json.Marshal(c)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(root, "service.json")
	if e = os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	return c, path
}
func TestProfileOnlyHasNoStateOrSecretOutput(t *testing.T) {
	c, path := commandConfig(t)
	var out, errout bytes.Buffer
	code, handle := run(context.Background(), []string{"--config", path, "--print-profile"}, &out, &errout)
	got := strings.TrimSuffix(out.String(), "\n")
	if code != 0 || handle != nil || len(got) != 64 || errout.Len() != 0 {
		t.Fatal("profile-only failed", code, errout.String())
	}
	if _, e := hex.DecodeString(got); e != nil {
		t.Fatal("nonidentifier profile")
	}
	for _, p := range []string{c.StoreRoot, c.JournalRoot, c.WorkspaceRoot, filepath.Dir(c.SocketPath)} {
		if _, e := os.Lstat(p); !errors.Is(e, os.ErrNotExist) {
			t.Fatal("profile-only created state", e)
		}
	}
	expected, e := artifact.BrokerServiceProfile(context.Background(), c)
	if e != nil || expected != got {
		t.Fatal("profile not reusable with actual executable", e)
	}
}
func TestCommandArgumentsAndPrivateConfigFailures(t *testing.T) {
	for _, args := range [][]string{{}, {"--unknown"}, {"--config", "relative"}, {"--config", "/private/missing/config.json", "extra"}} {
		var out, errout bytes.Buffer
		code, handle := run(context.Background(), args, &out, &errout)
		if code == 0 || handle != nil || out.Len() != 0 || strings.Contains(errout.String(), "/private/") {
			t.Fatal("invalid command exposed data or started service")
		}
	}
	_, path := commandConfig(t)
	if e := os.Chmod(path, 0644); e != nil {
		t.Fatal(e)
	}
	var out, errout bytes.Buffer
	code, handle := run(context.Background(), []string{"--config", path, "--print-profile"}, &out, &errout)
	if code != 1 || handle != nil || out.Len() != 0 || errout.String() != "artifact_service_config_invalid\n" {
		t.Fatal("unsafe config accepted or leaked path")
	}
}
