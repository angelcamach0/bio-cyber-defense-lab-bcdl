//go:build linux

package artifactexecutor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func serviceFixtureConfig(t *testing.T) (BrokerServiceConfig, string) {
	t.Helper()
	root := t.TempDir()
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	assets := filepath.Join(root, "assets")
	if e := os.Mkdir(assets, 0700); e != nil {
		t.Fatal(e)
	}
	asset := func(name, content string, mode os.FileMode) BrokerServiceAsset {
		path := filepath.Join(assets, name)
		if e := os.WriteFile(path, []byte(content), mode); e != nil {
			t.Fatal(e)
		}
		return BrokerServiceAsset{path, digest([]byte(content))}
	}
	python, e := filepath.EvalSymlinks("/usr/bin/true")
	if e != nil {
		t.Fatal(e)
	}
	c := BrokerServiceConfig{SchemaVersion: 1, Provider: "native", Mode: "stats", StoreRoot: filepath.Join(root, "store"), JournalRoot: filepath.Join(root, "journal"), WorkspaceRoot: filepath.Join(root, "workspaces"), SocketPath: filepath.Join(root, "channel", "bridge.sock"), AllowedUID: uint32(os.Geteuid()), TimeoutSeconds: 60, PythonPath: python, ToolPath: "/usr/bin", DockerCommand: []string{}, NativeHelper: asset("native_capsule.py", "# synthetic helper, not executed\n", 0600), Pipeline: asset("pipeline.py", "# synthetic pipeline, not executed\n", 0600), ResourceBudget: asset("resource_budget.py", "# synthetic budget\n", 0600), AnalysisExecutable: asset("capsule-analysis", "synthetic executable fixture, not executed\n", 0700), AnalysisRules: asset("rules.json", "{}\n", 0600)}
	path := filepath.Join(root, "service.json")
	raw, _ := json.Marshal(c)
	if e = os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	return c, path
}
func assertServiceNoState(t *testing.T, c BrokerServiceConfig) {
	t.Helper()
	for _, p := range []string{c.StoreRoot, c.JournalRoot, c.WorkspaceRoot, filepath.Dir(c.SocketPath)} {
		if _, e := os.Lstat(p); !errors.Is(e, os.ErrNotExist) {
			t.Fatalf("state created before validated start: %v", e)
		}
	}
}

func TestBrokerServicePrivateStrictConfigAndProfile(t *testing.T) {
	c, path := serviceFixtureConfig(t)
	loaded, e := LoadBrokerServiceConfig(context.Background(), path)
	if e != nil {
		t.Fatal(e)
	}
	p, e := BrokerServiceProfile(context.Background(), loaded)
	if e != nil || !hexID(p, 64) {
		t.Fatal("profile failed", e)
	}
	again, e := BrokerServiceProfile(context.Background(), loaded)
	if e != nil || again != p {
		t.Fatal("profile nondeterministic", e)
	}
	changed := loaded
	changed.AllowedUID = 0
	zero, e := BrokerServiceProfile(context.Background(), changed)
	if e != nil {
		t.Fatal("explicit UID zero rejected", e)
	}
	if changed.AllowedUID != loaded.AllowedUID && zero == p {
		t.Fatal("peer identity absent from profile")
	}
	changed.TimeoutSeconds++
	next, e := BrokerServiceProfile(context.Background(), changed)
	if e != nil || next == zero {
		t.Fatal("timeout absent from profile", e)
	}
	assertServiceNoState(t, c)
	raw, _ := json.Marshal(c)
	for name, change := range map[string]func(map[string]any){
		"missing_uid": func(m map[string]any) { delete(m, "allowed_uid") }, "null_uid": func(m map[string]any) { m["allowed_uid"] = nil }, "negative_uid": func(m map[string]any) { m["allowed_uid"] = -1 }, "unknown": func(m map[string]any) { m["policy"] = "relaxed" }, "null_asset": func(m map[string]any) { m["pipeline"] = nil }, "missing_pin": func(m map[string]any) { delete(m["pipeline"].(map[string]any), "sha256") }, "null_array": func(m map[string]any) { m["docker_command"] = nil }, "version": func(m map[string]any) { m["schema_version"] = 2 },
	} {
		t.Run(name, func(t *testing.T) {
			var m map[string]any
			json.Unmarshal(raw, &m)
			change(m)
			data, _ := json.Marshal(m)
			if e := os.WriteFile(path, data, 0600); e != nil {
				t.Fatal(e)
			}
			if _, e := LoadBrokerServiceConfig(context.Background(), path); e == nil {
				t.Fatal("invalid config accepted")
			}
			assertServiceNoState(t, c)
		})
	}
	if e = os.WriteFile(path, bytes.Replace(raw, []byte(`"allowed_uid":`), []byte(`"allowed_uid":0,"allowed_uid":`), 1), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = LoadBrokerServiceConfig(context.Background(), path); e == nil {
		t.Fatal("duplicate UID accepted")
	}
}

func TestBrokerServiceRejectsUnsafeConfigurationFiles(t *testing.T) {
	for _, kind := range []string{"mode", "hardlink", "symlink", "ancestor_symlink", "oversized", "invalid_utf8"} {
		t.Run(kind, func(t *testing.T) {
			c, path := serviceFixtureConfig(t)
			switch kind {
			case "mode":
				os.Chmod(path, 0640)
			case "hardlink":
				if e := os.Link(path, path+".link"); e != nil {
					t.Fatal(e)
				}
			case "symlink":
				if e := os.Symlink(path, path+".symlink"); e != nil {
					t.Fatal(e)
				}
				path += ".symlink"
			case "ancestor_symlink":
				alias := filepath.Join(t.TempDir(), "alias")
				if e := os.Symlink(filepath.Dir(path), alias); e != nil {
					t.Fatal(e)
				}
				path = filepath.Join(alias, filepath.Base(path))
			case "oversized":
				os.WriteFile(path, bytes.Repeat([]byte(" "), int(brokerServiceConfigLimit)+1), 0600)
			case "invalid_utf8":
				os.WriteFile(path, []byte{0xff}, 0600)
			}
			if _, e := LoadBrokerServiceConfig(context.Background(), path); e == nil {
				t.Fatal("unsafe config accepted")
			}
			assertServiceNoState(t, c)
		})
	}
}

func TestBrokerServiceAssetsRootsAndCompleteProfileBeforeProvider(t *testing.T) {
	for _, kind := range []string{"changed_pin", "missing_asset", "overlap", "resource_sibling", "analysis_panel_mismatch", "variants_without_evaluator", "stats_with_evaluator", "relative_root", "docker_command_in_native", "native_missing_analysis"} {
		t.Run(kind, func(t *testing.T) {
			c, _ := serviceFixtureConfig(t)
			switch kind {
			case "changed_pin":
				c.Pipeline.SHA256 = strings.Repeat("b", 64)
			case "missing_asset":
				c.Pipeline.Path = filepath.Join(filepath.Dir(c.Pipeline.Path), "missing", "pipeline.py")
			case "overlap":
				c.JournalRoot = filepath.Join(c.StoreRoot, "journal")
			case "resource_sibling":
				c.ResourceBudget.Path = filepath.Join(filepath.Dir(c.Pipeline.Path), "elsewhere.py")
			case "analysis_panel_mismatch":
				c.AnalysisPanel = c.Pipeline
			case "variants_without_evaluator":
				c.Mode = "variants"
				c.Reference = c.Pipeline
			case "stats_with_evaluator":
				c.Evaluator = c.Pipeline
				c.Truth = c.Pipeline
			case "relative_root":
				c.StoreRoot = "relative"
			case "docker_command_in_native":
				c.DockerCommand = []string{"/bin/sh"}
			case "native_missing_analysis":
				c.AnalysisExecutable = BrokerServiceAsset{}
			}
			called := false
			handle, e := openBrokerService(context.Background(), c, func(context.Context, BrokerServiceConfig) (Provider, func() error, error) {
				called = true
				return fixtureProvider(successfulFixtureProvider), func() error { return nil }, nil
			})
			if e == nil || handle != nil || called {
				t.Fatal("invalid config reached provider/socket", e)
			}
			assertServiceNoState(t, c)
		})
	}
}

func TestBrokerServiceRealSocketCustodyAndHealthyShutdown(t *testing.T) {
	c, _ := serviceFixtureConfig(t)
	var calls, closed atomic.Int32
	provider := fixtureProvider(func(ctx context.Context, in *ScopedInput, out *Exporter) ProviderCompletion {
		calls.Add(1)
		if in.AnalysisContext == nil {
			t.Error("facts missing")
		}
		receipt := []byte(`{"synthetic":true}`)
		if _, e := in.CopyTo(ctx, io.Discard); e != nil {
			return ProviderCompletion{Quiescent: true, Err: e}
		}
		if e := out.Export("execution_receipt", digest(receipt), bytes.NewReader(receipt)); e != nil {
			return ProviderCompletion{Quiescent: true, Err: e}
		}
		return ProviderCompletion{Quiescent: true, Outcome: Outcome{ExecutionStatus: "succeeded", ReleaseStatus: "unassessed"}}
	})
	service, e := openBrokerService(context.Background(), c, func(context.Context, BrokerServiceConfig) (Provider, func() error, error) {
		return provider, func() error { closed.Add(1); return nil }, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ended := make(chan error, 1)
	go func() { ended <- service.Serve(ctx) }()
	defer cancel()
	data := []byte("synthetic verified plaintext")
	input := bridgeTestFile(t, data)
	q := BridgeRequestV2{SchemaVersion: 2, Operation: "submit", JobID: strings.Repeat("a", 16), UploadSHA256: digest([]byte("original ciphertext placeholder")), ExpectedProfileSHA256: service.ProfileSHA256(), ProcessedSHA256: digest(data), ProcessedBytes: int64(len(data)), OriginalName: "synthetic.fastq", AnalysisContext: AnalysisContext{OriginalName: "synthetic.fastq", ProcessedSizeBytes: int64(len(data)), Decrypted: true, SignatureValid: true}}
	response, fd, e := CallBridgeUnixV2(context.Background(), c.SocketPath, q, input)
	if e != nil || fd != nil || response.State != "committed" || response.ErrorCode != "" {
		t.Fatal("service submit failed", e)
	}
	r, fd, e := CallBridgeUnixV2(context.Background(), c.SocketPath, brokerQueryV2(q, "receipt"), nil)
	if e != nil || fd == nil {
		t.Fatal("service receipt failed", e)
	}
	raw, e := io.ReadAll(fd)
	fd.Close()
	if e != nil || digest(raw) != r.ReceiptSHA256 {
		t.Fatal("receipt bytes")
	}
	stopCtx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if e = service.Shutdown(stopCtx); e != nil {
		t.Fatal(e)
	}
	if e = <-ended; e != nil {
		t.Fatal(e)
	}
	if calls.Load() != 1 || closed.Load() != 1 || !service.closed {
		t.Fatal("healthy lifetime not closed exactly once")
	}
	if _, e = os.Lstat(c.SocketPath); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("socket survives shutdown", e)
	}
	if e = service.Shutdown(stopCtx); e != nil || closed.Load() != 1 {
		t.Fatal("nonidempotent shutdown")
	}
	// Exact committed history reopens under the same executable/config profile,
	// rather than being removed or adopted as a fresh budget.
	reopened, e := openBrokerService(context.Background(), c, func(context.Context, BrokerServiceConfig) (Provider, func() error, error) {
		return fixtureProvider(func(context.Context, *ScopedInput, *Exporter) ProviderCompletion {
			t.Fatal("restart reran provider")
			return ProviderCompletion{}
		}), func() error { return nil }, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	if reopened.ProfileSHA256() != service.ProfileSHA256() || reopened.store.Snapshot().RetainedOrReservedJobs != 1 {
		t.Fatal("restart lost profile/history")
	}
	if e = reopened.Shutdown(stopCtx); e != nil {
		t.Fatal(e)
	}
}

func TestBrokerServiceUncertaintyRetainsAuthorityAndHistory(t *testing.T) {
	c, _ := serviceFixtureConfig(t)
	var closed atomic.Int32
	service, e := openBrokerService(context.Background(), c, func(context.Context, BrokerServiceConfig) (Provider, func() error, error) {
		return fixtureProvider(func(context.Context, *ScopedInput, *Exporter) ProviderCompletion {
			return ProviderCompletion{Quiescent: false, Err: errors.New("synthetic uncertainty")}
		}), func() error { closed.Add(1); return nil }, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	// Fake-provider process-ending cleanup only: never use this to release real
	// uncertain capsule authority or modify historical accounting.
	defer func() {
		service.server.Close()
		service.registry.Close()
		service.broker.lock.Close()
		service.broker.root.Close()
		service.store.Close()
	}()
	data := []byte("synthetic uncertainty input")
	input := bridgeTestFile(t, data)
	q := BridgeRequestV2{2, "submit", strings.Repeat("a", 16), digest([]byte("original ciphertext")), service.ProfileSHA256(), digest(data), int64(len(data)), "synthetic.fastq", AnalysisContext{OriginalName: "synthetic.fastq", ProcessedSizeBytes: int64(len(data)), Decrypted: true, SignatureValid: true}}
	if _, _, e = service.broker.HandleBridgeV2(context.Background(), q, input); e == nil {
		t.Fatal("uncertain completion accepted")
	}
	before := brokerRead(t, filepath.Join(c.StoreRoot, "ledger.json"))
	journal := brokerRead(t, filepath.Join(c.JournalRoot, "journal.json"))
	charge := service.store.Snapshot().ChargedBytes
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if e = service.Shutdown(ctx); e == nil || closed.Load() != 0 || service.closed {
		t.Fatal("uncertain shutdown released authority")
	}
	if _, e = service.broker.lock.Stat(); e != nil {
		t.Fatal("journal lock released")
	}
	if _, e = service.store.lock.Stat(); e != nil {
		t.Fatal("store lock released")
	}
	if charge <= 0 || service.store.Snapshot().ChargedBytes != charge || !bytes.Equal(before, brokerRead(t, filepath.Join(c.StoreRoot, "ledger.json"))) || !bytes.Equal(journal, brokerRead(t, filepath.Join(c.JournalRoot, "journal.json"))) {
		t.Fatal("uncertainty changed charge/history")
	}
}

func TestBrokerServicePythonMetadataWithoutExecution(t *testing.T) {
	for _, kind := range []string{"non_executable", "writable", "special_mode", "fifo", "directory", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			c, _ := serviceFixtureConfig(t)
			path := filepath.Join(filepath.Dir(c.NativeHelper.Path), "python-fixture")
			switch kind {
			case "fifo":
				if e := syscall.Mkfifo(path, 0600); e != nil {
					t.Fatal(e)
				}
			case "directory":
				if e := os.Mkdir(path, 0700); e != nil {
					t.Fatal(e)
				}
			case "symlink":
				if e := os.Symlink(c.PythonPath, path); e != nil {
					t.Fatal(e)
				}
			default:
				mode := os.FileMode(0600)
				if kind == "writable" {
					mode = 0720
				}
				if e := os.WriteFile(path, []byte("not executed\n"), mode); e != nil {
					t.Fatal(e)
				}
				if e := os.Chmod(path, mode); e != nil {
					t.Fatal(e)
				}
				if kind == "special_mode" {
					if e := os.Chmod(path, 0700|os.ModeSetuid); e != nil {
						t.Fatal(e)
					}
				}
			}
			c.PythonPath = path
			if _, e := BrokerServiceProfile(context.Background(), c); e == nil {
				t.Fatal("unsafe interpreter metadata accepted")
			}
			assertServiceNoState(t, c)
		})
	}
}

func TestBrokerServiceSocketCleanupErrorsPersistAcrossShutdown(t *testing.T) {
	for _, lifecycle := range []string{"cancel_serve", "direct_shutdown"} {
		for _, tamper := range []string{"replacement", "unsafe_mode"} {
			t.Run(lifecycle+"/"+tamper, func(t *testing.T) {
				c, _ := serviceFixtureConfig(t)
				var closed atomic.Int32
				service, e := openBrokerService(context.Background(), c, func(context.Context, BrokerServiceConfig) (Provider, func() error, error) {
					return fixtureProvider(successfulFixtureProvider), func() error { closed.Add(1); return nil }, nil
				})
				if e != nil {
					t.Fatal(e)
				}
				// Synthetic idle fixture only; defensive cleanup does not alter journal or
				// ledger contents and never deletes the replacement/unsafe socket evidence.
				defer func() {
					service.server.Close()
					service.registry.Close()
					service.broker.lock.Close()
					service.broker.root.Close()
					service.store.Close()
				}()
				var cancel context.CancelFunc
				var ended chan error
				if lifecycle == "cancel_serve" {
					ctx, stop := context.WithCancel(context.Background())
					cancel = stop
					defer stop()
					ended = make(chan error, 1)
					go func() { ended <- service.Serve(ctx) }()
					until := time.Now().Add(time.Second)
					for {
						service.server.base.mu.Lock()
						started := service.server.base.started
						service.server.base.mu.Unlock()
						if started {
							break
						}
						if time.Now().After(until) {
							t.Fatal("service Serve not started")
						}
						time.Sleep(time.Millisecond)
					}
				}
				if tamper == "replacement" {
					if e = os.Remove(c.SocketPath); e != nil {
						t.Fatal(e)
					}
					if e = os.WriteFile(c.SocketPath, []byte("preserve replacement evidence\n"), 0600); e != nil {
						t.Fatal(e)
					}
				} else {
					if e = os.Chmod(c.SocketPath, 0644); e != nil {
						t.Fatal(e)
					}
				}
				beforeLedger := brokerRead(t, filepath.Join(c.StoreRoot, "ledger.json"))
				beforeJournal := brokerRead(t, filepath.Join(c.JournalRoot, "journal.json"))
				if cancel != nil {
					cancel()
					select {
					case e := <-ended:
						if e != nil {
							t.Fatal(e)
						}
					case <-time.After(time.Second):
						t.Fatal("cancelled service did not stop")
					}
				}
				ctx, stop := context.WithTimeout(context.Background(), time.Second)
				defer stop()
				if e = service.Shutdown(ctx); e == nil || e.Error() != "artifact_socket_changed" {
					t.Fatal("socket cleanup error lost", e)
				}
				if !service.closed || closed.Load() != 1 || !service.broker.released || !service.registry.closed || !service.store.closed {
					t.Fatal("cleanup error bypassed healthy custody completion")
				}
				if again := service.Shutdown(ctx); again == nil || again.Error() != e.Error() || closed.Load() != 1 {
					t.Fatal("repeated shutdown hid failure or closed twice", again)
				}
				if !bytes.Equal(beforeLedger, brokerRead(t, filepath.Join(c.StoreRoot, "ledger.json"))) || !bytes.Equal(beforeJournal, brokerRead(t, filepath.Join(c.JournalRoot, "journal.json"))) {
					t.Fatal("socket failure rolled back durable history")
				}
				if tamper == "replacement" {
					if !bytes.Equal(brokerRead(t, c.SocketPath), []byte("preserve replacement evidence\n")) {
						t.Fatal("replacement changed/deleted")
					}
				} else {
					info, e := os.Lstat(c.SocketPath)
					if e != nil || info.Mode().Perm() != 0644 || info.Mode()&os.ModeSocket == 0 {
						t.Fatal("unsafe socket evidence repaired/deleted", e)
					}
				}
			})
		}
	}
}

func TestBrokerServiceCleanupErrorStillCancelsAndWaitsForProvider(t *testing.T) {
	c, _ := serviceFixtureConfig(t)
	started, cancelled := make(chan struct{}), make(chan struct{})
	var closed atomic.Int32
	provider := fixtureProvider(func(ctx context.Context, in *ScopedInput, out *Exporter) ProviderCompletion {
		close(started)
		<-ctx.Done()
		close(cancelled)
		return ProviderCompletion{Quiescent: true, Outcome: Outcome{ExecutionStatus: "failed", ReleaseStatus: "withheld", ErrorCode: "synthetic_cancelled"}}
	})
	service, e := openBrokerService(context.Background(), c, func(context.Context, BrokerServiceConfig) (Provider, func() error, error) {
		return provider, func() error { closed.Add(1); return nil }, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		service.server.Close()
		service.registry.Close()
		service.broker.lock.Close()
		service.broker.root.Close()
		service.store.Close()
	}()
	data := []byte("synthetic active cancellation")
	input := bridgeTestFile(t, data)
	q := BridgeRequestV2{2, "submit", strings.Repeat("a", 16), digest([]byte("original ciphertext")), service.ProfileSHA256(), digest(data), int64(len(data)), "synthetic.fastq", AnalysisContext{OriginalName: "synthetic.fastq", ProcessedSizeBytes: int64(len(data)), Decrypted: true, SignatureValid: true}}
	submitted := make(chan error, 1)
	go func() { _, _, e := service.broker.HandleBridgeV2(context.Background(), q, input); submitted <- e }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("provider did not start")
	}
	if e = os.Chmod(c.SocketPath, 0644); e != nil {
		t.Fatal(e)
	}
	ctx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if e = service.Shutdown(ctx); e == nil || e.Error() != "artifact_socket_changed" {
		t.Fatal("cleanup failure lost", e)
	}
	select {
	case <-cancelled:
	default:
		t.Fatal("socket error bypassed provider cancellation")
	}
	select {
	case <-submitted:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not wait for active handler")
	}
	if !service.closed || closed.Load() != 1 || service.store.Snapshot().RetainedOrReservedJobs != 1 || service.store.Snapshot().ChargedBytes <= 0 {
		t.Fatal("active cancellation did not retain accounting and close proven custody")
	}
	raw := brokerRead(t, filepath.Join(c.StoreRoot, "ledger.json"))
	var history ledger
	if strictJSON(raw, &history) != nil || len(history.Records) != 1 {
		t.Fatal("cancellation lost history")
	}
	for _, record := range history.Records {
		if record.State != "committed" || record.Charge <= 0 {
			t.Fatal("cancellation fabricated rollback/release")
		}
	}
}
