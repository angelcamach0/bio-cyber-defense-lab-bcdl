//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package artifactexecutor

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	ownership "biozero/ownership-authority"
)

func ownerReadServiceFixture(t *testing.T) (OwnerReadBrokerServiceConfig, string) {
	t.Helper()
	owner, path := ownerServiceTestConfig(t)
	sockets, err := os.MkdirTemp("/tmp", "bz-reads-")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(sockets, 0700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(sockets) })
	owner.Execution.SocketPath = filepath.Join(sockets, "w", "w.sock")
	c := OwnerReadBrokerServiceConfig{1, owner, OwnerReaderServiceConfig{filepath.Join(sockets, "r", "r.sock"), uint32(os.Geteuid())}}
	raw, _ := json.Marshal(c)
	if e := os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	return c, path
}
func TestOwnerReadServiceProfileStrictShapeAndFreshHistory(t *testing.T) {
	c, path := ownerReadServiceFixture(t)
	loaded, e := LoadOwnerReadBrokerServiceConfig(context.Background(), path)
	if e != nil {
		t.Fatal(e)
	}
	first, e := OwnerReadBrokerServiceProfile(context.Background(), loaded)
	if e != nil {
		t.Fatal(e)
	}
	other := loaded
	other.Owner.ExpectedScope = ownership.AcceptanceScope{}
	second, e := OwnerReadBrokerServiceProfile(context.Background(), other)
	if e != nil || second != first {
		t.Fatal("scope hash cycle", e)
	}
	other = loaded
	other.Reader.SocketPath = filepath.Join(filepath.Dir(other.Reader.SocketPath), "other.sock")
	second, e = OwnerReadBrokerServiceProfile(context.Background(), other)
	if e != nil || second == first {
		t.Fatal("reader policy unsealed", e)
	}
	legacy, e := OwnerBrokerServiceProfile(context.Background(), c.Owner)
	if e != nil || legacy == first {
		t.Fatal("reader profile reused writer profile", e)
	}
	assertServiceNoState(t, c.Owner.Execution)
	if _, e = os.Lstat(filepath.Dir(c.Reader.SocketPath)); !os.IsNotExist(e) {
		t.Fatal("profile created reader state")
	}
	raw, _ := json.Marshal(c)
	for _, kind := range []string{"unknown", "missing_uid", "null_reader", "other_uid", "overlap", "legacy"} {
		t.Run(kind, func(t *testing.T) {
			var m map[string]any
			json.Unmarshal(raw, &m)
			switch kind {
			case "unknown":
				m["store_mount"] = "forbidden"
			case "missing_uid":
				delete(m["reader"].(map[string]any), "allowed_results_uid")
			case "null_reader":
				m["reader"] = nil
			case "other_uid":
				m["reader"].(map[string]any)["allowed_results_uid"] = float64(uint32(os.Geteuid()) + 1)
			case "overlap":
				m["reader"].(map[string]any)["socket_path"] = c.Owner.Execution.SocketPath
			case "legacy":
				m["schema_version"] = 2
			}
			bad, _ := json.Marshal(m)
			os.WriteFile(path, bad, 0600)
			if _, e := LoadOwnerReadBrokerServiceConfig(context.Background(), path); e == nil {
				t.Fatal("unsafe config admitted")
			}
			assertServiceNoState(t, c.Owner.Execution)
		})
	}
}
func TestOwnerReadServiceTwoListenersDrainAndCleanupError(t *testing.T) {
	for _, tamper := range []bool{false, true} {
		t.Run(map[bool]string{false: "healthy", true: "reader_socket_replaced"}[tamper], func(t *testing.T) {
			c, _ := ownerReadServiceFixture(t)
			initialized, e := InitializeOwnerReadBrokerService(context.Background(), c)
			if e != nil {
				t.Fatal(e)
			}
			if initialized.reader != nil || initialized.engine.server != nil {
				t.Fatal("init listening")
			}
			if e = initialized.Shutdown(context.Background()); e != nil {
				t.Fatal(e)
			}
			ledger := brokerRead(t, filepath.Join(c.Owner.Execution.StoreRoot, "ledger.json"))
			journal := brokerRead(t, filepath.Join(c.Owner.Execution.JournalRoot, "journal.json"))
			factory := func(context.Context, BrokerServiceConfig) (Provider, func() error, error) {
				return ownerInitializationProvider{}, func() error { return nil }, nil
			}
			s, e := openOwnerReadBrokerService(context.Background(), c, false, factory)
			if e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- s.Serve(ctx) }()
			deadline := time.Now().Add(2 * time.Second)
			for {
				s.reader.mu.Lock()
				readerStarted := s.reader.started
				s.reader.mu.Unlock()
				s.engine.server.base.mu.Lock()
				writerStarted := s.engine.server.base.started
				s.engine.server.base.mu.Unlock()
				if readerStarted && writerStarted {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("listeners not started")
				}
				time.Sleep(time.Millisecond)
			}
			marker := []byte("retained socket replacement evidence")
			if tamper {
				if e = os.Remove(c.Reader.SocketPath); e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(c.Reader.SocketPath, marker, 0600); e != nil {
					t.Fatal(e)
				}
			}
			cancel()
			budget, stop := context.WithTimeout(context.Background(), 3*time.Second)
			defer stop()
			shutdown := s.Shutdown(budget)
			serve := <-done
			if tamper {
				if shutdown == nil || serve == nil {
					t.Fatal("cleanup error lost", shutdown, serve)
				}
				if string(brokerRead(t, c.Reader.SocketPath)) != string(marker) {
					t.Fatal("replacement deleted")
				}
				if repeat := s.Shutdown(context.Background()); repeat == nil || repeat.Error() != shutdown.Error() {
					t.Fatal("repeat hid first close error")
				}
			} else if shutdown != nil || serve != nil {
				t.Fatal(shutdown, serve)
			}
			if !s.engine.closed || !s.closed {
				t.Fatal("healthy custody not released after drain")
			}
			if !reflect.DeepEqual(ledger, brokerRead(t, filepath.Join(c.Owner.Execution.StoreRoot, "ledger.json"))) || !reflect.DeepEqual(journal, brokerRead(t, filepath.Join(c.Owner.Execution.JournalRoot, "journal.json"))) {
				t.Fatal("cleanup changed history")
			}
			// A cleanup failure is not execution corruption: the same sealed history opens.
			reopened, e := openOwnerReadBrokerService(context.Background(), c, false, factory)
			if tamper { // Retained marker prevents listener publication; preserve it.
				if e == nil {
					reopened.Shutdown(context.Background())
					t.Fatal("marker overwritten")
				}
			} else {
				if e != nil {
					t.Fatal(e)
				}
				if e = reopened.Shutdown(context.Background()); e != nil {
					t.Fatal(e)
				}
			}
		})
	}
}

func TestOwnerReadServiceCloseBeforeServeGoroutinesDrains(t *testing.T) {
	c, _ := ownerReadServiceFixture(t)
	initialized, e := InitializeOwnerReadBrokerService(context.Background(), c)
	if e != nil {
		t.Fatal(e)
	}
	if e = initialized.Shutdown(context.Background()); e != nil {
		t.Fatal(e)
	}
	factory := func(context.Context, BrokerServiceConfig) (Provider, func() error, error) {
		return ownerInitializationProvider{}, func() error { return nil }, nil
	}
	s, e := openOwnerReadBrokerService(context.Background(), c, false, factory)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.closeListeners(); e != nil {
		t.Fatal(e)
	}
	if e = s.Serve(context.Background()); e != nil {
		t.Fatal("normal early close reported accept failure", e)
	}
	if e = s.Shutdown(context.Background()); e != nil {
		t.Fatal(e)
	}
}
