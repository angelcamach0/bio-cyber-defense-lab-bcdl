//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package artifactexecutor

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ownership "biozero/ownership-authority"
)

func ownerServiceTestConfig(t *testing.T) (OwnerBrokerServiceConfig, string) {
	t.Helper()
	engine, path := serviceFixtureConfig(t)
	ownerTestKeys(t)
	c := OwnerBrokerServiceConfig{SchemaVersion: 1, Execution: engine, AuthorityID: ownerTestPin.AuthorityID, PublicKeyHex: hex.EncodeToString(ownerTestPin.PublicKey), ExpectedScope: ownership.AcceptanceScope{StoreID: strings.Repeat("a", 32), PolicySHA256: strings.Repeat("b", 64)}}
	raw, _ := json.Marshal(c)
	if e := os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	return c, path
}
func TestOwnerBrokerServiceProfileScopeSeparationAndStrictConfig(t *testing.T) {
	c, path := ownerServiceTestConfig(t)
	loaded, e := LoadOwnerBrokerServiceConfig(context.Background(), path)
	if e != nil {
		t.Fatal(e)
	}
	first, e := OwnerBrokerServiceProfile(context.Background(), loaded)
	if e != nil || !hexID(first, 64) {
		t.Fatal(e)
	}
	changed := loaded
	changed.ExpectedScope = ownership.AcceptanceScope{}
	without, e := OwnerBrokerServiceProfile(context.Background(), changed)
	if e != nil || first != without {
		t.Fatal("scope entered profile hash cycle", e)
	}
	changed.AuthorityID = strings.Repeat("e", 32)
	other, e := OwnerBrokerServiceProfile(context.Background(), changed)
	if e != nil || other == first {
		t.Fatal("authority pin absent from profile", e)
	}
	assertServiceNoState(t, c.Execution)
	if s, e := InitializeOwnerBrokerService(context.Background(), OwnerBrokerServiceConfig{SchemaVersion: 1, Execution: c.Execution, AuthorityID: c.AuthorityID, PublicKeyHex: c.PublicKeyHex}); e == nil {
		if s != nil {
			s.Shutdown(context.Background())
		}
		t.Fatal("zero scope initialized")
	}
	assertServiceNoState(t, c.Execution)
	raw, _ := json.Marshal(c)
	for _, kind := range []string{"unknown", "missing_scope", "null_scope", "null_execution", "legacy"} {
		t.Run(kind, func(t *testing.T) {
			var m map[string]any
			json.Unmarshal(raw, &m)
			switch kind {
			case "unknown":
				m["decrypt_key"] = "forbidden"
			case "missing_scope":
				delete(m, "expected_scope")
			case "null_scope":
				m["expected_scope"] = nil
			case "null_execution":
				m["execution"] = nil
			case "legacy":
				m["schema_version"] = 2
			}
			bad, _ := json.Marshal(m)
			if e := os.WriteFile(path, bad, 0600); e != nil {
				t.Fatal(e)
			}
			if _, e := LoadOwnerBrokerServiceConfig(context.Background(), path); e == nil {
				t.Fatal("unsafe config accepted")
			}
			assertServiceNoState(t, c.Execution)
		})
	}
}
func TestOwnerBrokerServiceExplicitInitOpenAndCleanShutdown(t *testing.T) {
	c, _ := ownerServiceTestConfig(t)
	if s, e := OpenOwnerBrokerService(context.Background(), c); e == nil {
		if s != nil {
			s.Shutdown(context.Background())
		}
		t.Fatal("Open initialized missing history")
	}
	assertServiceNoState(t, c.Execution)
	initialized, e := InitializeOwnerBrokerService(context.Background(), c)
	if e != nil {
		t.Fatal(e)
	}
	if initialized.server != nil || initialized.broker.data.SchemaVersion != 3 || len(initialized.broker.owner.bindings) != 0 {
		t.Fatal("init served or adopted history")
	}
	if e = initialized.Shutdown(context.Background()); e != nil {
		t.Fatal(e)
	}
	ledger := brokerRead(t, filepath.Join(c.Execution.StoreRoot, "ledger.json"))
	journal := brokerRead(t, filepath.Join(c.Execution.JournalRoot, "journal.json"))
	if s, e := InitializeOwnerBrokerService(context.Background(), c); e == nil {
		if s != nil {
			s.Shutdown(context.Background())
		}
		t.Fatal("reinitialized existing roots")
	}
	if string(ledger) != string(brokerRead(t, filepath.Join(c.Execution.StoreRoot, "ledger.json"))) || string(journal) != string(brokerRead(t, filepath.Join(c.Execution.JournalRoot, "journal.json"))) {
		t.Fatal("initialization rewrote history")
	}
	factory := func(context.Context, BrokerServiceConfig) (Provider, func() error, error) {
		return ownerInitializationProvider{}, func() error { return nil }, nil
	}
	service, e := openOwnerBrokerService(context.Background(), c, false, factory)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.Serve(ctx) }()
	readyDeadline := time.Now().Add(time.Second)
	for {
		service.server.base.mu.Lock()
		started := service.server.base.started
		service.server.base.mu.Unlock()
		if started {
			break
		}
		if time.Now().After(readyDeadline) {
			t.Fatal("fixture server did not start")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	budget, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if e = service.Shutdown(budget); e != nil {
		t.Fatal(e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	if e = service.Shutdown(context.Background()); e != nil {
		t.Fatal("repeat shutdown changed result", e)
	}
	if string(ledger) != string(brokerRead(t, filepath.Join(c.Execution.StoreRoot, "ledger.json"))) || string(journal) != string(brokerRead(t, filepath.Join(c.Execution.JournalRoot, "journal.json"))) {
		t.Fatal("healthy restart changed history")
	}
}
func TestOwnerBrokerServiceMissingJournalDoesNotOpenStoreOrProvider(t *testing.T) {
	c, _ := ownerServiceTestConfig(t)
	initialized, e := InitializeOwnerBrokerService(context.Background(), c)
	if e != nil {
		t.Fatal(e)
	}
	if e = initialized.Shutdown(context.Background()); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(filepath.Join(c.Execution.JournalRoot, "journal.json"), filepath.Join(c.Execution.JournalRoot, "preserved-journal")); e != nil {
		t.Fatal(e)
	}
	called := false
	factory := func(context.Context, BrokerServiceConfig) (Provider, func() error, error) {
		called = true
		return ownerInitializationProvider{}, func() error { return nil }, nil
	}
	if service, e := openOwnerBrokerService(context.Background(), c, false, factory); e == nil || service != nil || called {
		t.Fatal("missing history opened runtime")
	}
	if _, e = os.Lstat(filepath.Join(c.Execution.JournalRoot, "journal.json")); !os.IsNotExist(e) {
		t.Fatal("missing journal recreated")
	}
}
