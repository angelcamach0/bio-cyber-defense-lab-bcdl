//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package ownership

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"
)

func TestClientOperationCheckBusyAndCorruption(t *testing.T) {
	x, cfg := operationFixture(t, "", false)
	op := operationOpen(t, cfg, true)
	t.Cleanup(func() {
		if op.rawHeld {
			_ = syscall.Close(op.rawFD)
			op.rawHeld = false
		}
		_ = op.root.Close()
		_ = op.lock.Close()
	})
	if err := op.Check(); err != nil {
		t.Fatal(err)
	}
	before := operationHistory(t, cfg.Directory)
	op.mu.Lock()
	start := time.Now()
	err := op.Check()
	op.mu.Unlock()
	if err == nil || err.Error() != "ownership_client_busy" || time.Since(start) > time.Second {
		t.Fatal("Check waited for operation mutex or misclassified busy", err)
	}
	if len(x.snapshot()) != 0 {
		t.Fatal("query-only Check performed HTTP")
	}
	after := operationHistory(t, cfg.Directory)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("Check changed retained journal bytes")
	}
	if err = os.WriteFile(filepath.Join(cfg.Directory, "00-intent.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = op.Check(); err == nil || !op.sticky {
		t.Fatal("changed custody accepted", err)
	}
	if reopened, err := OpenClientOperation(cfg); err == nil {
		_ = reopened.Close()
		t.Fatal("Check corruption released writer lock")
	}
}
func TestClientDeliveryCheckBusyAndCorruption(t *testing.T) {
	x, cfg := deliveryFixture(t)
	dir := filepath.Join(t.TempDir(), "delivery")
	d, err := CreateClientDelivery(context.Background(), dir, cfg, x.bundle)
	if err != nil {
		t.Fatal(err)
	}
	deliveryCleanup(t, d)
	if err = d.Check(); err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	start := time.Now()
	err = d.Check()
	d.mu.Unlock()
	if err == nil || err.Error() != "ownership_delivery_busy" || time.Since(start) > time.Second {
		t.Fatal("Check waited for delivery mutex or misclassified busy", err)
	}
	posts, gets := x.counts()
	if posts != 0 || gets != 0 {
		t.Fatal("Check performed upload or recovery HTTP")
	}
	if err = os.WriteFile(filepath.Join(dir, "ciphertext.bin"), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = d.Check(); err == nil || !d.sticky {
		t.Fatal("changed delivery custody accepted", err)
	}
	if reopened, err := OpenClientDelivery(context.Background(), dir, cfg); err == nil {
		_ = reopened.Close()
		t.Fatal("Check corruption released writer lock")
	}
}
