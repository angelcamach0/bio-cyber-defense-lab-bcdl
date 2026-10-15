//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package ownership

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// Tests use the existing real-mTLS/signed-acceptance fixture. The endpoint below
// is protocol instrumentation, not a production publisher or scientific result.
type publicationOperationEndpoint struct {
	mu          sync.Mutex
	mode        string
	expected    PublicationReceipt
	posts, gets int
	hook        func(*http.Request)
}

func publicationOperationFixture(t *testing.T) (*publicationOperationEndpoint, PublicationOperationConfig) {
	t.Helper()
	x := &publicationOperationEndpoint{}
	config, accepted, receipt := publicationClientFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		x.mu.Lock()
		if r.Method == http.MethodPost {
			x.posts++
		} else if r.Method == http.MethodGet {
			x.gets++
		} else {
			t.Error("unexpected method")
		}
		mode, expected, hook := x.mode, x.expected, x.hook
		x.mu.Unlock()
		if r.Method == http.MethodPost {
			if digest(body) != expected.AcceptanceSHA256 {
				t.Error("unverified/noncanonical publication body")
			}
		} else if len(body) != 0 {
			t.Error("GET carried a body")
		}
		if hook != nil {
			hook(r)
		}
		if mode == "drop" && r.Method == http.MethodPost {
			connection, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			connection.Close()
			return
		}
		if mode == "absent" {
			w.WriteHeader(404)
			return
		}
		if mode == "wrong_receipt" {
			expected.AcceptanceSHA256 = strings.Repeat("f", 64)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(expected)
	}))
	x.expected = receipt
	chain := fixture(t).stateA.VerifiedChains[0]
	return x, PublicationOperationConfig{Directory: filepath.Join(t.TempDir(), "publication"), Client: config, Acceptance: accepted,
		TrustSHA256: digest(chain[len(chain)-1].Raw)}
}

func (x *publicationOperationEndpoint) counts() (int, int) {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.posts, x.gets
}
func (x *publicationOperationEndpoint) set(mode string) { x.mu.Lock(); x.mode = mode; x.mu.Unlock() }

func publicationOperationCleanup(t *testing.T, o *PublicationOperation) {
	t.Helper()
	if o == nil {
		return
	}
	t.Cleanup(func() { publicationOperationSimulateExit(o) })
}

// Test-only release of the exact held descriptors models process exit. It is
// not evidence of actual SIGKILL recovery and never belongs to production code.
func publicationOperationSimulateExit(o *PublicationOperation) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.client.CloseIdleConnections()
	if o.root != nil {
		o.root.Close()
	}
	if o.lock != nil {
		o.lock.Close()
	}
	if o.rawHeld {
		syscall.Close(o.rawFD)
		o.rawHeld = false
	}
	o.closed = true
}

func publicationOperationCreate(t *testing.T, config PublicationOperationConfig) *PublicationOperation {
	t.Helper()
	o, err := CreatePublicationOperation(config)
	publicationOperationCleanup(t, o)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func publicationOperationHistory(t *testing.T, directory string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	result := map[string]string{}
	for _, entry := range entries {
		raw, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		result[entry.Name()] = digest(raw)
	}
	return result
}

func TestPublicationOperationDurableIntentAndPublishedIdempotence(t *testing.T) {
	x, config := publicationOperationFixture(t)
	o := publicationOperationCreate(t, config)
	before := publicationOperationHistory(t, config.Directory)
	if posts, gets := x.counts(); posts != 0 || gets != 0 || o.State() != "intent" || o.Check() != nil {
		t.Fatal("Create performed network")
	}
	if _, err := o.Receipt(); err == nil {
		t.Fatal("intent fabricated receipt")
	}
	x.mu.Lock()
	x.hook = func(r *http.Request) {
		if r.Method != http.MethodPost {
			return
		}
		raw, err := os.ReadFile(filepath.Join(config.Directory, "01-publishing.json"))
		var step publicationOperationStep
		_, markerErr := os.Lstat(filepath.Join(config.Directory, "publication.intent"))
		if err != nil || strictJSON(raw, &step, clientStepLimit) != nil || step.Sequence != 1 ||
			step.PreviousSHA256 != before["00-intent.json"] || step.AcceptanceJSON != string(config.Acceptance) || !os.IsNotExist(markerErr) {
			t.Error("actual POST preceded complete retained publishing intent")
		}
	}
	x.mu.Unlock()
	got, err := o.Publish(context.Background())
	if err != nil || got != x.expected || o.State() != "published" {
		t.Fatal("publish", err, got)
	}
	history := publicationOperationHistory(t, config.Directory)
	if len(history) != 4 || history["00-intent.json"] != before["00-intent.json"] {
		t.Fatal("immutable intent changed")
	}
	for _, read := range []func(context.Context) (PublicationReceipt, error){o.Publish, o.Recover} {
		if got, err := read(context.Background()); err != nil || got != x.expected {
			t.Fatal("published idempotence", err)
		}
	}
	if got, err := o.Receipt(); err != nil || got != x.expected {
		t.Fatal("retained receipt", err)
	}
	if posts, gets := x.counts(); posts != 1 || gets != 0 || !reflect.DeepEqual(history, publicationOperationHistory(t, config.Directory)) {
		t.Fatal("idempotent read mutated history/network")
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	cold, err := OpenPublicationOperation(config)
	publicationOperationCleanup(t, cold)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := cold.Publish(context.Background()); err != nil || got != x.expected {
		t.Fatal("cold published read", err)
	}
	if posts, gets := x.counts(); posts != 1 || gets != 0 || !reflect.DeepEqual(history, publicationOperationHistory(t, config.Directory)) {
		t.Fatal("cold Open/read performed network or wrote history")
	}
	if err := cold.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestPublicationOperationColdIntentNeverPostsAndContextIsExternal(t *testing.T) {
	x, config := publicationOperationFixture(t)
	o := publicationOperationCreate(t, config)
	history := publicationOperationHistory(t, config.Directory)
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	cold, err := OpenPublicationOperation(config)
	publicationOperationCleanup(t, cold)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cold.Publish(context.Background()); err == nil {
		t.Fatal("cold intent posted")
	}
	if _, err := cold.Recover(context.Background()); err == nil {
		t.Fatal("unattempted cold intent adopted remote history")
	}
	if posts, gets := x.counts(); posts != 0 || gets != 0 || !reflect.DeepEqual(history, publicationOperationHistory(t, config.Directory)) {
		t.Fatal("cold intent changed")
	}
	if err := cold.Close(); err != nil {
		t.Fatal(err)
	}
	bad := config
	bad.TrustSHA256 = strings.Repeat("f", 64)
	opened, err := OpenPublicationOperation(bad)
	publicationOperationCleanup(t, opened)
	if err == nil || !reflect.DeepEqual(history, publicationOperationHistory(t, config.Directory)) {
		t.Fatal("new CA trust adopted old intent")
	}
}

func TestPublicationOperationActualLostResponseOnlyKnownGetRecovery(t *testing.T) {
	x, config := publicationOperationFixture(t)
	o := publicationOperationCreate(t, config)
	x.set("drop")
	if _, err := o.Publish(context.Background()); err == nil || o.State() != "publishing" {
		t.Fatal("lost response fabricated ACK")
	}
	history := publicationOperationHistory(t, config.Directory)
	if _, err := o.Publish(context.Background()); err == nil {
		t.Fatal("uncertain POST automatically retried")
	}
	if posts, gets := x.counts(); posts != 1 || gets != 0 {
		t.Fatal("wrong request count", posts, gets)
	}
	if err := o.Close(); err == nil || !o.rawHeld {
		t.Fatal("uncertain Close released lock")
	}
	if _, err := OpenPublicationOperation(config); err == nil {
		t.Fatal("live uncertain writer was bypassed")
	}
	publicationOperationSimulateExit(o)
	cold, err := OpenPublicationOperation(config)
	publicationOperationCleanup(t, cold)
	if err != nil || cold.State() != "publishing" {
		t.Fatal("cold known intent", err)
	}
	if _, err := cold.Publish(context.Background()); err == nil {
		t.Fatal("cold uncertain operation reposted")
	}
	if posts, gets := x.counts(); posts != 1 || gets != 0 || !reflect.DeepEqual(history, publicationOperationHistory(t, config.Directory)) {
		t.Fatal("Open or rejected Publish mutated history")
	}
	x.set("absent")
	if _, err := cold.Recover(context.Background()); err == nil {
		t.Fatal("absence became publication")
	}
	if posts, gets := x.counts(); posts != 1 || gets != 1 || !reflect.DeepEqual(history, publicationOperationHistory(t, config.Directory)) {
		t.Fatal("absence allowed resend/history rewrite")
	}
	x.set("")
	if got, err := cold.Recover(context.Background()); err != nil || got != x.expected || cold.State() != "published" {
		t.Fatal("explicit GET recovery", err)
	}
	if posts, gets := x.counts(); posts != 1 || gets != 2 {
		t.Fatal("recovery sent mutation", posts, gets)
	}
	if err := cold.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestPublicationOperationChecksAreNonblockingAndStorageWinsCancellation(t *testing.T) {
	x, config := publicationOperationFixture(t)
	o := publicationOperationCreate(t, config)
	entered, release := make(chan struct{}), make(chan struct{})
	x.mu.Lock()
	x.hook = func(*http.Request) { close(entered); <-release }
	x.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := o.Publish(ctx); done <- err }()
	<-entered
	checked := make(chan error, 1)
	go func() { checked <- o.Check() }()
	select {
	case err := <-checked:
		if err == nil || err.Error() != "ownership_publication_operation_busy" {
			close(release)
			t.Fatal("Check inferred health", err)
		}
	case <-time.After(time.Second):
		close(release)
		t.Fatal("Check waited behind active upstream mutation")
	}
	if err := os.WriteFile(filepath.Join(config.Directory, "00-intent.json"), []byte("changed trusted custody"), 0600); err != nil {
		close(release)
		t.Fatal(err)
	}
	cancel()
	close(release)
	if err := <-done; err == nil || err.Error() != "ownership_publication_operation_uncertain" || !o.rawHeld {
		t.Fatal("cancellation hid trusted storage fault", err)
	}
	if err := o.Close(); err == nil || !o.rawHeld {
		t.Fatal("fault released lifetime lock")
	}
}

func TestPublicationOperationFaultPointsPreserveTornHistoryAndRawLock(t *testing.T) {
	for _, point := range []string{"file_sync", "marker_directory_sync", "directory_sync", "intent_unlink", "intent_directory_sync", "after_receipt"} {
		t.Run(point, func(t *testing.T) {
			x, config := publicationOperationFixture(t)
			o := publicationOperationCreate(t, config)
			o.fault = func(name string) error {
				if name == point || point == "after_receipt" && o.step.Sequence == 1 && name == "directory_sync" {
					return io.ErrUnexpectedEOF
				}
				return nil
			}
			if _, err := o.Publish(context.Background()); err == nil || !o.rawHeld || !o.sticky {
				t.Fatal("failed publication released uncertainty")
			}
			if posts, gets := x.counts(); gets != 0 || point == "after_receipt" && posts != 1 || point != "after_receipt" && posts != 0 {
				t.Fatal("fault ordering", posts, gets)
			}
			history := publicationOperationHistory(t, config.Directory)
			if err := o.Close(); err == nil || !o.rawHeld || !reflect.DeepEqual(history, publicationOperationHistory(t, config.Directory)) {
				t.Fatal("Close repaired/reset failed history")
			}
			if _, err := OpenPublicationOperation(config); err == nil {
				t.Fatal("raw lock lost")
			}
			publicationOperationSimulateExit(o)
			opened, err := OpenPublicationOperation(config)
			publicationOperationCleanup(t, opened)
			// After marker unlink and failed final sync, a complete01 may be
			// visible. It is known uncertainty and still cannot POST on Open.
			if err == nil {
				if point != "intent_directory_sync" || opened.State() != "publishing" {
					t.Fatal("partial history adopted", point)
				}
				if _, err := opened.Publish(context.Background()); err == nil {
					t.Fatal("cold history retried POST")
				}
			}
			if !reflect.DeepEqual(history, publicationOperationHistory(t, config.Directory)) {
				t.Fatal("Open changed failed history")
			}
		})
	}
}

func TestPublicationOperationImmutableFileIdentityAndClosedHistory(t *testing.T) {
	for _, kind := range []string{"same_bytes_new_inode", "mode", "hardlink", "symlink", "unknown", "receipt"} {
		t.Run(kind, func(t *testing.T) {
			_, config := publicationOperationFixture(t)
			o := publicationOperationCreate(t, config)
			if _, err := o.Publish(context.Background()); err != nil {
				t.Fatal(err)
			}
			name := filepath.Join(config.Directory, "00-intent.json")
			raw, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "same_bytes_new_inode":
				if err := os.Rename(name, filepath.Join(t.TempDir(), "prior")); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(name, raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "mode":
				if err := os.Chmod(name, 0640); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(name, filepath.Join(t.TempDir(), "link")); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Remove(name); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(t.TempDir(), "absent"), name); err != nil {
					t.Fatal(err)
				}
			case "unknown":
				if err := os.WriteFile(filepath.Join(config.Directory, "untrusted.extra"), nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "receipt":
				path := filepath.Join(config.Directory, "02-published.json")
				body, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				body = bytes.Replace(body, []byte(`"state":"published"`), []byte(`"state":"pending"`), 1)
				if err := os.WriteFile(path, body, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := o.Check(); err == nil || !o.sticky || !o.rawHeld {
				t.Fatal("changed custody accepted")
			}
			if _, err := o.Receipt(); err == nil {
				t.Fatal("cached receipt bypassed changed history")
			}
			if err := o.Close(); err == nil || !o.rawHeld {
				t.Fatal("faulted close released custody")
			}
		})
	}
}

func TestPublicationOperationWrongReceiptAndFirstCloseErrorPersist(t *testing.T) {
	x, config := publicationOperationFixture(t)
	o := publicationOperationCreate(t, config)
	x.set("wrong_receipt")
	if _, err := o.Publish(context.Background()); err == nil || o.State() != "publishing" {
		t.Fatal("wrong receipt accepted")
	}
	first := o.Close()
	if first == nil || !o.rawHeld {
		t.Fatal("unknown history was closed")
	}
	x.set("")
	if got, err := o.Recover(context.Background()); err != nil || got != x.expected {
		t.Fatal("known GET could not resolve receipt", err)
	}
	if err := o.Close(); err != first || !o.rawHeld {
		t.Fatal("first pending Close error disappeared")
	}
	if posts, gets := x.counts(); posts != 1 || gets != 1 {
		t.Fatal("wrong receipt triggered resend")
	}
}

func TestPublicationOperationInputValidationBeforeDirectoryAndCopies(t *testing.T) {
	_, config := publicationOperationFixture(t)
	for _, kind := range []string{"body", "trust", "scope", "relative"} {
		t.Run(kind, func(t *testing.T) {
			cfg := config
			cfg.Directory = filepath.Join(t.TempDir(), "new")
			switch kind {
			case "body":
				cfg.Acceptance = []byte(`{"record":null}`)
			case "trust":
				cfg.TrustSHA256 = "not a pin"
			case "scope":
				cfg.Client.ExpectedPublisherScope = PublicationScope{}
			case "relative":
				cfg.Directory = "relative"
			}
			if o, err := CreatePublicationOperation(cfg); err == nil || o != nil {
				t.Fatal("invalid trusted input accepted")
			}
			if kind != "relative" {
				if _, err := os.Lstat(cfg.Directory); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("invalid input touched directory", err)
				}
			}
		})
	}
	copyInput := append([]byte(nil), config.Acceptance...)
	config.Acceptance = copyInput
	o := publicationOperationCreate(t, config)
	copyInput[0] = '!'
	if _, err := o.Publish(context.Background()); err != nil {
		t.Fatal("caller acceptance alias changed retained bytes", err)
	}
}

func TestPublicationOperationCloseFailureRetainsRawLock(t *testing.T) {
	for _, point := range []string{"close_root", "close_lock", "close_raw"} {
		t.Run(point, func(t *testing.T) {
			_, config := publicationOperationFixture(t)
			o := publicationOperationCreate(t, config)
			var faults atomic.Int32
			o.fault = func(name string) error {
				if name == point {
					faults.Add(1)
					return io.ErrUnexpectedEOF
				}
				return nil
			}
			first := o.Close()
			if first == nil || !o.rawHeld {
				t.Fatal("close failure lost raw lock")
			}
			o.fault = nil
			if err := o.Close(); err != first || faults.Load() != 1 || !o.rawHeld {
				t.Fatal("first close error did not persist")
			}
			if _, err := OpenPublicationOperation(config); err == nil {
				t.Fatal("failed close allowed second writer")
			}
		})
	}
}

func TestPublicationOperationReadChecksPathAfterFDSnapshot(t *testing.T) {
	_, config := publicationOperationFixture(t)
	o := publicationOperationCreate(t, config)
	path := filepath.Join(config.Directory, "00-intent.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	oldPath := filepath.Join(t.TempDir(), "original")
	var replaced atomic.Bool
	o.fault = func(name string) error {
		if name != "read_path_guard" || !replaced.CompareAndSwap(false, true) {
			return nil
		}
		if err := os.Rename(path, oldPath); err != nil {
			return err
		}
		return os.WriteFile(path, raw, 0600)
	}
	// Calling the snapshot primitive directly isolates its pathname guard from
	// the operation's previously pinned inode comparison in preflight.
	if _, _, err := o.read("00-intent.json"); err == nil || !replaced.Load() {
		t.Fatal("same-byte pathname replacement during read was accepted")
	}
	o.fault = nil
	if err := o.Check(); err == nil || !o.rawHeld {
		t.Fatal("replacement did not fence custody")
	}
}

func TestPublicationOperationPreflightCloseErrorsFenceCustody(t *testing.T) {
	for _, point := range []string{"preflight_close_root", "preflight_close_lock"} {
		t.Run(point, func(t *testing.T) {
			_, config := publicationOperationFixture(t)
			o := publicationOperationCreate(t, config)
			o.fault = func(name string) error {
				if name == point {
					return io.ErrUnexpectedEOF
				}
				return nil
			}
			if err := o.Check(); err == nil || !o.sticky || !o.rawHeld {
				t.Fatal("trusted temporary-close error was ignored")
			}
			o.fault = nil
			if err := o.Close(); err == nil || !o.rawHeld {
				t.Fatal("close error released custody")
			}
		})
	}
}
