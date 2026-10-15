// SPDX-License-Identifier: AGPL-3.0-only
//go:build linux

package ownership

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func storeFixture(t *testing.T, policy StorePolicy) (*Store, StoreConfig) {
	t.Helper()
	f := fixture(t)
	cfg := StoreConfig{Directory: filepath.Join(t.TempDir(), "authority"), Namespace: "test-scope", Pin: f.pin, SigningKey: f.private, Policy: policy}
	s, err := CreateStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ExpectedScope = s.Scope()
	t.Cleanup(func() { s.Close() })
	return s, cfg
}
func storeRequest(n int) string { return fmt.Sprintf("%032x", n) }
func storeReserve(t *testing.T, s *Store, n int) SignedChallenge {
	t.Helper()
	f := fixture(t)
	ch, err := s.Reserve(&f.stateA, storeRequest(n), "sample.fastq", f.now)
	if err != nil {
		t.Fatal(err)
	}
	return ch
}
func storeManifest(t *testing.T, ch SignedChallenge, body []byte) ([]byte, []byte) {
	t.Helper()
	f := fixture(t)
	raw, _ := MarshalChallenge(ch)
	v, err := VerifyChallengeForClient(raw, f.pin, f.certA, f.now)
	if err != nil {
		t.Fatal(err)
	}
	m, err := SignManifest(f.keyA, f.certA, v, ManifestInput{digest(body), int64(len(body)), strings.Repeat("4", 64)})
	if err != nil {
		t.Fatal(err)
	}
	manifest, _ := MarshalManifest(m)
	return raw, manifest
}
func storeAccept(t *testing.T, s *Store, n int) (SignedChallenge, SignedAcceptance) {
	t.Helper()
	f := fixture(t)
	ch := storeReserve(t, s, n)
	body := bytes.Repeat([]byte("x"), 32)
	raw, manifest := storeManifest(t, ch, body)
	a, err := s.Finalize(context.Background(), &f.stateA, raw, manifest, bytes.NewReader(body), f.now)
	if err != nil {
		t.Fatal(err)
	}
	return ch, a
}
func fileBytes(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestStoreCreateOpenScopeAndHistoricalReplay(t *testing.T) {
	f := fixture(t)
	s, cfg := storeFixture(t, DefaultStorePolicy())
	ch, a := storeAccept(t, s, 1)
	scope := s.Scope()
	if scope.StoreID == "" || scope.PolicySHA256 == "" {
		t.Fatal("missing external genesis")
	}
	if _, err := CreateStore(StoreConfig{Directory: cfg.Directory, Namespace: cfg.Namespace, Pin: cfg.Pin, SigningKey: cfg.SigningKey, Policy: cfg.Policy}); err == nil {
		t.Fatal("existing directory adopted")
	}
	if _, err := OpenStore(cfg); err == nil {
		t.Fatal("flock failed to exclude second store")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	missing := cfg
	missing.ExpectedScope = AcceptanceScope{}
	if _, err := OpenStore(missing); err == nil {
		t.Fatal("implicit scope adoption")
	}
	wrong := cfg
	wrong.ExpectedScope.StoreID = strings.Repeat("f", 32)
	if _, err := OpenStore(wrong); err == nil {
		t.Fatal("different store accepted")
	}
	wrong = cfg
	wrong.Namespace = "another"
	if _, err := OpenStore(wrong); err == nil {
		t.Fatal("namespace changed")
	}
	wrong = cfg
	wrong.Policy.MaxJobs--
	if _, err := OpenStore(wrong); err == nil {
		t.Fatal("policy changed")
	}
	s, err := OpenStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	before := fileBytes(t, filepath.Join(cfg.Directory, "ledger.json"))
	body := bytes.Repeat([]byte("x"), 32)
	raw, _ := MarshalChallenge(ch)
	manifest, _ := MarshalManifest(a.Record.Manifest)
	r := &observedReader{r: bytes.NewReader(body)}
	replay, err := s.Finalize(context.Background(), &f.stateA, raw, manifest, r, f.now.Add(24*time.Hour))
	if err != nil || r.calls != 0 {
		t.Fatalf("historical replay read data or expired: %v", err)
	}
	expected, _ := MarshalAcceptance(a)
	actual, _ := MarshalAcceptance(replay)
	if !bytes.Equal(expected, actual) || !bytes.Equal(before, fileBytes(t, filepath.Join(cfg.Directory, "ledger.json"))) {
		t.Fatal("replay changed accepted state/time")
	}
	got, err := s.Get(&f.stateA, ch.Claim.JobID)
	if err != nil || got.State != "accepted" || got.Acceptance == nil {
		t.Fatal("authorized Get failed")
	}
	got.Challenge.Claim.JobID = "mutated"
	got.Acceptance.Record.Binding.JobID = "mutated"
	got, err = s.Get(&f.stateA, ch.Claim.JobID)
	if err != nil || got.Acceptance.Record.Binding.JobID != ch.Claim.JobID {
		t.Fatal("Get exposes mutable state")
	}
	if _, err = s.Get(&f.stateB, ch.Claim.JobID); err == nil {
		t.Fatal("renewed/same CN certificate gained owner access")
	}
	if _, err = VerifyAcceptance(actual, f.pin, scope); err != nil {
		t.Fatal(err)
	}
	st := s.Snapshot()
	if st.Accepted != 1 || st.Active != 0 || st.Jobs != 1 || st.ChargedBytes != cfg.Policy.MaxBodyBytes+StoreMetadataHeadroom {
		t.Fatal("retained charge was released")
	}
}

func TestStoreReserveReplayRenewalAndConflicts(t *testing.T) {
	f := fixture(t)
	p := DefaultStorePolicy()
	p.MaxPrincipalJobs = 1
	p.MaxPrincipalActive = 1
	s, cfg := storeFixture(t, p)
	ch := storeReserve(t, s, 1)
	before := fileBytes(t, filepath.Join(cfg.Directory, "ledger.json"))
	again, err := s.Reserve(&f.stateA, storeRequest(1), "sample.fastq", f.now.Add(time.Hour))
	if err != nil || again != ch {
		t.Fatal("reserve replay changed challenge")
	}
	for _, tc := range []struct {
		state         *tls.ConnectionState
		request, name string
	}{
		{&f.stateA, storeRequest(1), "different.fastq"}, {&f.stateB, storeRequest(1), "sample.fastq"}, {&f.stateB, storeRequest(2), "sample.fastq"},
	} {
		if _, err := s.Reserve(tc.state, tc.request, tc.name, f.now); err == nil {
			t.Fatal("conflict or renewal quota bypass accepted")
		}
	}
	if !bytes.Equal(before, fileBytes(t, filepath.Join(cfg.Directory, "ledger.json"))) || s.Snapshot().Jobs != 1 {
		t.Fatal("conflict mutated ledger")
	}
	if _, err := s.Reserve(nil, storeRequest(3), "sample.fastq", f.now); err == nil {
		t.Fatal("unauthenticated reserve accepted")
	}
}

func TestStoreQuotaExactAndFinalSlotRace(t *testing.T) {
	f := fixture(t)
	for _, dimension := range []string{"global jobs", "principal jobs", "global bytes", "principal bytes", "active", "principal active"} {
		t.Run(dimension, func(t *testing.T) {
			p := DefaultStorePolicy()
			p.MaxBodyBytes = 32
			p.MaxPrincipalActive = 2
			charge := p.MaxBodyBytes + StoreMetadataHeadroom
			switch dimension {
			case "global jobs":
				p.MaxJobs = 1
				p.MaxPrincipalJobs = 1
				p.MaxActive = 1
				p.MaxPrincipalActive = 1
			case "principal jobs":
				p.MaxPrincipalJobs = 1
				p.MaxPrincipalActive = 1
			case "global bytes":
				p.MaxBytes = charge
				p.MaxPrincipalBytes = charge
			case "principal bytes":
				p.MaxPrincipalBytes = charge
			case "active":
				p.MaxActive = 1
				p.MaxPrincipalActive = 1
			case "principal active":
				p.MaxPrincipalActive = 1
			}
			s, _ := storeFixture(t, p)
			var wg sync.WaitGroup
			success := make(chan bool, 2)
			for i := 1; i <= 2; i++ {
				wg.Add(1)
				go func(n int) {
					defer wg.Done()
					_, err := s.Reserve(&f.stateA, storeRequest(n), "sample.fastq", f.now)
					success <- err == nil
				}(i)
			}
			wg.Wait()
			close(success)
			count := 0
			for ok := range success {
				if ok {
					count++
				}
			}
			if count != 1 || s.Snapshot().Jobs != 1 || s.Snapshot().ChargedBytes != charge {
				t.Fatalf("quota race admitted %d", count)
			}
		})
	}
}

func TestStoreCapacitySensorSubtractsPromises(t *testing.T) {
	f := fixture(t)
	p := DefaultStorePolicy()
	p.MaxBodyBytes = 32
	p.MaxPrincipalActive = 2
	s, _ := storeFixture(t, p)
	charge := p.MaxBodyBytes + StoreMetadataHeadroom
	first := uint64(p.FreeSpaceFloorBytes + charge + 2*StoreLedgerLimit)
	s.available = func(*os.File) (uint64, error) { return first - 1, nil }
	if _, err := s.Reserve(&f.stateA, storeRequest(1), "sample.fastq", f.now); err == nil {
		t.Fatal("floor-minus-one accepted")
	}
	s.available = func(*os.File) (uint64, error) { return first, nil }
	storeReserve(t, s, 1)
	if _, err := s.Reserve(&f.stateA, storeRequest(2), "sample.fastq", f.now); err == nil {
		t.Fatal("promised bytes omitted from floor")
	}
	s.available = func(*os.File) (uint64, error) { return first + uint64(charge), nil }
	storeReserve(t, s, 2)
}

func TestStoreFinalizeAuthBeforeReaderAndUnchangedReservation(t *testing.T) {
	f := fixture(t)
	s, cfg := storeFixture(t, DefaultStorePolicy())
	ch := storeReserve(t, s, 1)
	body := bytes.Repeat([]byte("x"), 32)
	raw, manifest := storeManifest(t, ch, body)
	before := fileBytes(t, filepath.Join(cfg.Directory, "ledger.json"))
	for _, tc := range []struct {
		name                string
		state               *tls.ConnectionState
		challenge, manifest []byte
		now                 time.Time
	}{
		{"owner", &f.stateB, raw, manifest, f.now}, {"signature", &f.stateA, raw, bytes.Replace(manifest, []byte(`"signature":"`), []byte(`"signature":"f`), 1), f.now},
		{"challenge", &f.stateA, append(append([]byte(nil), raw...), byte(' ')), manifest, f.now}, {"expiry", &f.stateA, raw, manifest, f.now.Add(time.Hour)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reader := &observedReader{r: bytes.NewReader(body)}
			if _, err := s.Finalize(context.Background(), tc.state, tc.challenge, tc.manifest, reader, tc.now); err == nil || reader.calls != 0 {
				t.Fatal("unauthenticated/unreserved finalization read data")
			}
			if !bytes.Equal(before, fileBytes(t, filepath.Join(cfg.Directory, "ledger.json"))) {
				t.Fatal("bad request changed reservation")
			}
		})
	}
	if s.Snapshot().Active != 1 || !s.Healthy() {
		t.Fatal("bad request damaged store")
	}
}

func TestStoreKnownReadFailureRetainsChargeAndReplaysWithoutRead(t *testing.T) {
	f := fixture(t)
	for _, kind := range []string{"short", "excess", "hash", "reader error", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			s, cfg := storeFixture(t, DefaultStorePolicy())
			ch := storeReserve(t, s, 1)
			body := bytes.Repeat([]byte("x"), 32)
			raw, manifest := storeManifest(t, ch, body)
			var reader io.Reader = bytes.NewReader(body)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch kind {
			case "short":
				reader = bytes.NewReader(body[:31])
			case "excess":
				reader = bytes.NewReader(append(body, 'x'))
			case "hash":
				reader = bytes.NewReader(bytes.Repeat([]byte("y"), 32))
			case "reader error":
				reader = readerFunc(func([]byte) (int, error) { return 0, errors.New("private-secret-path") })
			case "cancel":
				reader = readerFunc(func(p []byte) (int, error) { cancel(); return copy(p, body), io.EOF })
			}
			_, err := s.Finalize(ctx, &f.stateA, raw, manifest, reader, f.now)
			if err == nil {
				t.Fatal("bad data accepted")
			}
			failure := err.Error()
			if strings.Contains(failure, "private-secret") {
				t.Fatal("reader secrets leaked")
			}
			if st := s.Snapshot(); st.Rejected != 1 || st.Active != 0 || st.ChargedBytes != cfg.Policy.MaxBodyBytes+StoreMetadataHeadroom {
				t.Fatal("read failure released retained charge")
			}
			if err = s.Close(); err != nil {
				t.Fatal(err)
			}
			s, err = OpenStore(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			r := &observedReader{r: bytes.NewReader(body)}
			_, err = s.Finalize(context.Background(), &f.stateA, raw, manifest, r, f.now.Add(time.Hour))
			if err == nil || err.Error() != failure || r.calls != 0 {
				t.Fatal("failed finalization retried data")
			}
		})
	}
}

func TestStoreReadingIsDurableWithoutHoldingMutex(t *testing.T) {
	f := fixture(t)
	p := DefaultStorePolicy()
	p.MaxPrincipalActive = 2
	s, cfg := storeFixture(t, p)
	ch := storeReserve(t, s, 1)
	body := bytes.Repeat([]byte("x"), 32)
	raw, manifest := storeManifest(t, ch, body)
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	reader := readerFunc(func(p []byte) (int, error) { close(entered); <-release; return copy(p, body), io.EOF })
	go func() {
		_, err := s.Finalize(context.Background(), &f.stateA, raw, manifest, reader, f.now)
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("reader never entered")
	}
	var env signedStoreLedger
	if err := decodeStoreJSON(fileBytes(t, filepath.Join(cfg.Directory, "ledger.json")), &env); err != nil || env.Ledger.Records[0].State != "reading" || env.Ledger.Records[0].ManifestJSON != string(manifest) {
		t.Fatal("reader started before durable reading")
	}
	if _, err := s.Get(&f.stateA, ch.Claim.JobID); err != nil {
		t.Fatal("mutex held during reader")
	}
	if err := s.Close(); err == nil {
		t.Fatal("closed lock while reader active")
	}
	if _, err := s.Reserve(&f.stateA, storeRequest(2), "second.fastq", f.now); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if st := s.Snapshot(); st.Accepted != 1 || st.Active != 1 {
		t.Fatal("parallel transaction lost reading update")
	}
}

func TestStoreFailurePersistenceKeepsReservationAndNoACK(t *testing.T) {
	f := fixture(t)
	for _, point := range []string{"marker_write", "marker_sync", "marker_parent_sync", "write", "file_sync", "file_close", "rename", "parent_sync", "marker_unlink", "marker_remove_sync"} {
		t.Run(point, func(t *testing.T) {
			s, cfg := storeFixture(t, DefaultStorePolicy())
			ch := storeReserve(t, s, 1)
			body := bytes.Repeat([]byte("x"), 32)
			raw, manifest := storeManifest(t, ch, body)
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			pc := storeProcessConfig{Config: cfg, CertificateDER: hex.EncodeToString(f.certA.Raw), Challenge: raw, Manifest: manifest, Mode: "fault", Fault: point}
			runStoreProcess(t, pc)
			reopened, err := OpenStore(cfg)
			if point == "marker_remove_sync" {
				if err != nil {
					t.Fatal("genuine durable state could not reopen after marker unlink")
				}
				defer reopened.Close()
				if reopened.Snapshot().Accepted != 1 {
					t.Fatal("wrong durable state")
				}
			} else if err == nil {
				reopened.Close()
				t.Fatal("ambiguous transaction adopted")
			}
		})
	}
}

func TestStoreACKFailureDoesNotLoseDurableAcceptance(t *testing.T) {
	f := fixture(t)
	s, cfg := storeFixture(t, DefaultStorePolicy())
	ch := storeReserve(t, s, 1)
	body := bytes.Repeat([]byte("x"), 32)
	raw, manifest := storeManifest(t, ch, body)
	s.Close()
	runStoreProcess(t, storeProcessConfig{Config: cfg, CertificateDER: hex.EncodeToString(f.certA.Raw), Challenge: raw, Manifest: manifest, Mode: "ack"})
	s, err := OpenStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	r := &observedReader{r: bytes.NewReader(body)}
	if _, err = s.Finalize(context.Background(), &f.stateA, raw, manifest, r, f.now.Add(time.Hour)); err != nil || r.calls != 0 {
		t.Fatal("lost ACK replay re-read ciphertext")
	}
}

func TestStoreLivePathSubstitutionAndLedgerTamper(t *testing.T) {
	for _, kind := range []string{"root", "lock", "ledger", "content", "mode"} {
		t.Run(kind, func(t *testing.T) {
			s, cfg := storeFixture(t, DefaultStorePolicy())
			f := fixture(t)
			switch kind {
			case "root":
				if err := os.Rename(cfg.Directory, cfg.Directory+"-old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(cfg.Directory, 0700); err != nil {
					t.Fatal(err)
				}
			case "lock":
				if err := os.Rename(filepath.Join(cfg.Directory, "instance.lock"), filepath.Join(cfg.Directory, "old-lock")); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(cfg.Directory, "instance.lock"), nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "ledger":
				path := filepath.Join(cfg.Directory, "ledger.json")
				raw := fileBytes(t, path)
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "content":
				if err := os.WriteFile(filepath.Join(cfg.Directory, "ledger.json"), []byte(`{}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "mode":
				if err := os.Chmod(filepath.Join(cfg.Directory, "ledger.json"), 0644); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.Reserve(&f.stateA, storeRequest(1), "sample.fastq", f.now); err == nil || s.Healthy() {
				t.Fatal("live substitution accepted")
			}
		})
	}
}

func TestStoreUnsafeHistoryPreserved(t *testing.T) {
	for _, kind := range []string{"missing ledger", "unknown", "pending", "temp", "lock bytes", "lock sparse", "ledger FIFO", "ledger symlink", "ledger hardlink", "ledger oversized", "ledger mode", "ancestor symlink"} {
		t.Run(kind, func(t *testing.T) {
			s, cfg := storeFixture(t, DefaultStorePolicy())
			s.Close()
			path := filepath.Join(cfg.Directory, "ledger.json")
			original := fileBytes(t, path)
			switch kind {
			case "missing ledger":
				os.Remove(path)
			case "unknown":
				os.WriteFile(filepath.Join(cfg.Directory, "unknown"), []byte("preserve"), 0600)
			case "pending":
				os.WriteFile(filepath.Join(cfg.Directory, "transaction.pending"), []byte("preserve"), 0600)
			case "temp":
				os.WriteFile(filepath.Join(cfg.Directory, "ledger.next"), original, 0600)
			case "lock bytes":
				os.WriteFile(filepath.Join(cfg.Directory, "instance.lock"), []byte("preserve"), 0600)
			case "lock sparse":
				os.Truncate(filepath.Join(cfg.Directory, "instance.lock"), 1<<30)
			case "ledger FIFO":
				os.Remove(path)
				if err := syscall.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			case "ledger symlink":
				os.Rename(path, path+".original")
				os.Symlink(path+".original", path)
			case "ledger hardlink":
				os.Link(path, path+".link")
			case "ledger oversized":
				os.Truncate(path, StoreLedgerLimit+1)
			case "ledger mode":
				os.Chmod(path, 0644)
			case "ancestor symlink":
				parent := filepath.Dir(cfg.Directory)
				os.Symlink(parent, parent+"-link")
				cfg.Directory = filepath.Join(parent+"-link", "authority")
			}
			started := time.Now()
			opened, err := OpenStore(cfg)
			if err == nil {
				opened.Close()
				t.Fatal("unsafe history accepted")
			}
			if time.Since(started) > time.Second {
				t.Fatal("unsafe filesystem read blocked")
			}
			if _, err := os.Stat(cfg.Directory); err != nil {
				t.Fatal("history directory deleted")
			}
		})
	}
}

func TestStoreSignedLedgerPreventsRelabelingAndStrictJSON(t *testing.T) {
	for _, kind := range []string{"request", "state", "charge", "case", "duplicate", "null", "trailing", "depth", "records null", "policy null"} {
		t.Run(kind, func(t *testing.T) {
			s, cfg := storeFixture(t, DefaultStorePolicy())
			storeReserve(t, s, 1)
			s.Close()
			path := filepath.Join(cfg.Directory, "ledger.json")
			raw := fileBytes(t, path)
			switch kind {
			case "request":
				raw = bytes.Replace(raw, []byte(storeRequest(1)), []byte(storeRequest(2)), 1)
			case "state":
				raw = bytes.Replace(raw, []byte(`"state":"reserved"`), []byte(`"state":"accepted"`), 1)
			case "charge":
				raw = bytes.Replace(raw, []byte(`"charge_bytes":26345472`), []byte(`"charge_bytes":1`), 1)
			case "case":
				raw = bytes.Replace(raw, []byte(`"schema_version"`), []byte(`"Schema_Version"`), 1)
			case "duplicate":
				raw = bytes.Replace(raw, []byte(`"schema_version":1`), []byte(`"schema_version":1,"schema_version":1`), 1)
			case "null":
				raw = bytes.Replace(raw, []byte(`"schema_version":1`), []byte(`"schema_version":null`), 1)
			case "trailing":
				raw = append(raw, []byte(`{}`)...)
			case "depth":
				raw = []byte(`{"ledger":` + strings.Repeat("[", 65) + `0` + strings.Repeat("]", 65) + `}`)
			case "records null":
				var env map[string]json.RawMessage
				json.Unmarshal(raw, &env)
				var ledger map[string]json.RawMessage
				json.Unmarshal(env["ledger"], &ledger)
				ledger["records"] = []byte("null")
				env["ledger"], _ = json.Marshal(ledger)
				raw, _ = json.Marshal(env)
			case "policy null":
				raw = bytes.Replace(raw, []byte(`"policy":{`), []byte(`"policy":null,"ignored":{`), 1)
			}
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if opened, err := OpenStore(cfg); err == nil {
				opened.Close()
				t.Fatal("tampered/ambiguous ledger accepted")
			}
			if !bytes.Equal(raw, fileBytes(t, path)) {
				t.Fatal("tampered history overwritten")
			}
		})
	}
}

type storeProcessConfig struct {
	Config         StoreConfig
	CertificateDER string
	Challenge      []byte
	Manifest       []byte
	Marker         string
	Mode           string
	Fault          string
}

func runStoreProcess(t *testing.T, pc storeProcessConfig) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "process.json")
	raw, _ := json.Marshal(pc)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestStoreProcessHelper$", "-test.timeout=20s", "-test.v")
	cmd.Env = append(os.Environ(), "BIOZERO_TEST_STORE_HELPER="+path)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("process fixture failed: %v %s", err, output)
	} else {
		t.Logf("Original subprocess evidence:\n%s", output)
	}
}

func TestStoreProcessHelper(t *testing.T) {
	path := os.Getenv("BIOZERO_TEST_STORE_HELPER")
	if path == "" {
		return
	}
	var pc storeProcessConfig
	if err := json.Unmarshal(fileBytes(t, path), &pc); err != nil {
		t.Fatal(err)
	}
	if pc.Mode == "fault" || pc.Mode == "ack" {
		probe := unreachableStickyStore(t, pc)
		before := fileBytes(t, filepath.Join(pc.Config.Directory, "ledger.json"))
		observeCollectedStoreFiles(t, probe)
		if other, err := OpenStore(pc.Config); err == nil {
			other.Close()
			t.Fatal("finalized os.File descriptors released ambiguous lifetime flock")
		} else if err.Error() != "ownership_instance_locked" {
			t.Fatal(err)
		}
		if !bytes.Equal(before, fileBytes(t, filepath.Join(pc.Config.Directory, "ledger.json"))) {
			t.Fatal("sticky history changed")
		}
		return
	}
	s, err := OpenStore(pc.Config)
	if pc.Mode == "lock" {
		if err == nil {
			s.Close()
			t.Fatal("cross-process lock bypass")
		}
		if err.Error() != "ownership_instance_locked" {
			t.Fatal(err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	der, _ := hex.DecodeString(pc.CertificateDER)
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	// The parent obtains this leaf from its real mTLS fixture. This helper
	// reuses its verified transport facts solely to stop inside a real Read.
	state := tls.ConnectionState{HandshakeComplete: true, PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
	reader := readerFunc(func([]byte) (int, error) {
		fd, err := os.OpenFile(pc.Marker, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal(err)
		}
		fd.Write([]byte("reading"))
		fd.Sync()
		fd.Close()
		time.Sleep(time.Hour)
		return 0, io.EOF
	})
	_, err = s.Finalize(context.Background(), &state, pc.Challenge, pc.Manifest, reader, fixtureTime(pc.Challenge))
	t.Fatalf("unexpected finalize return: %v", err)
}

// stickyFDProbe contains only numeric descriptors and copied kernel metadata.
// It cannot retain Store, os.File or a cleanup closure containing either.
type stickyFDProbe struct {
	originals [3]int
	raw       int
	rawStat   syscall.Stat_t
}

//go:noinline
func unreachableStickyStore(t *testing.T, pc storeProcessConfig) stickyFDProbe {
	t.Helper()
	s, err := OpenStore(pc.Config)
	if err != nil {
		t.Fatal(err)
	}
	// No defer or Cleanup may capture s: this frame must return before GC.
	der, _ := hex.DecodeString(pc.CertificateDER)
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	state := tls.ConnectionState{HandshakeComplete: true, PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
	seen := 0
	s.fault = func(name string) error {
		if pc.Mode == "ack" && name == "ack" {
			return errors.New("injected ACK")
		}
		if name == pc.Fault {
			seen++
			if seen == 2 {
				return errors.New("injected transaction")
			}
		}
		return nil
	}
	if _, err = s.Finalize(context.Background(), &state, pc.Challenge, pc.Manifest, bytes.NewReader(bytes.Repeat([]byte("x"), 32)), fixtureTime(pc.Challenge)); err == nil {
		t.Fatal("ACK on injected failure")
	}
	st := s.Snapshot()
	if !st.Sticky || st.ChargedBytes != pc.Config.Policy.MaxBodyBytes+StoreMetadataHeadroom {
		t.Fatal("sticky/fullcharge lost")
	}
	if pc.Mode == "fault" && (st.Reading != 1 || st.Active != 1 || st.Accepted != 0) {
		t.Fatal("uncertain state reduced reservation")
	}
	if pc.Mode == "ack" && st.Accepted != 1 {
		t.Fatal("ACK failure lost durable record")
	}
	if s.Close() == nil {
		t.Fatal("sticky Close released lifetime authority")
	}
	probe := stickyFDProbe{originals: [3]int{int(s.root.Fd()), int(s.lock.Fd()), int(s.ledgerFile.Fd())}, raw: s.rawLockFD}
	if !s.rawLockHeld || syscall.Fstat(probe.raw, &probe.rawStat) != nil {
		t.Fatal("missing raw lifetime anchor")
	}
	var lockStat syscall.Stat_t
	if syscall.Fstat(probe.originals[1], &lockStat) != nil || lockStat.Dev != probe.rawStat.Dev || lockStat.Ino != probe.rawStat.Ino {
		t.Fatal("raw descriptor does not pin the original flock inode")
	}
	for _, fd := range probe.originals {
		if fd == probe.raw {
			t.Fatal("raw anchor aliases an os.File descriptor")
		}
		if _, err := descriptorFlags(fd); err != 0 {
			t.Fatal("original os.File descriptor not initially open")
		}
	}
	runtime.KeepAlive(s)
	return probe
}

func descriptorFlags(fd int) (uintptr, syscall.Errno) {
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFD, 0)
	return flags, errno
}

func observeCollectedStoreFiles(t *testing.T, probe stickyFDProbe) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		runtime.GC()
		runtime.Gosched()
		closed := 0
		for _, fd := range probe.originals {
			_, errno := descriptorFlags(fd)
			if errno == syscall.EBADF {
				closed++
			} else if errno != 0 {
				t.Fatalf("unexpected descriptor probe error: %v", errno)
			}
		}
		if closed == len(probe.originals) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d/%d original os.File descriptors finalized", closed, len(probe.originals))
		}
		time.Sleep(5 * time.Millisecond)
	}
	// No descriptors were opened during the collection loop; numeric FDs cannot
	// have been reused by the test's own filesystem probes before EBADF checks.
	flags, errno := descriptorFlags(probe.raw)
	var stat syscall.Stat_t
	if errno != 0 || flags&syscall.FD_CLOEXEC == 0 || syscall.Fstat(probe.raw, &stat) != nil || stat.Dev != probe.rawStat.Dev || stat.Ino != probe.rawStat.Ino {
		t.Fatal("raw CLOEXEC flock anchor did not survive original file finalization")
	}
	t.Logf("Observed all %d original os.File descriptors closed (EBADF); raw CLOEXEC flock anchor remains open", len(probe.originals))
}

func fixtureTime(raw []byte) time.Time {
	var ch SignedChallenge
	json.Unmarshal(raw, &ch)
	v, _ := canonicalTime(ch.Claim.IssuedAt)
	return v
}

func TestStoreRealProcessLockAndSIGKILLReadingRecovery(t *testing.T) {
	f := fixture(t)
	s, cfg := storeFixture(t, DefaultStorePolicy())
	ch := storeReserve(t, s, 1)
	raw, manifest := storeManifest(t, ch, bytes.Repeat([]byte("x"), 32))
	privateDir := t.TempDir()
	pc := storeProcessConfig{Config: cfg, CertificateDER: hex.EncodeToString(f.certA.Raw), Challenge: raw, Manifest: manifest, Marker: filepath.Join(privateDir, "reading.marker"), Mode: "lock"}
	configPath := filepath.Join(privateDir, "helper.json")
	write := func() {
		data, _ := json.Marshal(pc)
		if err := os.WriteFile(configPath, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	command := func() *exec.Cmd {
		cmd := exec.Command(os.Args[0], "-test.run=^TestStoreProcessHelper$", "-test.timeout=20s")
		cmd.Env = append(os.Environ(), "BIOZERO_TEST_STORE_HELPER="+configPath)
		return cmd
	}
	if output, err := command().CombinedOutput(); err != nil {
		t.Fatalf("lock helper failed: %v %s", err, output)
	}
	s.Close()
	pc.Mode = "reading"
	write()
	cmd := command()
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cmd.ProcessState == nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(pc.Marker); err == nil {
			break
		}
		if time.Now().After(deadline) {
			cmd.Process.Kill()
			cmd.Wait()
			t.Fatalf("reading marker timeout: %s", output.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	before := fileBytes(t, filepath.Join(cfg.Directory, "ledger.json"))
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("worker not killed")
	}
	wait, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if !ok || wait.Signal() != syscall.SIGKILL {
		t.Fatal("missing causal SIGKILL")
	}
	if opened, err := OpenStore(cfg); err == nil {
		opened.Close()
		t.Fatal("pending read adopted after SIGKILL")
	}
	if !bytes.Equal(before, fileBytes(t, filepath.Join(cfg.Directory, "ledger.json"))) {
		t.Fatal("pending history changed")
	}
}

func TestStorePolicyAndKeyCopies(t *testing.T) {
	f := fixture(t)
	s, cfg := storeFixture(t, DefaultStorePolicy())
	key := append(ed25519.PrivateKey(nil), f.private...)
	public := append(ed25519.PublicKey(nil), f.pin.PublicKey...)
	other := cfg
	other.Directory = filepath.Join(t.TempDir(), "other")
	other.ExpectedScope = AcceptanceScope{}
	other.SigningKey = key
	other.Pin.PublicKey = public
	copyStore, err := CreateStore(other)
	if err != nil {
		t.Fatal(err)
	}
	defer copyStore.Close()
	key[0] ^= 1
	public[0] ^= 1
	if _, err := copyStore.Reserve(&f.stateA, storeRequest(1), "sample.fastq", f.now); err != nil {
		t.Fatal("caller key mutation changed store")
	}
	if s.Snapshot().Jobs != 0 {
		t.Fatal("unrelated store changed")
	}
	for _, mutate := range []func(*StorePolicy){func(p *StorePolicy) { p.MaxJobs = 65 }, func(p *StorePolicy) { p.MaxPrincipalJobs = 0 }, func(p *StorePolicy) { p.MaxBytes = 1 }, func(p *StorePolicy) { p.MaxActive = 0 }, func(p *StorePolicy) { p.MaxBodyBytes = 15 }, func(p *StorePolicy) { p.MaxBodyBytes = MaxCiphertextBytes + 1 }, func(p *StorePolicy) { p.ChallengeTTLSeconds = 301 }, func(p *StorePolicy) { p.FreeSpaceFloorBytes = -1 }} {
		p := DefaultStorePolicy()
		mutate(&p)
		if p.validate() == nil {
			t.Fatal("invalid policy accepted")
		}
	}
}

func TestStoreCancellationAtDecisionBoundaries(t *testing.T) {
	f := fixture(t)
	for _, point := range []string{"before_seal", "before_accept"} {
		t.Run(point, func(t *testing.T) {
			s, _ := storeFixture(t, DefaultStorePolicy())
			ch := storeReserve(t, s, 1)
			body := bytes.Repeat([]byte("x"), 32)
			raw, manifest := storeManifest(t, ch, body)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s.fault = func(name string) error {
				if name == point {
					cancel()
				}
				return nil
			}
			if _, err := s.Finalize(ctx, &f.stateA, raw, manifest, bytes.NewReader(body), f.now); err == nil || err.Error() != "ownership_cancelled" {
				t.Fatalf("cancellation accepted: %v", err)
			}
			if st := s.Snapshot(); st.Accepted != 0 || st.Rejected != 1 || st.Active != 0 {
				t.Fatalf("cancelled decision persisted as accepted: %+v", st)
			}
		})
	}
	s, _ := storeFixture(t, DefaultStorePolicy())
	ch, a := storeAccept(t, s, 1)
	raw, _ := MarshalChallenge(ch)
	manifest, _ := MarshalManifest(a.Record.Manifest)
	ctx, cancel := context.WithCancel(context.Background())
	s.mu.Lock()
	done := make(chan error, 1)
	r := &observedReader{r: bytes.NewReader(bytes.Repeat([]byte("x"), 32))}
	go func() { _, err := s.Finalize(ctx, &f.stateA, raw, manifest, r, f.now); done <- err }()
	cancel()
	s.mu.Unlock()
	if err := <-done; err == nil || err.Error() != "ownership_cancelled" || r.calls != 0 {
		t.Fatal("cancelled accepted replay returned ACK")
	}
}

func TestStoreExpiryDuringPreparationPreventsReader(t *testing.T) {
	f := fixture(t)
	p := DefaultStorePolicy()
	p.ChallengeTTLSeconds = 1
	s, _ := storeFixture(t, p)
	ch := storeReserve(t, s, 1)
	body := bytes.Repeat([]byte("x"), 32)
	raw, manifest := storeManifest(t, ch, body)
	s.fault = func(name string) error {
		if name == "file_sync" {
			time.Sleep(20 * time.Millisecond)
		}
		return nil
	}
	r := &observedReader{r: bytes.NewReader(body)}
	if _, err := s.Finalize(context.Background(), &f.stateA, raw, manifest, r, f.now.Add(time.Second-5*time.Millisecond)); err == nil || err.Error() != "ownership_challenge_expired" || r.calls != 0 {
		t.Fatalf("read began after preparation crossed expiry: %v reads=%d", err, r.calls)
	}
	if s.Snapshot().Rejected != 1 {
		t.Fatal("known expired read attempt not recorded")
	}
}

func TestStoreStickyStopsInflightLateAcceptance(t *testing.T) {
	f := fixture(t)
	p := DefaultStorePolicy()
	p.MaxPrincipalActive = 2
	s, _ := storeFixture(t, p)
	ch := storeReserve(t, s, 1)
	body := bytes.Repeat([]byte("x"), 32)
	raw, manifest := storeManifest(t, ch, body)
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := s.Finalize(context.Background(), &f.stateA, raw, manifest, readerFunc(func(p []byte) (int, error) { close(entered); <-release; return copy(p, body), io.EOF }), f.now)
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("reader did not start")
	}
	s.fault = func(name string) error {
		if name == "file_sync" {
			return errors.New("injected")
		}
		return nil
	}
	if _, err := s.Reserve(&f.stateA, storeRequest(2), "second.fastq", f.now); err == nil {
		t.Fatal("injected reservation ACK")
	}
	close(release)
	if err := <-done; err == nil {
		t.Fatal("late acceptance despite sticky")
	}
	if st := s.Snapshot(); !st.Sticky || st.Reading != 1 || st.Accepted != 0 || st.Jobs != 1 {
		t.Fatalf("ambiguous update altered charge/state: %+v", st)
	}
}

func TestStoreSignedContradictionsRejected(t *testing.T) {
	f := fixture(t)
	for _, kind := range []string{"duplicate", "credential", "principal", "unknown state", "reserved manifest", "charge", "nonce", "certificate"} {
		t.Run(kind, func(t *testing.T) {
			s, cfg := storeFixture(t, DefaultStorePolicy())
			storeReserve(t, s, 1)
			s.Close()
			path := filepath.Join(cfg.Directory, "ledger.json")
			var env signedStoreLedger
			if err := decodeStoreJSON(fileBytes(t, path), &env); err != nil {
				t.Fatal(err)
			}
			r := &env.Ledger.Records[0]
			switch kind {
			case "duplicate":
				env.Ledger.Records = append(env.Ledger.Records, *r)
			case "credential":
				r.CredentialSHA256 = digest(f.certB.Raw)
			case "principal":
				r.PrincipalSHA256 = strings.Repeat("f", 64)
			case "unknown state":
				r.State = "ready"
			case "reserved manifest":
				r.ManifestJSON = "{}"
			case "charge":
				r.ChargeBytes--
			case "nonce":
				var ch SignedChallenge
				json.Unmarshal([]byte(r.ChallengeJSON), &ch)
				ch.Claim.Nonce = strings.Repeat("f", 64)
				raw, _ := MarshalChallenge(ch)
				r.ChallengeJSON = string(raw)
			case "certificate":
				r.CertificateDER = hex.EncodeToString(f.certB.Raw)
			}
			canonical, _ := json.Marshal(env.Ledger)
			env.Signature = hex.EncodeToString(ed25519.Sign(f.private, canonical))
			raw, _ := json.Marshal(env)
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if reopened, err := OpenStore(cfg); err == nil {
				reopened.Close()
				t.Fatal("contradictory signed ledger accepted")
			}
			if !bytes.Equal(raw, fileBytes(t, path)) {
				t.Fatal("contradictory ledger repaired implicitly")
			}
		})
	}
}
