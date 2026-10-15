//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
)

func stageFixture(t *testing.T) (string, *VerifiedPlaintextStage) {
	t.Helper()
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	d, e := openWorkerStageDir(dir)
	if e != nil {
		t.Fatal(e)
	}
	// Deliberately bypass only the tmpfs precondition: these unit tests establish
	// real file/descriptor custody, never namespace/mount/quota enforcement.
	s, e := stagePlaintextInDir(context.Background(), d, "0000000000000001", []byte("synthetic verified plaintext\n"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	return dir, s
}
func TestWorkerStagePublicAdmissionRejectsUnboundedFilesystem(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	if s, e := StageVerifiedPlaintext(context.Background(), dir, "0000000000000001", []byte("synthetic")); e == nil {
		s.DiscardUnsubmitted()
		s.Close()
		t.Fatal("ordinary test filesystem was admitted without exact tmpfs policy")
	}
	entries, e := os.ReadDir(dir)
	if e != nil || len(entries) != 0 {
		t.Fatal("failed preflight created plaintext")
	}
	if e := ValidateWorkerStageDirectory(context.Background(), dir); e == nil {
		t.Fatal("startup accepted unbounded filesystem")
	}
}
func TestWorkerStageReadonlyCustodyAndUncertainClose(t *testing.T) {
	dir, s := stageFixture(t)
	raw, e := io.ReadAll(s.File)
	want := []byte("synthetic verified plaintext\n")
	h := sha256.Sum256(want)
	if e != nil || string(raw) != string(want) || s.Bytes != int64(len(want)) || s.SHA256 != hex.EncodeToString(h[:]) {
		t.Fatal("staging changed verified bytes")
	}
	if _, e := s.File.Write([]byte("x")); e == nil {
		t.Fatal("staging FD is writable")
	}
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, s.File.Fd(), syscall.F_GETFD, 0)
	if errno != 0 || flags&syscall.FD_CLOEXEC == 0 {
		t.Fatal("plaintext descriptor lacks CLOEXEC")
	}
	info, e := s.File.Stat()
	if e != nil || info.Mode().Perm() != 0600 || info.Sys().(*syscall.Stat_t).Nlink != 1 {
		t.Fatal("plaintext metadata unsafe")
	}
	if e = s.MarkSubmitStarted(); e != nil {
		t.Fatal(e)
	}
	if e = s.DiscardUnsubmitted(); e == nil {
		t.Fatal("uncertain submission discarded plaintext")
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	if e = s.Close(); e != nil {
		t.Fatal("Close not idempotent")
	}
	entries, e := os.ReadDir(dir)
	if e != nil || len(entries) != 1 {
		t.Fatal("Close removed pending name")
	}
	if e = s.ReleaseConfirmed(); e == nil {
		t.Fatal("closed authority released pending name")
	}
}
func TestWorkerStageExplicitReleaseAndDiscard(t *testing.T) {
	for _, submitted := range []bool{false, true} {
		t.Run(map[bool]string{false: "discard_unsubmitted", true: "release_committed"}[submitted], func(t *testing.T) {
			dir, s := stageFixture(t)
			if submitted {
				if e := s.MarkSubmitStarted(); e != nil {
					t.Fatal(e)
				}
				if e := s.ReleaseConfirmed(); e != nil {
					t.Fatal(e)
				}
			} else {
				if e := s.DiscardUnsubmitted(); e != nil {
					t.Fatal(e)
				}
			}
			if e := s.ReleaseConfirmed(); e != nil {
				t.Fatal("repeat confirmed release failed", e)
			}
			if entries, e := os.ReadDir(dir); e != nil || len(entries) != 0 {
				t.Fatal("explicit release retained own file")
			}
			// Unlink does not close a borrowed RO handle prematurely.
			if _, e := s.File.ReadAt(make([]byte, 1), 0); e != nil {
				t.Fatal("confirmed release invalidated borrowed descriptor")
			}
		})
	}
}
func TestWorkerStageDoesNotUnlinkReplacementOrHardlink(t *testing.T) {
	for _, kind := range []string{"regular_replacement", "symlink", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			dir, s := stageFixture(t)
			path := filepath.Join(dir, s.name)
			switch kind {
			case "regular_replacement":
				if e := os.Remove(path); e != nil {
					t.Fatal(e)
				}
				if e := os.WriteFile(path, []byte("retain foreign replacement\n"), 0600); e != nil {
					t.Fatal(e)
				}
			case "symlink":
				if e := os.Remove(path); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink("untrusted-target", path); e != nil {
					t.Fatal(e)
				}
			case "hardlink":
				if e := os.Link(path, path+".second"); e != nil {
					t.Fatal(e)
				}
			}
			if e := s.ReleaseConfirmed(); e == nil {
				t.Fatal("unverified name removed")
			}
			if _, e := os.Lstat(path); e != nil {
				t.Fatal("replacement/linked evidence deleted")
			}
		})
	}
}
func TestWorkerStageFlockAndLeftoversFenceNewAdmission(t *testing.T) {
	dir, s := stageFixture(t)
	try := func() error {
		d, e := openWorkerStageDir(dir)
		if e != nil {
			return e
		}
		next, e := stagePlaintextInDir(context.Background(), d, "0000000000000002", []byte("new synthetic plaintext"))
		if next != nil {
			next.Close()
		}
		return e
	}
	var wg sync.WaitGroup
	failures := make(chan error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); failures <- try() }()
	}
	wg.Wait()
	close(failures)
	for e := range failures {
		if e == nil || e.Error() != "plaintext_stage_busy" {
			t.Fatal("concurrent stage bypassed lifetime flock", e)
		}
	}
	s.Close()
	if e := try(); e == nil || e.Error() != "plaintext_stage_history_pending" {
		t.Fatal("retained name was adopted/reset", e)
	}
	entries, e := os.ReadDir(dir)
	if e != nil || len(entries) != 1 {
		t.Fatal("admission failure changed pending history")
	}
}
func TestWorkerStageRejectsSymlinkModesAndInvalidInput(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "private")
	if e := os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	link := filepath.Join(root, "link")
	if e := os.Symlink(dir, link); e != nil {
		t.Fatal(e)
	}
	for _, p := range []string{link, filepath.Join(link, "child"), "relative", "/"} {
		if d, e := openWorkerStageDir(p); e == nil {
			d.Close()
			t.Fatal("unsafe staging directory accepted")
		}
	}
	if e := os.Chmod(dir, 0755); e != nil {
		t.Fatal(e)
	}
	if d, e := openWorkerStageDir(dir); e == nil {
		d.Close()
		t.Fatal("nonprivate directory accepted")
	}
	os.Chmod(dir, 0700)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tt := range []struct {
		ctx  context.Context
		id   string
		data []byte
	}{{nil, "0000000000000001", nil}, {ctx, "0000000000000001", nil}, {context.Background(), "../unsafe", nil}, {context.Background(), strings.Repeat("a", 16), make([]byte, workerStageMaxBytes+1)}} {
		if s, e := StageVerifiedPlaintext(tt.ctx, dir, tt.id, tt.data); e == nil {
			s.Close()
			t.Fatal("invalid plaintext admission accepted")
		}
	}
	entries, e := os.ReadDir(dir)
	if e != nil || len(entries) != 0 {
		t.Fatal("invalid input created a file")
	}
}
