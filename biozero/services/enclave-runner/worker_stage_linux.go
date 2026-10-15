//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

const workerStageMaxBytes int64 = 25 << 20
const workerStageFSBytes int64 = 32 << 20
const workerStageFSInodes uint64 = 4096

// VerifiedPlaintextStage owns one randomly named private plaintext file. The
// caller supplies already verified bytes; staging is not cryptographic proof.
// File is borrowed by submissions and remains read-only. Close retains its name
// after any uncertain submission. Only an explicit confirmed release unlinks it.
type VerifiedPlaintextStage struct {
	File      *os.File
	SHA256    string
	Bytes     int64
	mu        sync.Mutex
	dir       *os.File
	name      string
	dev       uint64
	ino       uint64
	submitted bool
	released  bool
	closed    bool
	closeErr  error
}

func stageError(code string) error { return errors.New(code) }

func stageJobID(job string) bool {
	if len(job) != 16 {
		return false
	}
	for _, c := range []byte(job) {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// Host root is unmapped inside the exact launcher user namespace. Parent
// preflight validates host ancestor owners before that mapping; the final stage
// directory must still belong to the current UID. Arbitrary maps do not qualify.
func workerStageAncestorOwner(uid uint32) bool {
	if uid == 0 || uid == uint32(os.Geteuid()) {
		return true
	}
	if os.Geteuid() != 0 {
		return false
	}
	mapping, e := os.ReadFile("/proc/self/uid_map")
	fields := strings.Fields(string(mapping))
	if e != nil || len(mapping) > 128 || len(fields) != 3 || fields[0] != "0" || fields[1] != "1000" || fields[2] != "1" {
		return false
	}
	raw, e := os.ReadFile("/proc/sys/kernel/overflowuid")
	if e != nil || len(raw) > 64 {
		return false
	}
	value, e := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 32)
	return e == nil && uint32(value) == uid
}

// Traverse each ancestor using descriptors. Ancestors are trusted current/root
// owned directories without group/other write, except sticky system temp dirs.
// The staging directory itself must be current-UID exact0700, without specials.
func openWorkerStageDir(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || strings.ContainsAny(path, "\x00\r\n") {
		return nil, stageError("plaintext_stage_directory_invalid")
	}
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, stageError("plaintext_stage_directory_unsafe")
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		next, e := syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
		syscall.Close(fd)
		if e != nil {
			return nil, stageError("plaintext_stage_directory_unsafe")
		}
		fd = next
		var st syscall.Stat_t
		if syscall.Fstat(fd, &st) != nil || !workerStageAncestorOwner(st.Uid) || st.Mode&0022 != 0 && st.Mode&syscall.S_ISVTX == 0 {
			syscall.Close(fd)
			return nil, stageError("plaintext_stage_directory_unsafe")
		}
	}
	f := os.NewFile(uintptr(fd), "worker-private-staging")
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil || st.Uid != uint32(os.Geteuid()) || st.Mode&07777 != 0700 {
		f.Close()
		return nil, stageError("plaintext_stage_directory_unsafe")
	}
	return f, nil
}

func workerStageFilesystem(dir *os.File) error {
	var fs syscall.Statfs_t
	if dir == nil || syscall.Fstatfs(int(dir.Fd()), &fs) != nil || fs.Type != 0x01021994 || fs.Bsize <= 0 || uint64(fs.Bsize) > uint64(workerStageFSBytes) || fs.Blocks != uint64(workerStageFSBytes)/uint64(fs.Bsize) || fs.Files != workerStageFSInodes || uint64(fs.Flags)&14 != 14 || uint64(fs.Flags)&1 != 0 {
		return stageError("plaintext_stage_tmpfs_required")
	}
	return nil
}

// ValidateWorkerStageDirectory checks the mount and directory identity without
// requiring emptiness or taking the staging lock. Retained names may be used only
// for status/receipt recovery, never adopted or removed by this validation.
func ValidateWorkerStageDirectory(ctx context.Context, dir string) error {
	if ctx == nil || ctx.Err() != nil {
		return stageError("plaintext_stage_cancelled")
	}
	d, err := openWorkerStageDir(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err = workerStageFilesystem(d); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return stageError("plaintext_stage_cancelled")
	}
	return nil
}

// StageVerifiedPlaintext requires an existing bounded tmpfs, never creates or
// remounts it. Keep this object reachable until submission resolution. Call
// MarkSubmitStarted immediately before the first transport attempt.
func StageVerifiedPlaintext(ctx context.Context, dir, jobID string, plain []byte) (*VerifiedPlaintextStage, error) {
	if ctx == nil || ctx.Err() != nil || !stageJobID(jobID) || int64(len(plain)) > workerStageMaxBytes {
		return nil, stageError("plaintext_stage_input_invalid")
	}
	d, err := openWorkerStageDir(dir)
	if err != nil {
		return nil, err
	}
	if err = workerStageFilesystem(d); err != nil {
		d.Close()
		return nil, err
	}
	return stagePlaintextInDir(ctx, d, jobID, plain)
}

// This internal routine owns dir even on failure. Its caller must first verify
// the tmpfs; filesystem-independent unit tests exercise file custody separately.
func stagePlaintextInDir(ctx context.Context, dir *os.File, jobID string, plain []byte) (stage *VerifiedPlaintextStage, err error) {
	if ctx == nil || ctx.Err() != nil || dir == nil || !stageJobID(jobID) || int64(len(plain)) > workerStageMaxBytes {
		if dir != nil {
			dir.Close()
		}
		return nil, stageError("plaintext_stage_input_invalid")
	}
	// A lifetime directory flock also fences simultaneous creators in another
	// process. Close releases the flock but retains a pending file name; its
	// presence continues to block admission after a restart.
	if syscall.Flock(int(dir.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		dir.Close()
		return nil, stageError("plaintext_stage_busy")
	}
	listing, e := os.ReadDir("/proc/self/fd/" + strconv.Itoa(int(dir.Fd())))
	if e != nil || len(listing) != 0 {
		dir.Close()
		return nil, stageError("plaintext_stage_history_pending")
	}
	owned := false
	defer func() {
		if !owned {
			dir.Close()
		}
	}()
	var nonce [16]byte
	if _, e := rand.Read(nonce[:]); e != nil {
		return nil, stageError("plaintext_stage_random_failed")
	}
	name := "verified-" + jobID + "-" + hex.EncodeToString(nonce[:])
	fd, e := syscall.Openat(int(dir.Fd()), name, syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0600)
	if e != nil {
		return nil, stageError("plaintext_stage_create_failed")
	}
	writable := os.NewFile(uintptr(fd), "worker-plaintext-write")
	defer writable.Close()
	if writable.Chmod(0600) != nil {
		return nil, stageError("plaintext_stage_permissions_failed")
	}
	var initial syscall.Stat_t
	if syscall.Fstat(fd, &initial) != nil {
		return nil, stageError("plaintext_stage_stat_failed")
	}
	stage = &VerifiedPlaintextStage{dir: dir, name: name, dev: uint64(initial.Dev), ino: initial.Ino, Bytes: int64(len(plain))}
	accepted := false
	created := stage
	defer func() {
		if !accepted {
			created.unlinkOwned()
			if created.File != nil {
				created.File.Close()
			}
		}
	}()
	h := sha256.New()
	for offset := 0; offset < len(plain); {
		if ctx.Err() != nil {
			return nil, stageError("plaintext_stage_cancelled")
		}
		end := offset + 65536
		if end > len(plain) {
			end = len(plain)
		}
		n, e := writable.Write(plain[offset:end])
		if e != nil || n != end-offset {
			return nil, stageError("plaintext_stage_write_failed")
		}
		h.Write(plain[offset:end])
		offset = end
	}
	if ctx.Err() != nil {
		return nil, stageError("plaintext_stage_cancelled")
	}
	if writable.Sync() != nil || dir.Sync() != nil {
		return nil, stageError("plaintext_stage_sync_failed")
	}
	readfd, e := syscall.Openat(int(dir.Fd()), name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, stageError("plaintext_stage_reopen_failed")
	}
	stage.File = os.NewFile(uintptr(readfd), "worker-verified-plaintext")
	if !stage.matches(stage.File, true) {
		return nil, stageError("plaintext_stage_file_unsafe")
	}
	verify := sha256.New()
	buf := make([]byte, 65536)
	reader := io.NewSectionReader(stage.File, 0, workerStageMaxBytes+1)
	var total int64
	for {
		if ctx.Err() != nil {
			return nil, stageError("plaintext_stage_cancelled")
		}
		n, e := reader.Read(buf)
		if n > 0 {
			total += int64(n)
			verify.Write(buf[:n])
		}
		if total > workerStageMaxBytes {
			return nil, stageError("plaintext_stage_oversize")
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, stageError("plaintext_stage_read_failed")
		}
	}
	if total != stage.Bytes || !stage.matches(stage.File, true) || !strings.EqualFold(hex.EncodeToString(verify.Sum(nil)), hex.EncodeToString(h.Sum(nil))) {
		return nil, stageError("plaintext_stage_integrity_failed")
	}
	stage.SHA256 = hex.EncodeToString(verify.Sum(nil))
	// The writable descriptor is closed before the caller obtains the RO handle.
	if writable.Close() != nil {
		return nil, stageError("plaintext_stage_close_failed")
	}
	accepted = true
	owned = true
	return stage, nil
}

func (s *VerifiedPlaintextStage) matches(f *os.File, size bool) bool {
	if f == nil {
		return false
	}
	var st syscall.Stat_t
	return syscall.Fstat(int(f.Fd()), &st) == nil && uint64(st.Dev) == s.dev && st.Ino == s.ino && st.Mode&syscall.S_IFMT == syscall.S_IFREG && st.Mode&07777 == 0600 && st.Uid == uint32(os.Geteuid()) && st.Nlink == 1 && (!size || st.Size == s.Bytes)
}

func (s *VerifiedPlaintextStage) unlinkOwned() error {
	if s.released {
		return nil
	}
	// O_PATH does not block on replacements such as FIFO and does not follow a
	// symlink. The private current-UID directory is a trusted-host boundary; no
	// protection against a malicious same-UID/privileged concurrent rename is claimed.
	fd, e := syscall.Openat(int(s.dir.Fd()), s.name, 0x200000|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		return stageError("plaintext_stage_release_unverified")
	}
	f := os.NewFile(uintptr(fd), "worker-plaintext-identity")
	same := s.matches(f, false)
	f.Close()
	if !same {
		return stageError("plaintext_stage_release_unverified")
	}
	if syscall.Unlinkat(int(s.dir.Fd()), s.name) != nil {
		return stageError("plaintext_stage_release_failed")
	}
	if s.dir.Sync() != nil {
		return stageError("plaintext_stage_release_sync_failed")
	}
	s.released = true
	return nil
}

// MarkSubmitStarted irreversibly disables pre-submission discard. An uncertain
// attempt must retain its name even when no ACK was observed.
func (s *VerifiedPlaintextStage) MarkSubmitStarted() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.released {
		return stageError("plaintext_stage_closed")
	}
	s.submitted = true
	return nil
}
func (s *VerifiedPlaintextStage) DiscardUnsubmitted() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return stageError("plaintext_stage_closed")
	}
	if s.submitted {
		return stageError("plaintext_stage_submission_uncertain")
	}
	return s.unlinkOwned()
}

// ReleaseConfirmed is an explicit assertion by the trusted caller that durable
// commit/proof has been checked. It does not derive confirmation from fd closure.
func (s *VerifiedPlaintextStage) ReleaseConfirmed() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return stageError("plaintext_stage_closed")
	}
	return s.unlinkOwned()
}

// Close closes descriptors only. It never removes a pending plaintext name.
func (s *VerifiedPlaintextStage) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return s.closeErr
	}
	s.closed = true
	if s.File != nil {
		s.closeErr = s.File.Close()
	}
	if s.dir != nil {
		if e := s.dir.Close(); e != nil && s.closeErr == nil {
			s.closeErr = e
		}
	}
	return s.closeErr
}
