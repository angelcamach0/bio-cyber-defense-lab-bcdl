//go:build linux

package artifactexecutor

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func registryFixture(t *testing.T) (*InputRegistry, *Store, string, *os.File, []byte) {
	t.Helper()
	s, _, _ := openTest(t, 4)
	r, err := NewInputRegistry(s)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	lease := reserveTest(t, s, 1)
	data := []byte("verified synthetic plaintext\n")
	p := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(p, data, 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return r, s, lease, f, data
}

func TestRegistrySeparatesUploadAndProcessedDigests(t *testing.T) {
	r, s, lease, f, data := registryFixture(t)
	f.Seek(5, io.SeekStart)
	ref, err := r.Bind(context.Background(), lease, f, digest(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	f.Close() // Registry owns a separate FD; no caller offset or lifetime authority.
	input, err := r.Acquire(lease, ref)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	if input.OriginalSHA256 != digest([]byte("original-upload")) || input.ProcessedSHA256 != digest(data) || input.OriginalSHA256 == input.ProcessedSHA256 {
		t.Fatal("encrypted upload digest was substituted for plaintext binding")
	}
	var copied bytes.Buffer
	if _, err := input.CopyTo(context.Background(), &copied); err != nil || !bytes.Equal(copied.Bytes(), data) {
		t.Fatal("bound copy mismatch", err)
	}
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, input.file.Fd(), syscall.F_GETFD, 0)
	if errno != 0 || flags&syscall.FD_CLOEXEC == 0 {
		t.Fatal("input FD lacks atomic close-on-exec")
	}
	if s.Snapshot().RetainedOrReservedJobs != 1 {
		t.Fatal("closing caller input released reservation")
	}
}

func TestRegistryRejectsCiphertextDigestAndUnreservedLease(t *testing.T) {
	for _, change := range []string{"cipher_digest", "wrong_size", "oversize", "bad_lease", "no_lease", "cancelled"} {
		t.Run(change, func(t *testing.T) {
			r, _, lease, f, data := registryFixture(t)
			sha, size := digest(data), int64(len(data))
			ctx := context.Background()
			switch change {
			case "cipher_digest":
				sha = digest([]byte("original-upload"))
			case "wrong_size":
				size++
			case "oversize":
				size = MaxInputBytes + 1
			case "bad_lease":
				lease = "not-a-lease"
			case "no_lease":
				lease = strings.Repeat("0", 32)
			case "cancelled":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			}
			if _, err := r.Bind(ctx, lease, f, sha, size); err == nil {
				t.Fatal("unverified input accepted")
			}
			if len(r.inputs) != 0 {
				t.Fatal("failed binding created authority")
			}
		})
	}
}

func TestRegistryRejectsWritableUnsafeAndClosedDescriptors(t *testing.T) {
	for _, change := range []string{"writable", "mode", "linked", "directory", "closed"} {
		t.Run(change, func(t *testing.T) {
			r, _, lease, f, data := registryFixture(t)
			source := f
			switch change {
			case "writable":
				var err error
				source, err = os.OpenFile(f.Name(), os.O_RDWR, 0)
				if err != nil {
					t.Fatal(err)
				}
				defer source.Close()
			case "mode":
				if err := os.Chmod(f.Name(), 0644); err != nil {
					t.Fatal(err)
				}
			case "linked":
				if err := os.Link(f.Name(), f.Name()+".hardlink"); err != nil {
					t.Fatal(err)
				}
			case "directory":
				var err error
				source, err = os.Open(filepath.Dir(f.Name()))
				if err != nil {
					t.Fatal(err)
				}
				defer source.Close()
			case "closed":
				f.Close()
			}
			if _, err := r.Bind(context.Background(), lease, source, digest(data), int64(len(data))); err == nil {
				t.Fatal("unsafe FD accepted")
			}
		})
	}
}

func TestRegistryFencesCrossLeaseAndReplay(t *testing.T) {
	r, s, lease, f, data := registryFixture(t)
	ref, err := r.Bind(context.Background(), lease, f, digest(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	other := reserveTest(t, s, 2)
	if _, err := r.Acquire(other, ref); err == nil {
		t.Fatal("cross-lease reference accepted")
	}
	if _, err := r.Bind(context.Background(), lease, f, digest(data), int64(len(data))); err == nil {
		t.Fatal("binding overwritten")
	}
	input, err := r.Acquire(lease, ref)
	if err != nil {
		t.Fatal(err)
	}
	input.Close()
	if _, err := r.Acquire(lease, ref); err == nil {
		t.Fatal("consumed reference replayed")
	}
	if _, err := input.CopyTo(context.Background(), io.Discard); err == nil {
		t.Fatal("closed FD copied")
	}
}

func TestRegistryDetectsSourceMutationBeforeCopy(t *testing.T) {
	r, _, lease, f, data := registryFixture(t)
	ref, err := r.Bind(context.Background(), lease, f, digest(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	input, err := r.Acquire(lease, ref)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	changed := append([]byte{}, data...)
	changed[0] ^= 1
	if err := os.WriteFile(f.Name(), changed, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := input.CopyTo(context.Background(), io.Discard); err == nil {
		t.Fatal("changed plaintext authorized")
	}
}

func TestRegistryCloseDoesNotReleaseOrRecoverHistory(t *testing.T) {
	r, s, lease, f, data := registryFixture(t)
	ref, err := r.Bind(context.Background(), lease, f, digest(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	before := s.Snapshot()
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Acquire(lease, ref); err == nil {
		t.Fatal("closed registry granted FD")
	}
	if _, err := r.Bind(context.Background(), lease, f, digest(data), int64(len(data))); err == nil {
		t.Fatal("closed registry rebound")
	}
	after := s.Snapshot()
	if before.ChargedBytes != after.ChargedBytes || before.RetainedOrReservedJobs != after.RetainedOrReservedJobs {
		t.Fatal("registry release changed durable quota")
	}
}
