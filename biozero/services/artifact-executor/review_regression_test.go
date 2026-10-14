package artifactexecutor

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestNonemptyInstanceLockRejectsWithoutBaselineOrDeletion(t *testing.T) {
	for _, size := range []int64{5, 1 << 30} {
		t.Run(itoaSize(size), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "store")
			if e := os.Mkdir(path, 0700); e != nil {
				t.Fatal(e)
			}
			lockPath := filepath.Join(path, "instance.lock")
			f, e := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
			if e != nil {
				t.Fatal(e)
			}
			content := []byte("keep!")
			if _, e = f.Write(content); e != nil {
				t.Fatal(e)
			}
			if e = f.Truncate(size); e != nil {
				t.Fatal(e)
			}
			f.Close()
			if s, e := Open(context.Background(), path, testPolicy(1)); e == nil {
				s.Close()
				t.Fatal("nonempty lock admitted")
			}
			if _, e = os.Stat(filepath.Join(path, "ledger.json")); !os.IsNotExist(e) {
				t.Fatal("baseline ledger created")
			}
			current, e := os.Open(lockPath)
			if e != nil {
				t.Fatal("lock deleted")
			}
			defer current.Close()
			st, e := current.Stat()
			if e != nil || st.Size() != size {
				t.Fatal("lock resized")
			}
			b := make([]byte, len(content))
			if _, e = io.ReadFull(current, b); e != nil || !bytes.Equal(b, content) {
				t.Fatal("lock content changed")
			}
		})
	}
}
func itoaSize(n int64) string {
	if n == 5 {
		return "content"
	}
	return "sparse_oversized"
}

func TestFailedCommitKeepsPreparedStateAndFullReservation(t *testing.T) {
	for _, point := range []string{"write", "file_sync", "rename", "directory_sync"} {
		t.Run(point, func(t *testing.T) {
			s, _, _ := openTest(t, 1)
			l := prepareTest(t, s, 1)
			if e := s.RecordQuiescence(l, proofFor(s, l)); e != nil {
				t.Fatal(e)
			}
			before := s.Snapshot().ChargedBytes
			old := s.data.Records[l]
			s.fault = func(x string) error {
				if x == point {
					return io.ErrClosedPipe
				}
				return nil
			}
			if e := s.Commit(l); e == nil {
				t.Fatal("commit persistence failure hidden")
			}
			after := s.Snapshot()
			if after.ChargedBytes != before {
				t.Fatal("ambiguous commit reduced reservation")
			}
			if after.Healthy {
				t.Fatal("ambiguous commit did not latch")
			}
			r := s.data.Records[l]
			if r.State != "prepared" || r.Charge != old.Charge || r.ManifestSHA256 != old.ManifestSHA256 || r.ProofSHA256 != old.ProofSHA256 {
				t.Fatal("ambiguous commit replaced prepared record")
			}
			called := false
			if e := s.Acknowledge(l, func() error { called = true; return nil }); e == nil || called {
				t.Fatal("ambiguous commit acknowledged")
			}
		})
	}
}
