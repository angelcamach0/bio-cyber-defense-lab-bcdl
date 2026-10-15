// SPDX-License-Identifier: AGPL-3.0-only
package ownership

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

func TestFinalizeExactShortExcessHashAndReaderFailures(t *testing.T) {
	f := fixture(t)
	body := bytes.Repeat([]byte("x"), 32)
	raw, manifest, _ := signed(t, f, body)
	for _, tc := range []struct {
		name string
		r    io.Reader
		code string
	}{
		{"exact", bytes.NewReader(body), ""},
		{"short", bytes.NewReader(body[:31]), "ownership_ciphertext_size_mismatch"},
		{"one extra", bytes.NewReader(append(append([]byte(nil), body...), 1)), "ownership_ciphertext_size_mismatch"},
		{"hash", bytes.NewReader(bytes.Repeat([]byte("y"), 32)), "ownership_ciphertext_hash_mismatch"},
		{"nil", nil, "ownership_ciphertext_reader_invalid"},
		{"read error", readerFunc(func([]byte) (int, error) { return 0, errors.New("SECRET path/cert") }), "ownership_ciphertext_read_failed"},
		{"no progress", readerFunc(func([]byte) (int, error) { return 0, nil }), "ownership_ciphertext_read_failed"},
		{"invalid count", readerFunc(func(p []byte) (int, error) { return len(p) + 1, nil }), "ownership_ciphertext_read_failed"},
		{"negative count", readerFunc(func([]byte) (int, error) { return -1, nil }), "ownership_ciphertext_read_failed"},
		{"bytes and EOF", readerFunc(func(p []byte) (int, error) { return copy(p, body), io.EOF }), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			binding, err := Finalize(context.Background(), &f.stateA, raw, manifest, f.pin, tc.r, f.now)
			if tc.code == "" {
				if err != nil {
					t.Fatal(err)
				}
				if binding.CiphertextSHA256 != digest(body) {
					t.Fatal("missing binding")
				}
			} else {
				if err == nil || err.Error() != tc.code {
					t.Fatalf("got %v, want %s", err, tc.code)
				}
				if binding != (Binding{}) {
					t.Fatal("partial binding escaped")
				}
			}
		})
	}
	large := &observedReader{r: io.LimitReader(zeroReader{}, MaxCiphertextBytes+100)}
	_, err := Finalize(context.Background(), &f.stateA, raw, manifest, f.pin, large, f.now)
	if err == nil || large.bytes != len(body)+1 {
		t.Fatalf("unbounded excess read: bytes=%d err=%v", large.bytes, err)
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }

func TestCiphertextMaximumAndManifestBounds(t *testing.T) {
	f := fixture(t)
	_, _, v := signed(t, f, bytes.Repeat([]byte("x"), 32))
	hash := sha256.New()
	_, _ = io.Copy(hash, io.LimitReader(zeroReader{}, MaxCiphertextBytes))
	sum := hex.EncodeToString(hash.Sum(nil))
	for _, size := range []int64{16, MaxCiphertextBytes} {
		t.Run(time.Duration(size).String(), func(t *testing.T) {
			h := sum
			if size == 16 {
				h = digest(make([]byte, 16))
			}
			sm, err := SignManifest(f.keyA, f.certA, v, ManifestInput{h, size, strings.Repeat("4", 64)})
			if err != nil {
				t.Fatal(err)
			}
			wire, _ := MarshalManifest(sm)
			var challenge SignedChallenge
			owner, _ := PrincipalFromTLS(&f.stateA)
			challenge, err = SignChallenge(f.private, f.pin, owner, ChallengeInput{"1234567890abcdef", strings.Repeat("3", 64), "sample.fastq", f.now, f.now.Add(5 * time.Minute)})
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := MarshalChallenge(challenge)
			reader := &observedReader{r: io.LimitReader(zeroReader{}, size)}
			binding, err := Finalize(context.Background(), &f.stateA, raw, wire, f.pin, reader, f.now)
			if err != nil || binding.CiphertextBytes != size || int64(reader.bytes) != size {
				t.Fatalf("boundary failure: %v", err)
			}
		})
	}
	for _, size := range []int64{-1, 0, 15, MaxCiphertextBytes + 1} {
		if _, err := SignManifest(f.keyA, f.certA, v, ManifestInput{sum, size, strings.Repeat("4", 64)}); err == nil {
			t.Fatalf("size %d accepted", size)
		}
	}
}

func TestFinalizeCancellationAndExpiry(t *testing.T) {
	f := fixture(t)
	body := bytes.Repeat([]byte("x"), 32)
	raw, manifest, _ := signed(t, f, body)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := &observedReader{r: bytes.NewReader(body)}
	if _, err := Finalize(ctx, &f.stateA, raw, manifest, f.pin, r, f.now); err == nil || r.calls != 0 {
		t.Fatal("cancelled operation read data")
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	r2 := readerFunc(func(p []byte) (int, error) { cancel(); return copy(p, body), io.EOF })
	if binding, err := Finalize(ctx, &f.stateA, raw, manifest, f.pin, r2, f.now); err == nil || binding != (Binding{}) {
		t.Fatal("cancelled during read accepted")
	}
	if _, err := Finalize(context.Background(), &f.stateA, raw, manifest, f.pin, bytes.NewReader(body), f.now.Add(5*time.Minute-time.Nanosecond)); err == nil || err.Error() != "ownership_challenge_expired" {
		t.Fatalf("expiry crossed during finalize accepted: %v", err)
	}
}

func TestManifestCannotRebindToAnotherChallenge(t *testing.T) {
	f := fixture(t)
	body := bytes.Repeat([]byte("x"), 32)
	_, manifest, _ := signed(t, f, body)
	owner, _ := PrincipalFromTLS(&f.stateA)
	for _, change := range []string{"job", "nonce", "name"} {
		t.Run(change, func(t *testing.T) {
			in := ChallengeInput{"1234567890abcdef", strings.Repeat("3", 64), "sample.fastq", f.now, f.now.Add(5 * time.Minute)}
			switch change {
			case "job":
				in.JobID = "fedcba0987654321"
			case "nonce":
				in.Nonce = strings.Repeat("5", 64)
			case "name":
				in.OriginalName = "other.fastq"
			}
			signedChallenge, err := SignChallenge(f.private, f.pin, owner, in)
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := MarshalChallenge(signedChallenge)
			reader := &observedReader{r: bytes.NewReader(body)}
			if _, err := Finalize(context.Background(), &f.stateA, raw, manifest, f.pin, reader, f.now); err == nil || reader.calls != 0 {
				t.Fatal("rebound manifest accepted or read ciphertext")
			}
		})
	}
}
