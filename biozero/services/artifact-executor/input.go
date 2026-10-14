package artifactexecutor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
)

// ReceiveInput is a bounded transfer primitive for a future authenticated
// capsule channel. It never opens paths. The worker's already verified plaintext
// digest must be supplied independently; transport metadata is not authority.
// Generic Reader cancellation is checked between reads. A future Unix server
// must also apply socket deadlines so a blocked network read can be cancelled.
func ReceiveInput(ctx context.Context, dst io.Writer, src io.Reader, expectedBytes int64, expectedSHA string) (int64, error) {
	if expectedBytes < 0 || expectedBytes > MaxInputBytes || !hexID(expectedSHA, 64) {
		return 0, fail("artifact_input_invalid")
	}
	h := sha256.New()
	buf := make([]byte, 65536)
	var size int64
	for {
		if ctx.Err() != nil {
			return size, fail("artifact_cancelled")
		}
		want := int64(len(buf))
		if expectedBytes-size+1 < want {
			want = expectedBytes - size + 1
		}
		n, e := src.Read(buf[:want])
		if n < 0 || int64(n) > want {
			return size, fail("artifact_input_invalid")
		}
		if n == 0 && e == nil {
			return size, fail("artifact_input_no_progress")
		}
		if size+int64(n) > expectedBytes {
			return size, fail("artifact_input_oversized")
		}
		if n > 0 {
			written, we := dst.Write(buf[:n])
			if we != nil || written != n {
				return size, fail("artifact_input_write_failed")
			}
			size += int64(n)
			h.Write(buf[:n])
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return size, fail("artifact_input_read_failed")
		}
	}
	if size != expectedBytes || hex.EncodeToString(h.Sum(nil)) != expectedSHA {
		return size, fail("artifact_input_digest_mismatch")
	}
	return size, nil
}
