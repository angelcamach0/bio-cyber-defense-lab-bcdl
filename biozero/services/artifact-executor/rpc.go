package artifactexecutor

import (
	"encoding/binary"
	"io"
)

const MaxFrameBytes = 64 << 10
const MaxInputBytes int64 = 25 << 20

// Framing/types only. This is not a running authenticated Unix RPC server.
// Caller requests cannot submit proofs, paths, commands, images, mounts or policy.
type Request struct {
	SchemaVersion int    `json:"schema_version"`
	Operation     string `json:"operation"`
	LeaseID       string `json:"lease_id"`
	InputRef      string `json:"input_ref"`
}

func ReadRequest(r io.Reader) (Request, error) {
	var q Request
	var header [4]byte
	if _, e := io.ReadFull(r, header[:]); e != nil {
		return q, fail("artifact_frame_invalid")
	}
	n := binary.BigEndian.Uint32(header[:])
	if n == 0 || n > MaxFrameBytes {
		return q, fail("artifact_frame_oversized")
	}
	b := make([]byte, n)
	if _, e := io.ReadFull(r, b); e != nil {
		return q, fail("artifact_frame_invalid")
	}
	if strictJSON(b, &q) != nil {
		return q, fail("artifact_request_invalid")
	}
	if q.SchemaVersion != 1 || !hexID(q.LeaseID, 32) {
		return q, fail("artifact_request_invalid")
	}
	switch q.Operation {
	case "run":
		if !hexID(q.InputRef, 32) {
			return q, fail("artifact_request_invalid")
		}
	case "status", "cancel":
		if q.InputRef != "" {
			return q, fail("artifact_request_invalid")
		}
	default:
		return q, fail("artifact_request_invalid")
	}
	return q, nil
}
func WriteFrame(w io.Writer, b []byte) error {
	if len(b) == 0 || len(b) > MaxFrameBytes {
		return fail("artifact_frame_oversized")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(b)))
	for _, part := range [][]byte{header[:], b} {
		for len(part) > 0 {
			n, e := w.Write(part)
			if e != nil || n <= 0 || n > len(part) {
				return fail("artifact_frame_failed")
			}
			part = part[n:]
		}
	}
	return nil
}
