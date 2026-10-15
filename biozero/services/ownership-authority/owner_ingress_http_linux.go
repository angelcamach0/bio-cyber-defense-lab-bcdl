//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package ownership

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const OwnerIngressFrameLimit = 8 + MaxAcceptanceBytes + 512

// OwnerIngressHandler requires a direct verified mTLS HTTP/1.1 server. It owns
// admission/handler lifetimes, not Store.Close. Its receipt means transport only.
type OwnerIngressHandler struct {
	store                     *OwnerIngressStore
	mu                        sync.Mutex
	stopping                  bool
	active                    int
	done                      chan struct{}
	readTimeout, writeTimeout time.Duration
}

func NewOwnerIngressHandler(store *OwnerIngressStore) (*OwnerIngressHandler, error) {
	if store == nil || !store.Healthy() {
		return nil, fail("ownership_ingress_unavailable")
	}
	return &OwnerIngressHandler{store: store, done: make(chan struct{}), readTimeout: 30 * time.Second, writeTimeout: 10 * time.Second}, nil
}
func (h *OwnerIngressHandler) StopAdmission() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.stopping {
		h.stopping = true
		if h.active == 0 {
			close(h.done)
		}
	}
}
func (h *OwnerIngressHandler) Wait(ctx context.Context) error {
	if ctx == nil {
		return fail("ownership_ingress_pending")
	}
	select {
	case <-h.done:
		return nil
	case <-ctx.Done():
		return fail("ownership_ingress_pending")
	}
}
func (h *OwnerIngressHandler) enter() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.stopping || h.active >= 4 {
		return false
	}
	h.active++
	return true
}
func (h *OwnerIngressHandler) leave() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.active--
	if h.stopping && h.active == 0 {
		close(h.done)
	}
}
func (h *OwnerIngressHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.Close = true
	w.Header().Set("Connection", "close")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	control := http.NewResponseController(w)
	if control.EnableFullDuplex() != nil || control.SetReadDeadline(time.Now().Add(h.readTimeout)) != nil {
		panic(http.ErrAbortHandler)
	}
	if !h.enter() {
		h.problem(w, r, 503, "ownership_ingress_busy")
		return
	}
	defer h.leave()
	if _, e := PrincipalFromTLS(r.TLS); e != nil || r.TLS.Version < tls.VersionTLS13 {
		h.problem(w, r, 403, "ownership_denied")
		return
	}
	if r.ProtoMajor != 1 || r.ProtoMinor != 1 || r.URL == nil || r.URL.IsAbs() || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.Fragment != "" || len(r.TransferEncoding) != 0 || len(r.Trailer) != 0 || len(r.Header.Values("Trailer")) != 0 || len(r.Header.Values("Content-Encoding")) != 0 || len(r.Header.Values("Expect")) != 0 || len(r.Header.Values("Upgrade")) != 0 {
		h.problem(w, r, 400, "ownership_ingress_transport_invalid")
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/healthz" {
		if r.ContentLength != 0 {
			h.problem(w, r, 400, "ownership_ingress_transport_invalid")
			return
		}
		if !h.store.Healthy() {
			h.problem(w, r, 503, "ownership_ingress_unavailable")
			return
		}
		h.generic(w, r, 200, []byte("{\"status\":\"ok\"}\n"))
		return
	}
	var receipt OwnerUploadReceipt
	var err error
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v1/uploads":
		if r.ContentLength < 8+1+256+16 || r.ContentLength > MaxCiphertextBytes+OwnerIngressFrameLimit {
			h.problem(w, r, 413, "ownership_ingress_payload_invalid")
			return
		}
		if len(r.Header.Values("Content-Type")) != 1 || r.Header.Get("Content-Type") != "application/octet-stream" {
			h.problem(w, r, 400, "ownership_ingress_transport_invalid")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, MaxCiphertextBytes+OwnerIngressFrameLimit)
		readFrame := func(limit int) ([]byte, error) {
			var size [4]byte
			if _, e := io.ReadFull(r.Body, size[:]); e != nil {
				return nil, e
			}
			n := int(binary.BigEndian.Uint32(size[:]))
			if n < 1 || n > limit {
				return nil, io.ErrUnexpectedEOF
			}
			raw := make([]byte, n)
			_, e := io.ReadFull(r.Body, raw)
			return raw, e
		}
		a, e := readFrame(MaxAcceptanceBytes)
		if e != nil {
			h.problem(w, r, 400, "ownership_ingress_frame_invalid")
			return
		}
		envelope, e := readFrame(512)
		if e != nil || len(envelope) < 256 {
			h.problem(w, r, 400, "ownership_ingress_frame_invalid")
			return
		}
		// Store verifies signatures/TLS/envelope before it ever calls this reader.
		receipt, err = h.store.Accept(r.Context(), r.TLS, a, envelope, r.Body, r.ContentLength-int64(8+len(a)+len(envelope)))
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/uploads/"):
		if r.ContentLength != 0 {
			h.problem(w, r, 400, "ownership_ingress_transport_invalid")
			return
		}
		receipt, err = h.store.Get(r.Context(), r.TLS, strings.TrimPrefix(r.URL.Path, "/v1/uploads/"))
	default:
		h.problem(w, r, 404, "ownership_ingress_route_invalid")
		return
	}
	if err != nil {
		code, status := ownerIngressPublicError(err)
		h.problem(w, r, status, code)
		return
	}
	raw, e := json.Marshal(receipt)
	if e != nil || len(raw) > 2048 {
		panic(http.ErrAbortHandler)
	}
	raw = append(raw, '\n')
	write := func() error {
		if r.Context().Err() != nil {
			return r.Context().Err()
		}
		if e := control.SetWriteDeadline(time.Now().Add(h.writeTimeout)); e != nil {
			return e
		}
		n, e := w.Write(raw)
		if e != nil {
			return e
		}
		if n != len(raw) {
			return io.ErrShortWrite
		}
		return control.Flush()
	}
	if h.store.deliver(r.Context(), receipt, write) != nil {
		panic(http.ErrAbortHandler)
	}
}
func ownerIngressPublicError(e error) (string, int) {
	switch e.Error() {
	case "ownership_denied":
		return "ownership_denied", 403
	case "ownership_ingress_quota":
		return "ownership_ingress_quota", 429
	case "ownership_ingress_pending", "ownership_ingress_conflict":
		return "ownership_ingress_pending", 409
	case "ownership_ingress_payload_invalid", "ownership_ingress_job_invalid":
		return "ownership_ingress_payload_invalid", 400
	case "ownership_cancelled":
		return "ownership_cancelled", 400
	default:
		return "ownership_ingress_unavailable", 503
	}
}
func (h *OwnerIngressHandler) problem(w http.ResponseWriter, r *http.Request, status int, code string) {
	raw, _ := json.Marshal(struct {
		Error string `json:"error"`
	}{code})
	h.generic(w, r, status, append(raw, '\n'))
}
func (h *OwnerIngressHandler) generic(w http.ResponseWriter, r *http.Request, status int, raw []byte) {
	c := http.NewResponseController(w)
	if r.Context().Err() != nil || c.SetWriteDeadline(time.Now().Add(h.writeTimeout)) != nil {
		panic(http.ErrAbortHandler)
	}
	w.WriteHeader(status)
	n, e := w.Write(raw)
	if e != nil || n != len(raw) || c.Flush() != nil {
		panic(http.ErrAbortHandler)
	}
}
