//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package ownership

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	HTTPReserveLimit  = 1024
	HTTPHeaderLimit   = 16 << 10
	HTTPFrameOverhead = 8 + 2*4096
	HTTPResponseLimit = MaxAcceptanceBytes + MaxChallengeBytes + 1024
	HTTPReadTimeout   = 30 * time.Second
	HTTPWriteTimeout  = 10 * time.Second
)

type HTTPHandlerConfig struct{ Store *Store }

// AuthorityHTTPHandler owns admission and request lifetimes, never Store.Close.
// It must be served directly over verified client-authenticated TLS and HTTP/1.1.
type AuthorityHTTPHandler struct {
	store        *Store
	mu           sync.Mutex
	stopping     bool
	active       int
	done         chan struct{}
	readTimeout  time.Duration
	writeTimeout time.Duration
}

func NewHTTPHandler(config HTTPHandlerConfig) (*AuthorityHTTPHandler, error) {
	if config.Store == nil || !config.Store.Healthy() {
		return nil, fail("ownership_http_store_unavailable")
	}
	return &AuthorityHTTPHandler{store: config.Store, done: make(chan struct{}), readTimeout: HTTPReadTimeout, writeTimeout: HTTPWriteTimeout}, nil
}

func (h *AuthorityHTTPHandler) StopAdmission() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.stopping {
		h.stopping = true
		if h.active == 0 {
			close(h.done)
		}
	}
}
func (h *AuthorityHTTPHandler) Wait(ctx context.Context) error {
	if ctx == nil {
		return fail("ownership_http_context_invalid")
	}
	select {
	case <-h.done:
		return nil
	case <-ctx.Done():
		return fail("ownership_http_handlers_pending")
	}
}
func (h *AuthorityHTTPHandler) enter() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.stopping || h.active >= 4 {
		return false
	}
	h.active++
	return true
}
func (h *AuthorityHTTPHandler) leave() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.active--
	if h.stopping && h.active == 0 {
		close(h.done)
	}
}

// Write failure is release uncertainty, even if the signed acceptance committed.
// Keep the lifetime lock, accepted bytes and full charge until actual process exit.
// The callback is bounded by the real connection deadline and cannot reenter Store.
func (s *Store) deliverHTTP(ctx context.Context, write func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.preflight(); err != nil {
		return err
	}
	if ctx == nil || ctx.Err() != nil {
		return fail("ownership_cancelled")
	}
	if err := write(); err != nil {
		return s.latch("ownership_http_delivery_failed")
	}
	return nil
}

type HTTPReserveRequest struct {
	SchemaVersion int    `json:"schema_version"`
	RequestID     string `json:"request_id"`
	OriginalName  string `json:"original_name"`
}
type HTTPJobResponse struct {
	SchemaVersion int               `json:"schema_version"`
	State         string            `json:"state"`
	Challenge     SignedChallenge   `json:"challenge"`
	Acceptance    *SignedAcceptance `json:"acceptance,omitempty"`
	FailureCode   string            `json:"failure_code,omitempty"`
}
type httpErrorResponse struct {
	Error string `json:"error"`
}

func (h *AuthorityHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// One request per connection. FullDuplex disables net/http's implicit body
	// drain before an early response; TLS/kernel buffering is not prevented.
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
		h.problem(w, r, http.StatusServiceUnavailable, "ownership_http_busy")
		return
	}
	defer h.leave()
	if _, err := PrincipalFromTLS(r.TLS); err != nil {
		h.problem(w, r, http.StatusForbidden, "ownership_denied")
		return
	}
	if r.ProtoMajor != 1 || r.ProtoMinor != 1 || r.URL == nil || r.URL.IsAbs() || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.Fragment != "" ||
		len(r.TransferEncoding) != 0 || len(r.Trailer) != 0 || len(r.Header.Values("Trailer")) != 0 || len(r.Header.Values("Content-Encoding")) != 0 || len(r.Header.Values("Upgrade")) != 0 || len(r.Header.Values("Expect")) != 0 {
		h.problem(w, r, http.StatusBadRequest, "ownership_http_transport_invalid")
		return
	}
	headerBytes := len(r.RequestURI) + len(r.Host)
	for k, values := range r.Header {
		headerBytes += len(k)
		for _, v := range values {
			headerBytes += len(v) + 4
		}
	}
	if headerBytes > HTTPHeaderLimit {
		h.problem(w, r, http.StatusRequestHeaderFieldsTooLarge, "ownership_http_headers_oversized")
		return
	}
	if !h.store.Healthy() {
		h.problem(w, r, http.StatusServiceUnavailable, "ownership_store_unavailable")
		return
	}
	switch {
	case r.URL.Path == "/healthz":
		if r.Method != http.MethodGet || r.ContentLength != 0 {
			h.problem(w, r, http.StatusBadRequest, "ownership_http_request_invalid")
			return
		}
		h.send(w, r, http.StatusOK, []byte(`{"status":"ok"}`), false)
	case r.URL.Path == "/v1/reservations":
		if !h.bodyShape(w, r, http.MethodPost, "application/json", 1, HTTPReserveLimit) {
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, HTTPReserveLimit))
		if err != nil || int64(len(raw)) != r.ContentLength {
			h.problem(w, r, http.StatusBadRequest, "ownership_http_body_invalid")
			return
		}
		var request HTTPReserveRequest
		if strictJSON(raw, &request, HTTPReserveLimit) != nil || request.SchemaVersion != 1 {
			h.problem(w, r, http.StatusBadRequest, "ownership_http_reserve_invalid")
			return
		}
		ch, err := h.store.Reserve(r.TLS, request.RequestID, request.OriginalName, time.Now().UTC().Truncate(time.Second))
		if err != nil {
			h.storeProblem(w, r, err)
			return
		}
		out, err := MarshalChallenge(ch)
		if err != nil {
			panic(http.ErrAbortHandler)
		}
		h.send(w, r, http.StatusOK, out, true)
	case r.URL.Path == "/v1/finalizations":
		if !h.bodyShape(w, r, http.MethodPost, "application/octet-stream", 26, h.store.config.Policy.MaxBodyBytes+HTTPFrameOverhead+1) {
			return
		}
		body := http.MaxBytesReader(w, r.Body, h.store.config.Policy.MaxBodyBytes+HTTPFrameOverhead+1)
		challenge, err := httpFrame(body, MaxChallengeBytes)
		if err != nil {
			h.problem(w, r, http.StatusBadRequest, "ownership_http_frame_invalid")
			return
		}
		manifest, err := httpFrame(body, MaxManifestBytes)
		if err != nil {
			h.problem(w, r, http.StatusBadRequest, "ownership_http_frame_invalid")
			return
		}
		accepted, err := h.store.Finalize(r.Context(), r.TLS, challenge, manifest, body, time.Now().UTC())
		if err != nil {
			h.storeProblem(w, r, err)
			return
		}
		out, err := MarshalAcceptance(accepted)
		if err != nil {
			panic(http.ErrAbortHandler)
		}
		h.send(w, r, http.StatusOK, out, true)
	case strings.HasPrefix(r.URL.Path, "/v1/jobs/"):
		job := strings.TrimPrefix(r.URL.Path, "/v1/jobs/")
		if r.Method != http.MethodGet || r.ContentLength != 0 || !hexValue(job, 16) {
			h.problem(w, r, http.StatusBadRequest, "ownership_http_request_invalid")
			return
		}
		record, err := h.store.Get(r.TLS, job)
		if err != nil {
			h.storeProblem(w, r, err)
			return
		}
		out, err := json.Marshal(HTTPJobResponse{1, record.State, record.Challenge, record.Acceptance, record.FailureCode})
		if err != nil || len(out) > HTTPResponseLimit {
			panic(http.ErrAbortHandler)
		}
		h.send(w, r, http.StatusOK, out, true)
	default:
		h.problem(w, r, http.StatusNotFound, "ownership_http_not_found")
	}
}

func httpFrame(r io.Reader, limit int) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, fail("ownership_http_frame_invalid")
	}
	n := binary.BigEndian.Uint32(header[:])
	if n == 0 || uint64(n) > uint64(limit) {
		return nil, fail("ownership_http_frame_invalid")
	}
	b := make([]byte, int(n))
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, fail("ownership_http_frame_invalid")
	}
	return b, nil
}
func (h *AuthorityHTTPHandler) bodyShape(w http.ResponseWriter, r *http.Request, method, kind string, min, max int64) bool {
	if r.Method != method || len(r.Header.Values("Content-Type")) != 1 || r.Header.Get("Content-Type") != kind || r.ContentLength < min || r.ContentLength > max {
		h.problem(w, r, http.StatusBadRequest, "ownership_http_request_invalid")
		return false
	}
	return true
}
func (h *AuthorityHTTPHandler) storeProblem(w http.ResponseWriter, r *http.Request, err error) {
	code := err.Error()
	status := http.StatusBadRequest
	switch code {
	case "ownership_denied", "ownership_tls_identity_invalid", "ownership_certificate_invalid":
		status = http.StatusForbidden
		code = "ownership_denied"
	case "ownership_request_conflict", "ownership_reading_pending":
		status = http.StatusConflict
	case "ownership_quota_exceeded":
		status = http.StatusTooManyRequests
	case "ownership_free_space_floor":
		status = http.StatusInsufficientStorage
	case "ownership_capacity_unavailable":
		status = http.StatusServiceUnavailable
	case "ownership_cancelled":
		status = http.StatusRequestTimeout
	default:
		if !h.store.Healthy() {
			status = http.StatusServiceUnavailable
			code = "ownership_store_unavailable"
		}
	}
	h.problem(w, r, status, code)
}
func (h *AuthorityHTTPHandler) problem(w http.ResponseWriter, r *http.Request, status int, code string) {
	code = httpPublicCode(code)
	b, _ := json.Marshal(httpErrorResponse{code})
	h.send(w, r, status, b, false)
}

func httpPublicCode(code string) string {
	switch code {
	case "ownership_denied", "ownership_store_unavailable", "ownership_request_conflict", "ownership_reading_pending",
		"ownership_quota_exceeded", "ownership_free_space_floor", "ownership_capacity_unavailable", "ownership_cancelled",
		"ownership_request_invalid", "ownership_quota_principal_invalid", "ownership_manifest_body_limit",
		"ownership_challenge_expired", "ownership_challenge_invalid", "ownership_manifest_invalid", "ownership_manifest_owner_mismatch",
		"ownership_signature_invalid", "ownership_time_invalid", "ownership_ciphertext_hash_mismatch", "ownership_ciphertext_read_failed", "ownership_ciphertext_size_mismatch",
		"ownership_json_size_invalid", "ownership_json_invalid", "ownership_json_trailing", "ownership_json_type_invalid", "ownership_json_key_invalid", "ownership_json_fields_invalid", "ownership_json_depth_invalid",
		"ownership_http_busy", "ownership_http_transport_invalid", "ownership_http_headers_oversized", "ownership_http_request_invalid", "ownership_http_body_invalid", "ownership_http_reserve_invalid", "ownership_http_frame_invalid", "ownership_http_not_found":
		return code
	default:
		return "ownership_http_request_invalid"
	}
}
func (h *AuthorityHTTPHandler) send(w http.ResponseWriter, r *http.Request, status int, raw []byte, protected bool) {
	if len(raw) == 0 || len(raw) > HTTPResponseLimit || r.Context().Err() != nil {
		panic(http.ErrAbortHandler)
	}
	write := func() error {
		control := http.NewResponseController(w)
		if control.SetWriteDeadline(time.Now().Add(h.writeTimeout)) != nil {
			return fail("ownership_http_deadline_failed")
		}
		if r.Context().Err() != nil {
			return fail("ownership_cancelled")
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(raw)))
		w.WriteHeader(status)
		n, err := w.Write(raw)
		if err != nil || n != len(raw) {
			return fail("ownership_http_write_failed")
		}
		if control.Flush() != nil {
			return fail("ownership_http_flush_failed")
		}
		return nil
	}
	if protected {
		if h.store.deliverHTTP(r.Context(), write) != nil {
			panic(http.ErrAbortHandler)
		}
	} else if write() != nil {
		panic(http.ErrAbortHandler)
	}
}
