//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package ownership

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type publicationConnectionKey struct{}

// PublicationHTTPHandler relays signed authorization only. It never executes a
// job or treats a producer response-write failure as an execution ACK failure.
type PublicationHTTPHandler struct {
	store          *PublicationStore
	pin            AuthorityPin
	authorityScope AcceptanceScope
	mu             sync.Mutex
	active         int
	stopping       bool
	done           chan struct{}
}

func NewPublicationHTTPHandler(store *PublicationStore, pin AuthorityPin, scope AcceptanceScope) (*PublicationHTTPHandler, error) {
	if store == nil || pin.validate() != nil || scope.validate() != nil || store.Check() != nil ||
		pin.AuthorityID != store.config.Pin.AuthorityID || pin.PipelineMode != store.config.Pin.PipelineMode || pin.ExecutionProfileSHA256 != store.config.Pin.ExecutionProfileSHA256 || !bytes.Equal(pin.PublicKey, store.config.Pin.PublicKey) || scope != store.config.AuthorityScope {
		return nil, fail("ownership_publication_http_invalid")
	}
	pin.PublicKey = append(ed25519.PublicKey(nil), pin.PublicKey...)
	return &PublicationHTTPHandler{store: store, pin: pin, authorityScope: scope, done: make(chan struct{})}, nil
}
func (h *PublicationHTTPHandler) StopAdmission() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.stopping {
		h.stopping = true
		if h.active == 0 {
			close(h.done)
		}
	}
}
func (h *PublicationHTTPHandler) Wait(ctx context.Context) error {
	if ctx == nil {
		return fail("ownership_publication_http_context_invalid")
	}
	select {
	case <-h.done:
		return nil
	case <-ctx.Done():
		return fail("ownership_publication_http_pending")
	}
}
func (h *PublicationHTTPHandler) enter() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.stopping || h.active >= 4 {
		return false
	}
	h.active++
	return true
}
func (h *PublicationHTTPHandler) leave() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.active--
	if h.stopping && h.active == 0 {
		close(h.done)
	}
}

// Only the actual TLS connection sealed by our runtime may supply a producer
// principal. Request/header/context lookalikes cannot replace that connection.
func publicationLiveTLS(r *http.Request) (*tls.ConnectionState, error) {
	conn, ok := r.Context().Value(publicationConnectionKey{}).(*tls.Conn)
	if !ok || conn == nil || r.TLS == nil || r.ProtoMajor != 1 || r.ProtoMinor != 1 {
		return nil, fail("ownership_publication_denied")
	}
	state := conn.ConnectionState()
	if state.Version != tls.VersionTLS13 || r.TLS.Version != tls.VersionTLS13 || !state.HandshakeComplete || !r.TLS.HandshakeComplete || len(state.PeerCertificates) == 0 || len(r.TLS.PeerCertificates) == 0 || state.PeerCertificates[0] == nil || r.TLS.PeerCertificates[0] == nil || !bytes.Equal(state.PeerCertificates[0].Raw, r.TLS.PeerCertificates[0].Raw) {
		return nil, fail("ownership_publication_denied")
	}
	if _, err := PrincipalFromTLS(&state); err != nil {
		return nil, fail("ownership_publication_denied")
	}
	now := time.Now()
	validChain := false
	for _, chain := range state.VerifiedChains {
		valid := len(chain) > 0
		for _, cert := range chain {
			if cert == nil || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
				valid = false
				break
			}
		}
		if valid {
			validChain = true
			break
		}
	}
	if !validChain {
		return nil, fail("ownership_publication_denied")
	}
	return &state, nil
}
func publicationHTTPWrite(w http.ResponseWriter, status int, body []byte) error {
	if len(body) > PublicationResponseLimit {
		return fail("ownership_publication_http_response_invalid")
	}
	if err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	w.WriteHeader(status)
	n, err := w.Write(body)
	if err != nil {
		return err
	}
	if n != len(body) {
		return io.ErrShortWrite
	}
	return http.NewResponseController(w).Flush()
}
func publicationHTTPProblem(w http.ResponseWriter, status int, code string) {
	raw, _ := json.Marshal(struct {
		Error string `json:"error"`
	}{code})
	if publicationHTTPWrite(w, status, raw) != nil {
		panic(http.ErrAbortHandler)
	}
}
func (h *PublicationHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.Close = true
	w.Header().Set("Connection", "close")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	control := http.NewResponseController(w)
	// Prevent implicit body draining on early producer denial. TLS/kernel input
	// buffering is not claimed to be absent.
	if control.EnableFullDuplex() != nil || control.SetReadDeadline(time.Now().Add(5*time.Second)) != nil {
		panic(http.ErrAbortHandler)
	}
	if !h.enter() {
		publicationHTTPProblem(w, 503, "ownership_publication_busy")
		return
	}
	defer h.leave()
	state, err := publicationLiveTLS(r)
	if err != nil || h.store.AuthorizeProducer(state) != nil {
		publicationHTTPProblem(w, 403, "ownership_publication_denied")
		return
	}
	if r.URL.IsAbs() || r.URL.Host != "" || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" || len(r.TransferEncoding) != 0 || len(r.Trailer) != 0 || len(r.Header.Values("Trailer")) != 0 || len(r.Header.Values("Content-Encoding")) != 0 {
		publicationHTTPProblem(w, 400, "ownership_publication_request_invalid")
		return
	}
	if r.URL.Path == "/healthz" {
		if r.Method != http.MethodGet || r.ContentLength != 0 {
			publicationHTTPProblem(w, 400, "ownership_publication_request_invalid")
			return
		}
		if h.store.Check() != nil {
			publicationHTTPProblem(w, 503, "ownership_publication_unavailable")
			return
		}
		if publicationHTTPWrite(w, 200, []byte(`{"status":"publication_alive"}`)) != nil {
			panic(http.ErrAbortHandler)
		}
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/acceptances/"), "/")
	if !strings.HasPrefix(r.URL.Path, "/v1/acceptances/") || len(parts) != 2 || !hexValue(parts[0], 16) || !hexValue(parts[1], 64) {
		publicationHTTPProblem(w, 404, "ownership_publication_not_found")
		return
	}
	job, hash := parts[0], parts[1]
	var receipt PublicationReceipt
	switch r.Method {
	case http.MethodPost:
		if len(r.Header.Values("Content-Type")) != 1 || r.Header.Get("Content-Type") != "application/json" || r.ContentLength < 1 || r.ContentLength > MaxAcceptanceBytes {
			publicationHTTPProblem(w, 400, "ownership_publication_request_invalid")
			return
		}
		raw, readErr := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxAcceptanceBytes))
		if readErr != nil || int64(len(raw)) != r.ContentLength || len(r.Trailer) != 0 {
			publicationHTTPProblem(w, 400, "ownership_publication_request_invalid")
			return
		}
		verified, verifyErr := VerifyAcceptance(raw, h.pin, h.authorityScope)
		if verifyErr != nil || verified.Binding().JobID != job || verified.SHA256() != hash || !bytes.Equal(verified.canonical, raw) {
			publicationHTTPProblem(w, 400, "ownership_publication_acceptance_invalid")
			return
		}
		receipt, err = h.store.Publish(r.Context(), state, raw)
	case http.MethodGet:
		if r.ContentLength != 0 {
			publicationHTTPProblem(w, 400, "ownership_publication_request_invalid")
			return
		}
		receipt, err = h.store.Get(r.Context(), state, job, hash)
	default:
		publicationHTTPProblem(w, 405, "ownership_publication_method_invalid")
		return
	}
	if err != nil {
		status := http.StatusServiceUnavailable
		code := "ownership_publication_unavailable"
		if err.Error() == "ownership_publication_not_found" {
			status = http.StatusNotFound
			code = "ownership_publication_not_found"
		}
		if err.Error() == "ownership_publication_denied" || err.Error() == "ownership_publication_role_invalid" {
			status = http.StatusForbidden
			code = "ownership_publication_denied"
		}
		if err.Error() == "ownership_publication_quota" {
			status = http.StatusTooManyRequests
			code = "ownership_publication_quota"
		}
		publicationHTTPProblem(w, status, code)
		return
	}
	if !h.receiptMatches(receipt, job, hash) {
		publicationHTTPProblem(w, 503, "ownership_publication_response_invalid")
		return
	}
	raw, err := json.Marshal(receipt)
	if err != nil || len(raw) > PublicationResponseLimit {
		publicationHTTPProblem(w, 503, "ownership_publication_response_invalid")
		return
	}
	// Publication is already durable. A lost response remains a local transport
	// failure; a later explicit GET can recover the same retained receipt.
	if publicationHTTPWrite(w, 200, raw) != nil {
		panic(http.ErrAbortHandler)
	}
}
func (h *PublicationHTTPHandler) receiptMatches(r PublicationReceipt, job, hash string) bool {
	return r.SchemaVersion == 1 && r.Domain == PublicationReceiptDomain && r.State == "published" && r.PublisherScope == h.store.Scope() && r.AuthorityScope == h.authorityScope && r.JobID == job && r.AcceptanceSHA256 == hash && hexValue(r.CredentialSHA256, 64) && r.ExecutionProfileSHA256 == h.pin.ExecutionProfileSHA256 && r.PipelineMode == h.pin.PipelineMode
}
