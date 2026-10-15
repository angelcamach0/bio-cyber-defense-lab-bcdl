// SPDX-License-Identifier: AGPL-3.0-only
// Upload API for BioZero: accepts FASTQ uploads from the UI and uploader-cli,
// stores payloads and job records for enclave-runner, and exposes /health for
// system checks; it optionally enforces mTLS and wraps sensitive job fields at rest.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// jobRecord captures upload metadata that the runner uses to process work.
type jobRecord struct {
	JobID             string `json:"job_id"`
	Status            string `json:"status"`
	UploadedAt        string `json:"uploaded_at"`
	OriginalName      string `json:"original_name"`
	SizeBytes         int64  `json:"size_bytes"`
	SHA256            string `json:"sha256"`
	ClientID          string `json:"client_id"`
	EncAlg            string `json:"enc_alg,omitempty"`
	EncKey            string `json:"enc_key,omitempty"`
	EncKeyWrapped     bool   `json:"enc_key_wrapped,omitempty"`
	EncKeyWrapAlg     string `json:"enc_key_wrap_alg,omitempty"`
	SigAlg            string `json:"sig_alg,omitempty"`
	Sig               string `json:"sig,omitempty"`
	ClientCertSubject string `json:"client_cert_subject,omitempty"`
	ClientCertIssuer  string `json:"client_cert_issuer,omitempty"`
	ClientCertSerial  string `json:"client_cert_serial,omitempty"`
}

// errorResponse standardizes error payloads returned by API handlers.
type errorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

/// main registers HTTP handlers and starts the upload API server.
///
/// Brief description of what the function does.
/// - Boots the upload API, wires health and upload endpoints, and enables TLS/mTLS.
///
/// Parameters:
///   None.
///
/// Returns no value; the process exits on fatal server errors.
///
/// Throws [FatalServerError] when TLS setup fails or the listener cannot start.
///
/// Example: `go run ./main.go`
func validateServerSecurity(certPath, keyPath, caPath string) error {
	mode := envOr("BIOZERO_SECURITY_MODE", "protected")
	if mode != "protected" && mode != "demo" {
		return fmt.Errorf("BIOZERO_SECURITY_MODE must be protected or demo")
	}
	if mode == "protected" && (certPath == "" || keyPath == "" || caPath == "") {
		return fmt.Errorf("protected mode requires server certificate, key, and client CA")
	}
	if (certPath == "") != (keyPath == "") {
		return fmt.Errorf("TLS certificate and key must be supplied together")
	}
	return nil
}
func uploadIdentity(r *http.Request) (string, error) {
	supplied := r.FormValue("client_id")
	if r.TLS != nil {
		if len(r.TLS.PeerCertificates) == 0 || len(r.TLS.VerifiedChains) == 0 {
			return "", fmt.Errorf("verified client certificate required")
		}
		owner := r.TLS.PeerCertificates[0].Subject.CommonName
		if !isValidClientID(owner) || (supplied != "" && supplied != owner) {
			return "", fmt.Errorf("client identity disagrees with certificate")
		}
		return owner, nil
	}
	if envOr("BIOZERO_SECURITY_MODE", "protected") != "demo" {
		return "", fmt.Errorf("mTLS required")
	}
	if supplied == "" {
		supplied = r.Header.Get("X-Client-Id")
	}
	if !isValidClientID(supplied) {
		return "", fmt.Errorf("invalid client identity")
	}
	return supplied, nil
}

const maxJobMetadataBytes = 64 << 10
const maxJobErrorCodeBytes = 64
const maxJobErrorMessageBytes = 512

// Reserve the exact current worker lifecycle fields without truncating any
// submitted metadata. NUL maximizes JSON expansion: six encoded bytes per byte.
func projectedJobJSON(job jobRecord) ([]byte, error) {
	job.Status = "incomplete" // Longest current persisted status: ten bytes.
	return json.MarshalIndent(struct {
		jobRecord
		StartedAt    string `json:"started_at"`
		ErrorCode    string `json:"error_code"`
		ErrorMessage string `json:"error_message"`
	}{job, "2000-01-01T00:00:00Z", strings.Repeat("\x00", maxJobErrorCodeBytes), strings.Repeat("\x00", maxJobErrorMessageBytes)}, "", "  ")
}

// uploadAdmissionHandler owns one lifetime-locked admission store.
type uploadAdmissionHandler struct {
	store   *admissionStore
	limiter *rateLimiter
	jobKey  string
	initErr error
}

func newUploadHandler(uploadDir, jobsDir string, maxUploadBytes int64, jobKey string, limiter *rateLimiter) http.Handler {
	dataDir := filepath.Dir(uploadDir)
	if filepath.Clean(jobsDir) != filepath.Join(dataDir, "jobs") {
		return &uploadAdmissionHandler{initErr: admissionError("admission_layout_invalid")}
	}
	store, err := openAdmissionStore(dataDir, defaultAdmissionPolicy(maxUploadBytes))
	return &uploadAdmissionHandler{store: store, limiter: limiter, jobKey: jobKey, initErr: err}
}

func (handler *uploadAdmissionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, 405, "method_not_allowed", "method not allowed")
		return
	}
	if handler.initErr != nil || handler.store == nil || !handler.store.healthy() {
		writeJSONError(w, 503, "admission_state_unavailable", "upload admission unavailable")
		return
	}
	cn, serial, err := requestPrincipal(r)
	if err != nil {
		writeJSONError(w, 403, "identity_invalid", "verified certificate owner required")
		return
	}
	if !handler.limiter.Allow(cn) {
		writeJSONError(w, 429, "rate_limited", "rate limit exceeded")
		return
	}
	if r.ContentLength > handler.store.policy.MaxBodyBytes {
		writeJSONError(w, 413, "payload_too_large", "payload too large")
		return
	}
	entry, err := handler.store.reserve(cn, serial)
	if err != nil {
		status := 503
		if err.Error() == "quota_exceeded" || err.Error() == "upload_concurrency_exceeded" {
			status = 429
		}
		writeJSONError(w, status, err.Error(), "upload admission denied")
		return
	}
	// This bound applies to wire bytes even for chunked bodies. Header parsing
	// occurs after durable reservation; stdlib MIME headers still have a 10MiB cap.
	r.Body = http.MaxBytesReader(w, r.Body, handler.store.policy.MaxBodyBytes)
	defer r.Body.Close()
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(30 * time.Second))
	streamed, err := streamMultipart(r.Context(), r, handler.store, entry)
	reject := func(status int, code string) {
		if handler.store.abort(entry) != nil {
			writeJSONError(w, 503, "admission_state_unavailable", "upload admission unavailable")
			return
		}
		writeJSONError(w, status, code, "upload rejected")
	}
	if err != nil {
		status := 400
		switch err.Error() {
		case "metadata_too_large", "payload_too_large":
			status = 413
		case "storage_error":
			status = 500
		}
		if !handler.store.healthy() {
			writeJSONError(w, 503, "admission_state_unavailable", "upload admission unavailable")
			return
		}
		reject(status, err.Error())
		return
	}
	clientID, err := uploadIdentity(r)
	if err != nil {
		reject(403, "identity_invalid")
		return
	}
	if headerHash := r.Header.Get("X-Content-SHA256"); headerHash != "" && headerHash != streamed.SHA256 {
		reject(400, "hash_mismatch")
		return
	}
	subject, issuer, certificateSerial := clientCertInfo(r)
	encKey := streamed.Fields.Get("enc_key")
	wrapped := false
	wrapAlg := ""
	if handler.jobKey != "" && encKey != "" {
		encKey, err = wrapSensitiveValue(encKey, handler.jobKey)
		if err != nil {
			reject(500, "enc_key_wrap_failed")
			return
		}
		wrapped = true
		wrapAlg = "aes-256-gcm"
	}
	job := jobRecord{JobID: entry.JobID, Status: "uploaded", UploadedAt: time.Now().UTC().Format(time.RFC3339),
		OriginalName: streamed.Filename, SizeBytes: streamed.Size, SHA256: streamed.SHA256, ClientID: clientID,
		EncAlg: streamed.Fields.Get("enc_alg"), EncKey: encKey, EncKeyWrapped: wrapped, EncKeyWrapAlg: wrapAlg,
		SigAlg: streamed.Fields.Get("sig_alg"), Sig: streamed.Fields.Get("sig"),
		ClientCertSubject: subject, ClientCertIssuer: issuer, ClientCertSerial: certificateSerial}
	jobJSON, err := json.MarshalIndent(job, "", "  ")
	if err != nil {
		reject(500, "job_encode_failed")
		return
	}
	projected, err := projectedJobJSON(job)
	if err != nil {
		reject(500, "job_encode_failed")
		return
	}
	if len(projected) > maxJobMetadataBytes {
		reject(413, "metadata_too_large")
		return
	}
	if len(entry.JobID+"_"+sanitizeFilename(job.OriginalName)) > 255 {
		reject(400, "invalid_filename")
		return
	}
	if r.Context().Err() != nil {
		reject(400, "upload_cancelled")
		return
	}
	if err := handler.store.commit(entry, job, jobJSON); err != nil {
		writeJSONError(w, 503, "admission_state_unavailable", "upload admission unavailable")
		return
	}
	if handler.store.acknowledge(func() {
		writeJSONResponse(w, map[string]string{"job_id": entry.JobID, "status": "uploaded"})
	}) != nil {
		writeJSONError(w, 503, "admission_state_unavailable", "upload admission unavailable")
	}
}

func main() {
	if dispatchOwnerUpload() {
		return
	}
	addr := envOr("BIOZERO_UPLOAD_ADDR", ":8081")
	dataDir := envOr("BIOZERO_DATA_DIR", "./data")
	certPath := os.Getenv("BIOZERO_TLS_CERT")
	keyPath := os.Getenv("BIOZERO_TLS_KEY")
	caPath := os.Getenv("BIOZERO_TLS_CA")
	if err := validateServerSecurity(certPath, keyPath, caPath); err != nil {
		log.Fatal(err)
	}
	policy, err := admissionPolicyFromEnv()
	if err != nil {
		log.Fatal("admission startup error: admission_config_invalid")
	}
	rateLimit := envOrInt("BIOZERO_RATE_LIMIT", 60)
	jobKey := os.Getenv("BIOZERO_JOB_KEY")

	store, err := openAdmissionStore(dataDir, policy)
	if err != nil {
		log.Fatalf("admission startup error: %s", err)
	}
	defer store.Close()

	limiter := newRateLimiter(rateLimit, time.Minute)
	// Periodically prune rate limiter state to control memory usage.
	go limiter.PruneStaleEntries(5 * time.Minute)

	// API boundary: health probe for UI and orchestration checks.
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if !store.healthy() {
			writeJSONError(w, 503, "admission_state_unavailable", "upload admission unavailable")
			return
		}
		// Respond quickly to indicate liveness.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// API boundary: accepts external multipart uploads and writes job records.
	http.Handle("/upload", &uploadAdmissionHandler{store: store, limiter: limiter, jobKey: jobKey})

	// Configure server timeouts to protect against slow clients.
	server := &http.Server{
		Addr:              addr,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	// Enable TLS/mTLS when certs are configured.
	if certPath != "" && keyPath != "" {
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
		// Require client certificates when a CA bundle is present.
		if caPath != "" {
			pool, err := loadCertPool(caPath)
			if err != nil {
				log.Fatalf("failed to load client CA: %v", err)
			}
			tlsConfig.ClientCAs = pool
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		}
		server.TLSConfig = tlsConfig
		log.Printf("upload-api listening with TLS on %s", addr)
		// Exit on fatal TLS server error.
		log.Fatal(server.ListenAndServeTLS(certPath, keyPath))
		// Return is unreachable because log.Fatal exits, but keep flow explicit.
		return
	}

	log.Printf("upload-api listening on %s", addr)
	// Exit on fatal HTTP server error.
	log.Fatal(server.ListenAndServe())
	// Return is unreachable because log.Fatal exits, but keep flow explicit.
	return
}

/// clientCertInfo extracts mTLS client certificate metadata when present.
///
/// Brief description of what the function does.
/// - Reads the first peer certificate to capture subject, issuer, and serial.
///
/// Parameters:
///   r - Incoming HTTP request with TLS state.
///
/// Returns subject, issuer, and serial strings; empty values if no cert present.
///
/// Throws [None] - returns empty values on missing TLS state.
///
/// Example: `subj, issuer, serial := clientCertInfo(r)`
func clientCertInfo(r *http.Request) (string, string, string) {
	// Guard against non-TLS or unauthenticated requests.
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		// Return blanks to indicate no client certificate available.
		return "", "", ""
	}
	cert := r.TLS.PeerCertificates[0]
	// Return certificate identity information for auditing.
	// Return certificate identity details for auditing.
	return cert.Subject.String(), cert.Issuer.String(), cert.SerialNumber.String()
}

/// loadCertPool reads a PEM bundle and constructs a CA pool.
///
/// Brief description of what the function does.
/// - Loads trusted CA certificates for mTLS verification.
///
/// Parameters:
///   path - Filesystem path to the PEM bundle.
///
/// Returns a populated CertPool or an error if parsing fails.
///
/// Throws [CertificateError] when PEM data is unreadable or invalid.
///
/// Example: `pool, err := loadCertPool("/pki/ca.crt")`
func loadCertPool(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		// Return file errors so callers can fail fast on TLS config.
		return nil, err
	}
	pool := x509.NewCertPool()
	// Guard against empty or invalid PEM content.
	if ok := pool.AppendCertsFromPEM(data); !ok {
		// Return a descriptive error to aid TLS setup debugging.
		return nil, fmt.Errorf("no valid CA certs in %s", path)
	}
	// Return the pool for TLS client verification.
	return pool, nil
}

/// sanitizeFilename normalizes filenames for safe filesystem storage.
///
/// Brief description of what the function does.
/// - Replaces path traversal characters to keep uploads in the target directory.
///
/// Parameters:
///   name - Original filename supplied by the client.
///
/// Returns a sanitized filename safe for path joins.
///
/// Throws [None] - operates on strings only.
///
/// Example: `safe := sanitizeFilename("../../etc/passwd")`
func sanitizeFilename(name string) string {
	replacer := strings.NewReplacer("/", "_", "\\", "_", "..", "_")
	// Return the sanitized string to prevent path traversal.
	// Return the sanitized string to prevent path traversal.
	return replacer.Replace(name)
}

/// randomID generates a random hex-encoded identifier.
///
/// Brief description of what the function does.
/// - Uses crypto/rand to generate a job ID for cross-service tracking.
///
/// Parameters:
///   n - Number of random bytes to read before hex encoding.
///
/// Returns a hex string with length 2*n.
///
/// Throws [EntropyError] when random bytes cannot be read.
///
/// Example: `jobID := randomID(8)`
func randomID(n int) string {
	buf := make([]byte, n)
	// Best-effort entropy read; failure yields a weak ID but avoids panic.
	_, _ = rand.Read(buf)
	// Return hex encoding for easy transport/storage.
	return hex.EncodeToString(buf)
}

/// writeJSONResponse serializes a value into the HTTP response body.
///
/// Brief description of what the function does.
/// - Writes JSON API responses with safe caching headers.
///
/// Parameters:
///   w - HTTP response writer.
///   v - Response payload to marshal.
///
/// Returns no value; writes to the response stream.
///
/// Throws [EncodeError] when JSON serialization fails.
///
/// Example: `writeJSONResponse(w, map[string]string{"status":"ok"})`
func writeJSONResponse(w http.ResponseWriter, v any) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		// Emit a standard error response when serialization fails.
		writeJSONError(w, http.StatusInternalServerError, "encode_failed", "failed to encode response")
		// Return to stop writing a partial response.
		return
	}
	// Set JSON content type and prevent caching of sensitive data.
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	// Best-effort write; ignore short writes as response is already committed.
	_, _ = w.Write(data)
}

/// writeJSONError sends a standardized JSON error payload.
///
/// Brief description of what the function does.
/// - Ensures API clients receive consistent error structure and codes.
///
/// Parameters:
///   w - HTTP response writer.
///   status - HTTP status code to return.
///   code - Machine-readable error code.
///   message - Human-readable error message.
///
/// Returns no value; writes to the response stream.
///
/// Throws [EncodeError] when error payload serialization fails.
///
/// Example: `writeJSONError(w, 400, "invalid_request", "missing file")`
func writeJSONError(w http.ResponseWriter, status int, code, message string) {
	data, err := json.MarshalIndent(errorResponse{Error: message, Code: code}, "", "  ")
	if err != nil {
		// Fall back to plain text to avoid recursive error handling.
		http.Error(w, "failed to encode error", http.StatusInternalServerError)
		// Return to avoid double-writing headers.
		return
	}
	// Set JSON content type and prevent caching of error responses.
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	// Best-effort write; response is already committed.
	_, _ = w.Write(data)
}

/// envOr returns the environment variable or a fallback value.
///
/// Brief description of what the function does.
/// - Reads configuration from env without panicking on missing values.
///
/// Parameters:
///   key - Environment variable name.
///   fallback - Default value when env is unset.
///
/// Returns the env value if set; otherwise the fallback.
///
/// Throws [None] - uses default on missing values.
///
/// Example: `addr := envOr("BIOZERO_UPLOAD_ADDR", ":8081")`
func envOr(key, fallback string) string {
	val := os.Getenv(key)
	if val == "" {
		// Return fallback to keep configuration predictable.
		return fallback
	}
	// Return the configured value when present.
	return val
}

/// envOrInt returns a numeric env var or fallback.
///
/// Brief description of what the function does.
/// - Parses integer config values safely with fallback defaults.
///
/// Parameters:
///   key - Environment variable name.
///   fallback - Default value when env is unset or invalid.
///
/// Returns the parsed integer or fallback.
///
/// Throws [ParseError] when env value is malformed; fallback is used.
///
/// Example: `limit := envOrInt("BIOZERO_RATE_LIMIT", 60)`
func envOrInt(key string, fallback int) int {
	val := os.Getenv(key)
	if val == "" {
		// Return fallback when unset to avoid zero-values.
		return fallback
	}
	parsed, err := strconv.Atoi(val)
	if err != nil {
		// Return fallback on parse errors.
		return fallback
	}
	// Return parsed value for valid configuration.
	return parsed
}

type rateLimiter struct {
	mu         sync.Mutex
	limit      int
	window     time.Duration
	requests   map[string]int
	windowEnds map[string]time.Time
}

/// newRateLimiter constructs a basic in-memory rate limiter.
///
/// Brief description of what the function does.
/// - Creates a sliding window limiter for per-client throttling.
///
/// Parameters:
///   limit - Maximum requests per window.
///   window - Duration of the rate limit window.
///
/// Returns a configured rateLimiter instance.
///
/// Throws [None] - in-memory allocation only.
///
/// Example: `limiter := newRateLimiter(60, time.Minute)`
func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	// Return a configured limiter with fresh maps.
	return &rateLimiter{
		limit:      limit,
		window:     window,
		requests:   make(map[string]int),
		windowEnds: make(map[string]time.Time),
	}
}

/// Allow checks whether a key is permitted within the current rate window.
///
/// Brief description of what the function does.
/// - Tracks per-key request counts and blocks when limit exceeded.
///
/// Parameters:
///   key - Identifier (e.g., client IP) to rate limit.
///
/// Returns true when the request is allowed; false when rate-limited.
///
/// Throws [None] - uses in-memory counters.
///
/// Performance:
///   Time complexity: O(1) per call.
///   Space complexity: O(k) for tracked keys.
///
/// Example: `if !limiter.Allow(clientIP(r)) { ... }`
func (r *rateLimiter) Allow(key string) bool {
	// Short-circuit when rate limiting is disabled.
	if r.limit <= 0 {
		// Return true to treat unlimited mode as always allowed.
		return true
	}
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()

	// Reset window when expired to avoid stale counts.
	if end, ok := r.windowEnds[key]; !ok || now.After(end) {
		r.windowEnds[key] = now.Add(r.window)
		r.requests[key] = 0
	}
	// Increment count for this key in the current window.
	r.requests[key]++
	// Return whether the key remains under the limit.
	return r.requests[key] <= r.limit
}

/// PruneStaleEntries periodically drops expired rate limit entries.
///
/// Brief description of what the function does.
/// - Prevents unbounded growth of in-memory rate limit maps.
///
/// Parameters:
///   interval - How often to scan for expired entries.
///
/// Returns no value; runs until the process exits.
///
/// Throws [None] - background maintenance loop.
///
/// Example: `go limiter.PruneStaleEntries(5 * time.Minute)`
func (r *rateLimiter) PruneStaleEntries(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	// Loop indefinitely to keep limiter state compact.
	for range ticker.C {
		now := time.Now()
		r.mu.Lock()
		for key, end := range r.windowEnds {
			// Drop keys whose window expired to free memory.
			if now.After(end) {
				delete(r.windowEnds, key)
				delete(r.requests, key)
			}
		}
		r.mu.Unlock()
	}
}

/// clientIP extracts the caller IP address from headers or remote address.
///
/// Brief description of what the function does.
/// - Prefers X-Forwarded-For when behind a proxy, otherwise uses RemoteAddr.
///
/// Parameters:
///   r - Incoming HTTP request.
///
/// Returns the best-effort client IP string.
///
/// Throws [None] - string parsing only.
///
/// Example: `ip := clientIP(r)`
func clientIP(r *http.Request) string {
	// Respect proxy headers when present to avoid grouping all clients.
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		parts := strings.Split(ip, ",")
		// Return the first hop to approximate the originating client.
		return strings.TrimSpace(parts[0])
	}
	host := r.RemoteAddr
	// Strip port suffix for cleaner IP keys.
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		return host[:idx]
	}
	// Return raw RemoteAddr when no port separator is found.
	return host
}

/// isValidClientID validates client IDs for safe storage and comparison.
///
/// Brief description of what the function does.
/// - Allows only alphanumerics, underscore, and hyphen with bounded length.
///
/// Parameters:
///   clientID - Caller-provided client identifier.
///
/// Returns true when the ID conforms to the allowed format.
///
/// Throws [None] - pure validation.
///
/// Example: `if !isValidClientID(id) { ... }`
func isValidClientID(clientID string) bool {
	// Enforce length bounds to keep logs and headers sane.
	if len(clientID) < 1 || len(clientID) > 64 {
		// Return false when length constraints are violated.
		return false
	}
	for _, r := range clientID {
		// Allow safe characters only to avoid injection or parsing issues.
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			continue
		}
		// Return false on the first invalid character.
		return false
	}
	// Return true when all characters are valid.
	return true
}

/// wrapSensitiveValue encrypts a string using AES-256-GCM.
///
/// Brief description of what the function does.
/// - Wraps sensitive data (enc_key) at rest using an env-provided key.
///
/// Parameters:
///   value - Cleartext value to wrap.
///   keyMaterial - 32-byte AES key material in base64 or hex.
///
/// Returns base64-encoded nonce+ciphertext or an error.
///
/// Throws [CryptoError] when key parsing or encryption fails.
///
/// SECURITY: Uses AES-256-GCM; do not reduce key size or bypass wrapping.
///
/// Example: `wrapped, err := wrapSensitiveValue(encKey, os.Getenv("BIOZERO_JOB_KEY"))`
func wrapSensitiveValue(value, keyMaterial string) (string, error) {
	key, err := decodeKeyMaterial(keyMaterial)
	if err != nil {
		// Return key parsing errors to prevent insecure storage.
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		// Return cipher errors to prevent insecure storage.
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		// Return GCM setup errors to avoid weak encryption.
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	// SECURITY: nonce must be unique; use crypto/rand.
	if _, err := rand.Read(nonce); err != nil {
		// Return entropy errors to avoid nonce reuse.
		return "", err
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(value), nil)
	payload := append(nonce, ciphertext...)
	// Return base64 to keep JSON safe and compact.
	return base64.StdEncoding.EncodeToString(payload), nil
}

/// decodeKeyMaterial parses base64/hex key material into 32 bytes.
///
/// Brief description of what the function does.
/// - Supports base64 or hex-encoded 256-bit keys from env vars.
///
/// Parameters:
///   raw - Encoded key material.
///
/// Returns a 32-byte key or an error on invalid input.
///
/// Throws [KeyMaterialError] when the key is missing or wrong length.
///
/// SECURITY: Enforces 32-byte key size for AES-256.
///
/// Example: `key, err := decodeKeyMaterial(os.Getenv("BIOZERO_JOB_KEY"))`
func decodeKeyMaterial(raw string) ([]byte, error) {
	// Guard against missing secrets to avoid nil keys.
	if raw == "" {
		// Return error to force explicit key provisioning.
		return nil, errors.New("missing key material")
	}
	// Accept base64-encoded 32-byte keys.
	if decoded, err := base64.StdEncoding.DecodeString(raw); err == nil && len(decoded) == 32 {
		// Return decoded bytes when base64 is valid.
		return decoded, nil
	}
	// Accept hex-encoded 32-byte keys.
	if decoded, err := hex.DecodeString(raw); err == nil && len(decoded) == 32 {
		// Return decoded bytes when hex is valid.
		return decoded, nil
	}
	// Return an explicit error to guide correct key provisioning.
	return nil, errors.New("job key must be 32 bytes (base64 or hex)")
}
