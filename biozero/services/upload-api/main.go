// SPDX-License-Identifier: AGPL-3.0-only
// Upload API for BioZero: accepts FASTQ uploads from the UI and uploader-cli,
// stores payloads and job records for enclave-runner, and exposes /health for
// system checks; it optionally enforces mTLS and wraps sensitive job fields at rest.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime/multipart"
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
	Sig              string `json:"sig,omitempty"`
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
func main() {
	addr := envOr("BIOZERO_UPLOAD_ADDR", ":8081")
	dataDir := envOr("BIOZERO_DATA_DIR", "./data")
	certPath := os.Getenv("BIOZERO_TLS_CERT")
	keyPath := os.Getenv("BIOZERO_TLS_KEY")
	caPath := os.Getenv("BIOZERO_TLS_CA")
	maxUploadBytes := envOrInt64("BIOZERO_MAX_UPLOAD_BYTES", 25*1024*1024)
	rateLimit := envOrInt("BIOZERO_RATE_LIMIT", 60)
	jobKey := os.Getenv("BIOZERO_JOB_KEY")

	uploadDir := filepath.Join(dataDir, "uploads")
	jobsDir := filepath.Join(dataDir, "jobs")
	// Ensure state directories exist before accepting requests.
	mustMkdirAll(uploadDir)
	mustMkdirAll(jobsDir)

	limiter := newRateLimiter(rateLimit, time.Minute)
	// Periodically prune rate limiter state to control memory usage.
	go limiter.PruneStaleEntries(5 * time.Minute)

	// API boundary: health probe for UI and orchestration checks.
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		// Respond quickly to indicate liveness.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// API boundary: accepts external multipart uploads and writes job records.
	http.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		// Guard against unsupported methods to limit surface area.
		if r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			// Return to stop processing non-upload methods.
			return
		}

		// Apply per-client throttling to protect storage and CPU.
		if !limiter.Allow(clientIP(r)) {
			writeJSONError(w, http.StatusTooManyRequests, "rate_limited", "rate limit exceeded")
			// Return to enforce throttling before any work is done.
			return
		}

		// Enforce declared size limits before parsing the body.
		if r.ContentLength > maxUploadBytes {
			writeJSONError(w, http.StatusRequestEntityTooLarge, "payload_too_large", "payload too large")
			// Return to avoid reading oversized request bodies.
			return
		}

		// Enforce upload size limits early to protect memory and disk.
		r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
		// Parse the multipart form for file and metadata fields.
		if err := r.ParseMultipartForm(32 << 20); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_form", "invalid multipart form")
			// Return to avoid accessing invalid multipart fields.
			return
		}

		file, header, err := r.FormFile("file")
		// Reject requests missing the expected file field.
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "missing_file", "missing file field")
			// Return because file content is required.
			return
		}
		// Ensure the uploaded file stream is closed even on errors.
		defer file.Close()

		clientID := r.FormValue("client_id")
		// Accept client_id from either form field or header for compatibility.
		if clientID == "" {
			clientID = r.Header.Get("X-Client-Id")
		}
		// Reject anonymous uploads to preserve attribution and access control.
		if clientID == "" {
			writeJSONError(w, http.StatusBadRequest, "missing_client_id", "missing client_id")
			// Return because client identity is required for tracking.
			return
		}
		// Validate client ID characters to avoid path/log injection.
		if !isValidClientID(clientID) {
			writeJSONError(w, http.StatusBadRequest, "invalid_client_id", "invalid client_id")
			// Return to prevent storing unsafe identifiers.
			return
		}

		// Generate a random job ID for cross-service coordination.
		jobID := randomID(8)
		storedName := fmt.Sprintf("%s_%s", jobID, sanitizeFilename(header.Filename))
		storedPath := filepath.Join(uploadDir, storedName)

		size, hash, err := saveAndHash(file, storedPath)
		// Abort on storage failure to avoid partial job records.
		if err != nil {
			log.Printf("upload save error: %v", err)
			writeJSONError(w, http.StatusInternalServerError, "storage_error", "failed to store upload")
			// Return because storage failed and job record would be inconsistent.
			return
		}

		// Re-check size after writing in case content-length was missing/misreported.
		if size > maxUploadBytes {
			_ = os.Remove(storedPath)
			writeJSONError(w, http.StatusRequestEntityTooLarge, "payload_too_large", "payload too large")
			// Return to enforce size limits and avoid dangling uploads.
			return
		}

		// Enforce client-provided integrity header when present.
		if headerHash := r.Header.Get("X-Content-SHA256"); headerHash != "" && headerHash != hash {
			_ = os.Remove(storedPath)
			writeJSONError(w, http.StatusBadRequest, "hash_mismatch", "content hash mismatch")
			// Return to prevent accepting corrupted or tampered data.
			return
		}

		// Capture mTLS metadata for downstream authorization checks.
		certSubject, certIssuer, certSerial := clientCertInfo(r)
		// Optionally wrap sensitive key material before writing job records to disk.
		encKey := r.FormValue("enc_key")
		encKeyWrapped := false
		encKeyWrapAlg := ""
		// SECURITY: wrap enc_key at rest to avoid cleartext key storage.
		if jobKey != "" && encKey != "" {
			wrapped, err := wrapSensitiveValue(encKey, jobKey)
			// Fail closed if encryption fails to avoid storing sensitive material.
			if err != nil {
				log.Printf("enc_key wrap error: %v", err)
				writeJSONError(w, http.StatusInternalServerError, "enc_key_wrap_failed", "failed to secure enc_key")
				// Return to avoid persisting unprotected secrets.
				return
			}
			encKey = wrapped
			encKeyWrapped = true
			encKeyWrapAlg = "aes-256-gcm"
		}

		// Job records are the coordination point for enclave-runner and results-api.
		job := jobRecord{
			JobID:             jobID,
			Status:            "uploaded",
			UploadedAt:        time.Now().UTC().Format(time.RFC3339),
			OriginalName:      header.Filename,
			SizeBytes:         size,
			SHA256:            hash,
			ClientID:          clientID,
			EncAlg:            r.FormValue("enc_alg"),
			EncKey:            encKey,
			EncKeyWrapped:     encKeyWrapped,
			EncKeyWrapAlg:     encKeyWrapAlg,
			SigAlg:            r.FormValue("sig_alg"),
			Sig:               r.FormValue("sig"),
			ClientCertSubject: certSubject,
			ClientCertIssuer:  certIssuer,
			ClientCertSerial:  certSerial,
		}

		// Persist the job record for enclave-runner to pick up.
		if err := writeJSON(filepath.Join(jobsDir, jobID+".json"), job); err != nil {
			log.Printf("job record write error: %v", err)
			writeJSONError(w, http.StatusInternalServerError, "job_write_failed", "failed to write job record")
			// Return to avoid confirming an unpersisted job.
			return
		}

		resp := map[string]string{"job_id": jobID, "status": "uploaded"}
		// Return the job ID for clients to poll results-api.
		writeJSONResponse(w, resp)
	})

	// Configure server timeouts to protect against slow clients.
	server := &http.Server{
		Addr:              addr,
		ReadHeaderTimeout: 5 * time.Second,
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

/// saveAndHash writes the upload to disk and computes SHA-256.
///
/// Brief description of what the function does.
/// - Streams the input to disk while hashing to avoid buffering.
///
/// Parameters:
///   src - Multipart file stream from the client upload.
///   destPath - Destination path for the stored upload.
///
/// Returns size in bytes, hex-encoded SHA-256, and an error if any step fails.
///
/// Throws [IOError] when disk write or hashing fails.
///
/// Example: `size, hash, err := saveAndHash(file, "/data/uploads/job.bin")`
func saveAndHash(src multipart.File, destPath string) (int64, string, error) {
	out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		// Return the IO error to let the caller respond with 500.
		return 0, "", err
	}
	// Ensure the output file is closed on all paths.
	defer out.Close()

	hasher := sha256.New()
	tee := io.TeeReader(src, hasher)
	size, err := io.Copy(out, tee)
	if err != nil {
		// Return IO errors so the caller can delete partial output.
		return 0, "", err
	}
	// Return computed size and hex digest for integrity checks.
	return size, hex.EncodeToString(hasher.Sum(nil)), nil
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

/// writeJSON persists a value as indented JSON on disk.
///
/// Brief description of what the function does.
/// - Serializes job records for enclave-runner consumption.
///
/// Parameters:
///   path - Destination file path for JSON output.
///   v - Value to marshal into JSON.
///
/// Returns an error when serialization or writing fails.
///
/// Throws [IOError] when file writing fails.
///
/// Example: `err := writeJSON("/data/jobs/123.json", job)`
func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		// Return marshal errors to avoid writing invalid JSON.
		return err
	}
	// Return any write error to the caller for error handling.
	return os.WriteFile(path, data, 0640)
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

/// envOrInt64 returns a 64-bit numeric env var or fallback.
///
/// Brief description of what the function does.
/// - Parses int64 config values safely with fallback defaults.
///
/// Parameters:
///   key - Environment variable name.
///   fallback - Default value when env is unset or invalid.
///
/// Returns the parsed int64 or fallback.
///
/// Throws [ParseError] when env value is malformed; fallback is used.
///
/// Example: `maxBytes := envOrInt64("BIOZERO_MAX_UPLOAD_BYTES", 25*1024*1024)`
func envOrInt64(key string, fallback int64) int64 {
	val := os.Getenv(key)
	if val == "" {
		// Return fallback when unset to avoid zero-values.
		return fallback
	}
	parsed, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		// Return fallback on parse errors.
		return fallback
	}
	// Return parsed value for valid configuration.
	return parsed
}

/// mustMkdirAll creates directories or exits the process.
///
/// Brief description of what the function does.
/// - Ensures required directories exist before starting the server.
///
/// Parameters:
///   path - Directory path to create if missing.
///
/// Returns no value; terminates process on failure.
///
/// Throws [FatalIOError] when directory creation fails.
///
/// Example: `mustMkdirAll("/data/uploads")`
func mustMkdirAll(path string) {
	// Fail fast if the filesystem layout cannot be prepared.
	if err := os.MkdirAll(path, 0755); err != nil {
		log.Fatalf("failed to create %s: %v", path, err)
	}
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
