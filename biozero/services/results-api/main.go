// SPDX-License-Identifier: AGPL-3.0-only
// Results API for BioZero: serves job status/results written by enclave-runner,
// authenticates callers via client ID or mTLS cert serial, and exposes /health for the UI.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
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

// errorResponse standardizes error payloads returned by API handlers.
type errorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

// resultResponse wraps job status and optional result payload.
type resultResponse struct {
	Status string          `json:"status"`
	Data   json.RawMessage `json:"data,omitempty"`
}

// jobRecord represents the minimal job metadata needed for authorization.
type jobRecord struct {
	JobID            string `json:"job_id"`
	Status           string `json:"status"`
	OriginalName     string `json:"original_name"`
	ClientID         string `json:"client_id"`
	ClientCertSerial string `json:"client_cert_serial,omitempty"`
}

/// main registers HTTP handlers and starts the results API server.
///
/// Brief description of what the function does.
/// - Boots the results API, wires health and results endpoints, and enables TLS/mTLS.
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
	addr := envOr("BIOZERO_RESULTS_ADDR", ":8082")
	dataDir := envOr("BIOZERO_DATA_DIR", "./data")
	certPath := os.Getenv("BIOZERO_TLS_CERT")
	keyPath := os.Getenv("BIOZERO_TLS_KEY")
	caPath := os.Getenv("BIOZERO_TLS_CA")
	rateLimit := envOrInt("BIOZERO_RATE_LIMIT", 120)

	resultsDir := filepath.Join(dataDir, "results")
	jobsDir := filepath.Join(dataDir, "jobs")
	// Ensure state directories exist before accepting requests.
	mustMkdirAll(resultsDir)
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

	// API boundary: serves results produced by enclave-runner.
	http.HandleFunc("/results/", func(w http.ResponseWriter, r *http.Request) {
		// Guard against unsupported methods to reduce surface area.
		if r.Method != http.MethodGet {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			// Return to stop processing non-read requests.
			return
		}
		// Apply per-client throttling to protect storage and CPU.
		if !limiter.Allow(clientIP(r)) {
			writeJSONError(w, http.StatusTooManyRequests, "rate_limited", "rate limit exceeded")
			// Return to enforce throttling before file I/O.
			return
		}

		jobID := strings.TrimPrefix(r.URL.Path, "/results/")
		// Reject missing job IDs to avoid ambiguous lookups.
		if jobID == "" {
			writeJSONError(w, http.StatusBadRequest, "missing_job_id", "missing job id")
			// Return to avoid scanning the filesystem with empty IDs.
			return
		}
		// Validate job ID format to avoid path traversal risks.
		if !isValidJobID(jobID) {
			writeJSONError(w, http.StatusBadRequest, "invalid_job_id", "invalid job id")
			// Return to prevent unsafe filesystem access.
			return
		}

		// Results are written by enclave-runner once processing is complete.
		resultPath := filepath.Join(resultsDir, jobID+".json")
		if data, err := os.ReadFile(resultPath); err == nil {
			// Enforce job-level authorization before returning results.
			if !authorizedForJob(r, jobsDir, jobID) {
				writeJSONError(w, http.StatusForbidden, "forbidden", "forbidden")
				// Return to avoid leaking result data.
				return
			}
			// Return processed results to the caller.
			writeJSONResponse(w, resultResponse{Status: "processed", Data: data})
			return
		}

		// Fall back to the job record to signal "pending" if processing isn't done.
		jobPath := filepath.Join(jobsDir, jobID+".json")
		if _, err := os.Stat(jobPath); err == nil {
			// Enforce job-level authorization before returning status.
			if !authorizedForJob(r, jobsDir, jobID) {
				writeJSONError(w, http.StatusForbidden, "forbidden", "forbidden")
				// Return to avoid leaking job existence.
				return
			}
			// Return pending status while the runner processes the job.
			writeJSONResponse(w, resultResponse{Status: "pending"})
			return
		}

		// Return not found when neither job nor results exist.
		writeJSONError(w, http.StatusNotFound, "job_not_found", "job not found")
		// Return to end the request after a not-found response.
		return
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
		log.Printf("results-api listening with TLS on %s", addr)
		log.Fatal(server.ListenAndServeTLS(certPath, keyPath))
		// Return is unreachable because log.Fatal exits, but keep flow explicit.
		return
	}

	log.Printf("results-api listening on %s", addr)
	log.Fatal(server.ListenAndServe())
	// Return is unreachable because log.Fatal exits, but keep flow explicit.
	return
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
/// Example: `writeJSONResponse(w, resultResponse{Status: "pending"})`
func writeJSONResponse(w http.ResponseWriter, v any) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
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
/// Example: `writeJSONError(w, 403, "forbidden", "forbidden")`
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
/// Example: `addr := envOr("BIOZERO_RESULTS_ADDR", ":8082")`
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
/// Example: `limit := envOrInt("BIOZERO_RATE_LIMIT", 120)`
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
/// Example: `mustMkdirAll("/data/results")`
func mustMkdirAll(path string) {
	// Fail fast if the filesystem layout cannot be prepared.
	if err := os.MkdirAll(path, 0755); err != nil {
		log.Fatalf("failed to create %s: %v", path, err)
	}
}

/// isValidJobID validates job IDs for safe filesystem access.
///
/// Brief description of what the function does.
/// - Enforces hex-only IDs with bounded length to prevent path traversal.
///
/// Parameters:
///   jobID - Job identifier from the request path.
///
/// Returns true when the ID is valid; false otherwise.
///
/// Throws [None] - pure validation.
///
/// Example: `if !isValidJobID(jobID) { ... }`
func isValidJobID(jobID string) bool {
	if len(jobID) < 8 || len(jobID) > 64 {
		// Return false when length constraints are violated.
		return false
	}
	for _, r := range jobID {
		// Reject non-hex characters to keep IDs predictable.
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			// Return false when a non-hex character is found.
			return false
		}
	}
	// Return true when all characters are valid.
	return true
}

/// authorizedForJob verifies caller access to a job using cert or client ID.
///
/// Brief description of what the function does.
/// - Checks mTLS cert serial or X-Client-Id header against job metadata.
///
/// Parameters:
///   r - Incoming HTTP request containing auth info.
///   jobsDir - Directory where job records are stored.
///   jobID - Job identifier for lookup.
///
/// Returns true when the caller is authorized for the job.
///
/// Throws [AuthError] when job metadata cannot be read.
///
/// Example: `if !authorizedForJob(r, jobsDir, jobID) { ... }`
func authorizedForJob(r *http.Request, jobsDir, jobID string) bool {
	jobPath := filepath.Join(jobsDir, jobID+".json")
	job, err := readJob(jobPath)
	if err != nil {
		// Return false to avoid leaking job data when read fails.
		return false
	}

	// Prefer cert-based auth when available and recorded.
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 && job.ClientCertSerial != "" {
		cert := r.TLS.PeerCertificates[0]
		// Return whether the client cert matches the recorded serial.
		return cert.SerialNumber.String() == job.ClientCertSerial
	}

	clientID := r.Header.Get("X-Client-Id")
	if clientID == "" {
		// Return false when no client ID is provided.
		return false
	}
	// Return whether the client ID matches job ownership.
	return clientID == job.ClientID
}

/// readJob loads a job record from disk.
///
/// Brief description of what the function does.
/// - Parses job JSON for authorization and status checks.
///
/// Parameters:
///   path - Filesystem path to the job JSON.
///
/// Returns the jobRecord and an error if reading or parsing fails.
///
/// Throws [IOError] when file reading fails.
///
/// Example: `job, err := readJob("/data/jobs/abc.json")`
func readJob(path string) (jobRecord, error) {
	var job jobRecord
	data, err := os.ReadFile(path)
	if err != nil {
		// Return file errors to the caller for authorization handling.
		return job, err
	}
	if err := json.Unmarshal(data, &job); err != nil {
		// Return parse errors to avoid using incomplete data.
		return job, err
	}
	// Return the parsed job record.
	return job, nil
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
/// Example: `limiter := newRateLimiter(120, time.Minute)`
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
		// Return the host without port for consistent keys.
		return host[:idx]
	}
	// Return raw RemoteAddr when no port separator is found.
	return host
}
