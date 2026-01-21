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

type errorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

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
	mustMkdirAll(uploadDir)
	mustMkdirAll(jobsDir)

	limiter := newRateLimiter(rateLimit, time.Minute)
	go limiter.PruneStaleEntries(5 * time.Minute)

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	http.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}

		if !limiter.Allow(clientIP(r)) {
			writeJSONError(w, http.StatusTooManyRequests, "rate_limited", "rate limit exceeded")
			return
		}

		if r.ContentLength > maxUploadBytes {
			writeJSONError(w, http.StatusRequestEntityTooLarge, "payload_too_large", "payload too large")
			return
		}

		// Enforce upload size limits early to protect memory and disk.
		r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
		if err := r.ParseMultipartForm(32 << 20); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_form", "invalid multipart form")
			return
		}

		file, header, err := r.FormFile("file")
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "missing_file", "missing file field")
			return
		}
		defer file.Close()

		clientID := r.FormValue("client_id")
		if clientID == "" {
			clientID = r.Header.Get("X-Client-Id")
		}
		if clientID == "" {
			writeJSONError(w, http.StatusBadRequest, "missing_client_id", "missing client_id")
			return
		}
		if !isValidClientID(clientID) {
			writeJSONError(w, http.StatusBadRequest, "invalid_client_id", "invalid client_id")
			return
		}

		jobID := randomID(8)
		storedName := fmt.Sprintf("%s_%s", jobID, sanitizeFilename(header.Filename))
		storedPath := filepath.Join(uploadDir, storedName)

		size, hash, err := saveAndHash(file, storedPath)
		if err != nil {
			log.Printf("upload save error: %v", err)
			writeJSONError(w, http.StatusInternalServerError, "storage_error", "failed to store upload")
			return
		}

		if size > maxUploadBytes {
			_ = os.Remove(storedPath)
			writeJSONError(w, http.StatusRequestEntityTooLarge, "payload_too_large", "payload too large")
			return
		}

		if headerHash := r.Header.Get("X-Content-SHA256"); headerHash != "" && headerHash != hash {
			_ = os.Remove(storedPath)
			writeJSONError(w, http.StatusBadRequest, "hash_mismatch", "content hash mismatch")
			return
		}

		certSubject, certIssuer, certSerial := clientCertInfo(r)
		// Optionally wrap sensitive key material before writing job records to disk.
		encKey := r.FormValue("enc_key")
		encKeyWrapped := false
		encKeyWrapAlg := ""
		if jobKey != "" && encKey != "" {
			wrapped, err := wrapSensitiveValue(encKey, jobKey)
			if err != nil {
				log.Printf("enc_key wrap error: %v", err)
				writeJSONError(w, http.StatusInternalServerError, "enc_key_wrap_failed", "failed to secure enc_key")
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

		if err := writeJSON(filepath.Join(jobsDir, jobID+".json"), job); err != nil {
			log.Printf("job record write error: %v", err)
			writeJSONError(w, http.StatusInternalServerError, "job_write_failed", "failed to write job record")
			return
		}

		resp := map[string]string{"job_id": jobID, "status": "uploaded"}
		writeJSONResponse(w, resp)
	})

	server := &http.Server{
		Addr:              addr,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	if certPath != "" && keyPath != "" {
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
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
		log.Fatal(server.ListenAndServeTLS(certPath, keyPath))
	}

	log.Printf("upload-api listening on %s", addr)
	log.Fatal(server.ListenAndServe())
}

func saveAndHash(src multipart.File, destPath string) (int64, string, error) {
	out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return 0, "", err
	}
	defer out.Close()

	hasher := sha256.New()
	tee := io.TeeReader(src, hasher)
	size, err := io.Copy(out, tee)
	if err != nil {
		return 0, "", err
	}
	return size, hex.EncodeToString(hasher.Sum(nil)), nil
}

func clientCertInfo(r *http.Request) (string, string, string) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", "", ""
	}
	cert := r.TLS.PeerCertificates[0]
	return cert.Subject.String(), cert.Issuer.String(), cert.SerialNumber.String()
}

func loadCertPool(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(data); !ok {
		return nil, fmt.Errorf("no valid CA certs in %s", path)
	}
	return pool, nil
}

func sanitizeFilename(name string) string {
	replacer := strings.NewReplacer("/", "_", "\\", "_", "..", "_")
	return replacer.Replace(name)
}

func randomID(n int) string {
	buf := make([]byte, n)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0640)
}

func writeJSONResponse(w http.ResponseWriter, v any) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "encode_failed", "failed to encode response")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func writeJSONError(w http.ResponseWriter, status int, code, message string) {
	data, err := json.MarshalIndent(errorResponse{Error: message, Code: code}, "", "  ")
	if err != nil {
		http.Error(w, "failed to encode error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(data)
}

func envOr(key, fallback string) string {
	val := os.Getenv(key)
	if val == "" {
		return fallback
	}
	return val
}

func envOrInt(key string, fallback int) int {
	val := os.Getenv(key)
	if val == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(val)
	if err != nil {
		return fallback
	}
	return parsed
}

func envOrInt64(key string, fallback int64) int64 {
	val := os.Getenv(key)
	if val == "" {
		return fallback
	}
	parsed, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		return fallback
	}
	return parsed
}

func mustMkdirAll(path string) {
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

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{
		limit:      limit,
		window:     window,
		requests:   make(map[string]int),
		windowEnds: make(map[string]time.Time),
	}
}

func (r *rateLimiter) Allow(key string) bool {
	if r.limit <= 0 {
		return true
	}
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()

	if end, ok := r.windowEnds[key]; !ok || now.After(end) {
		r.windowEnds[key] = now.Add(r.window)
		r.requests[key] = 0
	}
	r.requests[key]++
	return r.requests[key] <= r.limit
}

func (r *rateLimiter) PruneStaleEntries(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		r.mu.Lock()
		for key, end := range r.windowEnds {
			if now.After(end) {
				delete(r.windowEnds, key)
				delete(r.requests, key)
			}
		}
		r.mu.Unlock()
	}
}

func clientIP(r *http.Request) string {
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		parts := strings.Split(ip, ",")
		return strings.TrimSpace(parts[0])
	}
	host := r.RemoteAddr
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		return host[:idx]
	}
	return host
}

func isValidClientID(clientID string) bool {
	if len(clientID) < 1 || len(clientID) > 64 {
		return false
	}
	for _, r := range clientID {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			continue
		}
		return false
	}
	return true
}

func wrapSensitiveValue(value, keyMaterial string) (string, error) {
	key, err := decodeKeyMaterial(keyMaterial)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(value), nil)
	payload := append(nonce, ciphertext...)
	return base64.StdEncoding.EncodeToString(payload), nil
}

func decodeKeyMaterial(raw string) ([]byte, error) {
	if raw == "" {
		return nil, errors.New("missing key material")
	}
	if decoded, err := base64.StdEncoding.DecodeString(raw); err == nil && len(decoded) == 32 {
		return decoded, nil
	}
	if decoded, err := hex.DecodeString(raw); err == nil && len(decoded) == 32 {
		return decoded, nil
	}
	return nil, errors.New("job key must be 32 bytes (base64 or hex)")
}
