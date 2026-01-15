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

type resultResponse struct {
	Status string          `json:"status"`
	Data   json.RawMessage `json:"data,omitempty"`
}

type jobRecord struct {
	JobID            string `json:"job_id"`
	Status           string `json:"status"`
	OriginalName     string `json:"original_name"`
	ClientID         string `json:"client_id"`
	ClientCertSerial string `json:"client_cert_serial,omitempty"`
}

func main() {
	addr := envOr("BIOZERO_RESULTS_ADDR", ":8082")
	dataDir := envOr("BIOZERO_DATA_DIR", "./data")
	certPath := os.Getenv("BIOZERO_TLS_CERT")
	keyPath := os.Getenv("BIOZERO_TLS_KEY")
	caPath := os.Getenv("BIOZERO_TLS_CA")
	rateLimit := envOrInt("BIOZERO_RATE_LIMIT", 120)

	resultsDir := filepath.Join(dataDir, "results")
	jobsDir := filepath.Join(dataDir, "jobs")
	mustMkdirAll(resultsDir)
	mustMkdirAll(jobsDir)

	limiter := newRateLimiter(rateLimit, time.Minute)

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	http.HandleFunc("/results/", func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow(clientIP(r)) {
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		jobID := strings.TrimPrefix(r.URL.Path, "/results/")
		if jobID == "" {
			http.Error(w, "missing job id", http.StatusBadRequest)
			return
		}
		if !isValidJobID(jobID) {
			http.Error(w, "invalid job id", http.StatusBadRequest)
			return
		}

		resultPath := filepath.Join(resultsDir, jobID+".json")
		if data, err := os.ReadFile(resultPath); err == nil {
			if !authorizedForJob(r, jobsDir, jobID) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			writeJSONResponse(w, resultResponse{Status: "processed", Data: data})
			return
		}

		jobPath := filepath.Join(jobsDir, jobID+".json")
		if _, err := os.Stat(jobPath); err == nil {
			if !authorizedForJob(r, jobsDir, jobID) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			writeJSONResponse(w, resultResponse{Status: "pending"})
			return
		}

		http.Error(w, "job not found", http.StatusNotFound)
	})

	server := &http.Server{Addr: addr}
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
		log.Printf("results-api listening with TLS on %s", addr)
		log.Fatal(server.ListenAndServeTLS(certPath, keyPath))
	}

	log.Printf("results-api listening on %s", addr)
	log.Fatal(server.ListenAndServe())
}

func writeJSONResponse(w http.ResponseWriter, v any) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
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

func mustMkdirAll(path string) {
	if err := os.MkdirAll(path, 0755); err != nil {
		log.Fatalf("failed to create %s: %v", path, err)
	}
}

func isValidJobID(jobID string) bool {
	if len(jobID) < 8 || len(jobID) > 64 {
		return false
	}
	for _, r := range jobID {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func authorizedForJob(r *http.Request, jobsDir, jobID string) bool {
	jobPath := filepath.Join(jobsDir, jobID+".json")
	job, err := readJob(jobPath)
	if err != nil {
		return false
	}

	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 && job.ClientCertSerial != "" {
		cert := r.TLS.PeerCertificates[0]
		return cert.SerialNumber.String() == job.ClientCertSerial
	}

	clientID := r.Header.Get("X-Client-Id")
	if clientID == "" {
		return false
	}
	return clientID == job.ClientID
}

func readJob(path string) (jobRecord, error) {
	var job jobRecord
	data, err := os.ReadFile(path)
	if err != nil {
		return job, err
	}
	if err := json.Unmarshal(data, &job); err != nil {
		return job, err
	}
	return job, nil
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
