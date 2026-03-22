// SPDX-License-Identifier: AGPL-3.0-only
// Uploader CLI: prepares payloads (optional encryption/signing), uploads to the
// upload-api, and polls results-api for completion; used by the UI and simulator.
package main

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// uploadResponse models the upload-api response payload.
type uploadResponse struct {
	JobID  string `json:"job_id"`
	Status string `json:"status"`
}

// resultsResponse models the results-api response payload.
type resultsResponse struct {
	Status string          `json:"status"`
	Data   json.RawMessage `json:"data"`
}

/// main parses flags, uploads a payload, and polls results.
///
/// Brief description of what the function does.
/// - Orchestrates optional encryption/signing, upload, and result polling.
///
/// Parameters:
///   None (reads flags for configuration).
///
/// Returns no value; exits with non-zero status on fatal errors.
///
/// Throws [FatalInputError] when required flags or TLS config are invalid.
///
/// Example: `go run ./main.go --file sample.fastq --client-id researcher-1`
func main() {
	filePath := flag.String("file", "", "path to file to upload")
	uploadURL := flag.String("upload-url", "http://localhost:8081/upload", "upload endpoint")
	resultsURL := flag.String("results-url", "http://localhost:8082/results", "results endpoint base")
	clientID := flag.String("client-id", "", "client identifier")
	pollSeconds := flag.Int("poll-seconds", 2, "poll interval seconds")
	maxPollErrors := flag.Int("max-poll-errors", 5, "max consecutive poll errors before exit")
	mtlsCert := flag.String("mtls-cert", "", "client TLS cert (PEM)")
	mtlsKey := flag.String("mtls-key", "", "client TLS key (PEM)")
	caCert := flag.String("ca-cert", "", "CA cert bundle (PEM)")
	serverCert := flag.String("server-cert", "", "server cert for encrypting payload (PEM)")
	signKey := flag.String("sign-key", "", "client private key for signing payload (PEM)")
	flag.Parse()

	// Validate required file input before any processing.
	if *filePath == "" {
		fatal("missing --file")
	}
	// Require client ID locally to match upload/results API authorization.
	if *clientID == "" {
		fatal("missing --client-id")
	}
	// Validate client ID format to avoid sending invalid identifiers.
	if !isValidClientID(*clientID) {
		fatal("invalid --client-id")
	}

	// Build HTTP client, optionally with mTLS configuration.
	client, err := newHTTPClient(*mtlsCert, *mtlsKey, *caCert)
	// Fail fast on TLS configuration errors.
	if err != nil {
		fatalf("tls config error: %v", err)
	}

	payloadPath := *filePath
	encAlg := ""
	encKey := ""
	// Encrypt the payload if a server certificate is provided.
	if *serverCert != "" {
		payloadPath, encKey, err = encryptFile(*filePath, *serverCert)
		// Fail fast if encryption fails.
		if err != nil {
			fatalf("encrypt error: %v", err)
		}
		encAlg = "aes-256-gcm+rsa-oaep-sha256"
		defer func() {
			// Remove temporary encrypted payloads to avoid disk leakage.
			if payloadPath != *filePath {
				_ = os.Remove(payloadPath)
			}
		}()
	}

	// Compute payload hash for integrity header.
	sha, err := fileSHA256(payloadPath)
	// Fail fast if hashing fails.
	if err != nil {
		fatalf("hash error: %v", err)
	}

	sigAlg := ""
	sigHex := ""
	// Sign the payload if a signing key is provided.
	if *signKey != "" {
		sigHex, err = signFile(payloadPath, *signKey)
		// Fail fast if signing fails.
		if err != nil {
			fatalf("sign error: %v", err)
		}
		sigAlg = "rsa-pss-sha256"
	}

	// API boundary: upload payload to the upload-api service.
	jobID, err := uploadFile(client, *uploadURL, payloadPath, *clientID, sha, encAlg, encKey, sigAlg, sigHex)
	// Fail fast if upload fails.
	if err != nil {
		fatalf("upload error: %v", err)
	}

	fmt.Printf("uploaded job %s\n", jobID)
	consecutiveErrors := 0
	// Poll results-api until processing completes or errors exceed threshold.
	for {
		status, payload, err := fetchResults(client, *resultsURL, jobID, *clientID)
		// Handle transient polling errors with retries.
		if err != nil {
			consecutiveErrors++
			// Exit when error threshold is exceeded.
			if consecutiveErrors > *maxPollErrors {
				fatalf("results error: %v", err)
			}
			fmt.Printf("results error: %v (retrying)\n", err)
			time.Sleep(time.Duration(*pollSeconds) * time.Second)
			// Continue polling after transient errors.
			continue
		}
		consecutiveErrors = 0
		// Stop polling once processing completes.
		if status == "processed" {
			fmt.Printf("results:\n%s\n", payload)
			// Break once final results are available.
			break
		}
		fmt.Printf("status: %s, waiting...\n", status)
		time.Sleep(time.Duration(*pollSeconds) * time.Second)
	}
}

/// newHTTPClient constructs an HTTP client with optional mTLS.
///
/// Brief description of what the function does.
/// - Builds a client that trusts the provided CA and optionally uses a client cert.
///
/// Parameters:
///   certPath - Path to client TLS certificate.
///   keyPath - Path to client TLS key.
///   caPath - Path to CA bundle.
///
/// Returns an http.Client or an error if TLS setup fails.
///
/// Throws [TLSConfigError] when certificate configuration is invalid.
///
/// Example: `client, err := newHTTPClient(cert, key, ca)`
func newHTTPClient(certPath, keyPath, caPath string) (*http.Client, error) {
	// Use the default client when no TLS configuration is provided.
	if certPath == "" && keyPath == "" && caPath == "" {
		// Return a default client when no TLS configuration is needed.
		return &http.Client{Timeout: 30 * time.Second}, nil
	}

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	// Configure client certificates when provided.
	if certPath != "" || keyPath != "" {
		// Require both cert and key to prevent partial mTLS setup.
		if certPath == "" || keyPath == "" {
			// Return error because incomplete mTLS config is unsafe.
			return nil, errors.New("mtls requires both --mtls-cert and --mtls-key")
		}
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		// Return error when the client certificate cannot be loaded.
		if err != nil {
			// Return error to indicate invalid client certificate.
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	// Configure trusted roots when a CA bundle is provided.
	if caPath != "" {
		pool, err := loadCertPool(caPath)
		// Return error when CA bundle parsing fails.
		if err != nil {
			// Return error to indicate invalid CA bundle.
			return nil, err
		}
		tlsConfig.RootCAs = pool
	}

	transport := &http.Transport{TLSClientConfig: tlsConfig}
	// Return a client with explicit timeout to avoid hanging requests.
	return &http.Client{Transport: transport, Timeout: 30 * time.Second}, nil
}

/// encryptFile encrypts a payload using AES-GCM and RSA-OAEP wrapped key.
///
/// Brief description of what the function does.
/// - Generates a random AES key/IV, encrypts the file, and wraps the key with RSA.
///
/// Parameters:
///   path - Path to the plaintext file.
///   certPath - Path to the server certificate containing RSA public key.
///
/// Returns (encryptedFilePath, encryptedKeyHex, error).
///
/// Throws [CryptoError] when key generation or encryption fails.
///
/// SECURITY: Uses AES-256-GCM and RSA-OAEP; do not downgrade algorithms.
///
/// Example: `encPath, encKey, err := encryptFile(filePath, serverCert)`
func encryptFile(path, certPath string) (string, string, error) {
	pub, err := loadRSAPublicKey(certPath)
	if err != nil {
		// Return error when public key extraction fails.
		return "", "", err
	}
	plaintext, err := os.ReadFile(path)
	if err != nil {
		// Return error when plaintext cannot be read.
		return "", "", err
	}

	aesKey := make([]byte, 32)
	iv := make([]byte, 12)
	// SECURITY: use crypto/rand for key and IV generation.
	if _, err := rand.Read(aesKey); err != nil {
		// Return error when key generation fails.
		return "", "", err
	}
	if _, err := rand.Read(iv); err != nil {
		// Return error when IV generation fails.
		return "", "", err
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		// Return error when cipher initialization fails.
		return "", "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		// Return error when GCM initialization fails.
		return "", "", err
	}

	ciphertext := gcm.Seal(nil, iv, plaintext, nil)
	// SECURITY: wrap key material with the server's RSA public key.
	encKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, append(aesKey, iv...), nil)
	if err != nil {
		// Return error when RSA wrapping fails.
		return "", "", err
	}

	out, err := os.CreateTemp("", "biozero-enc-*.bin")
	if err != nil {
		// Return error when temp file creation fails.
		return "", "", err
	}
	defer out.Close()

	if _, err := out.Write(ciphertext); err != nil {
		// Return error when encrypted payload write fails.
		return "", "", err
	}

	// Return temp path and wrapped key for upload metadata.
	return out.Name(), hex.EncodeToString(encKey), nil
}

/// signFile signs a file using RSA-PSS with SHA-256.
///
/// Brief description of what the function does.
/// - Computes a hash of the file and signs it for integrity verification.
///
/// Parameters:
///   path - Path to the file to sign.
///   keyPath - Path to the RSA private key.
///
/// Returns the signature hex string or an error.
///
/// Throws [CryptoError] when signing fails.
///
/// SECURITY: Uses RSA-PSS with SHA-256; do not switch to weaker schemes.
///
/// Example: `sig, err := signFile(filePath, keyPath)`
func signFile(path, keyPath string) (string, error) {
	priv, err := loadRSAPrivateKey(keyPath)
	if err != nil {
		// Return error when private key parsing fails.
		return "", err
	}

	hash, err := fileSHA256Bytes(path)
	if err != nil {
		// Return error when hashing fails.
		return "", err
	}
	sig, err := rsa.SignPSS(rand.Reader, priv, crypto.SHA256, hash, nil)
	if err != nil {
		// Return error when signing fails.
		return "", err
	}
	// Return hex-encoded signature for transport in headers/forms.
	return hex.EncodeToString(sig), nil
}

/// loadRSAPublicKey extracts an RSA public key from a PEM certificate.
///
/// Brief description of what the function does.
/// - Reads a PEM bundle and returns the first RSA public key found.
///
/// Parameters:
///   certPath - Path to the PEM-encoded certificate.
///
/// Returns the RSA public key or an error.
///
/// Throws [CertificateError] when the certificate is invalid or missing.
///
/// Example: `pub, err := loadRSAPublicKey("/pki/server.crt")`
func loadRSAPublicKey(certPath string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		// Return error when certificate cannot be read.
		return nil, err
	}
	// Iterate through PEM blocks to find a certificate.
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			// Break when no further PEM blocks are available.
			break
		}
		if block.Type != "CERTIFICATE" {
			// Continue until a certificate block is found.
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			// Return error when certificate parsing fails.
			return nil, err
		}
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			// Return error when certificate lacks RSA public key.
			return nil, errors.New("certificate does not contain RSA public key")
		}
		// Return the first RSA public key found.
		return pub, nil
	}
	// Return error when no certificate blocks are found.
	return nil, errors.New("no certificate found in PEM")
}

/// loadRSAPrivateKey reads an RSA private key from PEM data.
///
/// Brief description of what the function does.
/// - Supports PKCS#1 and PKCS#8 PEM-encoded keys.
///
/// Parameters:
///   keyPath - Path to the PEM-encoded private key.
///
/// Returns the RSA private key or an error.
///
/// Throws [KeyParseError] when key parsing fails.
///
/// Example: `priv, err := loadRSAPrivateKey("/pki/client.key")`
func loadRSAPrivateKey(keyPath string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(keyPath)
	if err != nil {
		// Return error when key file cannot be read.
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		// Return error when PEM decoding fails.
		return nil, errors.New("no PEM data found")
	}
	// Attempt PKCS#1 parsing first for compatibility.
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		// Return the parsed PKCS#1 key when available.
		return key, nil
	}
	// Fall back to PKCS#8 parsing when needed.
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Return error when PKCS#8 parsing fails.
		return nil, err
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		// Return error when key is not RSA.
		return nil, errors.New("not an RSA private key")
	}
	// Return the parsed RSA private key.
	return key, nil
}

/// loadCertPool reads a PEM bundle and constructs a CA pool.
///
/// Brief description of what the function does.
/// - Loads trusted CA certificates for TLS validation.
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
	// Fail fast when the CA bundle cannot be read.
	if err != nil {
		// Return error when CA bundle cannot be read.
		return nil, err
	}
	pool := x509.NewCertPool()
	// Fail fast when the PEM bundle contains no valid certs.
	if ok := pool.AppendCertsFromPEM(data); !ok {
		// Return error when no valid CA certs are found.
		return nil, fmt.Errorf("no valid CA certs in %s", path)
	}
	// Return the pool for TLS client verification.
	return pool, nil
}

/// uploadFile streams a multipart payload to upload-api.
///
/// Brief description of what the function does.
/// - Streams the file and metadata to the upload endpoint without buffering.
///
/// Parameters:
///   client - HTTP client to use.
///   url - Upload API endpoint.
///   path - Local file path to upload.
///   clientID - Client identifier for headers and form fields.
///   sha - Hex-encoded SHA-256 hash for integrity header.
///   encAlg - Encryption algorithm label (optional).
///   encKey - Wrapped encryption key (optional).
///   sigAlg - Signature algorithm label (optional).
///   sigHex - Signature hex string (optional).
///
/// Returns job ID or an error if upload fails.
///
/// Throws [NetworkError] when the upload request fails.
///
/// Example: `jobID, err := uploadFile(client, url, path, id, sha, encAlg, encKey, sigAlg, sig)`
func uploadFile(client *http.Client, url, path, clientID, sha, encAlg, encKey, sigAlg, sigHex string) (string, error) {
	file, err := os.Open(path)
	// Fail fast when the payload file cannot be opened.
	if err != nil {
		// Return error when the payload file cannot be opened.
		return "", err
	}

	// Stream multipart form data to avoid buffering large uploads in memory.
	pr, pw := io.Pipe()
	writer := multipart.NewWriter(pw)
	go func() {
		defer file.Close()
		defer pw.Close()
		defer writer.Close()

		part, err := writer.CreateFormFile("file", filepath.Base(path))
		// Abort the stream when the multipart file part cannot be created.
		if err != nil {
			_ = pw.CloseWithError(err)
			// Return to stop streaming after a fatal multipart error.
			return
		}
		// Stream the file content into the multipart part.
		if _, err := io.Copy(part, file); err != nil {
			_ = pw.CloseWithError(err)
			// Return to stop streaming after a copy error.
			return
		}
		// Include client_id only when provided to avoid empty fields.
		if clientID != "" {
			_ = writer.WriteField("client_id", clientID)
		}
		// Include enc_alg only when encryption was used.
		if encAlg != "" {
			_ = writer.WriteField("enc_alg", encAlg)
		}
		// Include enc_key only when encryption was used.
		if encKey != "" {
			_ = writer.WriteField("enc_key", encKey)
		}
		// Include sig_alg only when signing was used.
		if sigAlg != "" {
			_ = writer.WriteField("sig_alg", sigAlg)
		}
		// Include sig only when signing was used.
		if sigHex != "" {
			_ = writer.WriteField("sig", sigHex)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, pr)
	// Fail fast when request construction fails.
	if err != nil {
		// Return error when request creation fails.
		return "", err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	// Set client ID header when provided for auth checks.
	if clientID != "" {
		req.Header.Set("X-Client-Id", clientID)
	}
	req.Header.Set("X-Content-SHA256", sha)

	resp, err := client.Do(req)
	// Fail fast when the upload request fails.
	if err != nil {
		// Return error when the upload request fails.
		return "", err
	}
	defer resp.Body.Close()

	// Return error for any non-OK response status.
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		// Return error when server responds with failure.
		return "", fmt.Errorf("upload failed: %s", string(body))
	}

	var payload uploadResponse
	// Decode the upload response payload.
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		// Return error when response JSON is invalid.
		return "", err
	}
	// Return the job ID to allow result polling.
	return payload.JobID, nil
}

/// fetchResults queries results-api for job status/results.
///
/// Brief description of what the function does.
/// - Calls the results endpoint and returns status and payload.
///
/// Parameters:
///   client - HTTP client to use.
///   baseURL - Base results URL (without job ID).
///   jobID - Job identifier to query.
///   clientID - Client identifier for results authorization.
///
/// Returns (status, payload, error).
///
/// Throws [NetworkError] when the results request fails.
///
/// Example: `status, payload, err := fetchResults(client, baseURL, jobID, clientID)`
func fetchResults(client *http.Client, baseURL, jobID, clientID string) (string, string, error) {
	url := fmt.Sprintf("%s/%s", strings.TrimRight(baseURL, "/"), jobID)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	// Fail fast when request construction fails.
	if err != nil {
		// Return error when request creation fails.
		return "", "", err
	}
	if clientID != "" {
		// Send client identity for non-mTLS authorization in results-api.
		req.Header.Set("X-Client-Id", clientID)
	}
	resp, err := client.Do(req)
	// Fail fast when the results request fails.
	if err != nil {
		// Return error when the results request fails.
		return "", "", err
	}
	defer resp.Body.Close()

	// Handle a not-found status without treating it as fatal.
	if resp.StatusCode == http.StatusNotFound {
		// Return not_found to indicate job does not yet exist.
		return "not_found", "", nil
	}
	// Return error for any non-OK status.
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		// Return error when server responds with failure.
		return "", "", fmt.Errorf("results failed: %s", string(body))
	}

	var payload resultsResponse
	// Decode results payload JSON.
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		// Return error when response JSON is invalid.
		return "", "", err
	}

	// Return status and raw payload for display.
	return payload.Status, string(payload.Data), nil
}

/// fileSHA256 computes a hex-encoded SHA-256 for a file.
///
/// Brief description of what the function does.
/// - Streams file contents to avoid loading large files into memory.
///
/// Parameters:
///   path - Filesystem path to the file.
///
/// Returns the hex-encoded SHA-256 digest or an error.
///
/// Throws [IOError] when file reading fails.
///
/// Example: `sha, err := fileSHA256(path)`
func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	// Fail fast when the file cannot be opened.
	if err != nil {
		// Return error when file open fails.
		return "", err
	}
	defer file.Close()

	hasher := sha256.New()
	// Stream file contents to avoid large memory usage.
	if _, err := io.Copy(hasher, file); err != nil {
		// Return error when hashing fails.
		return "", err
	}
	// Return hex digest for header compatibility.
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

/// fileSHA256Bytes computes raw SHA-256 bytes for a file.
///
/// Brief description of what the function does.
/// - Streams file contents to produce raw digest bytes.
///
/// Parameters:
///   path - Filesystem path to the file.
///
/// Returns the raw SHA-256 digest bytes or an error.
///
/// Throws [IOError] when file reading fails.
///
/// Example: `digest, err := fileSHA256Bytes(path)`
func fileSHA256Bytes(path string) ([]byte, error) {
	file, err := os.Open(path)
	// Fail fast when the file cannot be opened.
	if err != nil {
		// Return error when file open fails.
		return nil, err
	}
	defer file.Close()

	hasher := sha256.New()
	// Stream file contents to avoid large memory usage.
	if _, err := io.Copy(hasher, file); err != nil {
		// Return error when hashing fails.
		return nil, err
	}
	// Return raw digest bytes for signing.
	return hasher.Sum(nil), nil
}

/// isValidClientID validates client IDs for safe transport.
///
/// Brief description of what the function does.
/// - Allows only alphanumerics, underscore, and hyphen with bounded length.
///
/// Parameters:
///   clientID - Client identifier to validate.
///
/// Returns true when the ID is valid.
///
/// Throws [None] - pure validation.
///
/// Example: `if !isValidClientID(id) { ... }`
func isValidClientID(clientID string) bool {
	// Allow empty client IDs because the flag is optional.
	if clientID == "" {
		// Return true when no client ID is provided (optional flag).
		return true
	}
	// Enforce length limits to keep identifiers reasonable.
	if len(clientID) > 64 {
		// Return false when client ID exceeds length constraints.
		return false
	}
	// Validate each character to avoid unsafe IDs.
	for _, r := range clientID {
		// Allow only safe characters for headers and logs.
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			continue
		}
		// Return false when an invalid character is found.
		return false
	}
	// Return true when all characters are valid.
	return true
}

/// fatal prints an error message and exits.
///
/// Brief description of what the function does.
/// - Sends a message to stderr and terminates with status 1.
///
/// Parameters:
///   message - Error message to print.
///
/// Returns no value; exits the process.
///
/// Throws [FatalError] always.
///
/// Example: `fatal("missing --file")`
func fatal(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}

/// fatalf formats an error message and exits.
///
/// Brief description of what the function does.
/// - Formats a message to stderr and terminates with status 1.
///
/// Parameters:
///   format - Format string.
///   args - Arguments for formatting.
///
/// Returns no value; exits the process.
///
/// Throws [FatalError] always.
///
/// Example: `fatalf("upload error: %v", err)`
func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
