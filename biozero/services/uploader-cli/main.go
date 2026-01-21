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

type uploadResponse struct {
	JobID  string `json:"job_id"`
	Status string `json:"status"`
}

type resultsResponse struct {
	Status string          `json:"status"`
	Data   json.RawMessage `json:"data"`
}

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

	if *filePath == "" {
		fatal("missing --file")
	}
	if !isValidClientID(*clientID) && *clientID != "" {
		fatal("invalid --client-id")
	}

	client, err := newHTTPClient(*mtlsCert, *mtlsKey, *caCert)
	if err != nil {
		fatalf("tls config error: %v", err)
	}

	payloadPath := *filePath
	encAlg := ""
	encKey := ""
	if *serverCert != "" {
		payloadPath, encKey, err = encryptFile(*filePath, *serverCert)
		if err != nil {
			fatalf("encrypt error: %v", err)
		}
		encAlg = "aes-256-gcm+rsa-oaep-sha256"
		defer func() {
			if payloadPath != *filePath {
				_ = os.Remove(payloadPath)
			}
		}()
	}

	sha, err := fileSHA256(payloadPath)
	if err != nil {
		fatalf("hash error: %v", err)
	}

	sigAlg := ""
	sigHex := ""
	if *signKey != "" {
		sigHex, err = signFile(payloadPath, *signKey)
		if err != nil {
			fatalf("sign error: %v", err)
		}
		sigAlg = "rsa-pss-sha256"
	}

	jobID, err := uploadFile(client, *uploadURL, payloadPath, *clientID, sha, encAlg, encKey, sigAlg, sigHex)
	if err != nil {
		fatalf("upload error: %v", err)
	}

	fmt.Printf("uploaded job %s\n", jobID)
	consecutiveErrors := 0
	for {
		status, payload, err := fetchResults(client, *resultsURL, jobID)
		if err != nil {
			consecutiveErrors++
			if consecutiveErrors > *maxPollErrors {
				fatalf("results error: %v", err)
			}
			fmt.Printf("results error: %v (retrying)\n", err)
			time.Sleep(time.Duration(*pollSeconds) * time.Second)
			continue
		}
		consecutiveErrors = 0
		if status == "processed" {
			fmt.Printf("results:\n%s\n", payload)
			break
		}
		fmt.Printf("status: %s, waiting...\n", status)
		time.Sleep(time.Duration(*pollSeconds) * time.Second)
	}
}

func newHTTPClient(certPath, keyPath, caPath string) (*http.Client, error) {
	if certPath == "" && keyPath == "" && caPath == "" {
		return &http.Client{Timeout: 30 * time.Second}, nil
	}

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if certPath != "" || keyPath != "" {
		if certPath == "" || keyPath == "" {
			return nil, errors.New("mtls requires both --mtls-cert and --mtls-key")
		}
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	if caPath != "" {
		pool, err := loadCertPool(caPath)
		if err != nil {
			return nil, err
		}
		tlsConfig.RootCAs = pool
	}

	transport := &http.Transport{TLSClientConfig: tlsConfig}
	return &http.Client{Transport: transport, Timeout: 30 * time.Second}, nil
}

func encryptFile(path, certPath string) (string, string, error) {
	pub, err := loadRSAPublicKey(certPath)
	if err != nil {
		return "", "", err
	}
	plaintext, err := os.ReadFile(path)
	if err != nil {
		return "", "", err
	}

	aesKey := make([]byte, 32)
	iv := make([]byte, 12)
	if _, err := rand.Read(aesKey); err != nil {
		return "", "", err
	}
	if _, err := rand.Read(iv); err != nil {
		return "", "", err
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", err
	}

	ciphertext := gcm.Seal(nil, iv, plaintext, nil)
	encKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, append(aesKey, iv...), nil)
	if err != nil {
		return "", "", err
	}

	out, err := os.CreateTemp("", "biozero-enc-*.bin")
	if err != nil {
		return "", "", err
	}
	defer out.Close()

	if _, err := out.Write(ciphertext); err != nil {
		return "", "", err
	}

	return out.Name(), hex.EncodeToString(encKey), nil
}

func signFile(path, keyPath string) (string, error) {
	priv, err := loadRSAPrivateKey(keyPath)
	if err != nil {
		return "", err
	}

	hash, err := fileSHA256Bytes(path)
	if err != nil {
		return "", err
	}
	sig, err := rsa.SignPSS(rand.Reader, priv, crypto.SHA256, hash, nil)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sig), nil
}

func loadRSAPublicKey(certPath string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("certificate does not contain RSA public key")
		}
		return pub, nil
	}
	return nil, errors.New("no certificate found in PEM")
}

func loadRSAPrivateKey(keyPath string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM data found")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA private key")
	}
	return key, nil
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

func uploadFile(client *http.Client, url, path, clientID, sha, encAlg, encKey, sigAlg, sigHex string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
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
		if err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		if _, err := io.Copy(part, file); err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		if clientID != "" {
			_ = writer.WriteField("client_id", clientID)
		}
		if encAlg != "" {
			_ = writer.WriteField("enc_alg", encAlg)
		}
		if encKey != "" {
			_ = writer.WriteField("enc_key", encKey)
		}
		if sigAlg != "" {
			_ = writer.WriteField("sig_alg", sigAlg)
		}
		if sigHex != "" {
			_ = writer.WriteField("sig", sigHex)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, pr)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	if clientID != "" {
		req.Header.Set("X-Client-Id", clientID)
	}
	req.Header.Set("X-Content-SHA256", sha)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("upload failed: %s", string(body))
	}

	var payload uploadResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", err
	}
	return payload.JobID, nil
}

func fetchResults(client *http.Client, baseURL, jobID string) (string, string, error) {
	url := fmt.Sprintf("%s/%s", strings.TrimRight(baseURL, "/"), jobID)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "not_found", "", nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", "", fmt.Errorf("results failed: %s", string(body))
	}

	var payload resultsResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", "", err
	}

	return payload.Status, string(payload.Data), nil
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func fileSHA256Bytes(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return nil, err
	}
	return hasher.Sum(nil), nil
}

func isValidClientID(clientID string) bool {
	if clientID == "" {
		return true
	}
	if len(clientID) > 64 {
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

func fatal(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
