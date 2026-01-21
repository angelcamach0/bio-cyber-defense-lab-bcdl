// SPDX-License-Identifier: AGPL-3.0-only
// Enclave runner for BioZero: polls job records written by upload-api, verifies
// signatures, decrypts payloads, invokes the bio pipeline, and writes results
// consumed by results-api; it can unwrap sensitive fields using BIOZERO_JOB_KEY.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// jobRecord captures upload metadata needed for processing and verification.
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

// detectionRules holds configurable thresholds and reference inputs.
type detectionRules struct {
	MaxSizeBytes               int64    `json:"max_size_bytes"`
	SuspiciousNameTokens       []string `json:"suspicious_name_patterns"`
	HighScore                  float64  `json:"high_score"`
	LowScore                   float64  `json:"low_score"`
	ThreatPanelFasta           string   `json:"threat_panel_fasta,omitempty"`
	ThreatMinReads             int       `json:"threat_min_reads,omitempty"`
	ThreatMinFraction          float64   `json:"threat_min_fraction,omitempty"`
	FastpMinQ30                float64   `json:"fastp_min_q30,omitempty"`
	CriticalWarningScoreBoost  float64   `json:"critical_warning_score_boost,omitempty"`
	HighThreshold              float64   `json:"high_threshold,omitempty"`
	MediumThreshold            float64   `json:"medium_threshold,omitempty"`
}

// resultRecord captures the processed output persisted for results-api.
type resultRecord struct {
	JobID            string          `json:"job_id"`
	Status           string          `json:"status"`
	ProcessedAt      string          `json:"processed_at"`
	UploadSHA256     string          `json:"upload_sha256"`
	ProcessedSHA256  string          `json:"processed_sha256"`
	SizeBytes        int64           `json:"size_bytes"`
	Decrypted        bool            `json:"decrypted"`
	DecryptionError  string          `json:"decryption_error,omitempty"`
	SignatureValid   bool            `json:"signature_valid"`
	SignatureError   string          `json:"signature_error,omitempty"`
	PipelineOutput   json.RawMessage `json:"pipeline_output,omitempty"`
	PipelineError    string          `json:"pipeline_error,omitempty"`
	Detection        detectionResult `json:"detection"`
	ClientCertSerial string          `json:"client_cert_serial,omitempty"`
}

// detectionResult summarizes scoring, verdict, and detection signals.
type detectionResult struct {
	Score   float64         `json:"score"`
	Reason  string          `json:"reason"`
	Verdict string          `json:"verdict,omitempty"`
	Reasons []string        `json:"reasons,omitempty"`
	Signals map[string]any  `json:"signals,omitempty"`
}

// pipelineInfo extracts key fields from pipeline JSON output.
type pipelineInfo struct {
	ReadCount     int
	AvgReadLength int
	Warnings      []string
	FastpQ30      float64
	HasFastp      bool
}

// warningSummary aggregates warning severity counts.
type warningSummary struct {
	Critical int `json:"critical"`
	Warn     int `json:"warn"`
	Info     int `json:"info"`
}

// alignmentStats captures alignment summary metrics.
type alignmentStats struct {
	MappedReads int            `json:"mapped_reads"`
	TotalReads  int            `json:"total_reads"`
	Fraction    float64        `json:"fraction"`
	Targets     map[string]int `json:"targets,omitempty"`
}

/// main starts the enclave-runner loop and processes job records.
///
/// Brief description of what the function does.
/// - Polls job records, verifies integrity, decrypts payloads, runs pipeline, and writes results.
///
/// Parameters:
///   None (reads env vars for configuration).
///
/// Returns no value; runs indefinitely until the process exits.
///
/// Throws [FatalIOError] when required directories cannot be created.
///
/// Example: `go run ./main.go`
func main() {
	dataDir := envOr("BIOZERO_DATA_DIR", "./data")
	pollSeconds := envOr("BIOZERO_POLL_SECONDS", "2")
	privateKeyPath := os.Getenv("BIOZERO_PRIVATE_KEY")
	signerCertPath := os.Getenv("BIOZERO_SIGNER_CERT")
	jobKey := os.Getenv("BIOZERO_JOB_KEY")
	decryptedDir := envOr("BIOZERO_DECRYPT_DIR", filepath.Join(dataDir, "decrypted"))
	pipelinePath := envOr("BIOZERO_PIPELINE_PATH", defaultPipelinePath())
	referencePath := os.Getenv("BIOZERO_REFERENCE_PATH")
	pipelineTimeout := envOrDuration("BIOZERO_PIPELINE_TIMEOUT", 10*time.Minute)

	uploadDir := filepath.Join(dataDir, "uploads")
	jobsDir := filepath.Join(dataDir, "jobs")
	resultsDir := filepath.Join(dataDir, "results")
	rulesPath := envOr("BIOZERO_RULES_PATH", defaultRulesPath())

	// Ensure required directories exist before processing jobs.
	mustMkdirAll(uploadDir)
	mustMkdirAll(jobsDir)
	mustMkdirAll(resultsDir)
	mustMkdirAll(decryptedDir)

	// Load detection rules once and apply defaults.
	rules := loadRules(rulesPath)
	interval, err := time.ParseDuration(pollSeconds + "s")
	if err != nil {
		// Fallback to a safe polling interval if parsing fails.
		interval = 2 * time.Second
	}

	log.Printf("enclave-runner watching %s", jobsDir)
	// Loop indefinitely to process jobs on a fixed interval.
	for {
		processJobs(jobsDir, uploadDir, resultsDir, decryptedDir, rules, privateKeyPath, signerCertPath, pipelinePath, referencePath, jobKey, pipelineTimeout)
		time.Sleep(interval)
	}
}

/// processJobs scans job records and produces results.
///
/// Brief description of what the function does.
/// - Reads job files, validates inputs, decrypts payloads, runs pipeline, and writes results.
///
/// Parameters:
///   jobsDir - Directory containing job records.
///   uploadDir - Directory containing uploaded payloads.
///   resultsDir - Directory to write results.
///   decryptedDir - Directory for decrypted payloads.
///   rules - Detection rules to apply.
///   privateKeyPath - RSA private key path for decryption.
///   signerCertPath - RSA signer cert path for signature verification.
///   pipelinePath - Path to the pipeline executable.
///   referencePath - Optional reference genome path.
///   jobKey - Optional key for unwrapping enc_key.
///   pipelineTimeout - Maximum duration for pipeline execution.
///
/// Returns no value; logs errors and continues processing.
///
/// Throws [IOError] when job directories cannot be read; errors are logged.
///
/// Example: `processJobs(jobsDir, uploadDir, resultsDir, decryptedDir, rules, privKey, signer, pipeline, ref, jobKey, timeout)`
func processJobs(jobsDir, uploadDir, resultsDir, decryptedDir string, rules detectionRules, privateKeyPath, signerCertPath, pipelinePath, referencePath, jobKey string, pipelineTimeout time.Duration) {
	entries, err := os.ReadDir(jobsDir)
	if err != nil {
		log.Printf("read jobs dir error: %v", err)
		// Return early when the jobs directory is unavailable.
		return
	}

	// Iterate over each job file and process when eligible.
	for _, entry := range entries {
		// Skip directories and non-JSON files.
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			// Continue to the next entry when this one is not a job file.
			continue
		}

		func() {
			defer func() {
				// Recover from panics to keep the runner alive.
				if recovered := recover(); recovered != nil {
					log.Printf("job processing panic %s: %v", entry.Name(), recovered)
				}
			}()

			jobPath := filepath.Join(jobsDir, entry.Name())
			job, err := readJob(jobPath)
			if err != nil {
				log.Printf("job read error %s: %v", entry.Name(), err)
				// Return to avoid processing an unreadable job file.
				return
			}
			if job.Status != "uploaded" {
				// Return to skip jobs already processed or in other states.
				return
			}
			if !isValidJobID(job.JobID) {
				log.Printf("job id validation failed %s", job.JobID)
				// Return to avoid path traversal or invalid IDs.
				return
			}

			resultPath := filepath.Join(resultsDir, job.JobID+".json")
			if _, err := os.Stat(resultPath); err == nil {
				// Return to avoid reprocessing jobs with existing results.
				return
			}

			// Upload path is derived from job metadata produced by upload-api.
			storedName := job.JobID + "_" + sanitizeFilename(job.OriginalName)
			uploadPath := filepath.Join(uploadDir, storedName)

			uploadSHA, _, err := hashFile(uploadPath)
			if err != nil {
				log.Printf("hash error %s: %v", uploadPath, err)
				// Return to avoid processing when the upload cannot be read.
				return
			}

			signatureValid, signatureErr := verifySignature(uploadPath, job.Sig, signerCertPath)

			contentPath := uploadPath
			decrypted := false
			decryptionError := ""
			encKey := job.EncKey
			// Unwrap the encryption key when it was wrapped at rest.
			if job.EncKeyWrapped {
				// Handle wrapped encryption keys when present.
				if jobKey == "" {
					// Record an error when the unwrap key is missing.
					decryptionError = "job key not configured"
				} else if job.EncKeyWrapAlg != "" && job.EncKeyWrapAlg != "aes-256-gcm" {
					// Record an error for unsupported wrapping algorithms.
					decryptionError = "unsupported enc_key_wrap_alg"
				} else {
					unwrapped, err := unwrapSensitiveValue(job.EncKey, jobKey)
					if err != nil {
						// Record the unwrap error for reporting.
						decryptionError = err.Error()
					} else {
						// Use the unwrapped key for subsequent decryption.
						encKey = unwrapped
					}
				}
			}

			// Decrypt only when encryption metadata is present and keys are configured.
			if job.EncAlg != "" && encKey != "" {
				if privateKeyPath == "" {
					// Record an error when the private key is missing.
					decryptionError = "private key not configured"
				} else if decryptionError == "" {
					outPath, err := decryptPayload(uploadPath, encKey, privateKeyPath, decryptedDir, job.JobID)
					if err != nil {
						// Record the decryption error for reporting.
						decryptionError = err.Error()
					} else {
						// Switch to decrypted content for downstream processing.
						contentPath = outPath
						decrypted = true
					}
				}
			}

			processedSHA, processedSize, err := hashFile(contentPath)
			if err != nil {
				log.Printf("hash error %s: %v", contentPath, err)
				// Return to avoid writing results for unreadable content.
				return
			}

			// Invoke the pipeline wrapper and evaluate detection signals.
			pipelineOutput, pipelineError := runPipeline(pipelinePath, contentPath, referencePath, pipelineTimeout)
			detection := evaluateDetection(job, processedSize, rules, decrypted, decryptionError, signatureValid, signatureErr, pipelineOutput, contentPath)
			result := resultRecord{
				JobID:            job.JobID,
				Status:           "processed",
				ProcessedAt:      time.Now().UTC().Format(time.RFC3339),
				UploadSHA256:     uploadSHA,
				ProcessedSHA256:  processedSHA,
				SizeBytes:        processedSize,
				Decrypted:        decrypted,
				DecryptionError:  decryptionError,
				SignatureValid:   signatureValid,
				SignatureError:   signatureErr,
				PipelineOutput:   pipelineOutput,
				PipelineError:    pipelineError,
				Detection:        detection,
				ClientCertSerial: job.ClientCertSerial,
			}

			if err := writeJSON(resultPath, result); err != nil {
				log.Printf("result write error %s: %v", resultPath, err)
				// Return to avoid updating job status when results are missing.
				return
			}

			job.Status = "processed"
			job.SHA256 = processedSHA
			job.SizeBytes = processedSize
			if err := writeJSON(jobPath, job); err != nil {
				log.Printf("job update error %s: %v", jobPath, err)
			}
		}()
	}
}

/// verifySignature checks RSA-PSS signatures for an uploaded payload.
///
/// Brief description of what the function does.
/// - Validates a hex-encoded signature against the file's SHA-256 digest.
///
/// Parameters:
///   path - Filesystem path to the payload.
///   sigHex - Hex-encoded signature string.
///   certPath - Path to the signer certificate containing RSA public key.
///
/// Returns (valid, errorMessage) where errorMessage is empty on success.
///
/// Throws [CryptoError] when signature decoding or verification fails.
///
/// SECURITY: Uses RSA-PSS with SHA-256; do not downgrade algorithms.
///
/// Example: `ok, errMsg := verifySignature(path, sigHex, signerCert)`
func verifySignature(path, sigHex, certPath string) (bool, string) {
	if sigHex == "" {
		// Return false with empty error when no signature is provided.
		return false, ""
	}
	if certPath == "" {
		// Return false when signer cert is missing.
		return false, "signer cert not configured"
	}
	pub, err := loadRSAPublicKey(certPath)
	if err != nil {
		// Return false when public key extraction fails.
		return false, err.Error()
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		// Return false when signature is not valid hex.
		return false, "invalid signature encoding"
	}

	hash, err := fileSHA256Bytes(path)
	if err != nil {
		// Return false when hashing fails.
		return false, err.Error()
	}
	if err := rsa.VerifyPSS(pub, crypto.SHA256, hash, sig, nil); err != nil {
		// Return false when signature verification fails.
		return false, err.Error()
	}
	// Return true when verification succeeds.
	return true, ""
}

/// decryptPayload decrypts an encrypted payload using RSA and AES-GCM.
///
/// Brief description of what the function does.
/// - Unwraps AES key material with RSA-OAEP and decrypts payload with AES-256-GCM.
///
/// Parameters:
///   cipherPath - Path to the encrypted payload.
///   encKeyHex - Hex-encoded wrapped AES key material.
///   privateKeyPath - RSA private key path for decryption.
///   decryptedDir - Directory to store decrypted output.
///   jobID - Job ID for naming the decrypted file.
///
/// Returns decrypted file path or an error.
///
/// Throws [CryptoError] when decryption or key unwrap fails.
///
/// SECURITY: Uses RSA-OAEP + AES-256-GCM; do not downgrade algorithms.
///
/// Example: `outPath, err := decryptPayload(encPath, encKey, privKey, decryptDir, jobID)`
func decryptPayload(cipherPath, encKeyHex, privateKeyPath, decryptedDir, jobID string) (string, error) {
	encKey, err := hex.DecodeString(encKeyHex)
	if err != nil {
		// Return error when wrapped key is not valid hex.
		return "", errors.New("invalid enc_key encoding")
	}
	priv, err := loadRSAPrivateKey(privateKeyPath)
	if err != nil {
		// Return error when private key cannot be loaded.
		return "", err
	}
	keyMaterial, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, encKey, nil)
	if err != nil {
		// Return error when RSA unwrapping fails.
		return "", err
	}
	if len(keyMaterial) < 44 {
		// Return error when key material is too short for key+IV.
		return "", errors.New("invalid key material length")
	}
	aesKey := keyMaterial[:32]
	iv := keyMaterial[32:44]

	ciphertext, err := os.ReadFile(cipherPath)
	if err != nil {
		// Return error when ciphertext cannot be read.
		return "", err
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		// Return error when cipher initialization fails.
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		// Return error when GCM initialization fails.
		return "", err
	}
	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		// Return error when decryption fails or tag is invalid.
		return "", err
	}

	outPath := filepath.Join(decryptedDir, fmt.Sprintf("%s_decrypted.bin", jobID))
	if err := os.WriteFile(outPath, plaintext, 0600); err != nil {
		// Return error when writing decrypted output fails.
		return "", err
	}
	// Return the path to the decrypted payload.
	return outPath, nil
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
/// Example: `pub, err := loadRSAPublicKey("/pki/signer.crt")`
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
/// Example: `priv, err := loadRSAPrivateKey("/pki/server.key")`
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
		// Return parsed PKCS#1 key when available.
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

/// evaluateDetection computes the detection score and verdict for a job.
///
/// Brief description of what the function does.
/// - Combines rules, pipeline signals, and integrity checks into a final score.
///
/// Parameters:
///   job - Job metadata for context.
///   size - Processed payload size in bytes.
///   rules - Detection rules and thresholds.
///   decrypted - Whether decryption succeeded.
///   decryptionError - Any decryption error message.
///   signatureValid - Whether signature verification succeeded.
///   signatureErr - Signature verification error message.
///   pipelineOutput - Raw pipeline JSON output.
///   contentPath - Path to the processed payload for alignment.
///
/// Returns a detectionResult with score, verdict, and signals.
///
/// Throws [None] - errors are represented in the result fields.
///
/// Example: `result := evaluateDetection(job, size, rules, decrypted, err, sigOk, sigErr, output, path)`
func evaluateDetection(job jobRecord, size int64, rules detectionRules, decrypted bool, decryptionError string, signatureValid bool, signatureErr string, pipelineOutput json.RawMessage, contentPath string) detectionResult {
	info := parsePipelineInfo(pipelineOutput)
	warnings := classifyWarnings(info.Warnings)

	signals := map[string]any{
		"warnings": warnings,
		"integrity": map[string]any{
			"signature_valid": signatureValid,
			"decrypted":       decrypted,
		},
		"pipeline": map[string]any{
			"read_count":      info.ReadCount,
			"avg_read_length": info.AvgReadLength,
		},
	}

	// Only include fastp metrics when present in pipeline output.
	if info.HasFastp {
		signals["fastp"] = map[string]any{
			"q30_rate": info.FastpQ30,
		}
	}

	var alignment alignmentStats
	// Run threat panel alignment when configured to augment signals.
	if rules.ThreatPanelFasta != "" {
		stats, warn := threatPanelAlignment(rules.ThreatPanelFasta, contentPath)
		if warn != "" {
			log.Printf("threat panel alignment warning: %s", warn)
		}
		alignment = stats
		// Avoid division by zero when no reads are present.
		if stats.TotalReads > 0 {
			stats.Fraction = float64(stats.MappedReads) / float64(stats.TotalReads)
			alignment = stats
		}
		signals["alignment"] = alignment
	}

	score := rules.LowScore
	reasons := []string{}

	lowerName := strings.ToLower(job.OriginalName)
	// Flag suspicious filenames based on configured tokens.
	for _, token := range rules.SuspiciousNameTokens {
		if token == "" {
			// Skip empty tokens to avoid false positives.
			continue
		}
		if strings.Contains(lowerName, strings.ToLower(token)) {
			score += 0.2
			reasons = append(reasons, "suspicious_filename")
			break
		}
	}

	// Flag oversized files when a max size rule is configured.
	if rules.MaxSizeBytes > 0 && size > rules.MaxSizeBytes {
		score += 0.2
		reasons = append(reasons, "file_size_exceeded")
	}

	// Penalize failed decryption when encryption was expected.
	if decryptionError != "" && !decrypted {
		score += 0.1
		reasons = append(reasons, "decryption_failed")
	}
	// Penalize invalid signatures when provided.
	if signatureErr != "" && !signatureValid {
		score += 0.2
		reasons = append(reasons, "signature_invalid")
	}

	// Boost score when critical pipeline warnings occur.
	if warnings.Critical > 0 {
		score += rules.CriticalWarningScoreBoost
		reasons = append(reasons, "critical_pipeline_warnings")
	}

	// Penalize low-quality reads when fastp metrics are available.
	if info.HasFastp && rules.FastpMinQ30 > 0 && info.FastpQ30 > 0 && info.FastpQ30 < rules.FastpMinQ30 {
		score += 0.1
		reasons = append(reasons, "low_quality_reads")
	}

	totalReads := info.ReadCount
	if totalReads == 0 {
		// Fall back to alignment-derived reads when pipeline count is missing.
		totalReads = alignment.TotalReads
	}
	// Check for threat panel hits using read thresholds.
	if rules.ThreatMinReads > 0 && totalReads > 0 {
		fraction := float64(alignment.MappedReads) / float64(totalReads)
		if alignment.MappedReads >= rules.ThreatMinReads && fraction >= rules.ThreatMinFraction {
			score += 0.6
			reasons = append(reasons, "threat_panel_hit")
		}
	}

	// Clamp scores to the [0,1] range to keep thresholds meaningful.
	if score > 1 {
		score = 1
	}
	if score < 0 {
		score = 0
	}

	verdict := "low"
	// Map score to verdict thresholds.
	if score >= rules.HighThreshold {
		verdict = "high"
	} else if score >= rules.MediumThreshold {
		verdict = "medium"
	}

	reason := "no suspicious indicators"
	// Prefer the first specific reason when available.
	if len(reasons) > 0 {
		reason = reasons[0]
	}

	// Return the assembled detection result.
	return detectionResult{
		Score:   score,
		Reason:  reason,
		Verdict: verdict,
		Reasons: reasons,
		Signals: signals,
	}
}

/// parsePipelineInfo extracts key fields from pipeline JSON output.
///
/// Brief description of what the function does.
/// - Parses counts, warnings, and fastp metrics from pipeline output.
///
/// Parameters:
///   raw - Raw pipeline JSON output.
///
/// Returns a pipelineInfo struct with parsed fields.
///
/// Throws [ParseError] when JSON is invalid; returns empty info instead.
///
/// Example: `info := parsePipelineInfo(output)`
func parsePipelineInfo(raw json.RawMessage) pipelineInfo {
	info := pipelineInfo{}
	if len(raw) == 0 {
		// Return empty info when pipeline output is missing.
		return info
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		// Return empty info when JSON cannot be parsed.
		return info
	}

	// Extract core counts when present.
	if v, ok := payload["read_count"]; ok {
		info.ReadCount = toInt(v)
	}
	if v, ok := payload["avg_read_length"]; ok {
		info.AvgReadLength = toInt(v)
	}
	if v, ok := payload["warnings"]; ok {
		info.Warnings = toStringSlice(v)
	}

	outputs, ok := payload["outputs"].(map[string]any)
	if !ok {
		// Return when outputs are not present in payload.
		return info
	}
	fastpSummary, ok := outputs["fastp_summary"].(map[string]any)
	if !ok {
		// Return when fastp summary is missing.
		return info
	}
	if q30, ok := extractFastpQ30(fastpSummary); ok {
		info.FastpQ30 = q30
		info.HasFastp = true
	}
	// Return the populated pipeline info.
	return info
}

/// extractFastpQ30 retrieves the Q30 rate from fastp summary data.
///
/// Brief description of what the function does.
/// - Reads q30_rate from fastp summary fields.
///
/// Parameters:
///   summary - Parsed fastp summary map.
///
/// Returns (q30Rate, ok) indicating whether the value was found.
///
/// Throws [None] - best-effort extraction.
///
/// Example: `q30, ok := extractFastpQ30(summary)`
func extractFastpQ30(summary map[string]any) (float64, bool) {
	summaryMap, ok := summary["summary"].(map[string]any)
	if !ok {
		// Return false when summary is missing or wrong type.
		return 0, false
	}
	if after, ok := summaryMap["after_filtering"].(map[string]any); ok {
		if q30, ok := toFloat(after["q30_rate"]); ok {
			// Return q30 rate from after_filtering when available.
			return q30, true
		}
	}
	if before, ok := summaryMap["before_filtering"].(map[string]any); ok {
		if q30, ok := toFloat(before["q30_rate"]); ok {
			// Return q30 rate from before_filtering when after is missing.
			return q30, true
		}
	}
	// Return false when no q30 rate could be extracted.
	return 0, false
}

/// classifyWarnings counts warning severities based on keywords.
///
/// Brief description of what the function does.
/// - Categorizes warnings into critical, warn, and info buckets.
///
/// Parameters:
///   warnings - List of warning strings from pipeline output.
///
/// Returns a warningSummary with severity counts.
///
/// Throws [None] - string classification only.
///
/// Example: `summary := classifyWarnings(warnings)`
func classifyWarnings(warnings []string) warningSummary {
	summary := warningSummary{}
	// Iterate through warnings to classify severity.
	for _, w := range warnings {
		lower := strings.ToLower(w)
		// Use keyword matching to determine severity.
		switch {
		case strings.Contains(lower, "error"),
			strings.Contains(lower, "failed"),
			strings.Contains(lower, "fatal"):
			// Increment critical count when errors are detected.
			summary.Critical++
		case strings.Contains(lower, "warn"):
			// Increment warning count when warning keywords are present.
			summary.Warn++
		default:
			// Treat remaining messages as informational.
			summary.Info++
		}
	}
	// Return the aggregated summary.
	return summary
}

/// threatPanelAlignment aligns reads to a threat panel FASTA.
///
/// Brief description of what the function does.
/// - Runs minimap2 to estimate mapped read counts by target.
///
/// Parameters:
///   fastaPath - Path to threat panel FASTA.
///   fastqPath - Path to input FASTQ file.
///
/// Returns (alignmentStats, warningMessage).
///
/// Throws [ExternalToolError] when minimap2 is missing or fails.
///
/// Performance:
///   Time complexity: O(n) over alignment output lines.
///   Space complexity: O(t) for target counts.
///
/// Example: `stats, warn := threatPanelAlignment(fastaPath, fastqPath)`
func threatPanelAlignment(fastaPath, fastqPath string) (alignmentStats, string) {
	stats := alignmentStats{Targets: map[string]int{}}
	if _, err := os.Stat(fastaPath); err != nil {
		// Return warning when threat panel FASTA is missing.
		return stats, "threat panel not found"
	}
	if _, err := exec.LookPath("minimap2"); err != nil {
		// Return warning when minimap2 is not installed.
		return stats, "minimap2 not available"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	// API boundary: run minimap2 for alignment.
	cmd := exec.CommandContext(ctx, "minimap2", "-a", fastaPath, fastqPath)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		// Return warning when stdout cannot be captured.
		return stats, "failed to read minimap2 stdout"
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		// Return warning when minimap2 cannot be started.
		return stats, "failed to start minimap2"
	}

	scanner := bufio.NewScanner(stdout)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	// Parse SAM output line by line to accumulate alignment stats.
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "@") {
			// Skip header lines to avoid counting them as reads.
			continue
		}
		stats.TotalReads++
		fields := strings.Split(line, "\t")
		if len(fields) < 3 {
			// Continue when fields are incomplete.
			continue
		}
		rname := fields[2]
		if rname != "*" {
			// Count mapped reads and accumulate target hits.
			stats.MappedReads++
			stats.Targets[rname]++
		}
	}

	if err := cmd.Wait(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = "minimap2 failed"
		}
		// Return warning when minimap2 exits with error.
		return stats, msg
	}
	if err := scanner.Err(); err != nil {
		// Return warning when scanner fails to parse output.
		return stats, "failed to parse minimap2 output"
	}
	// Return collected stats when alignment completes.
	return stats, ""
}

/// toInt converts common types to int with best-effort parsing.
///
/// Brief description of what the function does.
/// - Handles float64, int, int64, and numeric strings.
///
/// Parameters:
///   value - Input value to convert.
///
/// Returns the converted int or 0 on failure.
///
/// Throws [None] - best-effort conversion.
///
/// Example: `count := toInt(payload["read_count"])`
func toInt(value any) int {
	// Convert based on the dynamic type.
	switch v := value.(type) {
	case float64:
		// Return integer truncation for float values.
		return int(v)
	case int:
		// Return the integer value directly.
		return v
	case int64:
		// Return the int64 value cast to int.
		return int(v)
	case string:
		parsed, err := strconv.Atoi(v)
		if err == nil {
			// Return parsed integer when string conversion succeeds.
			return parsed
		}
	}
	// Return 0 when conversion fails.
	return 0
}

/// toFloat converts common types to float64.
///
/// Brief description of what the function does.
/// - Handles float64, int, int64, and numeric strings.
///
/// Parameters:
///   value - Input value to convert.
///
/// Returns (float64, ok) indicating success.
///
/// Throws [None] - best-effort conversion.
///
/// Example: `q30, ok := toFloat(payload["q30_rate"])`
func toFloat(value any) (float64, bool) {
	// Convert based on the dynamic type.
	switch v := value.(type) {
	case float64:
		// Return the float directly when already float64.
		return v, true
	case int:
		// Convert int to float64.
		return float64(v), true
	case int64:
		// Convert int64 to float64.
		return float64(v), true
	case string:
		parsed, err := strconv.ParseFloat(v, 64)
		if err == nil {
			// Return parsed float when string conversion succeeds.
			return parsed, true
		}
	}
	// Return false when conversion fails.
	return 0, false
}

/// toStringSlice converts a generic slice to a string slice.
///
/// Brief description of what the function does.
/// - Filters non-string elements and returns only strings.
///
/// Parameters:
///   value - Input value expected to be a slice.
///
/// Returns a slice of strings or nil when type mismatch occurs.
///
/// Throws [None] - best-effort conversion.
///
/// Example: `warnings := toStringSlice(payload["warnings"])`
func toStringSlice(value any) []string {
	raw, ok := value.([]any)
	if !ok {
		// Return nil when the input is not a slice.
		return nil
	}
	out := make([]string, 0, len(raw))
	// Filter for string items only.
	for _, item := range raw {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	// Return the collected string slice.
	return out
}

/// readJob loads a job record from disk.
///
/// Brief description of what the function does.
/// - Parses job JSON for processing and authorization checks.
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
	// Fail fast when the job file cannot be read.
	if err != nil {
		// Return error when the job file cannot be read.
		return job, err
	}
	// Parse the JSON payload into the job struct.
	if err := json.Unmarshal(data, &job); err != nil {
		// Return error when job JSON is invalid.
		return job, err
	}
	// Return the parsed job record.
	return job, nil
}

/// writeJSON persists a value as indented JSON on disk.
///
/// Brief description of what the function does.
/// - Writes result and job records for results-api consumption.
///
/// Parameters:
///   path - Destination file path for JSON output.
///   v - Value to marshal into JSON.
///
/// Returns an error when serialization or writing fails.
///
/// Throws [IOError] when file writing fails.
///
/// Example: `err := writeJSON("/data/results/abc.json", result)`
func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	// Fail fast when JSON marshalling fails.
	if err != nil {
		// Return error when JSON marshalling fails.
		return err
	}
	// Return any file write error to the caller.
	return os.WriteFile(path, data, 0600)
}

/// hashFile computes a SHA-256 hash and size for a file.
///
/// Brief description of what the function does.
/// - Streams file contents into a hasher to avoid large memory usage.
///
/// Parameters:
///   path - Filesystem path to the file.
///
/// Returns (hexDigest, sizeBytes, error).
///
/// Throws [IOError] when file reading fails.
///
/// Example: `digest, size, err := hashFile(path)`
func hashFile(path string) (string, int64, error) {
	file, err := os.Open(path)
	// Fail fast when the file cannot be opened.
	if err != nil {
		// Return error when file open fails.
		return "", 0, err
	}
	defer file.Close()

	hasher := sha256.New()
	// Stream file content into the hasher to avoid large memory use.
	size, err := file.WriteTo(hasher)
	if err != nil {
		// Return error when hashing fails.
		return "", 0, err
	}
	// Return hex digest and size for auditing.
	return hex.EncodeToString(hasher.Sum(nil)), size, nil
}

/// fileSHA256Bytes computes raw SHA-256 bytes for a file.
///
/// Brief description of what the function does.
/// - Streams file contents to produce raw digest bytes.
///
/// Parameters:
///   path - Filesystem path to the file.
///
/// Returns raw digest bytes or an error.
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
	// Stream file content into the hasher to avoid large memory use.
	if _, err := file.WriteTo(hasher); err != nil {
		// Return error when hashing fails.
		return nil, err
	}
	// Return raw digest bytes for signature verification.
	return hasher.Sum(nil), nil
}

/// loadRules loads detection rules from a JSON file.
///
/// Brief description of what the function does.
/// - Reads and parses rules, applying defaults on errors.
///
/// Parameters:
///   path - Filesystem path to rules JSON.
///
/// Returns a detectionRules struct with defaults applied.
///
/// Throws [IOError] when file reading fails; defaults are used.
///
/// Example: `rules := loadRules("/rules/rules.json")`
func loadRules(path string) detectionRules {
	data, err := os.ReadFile(path)
	// Use defaults when rule file cannot be read.
	if err != nil {
		log.Printf("rules read error: %v", err)
		// Return defaults when rules cannot be read.
		return defaultRules()
	}
	var rules detectionRules
	// Use defaults when rule file cannot be parsed.
	if err := json.Unmarshal(data, &rules); err != nil {
		log.Printf("rules parse error: %v", err)
		// Return defaults when rules cannot be parsed.
		return defaultRules()
	}
	// Apply defaults for any missing rule values.
	applyRuleDefaults(&rules)
	// Return the normalized rules.
	return rules
}

/// defaultRules returns baseline detection rules.
///
/// Brief description of what the function does.
/// - Provides safe defaults when rules are missing or incomplete.
///
/// Parameters:
///   None.
///
/// Returns a detectionRules struct with default values.
///
/// Throws [None] - constant defaults only.
///
/// Example: `rules := defaultRules()`
func defaultRules() detectionRules {
	// Return the default rule set for baseline scoring.
	return detectionRules{
		HighScore:                 0.9,
		LowScore:                  0.1,
		ThreatMinReads:            50,
		ThreatMinFraction:         0.02,
		FastpMinQ30:               0.75,
		CriticalWarningScoreBoost: 0.2,
		HighThreshold:             0.8,
		MediumThreshold:           0.5,
	}
}

/// applyRuleDefaults fills in missing rule values with defaults.
///
/// Brief description of what the function does.
/// - Mutates the provided rules in-place to ensure thresholds are set.
///
/// Parameters:
///   rules - Pointer to detectionRules to update.
///
/// Returns no value; mutates the input struct.
///
/// Throws [None] - only local assignment.
///
/// Example: `applyRuleDefaults(&rules)`
func applyRuleDefaults(rules *detectionRules) {
	defaults := defaultRules()
	if rules.HighScore == 0 {
		// Set default high score when missing.
		rules.HighScore = defaults.HighScore
	}
	if rules.LowScore == 0 {
		// Set default low score when missing.
		rules.LowScore = defaults.LowScore
	}
	if rules.ThreatMinReads == 0 {
		// Set default threat read minimum when missing.
		rules.ThreatMinReads = defaults.ThreatMinReads
	}
	if rules.ThreatMinFraction == 0 {
		// Set default threat fraction when missing.
		rules.ThreatMinFraction = defaults.ThreatMinFraction
	}
	if rules.FastpMinQ30 == 0 {
		// Set default fastp Q30 threshold when missing.
		rules.FastpMinQ30 = defaults.FastpMinQ30
	}
	if rules.CriticalWarningScoreBoost == 0 {
		// Set default critical warning boost when missing.
		rules.CriticalWarningScoreBoost = defaults.CriticalWarningScoreBoost
	}
	if rules.HighThreshold == 0 {
		// Set default high verdict threshold when missing.
		rules.HighThreshold = defaults.HighThreshold
	}
	if rules.MediumThreshold == 0 {
		// Set default medium verdict threshold when missing.
		rules.MediumThreshold = defaults.MediumThreshold
	}
}

/// defaultRulesPath returns the default rules file path.
///
/// Brief description of what the function does.
/// - Provides a relative path to the rules JSON.
///
/// Parameters:
///   None.
///
/// Returns the default rules path string.
///
/// Throws [None] - constant path value.
///
/// Example: `path := defaultRulesPath()`
func defaultRulesPath() string {
	// Return the repository-relative rules path.
	return "../../bio/reference-db/rules.json"
}

/// defaultPipelinePath returns the default pipeline script path.
///
/// Brief description of what the function does.
/// - Provides a relative path to the pipeline wrapper.
///
/// Parameters:
///   None.
///
/// Returns the default pipeline path string.
///
/// Throws [None] - constant path value.
///
/// Example: `path := defaultPipelinePath()`
func defaultPipelinePath() string {
	// Return the repository-relative pipeline path.
	return "../../bio/pipeline/pipeline.py"
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
/// Example: `dir := envOr("BIOZERO_DATA_DIR", "./data")`
func envOr(key, fallback string) string {
	val := os.Getenv(key)
	// Use fallback when the environment variable is unset.
	if val == "" {
		// Return fallback to keep configuration predictable.
		return fallback
	}
	// Return the configured value when present.
	return val
}

/// envOrDuration returns a duration env var or fallback.
///
/// Brief description of what the function does.
/// - Parses duration strings like "10m" with safe defaults.
///
/// Parameters:
///   key - Environment variable name.
///   fallback - Default duration when env is unset or invalid.
///
/// Returns the parsed duration or fallback.
///
/// Throws [ParseError] when env value is malformed; fallback is used.
///
/// Example: `timeout := envOrDuration("BIOZERO_PIPELINE_TIMEOUT", 10*time.Minute)`
func envOrDuration(key string, fallback time.Duration) time.Duration {
	val := strings.TrimSpace(os.Getenv(key))
	// Use fallback when the environment variable is unset.
	if val == "" {
		// Return fallback when unset to avoid zero durations.
		return fallback
	}
	parsed, err := time.ParseDuration(val)
	// Use fallback when the duration string cannot be parsed.
	if err != nil {
		// Return fallback on parse errors.
		return fallback
	}
	// Return parsed duration for valid configuration.
	return parsed
}

/// mustMkdirAll creates directories or exits the process.
///
/// Brief description of what the function does.
/// - Ensures required directories exist before processing jobs.
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
	// Create directories recursively for required storage paths.
	if err := os.MkdirAll(path, 0755); err != nil {
		// Exit immediately when required directories cannot be created.
		log.Fatalf("failed to create %s: %v", path, err)
	}
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
/// Example: `safe := sanitizeFilename("../evil.fastq")`
func sanitizeFilename(name string) string {
	replacer := strings.NewReplacer("/", "_", "\\", "_", "..", "_")
	// Return a sanitized filename safe for filesystem use.
	return replacer.Replace(name)
}

/// runPipeline executes the pipeline wrapper and validates JSON output.
///
/// Brief description of what the function does.
/// - Invokes the pipeline script with timeout and returns its JSON output.
///
/// Parameters:
///   path - Path to the pipeline executable.
///   input - Path to input FASTQ file.
///   referencePath - Optional reference genome path.
///   timeout - Maximum duration for pipeline execution.
///
/// Returns (jsonOutput, errorMessage) where errorMessage is empty on success.
///
/// Throws [ExternalToolError] when pipeline execution fails or times out.
///
/// Example: `out, errMsg := runPipeline(pipelinePath, input, ref, 10*time.Minute)`
func runPipeline(path, input, referencePath string, timeout time.Duration) (json.RawMessage, string) {
	// Short-circuit when the pipeline path is empty.
	if path == "" {
		// Return empty output when pipeline path is not configured.
		return nil, ""
	}
	// Validate pipeline path before execution.
	if _, err := os.Stat(path); err != nil {
		// Return error message when pipeline script is missing.
		return nil, "pipeline not found"
	}

	args := []string{input}
	if referencePath != "" {
		// Append reference path when provided.
		args = append(args, "--reference", referencePath)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	// API boundary: execute external pipeline process.
	cmd := exec.CommandContext(ctx, path, args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Run the pipeline and handle error cases explicitly.
	if err := cmd.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			// Return timeout message when the pipeline exceeds its budget.
			return nil, "pipeline timed out"
		}
		if stderr.Len() > 0 {
			// Return stderr output to aid debugging.
			return nil, strings.TrimSpace(stderr.String())
		}
		// Return the process error when no stderr is available.
		return nil, err.Error()
	}

	out := bytes.TrimSpace(stdout.Bytes())
	if len(out) == 0 {
		// Return error when pipeline emits no output.
		return nil, "pipeline returned empty output"
	}
	if !json.Valid(out) {
		// Return error when output is not valid JSON.
		return nil, "pipeline output is not valid JSON"
	}
	// Return the JSON payload when valid.
	return json.RawMessage(out), ""
}

/// isValidJobID validates job IDs for safe filesystem access.
///
/// Brief description of what the function does.
/// - Enforces hex-only IDs with bounded length to prevent path traversal.
///
/// Parameters:
///   jobID - Job identifier from the job record.
///
/// Returns true when the ID is valid; false otherwise.
///
/// Throws [None] - pure validation.
///
/// Example: `if !isValidJobID(jobID) { ... }`
func isValidJobID(jobID string) bool {
	// Enforce length bounds to keep IDs predictable.
	if len(jobID) < 8 || len(jobID) > 64 {
		// Return false when length constraints are violated.
		return false
	}
	// Check each rune for hex-only characters.
	for _, r := range jobID {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			// Return false when a non-hex character is found.
			return false
		}
	}
	// Return true when all characters are valid.
	return true
}

/// unwrapSensitiveValue decrypts a wrapped string using AES-256-GCM.
///
/// Brief description of what the function does.
/// - Decodes base64 payload and decrypts with a provided key.
///
/// Parameters:
///   payload - Base64-encoded nonce+ciphertext.
///   keyMaterial - 32-byte AES key in base64 or hex.
///
/// Returns the decrypted string or an error.
///
/// Throws [CryptoError] when decryption fails or payload is malformed.
///
/// SECURITY: Uses AES-256-GCM; do not reduce key size.
///
/// Example: `plain, err := unwrapSensitiveValue(wrapped, jobKey)`
func unwrapSensitiveValue(payload, keyMaterial string) (string, error) {
	key, err := decodeKeyMaterial(keyMaterial)
	// Fail fast when key material cannot be decoded.
	if err != nil {
		// Return error when key material is invalid.
		return "", err
	}
	raw, err := base64.StdEncoding.DecodeString(payload)
	// Fail fast when payload is not valid base64.
	if err != nil {
		// Return error when payload is not valid base64.
		return "", err
	}
	block, err := aes.NewCipher(key)
	// Fail fast when cipher initialization fails.
	if err != nil {
		// Return error when cipher initialization fails.
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	// Fail fast when GCM initialization fails.
	if err != nil {
		// Return error when GCM initialization fails.
		return "", err
	}
	// Validate payload length before slicing nonce and ciphertext.
	if len(raw) < gcm.NonceSize() {
		// Return error when payload is too short to contain nonce.
		return "", errors.New("wrapped value too short")
	}
	nonce := raw[:gcm.NonceSize()]
	ciphertext := raw[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	// Fail fast when decryption fails.
	if err != nil {
		// Return error when decryption fails or tag is invalid.
		return "", err
	}
	// Return the decrypted string value.
	return string(plaintext), nil
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
	// Require explicit key material to avoid insecure defaults.
	if raw == "" {
		// Return error to force explicit key provisioning.
		return nil, errors.New("missing key material")
	}
	// Prefer base64 decoding when possible.
	if decoded, err := base64.StdEncoding.DecodeString(raw); err == nil && len(decoded) == 32 {
		// Return decoded bytes when base64 is valid.
		return decoded, nil
	}
	// Fall back to hex decoding for alternative provisioning.
	if decoded, err := hex.DecodeString(raw); err == nil && len(decoded) == 32 {
		// Return decoded bytes when hex is valid.
		return decoded, nil
	}
	// Return error when key material is invalid or wrong length.
	return nil, errors.New("job key must be 32 bytes (base64 or hex)")
}
