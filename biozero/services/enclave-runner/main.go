// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
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
	SigAlg            string `json:"sig_alg,omitempty"`
	Sig              string `json:"sig,omitempty"`
	ClientCertSubject string `json:"client_cert_subject,omitempty"`
	ClientCertIssuer  string `json:"client_cert_issuer,omitempty"`
	ClientCertSerial  string `json:"client_cert_serial,omitempty"`
}

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

type detectionResult struct {
	Score   float64         `json:"score"`
	Reason  string          `json:"reason"`
	Verdict string          `json:"verdict,omitempty"`
	Reasons []string        `json:"reasons,omitempty"`
	Signals map[string]any  `json:"signals,omitempty"`
}

type pipelineInfo struct {
	ReadCount     int
	AvgReadLength int
	Warnings      []string
	FastpQ30      float64
	HasFastp      bool
}

type warningSummary struct {
	Critical int `json:"critical"`
	Warn     int `json:"warn"`
	Info     int `json:"info"`
}

type alignmentStats struct {
	MappedReads int            `json:"mapped_reads"`
	TotalReads  int            `json:"total_reads"`
	Fraction    float64        `json:"fraction"`
	Targets     map[string]int `json:"targets,omitempty"`
}

func main() {
	dataDir := envOr("BIOZERO_DATA_DIR", "./data")
	pollSeconds := envOr("BIOZERO_POLL_SECONDS", "2")
	privateKeyPath := os.Getenv("BIOZERO_PRIVATE_KEY")
	signerCertPath := os.Getenv("BIOZERO_SIGNER_CERT")
	decryptedDir := envOr("BIOZERO_DECRYPT_DIR", filepath.Join(dataDir, "decrypted"))
	pipelinePath := envOr("BIOZERO_PIPELINE_PATH", defaultPipelinePath())
	referencePath := os.Getenv("BIOZERO_REFERENCE_PATH")

	uploadDir := filepath.Join(dataDir, "uploads")
	jobsDir := filepath.Join(dataDir, "jobs")
	resultsDir := filepath.Join(dataDir, "results")
	rulesPath := envOr("BIOZERO_RULES_PATH", defaultRulesPath())

	mustMkdirAll(uploadDir)
	mustMkdirAll(jobsDir)
	mustMkdirAll(resultsDir)
	mustMkdirAll(decryptedDir)

	rules := loadRules(rulesPath)
	interval, err := time.ParseDuration(pollSeconds + "s")
	if err != nil {
		interval = 2 * time.Second
	}

	log.Printf("enclave-runner watching %s", jobsDir)
	for {
		processJobs(jobsDir, uploadDir, resultsDir, decryptedDir, rules, privateKeyPath, signerCertPath, pipelinePath, referencePath)
		time.Sleep(interval)
	}
}

func processJobs(jobsDir, uploadDir, resultsDir, decryptedDir string, rules detectionRules, privateKeyPath, signerCertPath, pipelinePath, referencePath string) {
	entries, err := os.ReadDir(jobsDir)
	if err != nil {
		log.Printf("read jobs dir error: %v", err)
		return
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		jobPath := filepath.Join(jobsDir, entry.Name())
		job, err := readJob(jobPath)
		if err != nil {
			log.Printf("job read error %s: %v", entry.Name(), err)
			continue
		}
		if job.Status != "uploaded" {
			continue
		}

		resultPath := filepath.Join(resultsDir, job.JobID+".json")
		if _, err := os.Stat(resultPath); err == nil {
			continue
		}

		storedName := job.JobID + "_" + sanitizeFilename(job.OriginalName)
		uploadPath := filepath.Join(uploadDir, storedName)

		uploadSHA, _, err := hashFile(uploadPath)
		if err != nil {
			log.Printf("hash error %s: %v", uploadPath, err)
			continue
		}

		signatureValid, signatureErr := verifySignature(uploadPath, job.Sig, signerCertPath)

		contentPath := uploadPath
		decrypted := false
		decryptionError := ""
		if job.EncAlg != "" && job.EncKey != "" {
			if privateKeyPath == "" {
				decryptionError = "private key not configured"
			} else {
				outPath, err := decryptPayload(uploadPath, job.EncKey, privateKeyPath, decryptedDir, job.JobID)
				if err != nil {
					decryptionError = err.Error()
				} else {
					contentPath = outPath
					decrypted = true
				}
			}
		}

		processedSHA, processedSize, err := hashFile(contentPath)
		if err != nil {
			log.Printf("hash error %s: %v", contentPath, err)
			continue
		}

		pipelineOutput, pipelineError := runPipeline(pipelinePath, contentPath, referencePath)
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
			continue
		}

		job.Status = "processed"
		job.SHA256 = processedSHA
		job.SizeBytes = processedSize
		if err := writeJSON(jobPath, job); err != nil {
			log.Printf("job update error %s: %v", jobPath, err)
		}
	}
}

func verifySignature(path, sigHex, certPath string) (bool, string) {
	if sigHex == "" {
		return false, ""
	}
	if certPath == "" {
		return false, "signer cert not configured"
	}
	pub, err := loadRSAPublicKey(certPath)
	if err != nil {
		return false, err.Error()
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err.Error()
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return false, "invalid signature encoding"
	}

	hash := sha256.Sum256(data)
	if err := rsa.VerifyPSS(pub, crypto.SHA256, hash[:], sig, nil); err != nil {
		return false, err.Error()
	}
	return true, ""
}

func decryptPayload(cipherPath, encKeyHex, privateKeyPath, decryptedDir, jobID string) (string, error) {
	encKey, err := hex.DecodeString(encKeyHex)
	if err != nil {
		return "", errors.New("invalid enc_key encoding")
	}
	priv, err := loadRSAPrivateKey(privateKeyPath)
	if err != nil {
		return "", err
	}
	keyMaterial, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, encKey, nil)
	if err != nil {
		return "", err
	}
	if len(keyMaterial) < 44 {
		return "", errors.New("invalid key material length")
	}
	aesKey := keyMaterial[:32]
	iv := keyMaterial[32:44]

	ciphertext, err := os.ReadFile(cipherPath)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return "", err
	}

	outPath := filepath.Join(decryptedDir, fmt.Sprintf("%s_decrypted.bin", jobID))
	if err := os.WriteFile(outPath, plaintext, 0600); err != nil {
		return "", err
	}
	return outPath, nil
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

	if info.HasFastp {
		signals["fastp"] = map[string]any{
			"q30_rate": info.FastpQ30,
		}
	}

	var alignment alignmentStats
	if rules.ThreatPanelFasta != "" {
		stats, warn := threatPanelAlignment(rules.ThreatPanelFasta, contentPath)
		if warn != "" {
			log.Printf("threat panel alignment warning: %s", warn)
		}
		alignment = stats
		if stats.TotalReads > 0 {
			stats.Fraction = float64(stats.MappedReads) / float64(stats.TotalReads)
			alignment = stats
		}
		signals["alignment"] = alignment
	}

	score := rules.LowScore
	reasons := []string{}

	lowerName := strings.ToLower(job.OriginalName)
	for _, token := range rules.SuspiciousNameTokens {
		if token == "" {
			continue
		}
		if strings.Contains(lowerName, strings.ToLower(token)) {
			score += 0.2
			reasons = append(reasons, "suspicious_filename")
			break
		}
	}

	if rules.MaxSizeBytes > 0 && size > rules.MaxSizeBytes {
		score += 0.2
		reasons = append(reasons, "file_size_exceeded")
	}

	if decryptionError != "" && !decrypted {
		score += 0.1
		reasons = append(reasons, "decryption_failed")
	}
	if signatureErr != "" && !signatureValid {
		score += 0.2
		reasons = append(reasons, "signature_invalid")
	}

	if warnings.Critical > 0 {
		score += rules.CriticalWarningScoreBoost
		reasons = append(reasons, "critical_pipeline_warnings")
	}

	if info.HasFastp && rules.FastpMinQ30 > 0 && info.FastpQ30 > 0 && info.FastpQ30 < rules.FastpMinQ30 {
		score += 0.1
		reasons = append(reasons, "low_quality_reads")
	}

	totalReads := info.ReadCount
	if totalReads == 0 {
		totalReads = alignment.TotalReads
	}
	if rules.ThreatMinReads > 0 && totalReads > 0 {
		fraction := float64(alignment.MappedReads) / float64(totalReads)
		if alignment.MappedReads >= rules.ThreatMinReads && fraction >= rules.ThreatMinFraction {
			score += 0.6
			reasons = append(reasons, "threat_panel_hit")
		}
	}

	if score > 1 {
		score = 1
	}
	if score < 0 {
		score = 0
	}

	verdict := "low"
	if score >= rules.HighThreshold {
		verdict = "high"
	} else if score >= rules.MediumThreshold {
		verdict = "medium"
	}

	reason := "no suspicious indicators"
	if len(reasons) > 0 {
		reason = reasons[0]
	}

	return detectionResult{
		Score:   score,
		Reason:  reason,
		Verdict: verdict,
		Reasons: reasons,
		Signals: signals,
	}
}

func parsePipelineInfo(raw json.RawMessage) pipelineInfo {
	info := pipelineInfo{}
	if len(raw) == 0 {
		return info
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return info
	}

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
		return info
	}
	fastpSummary, ok := outputs["fastp_summary"].(map[string]any)
	if !ok {
		return info
	}
	if q30, ok := extractFastpQ30(fastpSummary); ok {
		info.FastpQ30 = q30
		info.HasFastp = true
	}
	return info
}

func extractFastpQ30(summary map[string]any) (float64, bool) {
	summaryMap, ok := summary["summary"].(map[string]any)
	if !ok {
		return 0, false
	}
	if after, ok := summaryMap["after_filtering"].(map[string]any); ok {
		if q30, ok := toFloat(after["q30_rate"]); ok {
			return q30, true
		}
	}
	if before, ok := summaryMap["before_filtering"].(map[string]any); ok {
		if q30, ok := toFloat(before["q30_rate"]); ok {
			return q30, true
		}
	}
	return 0, false
}

func classifyWarnings(warnings []string) warningSummary {
	summary := warningSummary{}
	for _, w := range warnings {
		lower := strings.ToLower(w)
		switch {
		case strings.Contains(lower, "error"),
			strings.Contains(lower, "failed"),
			strings.Contains(lower, "fatal"):
			summary.Critical++
		case strings.Contains(lower, "warn"):
			summary.Warn++
		default:
			summary.Info++
		}
	}
	return summary
}

func threatPanelAlignment(fastaPath, fastqPath string) (alignmentStats, string) {
	stats := alignmentStats{Targets: map[string]int{}}
	if _, err := os.Stat(fastaPath); err != nil {
		return stats, "threat panel not found"
	}
	if _, err := exec.LookPath("minimap2"); err != nil {
		return stats, "minimap2 not available"
	}

	cmd := exec.Command("minimap2", "-a", fastaPath, fastqPath)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return stats, "failed to read minimap2 stdout"
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return stats, "failed to start minimap2"
	}

	scanner := bufio.NewScanner(stdout)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "@") {
			continue
		}
		stats.TotalReads++
		fields := strings.Split(line, "\t")
		if len(fields) < 3 {
			continue
		}
		rname := fields[2]
		if rname != "*" {
			stats.MappedReads++
			stats.Targets[rname]++
		}
	}

	if err := cmd.Wait(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = "minimap2 failed"
		}
		return stats, msg
	}
	if err := scanner.Err(); err != nil {
		return stats, "failed to parse minimap2 output"
	}
	return stats, ""
}

func toInt(value any) int {
	switch v := value.(type) {
	case float64:
		return int(v)
	case int:
		return v
	case int64:
		return int(v)
	case string:
		parsed, err := strconv.Atoi(v)
		if err == nil {
			return parsed
		}
	}
	return 0
}

func toFloat(value any) (float64, bool) {
	switch v := value.(type) {
	case float64:
		return v, true
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case string:
		parsed, err := strconv.ParseFloat(v, 64)
		if err == nil {
			return parsed, true
		}
	}
	return 0, false
}

func toStringSlice(value any) []string {
	raw, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
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

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func hashFile(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()

	hasher := sha256.New()
	size, err := file.WriteTo(hasher)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(hasher.Sum(nil)), size, nil
}

func loadRules(path string) detectionRules {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("rules read error: %v", err)
		return defaultRules()
	}
	var rules detectionRules
	if err := json.Unmarshal(data, &rules); err != nil {
		log.Printf("rules parse error: %v", err)
		return defaultRules()
	}
	applyRuleDefaults(&rules)
	return rules
}

func defaultRules() detectionRules {
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

func applyRuleDefaults(rules *detectionRules) {
	defaults := defaultRules()
	if rules.HighScore == 0 {
		rules.HighScore = defaults.HighScore
	}
	if rules.LowScore == 0 {
		rules.LowScore = defaults.LowScore
	}
	if rules.ThreatMinReads == 0 {
		rules.ThreatMinReads = defaults.ThreatMinReads
	}
	if rules.ThreatMinFraction == 0 {
		rules.ThreatMinFraction = defaults.ThreatMinFraction
	}
	if rules.FastpMinQ30 == 0 {
		rules.FastpMinQ30 = defaults.FastpMinQ30
	}
	if rules.CriticalWarningScoreBoost == 0 {
		rules.CriticalWarningScoreBoost = defaults.CriticalWarningScoreBoost
	}
	if rules.HighThreshold == 0 {
		rules.HighThreshold = defaults.HighThreshold
	}
	if rules.MediumThreshold == 0 {
		rules.MediumThreshold = defaults.MediumThreshold
	}
}

func defaultRulesPath() string {
	return "../../bio/reference-db/rules.json"
}

func defaultPipelinePath() string {
	return "../../bio/pipeline/pipeline.py"
}

func envOr(key, fallback string) string {
	val := os.Getenv(key)
	if val == "" {
		return fallback
	}
	return val
}

func mustMkdirAll(path string) {
	if err := os.MkdirAll(path, 0755); err != nil {
		log.Fatalf("failed to create %s: %v", path, err)
	}
}

func sanitizeFilename(name string) string {
	replacer := strings.NewReplacer("/", "_", "\\", "_", "..", "_")
	return replacer.Replace(name)
}

func runPipeline(path, input, referencePath string) (json.RawMessage, string) {
	if path == "" {
		return nil, ""
	}
	if _, err := os.Stat(path); err != nil {
		return nil, "pipeline not found"
	}

	args := []string{input}
	if referencePath != "" {
		args = append(args, "--reference", referencePath)
	}
	cmd := exec.Command(path, args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if stderr.Len() > 0 {
			return nil, strings.TrimSpace(stderr.String())
		}
		return nil, err.Error()
	}

	out := bytes.TrimSpace(stdout.Bytes())
	if len(out) == 0 {
		return nil, "pipeline returned empty output"
	}
	if !json.Valid(out) {
		return nil, "pipeline output is not valid JSON"
	}
	return json.RawMessage(out), ""
}
