// SPDX-License-Identifier: AGPL-3.0-only
// ZeroResponder: accepts alert webhooks, validates the payload, and writes
// action artifacts for the SOC pipeline; the UI and automation clients call /alert.
package main

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// errorResponse standardizes error payloads returned by API handlers.
type errorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

// alertPayload represents an incoming webhook alert from external systems.
type alertPayload struct {
	AlertID    string            `json:"alert_id"`
	Source     string            `json:"source"`
	Severity   string            `json:"severity"`
	Timestamp  string            `json:"timestamp"`
	Indicators map[string]string `json:"indicators"`
	Actions    []string          `json:"actions"`
}

// actionRecord captures actions written to audit logs and artifacts.
type actionRecord struct {
	AlertID   string            `json:"alert_id"`
	Action    string            `json:"action"`
	Target    string            `json:"target"`
	Timestamp string            `json:"timestamp"`
	Meta      map[string]string `json:"meta,omitempty"`
}

/// main registers HTTP handlers and starts the ZeroResponder server.
///
/// Brief description of what the function does.
/// - Boots the responder API, wires health and alert endpoints, and configures limits.
///
/// Parameters:
///   None.
///
/// Returns no value; the process exits on fatal server errors.
///
/// Throws [FatalServerError] when the listener cannot start.
///
/// Example: `go run ./main.go`
func main() {
	addr := envOr("BIOZERO_RESPONDER_ADDR", ":8090")
	dataDir := envOr("BIOZERO_DATA_DIR", "./data")
	secret := os.Getenv("BIOZERO_WEBHOOK_SECRET")
	maxAlertBytes := envOrInt64("BIOZERO_ALERT_MAX_BYTES", 1<<20)

	actionsDir := filepath.Join(dataDir, "actions")
	// Ensure action directories exist before accepting alerts.
	mustMkdirAll(actionsDir)

	// API boundary: health probe for UI and orchestration checks.
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		// Respond quickly to indicate liveness.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// API boundary: accepts external alert webhooks from UI and automation.
	http.HandleFunc("/alert", func(w http.ResponseWriter, r *http.Request) {
		// Guard against unsupported methods to reduce surface area.
		if r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			// Return to stop processing non-alert requests.
			return
		}
		// SECURITY: verify shared secret when configured to block unauthenticated alerts.
		if secret != "" {
			provided := r.Header.Get("X-Webhook-Secret")
			if subtle.ConstantTimeCompare([]byte(provided), []byte(secret)) != 1 {
				writeJSONError(w, http.StatusForbidden, "forbidden", "forbidden")
				// Return to avoid processing unauthorized alerts.
				return
			}
		}

		// Cap body size to reduce abuse and protect the responder log pipeline.
		r.Body = http.MaxBytesReader(w, r.Body, maxAlertBytes)
		var payload alertPayload
		// Decode JSON payload and reject malformed input.
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_json", "invalid json")
			// Return to prevent partial or unsafe processing.
			return
		}

		// Validate required fields and bounds to keep logs consistent.
		if err := validateAlert(payload); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_alert", err.Error())
			// Return to avoid writing invalid action artifacts.
			return
		}

		// Write action artifacts so downstream SOC tooling can consume them.
		records := handleActions(payload, actionsDir)
		resp := map[string]any{
			"status":  "ok",
			"actions": records,
		}
		// Return the action summary to the caller.
		writeJSONResponse(w, resp)
	})

	// Configure server timeouts to protect against slow clients.
	server := &http.Server{
		Addr:              addr,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	log.Printf("zeroresponder listening on %s", addr)
	log.Fatal(server.ListenAndServe())
	// Return is unreachable because log.Fatal exits, but keep flow explicit.
	return
}

/// handleActions expands alert actions into persisted records and files.
///
/// Brief description of what the function does.
/// - Maps action strings to artifacts that downstream SOC tooling can read.
///
/// Parameters:
///   alert - Parsed alert payload from the caller.
///   actionsDir - Directory for writing action artifacts.
///
/// Returns a list of action records written to disk.
///
/// Throws [IOError] when artifact writing fails; failures are logged as noop.
///
/// Example: `records := handleActions(payload, "/data/actions")`
func handleActions(alert alertPayload, actionsDir string) []actionRecord {
	var records []actionRecord

	// Iterate through each requested action for this alert.
	for _, action := range alert.Actions {
		// Normalize action tokens to keep downstream handling predictable.
		action = strings.ToLower(strings.TrimSpace(action))
		// Route action types to their respective artifact outputs.
		switch action {
		case "block_ip":
			target := alert.Indicators["ip"]
			records = append(records, writeAction(actionsDir, alert, action, target, map[string]string{"type": "blocklist"}))
		case "revoke_cert":
			target := alert.Indicators["cert_serial"]
			records = append(records, writeAction(actionsDir, alert, action, target, map[string]string{"type": "revocation"}))
		case "quarantine":
			target := alert.Indicators["job_id"]
			records = append(records, writeAction(actionsDir, alert, action, target, map[string]string{"type": "quarantine"}))
		default:
			records = append(records, writeAction(actionsDir, alert, "noop", "", map[string]string{"reason": "unknown action"}))
		}
	}

	// Return the assembled action records for response payloads.
	return records
}

/// writeAction persists an action record and writes supporting artifacts.
///
/// Brief description of what the function does.
/// - Writes a JSON log entry and appends to action-specific files.
///
/// Parameters:
///   dir - Base directory for action artifacts.
///   alert - Original alert payload for context.
///   action - Normalized action string.
///   target - Target identifier (IP, cert serial, job ID).
///   meta - Additional metadata for the action log.
///
/// Returns the actionRecord persisted to disk.
///
/// Throws [IOError] when file writes fail; errors are ignored to keep flow moving.
///
/// Example: `record := writeAction("/data/actions", alert, "block_ip", "10.0.0.1", meta)`
func writeAction(dir string, alert alertPayload, action, target string, meta map[string]string) actionRecord {
	record := actionRecord{
		AlertID:   alert.AlertID,
		Action:    action,
		Target:    target,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Meta:      meta,
	}

	logPath := filepath.Join(dir, "actions.log")
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	// Best-effort logging: skip file write if the log cannot be opened.
	if err == nil {
		defer f.Close()
		data, err := json.Marshal(record)
		// Only write valid JSON entries to the log.
		if err == nil {
			_, _ = f.Write(append(data, '\n'))
		}
	}

	// Write action-specific artifacts for downstream tooling.
	if action == "block_ip" && target != "" {
		appendLine(filepath.Join(dir, "blocklist.txt"), target)
	}
	// Append cert revocations for PKI integrations.
	if action == "revoke_cert" && target != "" {
		appendLine(filepath.Join(dir, "revocations.txt"), target)
	}
	// Append job IDs for quarantine workflows.
	if action == "quarantine" && target != "" {
		appendLine(filepath.Join(dir, "quarantine.txt"), target)
	}

	// Return the record for API response aggregation.
	return record
}

/// appendLine appends a single line to a file, creating it if needed.
///
/// Brief description of what the function does.
/// - Writes action artifacts for blocking, revocation, and quarantine lists.
///
/// Parameters:
///   path - Destination file path.
///   value - Line value to append.
///
/// Returns no value; failures are silently ignored.
///
/// Throws [IOError] when file open/write fails; errors are ignored intentionally.
///
/// Example: `appendLine("/data/actions/blocklist.txt", "10.0.0.1")`
func appendLine(path, value string) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		// Return to keep alert handling resilient to filesystem issues.
		return
	}
	defer f.Close()
	// Best-effort append; ignore errors for resilience.
	_, _ = f.WriteString(value + "\n")
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
/// Example: `writeJSONResponse(w, map[string]any{"status":"ok"})`
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
/// Example: `writeJSONError(w, 400, "invalid_alert", "missing alert_id")`
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
/// Example: `addr := envOr("BIOZERO_RESPONDER_ADDR", ":8090")`
func envOr(key, fallback string) string {
	val := os.Getenv(key)
	if val == "" {
		// Return fallback to keep configuration predictable.
		return fallback
	}
	// Return the configured value when present.
	return val
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
/// Example: `maxBytes := envOrInt64("BIOZERO_ALERT_MAX_BYTES", 1<<20)`
func envOrInt64(key string, fallback int64) int64 {
	val := strings.TrimSpace(os.Getenv(key))
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
/// Example: `mustMkdirAll("/data/actions")`
func mustMkdirAll(path string) {
	// Fail fast if the filesystem layout cannot be prepared.
	if err := os.MkdirAll(path, 0755); err != nil {
		log.Fatalf("failed to create %s: %v", path, err)
	}
}

/// validateAlert checks required fields and size constraints.
///
/// Brief description of what the function does.
/// - Verifies the minimal alert schema before processing actions.
///
/// Parameters:
///   payload - Parsed alert payload.
///
/// Returns nil when valid; otherwise an error with a message.
///
/// Throws [ValidationError] when required fields are missing or too long.
///
/// Example: `if err := validateAlert(payload); err != nil { ... }`
func validateAlert(payload alertPayload) error {
	if payload.AlertID == "" {
		// Return a descriptive error when the alert ID is missing.
		return errors.New("missing alert_id")
	}
	if payload.Source == "" {
		// Return a descriptive error when the source is missing.
		return errors.New("missing source")
	}
	if payload.Severity == "" {
		// Return a descriptive error when the severity is missing.
		return errors.New("missing severity")
	}
	if payload.Timestamp == "" {
		// Return a descriptive error when the timestamp is missing.
		return errors.New("missing timestamp")
	}
	if len(payload.Actions) == 0 {
		// Return a descriptive error when no actions are provided.
		return errors.New("missing actions")
	}
	if len(payload.AlertID) > 128 || len(payload.Source) > 64 {
		// Return a descriptive error when fields exceed length limits.
		return errors.New("alert_id or source too long")
	}
	// Return nil when all validations pass.
	return nil
}
