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

type errorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

type alertPayload struct {
	AlertID    string            `json:"alert_id"`
	Source     string            `json:"source"`
	Severity   string            `json:"severity"`
	Timestamp  string            `json:"timestamp"`
	Indicators map[string]string `json:"indicators"`
	Actions    []string          `json:"actions"`
}

type actionRecord struct {
	AlertID   string            `json:"alert_id"`
	Action    string            `json:"action"`
	Target    string            `json:"target"`
	Timestamp string            `json:"timestamp"`
	Meta      map[string]string `json:"meta,omitempty"`
}

func main() {
	addr := envOr("BIOZERO_RESPONDER_ADDR", ":8090")
	dataDir := envOr("BIOZERO_DATA_DIR", "./data")
	secret := os.Getenv("BIOZERO_WEBHOOK_SECRET")
	maxAlertBytes := envOrInt64("BIOZERO_ALERT_MAX_BYTES", 1<<20)

	actionsDir := filepath.Join(dataDir, "actions")
	mustMkdirAll(actionsDir)

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	http.HandleFunc("/alert", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}
		if secret != "" {
			provided := r.Header.Get("X-Webhook-Secret")
			if subtle.ConstantTimeCompare([]byte(provided), []byte(secret)) != 1 {
				writeJSONError(w, http.StatusForbidden, "forbidden", "forbidden")
				return
			}
		}

		// Cap body size to reduce abuse and protect the responder log pipeline.
		r.Body = http.MaxBytesReader(w, r.Body, maxAlertBytes)
		var payload alertPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_json", "invalid json")
			return
		}

		if err := validateAlert(payload); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_alert", err.Error())
			return
		}

		// Write action artifacts so downstream SOC tooling can consume them.
		records := handleActions(payload, actionsDir)
		resp := map[string]any{
			"status":  "ok",
			"actions": records,
		}
		writeJSONResponse(w, resp)
	})

	server := &http.Server{
		Addr:              addr,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	log.Printf("zeroresponder listening on %s", addr)
	log.Fatal(server.ListenAndServe())
}

func handleActions(alert alertPayload, actionsDir string) []actionRecord {
	var records []actionRecord

	for _, action := range alert.Actions {
		action = strings.ToLower(strings.TrimSpace(action))
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

	return records
}

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
	if err == nil {
		defer f.Close()
		data, err := json.Marshal(record)
		if err == nil {
			_, _ = f.Write(append(data, '\n'))
		}
	}

	if action == "block_ip" && target != "" {
		appendLine(filepath.Join(dir, "blocklist.txt"), target)
	}
	if action == "revoke_cert" && target != "" {
		appendLine(filepath.Join(dir, "revocations.txt"), target)
	}
	if action == "quarantine" && target != "" {
		appendLine(filepath.Join(dir, "quarantine.txt"), target)
	}

	return record
}

func appendLine(path, value string) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.WriteString(value + "\n")
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

func envOrInt64(key string, fallback int64) int64 {
	val := strings.TrimSpace(os.Getenv(key))
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

func validateAlert(payload alertPayload) error {
	if payload.AlertID == "" {
		return errors.New("missing alert_id")
	}
	if payload.Source == "" {
		return errors.New("missing source")
	}
	if payload.Severity == "" {
		return errors.New("missing severity")
	}
	if payload.Timestamp == "" {
		return errors.New("missing timestamp")
	}
	if len(payload.Actions) == 0 {
		return errors.New("missing actions")
	}
	if len(payload.AlertID) > 128 || len(payload.Source) > 64 {
		return errors.New("alert_id or source too long")
	}
	return nil
}
