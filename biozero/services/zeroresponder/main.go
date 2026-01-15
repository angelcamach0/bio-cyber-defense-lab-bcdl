// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type alertPayload struct {
	AlertID   string            `json:"alert_id"`
	Source    string            `json:"source"`
	Severity  string            `json:"severity"`
	Timestamp string            `json:"timestamp"`
	Indicators map[string]string `json:"indicators"`
	Actions   []string          `json:"actions"`
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

	actionsDir := filepath.Join(dataDir, "actions")
	mustMkdirAll(actionsDir)

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	http.HandleFunc("/alert", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if secret != "" {
			provided := r.Header.Get("X-Webhook-Secret")
			if subtle.ConstantTimeCompare([]byte(provided), []byte(secret)) != 1 {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
		}

		var payload alertPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}

		if payload.AlertID == "" {
			http.Error(w, "missing alert_id", http.StatusBadRequest)
			return
		}

		records := handleActions(payload, actionsDir)
		resp := map[string]any{
			"status":  "ok",
			"actions": records,
		}
		writeJSONResponse(w, resp)
	})

	log.Printf("zeroresponder listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
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
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
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
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.WriteString(value + "\n")
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
