// SPDX-License-Identifier: AGPL-3.0-only
// ZeroResponder authenticates bounded simulation requests and durably records
// intentions. It never enforces firewall, certificate or job-state changes.
package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const maxPayloadBytes = 64 << 10

var alertIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
var jobIDPattern = regexp.MustCompile(`^[a-f0-9]{8,64}$`)
var serialPattern = regexp.MustCompile(`^[a-fA-F0-9]{1,128}$`)
var workerEvents = map[string]bool{
	"upload_integrity_failed": true, "signature_required": true, "signature_algorithm_invalid": true,
	"signature_invalid": true, "encryption_required": true, "encryption_metadata_invalid": true,
	"key_unwrap_failed": true, "decryption_failed": true,
}

// Field order is part of the relay's canonical SHA256 wire contract.
type alertPayload struct {
	SchemaVersion int               `json:"schema_version"`
	AlertID       string            `json:"alert_id"`
	Source        string            `json:"source"`
	EventCode     string            `json:"event_code"`
	Severity      string            `json:"severity"`
	Timestamp     string            `json:"timestamp"`
	Indicators    map[string]string `json:"indicators"`
	Actions       []string          `json:"actions"`
}
type simulatedAction struct {
	Action   string `json:"action"`
	Target   string `json:"target"`
	Status   string `json:"status"`
	Enforced bool   `json:"enforced"`
}
type receipt struct {
	SchemaVersion int               `json:"schema_version"`
	Status        string            `json:"status"`
	Mode          string            `json:"mode"`
	Enforced      bool              `json:"enforced"`
	AlertID       string            `json:"alert_id"`
	PayloadSHA256 string            `json:"payload_sha256"`
	RecordedAt    string            `json:"recorded_at"`
	Alert         alertPayload      `json:"alert"`
	Actions       []simulatedAction `json:"actions"`
}
type acknowledgment struct {
	Status        string            `json:"status"`
	Mode          string            `json:"mode"`
	Enforced      bool              `json:"enforced"`
	AlertID       string            `json:"alert_id"`
	PayloadSHA256 string            `json:"payload_sha256"`
	RecordedAt    string            `json:"recorded_at"`
	Replay        bool              `json:"replay"`
	Actions       []simulatedAction `json:"actions"`
}
type serverConfig struct{ Address, DataDir, Secret, TLSCert, TLSKey string }
type persistenceOps struct {
	CreateTemp func(string, string) (*os.File, error)
	Write      func(*os.File, []byte) error
	SyncFile   func(*os.File) error
	Link       func(string, string) error
	Remove     func(string) error
	SyncDir    func(string) error
}
type responder struct {
	dir        string
	directory  *os.File
	secretHash [32]byte
	mu         sync.Mutex
	healthy    bool
	now        func() time.Time
	ops        persistenceOps
}

func main() {
	cfg := serverConfig{Address: envOr("BIOZERO_RESPONDER_ADDR", "127.0.0.1:8090"), DataDir: envOr("BIOZERO_DATA_DIR", "./data"),
		Secret: os.Getenv("BIOZERO_WEBHOOK_SECRET"), TLSCert: os.Getenv("BIOZERO_TLS_CERT"), TLSKey: os.Getenv("BIOZERO_TLS_KEY")}
	if err := validateServerConfig(cfg); err != nil {
		log.Fatal(err)
	}
	handler, err := newResponder(filepath.Join(cfg.DataDir, "actions"), cfg.Secret)
	if err != nil {
		log.Fatal("simulation receipt store unavailable")
	}
	server := &http.Server{Addr: cfg.Address, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	log.Print("zeroresponder starting in simulation mode; no actions are enforced")
	if cfg.TLSCert != "" {
		err = server.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
	} else {
		err = server.ListenAndServe()
	}
	if err != nil {
		log.Fatal("zeroresponder listener stopped")
	}
}
func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
func validateServerConfig(cfg serverConfig) error {
	if len(cfg.Secret) < 32 || len(cfg.Secret) > 512 || strings.ContainsAny(cfg.Secret, "\r\n\x00") {
		return errors.New("a configured webhook secret of 32 to 512 bytes is required")
	}
	if (cfg.TLSCert == "") != (cfg.TLSKey == "") {
		return errors.New("TLS certificate and key must be configured together")
	}
	host, port, err := net.SplitHostPort(cfg.Address)
	if err != nil || port == "" {
		return errors.New("invalid responder listener address")
	}
	addr, err := netip.ParseAddr(host)
	if cfg.TLSCert == "" && (err != nil || !addr.IsLoopback() || addr.Zone() != "") {
		return errors.New("non-loopback responders require TLS")
	}
	return nil
}
func defaultOps() persistenceOps {
	return persistenceOps{
		CreateTemp: os.CreateTemp,
		Write: func(file *os.File, data []byte) error {
			n, err := file.Write(data)
			if err == nil && n != len(data) {
				return io.ErrShortWrite
			}
			return err
		},
		SyncFile: func(file *os.File) error { return file.Sync() }, Link: os.Link, Remove: os.Remove,
		SyncDir: func(path string) error {
			dir, err := os.Open(path)
			if err != nil {
				return err
			}
			defer dir.Close()
			return dir.Sync()
		},
	}
}
func newResponder(dir, secret string) (*responder, error) {
	return newResponderWithOps(dir, secret, defaultOps())
}
func newResponderWithOps(dir, secret string, ops persistenceOps) (*responder, error) {
	if err := validateServerConfig(serverConfig{Address: "127.0.0.1:8090", Secret: secret}); err != nil {
		return nil, err
	}
	directory, err := prepareDirectory(dir, ops)
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			directory.Close()
		}
	}()
	// Linux proc-fd path is internal and pins every operation to the verified store.
	anchored := "/proc/self/fd/" + strconv.FormatUint(uint64(directory.Fd()), 10)
	r := &responder{dir: anchored, directory: directory, secretHash: sha256.Sum256([]byte(secret)), healthy: true, now: time.Now, ops: ops}
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".json") {
			id := strings.TrimSuffix(entry.Name(), ".json")
			if !alertIDPattern.MatchString(id) {
				return nil, errors.New("invalid receipt filename")
			}
			if _, err = r.readReceipt(id); err != nil {
				return nil, err
			}
		}
	}
	if err = r.ops.SyncDir(r.dir); err != nil {
		return nil, err
	}
	keep = true
	return r, nil
}
func prepareDirectory(path string, ops persistenceOps) (*os.File, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	current := os.NewFile(uintptr(fd), "receipt-parent")
	for _, part := range strings.Split(strings.TrimPrefix(absolute, "/"), "/") {
		if part == "" {
			continue
		}
		nextFD, openErr := syscall.Openat(int(current.Fd()), part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		if errors.Is(openErr, syscall.ENOENT) {
			if mkdirErr := syscall.Mkdirat(int(current.Fd()), part, 0700); mkdirErr != nil && !errors.Is(mkdirErr, syscall.EEXIST) {
				current.Close()
				return nil, mkdirErr
			}
			nextFD, openErr = syscall.Openat(int(current.Fd()), part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		}
		if openErr != nil {
			current.Close()
			return nil, errors.New("receipt path ancestors must be nonsymlink directories")
		}
		next := os.NewFile(uintptr(nextFD), "receipt-directory")
		// Sync even an existing entry: a preceding failed attempt may have created it
		// without reaching its parent's durability boundary.
		parent := "/proc/self/fd/" + strconv.FormatUint(uint64(current.Fd()), 10)
		if err = ops.SyncDir(parent); err != nil {
			next.Close()
			current.Close()
			return nil, err
		}
		current.Close()
		current = next
	}
	info, err := current.Stat()
	if err != nil {
		current.Close()
		return nil, err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode().Perm() != 0700 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || owner.Uid != uint32(os.Geteuid()) {
		current.Close()
		return nil, errors.New("receipt directory requires mode 0700 and process ownership")
	}
	return current, nil
}
func (r *responder) openReceipt(id string) (*os.File, error) {
	fd, err := syscall.Openat(int(r.directory.Fd()), id+".json", syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "simulation-receipt")
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || info.Size() > maxPayloadBytes || owner.Uid != uint32(os.Geteuid()) {
		file.Close()
		return nil, errors.New("receipt must be a private bounded regular file owned by the process")
	}
	return file, nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func fail(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code, "code": code})
}
func (r *responder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path == "/health" && req.Method == http.MethodGet {
		r.mu.Lock()
		defer r.mu.Unlock()
		status := 200
		if !r.healthy {
			status = 503
		}
		writeJSON(w, status, map[string]any{"status": "responder_alive", "healthy": r.healthy, "mode": "simulation", "enforced": false})
		return
	}
	if req.URL.Path != "/alert" {
		fail(w, 404, "not_found")
		return
	}
	if req.Method != http.MethodPost {
		fail(w, 405, "method_not_allowed")
		return
	}
	// Duplicate authentication headers are ambiguous and are never accepted.
	secrets := req.Header.Values("X-Webhook-Secret")
	if len(secrets) != 1 || len(secrets[0]) < 32 || len(secrets[0]) > 512 {
		fail(w, 403, "forbidden")
		return
	}
	digest := sha256.Sum256([]byte(secrets[0]))
	if subtle.ConstantTimeCompare(digest[:], r.secretHash[:]) != 1 {
		fail(w, 403, "forbidden")
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, req.Body, maxPayloadBytes))
	if err != nil {
		var limit *http.MaxBytesError
		if errors.As(err, &limit) {
			fail(w, 413, "payload_too_large")
		} else {
			fail(w, 400, "invalid_json")
		}
		return
	}
	var alert alertPayload
	if strictDecode(data, &alert) != nil || requiredKeys(data, []string{"schema_version", "alert_id", "source", "event_code", "severity", "timestamp", "indicators", "actions"}) != nil {
		fail(w, 400, "invalid_json")
		return
	}
	if err = canonicalize(&alert); err != nil {
		fail(w, 400, "invalid_alert")
		return
	}
	canonical, err := json.Marshal(alert)
	if err != nil {
		fail(w, 400, "invalid_alert")
		return
	}
	hash := sha256.Sum256(canonical)
	payloadSHA := hex.EncodeToString(hash[:])
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.healthy {
		fail(w, 503, "receipt_store_unavailable")
		return
	}
	existing, err := r.readReceipt(alert.AlertID)
	if err == nil {
		r.ackExisting(w, existing, payloadSHA)
		return
	}
	if !os.IsNotExist(err) {
		r.healthy = false
		fail(w, 503, "receipt_store_unavailable")
		return
	}
	record := receipt{SchemaVersion: 1, Status: "recorded", Mode: "simulation", Enforced: false, AlertID: alert.AlertID, PayloadSHA256: payloadSHA,
		RecordedAt: r.now().UTC().Format(time.RFC3339Nano), Alert: alert, Actions: deriveActions(alert)}
	if err = r.publish(record); err != nil {
		// Another process may publish this ID concurrently. No final file is replaced.
		if errors.Is(err, os.ErrExist) {
			existing, readErr := r.readReceipt(alert.AlertID)
			if readErr == nil {
				r.ackExisting(w, existing, payloadSHA)
				return
			}
		}
		r.healthy = false
		fail(w, 503, "receipt_store_unavailable")
		return
	}
	writeJSON(w, 200, acknowledge(record, false))
}
func (r *responder) ackExisting(w http.ResponseWriter, record receipt, payloadSHA string) {
	if record.PayloadSHA256 != payloadSHA {
		fail(w, 409, "alert_id_conflict")
		return
	}
	// A concurrent instance may have linked the receipt before its directory sync.
	// Establish this instance's durability boundary before acknowledging a replay.
	file, err := r.openReceipt(record.AlertID)
	if err == nil {
		err = r.ops.SyncFile(file)
		closeErr := file.Close()
		if err == nil {
			err = closeErr
		}
	}
	if err == nil {
		err = r.ops.SyncDir(r.dir)
	}
	if err != nil {
		r.healthy = false
		fail(w, 503, "receipt_store_unavailable")
		return
	}
	writeJSON(w, 200, acknowledge(record, true))
}
func acknowledge(record receipt, replay bool) acknowledgment {
	return acknowledgment{Status: "recorded", Mode: "simulation", Enforced: false,
		AlertID: record.AlertID, PayloadSHA256: record.PayloadSHA256, RecordedAt: record.RecordedAt, Replay: replay, Actions: record.Actions}
}
func deriveActions(alert alertPayload) []simulatedAction {
	records := make([]simulatedAction, 0, len(alert.Actions))
	for _, action := range alert.Actions {
		key := "job_id"
		if action == "block_ip" {
			key = "ip"
		} else if action == "revoke_cert" {
			key = "cert_serial"
		}
		records = append(records, simulatedAction{Action: action, Target: alert.Indicators[key], Status: "simulated", Enforced: false})
	}
	return records
}
func canonicalize(alert *alertPayload) error {
	invalid := errors.New("invalid simulation alert")
	if alert.SchemaVersion != 1 || !alertIDPattern.MatchString(alert.AlertID) || len(alert.Actions) < 1 || len(alert.Actions) > 3 {
		return invalid
	}
	stamp, err := time.Parse(time.RFC3339Nano, alert.Timestamp)
	if err != nil {
		return invalid
	}
	alert.Timestamp = stamp.UTC().Format(time.RFC3339Nano)
	if alert.Source == "enclave-runner" {
		if !workerEvents[alert.EventCode] || alert.Severity != "high" || len(alert.Actions) != 1 || alert.Actions[0] != "quarantine" {
			return invalid
		}
	} else if alert.Source == "siem" {
		if alert.EventCode != "policy_alert" {
			return invalid
		}
		switch alert.Severity {
		case "low", "medium", "high", "critical":
		default:
			return invalid
		}
	} else {
		return invalid
	}
	used, seen := map[string]bool{}, map[string]bool{}
	for _, action := range alert.Actions {
		if seen[action] {
			return invalid
		}
		seen[action] = true
		switch action {
		case "quarantine":
			used["job_id"] = true
			if !jobIDPattern.MatchString(alert.Indicators["job_id"]) {
				return invalid
			}
		case "block_ip":
			used["ip"] = true
			addr, err := netip.ParseAddr(alert.Indicators["ip"])
			if err != nil || addr.Zone() != "" {
				return invalid
			}
			alert.Indicators["ip"] = addr.Unmap().String()
		case "revoke_cert":
			used["cert_serial"] = true
			if !serialPattern.MatchString(alert.Indicators["cert_serial"]) {
				return invalid
			}
			alert.Indicators["cert_serial"] = strings.ToLower(alert.Indicators["cert_serial"])
		default:
			return invalid
		}
	}
	if len(alert.Indicators) != len(used) {
		return invalid
	}
	for key := range alert.Indicators {
		if !used[key] {
			return invalid
		}
	}
	if alert.Source == "enclave-runner" {
		hash := sha256.Sum256([]byte("enclave-runner/" + alert.Indicators["job_id"] + "/" + alert.EventCode))
		if alert.AlertID != "evt-"+hex.EncodeToString(hash[:]) {
			return invalid
		}
	}
	sort.Strings(alert.Actions)
	return nil
}
func (r *responder) publish(record receipt) error {
	data, err := json.Marshal(record)
	if err != nil || len(data) > maxPayloadBytes {
		return errors.New("receipt encoding failed")
	}
	file, err := r.ops.CreateTemp(r.dir, ".receipt-*")
	if err != nil {
		return err
	}
	name := file.Name()
	defer r.ops.Remove(name)
	if err = file.Chmod(0600); err == nil {
		err = r.ops.Write(file, data)
	}
	if err == nil {
		err = r.ops.SyncFile(file)
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = r.ops.Link(name, filepath.Join(r.dir, record.AlertID+".json")); err != nil {
		return err
	}
	if err = r.ops.Remove(name); err != nil {
		return err
	}
	return r.ops.SyncDir(r.dir)
}
func (r *responder) readReceipt(id string) (receipt, error) {
	var record receipt
	file, err := r.openReceipt(id)
	if err != nil {
		return record, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxPayloadBytes+1))
	if err != nil || len(data) > maxPayloadBytes {
		return record, errors.New("invalid receipt file")
	}
	if strictDecode(data, &record) != nil || requiredKeys(data, []string{"schema_version", "status", "mode", "enforced", "alert_id", "payload_sha256", "recorded_at", "alert", "actions"}) != nil {
		return record, errors.New("invalid receipt JSON")
	}
	if record.SchemaVersion != 1 || record.Status != "recorded" || record.Mode != "simulation" || record.Enforced || record.AlertID != id {
		return record, errors.New("invalid receipt contract")
	}
	stamp, err := time.Parse(time.RFC3339Nano, record.RecordedAt)
	if err != nil || stamp.UTC().Format(time.RFC3339Nano) != record.RecordedAt {
		return record, errors.New("invalid recorded timestamp")
	}
	before, err := json.Marshal(record.Alert)
	if err != nil {
		return record, err
	}
	canonical := record.Alert
	canonical.Indicators = make(map[string]string, len(record.Alert.Indicators))
	for key, value := range record.Alert.Indicators {
		canonical.Indicators[key] = value
	}
	canonical.Actions = append([]string(nil), record.Alert.Actions...)
	if canonicalize(&canonical) != nil {
		return record, errors.New("invalid receipt alert")
	}
	after, err := json.Marshal(canonical)
	if err != nil || !bytes.Equal(before, after) || record.Alert.AlertID != id {
		return record, errors.New("noncanonical receipt alert")
	}
	hash := sha256.Sum256(after)
	if record.PayloadSHA256 != hex.EncodeToString(hash[:]) {
		return record, errors.New("receipt digest mismatch")
	}
	expected, _ := json.Marshal(deriveActions(canonical))
	actual, _ := json.Marshal(record.Actions)
	if !bytes.Equal(expected, actual) {
		return record, errors.New("receipt actions mismatch")
	}
	// Require explicit false flags in every action, not missing/default booleans.
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(data, &fields)
	var actionRows []json.RawMessage
	if json.Unmarshal(fields["actions"], &actionRows) != nil {
		return record, errors.New("invalid receipt actions")
	}
	for _, row := range actionRows {
		if requiredKeys(row, []string{"action", "target", "status", "enforced"}) != nil {
			return record, errors.New("incomplete action receipt")
		}
	}
	if requiredKeys(fields["alert"], []string{"schema_version", "alert_id", "source", "event_code", "severity", "timestamp", "indicators", "actions"}) != nil {
		return record, errors.New("incomplete receipt alert")
	}
	return record, nil
}
func requiredKeys(data []byte, names []string) error {
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || len(fields) != len(names) {
		return errors.New("missing fields")
	}
	for _, name := range names {
		if _, exists := fields[name]; !exists {
			return errors.New("missing fields")
		}
	}
	return nil
}

var knownKeys = map[string]bool{
	"schema_version": true, "alert_id": true, "source": true, "event_code": true, "severity": true, "timestamp": true, "indicators": true, "actions": true,
	"job_id": true, "ip": true, "cert_serial": true, "status": true, "mode": true, "enforced": true, "payload_sha256": true, "recorded_at": true, "alert": true, "action": true, "target": true,
}

func strictDecode(data []byte, target any) error {
	check := json.NewDecoder(bytes.NewReader(data))
	check.UseNumber()
	if err := checkValue(check); err != nil {
		return err
	}
	if _, err := check.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return err
	}
	if dec.Decode(new(any)) != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
func checkValue(dec *json.Decoder) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}
	if token == nil {
		return errors.New("null not allowed")
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok || seen[key] || !knownKeys[key] {
				return errors.New("unknown or duplicate field")
			}
			seen[key] = true
			if err = checkValue(dec); err != nil {
				return err
			}
		}
	case '[':
		for dec.More() {
			if err := checkValue(dec); err != nil {
				return err
			}
		}
	default:
		return errors.New("invalid JSON structure")
	}
	_, err = dec.Token()
	return err
}
