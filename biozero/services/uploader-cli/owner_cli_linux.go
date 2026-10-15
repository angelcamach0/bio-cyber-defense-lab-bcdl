//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	ownership "biozero/ownership-authority"
)

// Protocol selection is deliberate and precedes all protocol-specific flags.
// An owner-v1 error can never dispatch to legacy code.
func runUploader(args []string, out, stderr io.Writer) int {
	protocol := ""
	rest := []string{}
	if len(args) > 0 && strings.HasPrefix(args[0], "--protocol=") {
		protocol = strings.TrimPrefix(args[0], "--protocol=")
		rest = args[1:]
	} else if len(args) > 1 && args[0] == "--protocol" {
		protocol = args[1]
		rest = args[2:]
	}
	switch protocol {
	case "owner-v1":
		return runOwnerCLI(rest, out, stderr)
	case "legacy":
		return runLegacyCLI(rest)
	default:
		fmt.Fprintln(stderr, "protocol_required: use --protocol owner-v1 or --protocol legacy")
		return 1
	}
}

type ownerRunIntent struct {
	SchemaVersion   int    `json:"schema_version"`
	Domain          string `json:"domain"`
	ConfigSHA256    string `json:"config_sha256"`
	OriginalName    string `json:"original_name"`
	PlaintextSHA256 string `json:"plaintext_sha256"`
	PlaintextBytes  int64  `json:"plaintext_bytes"`
}

func openOwnerRun(path string, create bool) (*os.File, error) {
	if !ownerPath(path) {
		return nil, ownerError("owner_run_unsafe")
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, ownerError("owner_run_unsafe")
	}
	for i, name := range parts {
		if create && i == len(parts)-1 {
			if syscall.Mkdirat(fd, name, 0700) != nil {
				syscall.Close(fd)
				return nil, ownerError("owner_run_not_new")
			}
			if syscall.Fsync(fd) != nil {
				syscall.Close(fd)
				return nil, ownerError("owner_run_sync_failed")
			}
		}
		next, e := syscall.Openat(fd, name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
		syscall.Close(fd)
		if e != nil {
			return nil, ownerError("owner_run_unsafe")
		}
		fd = next
	}
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil || st.Uid != uint32(os.Geteuid()) || st.Mode&07777 != 0700 {
		syscall.Close(fd)
		return nil, ownerError("owner_run_unsafe")
	}
	return os.NewFile(uintptr(fd), "owner-run"), nil
}
func writeOwnerRun(root *os.File, intent ownerRunIntent) error {
	raw, err := json.Marshal(intent)
	if err != nil || len(raw) > 4096 {
		return ownerError("owner_run_invalid")
	}
	fd, e := syscall.Openat(int(root.Fd()), "run.json", syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if e != nil {
		return ownerError("owner_run_write_failed")
	}
	f := os.NewFile(uintptr(fd), "owner-run-intent")
	if _, e = ownerFileStat(f); e != nil {
		f.Close()
		return e
	}
	n, e := f.Write(raw)
	if e == nil && n != len(raw) {
		e = io.ErrShortWrite
	}
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil || closeErr != nil || root.Sync() != nil {
		return ownerError("owner_run_sync_failed")
	}
	return nil
}
func loadOwnerRun(path, configSHA, name string) (ownerRunIntent, error) {
	var intent ownerRunIntent
	root, err := openOwnerRun(path, false)
	if err != nil {
		return intent, err
	}
	defer root.Close()
	// Only the two fixed journal subdirectories are allowed. Neither is adopted.
	entries, err := root.ReadDir(5)
	if err != nil && err != io.EOF || len(entries) > 3 {
		return intent, ownerError("owner_run_history_unknown")
	}
	seen := map[string]bool{}
	for _, e := range entries {
		n := e.Name()
		if n != "run.json" && n != "operation" && n != "delivery" {
			return intent, ownerError("owner_run_history_unknown")
		}
		seen[n] = true
		if n != "run.json" {
			child, e := openOwnerRun(filepath.Join(path, n), false)
			if e != nil {
				return intent, e
			}
			child.Close()
		}
	}
	if !seen["run.json"] || !seen["operation"] {
		return intent, ownerError("owner_run_history_unknown")
	}
	raw, err := readOwnerFile(filepath.Join(path, "run.json"), 4096)
	if err != nil {
		return intent, err
	}
	if err = decodeOwnerJSON(raw, &intent); err != nil {
		return intent, err
	}
	if intent.SchemaVersion != 1 || intent.Domain != "biozero.uploader.owner-v1.run" || intent.ConfigSHA256 != configSHA || intent.OriginalName != name || !ownerHex(intent.PlaintextSHA256, 64) || intent.PlaintextBytes < 0 || intent.PlaintextBytes > ownership.MaxPlaintextBytes {
		return intent, ownerError("owner_run_context_mismatch")
	}
	return intent, nil
}
func readOwnerInput(path string) ([]byte, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, ownerError("owner_input_invalid")
	}
	return readOwnerFile(abs, ownership.MaxPlaintextBytes)
}

func ownerDeliveryExists(path string) (bool, error) {
	root, err := openOwnerRun(path, false)
	if err != nil {
		return false, err
	}
	defer root.Close()
	fd, err := syscall.Openat(int(root.Fd()), "delivery", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err == syscall.ENOENT {
		return false, nil
	}
	if err != nil {
		return false, ownerError("owner_delivery_unsafe")
	}
	defer syscall.Close(fd)
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil || st.Uid != uint32(os.Geteuid()) || st.Mode&07777 != 0700 {
		return false, ownerError("owner_delivery_unsafe")
	}
	return true, nil
}

func runOwnerCLI(args []string, out, stderr io.Writer) (code int) {
	flags := flag.NewFlagSet("uploader --protocol owner-v1", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "private pinned client configuration")
	runDir := flags.String("run-dir", "", "absolute private run directory")
	action := flags.String("action", "submit", "submit, create, reserve, prepare, finalize, recover-authority, deliver, recover-delivery or status")
	input := flags.String("file", "", "private plaintext input (submit/create/prepare only)")
	timeout := flags.Duration("timeout", 3*time.Minute, "total command context budget")
	reportErr := func(err error) int { fmt.Fprintln(stderr, err.Error()); return 1 }
	if flags.Parse(args) != nil || flags.NArg() != 0 || *timeout <= 0 || *timeout > 10*time.Minute || !ownerPath(*runDir) {
		return reportErr(ownerError("owner_arguments_invalid"))
	}
	valid := map[string]bool{"submit": true, "create": true, "reserve": true, "prepare": true, "finalize": true, "recover-authority": true, "deliver": true, "recover-delivery": true, "status": true}
	if !valid[*action] {
		return reportErr(ownerError("owner_action_invalid"))
	}
	needsInput := *action == "submit" || *action == "create" || *action == "prepare"
	if needsInput != (*input != "") {
		return reportErr(ownerError("owner_input_arguments_invalid"))
	}
	material, err := loadOwnerConfig(*configPath)
	if err != nil {
		return reportErr(err)
	}
	for _, p := range []string{*configPath, material.config.TLSCertificate.Path, material.config.TLSPrivateKey.Path, material.config.AuthorityCA.Path, material.config.UploadCA.Path, material.config.EncryptionPublicKey.Path} {
		if ownerOverlap(*runDir, p) {
			return reportErr(ownerError("owner_run_asset_overlap"))
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	operationConfig := ownership.ClientOperationConfig{Directory: filepath.Join(*runDir, "operation"), Client: material.authority, EncryptionKey: material.encryption, OriginalName: material.config.OriginalName}
	var operation *ownership.ClientOperation
	var plaintext []byte
	var intent ownerRunIntent
	if *action == "submit" || *action == "create" {
		plaintext, err = readOwnerInput(*input)
		if err != nil {
			return reportErr(err)
		}
		defer clear(plaintext)
		intent = ownerRunIntent{1, "biozero.uploader.owner-v1.run", material.configSHA, material.config.OriginalName, ownerDigest(plaintext), int64(len(plaintext))}
		root, e := openOwnerRun(*runDir, true)
		if e != nil {
			return reportErr(e)
		}
		e = writeOwnerRun(root, intent)
		closeErr := root.Close()
		if e != nil {
			return reportErr(e)
		}
		if closeErr != nil {
			return reportErr(ownerError("owner_run_close_failed"))
		}
		operation, err = ownership.CreateClientOperation(operationConfig)
	} else {
		intent, err = loadOwnerRun(*runDir, material.configSHA, material.config.OriginalName)
		if err == nil {
			operation, err = ownership.OpenClientOperation(operationConfig)
		}
	}
	if err != nil {
		return reportErr(err)
	}
	defer func() {
		if e := operation.Close(); e != nil {
			fmt.Fprintln(stderr, "owner_operation_close_failed")
			code = 1
		}
	}()
	prepare := func() error {
		if plaintext == nil {
			var e error
			plaintext, e = readOwnerInput(*input)
			if e != nil {
				return e
			}
			defer clear(plaintext)
		}
		if int64(len(plaintext)) != intent.PlaintextBytes || ownerDigest(plaintext) != intent.PlaintextSHA256 {
			return ownerError("owner_input_changed")
		}
		return operation.Prepare(ctx, plaintext, time.Now())
	}
	var receipt *ownership.OwnerUploadReceipt
	deliver := func(recoverOnly bool) error {
		var delivery *ownership.ClientDelivery
		var e error
		bundle, be := operation.AcceptedBundle()
		if be != nil {
			return be
		}
		accepted, be := ownership.VerifyAcceptance(bundle.Acceptance, material.authority.Pin, material.authority.Scope)
		if be != nil {
			return be
		}
		exists, be := ownerDeliveryExists(*runDir)
		if be != nil {
			return be
		}
		if recoverOnly || exists {
			delivery, e = ownership.OpenClientDelivery(ctx, filepath.Join(*runDir, "delivery"), material.upload)
		} else {
			delivery, e = ownership.CreateClientDelivery(ctx, filepath.Join(*runDir, "delivery"), material.upload, bundle)
		}
		if e != nil {
			return e
		}
		if delivery.JobID() != operation.JobID() {
			_ = delivery.Close()
			return ownerError("owner_delivery_job_mismatch")
		}
		deliverySHA, be := delivery.AcceptanceSHA256()
		if be != nil || deliverySHA != accepted.SHA256() {
			_ = delivery.Close()
			return ownerError("owner_delivery_acceptance_mismatch")
		}
		var r ownership.OwnerUploadReceipt
		if recoverOnly {
			r, e = delivery.Recover(ctx)
		} else {
			r, e = delivery.Deliver(ctx)
		}
		ce := delivery.Close()
		if e != nil {
			return e
		}
		if ce != nil {
			return ownerError("owner_delivery_close_failed")
		}
		binding := accepted.Binding()
		if r.JobID != binding.JobID || r.AcceptanceSHA256 != accepted.SHA256() || r.CredentialSHA256 != binding.CredentialSHA256 || r.CiphertextSHA256 != binding.CiphertextSHA256 || r.CiphertextBytes != binding.CiphertextBytes || r.KeyEnvelopeSHA256 != binding.KeyEnvelopeSHA256 || r.State != "delivered" || r.SchemaVersion != 1 {
			return ownerError("owner_delivery_receipt_mismatch")
		}
		receipt = &r
		return nil
	}
	statusPhase := ""
	statusPending := false
	switch *action {
	case "submit":
		if err = operation.Reserve(ctx); err == nil {
			err = prepare()
		}
		if err == nil {
			err = operation.Finalize(ctx)
		}
		if err == nil {
			err = deliver(false)
		}
	case "create":
	case "status":
		exists, e := ownerDeliveryExists(*runDir)
		if e != nil {
			err = e
			break
		}
		if !exists {
			break
		}
		bundle, e := operation.AcceptedBundle()
		if e != nil {
			err = e
			break
		}
		accepted, e := ownership.VerifyAcceptance(bundle.Acceptance, material.authority.Pin, material.authority.Scope)
		if e != nil {
			err = e
			break
		}
		delivery, e := ownership.OpenClientDelivery(ctx, filepath.Join(*runDir, "delivery"), material.upload)
		if e != nil {
			err = e
			break
		}
		sha, e := delivery.AcceptanceSHA256()
		if e != nil || sha != accepted.SHA256() || delivery.JobID() != operation.JobID() {
			_ = delivery.Close()
			err = ownerError("owner_delivery_acceptance_mismatch")
			break
		}
		state := delivery.State()
		if state == "delivered" {
			r, e := delivery.Receipt()
			if e != nil {
				err = e
			} else {
				binding := accepted.Binding()
				if r.JobID != binding.JobID || r.AcceptanceSHA256 != accepted.SHA256() || r.CredentialSHA256 != binding.CredentialSHA256 || r.CiphertextSHA256 != binding.CiphertextSHA256 || r.CiphertextBytes != binding.CiphertextBytes || r.KeyEnvelopeSHA256 != binding.KeyEnvelopeSHA256 || r.SchemaVersion != 1 || r.State != "delivered" {
					err = ownerError("owner_delivery_receipt_mismatch")
				} else {
					receipt = &r
				}
			}
		} else if state == "prepared" {
			statusPhase = "delivery_prepared"
			statusPending = true
		} else if state == "delivering" {
			statusPhase = "delivery_pending"
			statusPending = true
		} else {
			err = ownerError("owner_delivery_unavailable")
		}
		closeErr := delivery.Close()
		if closeErr != nil && !(state == "delivering" && closeErr.Error() == "ownership_delivery_pending") {
			err = ownerError("owner_delivery_close_failed")
		}
	case "reserve":
		err = operation.Reserve(ctx)
	case "prepare":
		err = prepare()
	case "finalize":
		err = operation.Finalize(ctx)
	case "recover-authority":
		err = operation.Recover(ctx)
	case "deliver":
		err = deliver(false)
	case "recover-delivery":
		err = deliver(true)
	}
	if err != nil {
		if ctx.Err() != nil {
			fmt.Fprintln(stderr, "owner_deadline_exceeded")
			return 4
		}
		return reportErr(err)
	}
	phase := operation.State()
	if statusPhase != "" {
		phase = statusPhase
	}
	if receipt != nil {
		phase = "delivered"
	}
	response := struct {
		Protocol         string `json:"protocol"`
		Phase            string `json:"phase"`
		JobID            string `json:"job_id"`
		AcceptanceSHA256 string `json:"acceptance_sha256,omitempty"`
	}{Protocol: "owner-v1", Phase: phase, JobID: operation.JobID()}
	if receipt != nil {
		response.AcceptanceSHA256 = receipt.AcceptanceSHA256
	}
	if json.NewEncoder(out).Encode(response) != nil {
		return reportErr(ownerError("owner_output_failed"))
	}
	if statusPending {
		return 2
	}
	return 0
}
