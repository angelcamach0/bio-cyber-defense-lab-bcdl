// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

const admissionHeadroom int64 = 2 * maxJobMetadataBytes
const maxAdmissionLedgerBytes = 8 << 20
const admissionStageName = ".biozero-admission-staging"

type admissionPolicy struct {
	GlobalJobs             int64 `json:"global_jobs"`
	PrincipalJobs          int64 `json:"principal_jobs"`
	GlobalBytes            int64 `json:"global_bytes"`
	PrincipalBytes         int64 `json:"principal_bytes"`
	ActiveUploads          int64 `json:"active_uploads"`
	PrincipalActiveUploads int64 `json:"principal_active_uploads"`
	MaxBodyBytes           int64 `json:"max_body_bytes"`
	FreeSpaceFloor         int64 `json:"free_space_floor"`
}

func defaultAdmissionPolicy(body int64) admissionPolicy {
	return admissionPolicy{64, 16, 512 << 20, 128 << 20, 2, 1, body, 128 << 20}
}

func admissionPolicyFromEnv() (admissionPolicy, error) {
	policy := defaultAdmissionPolicy(25 << 20)
	fields := []struct {
		name   string
		target *int64
	}{
		{"BIOZERO_ADMISSION_GLOBAL_JOBS", &policy.GlobalJobs}, {"BIOZERO_ADMISSION_PRINCIPAL_JOBS", &policy.PrincipalJobs},
		{"BIOZERO_ADMISSION_GLOBAL_BYTES", &policy.GlobalBytes}, {"BIOZERO_ADMISSION_PRINCIPAL_BYTES", &policy.PrincipalBytes},
		{"BIOZERO_ADMISSION_ACTIVE_UPLOADS", &policy.ActiveUploads}, {"BIOZERO_ADMISSION_PRINCIPAL_ACTIVE_UPLOADS", &policy.PrincipalActiveUploads},
		{"BIOZERO_MAX_UPLOAD_BYTES", &policy.MaxBodyBytes}, {"BIOZERO_ADMISSION_FREE_SPACE_FLOOR", &policy.FreeSpaceFloor},
	}
	for _, field := range fields {
		if raw, present := os.LookupEnv(field.name); present {
			value, err := strconv.ParseInt(raw, 10, 64)
			if err != nil || value <= 0 {
				return policy, admissionError("admission_config_invalid")
			}
			*field.target = value
		}
	}
	return policy, policy.validate()
}

func (policy admissionPolicy) validate() error {
	if policy.GlobalJobs <= 0 || policy.GlobalJobs > 10000 || policy.PrincipalJobs <= 0 || policy.PrincipalJobs > policy.GlobalJobs ||
		policy.ActiveUploads <= 0 || policy.ActiveUploads > policy.GlobalJobs || policy.PrincipalActiveUploads <= 0 ||
		policy.PrincipalActiveUploads > policy.ActiveUploads || policy.PrincipalActiveUploads > policy.PrincipalJobs ||
		policy.MaxBodyBytes <= 0 || policy.MaxBodyBytes > math.MaxInt64-admissionHeadroom || policy.GlobalBytes <= 0 ||
		policy.PrincipalBytes <= 0 || policy.PrincipalBytes > policy.GlobalBytes || policy.MaxBodyBytes+admissionHeadroom > policy.PrincipalBytes ||
		policy.FreeSpaceFloor <= 0 || policy.FreeSpaceFloor > math.MaxInt64-policy.MaxBodyBytes-admissionHeadroom {
		return admissionError("admission_config_invalid")
	}
	return nil
}

type admissionEntry struct {
	JobID              string `json:"job_id"`
	PrincipalKey       string `json:"principal_key"`
	CertificateSerial  string `json:"certificate_serial"`
	State              string `json:"state"`
	ChargedBytes       int64  `json:"charged_bytes"`
	ActualInputBytes   int64  `json:"actual_input_bytes"`
	PayloadDevice      uint64 `json:"payload_device"`
	PayloadInode       uint64 `json:"payload_inode"`
	JobDevice          uint64 `json:"job_device"`
	JobInode           uint64 `json:"job_inode"`
	PayloadName        string `json:"payload_name"`
	PayloadSHA256      string `json:"payload_sha256"`
	ImmutableJobSHA256 string `json:"immutable_job_sha256"`
}

type admissionLedger struct {
	SchemaVersion int                       `json:"schema_version"`
	Policy        admissionPolicy           `json:"policy"`
	Entries       map[string]admissionEntry `json:"entries"`
}

type admissionStore struct {
	mu                                                   sync.Mutex // Mutual exclusion only; quota authority is always the ledger.
	dir, payloadStaging, jobStaging, uploads, jobs, lock *os.File
	policy                                               admissionPolicy
	sticky                                               bool
	failpoint                                            func(string) error // Tests inject durable-step failures; never configured remotely.
}

func principalKey(cn string) string {
	sum := sha256.Sum256([]byte(cn))
	return hex.EncodeToString(sum[:])
}
func dataSHA(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func isAdmissionHash(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && strings.ToLower(value) == value
}
func isAdmissionID(id string) bool {
	if len(id) != 16 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil && strings.ToLower(id) == id
}

func openAdmissionStore(dataDir string, policy admissionPolicy) (*admissionStore, error) {
	if err := policy.validate(); err != nil {
		return nil, err
	}
	store := &admissionStore{policy: policy}
	closeOnError := func(err error) (*admissionStore, error) { store.Close(); return nil, err }
	var err error
	if store.uploads, err = secureDirectory(filepath.Join(dataDir, "uploads"), true, false); err != nil {
		return closeOnError(err)
	}
	if store.jobs, err = secureDirectory(filepath.Join(dataDir, "jobs"), true, false); err != nil {
		return closeOnError(err)
	}
	if store.dir, err = secureDirectory(filepath.Join(dataDir, "admission"), true, true); err != nil {
		return closeOnError(err)
	}
	fd, err := syscall.Openat(int(store.dir.Fd()), "instance.lock", syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return closeOnError(admissionError("admission_instance_lock_unsafe"))
	}
	store.lock = os.NewFile(uintptr(fd), "admission-lock")
	info, err := store.lock.Stat()
	stat, ok := infoSysStat(info)
	if err != nil || !ok || !info.Mode().IsRegular() || stat.Mode&07777 != 0600 || stat.Uid != uint32(os.Geteuid()) {
		return closeOnError(admissionError("admission_instance_lock_unsafe"))
	}
	if syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return closeOnError(admissionError("admission_instance_already_running"))
	}
	if store.lock.Sync() != nil || store.dir.Sync() != nil {
		return closeOnError(admissionError("admission_instance_lock_sync_failed"))
	}
	namespace, err := readDirectoryFresh(store.dir)
	if err != nil {
		return closeOnError(admissionError("admission_namespace_unavailable"))
	}
	for _, item := range namespace {
		switch item.Name() {
		case "ledger.json", "instance.lock":
		default:
			return closeOnError(admissionError("admission_unknown_namespace_file"))
		}
	}
	// Hardlinks may not cross distinct bind mounts even when st_dev matches.
	// Each private stage therefore belongs to the mount of its destination.
	if store.payloadStaging, err = secureChildDirectory(store.uploads, admissionStageName, true); err != nil {
		return closeOnError(err)
	}
	if store.jobStaging, err = secureChildDirectory(store.jobs, admissionStageName, true); err != nil {
		return closeOnError(err)
	}
	var admissionDevice uint64
	for index, directory := range []*os.File{store.dir, store.payloadStaging, store.jobStaging, store.uploads, store.jobs} {
		info, statErr := directory.Stat()
		stat, ok := infoSysStat(info)
		if statErr != nil || !ok {
			return closeOnError(admissionError("admission_filesystem_invalid"))
		}
		if index == 0 {
			admissionDevice = stat.Dev
		} else if stat.Dev != admissionDevice {
			return closeOnError(admissionError("admission_filesystem_mismatch"))
		}
	}
	if _, err = secureRead(store.dir, "ledger.json", maxAdmissionLedgerBytes); os.IsNotExist(err) {
		for _, directory := range []*os.File{store.uploads, store.jobs} {
			entries, err := readDirectoryFresh(directory)
			if err != nil {
				return closeOnError(admissionError("admission_existing_data_requires_ledger"))
			}
			for _, entry := range entries {
				if entry.Name() != admissionStageName || !entry.IsDir() {
					return closeOnError(admissionError("admission_existing_data_requires_ledger"))
				}
			}
		}
		for _, directory := range []*os.File{store.payloadStaging, store.jobStaging} {
			entries, err := readDirectoryFresh(directory)
			if err != nil || len(entries) != 0 {
				return closeOnError(admissionError("admission_existing_data_requires_ledger"))
			}
		}
		ledger := admissionLedger{1, policy, map[string]admissionEntry{}}
		if err = store.save(ledger); err != nil {
			return closeOnError(err)
		}
	} else if err != nil {
		return closeOnError(err)
	}
	ledger, err := store.load()
	if err != nil {
		return closeOnError(err)
	}
	if err = store.recover(&ledger); err != nil {
		store.sticky = true
		return store, nil
	}
	return store, nil
}

func (store *admissionStore) Close() {
	for _, file := range []*os.File{store.payloadStaging, store.jobStaging, store.jobs, store.uploads, store.lock, store.dir} {
		if file != nil {
			file.Close()
		}
	}
}

func (store *admissionStore) healthy() bool {
	store.mu.Lock()
	defer store.mu.Unlock()
	return !store.sticky
}

// The acknowledgement and ambiguity latch share one linearization point. A
// published input remains charged even when this step cannot acknowledge it.
func (store *admissionStore) acknowledge(writeResponse func()) error {
	preflight := store.step("ack_before_lock")
	store.mu.Lock()
	defer store.mu.Unlock()
	if preflight != nil {
		store.sticky = true
	}
	if store.sticky {
		return admissionError("admission_state_unavailable")
	}
	writeResponse()
	return nil
}

func (store *admissionStore) step(name string) error {
	if store.failpoint != nil {
		return store.failpoint(name)
	}
	return nil
}

func (store *admissionStore) save(ledger admissionLedger) error {
	if store.step("ledger_before_write") != nil {
		store.sticky = true
		return admissionError("admission_state_unavailable")
	}
	data, err := json.MarshalIndent(ledger, "", "  ")
	if err != nil || len(data) > maxAdmissionLedgerBytes {
		store.sticky = true
		return admissionError("admission_state_unavailable")
	}
	if atomicLedgerWrite(store.dir, data) != nil || store.step("ledger_after_write") != nil {
		store.sticky = true
		return admissionError("admission_state_unavailable")
	}
	return nil
}

func (store *admissionStore) load() (admissionLedger, error) {
	var ledger admissionLedger
	data, err := secureRead(store.dir, "ledger.json", maxAdmissionLedgerBytes)
	if err != nil || strictAdmissionJSON(data, &ledger) != nil || ledger.SchemaVersion != 1 || ledger.Entries == nil || !reflect.DeepEqual(ledger.Policy, store.policy) {
		return ledger, admissionError("admission_state_invalid")
	}
	var totalBytes, totalActive int64
	principalJobs, principalBytes, principalActive := map[string]int64{}, map[string]int64{}, map[string]int64{}
	if int64(len(ledger.Entries)) > store.policy.GlobalJobs {
		return ledger, admissionError("admission_state_invalid")
	}
	for id, entry := range ledger.Entries {
		if !isAdmissionID(id) || entry.JobID != id || !isAdmissionHash(entry.PrincipalKey) || entry.ChargedBytes < admissionHeadroom || entry.ChargedBytes > store.policy.MaxBodyBytes+admissionHeadroom || entry.ActualInputBytes < 0 || entry.ActualInputBytes > store.policy.MaxBodyBytes {
			return ledger, admissionError("admission_state_invalid")
		}
		if entry.State != "reserved" && entry.State != "prepared" && entry.State != "committed" && entry.State != "blocked" {
			return ledger, admissionError("admission_state_invalid")
		}
		if entry.State != "committed" && entry.ChargedBytes != store.policy.MaxBodyBytes+admissionHeadroom {
			return ledger, admissionError("admission_state_invalid")
		}
		if entry.State == "committed" && entry.ChargedBytes != entry.ActualInputBytes+admissionHeadroom {
			return ledger, admissionError("admission_state_invalid")
		}
		if entry.State == "reserved" && (entry.ActualInputBytes != 0 || entry.JobDevice != 0 || entry.JobInode != 0 || entry.PayloadName != "" || entry.PayloadSHA256 != "" || entry.ImmutableJobSHA256 != "" || (entry.PayloadInode == 0 && entry.PayloadDevice != 0)) {
			return ledger, admissionError("admission_state_invalid")
		}
		if entry.State == "prepared" || entry.State == "committed" {
			if !safeBase(entry.PayloadName) || len(entry.PayloadName) > 255 || !strings.HasPrefix(entry.PayloadName, id+"_") || !isAdmissionHash(entry.PayloadSHA256) || !isAdmissionHash(entry.ImmutableJobSHA256) || entry.PayloadInode == 0 || entry.JobInode == 0 {
				return ledger, admissionError("admission_state_invalid")
			}
		}

		if totalBytes > store.policy.GlobalBytes-entry.ChargedBytes || principalBytes[entry.PrincipalKey] > store.policy.PrincipalBytes-entry.ChargedBytes {
			return ledger, admissionError("admission_state_invalid")
		}
		totalBytes += entry.ChargedBytes
		principalBytes[entry.PrincipalKey] += entry.ChargedBytes
		principalJobs[entry.PrincipalKey]++
		if entry.State != "committed" {
			totalActive++
			principalActive[entry.PrincipalKey]++
		}
		if principalJobs[entry.PrincipalKey] > store.policy.PrincipalJobs || principalActive[entry.PrincipalKey] > store.policy.PrincipalActiveUploads || totalActive > store.policy.ActiveUploads {
			return ledger, admissionError("admission_state_invalid")
		}
	}
	return ledger, nil
}

func (store *admissionStore) reserve(cn, serial string) (admissionEntry, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.sticky {
		return admissionEntry{}, admissionError("admission_state_unavailable")
	}
	ledger, err := store.load()
	if err != nil {
		store.sticky = true
		return admissionEntry{}, admissionError("admission_state_unavailable")
	}
	key := principalKey(cn)
	var jobs, ownerJobs, totalBytes, ownerBytes, active, ownerActive, pendingBytes int64
	for _, entry := range ledger.Entries {
		if totalBytes > math.MaxInt64-entry.ChargedBytes {
			store.sticky = true
			return admissionEntry{}, admissionError("admission_state_unavailable")
		}
		jobs++
		totalBytes += entry.ChargedBytes
		if entry.State != "committed" {
			active++
			pendingBytes += entry.ChargedBytes
		}
		if entry.PrincipalKey == key {
			ownerJobs++
			ownerBytes += entry.ChargedBytes
			if entry.State != "committed" {
				ownerActive++
			}
		}
	}
	reserveBytes := store.policy.MaxBodyBytes + admissionHeadroom
	if jobs >= store.policy.GlobalJobs || ownerJobs >= store.policy.PrincipalJobs || totalBytes > store.policy.GlobalBytes-reserveBytes || ownerBytes > store.policy.PrincipalBytes-reserveBytes {
		return admissionEntry{}, admissionError("quota_exceeded")
	}
	if active >= store.policy.ActiveUploads || ownerActive >= store.policy.PrincipalActiveUploads {
		return admissionEntry{}, admissionError("upload_concurrency_exceeded")
	}
	var fs syscall.Statfs_t
	if syscall.Fstatfs(int(store.dir.Fd()), &fs) != nil || fs.Bsize <= 0 || fs.Bavail > uint64(math.MaxInt64)/uint64(fs.Bsize) || int64(fs.Bavail)*fs.Bsize < store.policy.FreeSpaceFloor+reserveBytes || pendingBytes > int64(fs.Bavail)*fs.Bsize-store.policy.FreeSpaceFloor-reserveBytes {
		return admissionEntry{}, admissionError("storage_free_space_low")
	}
	id := randomID(8)
	if !isAdmissionID(id) {
		return admissionEntry{}, admissionError("admission_id_failed")
	}
	if _, exists := ledger.Entries[id]; exists {
		return admissionEntry{}, admissionError("admission_id_conflict")
	}
	entry := admissionEntry{JobID: id, PrincipalKey: key, CertificateSerial: serial, State: "reserved", ChargedBytes: reserveBytes}
	ledger.Entries[id] = entry
	if err := store.save(ledger); err != nil {
		return admissionEntry{}, err
	}
	return entry, nil
}

func (store *admissionStore) beginPayload(entry admissionEntry) (*os.File, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	ledger, err := store.load()
	if err != nil || store.sticky {
		store.sticky = true
		return nil, admissionError("admission_state_unavailable")
	}
	current, exists := ledger.Entries[entry.JobID]
	if !exists || current.State != "reserved" {
		return nil, admissionError("admission_reservation_invalid")
	}
	if syscall.Mkdirat(int(store.payloadStaging.Fd()), entry.JobID, 0700) != nil || store.payloadStaging.Sync() != nil {
		store.sticky = true
		return nil, admissionError("admission_stage_create_failed")
	}
	stage, err := secureChildDirectory(store.payloadStaging, entry.JobID, false)
	if err != nil {
		store.sticky = true
		return nil, err
	}
	defer stage.Close()
	file, err := exclusiveFile(stage, "payload.part")
	if err != nil {
		store.sticky = true
		return nil, err
	}
	if file.Sync() != nil || stage.Sync() != nil || store.step("payload_created_before_identity") != nil {
		file.Close()
		store.sticky = true
		return nil, admissionError("admission_stage_sync_failed")
	}
	info, err := file.Stat()
	stat, ok := infoSysStat(info)
	if err != nil || !ok {
		file.Close()
		store.sticky = true
		return nil, admissionError("admission_stage_stat_failed")
	}
	current.PayloadDevice, current.PayloadInode = stat.Dev, stat.Ino
	ledger.Entries[entry.JobID] = current
	if err := store.save(ledger); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func immutableJobHash(job jobRecord) string {
	job.Status = ""
	data, _ := json.MarshalIndent(job, "", "  ")
	return dataSHA(data)
}

func (store *admissionStore) commit(entry admissionEntry, job jobRecord, jobJSON []byte) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	ledger, err := store.load()
	if err != nil || store.sticky {
		store.sticky = true
		return admissionError("admission_state_unavailable")
	}
	current, ok := ledger.Entries[entry.JobID]
	if !ok || current.State != "reserved" || job.JobID != entry.JobID {
		return admissionError("admission_reservation_invalid")
	}
	payloadStage, err := secureChildDirectory(store.payloadStaging, entry.JobID, false)
	if err != nil {
		store.sticky = true
		return err
	}
	defer payloadStage.Close()
	if syscall.Mkdirat(int(store.jobStaging.Fd()), entry.JobID, 0700) != nil || store.jobStaging.Sync() != nil {
		store.sticky = true
		return admissionError("admission_stage_create_failed")
	}
	stage, err := secureChildDirectory(store.jobStaging, entry.JobID, false)
	if err != nil {
		store.sticky = true
		return err
	}
	defer stage.Close()
	file, err := exclusiveFile(stage, "job.part")
	if err != nil {
		store.sticky = true
		return err
	}
	if file.Sync() != nil || stage.Sync() != nil {
		file.Close()
		store.sticky = true
		return admissionError("admission_stage_sync_failed")
	}
	info, err := file.Stat()
	stat, ok := infoSysStat(info)
	if err != nil || !ok {
		file.Close()
		store.sticky = true
		return admissionError("admission_stage_stat_failed")
	}
	current.State = "prepared"
	current.ActualInputBytes = job.SizeBytes
	current.PayloadName = job.JobID + "_" + sanitizeFilename(job.OriginalName)
	current.PayloadSHA256 = job.SHA256
	current.ImmutableJobSHA256 = immutableJobHash(job)
	current.JobDevice, current.JobInode = stat.Dev, stat.Ino
	ledger.Entries[entry.JobID] = current
	if err := store.save(ledger); err != nil {
		file.Close()
		return err
	}
	_, err = file.Write(jobJSON)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil || stage.Sync() != nil || store.step("prepared_before_publication") != nil {
		store.sticky = true
		return admissionError("admission_publication_failed")
	}
	// Both publications are same-filesystem, atomic and refuse existing names.
	if os.Link(filepath.Join(directoryPath(payloadStage), "payload.part"), filepath.Join(directoryPath(store.uploads), current.PayloadName)) != nil || store.uploads.Sync() != nil || store.step("payload_published") != nil {
		store.sticky = true
		return admissionError("admission_publication_failed")
	}
	if os.Link(filepath.Join(directoryPath(stage), "job.part"), filepath.Join(directoryPath(store.jobs), entry.JobID+".json")) != nil || store.jobs.Sync() != nil || store.step("job_published") != nil {
		store.sticky = true
		return admissionError("admission_publication_failed")
	}
	if err := store.cleanupStage(current); err != nil {
		store.sticky = true
		return err
	}
	current.State = "committed"
	current.ChargedBytes = current.ActualInputBytes + admissionHeadroom
	ledger.Entries[entry.JobID] = current
	if err := store.save(ledger); err != nil {
		return err
	}
	if store.step("committed_before_ack") != nil {
		store.sticky = true
		return admissionError("admission_state_unavailable")
	}
	return nil
}

func fileIdentity(dir *os.File, name string, device, inode uint64) error {
	fd, err := syscall.Openat(int(dir.Fd()), name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err == syscall.ENOENT {
		return os.ErrNotExist
	}
	if err != nil {
		return admissionError("admission_stage_unsafe")
	}
	file := os.NewFile(uintptr(fd), "admission-stage-file")
	defer file.Close()
	info, err := file.Stat()
	stat, ok := infoSysStat(info)
	if err != nil || !ok || !info.Mode().IsRegular() || stat.Mode&07777 != 0600 || stat.Uid != uint32(os.Geteuid()) || inode == 0 || stat.Dev != device || stat.Ino != inode {
		return admissionError("admission_stage_identity_mismatch")
	}
	return nil
}

func readDirectoryFresh(dir *os.File) ([]os.DirEntry, error) {
	fd, err := syscall.Openat(int(dir.Fd()), ".", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, admissionError("admission_directory_unavailable")
	}
	file := os.NewFile(uintptr(fd), "admission-directory")
	defer file.Close()
	return file.ReadDir(-1)
}

func (store *admissionStore) cleanupStage(entry admissionEntry) error {
	type ownedStage struct {
		parent, directory *os.File
		entries           []os.DirEntry
	}
	var stages []ownedStage
	defer func() {
		for _, stage := range stages {
			stage.directory.Close()
		}
	}()
	for _, spec := range []struct {
		parent        *os.File
		name          string
		device, inode uint64
	}{
		{store.payloadStaging, "payload.part", entry.PayloadDevice, entry.PayloadInode},
		{store.jobStaging, "job.part", entry.JobDevice, entry.JobInode},
	} {
		stage, err := secureChildDirectory(spec.parent, entry.JobID, false)
		if os.IsNotExist(err) {
			if spec.parent.Sync() != nil {
				return admissionError("admission_stage_cleanup_failed")
			}
			continue
		}
		if err != nil {
			return err
		}
		items, err := readDirectoryFresh(stage)
		stages = append(stages, ownedStage{spec.parent, stage, items})
		if err != nil {
			return admissionError("admission_stage_unavailable")
		}
		for _, item := range items {
			if item.Name() != spec.name {
				return admissionError("admission_stage_unknown_file")
			}
			if fileIdentity(stage, item.Name(), spec.device, spec.inode) != nil {
				return admissionError("admission_stage_identity_mismatch")
			}
		}
	}
	for _, stage := range stages {
		for _, item := range stage.entries {
			if syscall.Unlinkat(int(stage.directory.Fd()), item.Name()) != nil {
				return admissionError("admission_stage_cleanup_failed")
			}
		}
		if stage.directory.Sync() != nil || os.Remove(filepath.Join(directoryPath(stage.parent), entry.JobID)) != nil || stage.parent.Sync() != nil || store.step("stage_cleanup_after_sync") != nil {
			return admissionError("admission_stage_cleanup_failed")
		}
	}
	return nil
}

func (store *admissionStore) abort(entry admissionEntry) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.sticky {
		return admissionError("admission_state_unavailable")
	}
	ledger, err := store.load()
	if err != nil {
		store.sticky = true
		return admissionError("admission_state_unavailable")
	}
	current, ok := ledger.Entries[entry.JobID]
	if !ok || current.State != "reserved" {
		store.sticky = true
		return admissionError("admission_reservation_invalid")
	}
	if err := store.cleanupStage(current); err != nil {
		store.sticky = true
		return err
	}
	delete(ledger.Entries, entry.JobID)
	return store.save(ledger)
}

func recoveredImmutableJob(data []byte) (jobRecord, error) {
	var job jobRecord
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	if scanAdmissionJSON(decoder, 0, nil) != nil {
		return job, admissionError("admission_published_job_invalid")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || fields == nil {
		return job, admissionError("admission_published_job_invalid")
	}
	typeOf := reflect.TypeOf(job)
	known := map[string]reflect.Type{}
	for i := 0; i < typeOf.NumField(); i++ {
		field := typeOf.Field(i)
		known[strings.Split(field.Tag.Get("json"), ",")[0]] = field.Type
	}
	for _, name := range []string{"started_at", "error_code", "error_message"} {
		known[name] = reflect.TypeOf("")
	}
	for key, raw := range fields {
		fieldType, ok := known[key]
		if !ok || string(raw) == "null" || json.Unmarshal(raw, reflect.New(fieldType).Interface()) != nil {
			return job, admissionError("admission_published_job_invalid")
		}
	}
	if json.Unmarshal(data, &job) != nil || !isAdmissionID(job.JobID) {
		return job, admissionError("admission_published_job_invalid")
	}
	switch job.Status {
	case "uploaded", "running", "succeeded", "incomplete", "rejected", "failed", "timed_out", "processed":
	default:
		return job, admissionError("admission_published_job_invalid")
	}
	return job, nil
}

func (store *admissionStore) recover(ledger *admissionLedger) error {
	knownUploads, knownJobs := map[string]bool{admissionStageName: true}, map[string]bool{admissionStageName: true}
	for id, entry := range ledger.Entries {
		if entry.State == "blocked" {
			return admissionError("admission_recovery_blocked")
		}
		jobData, jobErr := secureRead(store.jobs, id+".json", maxJobMetadataBytes)
		if entry.State == "reserved" {
			if !os.IsNotExist(jobErr) {
				return admissionError("admission_unexpected_publication")
			}
			if err := store.cleanupStage(entry); err != nil {
				return err
			}
			delete(ledger.Entries, id)
			continue
		}
		if jobErr == nil {
			job, err := recoveredImmutableJob(jobData)
			if err != nil || immutableJobHash(job) != entry.ImmutableJobSHA256 {
				return admissionError("admission_published_job_mismatch")
			}
			payload, err := secureRead(store.uploads, entry.PayloadName, store.policy.MaxBodyBytes)
			if err != nil || int64(len(payload)) != entry.ActualInputBytes || dataSHA(payload) != entry.PayloadSHA256 {
				return admissionError("admission_published_payload_mismatch")
			}
			if err := store.cleanupStage(entry); err != nil {
				return err
			}
			entry.State = "committed"
			entry.ChargedBytes = entry.ActualInputBytes + admissionHeadroom
			ledger.Entries[id] = entry
		} else {
			// Only definitively unpublished originals may be cleaned. A retained
			// payload without its job is ambiguous and stays charged for review.
			_, payloadErr := secureRead(store.uploads, entry.PayloadName, store.policy.MaxBodyBytes)
			if entry.State == "committed" || !os.IsNotExist(jobErr) || !os.IsNotExist(payloadErr) {
				return admissionError("admission_prepared_publication_ambiguous")
			}
			if err := store.cleanupStage(entry); err != nil {
				return err
			}
			delete(ledger.Entries, id)
		}
	}
	// Only retained ledger entries authorize final files. Deleted reservations
	// cannot grandfather names into the recovery scan; all staging was cleaned.
	for id, entry := range ledger.Entries {
		knownJobs[id+".json"] = true
		knownUploads[entry.PayloadName] = true
	}
	for _, scan := range []struct {
		dir   *os.File
		known map[string]bool
	}{{store.uploads, knownUploads}, {store.jobs, knownJobs}, {store.payloadStaging, map[string]bool{}}, {store.jobStaging, map[string]bool{}}} {
		entries, err := readDirectoryFresh(scan.dir)
		if err != nil {
			return admissionError("admission_recovery_scan_failed")
		}
		for _, item := range entries {
			if !scan.known[item.Name()] {
				return admissionError("admission_unknown_existing_file")
			}
		}
	}
	return store.save(*ledger)
}
