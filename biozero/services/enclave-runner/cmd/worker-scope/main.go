//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
// worker-scope prepares a private staging filesystem before executing the pinned
// protected worker. Operator configuration is trusted; this is not an RPC surface.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const stageBytes int64 = 32 << 20
const stageInodes uint64 = 4096
const workerLimit int64 = 32 << 20
const internalArgument = "--worker-scope-child"

type launchSpec struct {
	SchemaVersion    int               `json:"schema_version"`
	Worker           string            `json:"worker"`
	SHA256           string            `json:"sha256"`
	Tmpfs            string            `json:"tmpfs"`
	ParentNamespaces map[string]string `json:"parent_namespaces"`
	Environment      []string          `json:"environment"`
}

var workerEnvironmentKeys = map[string]bool{
	"BIOZERO_DATA_DIR": true, "BIOZERO_POLL_SECONDS": true, "BIOZERO_PRIVATE_KEY": true,
	"BIOZERO_SIGNER_CERT": true, "BIOZERO_JOB_KEY": true, "BIOZERO_SECURITY_MODE": true,
	"BIOZERO_PIPELINE_MODE": true, "BIOZERO_SECURITY_EVENTS_DIR": true,
	"BIOZERO_ARTIFACT_SOCKET": true, "BIOZERO_ARTIFACT_PROFILE_SHA256": true,
	"BIOZERO_WORKER_CUSTODY_DIR": true, "BIOZERO_ARTIFACT_PROJECTION_POLICY": true, "BIOZERO_EXECUTION_BACKEND": true, "BIOZERO_PIPELINE_TIMEOUT": true,
}

func safePath(p string) bool {
	return filepath.IsAbs(p) && filepath.Clean(p) == p && p != "/" && !strings.ContainsAny(p, "\x00\r\n")
}
func validSHA(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func fixedEnvironment(in []string, tmpfs string) ([]string, error) {
	env := []string{"LANG=C", "LC_ALL=C", "BIOZERO_DECRYPT_DIR=" + tmpfs}
	seen := map[string]bool{}
	for _, pair := range in {
		k, v, ok := strings.Cut(pair, "=")
		if !ok || strings.ContainsRune(v, 0) {
			return nil, errors.New("worker_scope_environment_invalid")
		}
		if !workerEnvironmentKeys[k] {
			continue
		}
		if seen[k] {
			return nil, errors.New("worker_scope_environment_invalid")
		}
		if k == "BIOZERO_EXECUTION_BACKEND" && v != "capsule" {
			return nil, errors.New("worker_scope_backend_invalid")
		}
		if k == "BIOZERO_PIPELINE_TIMEOUT" {
			d, e := time.ParseDuration(v)
			if e != nil || d <= 0 || d > 10*time.Minute {
				return nil, errors.New("worker_scope_timeout_invalid")
			}
		}

		seen[k] = true
		env = append(env, k+"="+v)
	}
	return env, nil
}
func ancestorOwner(uid uint32) bool {
	if uid == 0 || uid == uint32(os.Geteuid()) {
		return true
	}
	if os.Geteuid() != 0 || checkMappings() != nil {
		return false
	}
	raw, e := os.ReadFile("/proc/sys/kernel/overflowuid")
	if e != nil || len(raw) > 64 {
		return false
	}
	value, e := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 32)
	return e == nil && uint32(value) == uid
}

func directory(path string, create bool) (*os.File, error) {
	if !safePath(path) {
		return nil, errors.New("worker_scope_directory_invalid")
	}
	fd, e := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, errors.New("worker_scope_directory_unsafe")
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, name := range parts {
		next, err := syscall.Openat(fd, name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
		if err == syscall.ENOENT && create && i == len(parts)-1 {
			if syscall.Mkdirat(fd, name, 0700) != nil {
				syscall.Close(fd)
				return nil, errors.New("worker_scope_directory_create_failed")
			}
			parent := os.NewFile(uintptr(fd), "worker-scope-parent")
			if parent.Sync() != nil {
				parent.Close()
				return nil, errors.New("worker_scope_directory_sync_failed")
			}
			next, err = syscall.Openat(fd, name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
			parent.Close()
			fd = -1
		}
		if fd >= 0 {
			syscall.Close(fd)
		}
		if err != nil {
			return nil, errors.New("worker_scope_directory_unsafe")
		}
		fd = next
		var s syscall.Stat_t
		if syscall.Fstat(fd, &s) != nil || !ancestorOwner(s.Uid) || s.Mode&0022 != 0 && s.Mode&syscall.S_ISVTX == 0 {
			syscall.Close(fd)
			return nil, errors.New("worker_scope_directory_unsafe")
		}
	}
	f := os.NewFile(uintptr(fd), "worker-scope-target")
	var s syscall.Stat_t
	if syscall.Fstat(fd, &s) != nil || s.Uid != uint32(os.Geteuid()) || s.Mode&07777 != 0700 {
		f.Close()
		return nil, errors.New("worker_scope_directory_unsafe")
	}
	return f, nil
}
func openWorker(ctx context.Context, path, pin string) (*os.File, error) {
	if !safePath(path) || !validSHA(pin) {
		return nil, errors.New("worker_scope_binary_invalid")
	}
	// Ancestor directories use nofollow traversal but need not be private leaves.
	fd, e := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, errors.New("worker_scope_binary_invalid")
	}
	for _, part := range strings.Split(strings.TrimPrefix(filepath.Dir(path), "/"), "/") {
		if part == "" {
			continue
		}
		n, err := syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
		syscall.Close(fd)
		if err != nil {
			return nil, errors.New("worker_scope_binary_invalid")
		}
		fd = n
		var st syscall.Stat_t
		if syscall.Fstat(fd, &st) != nil || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) || st.Mode&0022 != 0 && st.Mode&syscall.S_ISVTX == 0 {
			syscall.Close(fd)
			return nil, errors.New("worker_scope_binary_invalid")
		}
	}
	raw, e := syscall.Openat(fd, filepath.Base(path), syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	syscall.Close(fd)
	if e != nil {
		return nil, errors.New("worker_scope_binary_invalid")
	}
	f := os.NewFile(uintptr(raw), "worker-scope-pinned-executable")
	var s syscall.Stat_t
	if syscall.Fstat(raw, &s) != nil || !ancestorOwner(s.Uid) || s.Mode&syscall.S_IFMT != syscall.S_IFREG || s.Mode&07022 != 0 || s.Mode&0111 == 0 || s.Nlink != 1 {
		f.Close()
		return nil, errors.New("worker_scope_binary_unsafe")
	}
	if verifyWorker(ctx, f, pin) != nil {
		f.Close()
		return nil, errors.New("worker_scope_binary_invalid")
	}
	return f, nil
}
func verifyWorker(ctx context.Context, f *os.File, pin string) error {
	if ctx == nil || ctx.Err() != nil || f == nil || !validSHA(pin) {
		return errors.New("worker_scope_binary_invalid")
	}
	var before, after syscall.Stat_t
	if syscall.Fstat(int(f.Fd()), &before) != nil || before.Mode&syscall.S_IFMT != syscall.S_IFREG || before.Mode&07022 != 0 || before.Mode&0111 == 0 || before.Nlink != 1 || before.Size < 1 || before.Size > workerLimit {
		return errors.New("worker_scope_binary_unsafe")
	}
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, f.Fd(), syscall.F_GETFL, 0)
	if errno != 0 || flags&syscall.O_ACCMODE != syscall.O_RDONLY {
		return errors.New("worker_scope_binary_unsafe")
	}
	h := sha256.New()
	buf := make([]byte, 65536)
	reader := io.NewSectionReader(f, 0, workerLimit+1)
	var total int64
	for {
		if ctx.Err() != nil {
			return errors.New("worker_scope_cancelled")
		}
		n, e := reader.Read(buf)
		if n > 0 {
			total += int64(n)
			h.Write(buf[:n])
		}
		if total > workerLimit {
			return errors.New("worker_scope_binary_invalid")
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return errors.New("worker_scope_binary_invalid")
		}
	}
	if syscall.Fstat(int(f.Fd()), &after) != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim || total != before.Size || hex.EncodeToString(h.Sum(nil)) != pin {
		return errors.New("worker_scope_binary_changed")
	}
	return nil
}
func namespaces() (map[string]string, error) {
	m := map[string]string{}
	for _, n := range []string{"user", "mnt", "net"} {
		v, e := os.Readlink("/proc/self/ns/" + n)
		if e != nil {
			return nil, errors.New("worker_scope_namespace_unavailable")
		}
		m[n] = v
	}
	return m, nil
}
func checkMappings() error {
	if os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
		return errors.New("worker_scope_namespace_required")
	}
	for _, p := range []string{"/proc/self/uid_map", "/proc/self/gid_map"} {
		raw, e := os.ReadFile(p)
		f := strings.Fields(string(raw))
		if e != nil || len(raw) > 128 || len(f) != 3 || f[0] != "0" || f[1] != "1000" || f[2] != "1" {
			return errors.New("worker_scope_mapping_invalid")
		}
	}
	return nil
}
func prctl(a, b uintptr) error {
	_, _, e := syscall.Syscall6(syscall.SYS_PRCTL, a, b, 0, 0, 0, 0)
	if e != 0 {
		return e
	}
	return nil
}
func dropCapabilities() error {
	for i := uintptr(0); i < 64; i++ {
		e := prctl(24, i)
		if e == syscall.EINVAL {
			break
		}
		if e != nil {
			return errors.New("worker_scope_capabilities_failed")
		}
	}
	if prctl(47, 4) != nil {
		return errors.New("worker_scope_capabilities_failed")
	}
	header := struct {
		Version uint32
		PID     int32
	}{0x20080522, 0}
	data := [2]struct{ Effective, Permitted, Inheritable uint32 }{}
	_, _, errno := syscall.RawSyscall(syscall.SYS_CAPSET, uintptr(unsafe.Pointer(&header)), uintptr(unsafe.Pointer(&data[0])), 0)
	if errno != 0 || prctl(38, 1) != nil {
		return errors.New("worker_scope_capabilities_failed")
	}
	raw, e := os.ReadFile("/proc/thread-self/status")
	if e != nil {
		return errors.New("worker_scope_capabilities_failed")
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		p := strings.Fields(line)
		if len(p) == 2 {
			fields[strings.TrimSuffix(p[0], ":")] = p[1]
		}
	}
	for _, k := range []string{"CapAmb", "CapBnd", "CapEff", "CapInh", "CapPrm"} {
		v, e := strconv.ParseUint(fields[k], 16, 64)
		if e != nil || v != 0 {
			return errors.New("worker_scope_capabilities_failed")
		}
	}
	if fields["NoNewPrivs"] != "1" {
		return errors.New("worker_scope_capabilities_failed")
	}
	return nil
}
func checkTmpfs(path string) error {
	d, e := directory(path, false)
	if e != nil {
		return e
	}
	defer d.Close()
	var s syscall.Statfs_t
	if syscall.Fstatfs(int(d.Fd()), &s) != nil || s.Type != 0x01021994 || s.Bsize <= 0 || uint64(s.Bsize) > uint64(stageBytes) || s.Blocks != uint64(stageBytes)/uint64(s.Bsize) || s.Files != stageInodes || uint64(s.Flags)&14 != 14 || uint64(s.Flags)&1 != 0 {
		return errors.New("worker_scope_tmpfs_invalid")
	}
	return nil
}

// An inherited directory FD retains its parent's mount object. Reopen only
// inside the new namespace, then compare inode and metadata before mounting.
func reopenMountTarget(path string, anchor *os.File) (*os.File, error) {
	reopened, err := directory(path, false)
	if err != nil {
		return nil, err
	}
	var a, b syscall.Stat_t
	if anchor == nil || syscall.Fstat(int(anchor.Fd()), &a) != nil || syscall.Fstat(int(reopened.Fd()), &b) != nil || a.Dev != b.Dev || a.Ino != b.Ino || a.Mode != b.Mode || a.Uid != b.Uid || a.Gid != b.Gid || a.Nlink != b.Nlink || a.Mtim != b.Mtim || a.Ctim != b.Ctim {
		reopened.Close()
		return nil, errors.New("worker_scope_directory_changed")
	}
	names, e := os.ReadDir("/proc/self/fd/" + strconv.Itoa(int(reopened.Fd())))
	if e != nil || len(names) != 0 {
		reopened.Close()
		return nil, errors.New("worker_scope_directory_not_empty")
	}
	return reopened, nil
}

func child(stdin io.Reader) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	raw, e := io.ReadAll(io.LimitReader(stdin, 65537))
	if e != nil || len(raw) > 65536 {
		return errors.New("worker_scope_config_invalid")
	}
	var spec launchSpec
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&spec) != nil {
		return errors.New("worker_scope_config_invalid")
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return errors.New("worker_scope_config_invalid")
	}
	if spec.SchemaVersion != 1 || !safePath(spec.Worker) || !safePath(spec.Tmpfs) || !validSHA(spec.SHA256) || checkMappings() != nil {
		return errors.New("worker_scope_config_invalid")
	}
	current, e := namespaces()
	if e != nil || len(spec.ParentNamespaces) != 3 {
		return errors.New("worker_scope_namespace_invalid")
	}
	for k, v := range current {
		if spec.ParentNamespaces[k] == "" || spec.ParentNamespaces[k] == v {
			return errors.New("worker_scope_namespace_invalid")
		}
	}
	// Only the trusted parent supplies descriptors. Never choose a path to reopen
	// the executable: validate and execute its already-pinned read-only descriptor.
	binary := os.NewFile(3, "worker-scope-executable")
	target := os.NewFile(4, "worker-scope-mount-target")
	defer binary.Close()
	defer target.Close()
	syscall.CloseOnExec(3)
	syscall.CloseOnExec(4)
	if verifyWorker(context.Background(), binary, spec.SHA256) != nil {
		return errors.New("worker_scope_binary_invalid")
	}
	var st syscall.Stat_t
	if syscall.Fstat(4, &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFDIR || st.Mode&07777 != 0700 || st.Uid != 0 {
		return errors.New("worker_scope_directory_unsafe")
	}
	list, e := os.ReadDir("/proc/self/fd/4")
	if e != nil || len(list) != 0 {
		return errors.New("worker_scope_directory_not_empty")
	}
	if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		return mountDiagnostic("propagation", err)
	}
	mountTarget, e := reopenMountTarget(spec.Tmpfs, target)
	if e != nil {
		return e
	}
	defer mountTarget.Close()
	syscall.CloseOnExec(int(mountTarget.Fd()))
	mountPath := "/proc/self/fd/" + strconv.Itoa(int(mountTarget.Fd()))
	if err := syscall.Mount("worker-private-plaintext", mountPath, "tmpfs", syscall.MS_NOEXEC|syscall.MS_NOSUID|syscall.MS_NODEV, "size=33554432,nr_inodes=4096,mode=0700"); err != nil {
		return mountDiagnostic("tmpfs", err)
	}
	// Reopen through the canonical operator path after mounting. The old target FD
	// still identifies the covered directory and cannot prove the mounted tmpfs.
	if checkTmpfs(spec.Tmpfs) != nil {
		return errors.New("worker_scope_tmpfs_invalid")
	}
	interfaces, e := net.Interfaces()
	if e != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" || interfaces[0].Flags&net.FlagUp != 0 {
		return errors.New("worker_scope_network_invalid")
	}
	if dropCapabilities() != nil {
		return errors.New("worker_scope_capabilities_failed")
	}
	env, e := fixedEnvironment(spec.Environment, spec.Tmpfs)
	if e != nil {
		return e
	}
	// fixedEnvironment ignores foreign keys; the internal envelope must not carry
	// any such keys, duplicate its fixed entries, or smuggle a second selector.
	if len(env) != len(spec.Environment) {
		return errors.New("worker_scope_environment_invalid")
	}
	for i := range env {
		if env[i] != spec.Environment[i] {
			return errors.New("worker_scope_environment_invalid")
		}
	}
	if verifyWorker(context.Background(), binary, spec.SHA256) != nil {
		return errors.New("worker_scope_binary_changed")
	}
	return syscall.Exec("/proc/self/fd/3", []string{spec.Worker}, env)
}
func launch(ctx context.Context, spec launchSpec, binary, target *os.File, stdout, stderr io.Writer) int {
	raw, e := json.Marshal(spec)
	if e != nil || len(raw) > 65536 {
		fmt.Fprintln(stderr, "worker_scope_config_invalid")
		return 1
	}
	command := exec.Command("/proc/self/exe", internalArgument)
	command.Stdin = bytes.NewReader(raw)
	command.Stdout, command.Stderr = stdout, stderr
	command.Env = []string{"LANG=C", "LC_ALL=C"}
	command.ExtraFiles = []*os.File{binary, target}
	command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWNET, UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: 1000, Size: 1}}, GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: 1000, Size: 1}}, GidMappingsEnableSetgroups: false, Credential: &syscall.Credential{Uid: 0, Gid: 0, NoSetGroups: true}, Pdeathsig: syscall.SIGKILL}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if command.Start() != nil {
		fmt.Fprintln(stderr, "worker_scope_start_failed")
		return 1
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case <-done:
	case <-ctx.Done():
		command.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			command.Process.Kill()
			<-done
		}
	}
	if command.ProcessState == nil {
		fmt.Fprintln(stderr, "worker_scope_wait_unproven")
		return 1
	}
	status, ok := command.ProcessState.Sys().(syscall.WaitStatus)
	if !ok || !status.Exited() && !status.Signaled() {
		fmt.Fprintln(stderr, "worker_scope_wait_unproven")
		return 1
	}
	if status.Signaled() {
		return 128 + int(status.Signal())
	}
	return status.ExitStatus()
}
func run(ctx context.Context, args []string, environ []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("worker-scope", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("worker", "", "pinned protected worker executable")
	pin := flags.String("worker-sha256", "", "worker SHA256")
	tmpfs := flags.String("tmpfs", "", "existing empty private staging directory")
	if flags.Parse(args) != nil || flags.NArg() != 0 || !safePath(*path) || !validSHA(*pin) || !safePath(*tmpfs) || ctx == nil || ctx.Err() != nil {
		fmt.Fprintln(stderr, "worker_scope_arguments_invalid")
		return 2
	}
	if os.Getuid() != 1000 || os.Geteuid() != 1000 || os.Getgid() != 1000 || os.Getegid() != 1000 {
		fmt.Fprintln(stderr, "worker_scope_identity_invalid")
		return 1
	}
	binary, e := openWorker(ctx, *path, *pin)
	if e != nil {
		fmt.Fprintln(stderr, "worker_scope_binary_invalid")
		return 1
	}
	defer binary.Close()
	target, e := directory(*tmpfs, true)
	if e != nil {
		fmt.Fprintln(stderr, "worker_scope_directory_invalid")
		return 1
	}
	defer target.Close()
	list, e := os.ReadDir("/proc/self/fd/" + strconv.Itoa(int(target.Fd())))
	if e != nil || len(list) != 0 {
		fmt.Fprintln(stderr, "worker_scope_directory_not_empty")
		return 1
	}
	env, e := fixedEnvironment(environ, *tmpfs)
	if e != nil {
		fmt.Fprintln(stderr, "worker_scope_environment_invalid")
		return 1
	}
	ns, e := namespaces()
	if e != nil {
		fmt.Fprintln(stderr, "worker_scope_namespace_invalid")
		return 1
	}
	return launch(ctx, launchSpec{1, *path, *pin, *tmpfs, ns, env}, binary, target, stdout, stderr)
}

// Only a fixed mount site and four known errno names may cross the log sink.
func mountDiagnostic(site string, err error) error {
	var base string
	switch site {
	case "propagation":
		base = "worker_scope_private_propagation_failed"
	case "tmpfs":
		base = "worker_scope_tmpfs_mount_failed"
	default:
		return errors.New("worker_scope_child_failed")
	}
	switch err {
	case syscall.EPERM:
		return errors.New(base + "_eperm")
	case syscall.EACCES:
		return errors.New(base + "_eacces")
	case syscall.EINVAL:
		return errors.New(base + "_einval")
	case syscall.ENOENT:
		return errors.New(base + "_enoent")
	default:
		return errors.New(base)
	}
}

// childDiagnostic prints only exact internal codes. Never log syscall.Exec
// errors, paths, wrapped errors or arbitrary text, even with a matching prefix.
func childDiagnostic(err error) string {
	if err == nil {
		return "worker_scope_child_failed"
	}
	code := err.Error()
	switch code {
	case "worker_scope_private_propagation_failed", "worker_scope_private_propagation_failed_eperm", "worker_scope_private_propagation_failed_eacces", "worker_scope_private_propagation_failed_einval", "worker_scope_private_propagation_failed_enoent",
		"worker_scope_tmpfs_mount_failed", "worker_scope_tmpfs_mount_failed_eperm", "worker_scope_tmpfs_mount_failed_eacces", "worker_scope_tmpfs_mount_failed_einval", "worker_scope_tmpfs_mount_failed_enoent",
		"worker_scope_backend_invalid", "worker_scope_binary_changed", "worker_scope_binary_invalid", "worker_scope_binary_unsafe",
		"worker_scope_cancelled", "worker_scope_capabilities_failed", "worker_scope_config_invalid",
		"worker_scope_directory_changed", "worker_scope_directory_create_failed", "worker_scope_directory_invalid", "worker_scope_directory_not_empty",
		"worker_scope_directory_sync_failed", "worker_scope_directory_unsafe", "worker_scope_environment_invalid",
		"worker_scope_mapping_invalid", "worker_scope_mount_failed", "worker_scope_namespace_invalid",
		"worker_scope_namespace_required", "worker_scope_namespace_unavailable", "worker_scope_network_invalid",
		"worker_scope_timeout_invalid", "worker_scope_tmpfs_invalid":
		return code
	default:
		return "worker_scope_child_failed"
	}
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == internalArgument {
		if err := child(os.Stdin); err != nil {
			fmt.Fprintln(os.Stderr, childDiagnostic(err))
			os.Exit(1)
		}
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Environ(), os.Stdout, os.Stderr))
}
