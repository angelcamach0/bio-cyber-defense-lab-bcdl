//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func scopeBinaryFixture(t *testing.T) (string, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "worker")
	raw := []byte("synthetic executable fixture; never executed\n")
	if e := os.WriteFile(p, raw, 0700); e != nil {
		t.Fatal(e)
	}
	h := sha256.Sum256(raw)
	return p, hex.EncodeToString(h[:])
}
func TestWorkerScopeEnvironmentHasOnlyIntendedWorkerFields(t *testing.T) {
	env, e := fixedEnvironment([]string{"PATH=/untrusted/bin", "LD_PRELOAD=/private/no.so", "AWS_SECRET_ACCESS_KEY=synthetic-secret", "HTTPS_PROXY=https://private.invalid", "BIOZERO_JOB_KEY=synthetic-worker-key", "BIOZERO_ARTIFACT_SOCKET=/private/broker.sock", "BIOZERO_WORKER_CUSTODY_DIR=/private/custody", "BIOZERO_ARTIFACT_PROJECTION_POLICY=strict", "BIOZERO_DECRYPT_DIR=/wrong", "BIOZERO_EXECUTION_BACKEND=capsule", "BIOZERO_PIPELINE_TIMEOUT=120s"}, "/private/tmpfs")
	if e != nil {
		t.Fatal(e)
	}
	got := strings.Join(env, "\n")
	for _, foreign := range []string{"PATH=", "LD_PRELOAD=", "AWS_SECRET", "HTTPS_PROXY=", "/wrong"} {
		if strings.Contains(got, foreign) {
			t.Fatal("foreign runtime selector inherited")
		}
	}
	for _, wanted := range []string{"LANG=C", "LC_ALL=C", "BIOZERO_DECRYPT_DIR=/private/tmpfs", "BIOZERO_JOB_KEY=synthetic-worker-key", "BIOZERO_ARTIFACT_SOCKET=/private/broker.sock", "BIOZERO_WORKER_CUSTODY_DIR=/private/custody", "BIOZERO_ARTIFACT_PROJECTION_POLICY=strict", "BIOZERO_EXECUTION_BACKEND=capsule", "BIOZERO_PIPELINE_TIMEOUT=120s"} {
		if !strings.Contains(got, wanted) {
			t.Fatal("intended worker field dropped")
		}
	}
	for _, bad := range [][]string{{"BIOZERO_JOB_KEY=a", "BIOZERO_JOB_KEY=b"}, {"BIOZERO_JOB_KEY=a\x00b"}, {"not-an-assignment"}, {"BIOZERO_PIPELINE_TIMEOUT=not-a-duration"}, {"BIOZERO_PIPELINE_TIMEOUT=0s"}, {"BIOZERO_PIPELINE_TIMEOUT=11m"}, {"BIOZERO_EXECUTION_BACKEND=legacy"}} {
		if _, e := fixedEnvironment(bad, "/private/tmpfs"); e == nil {
			t.Fatal("ambiguous environment accepted")
		}
	}
}
func TestWorkerScopeOwnerProtocolPairIsExplicitAndBounded(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []string
	}{
		{"historical_without_selector", []string{"BIOZERO_EXECUTION_BACKEND=capsule", "BIOZERO_JOB_KEY=synthetic-worker-key"}},
		{"explicit_legacy", []string{"BIOZERO_WORKER_PROTOCOL=legacy", "BIOZERO_EXECUTION_BACKEND=capsule"}},
		{"owner_pair", []string{"BIOZERO_WORKER_PROTOCOL=owner-v1", "BIOZERO_OWNER_WORKER_CONFIG=/private/owner-worker.json"}},
		{"owner_pair_reverse_order", []string{"BIOZERO_OWNER_WORKER_CONFIG=/private/owner-worker.json", "BIOZERO_WORKER_PROTOCOL=owner-v1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, e := fixedEnvironment(tc.in, "/private/tmpfs")
			if e != nil {
				t.Fatal("valid explicit selection rejected", e)
			}
			for _, pair := range tc.in {
				found := 0
				for _, got := range env {
					if got == pair {
						found++
					}
				}
				if found != 1 {
					t.Fatal("intended selection dropped or duplicated")
				}
			}
			if !strings.Contains(strings.Join(env, "\n"), "BIOZERO_DECRYPT_DIR=/private/tmpfs") {
				t.Fatal("launcher tmpfs authority lost")
			}
		})
	}
	for name, in := range map[string][]string{
		"owner_without_config":     {"BIOZERO_WORKER_PROTOCOL=owner-v1"},
		"config_without_selector":  {"BIOZERO_OWNER_WORKER_CONFIG=/private/owner.json"},
		"legacy_with_owner_config": {"BIOZERO_WORKER_PROTOCOL=legacy", "BIOZERO_OWNER_WORKER_CONFIG=/private/owner.json"},
		"unknown_protocol":         {"BIOZERO_WORKER_PROTOCOL=auto"},
		"empty_protocol":           {"BIOZERO_WORKER_PROTOCOL="},
		"empty_config":             {"BIOZERO_WORKER_PROTOCOL=owner-v1", "BIOZERO_OWNER_WORKER_CONFIG="},
		"relative_config":          {"BIOZERO_WORKER_PROTOCOL=owner-v1", "BIOZERO_OWNER_WORKER_CONFIG=private/owner.json"},
		"unclean_config":           {"BIOZERO_WORKER_PROTOCOL=owner-v1", "BIOZERO_OWNER_WORKER_CONFIG=/private/../owner.json"},
		"root_config":              {"BIOZERO_WORKER_PROTOCOL=owner-v1", "BIOZERO_OWNER_WORKER_CONFIG=/"},
		"invalid_utf8_config":      {"BIOZERO_WORKER_PROTOCOL=owner-v1", "BIOZERO_OWNER_WORKER_CONFIG=/private/\xff"},
		"duplicate_protocol":       {"BIOZERO_WORKER_PROTOCOL=owner-v1", "BIOZERO_OWNER_WORKER_CONFIG=/private/owner.json", "BIOZERO_WORKER_PROTOCOL=owner-v1"},
		"duplicate_config":         {"BIOZERO_WORKER_PROTOCOL=owner-v1", "BIOZERO_OWNER_WORKER_CONFIG=/private/owner.json", "BIOZERO_OWNER_WORKER_CONFIG=/private/owner.json"},
		"nul_config":               {"BIOZERO_WORKER_PROTOCOL=owner-v1", "BIOZERO_OWNER_WORKER_CONFIG=/private/owner\x00.json"},
		"lf_config":                {"BIOZERO_WORKER_PROTOCOL=owner-v1", "BIOZERO_OWNER_WORKER_CONFIG=/private/owner\n.json"},
		"cr_config":                {"BIOZERO_WORKER_PROTOCOL=owner-v1", "BIOZERO_OWNER_WORKER_CONFIG=/private/owner\r.json"},
		"tab_config":               {"BIOZERO_WORKER_PROTOCOL=owner-v1", "BIOZERO_OWNER_WORKER_CONFIG=/private/owner\t.json"},
		"escape_config":            {"BIOZERO_WORKER_PROTOCOL=owner-v1", "BIOZERO_OWNER_WORKER_CONFIG=/private/owner\x1b.json"},
		"delete_config":            {"BIOZERO_WORKER_PROTOCOL=owner-v1", "BIOZERO_OWNER_WORKER_CONFIG=/private/owner\x7f.json"},
		"protocol_control":         {"BIOZERO_WORKER_PROTOCOL=owner-v1\n", "BIOZERO_OWNER_WORKER_CONFIG=/private/owner.json"},
		"historical_field_control": {"BIOZERO_JOB_KEY=synthetic\tprivate-key"},
	} {
		t.Run(name, func(t *testing.T) {
			env, e := fixedEnvironment(in, "/private/tmpfs")
			if e == nil || env != nil || strings.Contains(e.Error(), "/private") || strings.Contains(e.Error(), "synthetic") {
				t.Fatal("invalid selection accepted or private input disclosed")
			}
		})
	}
}

func TestWorkerScopePinnedDescriptorRejectsUnsafeSources(t *testing.T) {
	for _, kind := range []string{"valid", "pin_mismatch", "writable", "not_executable", "symlink", "hardlink", "fifo", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			p, pin := scopeBinaryFixture(t)
			switch kind {
			case "pin_mismatch":
				pin = strings.Repeat("0", 64)
			case "writable":
				os.Chmod(p, 0777)
			case "not_executable":
				os.Chmod(p, 0600)
			case "symlink":
				link := p + ".link"
				if e := os.Symlink(p, link); e != nil {
					t.Fatal(e)
				}
				p = link
			case "hardlink":
				if e := os.Link(p, p+".link"); e != nil {
					t.Fatal(e)
				}
			case "fifo":
				os.Remove(p)
				if e := syscall.Mkfifo(p, 0600); e != nil {
					t.Fatal(e)
				}
			case "oversize":
				if e := os.Truncate(p, workerLimit+1); e != nil {
					t.Fatal(e)
				}
			}
			f, e := openWorker(context.Background(), p, pin)
			if (e == nil) != (kind == "valid") {
				t.Fatal("incorrect pinned source gate", e)
			}
			if f != nil {
				defer f.Close()
				if _, e = f.Write([]byte("x")); e == nil {
					t.Fatal("pinned descriptor writable")
				}
			}
		})
	}
}
func TestWorkerScopeDirectoryAndCLIRejectBeforeNamespaces(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "new")
	d, e := directory(target, true)
	if e != nil {
		t.Fatal(e)
	}
	d.Close()
	if info, e := os.Stat(target); e != nil || info.Mode().Perm() != 0700 {
		t.Fatal("target not private")
	}
	link := filepath.Join(root, "link")
	if e := os.Symlink(target, link); e != nil {
		t.Fatal(e)
	}
	if d, e = directory(link, false); e == nil {
		d.Close()
		t.Fatal("symlink target accepted")
	}
	path, pin := scopeBinaryFixture(t)
	for _, args := range [][]string{{}, {"--unknown"}, {"--worker", path, "--worker-sha256", pin, "--tmpfs", "relative"}, {"--worker", path, "--worker-sha256", "bad", "--tmpfs", target}, {"--worker", path, "--worker-sha256", pin, "--tmpfs", target, "extra"}} {
		var out, errout bytes.Buffer
		code := run(context.Background(), args, []string{"BIOZERO_JOB_KEY=synthetic-private-key"}, &out, &errout)
		if code != 2 || out.Len() != 0 || strings.Contains(errout.String(), path) || strings.Contains(errout.String(), "synthetic-private-key") {
			t.Fatal("invalid CLI exposed secrets or reached execution")
		}
	}
	if checkTmpfs(target) == nil {
		t.Fatal("ordinary filesystem accepted as bounded tmpfs")
	}
}
func TestWorkerScopeInternalEnvelopeFailsBeforeMount(t *testing.T) {
	for _, raw := range []string{"", `{}`, `{"unexpected":true}`, `{} {}`, strings.Repeat("x", 65537)} {
		if e := child(strings.NewReader(raw)); e == nil {
			t.Fatal("invalid internal envelope accepted")
		}
	}
}

func TestWorkerScopeChildDiagnosticDoesNotLeakArbitraryErrors(t *testing.T) {
	for _, code := range []string{"worker_scope_mount_failed", "worker_scope_capabilities_failed", "worker_scope_config_invalid", "worker_scope_network_invalid", "worker_scope_binary_changed"} {
		if got := childDiagnostic(errors.New(code)); got != code {
			t.Fatal("stable internal diagnostic hidden")
		}
	}
	private := "/private/synthetic-secret-path"
	for _, err := range []error{nil, syscall.ENOENT, &os.PathError{Op: "exec", Path: private, Err: syscall.EACCES}, errors.New("arbitrary synthetic-secret"), errors.New("worker_scope_unknown"), errors.New("worker_scope_config_invalid\nBIOZERO_JOB_KEY=synthetic-secret"), fmt.Errorf("%s: %w", private, errors.New("worker_scope_mount_failed")), errors.New("worker_scope_mount_failed: " + private)} {
		got := childDiagnostic(err)
		if got != "worker_scope_child_failed" || strings.Contains(got, "synthetic-secret") || strings.Contains(got, "/") {
			t.Fatal("arbitrary child error escaped allowlist")
		}
	}
}

func TestWorkerScopeMountDiagnosticOnlyExposesKnownErrno(t *testing.T) {
	for _, site := range []string{"propagation", "tmpfs"} {
		base := "worker_scope_private_propagation_failed"
		if site == "tmpfs" {
			base = "worker_scope_tmpfs_mount_failed"
		}
		for _, tc := range []struct {
			err    error
			suffix string
		}{{syscall.EPERM, "_eperm"}, {syscall.EACCES, "_eacces"}, {syscall.EINVAL, "_einval"}, {syscall.ENOENT, "_enoent"}, {syscall.EIO, ""}, {&os.PathError{Op: "mount", Path: "/private/synthetic-secret", Err: syscall.EINVAL}, ""}} {
			if got := childDiagnostic(mountDiagnostic(site, tc.err)); got != base+tc.suffix || strings.Contains(got, "/") || strings.Contains(got, "synthetic-secret") {
				t.Fatal("mount diagnostic leaked unknown error or lost fixed errno")
			}
		}
	}
	if got := childDiagnostic(mountDiagnostic("/private/synthetic-secret", syscall.EINVAL)); got != "worker_scope_child_failed" {
		t.Fatal("arbitrary site exposed")
	}
}

func TestWorkerScopeMountTargetReopenRequiresSameInode(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "target")
	anchor, e := directory(path, true)
	if e != nil {
		t.Fatal(e)
	}
	defer anchor.Close()
	reopened, e := reopenMountTarget(path, anchor)
	if e != nil {
		t.Fatal(e)
	}
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, reopened.Fd(), syscall.F_GETFD, 0)
	if errno != 0 || flags&syscall.FD_CLOEXEC == 0 {
		t.Fatal("reopened target inherited across exec")
	}
	reopened.Close()
	original := path + ".original"
	if e := os.Rename(path, original); e != nil {
		t.Fatal(e)
	}
	if e := os.Mkdir(path, 0700); e != nil {
		t.Fatal(e)
	}
	if f, e := reopenMountTarget(path, anchor); e == nil {
		f.Close()
		t.Fatal("replacement inode accepted")
	}
	if e := os.Remove(path); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(original, path); e != nil {
		t.Fatal(e)
	}
	if f, e := reopenMountTarget(path, anchor); e == nil {
		f.Close()
		t.Fatal("symlink target followed")
	}
	if _, e := os.Stat(original); e != nil {
		t.Fatal("original anchor altered")
	}
	if e := os.Remove(path); e != nil {
		t.Fatal(e)
	}
	if e := os.Rename(original, path); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(path, "unknown"), []byte("retain unknown fixture"), 0600); e != nil {
		t.Fatal(e)
	}
	if f, e := reopenMountTarget(path, anchor); e == nil {
		f.Close()
		t.Fatal("nonempty target hidden by mount")
	}
}
