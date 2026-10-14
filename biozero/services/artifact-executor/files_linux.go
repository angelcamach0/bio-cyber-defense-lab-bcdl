//go:build linux

package artifactexecutor

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// All managed names are internal constants or validated opaque IDs. Ancestors
// are traversed by descriptor; no Lstat followed by a pathname open is used.
func openRoot(path string) (*os.File, error) {
	abs, e := filepath.Abs(path)
	if e != nil {
		return nil, fail("artifact_directory_unsafe")
	}
	fd, e := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, fail("artifact_directory_unsafe")
	}
	for _, name := range strings.Split(strings.TrimPrefix(abs, "/"), "/") {
		if name == "" {
			continue
		}
		n, e := syscall.Openat(fd, name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
		if e == syscall.ENOENT {
			if e = syscall.Mkdirat(fd, name, 0700); e != nil && e != syscall.EEXIST {
				syscall.Close(fd)
				return nil, fail("artifact_directory_unsafe")
			}
			n, e = syscall.Openat(fd, name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
		}
		if e != nil {
			syscall.Close(fd)
			return nil, fail("artifact_directory_unsafe")
		}
		if syscall.Fsync(fd) != nil {
			syscall.Close(n)
			syscall.Close(fd)
			return nil, fail("artifact_directory_sync_failed")
		}
		syscall.Close(fd)
		fd = n
	}
	f := os.NewFile(uintptr(fd), "artifact-directory")
	if !safeInfo(f, true) {
		f.Close()
		return nil, fail("artifact_directory_unsafe")
	}
	return f, nil
}
func safeInfo(f *os.File, dir bool) bool {
	info, e := f.Stat()
	if e != nil {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) {
		return false
	}
	if dir {
		return info.IsDir() && st.Mode&07777 == 0700
	}
	return info.Mode().IsRegular() && st.Mode&07777 == 0600 && st.Nlink == 1
}
func childDir(parent *os.File, name string, create bool) (*os.File, error) {
	flags := syscall.O_RDONLY | syscall.O_DIRECTORY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK | syscall.O_CLOEXEC
	fd, e := syscall.Openat(int(parent.Fd()), name, flags, 0)
	if e == syscall.ENOENT && create {
		if e = syscall.Mkdirat(int(parent.Fd()), name, 0700); e != nil {
			return nil, fail("artifact_directory_unsafe")
		}
		fd, e = syscall.Openat(int(parent.Fd()), name, flags, 0)
	}
	if e == syscall.ENOENT {
		return nil, os.ErrNotExist
	}
	if e != nil {
		return nil, fail("artifact_directory_unsafe")
	}
	f := os.NewFile(uintptr(fd), "artifact-directory")
	if !safeInfo(f, true) {
		f.Close()
		return nil, fail("artifact_directory_unsafe")
	}
	if syscall.Fsync(int(parent.Fd())) != nil {
		f.Close()
		return nil, fail("artifact_directory_sync_failed")
	}
	return f, nil
}
func regular(parent *os.File, name string, create bool) (*os.File, error) {
	flags := syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK | syscall.O_CLOEXEC
	if create {
		flags = syscall.O_RDWR | syscall.O_CREAT | syscall.O_EXCL | syscall.O_NOFOLLOW | syscall.O_NONBLOCK | syscall.O_CLOEXEC
	}
	fd, e := syscall.Openat(int(parent.Fd()), name, flags, 0600)
	if e == syscall.ENOENT {
		return nil, os.ErrNotExist
	}
	if e != nil {
		return nil, fail("artifact_file_unsafe")
	}
	f := os.NewFile(uintptr(fd), "artifact-file")
	if !safeInfo(f, false) {
		f.Close()
		return nil, fail("artifact_file_unsafe")
	}
	return f, nil
}
func boundedRead(ctx context.Context, dir *os.File, name string, limit int64) ([]byte, error) {
	f, e := regular(dir, name, false)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || st.Size() > limit {
		return nil, fail("artifact_file_oversized")
	}
	out := make([]byte, 0, int(st.Size()))
	buf := make([]byte, 65536)
	for {
		if ctx.Err() != nil {
			return nil, fail("artifact_cancelled")
		}
		n, e := f.Read(buf)
		out = append(out, buf[:n]...)
		if int64(len(out)) > limit {
			return nil, fail("artifact_file_oversized")
		}
		if e == io.EOF {
			return out, nil
		}
		if e != nil {
			return nil, fail("artifact_read_failed")
		}
	}
}
func entries(dir *os.File) ([]os.DirEntry, error) {
	// A fresh descriptor avoids sharing/retaining a directory iteration offset.
	fd, e := syscall.Openat(int(dir.Fd()), ".", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, fail("artifact_scan_failed")
	}
	f := os.NewFile(uintptr(fd), "artifact-scan")
	defer f.Close()
	list, err := f.ReadDir(129)
	if len(list) > 128 {
		return nil, fail("artifact_directory_oversized")
	}
	if err == io.EOF {
		err = nil
	}
	return list, err
}
func absent(e error) bool { return errors.Is(e, os.ErrNotExist) }
