//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package ownership

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func storeRoot(path string, create bool) (*os.File, error) {
	abs, err := filepath.Abs(path)
	if err != nil || abs == "/" {
		return nil, fail("ownership_directory_unsafe")
	}
	parts := strings.Split(strings.TrimPrefix(abs, "/"), "/")
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fail("ownership_directory_unsafe")
	}
	for i, name := range parts {
		last := i == len(parts)-1
		if create && last {
			if err = syscall.Mkdirat(fd, name, 0700); err != nil {
				syscall.Close(fd)
				return nil, fail("ownership_directory_not_new")
			}
			if err = syscall.Fsync(fd); err != nil {
				syscall.Close(fd)
				return nil, fail("ownership_directory_sync_failed")
			}
		}
		next, e := syscall.Openat(fd, name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
		syscall.Close(fd)
		if e != nil {
			return nil, fail("ownership_directory_unsafe")
		}
		fd = next
	}
	f := os.NewFile(uintptr(fd), "ownership-store")
	info, err := f.Stat()
	st, ok := storeStat(info)
	if err != nil || !ok || !info.IsDir() || st.Uid != uint32(os.Geteuid()) || st.Mode&07777 != 0700 {
		f.Close()
		return nil, fail("ownership_directory_unsafe")
	}
	return f, nil
}

func storeStat(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return st, ok
}
func storeSafeFile(f *os.File) (os.FileInfo, error) {
	info, err := f.Stat()
	st, ok := storeStat(info)
	if err != nil || !ok || !info.Mode().IsRegular() || st.Uid != uint32(os.Geteuid()) || st.Mode&07777 != 0600 || st.Nlink != 1 {
		return nil, fail("ownership_file_unsafe")
	}
	return info, nil
}
func storeFile(root *os.File, name string, create bool) (*os.File, error) {
	flags := syscall.O_RDONLY | syscall.O_NONBLOCK | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
	if create {
		flags = syscall.O_RDWR | syscall.O_CREAT | syscall.O_EXCL | syscall.O_NONBLOCK | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
	}
	fd, err := syscall.Openat(int(root.Fd()), name, flags, 0600)
	if err != nil {
		if err == syscall.ENOENT {
			return nil, os.ErrNotExist
		}
		return nil, fail("ownership_file_unsafe")
	}
	f := os.NewFile(uintptr(fd), "ownership-file")
	if _, err = storeSafeFile(f); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}
func storeInfoEqual(a, b os.FileInfo) bool {
	x, ok := storeStat(a)
	y, ok2 := storeStat(b)
	return ok && ok2 && x.Dev == y.Dev && x.Ino == y.Ino && x.Uid == y.Uid && x.Mode == y.Mode && x.Nlink == y.Nlink && x.Size == y.Size && x.Mtim == y.Mtim && x.Ctim == y.Ctim
}
func storeRead(root *os.File, name string, limit int64) ([]byte, error) {
	f, err := storeFile(root, name, false)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	before, err := storeSafeFile(f)
	if err != nil {
		return nil, err
	}
	if before.Size() < 0 || before.Size() > limit {
		return nil, fail("ownership_file_oversized")
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, fail("ownership_file_read_failed")
	}
	after, err := storeSafeFile(f)
	if err != nil || !storeInfoEqual(before, after) || int64(len(raw)) != before.Size() {
		return nil, fail("ownership_file_changed")
	}
	return raw, nil
}
func storeNames(root *os.File) ([]string, error) {
	fd, err := syscall.Openat(int(root.Fd()), ".", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fail("ownership_scan_failed")
	}
	f := os.NewFile(uintptr(fd), "ownership-scan")
	defer f.Close()
	entries, err := f.ReadDir(5)
	if err != nil && err != io.EOF {
		return nil, fail("ownership_scan_failed")
	}
	if len(entries) > 4 {
		return nil, fail("ownership_history_unknown")
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names, nil
}
func storeAvailable(root *os.File) (uint64, error) {
	var st syscall.Statfs_t
	if syscall.Fstatfs(int(root.Fd()), &st) != nil || st.Bsize <= 0 || st.Bavail > ^uint64(0)/uint64(st.Bsize) {
		return 0, fail("ownership_capacity_unavailable")
	}
	return st.Bavail * uint64(st.Bsize), nil
}
