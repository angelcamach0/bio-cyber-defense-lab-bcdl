// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
)

func admissionError(code string) error { return errors.New(code) }

func directoryPath(dir *os.File) string {
	return "/proc/self/fd/" + strconv.FormatUint(uint64(dir.Fd()), 10)
}

func secureDirectory(path string, create, private bool) (*os.File, error) {
	return secureDirectoryWithSync(path, create, private, syscall.Fsync)
}

func secureDirectoryWithSync(path string, create, private bool, syncParent func(int) error) (*os.File, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, admissionError("admission_path_invalid")
	}
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, admissionError("admission_directory_unavailable")
	}
	for _, part := range strings.Split(strings.TrimPrefix(absolute, "/"), "/") {
		if part == "" {
			continue
		}
		next, openErr := syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
		if openErr == syscall.ENOENT && create {
			if err := syscall.Mkdirat(fd, part, 0700); err != nil && err != syscall.EEXIST {
				syscall.Close(fd)
				return nil, admissionError("admission_directory_create_failed")
			}
			next, openErr = syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
		}
		if openErr != nil {
			syscall.Close(fd)
			return nil, admissionError("admission_directory_unsafe")
		}
		// Existing components also need a retryable durability barrier: an
		// earlier mkdir may have succeeded while its parent fsync failed.
		if syncParent(fd) != nil {
			syscall.Close(next)
			syscall.Close(fd)
			return nil, admissionError("admission_directory_sync_failed")
		}
		syscall.Close(fd)
		fd = next
	}
	dir := os.NewFile(uintptr(fd), "admission-directory")
	info, err := dir.Stat()
	stat, ok := infoSysStat(info)
	if err != nil || !ok || !info.IsDir() || stat.Uid != uint32(os.Geteuid()) || (private && stat.Mode&07777 != 0700) {
		dir.Close()
		return nil, admissionError("admission_directory_permissions_invalid")
	}
	return dir, nil
}

func infoSysStat(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return stat, ok
}

func secureChildDirectory(parent *os.File, name string, create bool) (*os.File, error) {
	return secureChildDirectoryWithSync(parent, name, create, syscall.Fsync)
}

func secureChildDirectoryWithSync(parent *os.File, name string, create bool, syncParent func(int) error) (*os.File, error) {
	if !safeBase(name) {
		return nil, admissionError("admission_filename_invalid")
	}
	fd, err := syscall.Openat(int(parent.Fd()), name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err == syscall.ENOENT && create {
		if err := syscall.Mkdirat(int(parent.Fd()), name, 0700); err != nil {
			return nil, admissionError("admission_directory_create_failed")
		}
		fd, err = syscall.Openat(int(parent.Fd()), name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	}
	if err == syscall.ENOENT {
		return nil, os.ErrNotExist
	}
	if err != nil {
		return nil, admissionError("admission_directory_unsafe")
	}
	if syncParent(int(parent.Fd())) != nil {
		syscall.Close(fd)
		return nil, admissionError("admission_directory_sync_failed")
	}
	dir := os.NewFile(uintptr(fd), "admission-directory")
	info, err := dir.Stat()
	stat, ok := infoSysStat(info)
	if err != nil || !ok || !info.IsDir() || stat.Mode&07777 != 0700 || stat.Uid != uint32(os.Geteuid()) {
		dir.Close()
		return nil, admissionError("admission_directory_permissions_invalid")
	}
	return dir, nil
}

func safeBase(name string) bool {
	return name != "" && name != "." && name != ".." && filepath.Base(name) == name && !strings.ContainsRune(name, 0)
}

func secureRead(dir *os.File, name string, maximum int64) ([]byte, error) {
	if !safeBase(name) {
		return nil, admissionError("admission_filename_invalid")
	}
	fd, err := syscall.Openat(int(dir.Fd()), name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err == syscall.ENOENT {
		return nil, os.ErrNotExist
	}
	if err != nil {
		return nil, admissionError("admission_file_unsafe")
	}
	file := os.NewFile(uintptr(fd), "admission-file")
	defer file.Close()
	info, err := file.Stat()
	stat, ok := infoSysStat(info)
	if err != nil || !ok || !info.Mode().IsRegular() || stat.Uid != uint32(os.Geteuid()) || stat.Mode&07777 != 0600 || info.Size() < 0 || info.Size() > maximum {
		return nil, admissionError("admission_file_unsafe")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) > maximum {
		return nil, admissionError("admission_file_read_failed")
	}
	return data, nil
}

func exclusiveFile(dir *os.File, name string) (*os.File, error) {
	if !safeBase(name) {
		return nil, admissionError("admission_filename_invalid")
	}
	fd, err := syscall.Openat(int(dir.Fd()), name, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, admissionError("admission_exclusive_create_failed")
	}
	return os.NewFile(uintptr(fd), "admission-file"), nil
}

func atomicLedgerWrite(dir *os.File, data []byte) error {
	file, err := os.CreateTemp(directoryPath(dir), ".ledger-*.tmp")
	if err != nil {
		return admissionError("admission_ledger_write_failed")
	}
	name := file.Name()
	defer os.Remove(name)
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write(data)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return admissionError("admission_ledger_write_failed")
	}
	if os.Rename(name, filepath.Join(directoryPath(dir), "ledger.json")) != nil {
		return admissionError("admission_ledger_publish_failed")
	}
	if dir.Sync() != nil {
		return admissionError("admission_ledger_sync_failed")
	}
	return nil
}

func strictAdmissionJSON(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	typeOf := reflect.TypeOf(value)
	if typeOf == nil || typeOf.Kind() != reflect.Pointer {
		return admissionError("admission_json_invalid")
	}
	if err := scanAdmissionJSON(decoder, 0, typeOf.Elem()); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return admissionError("admission_json_trailing")
	}
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil {
		return admissionError("admission_json_invalid")
	}
	return nil
}

func scanAdmissionJSON(decoder *json.Decoder, depth int, recordType reflect.Type) error {
	token, err := decoder.Token()
	if err != nil {
		return admissionError("admission_json_invalid")
	}
	if token == nil && recordType != nil {
		return admissionError("admission_json_null")
	}
	structured := recordType != nil && recordType.Kind() == reflect.Struct
	if structured && token != json.Delim('{') {
		return admissionError("admission_json_type_invalid")
	}
	delim, container := token.(json.Delim)
	if !container {
		return nil
	}
	if depth >= 64 {
		return admissionError("admission_json_depth_exceeded")
	}
	seen := map[string]bool{}
	fields := map[string]reflect.Type{}
	if structured {
		for i := 0; i < recordType.NumField(); i++ {
			field := recordType.Field(i)
			fields[strings.Split(field.Tag.Get("json"), ",")[0]] = field.Type
		}
	}
	for decoder.More() {
		var childType reflect.Type
		if delim == '{' {
			token, err := decoder.Token()
			key, ok := token.(string)
			if err != nil || !ok || seen[key] {
				return admissionError("admission_json_duplicate_or_invalid")
			}
			seen[key] = true
			if structured {
				childType = fields[key]
				if childType == nil {
					return admissionError("admission_json_unknown_or_aliased")
				}
			}
			if recordType != nil && recordType.Kind() == reflect.Map {
				childType = recordType.Elem()
			}
		} else if recordType != nil && recordType.Kind() == reflect.Slice {
			childType = recordType.Elem()
		}
		if err := scanAdmissionJSON(decoder, depth+1, childType); err != nil {
			return err
		}
	}
	if _, err := decoder.Token(); err != nil {
		return admissionError("admission_json_invalid")
	}
	if structured {
		for name := range fields {
			if !seen[name] {
				return admissionError("admission_json_required_missing")
			}
		}
	}
	return nil
}
