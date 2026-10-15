// SPDX-License-Identifier: AGPL-3.0-only
// Native acceptance inspector for a synthetic owner upload. Signature and trust
// verification belong to the calling harness; this independent stdlib program
// checks actual emitted OAEP/GCM bytes and supplied canonical signed-context AAD.
// It performs no network, storage mutation, worker execution or result release.
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"
	"syscall"
)

const bodyLimit = 25 << 20

func privateRead(path string, limit int64) ([]byte, error) {
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "private-acceptance-input")
	defer f.Close()
	var before, after syscall.Stat_t
	if syscall.Fstat(fd, &before) != nil || before.Mode&syscall.S_IFMT != syscall.S_IFREG || before.Mode&07777 != 0600 || before.Uid != uint32(os.Geteuid()) || before.Nlink != 1 || before.Size < 0 || before.Size > limit {
		return nil, io.ErrUnexpectedEOF
	}
	raw, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil || int64(len(raw)) != before.Size {
		return nil, io.ErrUnexpectedEOF
	}
	if syscall.Fstat(fd, &after) != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Mode != after.Mode || before.Uid != after.Uid || before.Nlink != after.Nlink || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		return nil, io.ErrUnexpectedEOF
	}
	return raw, nil
}

func inspect() bool {
	flags := flag.NewFlagSet("owner-upload-inspector", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	keyPath := flags.String("key", "", "private synthetic RSA key")
	bodyPath := flags.String("ciphertext", "", "measured encrypted payload")
	envelopePath := flags.String("envelope", "", "decoded OAEP envelope")
	plainPath := flags.String("plaintext", "", "original synthetic fixture")
	aadPath := flags.String("aad", "", "canonical externally verified signed context")
	if flags.Parse(os.Args[1:]) != nil || flags.NArg() != 0 {
		return false
	}
	keyPEM, e := privateRead(*keyPath, 32<<10)
	if e != nil {
		return false
	}
	defer clear(keyPEM)
	block, rest := pem.Decode(keyPEM)
	if block == nil || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return false
	}
	defer clear(block.Bytes)
	var key *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, e = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		var parsed any
		parsed, e = x509.ParsePKCS8PrivateKey(block.Bytes)
		if e == nil {
			key, _ = parsed.(*rsa.PrivateKey)
		}
	default:
		return false
	}
	if e != nil || key == nil || key.N == nil || key.N.BitLen() < 2048 || key.N.BitLen() > 4096 || key.E != 65537 || key.Validate() != nil {
		return false
	}
	envelope, e := privateRead(*envelopePath, 512)
	if e != nil || len(envelope) != key.Size() {
		return false
	}
	material, e := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, envelope, nil)
	if e != nil || len(material) != 44 {
		clear(material)
		return false
	}
	defer clear(material)
	body, e := privateRead(*bodyPath, bodyLimit)
	if e != nil || len(body) < 16 {
		return false
	}
	expected, e := privateRead(*plainPath, bodyLimit-16)
	if e != nil {
		return false
	}
	defer clear(expected)
	aad, e := privateRead(*aadPath, 4096)
	if e != nil || len(aad) == 0 {
		return false
	}
	aesBlock, e := aes.NewCipher(material[:32])
	if e != nil {
		return false
	}
	gcm, e := cipher.NewGCM(aesBlock)
	if e != nil {
		return false
	}
	plain, e := gcm.Open(nil, material[32:], body, aad)
	if e != nil {
		return false
	}
	defer clear(plain)
	if !bytes.Equal(plain, expected) {
		return false
	}
	changed := append([]byte(nil), aad...)
	changed[0] ^= 1
	unexpected, e := gcm.Open(nil, material[32:], body, changed)
	clear(unexpected)
	return e != nil
}

func main() {
	if !inspect() {
		fmt.Fprintln(os.Stderr, "owner_upload_payload_verification_failed")
		os.Exit(1)
	}
	fmt.Println(`{"plaintext_matches":true,"changed_aad_rejected":true}`)
}
