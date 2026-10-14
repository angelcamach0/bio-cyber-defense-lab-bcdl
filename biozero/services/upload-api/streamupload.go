// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
)

type streamedUpload struct {
	Fields   url.Values
	Filename string
	Size     int64
	SHA256   string
}

// Transport TLS is verified before any multipart parsing. The form assertion
// is compared later by uploadIdentity; it never supplies the quota principal.
func requestPrincipal(r *http.Request) (string, string, error) {
	if r.TLS != nil {
		if len(r.TLS.PeerCertificates) == 0 || len(r.TLS.VerifiedChains) == 0 || r.TLS.PeerCertificates[0] == nil || len(r.TLS.VerifiedChains[0]) == 0 {
			return "", "", admissionError("identity_invalid")
		}
		cert := r.TLS.PeerCertificates[0]
		if !isValidClientID(cert.Subject.CommonName) || cert.SerialNumber == nil {
			return "", "", admissionError("identity_invalid")
		}
		return cert.Subject.CommonName, cert.SerialNumber.String(), nil
	}
	if envOr("BIOZERO_SECURITY_MODE", "protected") == "demo" {
		return "demo-global", "", nil
	}
	return "", "", admissionError("identity_invalid")
}

func multipartReadError(err error) error {
	var capError *http.MaxBytesError
	if errors.As(err, &capError) {
		return admissionError("payload_too_large")
	}
	return admissionError("invalid_form")
}

func streamMultipart(ctx context.Context, r *http.Request, store *admissionStore, entry admissionEntry) (streamedUpload, error) {
	result := streamedUpload{Fields: url.Values{}}
	reader, err := r.MultipartReader()
	if err != nil {
		return result, admissionError("invalid_form")
	}
	seen := map[string]bool{}
	var fieldBytes int64
	for parts := 0; ; parts++ {
		if err := ctx.Err(); err != nil {
			return result, admissionError("upload_cancelled")
		}
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return result, multipartReadError(err)
		}
		if parts >= 7 {
			return result, admissionError("invalid_form")
		}
		name := part.FormName()
		if seen[name] {
			return result, admissionError("invalid_form")
		}
		seen[name] = true
		if name == "file" {
			if part.FileName() == "" {
				return result, admissionError("missing_file")
			}
			result.Filename = part.FileName()
			file, err := store.beginPayload(entry)
			if err != nil {
				return result, err
			}
			hash := sha256.New()
			buffer := make([]byte, 32<<10)
			for {
				if ctx.Err() != nil {
					err = admissionError("upload_cancelled")
					break
				}
				n, readErr := part.Read(buffer)
				if n > 0 {
					result.Size += int64(n)
					if result.Size > store.policy.MaxBodyBytes {
						err = admissionError("payload_too_large")
						break
					}
					if _, writeErr := file.Write(buffer[:n]); writeErr != nil {
						err = admissionError("storage_error")
						break
					}
					hash.Write(buffer[:n])
				}
				if readErr == io.EOF {
					break
				}
				if readErr != nil {
					err = multipartReadError(readErr)
					break
				}
			}
			if err == nil && file.Sync() != nil {
				err = admissionError("storage_error")
			}
			if closeErr := file.Close(); err == nil && closeErr != nil {
				err = admissionError("storage_error")
			}
			if err != nil {
				return result, err
			}
			part.Close()
			result.SHA256 = hex.EncodeToString(hash.Sum(nil))
		} else {
			switch name {
			case "client_id", "enc_alg", "enc_key", "sig_alg", "sig":
			default:
				return result, admissionError("invalid_form")
			}
			if part.FileName() != "" {
				return result, admissionError("invalid_form")
			}
			value, err := io.ReadAll(io.LimitReader(part, maxJobMetadataBytes-fieldBytes+1))
			fieldBytes += int64(len(value))
			if fieldBytes > maxJobMetadataBytes {
				return result, admissionError("metadata_too_large")
			}
			if err != nil {
				return result, multipartReadError(err)
			}
			part.Close()
			result.Fields.Set(name, string(value))
		}
	}
	if !seen["file"] {
		return result, admissionError("missing_file")
	}
	r.Form = result.Fields // Preserve existing form/CN comparison without ParseMultipartForm.
	return result, nil
}
