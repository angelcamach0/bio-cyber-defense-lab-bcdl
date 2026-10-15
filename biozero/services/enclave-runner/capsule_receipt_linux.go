//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"regexp"

	artifact "biozero/artifact-executor"
	"biozero/enclave-runner/receiptprojection"
)

// Legacy names intentionally alias the shared projector's unchanged DTOs.
type capsuleSourcePin = receiptprojection.SourcePin
type capsuleReceiptFacts = receiptprojection.Facts
type capsuleReceiptProjection = receiptprojection.Projection

var receiptCode = regexp.MustCompile(receiptprojection.ErrorCodePattern)

func receiptDigest(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }

// Projection uses the original schema-2 retained receipt, not mutable result JSON.
// The caller still owns authenticated-channel, descriptor and custody authority.
func ProjectCapsuleReceipt(ctx context.Context, reader io.Reader, r artifact.BridgeResponse, f capsuleReceiptFacts) (capsuleReceiptProjection, error) {
	return receiptprojection.ProjectCapsuleReceipt(ctx, reader, r, f)
}
