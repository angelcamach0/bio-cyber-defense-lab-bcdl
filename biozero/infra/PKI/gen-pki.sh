#!/usr/bin/env bash
set -euo pipefail
# Local synthetic-data milestone PKI. Never reuse these demo identities in production.
umask 077
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${1:-$SCRIPT_DIR/pki}"
command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 1; }
# mkdir is atomic: any existing destination is refused to preserve stored jobs.
mkdir -p -- "$(dirname -- "$OUT_DIR")"
if ! mkdir -- "$OUT_DIR"; then
  echo "Refusing to overwrite PKI destination: $OUT_DIR" >&2
  exit 1
fi
OUT_DIR="$(cd -- "$OUT_DIR" && pwd)"
mkdir -p -- "$OUT_DIR/authorities" "$OUT_DIR/clients" \
  "$OUT_DIR/runtime/upload" "$OUT_DIR/runtime/results" "$OUT_DIR/runtime/worker" \
  "$OUT_DIR/runtime/gateway"
WORK_DIR="$OUT_DIR/.generation"
mkdir -- "$WORK_DIR"
trap 'rm -f -- "$WORK_DIR"/*.csr "$WORK_DIR"/*.ext; rmdir -- "$WORK_DIR"' EXIT

openssl genrsa -out "$OUT_DIR/authorities/ca.key" 4096
openssl req -x509 -new -key "$OUT_DIR/authorities/ca.key" -sha256 -days 30 \
  -subj "/O=BioZero Demo/CN=BioZero Local CA" \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -out "$OUT_DIR/authorities/ca.crt"

issue_cert() {
  local name="$1" key_path="$2" cert_path="$3" extensions="$4"
  openssl genrsa -out "$key_path" 2048
  openssl req -new -key "$key_path" -subj "/O=BioZero Demo/CN=$name" \
    -out "$WORK_DIR/$name.csr"
  printf '%s\n' 'basicConstraints=critical,CA:FALSE' "$extensions" > "$WORK_DIR/$name.ext"
  openssl x509 -req -in "$WORK_DIR/$name.csr" \
    -CA "$OUT_DIR/authorities/ca.crt" -CAkey "$OUT_DIR/authorities/ca.key" \
    -CAcreateserial -sha256 -days 7 -extfile "$WORK_DIR/$name.ext" -out "$cert_path"
}

for service in upload results; do
  issue_cert "$service-api" "$OUT_DIR/runtime/$service/server.key" \
    "$OUT_DIR/runtime/$service/server.crt" \
    "subjectAltName=DNS:localhost,IP:127.0.0.1,DNS:$service-api
extendedKeyUsage=serverAuth
keyUsage=critical,digitalSignature,keyEncipherment"
  cp -- "$OUT_DIR/authorities/ca.crt" "$OUT_DIR/runtime/$service/ca.crt"
done
issue_cert reviewer-gateway "$OUT_DIR/runtime/gateway/server.key" \
  "$OUT_DIR/runtime/gateway/server.crt" \
  'subjectAltName=DNS:localhost,IP:127.0.0.1,DNS:reviewer-gateway
extendedKeyUsage=serverAuth
keyUsage=critical,digitalSignature,keyEncipherment'
for principal in researcher-a researcher-b; do
  issue_cert "$principal" "$OUT_DIR/clients/$principal.key" \
    "$OUT_DIR/clients/$principal.crt" \
    'extendedKeyUsage=clientAuth
keyUsage=critical,digitalSignature'
done
# Decryption is separate from both API TLS private keys.
issue_cert decrypt "$OUT_DIR/runtime/worker/decrypt.key" "$OUT_DIR/clients/decrypt.crt" \
  'keyUsage=critical,keyEncipherment'
# One trusted signing key is a demo fixture, held client-side.
issue_cert signer "$OUT_DIR/clients/signer.key" "$OUT_DIR/runtime/worker/signer.crt" \
  'keyUsage=critical,digitalSignature
extendedKeyUsage=codeSigning'
cp -- "$OUT_DIR/authorities/ca.crt" "$OUT_DIR/clients/ca.crt"
# The gateway holds two distinct TLS identities, plus the synthetic fixture signer.
# It never receives the CA private key or the worker's decryption private key.
cp -- "$OUT_DIR/clients/ca.crt" "$OUT_DIR/clients/decrypt.crt" \
  "$OUT_DIR/clients/signer.key" "$OUT_DIR/clients/researcher-a.crt" \
  "$OUT_DIR/clients/researcher-a.key" "$OUT_DIR/clients/researcher-b.crt" \
  "$OUT_DIR/clients/researcher-b.key" "$OUT_DIR/runtime/gateway/"
chmod 644 -- "$OUT_DIR/authorities/ca.crt" "$OUT_DIR/clients"/*.crt \
  "$OUT_DIR/runtime/upload"/*.crt "$OUT_DIR/runtime/results"/*.crt \
  "$OUT_DIR/runtime/worker/signer.crt" "$OUT_DIR/runtime/gateway"/*.crt
printf 'Demo PKI generated at %s; existing keys are never overwritten.\n' "$OUT_DIR"
