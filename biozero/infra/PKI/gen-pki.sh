#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${1:-./pki}"
mkdir -p "$OUT_DIR"

CA_KEY="$OUT_DIR/ca.key"
CA_CERT="$OUT_DIR/ca.crt"
SERVER_KEY="$OUT_DIR/server.key"
SERVER_CSR="$OUT_DIR/server.csr"
SERVER_CERT="$OUT_DIR/server.crt"
CLIENT_KEY="$OUT_DIR/client.key"
CLIENT_CSR="$OUT_DIR/client.csr"
CLIENT_CERT="$OUT_DIR/client.crt"
SIGNER_KEY="$OUT_DIR/signer.key"
SIGNER_CSR="$OUT_DIR/signer.csr"
SIGNER_CERT="$OUT_DIR/signer.crt"

openssl genrsa -out "$CA_KEY" 4096
openssl req -x509 -new -nodes -key "$CA_KEY" -sha256 -days 3650 \
  -subj "/C=US/ST=CO/L=Colorado Springs/O=BioZero/OU=PKI/CN=BioZero Root CA" \
  -out "$CA_CERT"

openssl genrsa -out "$SERVER_KEY" 2048
openssl req -new -key "$SERVER_KEY" -out "$SERVER_CSR" \
  -subj "/C=US/ST=CO/L=Colorado Springs/O=BioZero/OU=Server/CN=localhost"

cat > "$OUT_DIR/server.ext" <<'EOT'
subjectAltName = DNS:localhost,IP:127.0.0.1,DNS:upload-api,DNS:results-api
extendedKeyUsage = serverAuth
keyUsage = digitalSignature, keyEncipherment
EOT

openssl x509 -req -in "$SERVER_CSR" -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial \
  -out "$SERVER_CERT" -days 825 -sha256 -extfile "$OUT_DIR/server.ext"

openssl genrsa -out "$CLIENT_KEY" 2048
openssl req -new -key "$CLIENT_KEY" -out "$CLIENT_CSR" \
  -subj "/C=US/ST=CO/L=Colorado Springs/O=BioZero/OU=Client/CN=biozero-client"

cat > "$OUT_DIR/client.ext" <<'EOT'
extendedKeyUsage = clientAuth
keyUsage = digitalSignature, keyEncipherment
EOT

openssl x509 -req -in "$CLIENT_CSR" -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial \
  -out "$CLIENT_CERT" -days 825 -sha256 -extfile "$OUT_DIR/client.ext"

openssl genrsa -out "$SIGNER_KEY" 2048
openssl req -new -key "$SIGNER_KEY" -out "$SIGNER_CSR" \
  -subj "/C=US/ST=CO/L=Colorado Springs/O=BioZero/OU=Signer/CN=biozero-signer"

cat > "$OUT_DIR/signer.ext" <<'EOT'
keyUsage = digitalSignature
extendedKeyUsage = clientAuth
EOT

openssl x509 -req -in "$SIGNER_CSR" -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial \
  -out "$SIGNER_CERT" -days 825 -sha256 -extfile "$OUT_DIR/signer.ext"

rm -f "$SERVER_CSR" "$CLIENT_CSR" "$SIGNER_CSR" "$OUT_DIR/server.ext" "$OUT_DIR/client.ext" "$OUT_DIR/signer.ext"

echo "PKI artifacts written to $OUT_DIR"
