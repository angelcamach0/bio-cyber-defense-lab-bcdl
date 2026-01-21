#!/usr/bin/env bash
set -euo pipefail
# PKI generator: creates CA, server, client, and signer keys for local mTLS demo.

umask 077

OUT_DIR="${1:-./pki}"
# Create output directory for PKI artifacts.
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

# SECURITY: generate a long-lived root CA key for local demo use.
openssl genrsa -out "$CA_KEY" 4096
# Use a self-signed CA certificate to anchor trust.
openssl req -x509 -new -nodes -key "$CA_KEY" -sha256 -days 3650 \
  -subj "/C=US/ST=CO/L=Colorado Springs/O=BioZero/OU=PKI/CN=BioZero Root CA" \
  -out "$CA_CERT"

# Generate the server key and CSR for upload-api/results-api.
openssl genrsa -out "$SERVER_KEY" 2048
openssl req -new -key "$SERVER_KEY" -out "$SERVER_CSR" \
  -subj "/C=US/ST=CO/L=Colorado Springs/O=BioZero/OU=Server/CN=localhost"

# Define server certificate extensions for SANs and EKU.
cat > "$OUT_DIR/server.ext" <<'EOT'
subjectAltName = DNS:localhost,IP:127.0.0.1,DNS:upload-api,DNS:results-api
extendedKeyUsage = serverAuth
keyUsage = digitalSignature, keyEncipherment
EOT

# Sign the server certificate with the demo CA.
openssl x509 -req -in "$SERVER_CSR" -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial \
  -out "$SERVER_CERT" -days 825 -sha256 -extfile "$OUT_DIR/server.ext"

# Generate the client key and CSR for mTLS clients.
openssl genrsa -out "$CLIENT_KEY" 2048
openssl req -new -key "$CLIENT_KEY" -out "$CLIENT_CSR" \
  -subj "/C=US/ST=CO/L=Colorado Springs/O=BioZero/OU=Client/CN=biozero-client"

# Define client certificate extensions for mTLS auth.
cat > "$OUT_DIR/client.ext" <<'EOT'
extendedKeyUsage = clientAuth
keyUsage = digitalSignature, keyEncipherment
EOT

# Sign the client certificate with the demo CA.
openssl x509 -req -in "$CLIENT_CSR" -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial \
  -out "$CLIENT_CERT" -days 825 -sha256 -extfile "$OUT_DIR/client.ext"

# Generate the signing key and CSR for payload signatures.
openssl genrsa -out "$SIGNER_KEY" 2048
openssl req -new -key "$SIGNER_KEY" -out "$SIGNER_CSR" \
  -subj "/C=US/ST=CO/L=Colorado Springs/O=BioZero/OU=Signer/CN=biozero-signer"

# Define signer certificate extensions for signing use.
cat > "$OUT_DIR/signer.ext" <<'EOT'
keyUsage = digitalSignature
extendedKeyUsage = clientAuth
EOT

# Sign the signer certificate with the demo CA.
openssl x509 -req -in "$SIGNER_CSR" -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial \
  -out "$SIGNER_CERT" -days 825 -sha256 -extfile "$OUT_DIR/signer.ext"

# Clean up temporary CSR and extension files.
rm -f "$SERVER_CSR" "$CLIENT_CSR" "$SIGNER_CSR" "$OUT_DIR/server.ext" "$OUT_DIR/client.ext" "$OUT_DIR/signer.ext"

# Emit the final output location for convenience.
echo "PKI artifacts written to $OUT_DIR"
