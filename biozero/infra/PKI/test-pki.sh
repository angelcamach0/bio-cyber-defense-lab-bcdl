#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TEST_DIR="$(mktemp -d "${TMPDIR:-/tmp}/biozero-pki-test.XXXXXX")"
trap 'rm -rf -- "$TEST_DIR"' EXIT
PKI="$TEST_DIR/keys with spaces"
bash "$SCRIPT_DIR/gen-pki.sh" "$PKI" >/dev/null 2>&1
for principal in researcher-a researcher-b; do
  openssl verify -purpose sslclient -CAfile "$PKI/clients/ca.crt" \
    "$PKI/clients/$principal.crt" >/dev/null
  subject="$(openssl x509 -in "$PKI/clients/$principal.crt" -noout -subject -nameopt RFC2253)"
  [[ "$subject" == *"CN=$principal,"* ]]
done
openssl verify -purpose sslserver -verify_hostname reviewer-gateway \
  -CAfile "$PKI/clients/ca.crt" "$PKI/runtime/gateway/server.crt" >/dev/null
serial_a="$(openssl x509 -in "$PKI/clients/researcher-a.crt" -noout -serial)"
serial_b="$(openssl x509 -in "$PKI/clients/researcher-b.crt" -noout -serial)"
[[ "$serial_a" != "$serial_b" ]]
for service in upload results; do
  openssl verify -purpose sslserver -verify_hostname "$service-api" \
    -CAfile "$PKI/runtime/$service/ca.crt" "$PKI/runtime/$service/server.crt" >/dev/null
done
if openssl verify -purpose sslserver -verify_hostname upload-api \
  -CAfile "$PKI/clients/ca.crt" "$PKI/runtime/results/server.crt" >/dev/null 2>&1; then
  echo "Wrong service hostname was accepted" >&2; exit 1
fi
if openssl verify -purpose sslclient -CAfile "$PKI/clients/ca.crt" \
  "$PKI/runtime/worker/signer.crt" >/dev/null 2>&1; then
  echo "Payload signer must not be usable as a TLS client" >&2; exit 1
fi
before="$(openssl x509 -in "$PKI/clients/researcher-a.crt" -noout -fingerprint -sha256)"
if bash "$SCRIPT_DIR/gen-pki.sh" "$PKI" >/dev/null 2>&1; then
  echo "Existing destination was overwritten" >&2; exit 1
fi
after="$(openssl x509 -in "$PKI/clients/researcher-a.crt" -noout -fingerprint -sha256)"
[[ "$before" == "$after" ]]
python3 - "$PKI" <<'PY'
from pathlib import Path
import stat, sys
pki = Path(sys.argv[1])
expected = {
    'upload': {'server.crt', 'server.key', 'ca.crt'},
    'results': {'server.crt', 'server.key', 'ca.crt'},
    'worker': {'decrypt.key', 'signer.crt'},
    'gateway': {'server.crt', 'server.key', 'ca.crt', 'decrypt.crt', 'signer.key',
                'researcher-a.crt', 'researcher-a.key', 'researcher-b.crt', 'researcher-b.key'},
}
for role, names in expected.items():
    assert {p.name for p in (pki / 'runtime' / role).iterdir()} == names
for key in pki.rglob('*.key'):
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
PY
if [[ "$(id -u)" != 0 ]]; then
  bash "$SCRIPT_DIR/prepare-runtime.sh" "$TEST_DIR/data" >/dev/null
  bash "$SCRIPT_DIR/prepare-runtime.sh" "$TEST_DIR/data" >/dev/null
  [[ -d "$TEST_DIR/data/artifacts" ]]
  ln -s "$TEST_DIR/data" "$TEST_DIR/link"
  if bash "$SCRIPT_DIR/prepare-runtime.sh" "$TEST_DIR/link" >/dev/null 2>&1; then
    echo "Symlink runtime directory was accepted" >&2; exit 1
  fi
fi
echo "PASS: independent A/B identities, CA chains, hostname/purpose rejection, no overwrite, minimal runtime keys, private modes, runtime preparation"
