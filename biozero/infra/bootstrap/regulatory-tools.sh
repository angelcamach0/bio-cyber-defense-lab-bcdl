#!/usr/bin/env bash
set -euo pipefail
# Recreate the measured CPU-only Python/Torch probe environment. No trained weights.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../../.." && pwd)"
if [[ "$(uname -s)" != Linux || "$(uname -m)" != aarch64 ]]; then
  echo 'The measured regulatory environment lock supports Linux ARM64 only.' >&2
  exit 1
fi
PREFIX="${BIOZERO_REGULATORY_PREFIX:-$REPO_ROOT/.biozero/regulatory}"
MAMBA_ROOT="${BIOZERO_MAMBA_ROOT:-$REPO_ROOT/.biozero/mamba-root}"
MAMBA_BIN="${BIOZERO_MICROMAMBA:-$REPO_ROOT/.biozero/micromamba}"
if [[ ! -x "$MAMBA_BIN" ]]; then
  mkdir -p -- "$(dirname -- "$MAMBA_BIN")"
  ARCHIVE="$(mktemp)"
  trap 'rm -f -- "$ARCHIVE"' EXIT
  curl --fail --silent --show-error --location \
    https://micro.mamba.pm/api/micromamba/linux-aarch64/2.9.0 -o "$ARCHIVE"
  python3 - "$ARCHIVE" "$MAMBA_BIN" <<'PY'
import pathlib, sys, tarfile
with tarfile.open(sys.argv[1]) as archive:
    binary = archive.extractfile('bin/micromamba').read()
target = pathlib.Path(sys.argv[2])
target.write_bytes(binary)
target.chmod(0o755)
PY
fi
LOCK_DIR="$REPO_ROOT/biozero/research/regulatory"
"$MAMBA_BIN" create -y -r "$MAMBA_ROOT" -p "$PREFIX" \
  --file "$LOCK_DIR/python-linux-aarch64.lock.txt"
"$PREFIX/bin/python" -m pip install --require-hashes \
  -r "$LOCK_DIR/wheels-linux-aarch64.lock.txt"
printf 'CPU-only probe environment prepared at %s. No model checkpoint was downloaded.\n' "$PREFIX"
