#!/usr/bin/env bash
set -euo pipefail
# Install free bioinformatics tools in a task-local prefix; retain exact ARM package lock.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../../.." && pwd)"
PREFIX="${BIOZERO_TOOLS_PREFIX:-$REPO_ROOT/.biozero/bio-tools}"
MAMBA_ROOT="${BIOZERO_MAMBA_ROOT:-$REPO_ROOT/.biozero/mamba-root}"
MAMBA_BIN="${BIOZERO_MICROMAMBA:-$REPO_ROOT/.biozero/micromamba}"
case "$(uname -m)" in
  aarch64|arm64) SUBDIR=linux-aarch64 ;;
  x86_64|amd64) SUBDIR=linux-64 ;;
  *) echo 'Only Linux ARM64 or x86_64 is configured; this host is unsupported.' >&2; exit 1 ;;
esac
if [[ "$(uname -s)" != Linux ]]; then echo 'This bootstrap targets Linux.' >&2; exit 1; fi
if [[ ! -x "$MAMBA_BIN" ]]; then
  command -v curl >/dev/null
  command -v python3 >/dev/null
  mkdir -p -- "$(dirname -- "$MAMBA_BIN")"
  ARCHIVE="$(mktemp)"
  trap 'rm -f -- "$ARCHIVE"' EXIT
  curl --fail --silent --show-error --location \
    "https://micro.mamba.pm/api/micromamba/$SUBDIR/2.9.0" -o "$ARCHIVE"
  python3 - "$ARCHIVE" "$MAMBA_BIN" <<'PY'
import pathlib, sys, tarfile
with tarfile.open(sys.argv[1]) as archive:
    binary = archive.extractfile('bin/micromamba').read()
target = pathlib.Path(sys.argv[2])
target.write_bytes(binary)
target.chmod(0o755)
PY
fi
LOCK="$SCRIPT_DIR/environment-$SUBDIR.lock.txt"
if [[ -f "$LOCK" ]]; then
  "$MAMBA_BIN" create -y -r "$MAMBA_ROOT" -p "$PREFIX" --file "$LOCK"
else
  "$MAMBA_BIN" create -y -r "$MAMBA_ROOT" -p "$PREFIX" -c conda-forge -c bioconda \
    samtools=1.24 bcftools=1.24 minimap2=2.31 fastp=1.4.0
fi
printf 'Tools ready at %s/bin. This does not verify container isolation or other platforms.\n' "$PREFIX"
