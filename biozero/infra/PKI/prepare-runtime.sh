#!/usr/bin/env bash
set -euo pipefail
umask 077
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="${1:-$SCRIPT_DIR/../compose/data}"
# Run as the same host user that generated the PKI; no chown or root init.
if [[ "$(id -u)" == 0 ]]; then
  echo "Prepare runtime as a non-root host user." >&2
  exit 1
fi
for directory in "$DATA_DIR" "$DATA_DIR/uploads" "$DATA_DIR/jobs" \
  "$DATA_DIR/results" "$DATA_DIR/artifacts" "$DATA_DIR/actions" \
  "$DATA_DIR/reviewer"; do
  if [[ -L "$directory" ]]; then
    echo "Refusing symlink runtime directory: $directory" >&2
    exit 1
  fi
  mkdir -p -- "$directory"
  if [[ ! -O "$directory" ]]; then
    echo "Runtime directory must be owned by the invoking user: $directory" >&2
    exit 1
  fi
  chmod 700 -- "$directory"
done
printf 'Runtime directories prepared. Set BIOZERO_UID=%s BIOZERO_GID=%s before Compose.\n' \
  "$(id -u)" "$(id -g)"
