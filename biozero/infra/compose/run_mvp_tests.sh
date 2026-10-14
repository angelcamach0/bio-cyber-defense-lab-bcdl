#!/usr/bin/env bash
set -euo pipefail
# Portable first-milestone runner. Native profile; no Docker daemon required.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../../.." && pwd)"
exec python3 -B "$REPO_ROOT/biozero/infra/native/run_experiment.py" \
  --tools-prefix "${BIOZERO_TOOLS_PREFIX:-$REPO_ROOT/.biozero/bio-tools}" "$@"
