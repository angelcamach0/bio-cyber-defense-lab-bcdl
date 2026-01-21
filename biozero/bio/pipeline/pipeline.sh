#!/usr/bin/env bash
set -euo pipefail
# Basic pipeline wrapper: computes FASTQ stats and emits JSON consumed by enclave-runner/results-api.

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <input-file>" >&2
  exit 1
fi

input="$1"
if [[ ! -f "$input" ]]; then
  echo "input not found: $input" >&2
  exit 1
fi
max_bytes="${BIOZERO_PIPELINE_MAX_BYTES:-26214400}"
if [[ "$(wc -c <"$input")" -gt "$max_bytes" ]]; then
  echo "input exceeds configured size limit" >&2
  exit 1
fi

read_count=0
avg_length=0
if read_count=$(awk 'NR%4==2 {reads++; total+=length($0)} END {if (reads>0) printf "%d", reads; else printf "0"}' "$input"); then
  total_len=$(awk 'NR%4==2 {total+=length($0)} END {if (total>0) printf "%d", total; else printf "0"}' "$input")
  if [[ "$read_count" -gt 0 ]]; then
    avg_length=$((total_len / read_count))
  fi
fi

byte_count=$(wc -c <"$input" | tr -d ' ')
line_count=$(wc -l <"$input" | tr -d ' ')
sha256=$(sha256sum "$input" | awk '{print $1}')

cat <<JSON
{
  "pipeline": "mvp-fastq-stats",
  "byte_count": ${byte_count},
  "line_count": ${line_count},
  "read_count": ${read_count},
  "avg_read_length": ${avg_length},
  "sha256": "${sha256}",
  "notes": "Basic FASTQ stats; replace with real bio pipeline"
}
JSON
