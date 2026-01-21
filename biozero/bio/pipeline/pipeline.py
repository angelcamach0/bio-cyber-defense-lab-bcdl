#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""
BioZero pipeline wrapper: inspects FASTQ input, runs optional tools, and prints
JSON for enclave-runner to persist as results consumed by results-api.
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from datetime import datetime

def sha256_file(path):
    """
    Brief description of what the function does.
    - Computes a SHA-256 digest for a file by streaming its contents.

    Parameters:
      path - Filesystem path to the file to hash.

    Returns the hex-encoded SHA-256 digest string.

    Throws [IOError] when file reading fails.

    Example: `digest = sha256_file("/data/sample.fastq")`
    """
    h = hashlib.sha256()
    with open(path, "rb") as f:
        # Stream the file in chunks to avoid loading large files into memory.
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    # Return the hex digest for logging and downstream verification.
    return h.hexdigest()

def fastq_stats(path):
    """
    Brief description of what the function does.
    - Computes basic FASTQ statistics needed for detection heuristics.

    Parameters:
      path - Filesystem path to the FASTQ file.

    Returns (read_count, avg_len, line_count).

    Throws [IOError] when file reading fails.

    Performance:
      Time complexity: O(n) over file lines.
      Space complexity: O(1) additional space.

    Example: `read_count, avg_len, line_count = fastq_stats(path)`
    """
    read_count = 0
    total_len = 0
    line_count = 0
    with open(path, "r", errors="ignore") as f:
        # Iterate through lines to count reads and accumulate lengths.
        for idx, line in enumerate(f, start=1):
            line_count += 1
            # FASTQ sequence lines occur every 4 lines.
            # Only count sequence lines (2nd line of each FASTQ record).
            if idx % 4 == 2:
                read_count += 1
                total_len += len(line.strip())
    # Avoid division by zero when no reads are present.
    # Avoid division by zero when no reads are present.
    avg_len = int(total_len / read_count) if read_count else 0
    # Return computed statistics for downstream scoring.
    return read_count, avg_len, line_count

def run_cmd(cmd, stdout_path=None, timeout_seconds=600):
    """
    Brief description of what the function does.
    - Runs a subprocess command with optional stdout redirection and timeout.

    Parameters:
      cmd - List of command arguments to execute.
      stdout_path - Optional path to write stdout output.
      timeout_seconds - Max runtime before timing out the command.

    Returns a subprocess.CompletedProcess instance.

    Throws [SubprocessError] when execution fails; errors are captured in returncode.

    Example: `result = run_cmd(["fastp", "-i", input_path], timeout_seconds=600)`
    """
    try:
        # Route stdout to a file when requested.
        if stdout_path:
            # API boundary: invokes external tooling and writes stdout to disk.
            with open(stdout_path, "w") as out:
                # Return the subprocess result for downstream error handling.
                return subprocess.run(
                    cmd, stdout=out, stderr=subprocess.PIPE, text=True, timeout=timeout_seconds
                )
        # API boundary: invoke external tooling and capture stdout/stderr.
        # Return the subprocess result for downstream error handling.
        return subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout_seconds
        )
    except subprocess.TimeoutExpired as exc:
        # Return a synthetic timeout result to keep downstream logic consistent.
        return subprocess.CompletedProcess(cmd, 124, "", f"timeout after {timeout_seconds}s")

def write_error(message):
    """
    Brief description of what the function does.
    - Emits a JSON error payload for machine-readable consumers.

    Parameters:
      message - Human-readable error message.

    Returns no value; writes to stdout.

    Throws [None] - JSON serialization is safe for strings.

    Example: `write_error("input not found")`
    """
    # Emit a JSON error payload for the caller.
    print(json.dumps({"error": message}))

def parse_timeout_seconds():
    """
    Brief description of what the function does.
    - Reads the pipeline timeout from environment variables.

    Parameters:
      None.

    Returns the timeout in seconds as an int.

    Throws [ValueError] when parsing fails; defaults are used instead.

    Example: `timeout_seconds = parse_timeout_seconds()`
    """
    raw = os.environ.get("BIOZERO_PIPELINE_TIMEOUT_SECONDS", "600")
    try:
        # Return a safe minimum of 1 second to avoid zero-timeout runs.
        return max(1, int(raw))
    except ValueError:
        # Return the default timeout on parse failure.
        return 600

def max_bytes_limit():
    """
    Brief description of what the function does.
    - Reads the maximum input size from environment variables.

    Parameters:
      None.

    Returns the max input size in bytes as an int.

    Throws [ValueError] when parsing fails; defaults are used instead.

    Example: `limit = max_bytes_limit()`
    """
    raw = os.environ.get("BIOZERO_PIPELINE_MAX_BYTES", "26214400")
    try:
        # Return a safe minimum of 1 byte to avoid zero-size limits.
        return max(1, int(raw))
    except ValueError:
        # Return the default size limit on parse failure.
        return 26214400

def main():
    """
    Brief description of what the function does.
    - Orchestrates the pipeline by running optional tools and emitting JSON.

    Parameters:
      None (reads CLI args and environment variables).

    Returns an integer process exit code (0 on success).

    Throws [Exception] when unexpected pipeline errors occur.

    Example: `python pipeline.py input.fastq --reference ref.fa`
    """
    try:
        parser = argparse.ArgumentParser(description="BioZero pipeline wrapper")
        parser.add_argument("input", help="input FASTQ file")
        parser.add_argument("--reference", help="reference genome (FASTA)")
        parser.add_argument("--out-dir", help="output directory")
        args = parser.parse_args()

        # Validate input existence before performing any work.
        # Validate input path before processing.
        if not os.path.isfile(args.input):
            write_error(f"input not found: {args.input}")
            # Return non-zero to signal invalid input.
            return 1
        # Enforce max input size to avoid expensive processing.
        # Enforce size limits before invoking tools.
        if os.path.getsize(args.input) > max_bytes_limit():
            write_error("input exceeds configured size limit")
            # Return non-zero to signal size violations.
            return 1

        out_dir = args.out_dir or os.environ.get("BIOZERO_PIPELINE_OUT_DIR")
        # Create a temp output directory when not provided.
        if not out_dir:
            out_dir = tempfile.mkdtemp(prefix="biozero-pipeline-")
        # Ensure the output directory exists for tool artifacts.
        os.makedirs(out_dir, exist_ok=True)

        timeout_seconds = parse_timeout_seconds()
        tools = {
            "fastp": shutil.which("fastp"),
            "minimap2": shutil.which("minimap2"),
            "bcftools": shutil.which("bcftools"),
            "samtools": shutil.which("samtools"),
        }

        warnings = []
        outputs = {}

        # Compute base stats for detection and reporting.
        read_count, avg_len, line_count = fastq_stats(args.input)
        byte_count = os.path.getsize(args.input)
        sha = sha256_file(args.input)

        working_input = args.input

        # Pre-process reads with fastp when available.
        # Run fastp when available for read cleaning and metrics.
        if tools["fastp"]:
            fastp_out = os.path.join(out_dir, "fastp_cleaned.fastq")
            fastp_json = os.path.join(out_dir, "fastp.json")
            fastp_html = os.path.join(out_dir, "fastp.html")
            result = run_cmd(
                [
                    tools["fastp"],
                    "-i", args.input,
                    "-o", fastp_out,
                    "--json", fastp_json,
                    "--html", fastp_html,
                ],
                timeout_seconds=timeout_seconds,
            )
            # Handle fastp success path.
            if result.returncode == 0:
                # Capture fastp outputs for downstream consumption.
                outputs["fastp_cleaned"] = fastp_out
                outputs["fastp_json"] = fastp_json
                outputs["fastp_html"] = fastp_html
                working_input = fastp_out
                try:
                    with open(fastp_json, "r") as f:
                        outputs["fastp_summary"] = json.load(f)
                except Exception:
                    # Record a warning when fastp JSON is malformed.
                    warnings.append("fastp produced invalid json")
            else:
                # Record a warning to preserve pipeline output on failures.
                warnings.append("fastp failed: " + result.stderr.strip())
        else:
            # Record missing tool warnings for visibility.
            warnings.append("fastp not installed")

        # Align against the reference to surface targeted signals.
        # Run minimap2 when available and reference is provided.
        if tools["minimap2"] and args.reference:
            sam_path = os.path.join(out_dir, "alignment.sam")
            result = run_cmd(
                [
                    tools["minimap2"],
                    "-a",
                    args.reference,
                    working_input,
                ],
                stdout_path=sam_path,
                timeout_seconds=timeout_seconds,
            )
            # Handle minimap2 success path.
            if result.returncode == 0:
                # Capture alignment output for later variant calling.
                outputs["alignment_sam"] = sam_path
                # Preserve minimap2 stderr output for context.
                if result.stderr:
                    outputs["minimap2_log"] = result.stderr.strip()
            else:
                # Record a warning to preserve pipeline output on failures.
                warnings.append("minimap2 failed: " + result.stderr.strip())
        else:
            # Record missing reference when alignment is skipped.
            if not args.reference:
                # Record missing reference to explain alignment omission.
                warnings.append("reference not provided for minimap2")
            # Record missing tool when alignment is skipped.
            if not tools["minimap2"]:
                # Record missing tool to explain alignment omission.
                warnings.append("minimap2 not installed")

        # Optional variant calling chain for richer evidence.
        # Run variant calling chain only when tools and reference are available.
        if tools["bcftools"] and tools["samtools"] and args.reference:
            sam_path = outputs.get("alignment_sam")
            # Proceed only when alignment output is available.
            if sam_path:
                bam_path = os.path.join(out_dir, "alignment.bam")
                sorted_bam = os.path.join(out_dir, "alignment.sorted.bam")
                vcf_path = os.path.join(out_dir, "variants.vcf.gz")
                view = run_cmd(
                    [tools["samtools"], "view", "-bS", sam_path],
                    stdout_path=bam_path,
                    timeout_seconds=timeout_seconds,
                )
                # Continue only when samtools view succeeds.
                if view.returncode == 0:
                    # Sort the BAM for downstream indexing and variant calling.
                    sort = run_cmd(
                        [tools["samtools"], "sort", "-o", sorted_bam, bam_path],
                        timeout_seconds=timeout_seconds,
                    )
                    # Continue only when samtools sort succeeds.
                    if sort.returncode == 0:
                        # Index the sorted BAM to enable random access.
                        run_cmd([tools["samtools"], "index", sorted_bam], timeout_seconds=timeout_seconds)
                        mpileup = subprocess.Popen(
                            [tools["bcftools"], "mpileup", "-f", args.reference, sorted_bam],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                        )
                        call = subprocess.run(
                            [tools["bcftools"], "call", "-mv", "-Oz", "-o", vcf_path],
                            stdin=mpileup.stdout,
                            stderr=subprocess.PIPE,
                            text=True,
                            timeout=timeout_seconds,
                        )
                        # Continue only when bcftools call succeeds.
                        if call.returncode == 0:
                            # Index the VCF for downstream consumption.
                            run_cmd([tools["bcftools"], "index", vcf_path], timeout_seconds=timeout_seconds)
                            outputs["variants_vcf"] = vcf_path
                        else:
                            # Record warning to preserve pipeline output on failures.
                            warnings.append("bcftools call failed: " + call.stderr.strip())
                    else:
                        # Record warning to preserve pipeline output on failures.
                        warnings.append("samtools sort failed: " + sort.stderr.strip())
                else:
                    # Record warning to preserve pipeline output on failures.
                    warnings.append("samtools view failed: " + view.stderr.strip())
            else:
                # Record skipped state when no alignment is available.
                warnings.append("bcftools skipped: no alignment SAM")
        else:
            # Record missing tool when variant calling is skipped.
            if not tools["bcftools"]:
                # Record missing tool to explain variant omission.
                warnings.append("bcftools not installed")
            # Record missing tool when variant calling is skipped.
            if not tools["samtools"]:
                # Record missing tool to explain variant omission.
                warnings.append("samtools not installed")

        payload = {
            "pipeline": "python-wrapper",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "input": os.path.abspath(args.input),
            "output_dir": os.path.abspath(out_dir),
            "byte_count": byte_count,
            "line_count": line_count,
            "read_count": read_count,
            "avg_read_length": avg_len,
            "sha256": sha,
            "tools": {k: bool(v) for k, v in tools.items()},
            "outputs": outputs,
            "warnings": warnings,
        }

        print(json.dumps(payload, indent=2))
        # Return success to indicate pipeline completion.
        return 0
    except Exception as exc:
        write_error(f"pipeline error: {exc}")
        # Return non-zero to indicate unexpected pipeline failure.
        return 1

# Entry point when executed as a script.
if __name__ == "__main__":
    raise SystemExit(main())
