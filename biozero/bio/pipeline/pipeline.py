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
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def fastq_stats(path):
    read_count = 0
    total_len = 0
    line_count = 0
    with open(path, "r", errors="ignore") as f:
        for idx, line in enumerate(f, start=1):
            line_count += 1
            if idx % 4 == 2:
                read_count += 1
                total_len += len(line.strip())
    avg_len = int(total_len / read_count) if read_count else 0
    return read_count, avg_len, line_count

def run_cmd(cmd, stdout_path=None, timeout_seconds=600):
    try:
        if stdout_path:
            with open(stdout_path, "w") as out:
                return subprocess.run(
                    cmd, stdout=out, stderr=subprocess.PIPE, text=True, timeout=timeout_seconds
                )
        return subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout_seconds
        )
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(cmd, 124, "", f"timeout after {timeout_seconds}s")

def write_error(message):
    print(json.dumps({"error": message}))

def parse_timeout_seconds():
    raw = os.environ.get("BIOZERO_PIPELINE_TIMEOUT_SECONDS", "600")
    try:
        return max(1, int(raw))
    except ValueError:
        return 600

def max_bytes_limit():
    raw = os.environ.get("BIOZERO_PIPELINE_MAX_BYTES", "26214400")
    try:
        return max(1, int(raw))
    except ValueError:
        return 26214400

def main():
    try:
        parser = argparse.ArgumentParser(description="BioZero pipeline wrapper")
        parser.add_argument("input", help="input FASTQ file")
        parser.add_argument("--reference", help="reference genome (FASTA)")
        parser.add_argument("--out-dir", help="output directory")
        args = parser.parse_args()

        if not os.path.isfile(args.input):
            write_error(f"input not found: {args.input}")
            return 1
        if os.path.getsize(args.input) > max_bytes_limit():
            write_error("input exceeds configured size limit")
            return 1

        out_dir = args.out_dir or os.environ.get("BIOZERO_PIPELINE_OUT_DIR")
        if not out_dir:
            out_dir = tempfile.mkdtemp(prefix="biozero-pipeline-")
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

        read_count, avg_len, line_count = fastq_stats(args.input)
        byte_count = os.path.getsize(args.input)
        sha = sha256_file(args.input)

        working_input = args.input

        # Pre-process reads with fastp when available.
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
            if result.returncode == 0:
                outputs["fastp_cleaned"] = fastp_out
                outputs["fastp_json"] = fastp_json
                outputs["fastp_html"] = fastp_html
                working_input = fastp_out
                try:
                    with open(fastp_json, "r") as f:
                        outputs["fastp_summary"] = json.load(f)
                except Exception:
                    warnings.append("fastp produced invalid json")
            else:
                warnings.append("fastp failed: " + result.stderr.strip())
        else:
            warnings.append("fastp not installed")

        # Align against the reference to surface targeted signals.
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
            if result.returncode == 0:
                outputs["alignment_sam"] = sam_path
                if result.stderr:
                    outputs["minimap2_log"] = result.stderr.strip()
            else:
                warnings.append("minimap2 failed: " + result.stderr.strip())
        else:
            if not args.reference:
                warnings.append("reference not provided for minimap2")
            if not tools["minimap2"]:
                warnings.append("minimap2 not installed")

        # Optional variant calling chain for richer evidence.
        if tools["bcftools"] and tools["samtools"] and args.reference:
            sam_path = outputs.get("alignment_sam")
            if sam_path:
                bam_path = os.path.join(out_dir, "alignment.bam")
                sorted_bam = os.path.join(out_dir, "alignment.sorted.bam")
                vcf_path = os.path.join(out_dir, "variants.vcf.gz")
                view = run_cmd(
                    [tools["samtools"], "view", "-bS", sam_path],
                    stdout_path=bam_path,
                    timeout_seconds=timeout_seconds,
                )
                if view.returncode == 0:
                    sort = run_cmd(
                        [tools["samtools"], "sort", "-o", sorted_bam, bam_path],
                        timeout_seconds=timeout_seconds,
                    )
                    if sort.returncode == 0:
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
                        if call.returncode == 0:
                            run_cmd([tools["bcftools"], "index", vcf_path], timeout_seconds=timeout_seconds)
                            outputs["variants_vcf"] = vcf_path
                        else:
                            warnings.append("bcftools call failed: " + call.stderr.strip())
                    else:
                        warnings.append("samtools sort failed: " + sort.stderr.strip())
                else:
                    warnings.append("samtools view failed: " + view.stderr.strip())
            else:
                warnings.append("bcftools skipped: no alignment SAM")
        else:
            if not tools["bcftools"]:
                warnings.append("bcftools not installed")
            if not tools["samtools"]:
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
        return 0
    except Exception as exc:
        write_error(f"pipeline error: {exc}")
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
