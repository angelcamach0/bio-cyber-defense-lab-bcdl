#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Validated FASTQ statistics or required variant calling; stdout is JSON only.

Exit 0: succeeded; exit 2: incomplete prerequisites; exit 1: failed execution
or invalid input. Statistics are not variant analysis. Each run uses a fresh
artifact directory, preventing previous outputs from satisfying new checks.
"""
import argparse
import errno
import gzip
import zlib
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from resource_budget import Budget, BudgetError, apply_kernel_file_limit, own_job_group, bounded_command
from datetime import datetime, timezone


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def max_bytes_limit():
    return Budget.from_env().input_bytes


def parse_timeout_seconds():
    return Budget.from_env().timeout_seconds


def fastq_stats(path, budget=None):
    """Validate unwrapped four-line FASTQ, including decompressed size limits."""
    budget = budget or Budget.from_env()
    opener = gzip.open if str(path).endswith(".gz") else open
    count = total = expanded = 0
    with opener(path, "rt", encoding="ascii", errors="strict", newline="") as stream:
        while True:
            raw = []
            for index in range(4):
                line = stream.readline(budget.input_bytes - expanded + 1)
                if index == 0 and not line:
                    break
                if not line:
                    raise ValueError(f"truncated FASTQ record {count + 1}")
                expanded += len(line)
                if expanded > budget.input_bytes:
                    raise ValueError("expanded FASTQ exceeds configured size limit")
                raw.append(line)
            if not raw:
                break
            header, sequence, plus, quality = [line.rstrip("\r\n") for line in raw]
            if not header.startswith("@") or not header[1:].strip():
                raise ValueError(f"invalid FASTQ header at record {count + 1}")
            if not plus.startswith("+"):
                raise ValueError(f"invalid FASTQ separator at record {count + 1}")
            if plus[1:] and plus[1:] != header[1:]:
                raise ValueError(f"FASTQ repeated identifier mismatch at record {count + 1}")
            if not sequence or any(base.upper() not in "ACGTRYSWKMBDHVN" for base in sequence):
                raise ValueError(f"invalid FASTQ sequence at record {count + 1}")
            if len(sequence) != len(quality) or any(not 33 <= ord(ch) <= 126 for ch in quality):
                raise ValueError(f"invalid FASTQ quality at record {count + 1}")
            count += 1
            total += len(sequence)
    if not count:
        raise ValueError("empty FASTQ")
    return count, total // count, count * 4


def run_cmd(cmd, stdout_path=None, timeout_seconds=600):
    # Files and samtools spill files share the dedicated job cwd/TMPDIR.
    directory = str(Path(stdout_path).parent) if stdout_path else None
    if directory is None:
        for item in cmd[1:]:
            candidate = Path(str(item))
            if candidate.is_absolute() and candidate.parent.name.startswith("biozero-run-"):
                directory = str(candidate.parent)
                break
    return bounded_command(cmd, stdout_path, timeout_seconds, cwd=directory)


def copy_reference(source, destination, maximum):
    digest = hashlib.sha256()
    copied = 0
    with open(source, "rb") as stream, open(destination, "xb") as out:
        while True:
            chunk = stream.read(min(1024 * 1024, maximum - copied + 1))
            if not chunk:
                break
            if copied + len(chunk) > maximum:
                raise BudgetError("reference_size_limit")
            out.write(chunk)
            digest.update(chunk)
            copied += len(chunk)
        out.flush()
        os.fsync(out.fileno())
    return digest.hexdigest()


class StageFailure(Exception):
    pass


def execute(args, budget=None, limits_applied=False):
    payload = {
        "schema_version": 1, "pipeline": "python-wrapper", "mode": args.mode,
        "pipeline_status": "failed", "timestamp": datetime.now(timezone.utc).isoformat(),
        "input": os.path.abspath(args.input), "output_dir": None,
        "stages": [], "outputs": {}, "errors": [], "warnings": [], "tools": {},
    }

    def error(stage, code, message, status="failed"):
        payload["pipeline_status"] = status
        payload["errors"].append({"stage": stage, "code": code, "message": message})
        payload["warnings"].append(message)
        payload["error"] = message

    try:
        budget = budget or Budget.from_env()
    except BudgetError as exc:
        error("resource_budget", exc.code, "resource budget configuration invalid")
        payload["stages"].append({"name": "resource_budget", "status": "failed", "error_code": exc.code})
        return payload, 1

    payload["resource_budget"] = {
        "file_bytes": budget.file_bytes, "reference_bytes": budget.reference_bytes,
        "expanded_input_bytes": budget.input_bytes,
        "tool_stdout_bytes": budget.stdout_bytes, "tool_stderr_bytes": budget.stderr_bytes,
        "file_enforcement": "kernel_rlimit_fsize" if limits_applied else "not_applied_library_call",
        "workspace_aggregate_enforcement": "pending", "group_mode": os.environ.get("BIOZERO_PIPELINE_GROUP_MODE", "owned"),
    }

    def command(name, cmd, artifacts=(), stdout_path=None):
        result = run_cmd(cmd, stdout_path, parse_timeout_seconds())
        record = {"name": name, "status": "succeeded", "returncode": result.returncode}
        payload["stages"].append(record)
        if result.returncode:
            code = getattr(result, "error_code", "") or ("timeout" if result.returncode == 124 else "tool_failed")
            record.update(status="failed", error_code=code)
            error(name, code, f"{name}: {(result.stderr or '').strip()[:4096]}")
            raise StageFailure()
        for path in artifacts:
            if not Path(path).is_file() or not Path(path).stat().st_size:
                record.update(status="failed", error_code="missing_output")
                error(name, "missing_output", f"{name}: required output missing or empty: {path}")
                raise StageFailure()
        return result

    try:
        if not Path(args.input).is_file():
            raise ValueError("input FASTQ not found")
        if Path(args.input).stat().st_size > budget.input_bytes:
            raise ValueError("input exceeds configured size limit")
        input_path = str(Path(args.input).resolve())
        count, length, lines = fastq_stats(input_path, budget)
        payload.update(read_count=count, avg_read_length=length, line_count=lines,
                       byte_count=Path(args.input).stat().st_size, sha256=sha256_file(args.input))
        payload["stages"].append({"name": "validate_fastq", "status": "succeeded"})
    except (OSError, ValueError, EOFError, zlib.error) as exc:
        error("validate_fastq", "invalid_input", str(exc))
        payload["stages"].append({"name": "validate_fastq", "status": "failed", "error_code": "invalid_input"})
        return payload, 1

    if args.mode == "stats":
        payload["pipeline_status"] = "succeeded"
        payload["stages"].append({"name": "fastq_stats", "status": "succeeded"})
        return payload, 0

    tools = {name: shutil.which(name) for name in ("minimap2", "samtools", "bcftools")}
    payload["tools"] = {name: bool(path) for name, path in tools.items()}
    missing = [name for name, path in tools.items() if not path]
    if not args.reference or not Path(args.reference).is_file():
        error("prerequisites", "missing_reference", "variants mode requires an existing FASTA reference", "incomplete")
    if missing:
        error("prerequisites", "missing_tool", "required tools unavailable: " + ", ".join(missing), "incomplete")
    if payload["errors"]:
        payload["stages"].append({"name": "prerequisites", "status": "incomplete"})
        return payload, 2
    payload["stages"].append({"name": "prerequisites", "status": "succeeded"})

    try:
        parent = args.out_dir or os.environ.get("BIOZERO_PIPELINE_OUT_DIR")
        if parent:
            Path(parent).mkdir(parents=True, exist_ok=True)
        directory = Path(tempfile.mkdtemp(prefix="biozero-run-", dir=parent)).resolve()
        payload["output_dir"] = str(directory.resolve())
        reference = directory / "reference.fa"
        if Path(args.reference).stat().st_size > budget.reference_bytes:
            error("reference_copy", "reference_size_limit", "reference exceeds configured copy limit")
            payload["stages"].append({"name": "reference_copy", "status": "failed", "error_code": "reference_size_limit"})
            return payload, 1
        payload["reference_sha256"] = copy_reference(args.reference, reference, budget.reference_bytes)
        command("reference_index", [tools["samtools"], "faidx", str(reference)], [str(reference) + ".fai"])
        sam = directory / "alignment.sam"
        bam = directory / "alignment.sorted.bam"
        command("align", [tools["minimap2"], "-a", "-x", "sr", "-t", "1", str(reference), input_path], [sam], sam)
        command("sort", [tools["samtools"], "sort", "-@", "1", "-T", str(directory / "sort-tmp"), "-o", str(bam), str(sam)], [bam])
        command("bam_check", [tools["samtools"], "quickcheck", "-v", str(bam)])
        command("bam_index", [tools["samtools"], "index", str(bam)], [str(bam) + ".bai"])
        # Materialize upstream output instead of a live pipe: each child
        # is waited for and checked, including mpileup failure or timeout.
        pileup = directory / "pileup.bcf"
        command("mpileup", [tools["bcftools"], "mpileup", "-Ob", "-o", str(pileup), "-f", str(reference), str(bam)], [pileup])
        raw_vcf = directory / "variants.raw.vcf.gz"
        command("call", [tools["bcftools"], "call", "-mv", "-Oz", "-o", str(raw_vcf), str(pileup)], [raw_vcf])
        vcf = directory / "variants.vcf.gz"
        command("normalize", [tools["bcftools"], "norm", "-f", str(reference), "-m", "-any", "-Oz", "-o", str(vcf), str(raw_vcf)], [vcf])
        command("vcf_index", [tools["bcftools"], "index", str(vcf)], [str(vcf) + ".csi"])
        # Successful decoding verifies the compressed output even for zero calls.
        decoded = directory / "variants.vcf"
        command("vcf_check", [tools["bcftools"], "view", "-Ov", "-o", str(decoded), str(vcf)], [decoded])
        header, variant_count = False, 0
        with open(decoded, encoding="utf-8") as stream:
            for line in stream:
                header = header or line.startswith("#CHROM\t")
                variant_count += int(not line.startswith("#") and bool(line.strip()))
        if not header:
            error("vcf_check", "invalid_output", "decoded VCF lacks a column header")
            payload["stages"][-1].update(status="failed", error_code="invalid_output")
            raise StageFailure()
        payload["variant_count"] = variant_count
        payload["outputs"] = {"alignment_sam": str(sam), "alignment_bam": str(bam),
                              "variants_vcf": str(vcf), "variants_vcf_index": str(vcf) + ".csi",
                              "normalized_vcf": str(decoded)}
        payload["pipeline_status"] = "succeeded"
        return payload, 0
    except StageFailure:
        return payload, 1
    except BudgetError as exc:
        error("pipeline", exc.code, "resource budget exceeded or invalid")
        payload["stages"].append({"name": "pipeline", "status": "failed", "error_code": exc.code})
        return payload, 1
    except Exception as exc:
        code = "artifact_file_limit" if isinstance(exc, OSError) and exc.errno == errno.EFBIG else "execution_error"
        error("pipeline", code, str(exc))
        return payload, 1


def main(argv=None, enforce_limits=False):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", help="four-line FASTQ input, optionally .gz")
    parser.add_argument("--reference", help="FASTA required in variants mode")
    parser.add_argument("--out-dir", help="parent for a fresh run artifact directory")
    parser.add_argument("--mode", choices=("stats", "variants"), default="stats")
    args = parser.parse_args(argv)
    try:
        budget = Budget.from_env()
        if enforce_limits:
            os.umask(0o077)
            own_job_group()
            apply_kernel_file_limit(budget)
        payload, code = execute(args, budget, limits_applied=enforce_limits)
    except BudgetError as exc:
        payload = {"schema_version": 1, "pipeline": "python-wrapper", "mode": args.mode,
                   "pipeline_status": "failed", "timestamp": datetime.now(timezone.utc).isoformat(),
                   "input": os.path.abspath(args.input), "output_dir": None,
                   "stages": [{"name": "resource_budget", "status": "failed", "error_code": exc.code}],
                   "outputs": {}, "errors": [{"stage": "resource_budget", "code": exc.code,
                                               "message": "resource budget unavailable or invalid"}],
                   "warnings": [], "tools": {}}
        code = 1
    print(json.dumps(payload, indent=2))
    return code


if __name__ == "__main__":
    raise SystemExit(main(enforce_limits=True))
