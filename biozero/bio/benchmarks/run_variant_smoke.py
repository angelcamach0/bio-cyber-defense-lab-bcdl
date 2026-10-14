#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Run BZ-EXP-001 twice, evaluate both, and verify a controlled invalid input."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import resource
import shutil
import subprocess
import sys
import tempfile
import time

from evaluate_variants import evaluate, read_reference, read_variants


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", help="parent for preserved experiment evidence")
    args = parser.parse_args()
    bio = Path(__file__).resolve().parent.parent
    fixture = bio / "fixtures" / "variant-smoke"
    if args.out_dir:
        Path(args.out_dir).mkdir(parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="bz-exp001-", dir=args.out_dir))
    evidence = {"experiment_id": "BZ-EXP-001", "started_at": datetime.now(timezone.utc).isoformat(),
                "architecture": platform.machine(), "platform": platform.platform(),
                "python_version": platform.python_version(), "evidence_dir": str(output),
                "tools": {}, "runs": [], "scope": "synthetic haploid SNP allele presence only"}
    for tool in ("minimap2", "samtools", "bcftools"):
        if shutil.which(tool):
            version = subprocess.run([tool, "--version"], capture_output=True, text=True,
                                     encoding="utf-8", errors="replace", timeout=10)
            evidence["tools"][tool] = (version.stdout or version.stderr).splitlines()[0]
    try:
        for label in ("a", "b", "invalid"):
            start = time.monotonic()
            command = [sys.executable, str(bio / "pipeline" / "pipeline.py"),
                       str(fixture / ("invalid.fastq" if label == "invalid" else "reads.fastq")),
                       "--mode", "variants", "--reference", str(fixture / "reference.fa"),
                       "--out-dir", str(output / label)]
            result = subprocess.run(command, capture_output=True, text=True, timeout=7200)
            (output / f"run-{label}.json").write_text(result.stdout)
            payload = json.loads(result.stdout)
            evidence["runs"].append({"label": label, "elapsed_seconds": time.monotonic() - start,
                                     "exit_code": result.returncode, "payload": payload})
        a, b, invalid = evidence["runs"]
        if any(run["exit_code"] != 0 or run["payload"]["pipeline_status"] != "succeeded" for run in (a, b)):
            raise ValueError("both variant pipelines must succeed before scientific evaluation")
        reference = read_reference(fixture / "reference.fa")
        evaluation = evaluate(read_variants(fixture / "expected.vcf", reference),
                              read_variants(a["payload"]["outputs"]["normalized_vcf"], reference),
                              read_variants(b["payload"]["outputs"]["normalized_vcf"], reference))
        evidence["evaluation"] = evaluation
        evidence["controlled_failure_passed"] = (
            invalid["exit_code"] == 1 and invalid["payload"]["pipeline_status"] == "failed"
            and any(error["code"] == "invalid_input" for error in invalid["payload"]["errors"]))
        evidence["experiment_status"] = "passed" if (
            evaluation["evaluation_status"] == "passed" and evaluation["tp"] == 3
            and evidence["controlled_failure_passed"]) else "failed"
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired) as exc:
        evidence.update(experiment_status="failed", error=str(exc))
    evidence["peak_child_rss_kib_linux"] = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    evidence["memory_scope"] = "maximum child RSS across the sequential experiment; Linux KiB, not summed RAM"
    (output / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print(json.dumps(evidence, indent=2))
    return 0 if evidence["experiment_status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
