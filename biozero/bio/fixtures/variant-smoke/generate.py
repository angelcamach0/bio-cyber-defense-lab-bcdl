#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic synthetic haploid SNP fixture; no human or patient data."""
import argparse
import hashlib
import json
from pathlib import Path
import random


def generate(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    rng = random.Random(20261014)
    reference = "".join(rng.choice("ACGT") for _ in range(6000))
    changes = {1001: "", 2501: "", 4501: ""}
    for position in changes:
        changes[position] = next(base for base in "ACGT" if base != reference[position - 1])
    sample = list(reference)
    for position, allele in changes.items():
        sample[position - 1] = allele
    sample = "".join(sample)
    (directory / "reference.fa").write_text(
        ">synthetic\n" + "\n".join(reference[i:i + 80] for i in range(0, len(reference), 80)) + "\n")
    complement = str.maketrans("ACGT", "TGCA")
    with (directory / "reads.fastq").open("w") as stream:
        for start in range(0, len(reference) - 149, 5):
            sequence = sample[start:start + 150]
            # Balanced strand support, ~30x total coverage away from boundaries.
            if (start // 5) % 2:
                sequence = sequence.translate(complement)[::-1]
            stream.write(f"@synthetic_{start}\n{sequence}\n+\n{'I' * len(sequence)}\n")
    with (directory / "expected.vcf").open("w") as stream:
        stream.write("##fileformat=VCFv4.2\n##contig=<ID=synthetic,length=6000>\n")
        stream.write("#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n")
        for position, allele in changes.items():
            stream.write(f"synthetic\t{position}\t.\t{reference[position - 1]}\t{allele}\t.\tPASS\t.\n")
    (directory / "invalid.fastq").write_text("@truncated\nACGT\n+\n")
    hashes = {name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
              for name in ("reference.fa", "reads.fastq", "expected.vcf", "invalid.fastq")}
    (directory / "manifest.json").write_text(json.dumps({
        "experiment_id": "BZ-EXP-001", "seed": 20261014, "reference_length": 6000,
        "read_length": 150, "read_count": 1171, "expected_snp_count": 3,
        "scope": "Synthetic error-free haploid SNP presence only; no genotype, indel, human-genome, or clinical claims.",
        "sha256": hashes,
    }, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", default=str(Path(__file__).parent))
    generate(parser.parse_args().out_dir)
