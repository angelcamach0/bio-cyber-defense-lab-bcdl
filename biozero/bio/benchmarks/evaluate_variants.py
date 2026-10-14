#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Compare normalized VCF allele presence with synthetic truth and another run.

Symbolic and breakend alleles are unsupported. Genotypes, QUAL and FILTER are
not evaluated: every submitted allele is counted, without silently filtering.
This small-reference evaluator is intended for the smoke fixture, not WGS.
"""
import argparse
import gzip
import json


def read_reference(path):
    sequences = {}
    name = None
    with open(path, encoding="ascii") as stream:
        for line in stream:
            line = line.strip()
            if not line:
                continue
            if line.startswith(">"):
                name = line[1:].split()[0]
                if name in sequences:
                    raise ValueError("duplicate reference contig")
                sequences[name] = ""
            elif name:
                sequences[name] += line.upper()
            else:
                raise ValueError("invalid reference FASTA")
    if not sequences or any(not seq for seq in sequences.values()):
        raise ValueError("empty reference sequence")
    return sequences


def normalize_variant(chrom, pos, ref, alt, reference):
    ref, alt = ref.upper(), alt.upper()
    if not ref or not alt or any(base not in "ACGTN" for base in ref + alt):
        raise ValueError("unsupported nonliteral allele")
    sequence = reference.get(chrom)
    if sequence is None or pos < 1 or sequence[pos - 1:pos - 1 + len(ref)] != ref:
        raise ValueError("VCF reference allele/coordinate mismatch")
    if ref == alt:
        raise ValueError("ALT equals REF")
    # Trim shared suffixes, then left-align indels in repeated sequence.
    while len(ref) > 1 and len(alt) > 1 and ref[-1] == alt[-1]:
        ref, alt = ref[:-1], alt[:-1]
    while len(ref) != len(alt) and pos > 1 and ref[-1] == alt[-1]:
        previous = sequence[pos - 2]
        ref, alt, pos = previous + ref[:-1], previous + alt[:-1], pos - 1
    while len(ref) > 1 and len(alt) > 1 and ref[0] == alt[0]:
        ref, alt, pos = ref[1:], alt[1:], pos + 1
    return chrom, pos, ref, alt


def read_variants(path, reference):
    opener = gzip.open if str(path).endswith(".gz") else open
    variants = set()
    header = False
    with opener(path, "rt", encoding="ascii") as stream:
        for line in stream:
            if line.startswith("#CHROM\t"):
                header = True
            if line.startswith("#") or not line.strip():
                continue
            if not header:
                raise ValueError("VCF missing column header")
            fields = line.rstrip().split("\t")
            if len(fields) < 8:
                raise ValueError("VCF record requires eight columns")
            for alt in fields[4].split(","):
                variants.add(normalize_variant(fields[0], int(fields[1]), fields[3], alt, reference))
    if not header:
        raise ValueError("VCF missing column header")
    return variants


def evaluate(expected, observed, repeated=None):
    tp, fp, fn = len(expected & observed), len(observed - expected), len(expected - observed)
    report = {"tp": tp, "fp": fp, "fn": fn,
              "precision": tp / (tp + fp) if tp + fp else None,
              "recall": tp / (tp + fn) if tp + fn else None,
              "unexpected": sorted(observed - expected), "missing": sorted(expected - observed),
              "scope": "normalized allele presence; no genotype or clinical validation"}
    if repeated is not None:
        report["reproducible_callset"] = observed == repeated
        report["run_difference"] = sorted(observed ^ repeated)
    report["evaluation_status"] = "passed" if not fp and not fn and (repeated is None or observed == repeated) else "failed"
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", required=True)
    parser.add_argument("--expected", required=True)
    parser.add_argument("--observed", required=True)
    parser.add_argument("--repeat", help="normalized VCF from an independent second run")
    args = parser.parse_args()
    try:
        reference = read_reference(args.reference)
        report = evaluate(read_variants(args.expected, reference), read_variants(args.observed, reference),
                          read_variants(args.repeat, reference) if args.repeat else None)
    except (OSError, ValueError, EOFError) as exc:
        report = {"evaluation_status": "failed", "error": str(exc)}
    print(json.dumps(report, indent=2))
    return 0 if report["evaluation_status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
