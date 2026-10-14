# SPDX-License-Identifier: AGPL-3.0-only
"""Export synthetic allele presence without tool commands, paths or sample names."""
import hashlib
import importlib.util
import pathlib
import re

_EVALUATOR = pathlib.Path(__file__).resolve().parents[2] / "bio/benchmarks/evaluate_variants.py"
_SPEC = importlib.util.spec_from_file_location("biozero_public_vcf_evaluator", _EVALUATOR)
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)


def export_alleles(source, reference_path, destination):
    """Derive eight-column VCF; retain only the normalized allele set we evaluate.

    Original genotypes, quality, filters and annotations are intentionally absent.
    The original source remains private, identified by its byte digest.
    """
    source, reference_path, destination = map(pathlib.Path, (source, reference_path, destination))
    reference = _MODULE.read_reference(reference_path)
    alleles = _MODULE.read_variants(source, reference)
    if any(not re.fullmatch(r"[A-Za-z0-9_.-]+", chrom) for chrom, _, _, _ in alleles):
        raise ValueError("unsafe public contig identifier")
    lines = ["##fileformat=VCFv4.2",
             "##source=BioZero-normalized-allele-presence-export",
             "##BioZeroScope=Allele presence only; genotype quality filters and annotations omitted",
             "#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO"]
    lines.extend(f"{chrom}\t{pos}\t.\t{ref}\t{alt}\t.\t.\t."
                 for chrom, pos, ref, alt in sorted(alleles))
    # Exclusive creation also rejects existing symlinks/hardlinks to originals.
    with destination.open("x", encoding="ascii") as stream:
        stream.write("\n".join(lines) + "\n")
    if _MODULE.read_variants(destination, reference) != alleles:
        destination.unlink()
        raise ValueError("public export changed the normalized allele set")
    return {"schema_version": 1, "format": "VCFv4.2",
            "scope": "normalized allele presence; no genotype, quality, filter or annotation preservation",
            "normalized_allele_count": len(alleles), "alleles_preserved": True,
            "source_vcf_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "reference_sha256": hashlib.sha256(reference_path.read_bytes()).hexdigest(),
            "export_vcf_sha256": hashlib.sha256(destination.read_bytes()).hexdigest()}
