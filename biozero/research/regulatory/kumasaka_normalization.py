"""Offline, pre-reference preparation for the frozen SCI02 Kumasaka contract.

Outputs contain public-source raw rows and belong in private research storage.
No DNA, final reference allele, final score rank or review approval is produced.
"""
from collections import Counter, defaultdict
import gzip
import hashlib
import json
import math
import os
from pathlib import Path
import stat
import zlib

import lift_chain

PROTOCOL_SEED = "SCI02-GM12878-ATAC-FP32-v1:20261014"
PREPOOL_DOMAIN = "SCI02-KUMASAKA-PREPOOL-v1"
SOURCE_HEADER = ("Peak", "Chr", "Pos", "RsID", "Ref", "Alt", "AF", "Inside_Peak",
                 "P_Lead", "Beta", "SE", "Log10_BF")
PEAK_HEADER = ("#Chr", "Pos_Left", "Pos_Right", "Peak", "GC", "Peak_Height",
               "P_caQTL", "PMR", "P_eQTL_Coloc")
CHR_NAMES = {str(i): "chr" + str(i) for i in range(1, 23)}
SELECTED_CHROMS = ("chr8", "chr9")
MAX_COMPRESSED_BYTES = 50 << 20
MAX_EXPANDED_BYTES = 512 << 20
MAX_ROWS = 1000000
MAX_LINE_BYTES = 8192
PREPOOL_SIZE = 256
EFFECT_SOURCE_URL = "https://zenodo.org/api/records/1405945/files/README.txt/content"
COMPLEMENT = str.maketrans("ACGT", "TGCA")


class NormalizationError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def _sha(value):
    if (not isinstance(value, str) or len(value) != 64
            or any(c not in "0123456789abcdef" for c in value)):
        raise NormalizationError("sha256_invalid")


def _limit(value, ceiling):
    if type(value) is not int or not 0 < value <= ceiling:
        raise NormalizationError("limit_invalid")


def _int(value, minimum=0):
    if not value or any(c not in "0123456789" for c in value):
        raise NormalizationError("integer_invalid")
    try:
        result = int(value)
    except ValueError as exc:
        raise NormalizationError("integer_invalid") from exc
    if result < minimum or str(result) != value:
        raise NormalizationError("integer_invalid")
    return result


def _float(value, minimum=None, maximum=None):
    try:
        result = float(value)
    except (ValueError, OverflowError) as exc:
        raise NormalizationError("number_invalid") from exc
    if not math.isfinite(result):
        raise NormalizationError("number_nonfinite")
    if minimum is not None and result < minimum or maximum is not None and result > maximum:
        raise NormalizationError("number_out_of_range")
    return result


def _chrom(value):
    if value not in CHR_NAMES:
        raise NormalizationError("source_chromosome_invalid")
    return CHR_NAMES[value]


def _annotations(specifications):
    """Nonessential annotations never gate technical/experimental eligibility."""
    values, states = {}, {}
    for name, raw, minimum, maximum in specifications:
        try:
            values[name] = _float(raw, minimum, maximum)
        except NormalizationError:
            values[name] = None
            states[name] = "missing" if raw in ("", ".", "NA", "NaN", "nan") else "invalid"
    return values, states


def _parent(path):
    """Walk every caller-supplied ancestor without symlinks, retaining a dir FD."""
    if not isinstance(path, (str, Path)) or not str(path):
        raise NormalizationError("path_invalid")
    target = Path(os.path.abspath(path))
    descriptor = None
    try:
        descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        for part in target.parent.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor, target.name
    except (OSError, ValueError) as exc:
        if descriptor is not None:
            os.close(descriptor)
        raise NormalizationError("private_path_open_failed") from exc


def _private_open(path):
    parent, name = _parent(path)
    try:
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    except (OSError, ValueError) as exc:
        raise NormalizationError("private_file_open_failed") from exc
    finally:
        os.close(parent)
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        os.close(descriptor)
        raise NormalizationError("private_file_not_regular")
    if stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_uid != os.getuid():
        os.close(descriptor)
        raise NormalizationError("private_file_not_owned_600")
    return os.fdopen(descriptor, "rb")


class _Compressed:
    def __init__(self, handle, maximum):
        self.handle, self.maximum, self.count = handle, maximum, 0
        self.sha = hashlib.sha256()

    def read(self, size=-1):
        remaining = self.maximum - self.count + 1
        raw = self.handle.read(remaining if size < 0 else min(size, remaining))
        self.count += len(raw)
        self.sha.update(raw)
        if self.count > self.maximum:
            raise NormalizationError("compressed_size_exceeded")
        return raw


def _table(path, expected_sha, header, consume_row, budget, limits):
    """Verify/hash and fully CRC-read the same FD; limits aggregate both tables."""
    with _private_open(path) as handle:
        first = _Compressed(handle, limits["compressed"] - budget["compressed_bytes"])
        while first.read(1 << 20):
            pass
        actual = first.sha.hexdigest()
        if actual != expected_sha:
            raise NormalizationError("sha256_mismatch")
        handle.seek(0)
        second = _Compressed(handle, first.count)
        row_number = 0
        expanded_count = 0
        try:
            with gzip.GzipFile(fileobj=second, mode="rb") as expanded:
                header_read = False
                while True:
                    remaining = limits["expanded"] - budget["expanded_bytes"]
                    raw = expanded.readline(min(MAX_LINE_BYTES + 1, remaining + 1))
                    if not raw:
                        break
                    budget["expanded_bytes"] += len(raw)
                    expanded_count += len(raw)
                    if budget["expanded_bytes"] > limits["expanded"]:
                        raise NormalizationError("expanded_size_exceeded")
                    if len(raw) > MAX_LINE_BYTES:
                        raise NormalizationError("line_size_exceeded")
                    try:
                        values = raw.rstrip(b"\r\n").decode("ascii").split("\t")
                    except UnicodeDecodeError as exc:
                        raise NormalizationError("table_encoding_invalid") from exc
                    if not header_read:
                        if tuple(values) != header:
                            raise NormalizationError("table_header_mismatch")
                        header_read = True
                        continue
                    row_number += 1
                    budget["rows"] += 1
                    if budget["rows"] > limits["rows"]:
                        raise NormalizationError("row_limit_exceeded")
                    consume_row(row_number, values, hashlib.sha256(raw).hexdigest())
                if not header_read:
                    raise NormalizationError("table_empty")
        except NormalizationError:
            raise
        except (OSError, EOFError, ValueError, zlib.error) as exc:
            raise NormalizationError("gzip_invalid") from exc
        if second.count != first.count or second.sha.hexdigest() != actual:
            raise NormalizationError("source_changed_during_read")
        budget["compressed_bytes"] += first.count
        return {"sha256": actual, "compressed_bytes": first.count,
                "expanded_bytes": expanded_count, "rows": row_number, "header": list(header)}


def _source(values):
    if len(values) != len(SOURCE_HEADER):
        raise NormalizationError("column_count_invalid")
    peak, chrom, position, rsid, ref, alt, af, location, p_lead, beta, se, log_bf = values
    annotations, states = _annotations((("p_lead", p_lead, 0, 1), ("log_bf", log_bf, None, None)))
    row = {"peak_id": _int(peak, 1), "chrom": _chrom(chrom), "position": _int(position, 1),
           "rsid": rsid, "ref": ref, "alt": alt, "af": _float(af, 0, 1),
           "location": _int(location), "beta": _float(beta), "se": _float(se), **annotations}
    if states:
        row["annotation_states"] = states
    if row["location"] not in (0, 1, 2):
        raise NormalizationError("location_enum_invalid")
    if row["se"] <= 0:
        raise NormalizationError("standard_error_not_positive")
    return row


def _peak(values):
    if len(values) != len(PEAK_HEADER):
        raise NormalizationError("column_count_invalid")
    chrom, left, right, peak, gc, height, p_caqtl, pmr, p_coloc = values
    annotations, states = _annotations((("gc", gc, 0, 100), ("height", height, 0, None),
        ("p_caqtl", p_caqtl, 0, 1), ("pmr", pmr, 0, 1), ("p_eqtl_coloc", p_coloc, 0, 1)))
    result = {"peak_id": _int(peak, 1), "chrom": _chrom(chrom), "start": _int(left),
              "end": _int(right), **annotations}
    if states:
        result["annotation_states"] = states
    if result["end"] <= result["start"]:
        raise NormalizationError("peak_interval_invalid")
    return result


def prepool_rank(candidate, source_sha256, seed=PROTOCOL_SEED):
    """The contract003 presample hash, distinct from the final SCI02 rank."""
    if seed != PROTOCOL_SEED:
        raise NormalizationError("seed_not_frozen")
    fields = [PREPOOL_DOMAIN, seed, source_sha256, candidate["origin_row_id"], "hg38",
              candidate["mapped_chrom"], str(candidate["mapped_position_1based"]),
              candidate["oriented_source_ref"], candidate["oriented_source_alt"]]
    return hashlib.sha256("\n".join(fields).encode("utf-8")).hexdigest()


def prepare_precandidates(source_path, peaks_path, chain_path, *, source_sha256,
                          peaks_sha256, chain_sha256, seed=PROTOCOL_SEED,
                          max_compressed_bytes=MAX_COMPRESSED_BYTES,
                          max_expanded_bytes=MAX_EXPANDED_BYTES, max_rows=MAX_ROWS):
    """Prepare all row outcomes and freeze at most256, with references pending.

    Production pins/permission/build receipts are the operator's responsibility.
    Even a nonempty result cannot authorize final normalization or inference.
    """
    for value in (source_sha256, peaks_sha256, chain_sha256):
        _sha(value)
    if seed != PROTOCOL_SEED:
        raise NormalizationError("seed_not_frozen")
    for value, ceiling in ((max_compressed_bytes, MAX_COMPRESSED_BYTES),
                           (max_expanded_bytes, MAX_EXPANDED_BYTES), (max_rows, MAX_ROWS)):
        _limit(value, ceiling)
    limits = {"compressed": max_compressed_bytes, "expanded": max_expanded_bytes, "rows": max_rows}
    budget = {"compressed_bytes": 0, "expanded_bytes": 0, "rows": 0}
    # Anchor the chain loader under a directory descriptor obtained without
    # caller-supplied symlink ancestors. Its final O_NOFOLLOW and SHA checks still apply.
    parent, name = _parent(chain_path)
    try:
        index = lift_chain.load_chain(Path("/proc/self/fd") / str(parent) / name,
                                      expected_sha256=chain_sha256)
    except lift_chain.ChainError as exc:
        raise NormalizationError("chain_" + exc.code) from exc
    finally:
        os.close(parent)
    peaks, peak_outcomes, duplicate_peaks = {}, [], set()
    seen_peak_ids = set()

    def peak_row(number, values, row_sha):
        record = {"row_number": number, "row_sha256": row_sha, "raw_values": values,
                  "status": "validated", "reasons": []}
        peak_outcomes.append(record)
        # Even malformed repeated metadata cannot rescue an ambiguous peak ID.
        try:
            peak_id = _int(values[3], 1)
            record["peak_id"] = peak_id
            if peak_id in seen_peak_ids:
                duplicate_peaks.add(peak_id)
            seen_peak_ids.add(peak_id)
        except (NormalizationError, IndexError):
            pass
        try:
            parsed = _peak(values)
        except NormalizationError as exc:
            record.update(status="excluded", reasons=[exc.code])
            return
        peaks.setdefault(parsed["peak_id"], {**parsed, "raw_values": values,
                                            "source_row_number": number, "source_row_sha256": row_sha})
        if parsed.get("annotation_states"):
            record["annotation_states"] = parsed["annotation_states"]

    peak_receipt = _table(peaks_path, peaks_sha256, PEAK_HEADER, peak_row, budget, limits)
    for record in peak_outcomes:
        if record.get("peak_id") in duplicate_peaks:
            record["status"] = "excluded"
            record["reasons"].append("duplicate_peak_id")
    outcomes, eligible, peak_variants, locus_peaks, associations = [], {}, defaultdict(set), defaultdict(set), Counter()

    def source_row(number, values, row_sha):
        record = {"source_row_number": number, "source_row_sha256": row_sha,
                  "origin_row_id": source_sha256 + ":row:" + str(number),
                  "raw_values": values, "status": "excluded", "reasons": []}
        outcomes.append(record)
        try:
            record["peak_id"] = _int(values[0], 1)
        except (NormalizationError, IndexError):
            pass
        try:
            parsed = _source(values)
        except NormalizationError as exc:
            record["reasons"].append(exc.code)
            return
        record["source_locus"] = [parsed["chrom"], parsed["position"]]
        if parsed.get("annotation_states"):
            record["annotation_states"] = parsed["annotation_states"]
        if parsed["location"] != 1:
            record["reasons"].append("not_focal_peak")
        if parsed["ref"] not in tuple("ACGT") or parsed["alt"] not in tuple("ACGT") or parsed["ref"] == parsed["alt"]:
            record["reasons"].append("not_biallelic_snv")
        if record["reasons"]:
            return
        eligible[number - 1] = parsed
        variant = (parsed["chrom"], parsed["position"], parsed["ref"], parsed["alt"])
        peak_variants[parsed["peak_id"]].add(variant)
        locus_peaks[variant[:2]].add(parsed["peak_id"])
        associations[(parsed["peak_id"], *variant)] += 1

    source_receipt = _table(source_path, source_sha256, SOURCE_HEADER, source_row, budget, limits)
    tied_peaks = {peak_id for peak_id, variants in peak_variants.items() if len(variants) > 1}
    multi_peak_loci = {locus for locus, peak_ids in locus_peaks.items() if len(peak_ids) > 1}
    mapped = []
    for i, record in enumerate(outcomes):
        if record.get("peak_id") in tied_peaks:
            record["reasons"].append("tied_focal_peak")
        if tuple(record.get("source_locus", ())) in multi_peak_loci:
            record["reasons"].append("multiple_focal_peaks_for_snp")
        if i not in eligible:
            continue
        row = eligible[i]
        association = (row["peak_id"], row["chrom"], row["position"], row["ref"], row["alt"])
        if associations[association] > 1:
            record["reasons"].append("duplicate_source_association")
        if row["chrom"] not in SELECTED_CHROMS:
            record["reasons"].append("source_chromosome_not_selected")
        if row["peak_id"] in duplicate_peaks:
            record["reasons"].append("duplicate_peak_id")
        peak = peaks.get(row["peak_id"])
        if peak is None:
            record["reasons"].append("peak_missing_or_invalid")
        elif peak["chrom"] != row["chrom"]:
            record["reasons"].append("peak_chromosome_mismatch")
        elif not peak["start"] <= row["position"] - 1 < peak["end"]:
            record["reasons"].append("source_snp_outside_focal_peak")
        if record["reasons"]:
            continue
        try:
            mapping = index.map_variant_peak(row["chrom"], row["position"], peak["start"], peak["end"],
                                             allowed_chromosomes=SELECTED_CHROMS)
        except lift_chain.ChainError as exc:
            record["reasons"].append("mapping_" + exc.code)
            continue
        minus = mapping["snp"]["strand"] == "-"
        candidate = {"candidate_id": "kumasaka1405945:row:" + str(i + 1),
                     "origin_row_id": record["origin_row_id"], "source_row_number": i + 1,
                     "source_row_sha256": record["source_row_sha256"],
                     "source_chrom": row["chrom"], "source_position_1based": row["position"],
                     "source_ref": row["ref"], "source_alt": row["alt"],
                     "source_rsid": row["rsid"], "source_raw_values": record["raw_values"],
                     "mapped_chrom": mapping["snp"]["target_chrom"],
                     "mapped_position_1based": mapping["snp"]["target_start"] + 1,
                     "oriented_source_ref": row["ref"].translate(COMPLEMENT) if minus else row["ref"],
                     "oriented_source_alt": row["alt"].translate(COMPLEMENT) if minus else row["alt"],
                     "source_effect": {"value": row["beta"], "standard_error": row["se"],
                        "effect_allele": row["alt"], "other_allele": row["ref"],
                        "orientation_known": True,
                        "orientation_source": EFFECT_SOURCE_URL,
                        "definition": "Source ALT-minus-REF regression slope for GBR100 LCL focal accessibility"},
                     "source_af": row["af"], "source_p_lead": row["p_lead"],
                     "source_log10_bf": row["log_bf"],
                     "source_annotation_states": row.get("annotation_states", {}),
                     "peak": peak, "mapping": mapping}
        candidate["prepool_rank_sha256"] = prepool_rank(candidate, source_sha256, seed)
        mapped.append(candidate)
        record["status"] = "mapped_not_presampled"
    mapped.sort(key=lambda row: (row["prepool_rank_sha256"], row["origin_row_id"]))
    precandidates = mapped[:PREPOOL_SIZE]
    for row in precandidates:
        outcomes[row["source_row_number"] - 1]["status"] = "precandidate"
    status = ("no_precandidates" if not precandidates else "insufficient_precandidates"
              if len(precandidates) < 110 else "precandidates_frozen_awaiting_references")
    inputs = {"source": source_receipt, "peaks": peak_receipt,
              "chain": {"sha256": index.source_sha256, "chains": index.chain_count, "blocks": index.block_count}}
    policy = {"domain": PREPOOL_DOMAIN, "seed": seed, "maximum_precandidates": PREPOOL_SIZE,
              "source_header": list(SOURCE_HEADER), "peak_header": list(PEAK_HEADER),
              "chromosomes": list(SELECTED_CHROMS), "ties": "exclude_all_rows_of_multilead_focal_peaks",
              "multiple_focal_peaks": "exclude_all_rows_of_source_snp_locus",
              "mapping": "same_chromosome_unique_full_single_ungapped_block_for_snp_and_peak",
              "strand": "complement_both_alleles_without_negating_raw_beta",
              "optional_annotations": "missing_or_invalid_numeric_annotation_is_None_with_raw_and_state_preserved; never eligibility_filter",
              "resource_limits": {"source_and_peaks_aggregate_compressed_bytes": max_compressed_bytes,
                  "source_and_peaks_aggregate_expanded_bytes": max_expanded_bytes,
                  "source_and_peaks_aggregate_rows": max_rows,
                  "chain_compressed_bytes": lift_chain.MAX_COMPRESSED_BYTES,
                  "chain_expanded_bytes": lift_chain.MAX_EXPANDED_BYTES},
              "rank_fields": ["domain", "seed", "source_sha256", "origin_row_id", "hg38",
                              "mapped_chrom", "mapped_position_1based", "oriented_source_ref", "oriented_source_alt"],
              "rank_tiebreak": "origin_row_id", "replenishment": False,
              "references_checked": False, "final_selection_produced": False}
    freeze = {"schema_version": 1, "status": status, "inputs": inputs, "policy": policy,
              "producer_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "lift_chain_sha256": hashlib.sha256(Path(lift_chain.__file__).read_bytes()).hexdigest(),
              "precandidates": precandidates}
    counts = {"source_rows": len(outcomes), "peak_rows": len(peak_outcomes),
              "initial_eligible_focal_snv_rows": len(eligible), "tied_focal_peaks": len(tied_peaks),
              "multiple_focal_peak_snp_loci": len(multi_peak_loci), "duplicate_peak_ids": len(duplicate_peaks),
              "mapped_rows_before_presample": len(mapped), "precandidates": len(precandidates),
              "status_counts": dict(sorted(Counter(row["status"] for row in outcomes).items())),
              "reason_counts": dict(sorted(Counter(code for row in outcomes for code in row["reasons"]).items())),
              "source_annotation_state_counts": dict(sorted(Counter(
                  name + ":" + state for row in outcomes for name, state in row.get("annotation_states", {}).items()).items())),
              "peak_annotation_state_counts": dict(sorted(Counter(
                  name + ":" + state for row in peak_outcomes for name, state in row.get("annotation_states", {}).items()).items())),
              "biological_loci_inferred": 0}
    return {"schema_version": 1, "status": status, "inputs": inputs, "counts": counts,
            "resource_counts": budget, "outcomes": outcomes, "peak_outcomes": peak_outcomes,
            "precandidates": precandidates, "freeze": freeze,
            "freeze_sha256": hashlib.sha256(canonical_bytes(freeze)).hexdigest(),
            "scope": "Pre-reference source mapping only; GBR LCL transfer proxy; rank64 training overlap unknown"}
