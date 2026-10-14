#!/usr/bin/env python3
"""Offline SCI02 normalized-ledger adapter; no dataset parser or downloader.

Validation uses only the standard library. Explicit --run loads the pinned FP32
trunk/head in a supervised subprocess, reusing the upstream both-strands forward.
Instrumentation controls never establish biological feasibility. All row outcomes
and predictions stay in a private report, including invalid frozen slots.
"""
import argparse
import collections
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import resource
import stat
import sys
import time
import uuid

import model_probe as probe
from checkpoint_fetch import atomic_json, load_manifest, SOURCE_COMMIT

HERE = Path(__file__).resolve().parent
PROTOCOL_SHA256 = "8c3f80a5b59eb3d165764bb5596e1b0451248bd2b0641d430fa6378b73a9126c"
PROTOCOL_ID = "SCI02-GM12878-ATAC-FP32-v1"
TRACK_IDS = [59676, 59678, 61819, 61820, 61821, 61822, 65259, 65260, 65262]
TRACK_INDICES = [10233, 10234, 10387, 10388, 10389, 10390, 12556, 12557, 12558]
ANNOTATION_SHA256 = "3a2cece0a7877dadb2c23e8fcaf57b25ef57523258437201785fde9e537376a9"
MAX_SOURCE_BYTES = 50 << 20
MAX_LEDGER_BYTES = 16 << 20
CASE_FIELDS = ("case_id", "origin_row_id", "genome_build", "chrom", "position_1based", "ref", "alt")


class AdapterError(ValueError):
    """A stable error code; never includes private paths or raw data."""


def digest(data):
    return hashlib.sha256(data).hexdigest()


def is_sha(value):
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def text(value):
    return isinstance(value, str) and bool(value.strip())


def finite(value):
    try:
        return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)
    except OverflowError:
        return False


def integer(value):
    return isinstance(value, int) and not isinstance(value, bool)


def decode_json(raw):
    # Reject duplicate keys, NaN/Infinity and oversized documents.
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise AdapterError("json_duplicate_key")
            result[key] = value
        return result
    try:
        value = json.loads(raw, object_pairs_hook=pairs,
                           parse_constant=lambda unused: (_ for _ in ()).throw(AdapterError("json_nonfinite")))
    except (ValueError, UnicodeDecodeError) as exc:
        raise AdapterError("json_invalid") from exc
    return value, digest(raw)


def read_json(path, maximum=MAX_LEDGER_BYTES):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise AdapterError("document_not_regular")
        raw = handle.read(maximum + 1)
    if len(raw) > maximum:
        raise AdapterError("document_size_exceeded")
    return decode_json(raw)


def private_file(path, base, expected_sha=None, maximum=MAX_SOURCE_BYTES, json_document=False):
    """No symlinks, escapes or nonregular files; hash actual bounded bytes."""
    if not isinstance(path, (str, Path)) or not text(str(path)):
        raise AdapterError("private_file_missing")
    base = Path(base).absolute()
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = base / candidate
    candidate = Path(os.path.abspath(candidate))
    try:
        relative = candidate.relative_to(base)
    except ValueError as exc:
        raise AdapterError("private_path_escape") from exc
    current = base
    # The private prefix itself cannot alias another location.
    for parent in [base, *base.parents]:
        if parent.is_symlink():
            raise AdapterError("private_path_symlink")
    for component in relative.parts:
        current = current / component
        if current.is_symlink():
            raise AdapterError("private_path_symlink")
    if not candidate.exists():
        raise AdapterError("private_file_missing")
    if not candidate.is_file():
        raise AdapterError("private_file_not_regular")
    if not is_sha(expected_sha):
        raise AdapterError("private_file_sha_missing")
    # Resolve every directory with O_NOFOLLOW as well as checking metadata above;
    # a concurrent symlink swap must not change the bytes being verified.
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in candidate.parent.parts[1:]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        file_descriptor = os.open(candidate.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
    finally:
        os.close(descriptor)
    sha, consumed, raw = hashlib.sha256(), 0, bytearray()
    with os.fdopen(file_descriptor, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise AdapterError("private_file_not_regular")
        if json_document:
            raw = handle.read(maximum + 1)
            if len(raw) > maximum:
                raise AdapterError("document_size_exceeded")
            value, actual = decode_json(raw)
        else:
            while True:
                block = handle.read(min(1 << 20, maximum - consumed + 1))
                if not block:
                    break
                consumed += len(block)
                if consumed > maximum:
                    raise AdapterError("document_size_exceeded")
                sha.update(block)
            value, actual = None, sha.hexdigest()
    if actual != expected_sha:
        raise AdapterError("private_file_sha_mismatch")
    return value


def load_protocol(path=HERE / "baseline-protocol.json"):
    protocol, actual = read_json(path)
    if actual != PROTOCOL_SHA256 or protocol.get("protocol_id") != PROTOCOL_ID:
        raise AdapterError("protocol_not_frozen_pin")
    return protocol


def annotation_indices(source):
    raw = (Path(source) / "dist/seillra/dat/target.names").read_bytes()
    if digest(raw) != ANNOTATION_SHA256:
        raise AdapterError("annotation_sha_mismatch")
    rows = raw.decode("utf-8").splitlines()
    found = []
    for index, row in enumerate(rows):
        fields = [field.strip() for field in row.split("|")]
        if len(fields) == 3 and fields[:2] == ["GM12878_B_Lymphocyte_Blood", "ATAC-seq"]:
            if not fields[2].startswith("ID:"):
                raise AdapterError("annotation_id_invalid")
            found.append((int(fields[2][3:]), index))
    if len(rows) != 21907 or found != list(zip(TRACK_IDS, TRACK_INDICES)):
        raise AdapterError("annotation_track_selection_mismatch")
    return TRACK_INDICES.copy()


def weights_pins():
    return {entry["component"]: entry["sha256"] for entry in load_manifest()["files"]
            if entry["component"] in ("trunk_fp32", "head64_fp32")}


def canonical(case):
    return {key: case.get(key) for key in CASE_FIELDS}


def locus(case):
    return (case.get("genome_build"), case.get("chrom"), case.get("position_1based"))


def interval(case):
    q = case["position_1based"] - 1
    return (case["chrom"], q - 2048, q + 2048)


def overlaps(first, second):
    return first[0] == second[0] and first[1] < second[2] and second[1] < first[2]


def normalize_effect(effect, ref, alt):
    if not isinstance(effect, dict):
        raise AdapterError("effect_missing")
    if effect.get("orientation_known") is not True or not text(effect.get("orientation_source")):
        raise AdapterError("effect_orientation_unknown")
    if not text(effect.get("definition")):
        raise AdapterError("effect_definition_missing")
    raw = effect.get("value")
    if not finite(raw):
        raise AdapterError("effect_nonfinite")
    pair = (effect.get("effect_allele"), effect.get("other_allele"))
    if pair == (alt, ref):
        multiplier = 1
    elif pair == (ref, alt):
        multiplier = -1
    else:
        raise AdapterError("effect_alleles_mismatch")
    # No supplied normalized beta is consumed; raw + explicit alleles is the only conversion.
    result = {"beta_raw": raw, "beta_alt_minus_ref": multiplier * raw,
              "effect_allele": pair[0], "other_allele": pair[1],
              "orientation_source": effect["orientation_source"], "definition": effect["definition"]}
    if "standard_error" in effect:
        if not finite(effect["standard_error"]) or effect["standard_error"] < 0:
            raise AdapterError("effect_standard_error_invalid")
        result["standard_error"] = effect["standard_error"]
    if "confidence_interval" in effect:
        ci = effect["confidence_interval"]
        if not isinstance(ci, list) or len(ci) != 2 or not all(finite(x) for x in ci) or ci[0] > ci[1]:
            raise AdapterError("effect_confidence_interval_invalid")
        result["confidence_interval_raw"] = ci
        result["confidence_interval_alt_minus_ref"] = ci if multiplier == 1 else [-ci[1], -ci[0]]
    return result


def case_record(case, index, biological):
    record = {"row_index": index, "status": "validated", "reasons": []}
    if not isinstance(case, dict):
        record.update(status="rejected", reasons=["case_not_object"])
        return record
    record.update(canonical(case))
    try:
        if not all(text(case.get(key)) for key in ("case_id", "origin_row_id", "chrom")):
            raise AdapterError("case_identity_missing")
        if case.get("genome_build") != "hg38":
            raise AdapterError("genome_build_mismatch")
        if not integer(case.get("position_1based")) or case["position_1based"] <= 2048:
            raise AdapterError("position_invalid")
        ref, alt = case.get("ref"), case.get("alt")
        if ref not in tuple("ACGT") or alt not in tuple("ACGT") or ref == alt:
            raise AdapterError("snv_alleles_invalid")
        window = case.get("window")
        if not isinstance(window, dict):
            raise AdapterError("window_missing")
        if window.get("chrom") != case["chrom"] or window.get("genome_build") != "hg38":
            raise AdapterError("window_locus_mismatch")
        if window.get("strand") != "+" or window.get("padding") is not False:
            raise AdapterError("window_orientation_or_padding_invalid")
        if not all(integer(window.get(key)) for key in ("start_zero_based", "end_zero_based")):
            raise AdapterError("window_coordinates_invalid")
        _, start, end = interval(case)
        if (window["start_zero_based"], window["end_zero_based"]) != (start, end):
            raise AdapterError("window_coordinates_mismatch")
        sequence = window.get("sequence")
        if not isinstance(sequence, str) or len(sequence) != 4096 or set(sequence) - set("ACGT"):
            raise AdapterError("window_dna_invalid")
        if digest(sequence.encode("ascii")) != window.get("sha256"):
            raise AdapterError("window_sha_mismatch")
        if sequence[2048] != ref:
            raise AdapterError("window_ref_mismatch")
        if not text(window.get("source_url")) or not window["source_url"].startswith("https://") or not isinstance(window.get("provenance"), dict) or not window["provenance"]:
            raise AdapterError("window_provenance_missing")
        record["window_sha256"] = window["sha256"]
        record["window_start_zero_based"], record["window_end_zero_based"] = start, end
        if biological or case.get("effect") is not None:
            record.update(normalize_effect(case.get("effect"), ref, alt))
    except AdapterError as exc:
        code = str(exc)
        # Missing biological definitions/effects cannot be invented from a TSV guess.
        record["status"] = "pending" if code in ("effect_missing", "effect_definition_missing") else "rejected"
        record["reasons"].append(code)
    return record


def reject_duplicates(records, cases):
    for key, reason in ((lambda c: c.get("case_id"), "duplicate_case_id"), (locus, "duplicate_locus")):
        buckets = collections.defaultdict(list)
        for index, case in enumerate(cases):
            if isinstance(case, dict):
                value = key(case)
                try:
                    if value is not None:
                        buckets[value].append(index)
                except TypeError:
                    continue  # Malformed values already receive a structural rejection.
        for indices in buckets.values():
            if len(indices) > 1:
                for index in indices:
                    records[index]["status"] = "rejected"
                    records[index]["reasons"].append(reason)


def rank_key(case, seed):
    return digest("\n".join([seed, case["genome_build"], case["chrom"], str(case["position_1based"]),
                             case["ref"], case["alt"], case["origin_row_id"]]).encode("utf-8"))


def deterministic_selection(cases, seed):
    """Technical eligibility, duplicate rejections, then greedy disjoint windows.

    Return every pool outcome as well as frozen 110 descriptors. No predictions
    or beta values enter the ranking. The current submitted rows never refill it.
    """
    records = [case_record(case, index, True) for index, case in enumerate(cases)]
    reject_duplicates(records, cases)
    eligible = [i for i, record in enumerate(records) if record["status"] == "validated"]
    eligible.sort(key=lambda i: (rank_key(cases[i], seed), cases[i]["case_id"]))
    admitted, intervals = [], []
    for index in eligible:
        candidate = interval(cases[index])
        if any(overlaps(candidate, prior) for prior in intervals):
            records[index].update(status="rejected")
            records[index]["reasons"].append("overlapping_selection_window")
            continue
        intervals.append(candidate)
        descriptor = canonical(cases[index])
        descriptor.update(rank_sha256=rank_key(cases[index], seed), window_sha256=cases[index]["window"]["sha256"])
        admitted.append(descriptor)
    return admitted[:110], records


def block(records, status, code):
    for record in records:
        if record["status"] != "rejected":
            record["status"] = status
        if code not in record["reasons"]:
            record["reasons"].append(code)


def verify_receipt(dataset, prefix, normalization_sha):
    receipt = private_file(dataset.get("verification_receipt_path", ""), prefix,
                           dataset.get("verification_receipt_sha256"), json_document=True)
    required = {"schema_version": 1, "dataset_id": dataset.get("id"), "dataset_version": dataset.get("version"),
                "dataset_sha256": dataset.get("sha256"), "review_status": "approved", "permission_scope": "internal_research",
                "schema_verified": True, "effect_orientation_verified": True, "license_verified": True,
                "normalization_sha256": normalization_sha}
    if not isinstance(receipt, dict) or any(receipt.get(key) != value for key, value in required.items()):
        raise AdapterError("dataset_review_receipt_mismatch")
    if not text(receipt.get("reviewed_by")) or not all(text(receipt.get(key)) and receipt[key].startswith("https://")
                                                     for key in ("license_source_url", "effect_source_url")):
        raise AdapterError("dataset_review_receipt_incomplete")
    return receipt


def verify_selection(ledger, protocol, prefix):
    split = ledger.get("split_metadata", {})
    if not isinstance(split, dict) or split.get("frozen") is not True or not text(split.get("selection_id")):
        raise AdapterError("selection_not_frozen")
    normalization = private_file(split.get("source_normalization_ledger_path", ""), Path(prefix) / "datasets",
                                 split.get("source_normalization_ledger_sha256"), json_document=True)
    frozen = private_file(split.get("frozen_selection_path", ""), Path(prefix) / "datasets",
                          split.get("frozen_selection_sha256"), json_document=True)
    identity = {"schema_version": 1, "dataset_sha256": ledger["dataset"]["sha256"], "protocol_sha256": PROTOCOL_SHA256}
    if not isinstance(normalization, dict) or not isinstance(frozen, dict) or any(
            document.get(key) != value for document in (normalization, frozen) for key, value in identity.items()):
        raise AdapterError("selection_source_identity_mismatch")
    rule = normalization.get("normalization", {})
    if not isinstance(rule, dict) or rule.get("reviewed_before_predictions") is not True or not all(
            text(rule.get(key)) for key in ("schema_definition", "filters", "orientation_definition")):
        raise AdapterError("source_normalization_not_frozen")
    if not isinstance(normalization.get("cases"), list):
        raise AdapterError("source_normalization_cases_missing")
    if frozen.get("normalization_sha256") != split["source_normalization_ledger_sha256"] or frozen.get("frozen_before_predictions") is not True:
        raise AdapterError("selection_not_frozen_before_predictions")
    selected, pool_records = deterministic_selection(normalization["cases"], protocol["selection"]["seed"])
    if len(selected) != 110:
        raise AdapterError("selection_requires_110_disjoint_windows")
    if frozen.get("selected") != selected:
        raise AdapterError("selection_rank_or_slots_mismatch")
    if split.get("adapter_loci") != selected[:10] or split.get("evaluation_loci") != selected[10:]:
        raise AdapterError("selection_split_mismatch")
    selected_ids = {row["case_id"] for row in selected}
    originals = {row["case_id"]: row for row in normalization["cases"]
                 if isinstance(row, dict) and text(row.get("case_id")) and row["case_id"] in selected_ids}
    return selected, pool_records, originals


def verify_adapter_receipt(ledger, prefix, selection_sha):
    split = ledger["split_metadata"]
    receipt = private_file(split.get("adapter_receipt_path", ""), prefix,
                           split.get("adapter_receipt_sha256"), json_document=True)
    expected = {"schema_version": 1, "phase": "adapter", "dataset_kind": "biological", "status": "passed",
                "dataset_sha256": ledger["dataset"]["sha256"], "protocol_sha256": PROTOCOL_SHA256,
                "weights_sha256": weights_pins(), "selection_sha256": selection_sha,
                "counts": {"submitted": 10, "validated": 10, "rejected": 0, "pending": 0, "inferred": 10}}
    if not isinstance(receipt, dict) or any(receipt.get(key) != value for key, value in expected.items()):
        raise AdapterError("prior_biological_adapter_receipt_mismatch")
    return receipt


def validate_ledger(ledger, prefix, protocol=None):
    protocol = load_protocol() if protocol is None else protocol
    if not isinstance(ledger, dict) or not isinstance(ledger.get("cases"), list):
        raise AdapterError("ledger_cases_missing")
    dataset = ledger.get("dataset", {})
    biological = isinstance(dataset, dict) and dataset.get("kind") == "biological"
    cases = ledger["cases"]
    records = [case_record(case, index, biological) for index, case in enumerate(cases)]
    reject_duplicates(records, cases)
    errors, pool = [], None
    def gate(status, code):
        errors.append({"status": status, "code": code})
        block(records, status, code)
    phase = ledger.get("phase")
    if ledger.get("schema_version") != 1 or ledger.get("protocol_id") != PROTOCOL_ID:
        gate("rejected", "ledger_protocol_mismatch")
    if phase not in ("control", "adapter", "evaluation"):
        gate("rejected", "phase_invalid")
    elif len(cases) != protocol["dataset_requirements"]["phase_case_counts"][phase]:
        gate("rejected", "phase_case_count_mismatch")
    if not isinstance(dataset, dict) or dataset.get("kind") not in ("biological", "instrumentation_control"):
        gate("pending", "dataset_kind_unknown")
        dataset = dataset if isinstance(dataset, dict) else {}
    elif biological != (phase in ("adapter", "evaluation")):
        gate("rejected", "phase_dataset_kind_mismatch")
    if not all(text(dataset.get(key)) for key in ("id", "version", "schema_definition")) or not is_sha(dataset.get("sha256")):
        gate("pending", "dataset_identity_or_schema_missing")
    permission = dataset.get("permission", {})
    if not isinstance(permission, dict) or permission.get("status") != "authorized" or permission.get("scope") != "internal_research":
        denied = isinstance(permission, dict) and permission.get("status") == "denied"
        gate("rejected" if denied else "pending", "dataset_permission_denied" if denied else "dataset_permission_pending")
    try:
        private_file(dataset.get("source_path", ""), Path(prefix) / "datasets", dataset.get("sha256"))
    except (AdapterError, OSError) as exc:
        code = str(exc) if isinstance(exc, AdapterError) else "private_file_unavailable"
        gate("pending" if code in ("private_file_missing", "private_file_sha_missing", "private_file_unavailable") else "rejected", code)
    selection_sha = None
    if biological:
        split = ledger.get("split_metadata", {})
        normalization_sha = split.get("source_normalization_ledger_sha256") if isinstance(split, dict) else None
        for check in (lambda: verify_receipt(dataset, prefix, normalization_sha), lambda: verify_selection(ledger, protocol, prefix)):
            try:
                outcome = check()
                if isinstance(outcome, tuple):
                    selected, pool, originals = outcome
                    selection_sha = ledger["split_metadata"]["frozen_selection_sha256"]
                    expected = selected[:10] if phase == "adapter" else selected[10:]
                    if len(cases) != len(expected):
                        gate("rejected", "frozen_slot_count_mismatch")
                    else:
                        for case, record, descriptor in zip(cases, records, expected):
                            if not isinstance(case, dict) or canonical(case) != {key: descriptor[key] for key in CASE_FIELDS}:
                                record["status"] = "rejected"
                                record["reasons"].append("frozen_case_slot_mismatch")
                            elif record.get("window_sha256") and record["window_sha256"] != descriptor["window_sha256"]:
                                record["status"] = "rejected"
                                record["reasons"].append("frozen_window_sha_mismatch")
                            elif case != originals[descriptor["case_id"]]:
                                record["status"] = "rejected"
                                record["reasons"].append("frozen_case_payload_mismatch")
            except (AdapterError, OSError) as exc:
                code = str(exc) if isinstance(exc, AdapterError) else "private_file_unavailable"
                gate("pending" if code in ("private_file_missing", "private_file_sha_missing", "private_file_unavailable", "selection_requires_110_disjoint_windows") else "rejected", code)
        if phase == "evaluation":
            try:
                verify_adapter_receipt(ledger, prefix, selection_sha)
            except (AdapterError, OSError, KeyError, TypeError) as exc:
                code = str(exc) if isinstance(exc, AdapterError) else "private_file_unavailable"
                gate("pending", "prior_biological_adapter_required" if code in ("private_file_missing", "private_file_sha_missing") else code)
    else:
        split = ledger.get("split_metadata", {})
        if not isinstance(split, dict) or split.get("frozen") is not True or not text(split.get("selection_id")) or not text(split.get("selection_rule")):
            gate("pending", "control_selection_not_frozen")
    # Submitted cases must remain independent; all conflicting rows are recorded.
    for index, first in enumerate(records):
        if first.get("window_start_zero_based") is None:
            continue
        for second in records[index + 1:]:
            if second.get("window_start_zero_based") is None:
                continue
            if overlaps((first["chrom"], first["window_start_zero_based"], first["window_end_zero_based"]),
                        (second["chrom"], second["window_start_zero_based"], second["window_end_zero_based"])):
                for record in (first, second):
                    record["status"] = "rejected"
                    if "overlapping_submitted_windows" not in record["reasons"]:
                        record["reasons"].append("overlapping_submitted_windows")
    counts = {"submitted": len(cases), **{name: sum(r["status"] == name for r in records) for name in ("validated", "rejected", "pending")}, "inferred": 0}
    ready = not errors and len(cases) > 0 and counts["validated"] == len(cases)
    return {"schema_version": 1, "protocol_id": PROTOCOL_ID, "protocol_sha256": PROTOCOL_SHA256,
            "phase": phase, "dataset_kind": dataset.get("kind"), "dataset_sha256": dataset.get("sha256"),
            "selection_sha256": selection_sha, "weights_sha256": weights_pins(),
            "status": "validated" if ready else "rejected" if counts["rejected"] or any(e["status"] == "rejected" for e in errors) else "pending",
            "ready_for_inference": ready, "trained_weights_loaded": False, "counts": counts,
            "records": records, "errors": errors,
            "normalization_pool_counts": dict(collections.Counter(r["status"] for r in pool)) if pool is not None else None,
            "scientific_feasibility": "pending", "scope": "Normalized offline ledger; instrumentation does not establish biological accuracy."}


def average_ranks(values):
    order = sorted(range(len(values)), key=values.__getitem__)
    ranks = [0.0] * len(values)
    i = 0
    while i < len(order):
        j = i + 1
        while j < len(order) and values[order[j]] == values[order[i]]:
            j += 1
        rank = (i + 1 + j) / 2
        for index in order[i:j]:
            ranks[index] = rank
        i = j
    return ranks


def biological_metrics(records):
    pairs = [(r["score"], r["beta_alt_minus_ref"]) for r in records
             if finite(r.get("score")) and finite(r.get("beta_alt_minus_ref"))]
    sign = lambda v: (v > 0) - (v < 0)
    agreed = sum(sign(score) == sign(beta) for score, beta in pairs)
    secondary = [(score, beta) for score, beta in pairs if beta != 0]
    result = {"scored_effect_pairs": len(pairs), "primary_sign_agreement": {"agreed": agreed, "denominator": len(pairs), "fraction": agreed / len(pairs) if pairs else None},
              "secondary_nonzero_effect_sign_agreement": {"agreed": sum(sign(a) == sign(b) for a, b in secondary), "denominator": len(secondary),
                                                        "fraction": sum(sign(a) == sign(b) for a, b in secondary) / len(secondary) if secondary else None},
              "exact_zero_predictions": sum(a == 0 for a, _ in pairs), "exact_zero_effects": sum(b == 0 for _, b in pairs),
              "provided_confidence_intervals": sum("confidence_interval_alt_minus_ref" in r for r in records),
              "confidence_intervals_containing_zero": sum(r["confidence_interval_alt_minus_ref"][0] <= 0 <= r["confidence_interval_alt_minus_ref"][1]
                                                         for r in records if "confidence_interval_alt_minus_ref" in r),
              "provided_standard_errors": sum("standard_error" in r for r in records), "raw_mae_against_beta": None}
    correlation, reason = None, None
    if len(pairs) < 2:
        reason = "fewer_than_two_pairs"
    else:
        a, b = (average_ranks(values) for values in zip(*pairs))
        ma, mb = math.fsum(a) / len(a), math.fsum(b) / len(b)
        va, vb = math.fsum((v-ma)**2 for v in a), math.fsum((v-mb)**2 for v in b)
        if not va or not vb:
            reason = "constant_ranked_vector"
        else:
            correlation = math.fsum((x-ma)*(y-mb) for x, y in zip(a, b)) / math.sqrt(va*vb)
    result["spearman"] = {"correlation": correlation, "undefined_reason": reason, "ties": "average_ranks", "denominator": len(pairs)}
    return result


def construct_head_model(torch, parts, wrappers, paths):
    def load(module, path):
        state = torch.load(path, map_location="cpu", weights_only=True)
        if not isinstance(state, collections.abc.Mapping):
            raise AdapterError("checkpoint_not_state_dict")
        module.load_state_dict(state, strict=True)
        return module.eval()
    trunk = load(parts.SeiTrunk(sequence_length=4096), paths["trunk_fp32"])
    head = load(parts.SeiHeadLLRA(k=64), paths["head64_fp32"])
    model = wrappers.Sei_LLRA.__new__(wrappers.Sei_LLRA)
    torch.nn.Module.__init__(model)
    model.trunk, model.head = trunk, head
    model.projection, model.mode, model.compile = False, "variant", False
    model.quant, model.device = None, torch.device("cpu")
    return model.eval()


def worker(args):
    probe.event({"event": "phase", "phase": "loading"})
    ledger, ledger_sha = read_json(args.ledger)
    protocol = load_protocol(args.protocol)
    report = validate_ledger(ledger, args.prefix, protocol)
    report["ledger_sha256"] = ledger_sha
    if not report["ready_for_inference"]:
        raise AdapterError("ledger_not_ready")
    report["status"] = "running"
    progress = Path(args.progress)
    if progress.parent != args.prefix.absolute() or not progress.name.startswith(".adapter-progress-") or progress.is_symlink():
        raise AdapterError("progress_path_invalid")
    atomic_json(progress, report)
    source = probe.verify_source(args.source)
    indices = annotation_indices(source)
    paths, unused_pins = probe.verified_paths(args.prefix, "fp32")
    import torch
    torch.set_num_threads(1)
    torch.set_num_interop_threads(1)
    torch.manual_seed(probe.SEED)
    parts, wrappers = probe.local_parts(source)
    start = time.monotonic()
    model = construct_head_model(torch, parts, wrappers, paths)
    load_seconds = time.monotonic() - start
    report.update(trained_weights_loaded=True, ledger_sha256=ledger_sha, source_commit=SOURCE_COMMIT,
                  annotation_sha256=ANNOTATION_SHA256, track_ids=TRACK_IDS, track_indices_zero_based=indices,
                  projection=False, head_outputs=21907, strict_state_dict=True, weights_only=True,
                  threads=1, batch=1, channel_order="ACGT", python=platform.python_version(), torch=torch.__version__,
                  architecture=platform.machine(), load_seconds=load_seconds,
                  strand_handling="pinned upstream forward: mean forward and reverse-complement head probabilities",
                  independence_limit="Disjoint 4096-base windows do not establish linkage-disequilibrium independence.")
    atomic_json(progress, report)
    def tensor_pair(case):
        dna = case["window"]["sequence"]
        ids = torch.tensor(["ACGT".index(base) for base in dna], dtype=torch.int64)
        ref = torch.nn.functional.one_hot(ids, num_classes=4).T.to(torch.float32).unsqueeze(0).contiguous()
        alt = ref.clone()
        alt[0, :, 2048] = 0
        alt[0, "ACGT".index(case["alt"]), 2048] = 1
        return ref, alt
    def infer(pair, phase, index):
        probe.event({"event": "phase", "phase": phase, "pair_index": index})
        start = time.monotonic()
        output = model(pair)
        elapsed = time.monotonic() - start
        if not isinstance(output, tuple) or len(output) != 2 or any(list(value.shape) != [1, 21907] for value in output):
            raise AdapterError("head_output_shape_invalid")
        if not all(bool(torch.isfinite(value).all()) and bool(((value >= 0) & (value <= 1)).all()) for value in output):
            raise AdapterError("head_probability_invalid")
        return output, elapsed
    with torch.inference_mode():
        _, warmup_seconds = infer(tensor_pair(ledger["cases"][0]), "warmup", 0)
        for index, (case, record) in enumerate(zip(ledger["cases"], report["records"])):
            output, elapsed = infer(tensor_pair(case), "measure", index)
            repeated, repeat_seconds = infer(tensor_pair(case), "repeat", index)
            if not all(torch.equal(a, b) for a, b in zip(output, repeated)):
                raise AdapterError("repeat_not_identical")
            ref, alt = (value[0, indices].tolist() for value in output)
            deltas = [a-r for r, a in zip(ref, alt)]
            record.update(status="inferred", score=math.fsum(deltas)/9, track_ref_probabilities=ref,
                          track_alt_probabilities=alt, track_deltas=deltas, seconds=elapsed,
                          repeat_seconds=repeat_seconds, repeat_identical=True)
            report["counts"]["inferred"] = index + 1
            atomic_json(progress, report)
    report["warmup_seconds"] = warmup_seconds
    report["peak_rss_bytes"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
    report["counts"]["inferred"] = len(report["records"])
    report["status"] = "passed"
    report["checks"] = {"full_head_shape_1x21907": True, "all_head_probabilities_finite_and_in_unit_interval": True,
                        "repeat_identical_all_head_outputs": True, "exact_nine_tracks": True,
                        "projection_disabled": True, "batch_one": True}
    report["metrics"] = biological_metrics(report["records"]) if report["dataset_kind"] == "biological" else None
    report["biological_association"] = "reported_descriptively" if report["phase"] == "evaluation" else "pending"
    # Adapter PASS denotes input/runtime checks only, never an accuracy threshold.
    report["scientific_feasibility"] = "pending"
    if report["peak_rss_bytes"] > protocol["constraints"]["max_rss_bytes"] or max(
            [load_seconds, warmup_seconds] + [r[key] for r in report["records"] for key in ("seconds", "repeat_seconds")]) > 120:
        raise AdapterError("worker_resource_budget_exceeded")
    probe.event({"event": "report", "report": report})
    return 0


def merge_execution_failure(validation, execution, progress_path, ledger_sha):
    """Keep completed rows after a worker timeout; never promote partial evidence."""
    report = validation
    try:
        partial, unused_sha = read_json(progress_path)
        if (isinstance(partial, dict) and partial.get("ledger_sha256") == ledger_sha and
                partial.get("protocol_sha256") == PROTOCOL_SHA256 and partial.get("phase") == validation["phase"] and
                partial.get("dataset_sha256") == validation["dataset_sha256"] and
                len(partial.get("records", [])) == validation["counts"]["submitted"]):
            report = partial
    except (OSError, AdapterError, ValueError):
        pass
    report.update(status="failed", execution=execution, scientific_feasibility="pending")
    for record in report["records"]:
        if record["status"] != "inferred":
            record.update(status="failed")
            record["reasons"].append(execution.get("error_code", "head_execution_failed"))
    report["counts"]["inferred"] = sum(r["status"] == "inferred" for r in report["records"])
    report["counts"]["failed"] = sum(r["status"] == "failed" for r in report["records"])
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", required=True, type=Path)
    parser.add_argument("--prefix", type=Path, default=probe.ROOT / ".biozero/regulatory-assets")
    parser.add_argument("--source", type=Path, default=probe.ROOT / ".biozero/seillra")
    parser.add_argument("--protocol", type=Path, default=HERE / "baseline-protocol.json")
    parser.add_argument("--python", type=Path, default=Path(sys.executable))
    operation = parser.add_mutually_exclusive_group()
    operation.add_argument("--validate-only", action="store_true")
    operation.add_argument("--run", action="store_true")
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--progress", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker:
        if not args.run:
            raise AdapterError("worker_requires_explicit_run")
        try:
            return worker(args)
        except Exception as exc:
            # Parent captures only stable error types; paths/raw data never escape.
            code = str(exc) if isinstance(exc, AdapterError) else "head_worker_" + type(exc).__name__
            probe.event({"event": "report", "report": {"status": "failed", "error_code": code, "scientific_feasibility": "pending"}})
            return 1
    protocol = load_protocol(args.protocol)
    ledger, ledger_sha = read_json(args.ledger)
    report = validate_ledger(ledger, args.prefix, protocol)
    report["ledger_sha256"] = ledger_sha
    args.prefix.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(args.prefix, 0o700)
    if args.run and report["ready_for_inference"]:
        progress = args.prefix.absolute() / (".adapter-progress-" + uuid.uuid4().hex + ".json")
        command = [str(args.python), str(Path(__file__).resolve()), "--worker", "--run", "--ledger", str(args.ledger.absolute()),
                   "--prefix", str(args.prefix.absolute()), "--source", str(args.source.absolute()), "--protocol", str(args.protocol.absolute()),
                   "--progress", str(progress)]
        try:
            execution = probe.supervise(command, len(ledger["cases"]), protocol["constraints"]["max_rss_bytes"], protocol["constraints"]["seconds_per_phase"])
        except (probe.ProbeError, KeyboardInterrupt, OSError):
            execution = {"status": "failed", "error_code": "head_controller_interrupted_or_start_failed"}
        if execution.get("status") == "passed":
            report = execution
        else:
            report = merge_execution_failure(report, execution, progress, ledger_sha)
        try:
            progress.unlink()
        except FileNotFoundError:
            pass
    destination = args.prefix / ("biological-adapter-" + uuid.uuid4().hex + ".json")
    atomic_json(destination, report)
    print(json.dumps({"status": report["status"], "phase": report["phase"], "dataset_kind": report["dataset_kind"],
                      "counts": report["counts"], "report": str(destination), "scientific_feasibility": "pending"}))
    return 0 if report["status"] in ("validated", "passed") else 2 if report["status"] == "pending" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AdapterError, OSError, ValueError) as exc:
        print(json.dumps({"status": "failed", "error_code": str(exc) if isinstance(exc, AdapterError) else "adapter_input_unavailable",
                          "scientific_feasibility": "pending"}), file=sys.stderr)
        raise SystemExit(1)
