#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Validate complete private SCI02 reports and print an allowlisted public receipt.

Offline reads only: no model, download, inference, input changes or publication.
Version 1 accepts the locked ARM64 FP32 runtime used for this frozen experiment.
An export PASS confirms input/report coherence, not predictive accuracy.
"""
import argparse
import copy
import hashlib
import json
import math
from pathlib import Path

import biological_adapter as adapter


STRANDS = "pinned upstream forward: mean forward and reverse-complement head probabilities"
MEMORY = "50 ms RSS watchdog plus self-reported peak; not RLIMIT_AS or a kernel allocation cap"
RUNTIME = {"python": "3.11.17", "torch": "2.14.1+cpu", "architecture": "aarch64"}
CHECKS = {"full_head_shape_1x21907": True,
          "all_head_probabilities_finite_and_in_unit_interval": True,
          "repeat_identical_all_head_outputs": True, "exact_nine_tracks": True,
          "projection_disabled": True, "batch_one": True}


class ExportError(adapter.AdapterError):
    """Fixed public error code, without private values or paths."""


def require(condition, code):
    if not condition:
        raise ExportError(code)


def finite_json(document):
    """Reject non-JSON values/nonfinite numbers even in nonexported fields."""
    pending = [(document, 0)]
    while pending:
        value, depth = pending.pop()
        require(depth <= 64, "biological_export_json_depth_invalid")
        if type(value) is dict:
            require(all(type(key) is str for key in value), "biological_export_json_type_invalid")
            pending.extend((item, depth + 1) for item in value.values())
        elif type(value) is list:
            pending.extend((item, depth + 1) for item in value)
        elif type(value) in (int, float):
            require(adapter.finite(value), "biological_export_nonfinite_number")
        else:
            require(value is None or type(value) in (str, bool), "biological_export_json_type_invalid")


def duration(value, maximum=None):
    require(adapter.finite(value) and value >= 0 and (maximum is None or value <= maximum),
            "biological_export_duration_invalid")
    return value


def validate_report(ledger, ledger_sha256, report, validation, protocol):
    """Check the actual writer's records/math against independently validated inputs."""
    finite_json(ledger)
    finite_json(report)
    require(type(ledger) is dict and type(report) is dict and adapter.is_sha(ledger_sha256),
            "biological_export_identity_invalid")
    phase = ledger.get("phase")
    require(phase in ("adapter", "evaluation") and ledger.get("dataset", {}).get("kind") == "biological",
            "biological_export_phase_invalid")
    count = 10 if phase == "adapter" else 100
    require(validation.get("ready_for_inference") is True and validation.get("status") == "validated",
            "biological_export_inputs_not_ready")
    expected = {key: validation[key] for key in
                ("schema_version", "protocol_id", "protocol_sha256", "phase", "dataset_kind",
                 "dataset_sha256", "selection_sha256", "weights_sha256", "normalization_pool_counts", "errors", "scope")}
    expected.update(status="passed", ledger_sha256=ledger_sha256, source_commit=adapter.SOURCE_COMMIT,
                    ready_for_inference=True, channel_order="ACGT", strand_handling=STRANDS,
                    counts={"submitted": count, "validated": count, "rejected": 0, "pending": 0, "inferred": count},
                    trained_weights_loaded=True, strict_state_dict=True, weights_only=True,
                    projection=False, head_outputs=21907, annotation_sha256=adapter.ANNOTATION_SHA256,
                    track_ids=adapter.TRACK_IDS, track_indices_zero_based=adapter.TRACK_INDICES,
                    threads=1, batch=1, checks=CHECKS, scientific_feasibility="pending",
                    biological_association="pending" if phase == "adapter" else "reported_descriptively")
    expected.update(RUNTIME)
    require(all(adapter.exact_json_equal(report.get(key), value) for key, value in expected.items()),
            "biological_export_report_configuration_mismatch")
    require(not any(key in report for key in ("execution", "partial_report", "error_code")),
            "biological_export_partial_report_invalid")
    records, originals = report.get("records"), validation.get("records")
    require(type(records) is list and len(records) == count and type(originals) is list and len(originals) == count,
            "biological_export_record_count_invalid")
    phase_limit = protocol["constraints"]["seconds_per_phase"]
    measure, repeated = [], []
    for record, original in zip(records, originals):
        require(type(record) is dict and original.get("status") == "validated"
                and record.get("status") == "inferred" and record.get("repeat_identical") is True,
                "biological_export_record_state_invalid")
        require(all(adapter.exact_json_equal(record.get(key), value)
                    for key, value in original.items() if key != "status"),
                "biological_export_original_record_mismatch")
        require(all((key in record) == (key in original) for key in
                    ("standard_error", "confidence_interval_raw", "confidence_interval_alt_minus_ref")),
                "biological_export_uncertainty_not_from_source")
        vectors = [record.get(key) for key in
                   ("track_ref_probabilities", "track_alt_probabilities", "track_deltas")]
        require(all(type(values) is list and len(values) == 9 and all(adapter.finite(v) for v in values)
                    for values in vectors), "biological_export_prediction_vectors_invalid")
        ref, alt, deltas = vectors
        require(all(0 <= value <= 1 for value in ref + alt) and deltas == [a - r for r, a in zip(ref, alt)]
                and adapter.finite(record.get("score")) and record["score"] == math.fsum(deltas) / 9,
                "biological_export_prediction_math_mismatch")
        measure.append(duration(record.get("seconds"), phase_limit))
        repeated.append(duration(record.get("repeat_seconds"), phase_limit))
    metrics = adapter.biological_metrics(records)
    require(adapter.exact_json_equal(report.get("metrics"), metrics), "biological_export_metrics_mismatch")
    supervisor = report.get("supervisor")
    require(type(supervisor) is dict, "biological_export_supervisor_invalid")
    rss_limit = protocol["constraints"]["max_rss_bytes"]
    total_limit = math.ceil(phase_limit * (2 * count + 2)) + 1
    supervisor_expected = {"returncode": 0, "rss_ceiling_bytes": rss_limit, "seconds_per_phase": phase_limit,
                           "cpu_time_total_limit_seconds": total_limit, "memory_enforcement": MEMORY}
    require(all(adapter.exact_json_equal(supervisor.get(key), value) for key, value in supervisor_expected.items()),
            "biological_export_supervisor_configuration_mismatch")
    for value in (report.get("peak_rss_bytes"), supervisor.get("watchdog_peak_rss_bytes")):
        require(type(value) is int and 0 < value <= rss_limit, "biological_export_rss_invalid")
    load = duration(report.get("load_seconds"), phase_limit)
    warmup = duration(report.get("warmup_seconds"), phase_limit)
    wall = duration(supervisor.get("seconds"), total_limit)
    require(wall >= math.fsum([load, warmup, *measure, *repeated]),
            "biological_export_wall_time_incoherent")
    return metrics, measure, repeated


def read_inputs(prefix, ledger_path, ledger_sha256, report_path, report_sha256):
    require(adapter.is_sha(ledger_sha256) and adapter.is_sha(report_sha256), "biological_export_sha_invalid")
    ledger = adapter.private_file(ledger_path, prefix / "datasets", ledger_sha256,
                                  maximum=adapter.MAX_LEDGER_BYTES, json_document=True)
    report = adapter.private_file(report_path, prefix, report_sha256,
                                  maximum=adapter.MAX_LEDGER_BYTES, json_document=True)
    protocol = adapter.load_protocol()
    validation = adapter.validate_ledger(ledger, prefix, protocol)
    metrics, measure, repeated = validate_report(ledger, ledger_sha256, report, validation, protocol)
    return ledger, report, validation, protocol, metrics, measure, repeated


def validate_prior_adapter(prefix, ledger):
    """Evaluation's pinned adapter must satisfy the same full-report boundary."""
    split = ledger["split_metadata"]
    report_sha = split.get("adapter_receipt_sha256")
    prior = adapter.private_file(split.get("adapter_receipt_path", ""), prefix, report_sha,
                                 maximum=adapter.MAX_LEDGER_BYTES, json_document=True)
    require(type(prior) is dict and adapter.is_sha(prior.get("ledger_sha256")),
            "biological_export_prior_adapter_identity_invalid")
    parent_sha = prior["ledger_sha256"]
    # This experiment retains its content-addressed original ten-case ledger.
    parent_path = prefix / "datasets" / ("kumasaka-adapter-ledger-" + parent_sha + ".json")
    parent, unused_report, unused_validation, unused_protocol, unused_metrics, unused_measure, unused_repeat = read_inputs(
        prefix, parent_path, parent_sha, split["adapter_receipt_path"], report_sha)
    require(parent.get("phase") == "adapter" and adapter.exact_json_equal(parent["dataset"], ledger["dataset"]),
            "biological_export_prior_adapter_parent_mismatch")
    original_split = {key: value for key, value in split.items()
                      if key not in ("adapter_receipt_path", "adapter_receipt_sha256")}
    require(adapter.exact_json_equal(parent["split_metadata"], original_split),
            "biological_export_prior_adapter_parent_mismatch")
    return parent_sha, report_sha


def duration_summary(values):
    return {"count": len(values), "minimum": min(values), "maximum": max(values),
            "sum": math.fsum(values), "mean": math.fsum(values) / len(values)}


def export_receipt(prefix, ledger_path, ledger_sha256, report_path, report_sha256):
    prefix = Path(prefix).absolute()
    ledger, report, validation, protocol, metrics, measure, repeated = read_inputs(
        prefix, Path(ledger_path).absolute(), ledger_sha256, Path(report_path).absolute(), report_sha256)
    prior_ledger_sha = prior_report_sha = None
    if ledger["phase"] == "evaluation":
        prior_ledger_sha, prior_report_sha = validate_prior_adapter(prefix, ledger)
    split = ledger["split_metadata"]
    parents = {"dataset_sha256": validation["dataset_sha256"], "ledger_sha256": ledger_sha256,
               "private_report_sha256": report_sha256, "selection_sha256": validation["selection_sha256"],
               "normalization_sha256": split.get("source_normalization_ledger_sha256"),
               "input_verification_receipt_sha256": ledger["dataset"].get("verification_receipt_sha256"),
               "prior_adapter_ledger_sha256": prior_ledger_sha, "prior_adapter_report_sha256": prior_report_sha}
    require(all(adapter.is_sha(value) for key, value in parents.items() if not key.startswith("prior_adapter_")),
            "biological_export_parent_sha_invalid")
    # Assemble the output from literals and individually checked fields. Never
    # project arbitrary private report/dataset dictionaries onto the public DTO.
    result = {"schema_version": 1, "experiment": "SCI02-biological-runtime",
              "status": "passed", "phase": ledger["phase"], "dataset_kind": "biological",
              "protocol_id": adapter.PROTOCOL_ID, "protocol_sha256": adapter.PROTOCOL_SHA256,
              "parents": parents,
              "technique": {"source_commit": adapter.SOURCE_COMMIT, "variant": "fp32", "rank": 64,
                            "annotation_sha256": adapter.ANNOTATION_SHA256, "weights_sha256": adapter.weights_pins(),
                            "track_ids": adapter.TRACK_IDS.copy(), "track_indices_zero_based": adapter.TRACK_INDICES.copy(),
                            "projection": False, "head_outputs": 21907, "strict_state_dict": True,
                            "weights_only": True, "threads": 1, "batch": 1, "channel_order": "ACGT",
                            "strand_handling": STRANDS, **RUNTIME},
              "counts": {key: report["counts"][key] for key in ("submitted", "validated", "rejected", "pending", "inferred")},
              "normalization_pool_counts": {key: validation["normalization_pool_counts"].get(key, 0)
                                            for key in ("validated", "rejected", "pending")},
              "checks": CHECKS.copy(), "metrics": copy.deepcopy(metrics),
              "runtime": {"load_seconds": report["load_seconds"], "warmup_seconds": report["warmup_seconds"],
                          "measurement_seconds": duration_summary(measure), "repeat_seconds": duration_summary(repeated),
                          "controller_seconds": report["supervisor"]["seconds"], "worker_peak_rss_bytes": report["peak_rss_bytes"],
                          "watchdog_peak_rss_bytes": report["supervisor"]["watchdog_peak_rss_bytes"],
                          "rss_ceiling_bytes": protocol["constraints"]["max_rss_bytes"],
                          "seconds_per_model_event": protocol["constraints"]["seconds_per_phase"],
                          "cpu_time_total_limit_seconds": report["supervisor"]["cpu_time_total_limit_seconds"],
                          "memory_enforcement": MEMORY},
              "scientific_feasibility": "pending", "biological_accuracy_approved": False,
              "rank64_verified_heldout": False,
              "biological_association": "reported_descriptively" if ledger["phase"] == "evaluation" else "pending",
              "raw_mae_method": "not_calculated_scales_not_established_as_comparable",
              "independence_limit": "Disjoint 4096-base windows do not establish linkage-disequilibrium independence.",
              "scope": "Complete frozen biological cases and coherent trusted-writer runtime reports; no accuracy, causal, clinical, economic or external-attestation approval.",
              "export_validation_source_sha256": {
                  "biological_runtime_export": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  "biological_adapter": hashlib.sha256(Path(adapter.__file__).read_bytes()).hexdigest()}}
    json.dumps(result, allow_nan=False)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--ledger-sha256", required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--report-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        public = export_receipt(args.prefix, args.ledger, args.ledger_sha256, args.report, args.report_sha256)
    except ExportError as exc:
        print(json.dumps({"status": "failed", "error_code": str(exc)}))
        return 1
    except Exception:
        print(json.dumps({"status": "failed", "error_code": "biological_export_input_invalid"}))
        return 1
    print(json.dumps(public, indent=2, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
