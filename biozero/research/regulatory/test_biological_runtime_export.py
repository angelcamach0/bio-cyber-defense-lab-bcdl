"""Synthetic privacy and mutation boundaries; no model, network or real datasets."""
import contextlib
import copy
import hashlib
import io
import json
import math
from pathlib import Path
import unittest

import biological_adapter as adapter
import biological_runtime_export as public
import test_biological_adapter as toy


class BiologicalRuntimeExportTests(unittest.TestCase):
    def setUp(self):
        self.inputs = toy.AdapterTests("test_control_without_effect_is_ready_but_biology_pending")
        self.inputs.setUp()
        self.prefix = self.inputs.prefix
        self.ledger_path = self.prefix / "datasets" / "execution-ledger.json"
        self.report_path = self.prefix / "execution-report.json"

    def tearDown(self):
        self.inputs.tearDown()

    def write(self, path, document):
        raw = json.dumps(document, sort_keys=True).encode()
        path.write_bytes(raw)
        return hashlib.sha256(raw).hexdigest()

    def report_for(self, ledger, ledger_sha):
        validation = adapter.validate_ledger(ledger, self.prefix)
        self.assertTrue(validation["ready_for_inference"])
        report = copy.deepcopy(validation)
        count = len(ledger["cases"])
        report.update(status="passed", ledger_sha256=ledger_sha, source_commit=adapter.SOURCE_COMMIT,
                      channel_order="ACGT", strand_handling=public.STRANDS,
                      trained_weights_loaded=True, strict_state_dict=True, weights_only=True,
                      projection=False, head_outputs=21907, annotation_sha256=adapter.ANNOTATION_SHA256,
                      track_ids=adapter.TRACK_IDS.copy(), track_indices_zero_based=adapter.TRACK_INDICES.copy(),
                      threads=1, batch=1, checks=public.CHECKS.copy(), load_seconds=0.5,
                      warmup_seconds=1.0, peak_rss_bytes=1_000_000,
                      biological_association="pending" if ledger["phase"] == "adapter" else "reported_descriptively",
                      **public.RUNTIME)
        report["counts"]["inferred"] = count
        for index, record in enumerate(report["records"]):
            ref, alt = [0.5] * 9, [0.75 if index % 2 == 0 else 0.25] * 9
            deltas = [a - r for r, a in zip(ref, alt)]
            record.update(status="inferred", repeat_identical=True, score=math.fsum(deltas) / 9,
                          track_ref_probabilities=ref, track_alt_probabilities=alt, track_deltas=deltas,
                          seconds=0.5, repeat_seconds=0.6)
        report["metrics"] = adapter.biological_metrics(report["records"])
        report["supervisor"] = {"returncode": 0, "rss_ceiling_bytes": 3 << 30, "seconds_per_phase": 120,
                                "cpu_time_total_limit_seconds": 120 * (2 * count + 2) + 1,
                                "memory_enforcement": public.MEMORY, "watchdog_peak_rss_bytes": 1_000_000,
                                "seconds": math.fsum([0.5, 1.0] + [0.5, 0.6] * count) + 1.0}
        return report

    def fixture(self, phase="adapter"):
        if phase == "evaluation":
            parent = self.inputs.ledger("adapter")
            parent_sha = hashlib.sha256(json.dumps(parent, sort_keys=True).encode()).hexdigest()
            parent_path = self.prefix / "datasets" / ("kumasaka-adapter-ledger-" + parent_sha + ".json")
            self.write(parent_path, parent)
            self.parent_report = self.report_for(parent, parent_sha)
            self.parent_report_path = self.prefix / "prior-adapter.json"
            prior_sha = self.write(self.parent_report_path, self.parent_report)
            ledger = self.inputs.ledger("evaluation")
            ledger["split_metadata"].update(adapter_receipt_path=self.parent_report_path.name,
                                             adapter_receipt_sha256=prior_sha)
        else:
            ledger = self.inputs.ledger("adapter")
        ledger_sha = self.write(self.ledger_path, ledger)
        report = self.report_for(ledger, ledger_sha)
        self.write(self.report_path, report)
        return ledger, report

    def export(self, ledger, report):
        ledger_sha = self.write(self.ledger_path, ledger)
        report_sha = self.write(self.report_path, report)
        return public.export_receipt(self.prefix, self.ledger_path, ledger_sha, self.report_path, report_sha)

    def test_adapter_export_is_allowlisted_and_preserves_private_inputs(self):
        ledger, report = self.fixture()
        canary = "PRIVATE_CANARY_PATH_AND_CASE_IDENTIFIER"
        report["private_note"] = {"path": "/private/" + canary, "dna": "ACGT" * 1024,
                                  "all_predictions": [0.1] * 21907}
        report["records"][0]["private_note"] = canary
        ledger_sha = self.write(self.ledger_path, ledger)
        report_sha = self.write(self.report_path, report)
        before = {p: p.read_bytes() for p in self.prefix.rglob("*") if p.is_file()}
        result = public.export_receipt(self.prefix, self.ledger_path, ledger_sha, self.report_path, report_sha)
        self.assertEqual(before, {p: p.read_bytes() for p in before})
        rendered = json.dumps(result, allow_nan=False)
        self.assertNotIn(canary, rendered)
        self.assertNotIn(str(self.prefix), rendered)
        self.assertNotIn("ACGT" * 128, rendered)
        self.assertNotIn("A" * 128, rendered)
        for record in report["records"]:
            self.assertNotIn(record["case_id"], rendered)
            self.assertNotIn(record["origin_row_id"], rendered)
        forbidden = {"records", "cases", "case_id", "origin_row_id", "sequence", "source_path",
                     "window_sha256", "position_1based", "chrom", "ref", "alt",
                     "track_ref_probabilities", "track_alt_probabilities", "track_deltas"}
        pending = [result]
        while pending:
            value = pending.pop()
            if type(value) is dict:
                self.assertFalse(forbidden.intersection(value))
                pending.extend(value.values())
            elif type(value) is list:
                pending.extend(value)
        self.assertEqual(result["counts"]["inferred"], 10)
        self.assertEqual(result["parents"]["private_report_sha256"], report_sha)
        self.assertFalse(result["biological_accuracy_approved"])
        self.assertEqual(result["scientific_feasibility"], "pending")

    def test_complete_evaluation_validates_prior_adapter_and_exports_only_aggregates(self):
        ledger, report = self.fixture("evaluation")
        result = self.export(ledger, report)
        self.assertEqual(result["phase"], "evaluation")
        self.assertEqual(result["counts"]["submitted"], 100)
        self.assertEqual(result["metrics"]["scored_effect_pairs"], 100)
        self.assertEqual(result["runtime"]["measurement_seconds"]["count"], 100)
        self.assertEqual(result["parents"]["prior_adapter_report_sha256"],
                         ledger["split_metadata"]["adapter_receipt_sha256"])
        self.assertFalse(result["biological_accuracy_approved"])
        self.assertEqual(result["biological_association"], "reported_descriptively")

    def test_descriptive_negative_or_undefined_metric_is_not_an_accuracy_gate(self):
        ledger, report = self.fixture()
        for record in report["records"]:
            record.update(track_alt_probabilities=[0.25] * 9, track_deltas=[-0.25] * 9, score=-0.25)
        report["metrics"] = adapter.biological_metrics(report["records"])
        result = self.export(ledger, report)
        self.assertEqual(result["metrics"]["primary_sign_agreement"]["fraction"], 0.0)
        self.assertIsNone(result["metrics"]["spearman"]["correlation"])
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["scientific_feasibility"], "pending")

    def test_partial_failed_control_or_alias_flags_reject(self):
        ledger, report = self.fixture()
        mutations = [lambda r: r.update(status="running"), lambda r: r.update(status="failed"),
                     lambda r: r.update(dataset_kind="instrumentation_control"),
                     lambda r: r["counts"].update(inferred=9), lambda r: r["counts"].update(validated=10.0),
                     lambda r: r.update(projection=0), lambda r: r.update(trained_weights_loaded=1),
                     lambda r: r.update(head_outputs=21907.0), lambda r: r.update(threads=True),
                     lambda r: r["checks"].update(exact_nine_tracks=1),
                     lambda r: r.update(scientific_feasibility="approved"),
                     lambda r: r.update(execution={"status": "failed"})]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                candidate = copy.deepcopy(report)
                mutate(candidate)
                with self.assertRaises(adapter.AdapterError):
                    self.export(ledger, candidate)

    def test_frozen_parent_and_runtime_mutations_reject(self):
        ledger, report = self.fixture()
        for update in ({"ledger_sha256": "d" * 64}, {"selection_sha256": "d" * 64},
                       {"dataset_sha256": "d" * 64}, {"source_commit": "d" * 40},
                       {"ready_for_inference": 1}, {"channel_order": "TGCA"},
                       {"strand_handling": "forward only"}, {"python": "3.9.25"},
                       {"architecture": "x86_64"}, {"torch": "/private/version-canary"}):
            with self.subTest(field=next(iter(update))):
                candidate = copy.deepcopy(report)
                candidate.update(update)
                with self.assertRaises(adapter.AdapterError):
                    self.export(ledger, candidate)
        candidate = copy.deepcopy(report)
        candidate["weights_sha256"]["head64_fp32"] = "d" * 64
        with self.assertRaises(adapter.AdapterError):
            self.export(ledger, candidate)

    def test_original_case_effect_slot_or_repeat_mutations_reject(self):
        ledger, report = self.fixture()
        for update in ({"beta_raw": 123.0}, {"beta_alt_minus_ref": 123.0}, {"row_index": True},
                       {"window_start_zero_based": 1}, {"window_sha256": "d" * 64},
                       {"repeat_identical": 1}, {"repeat_identical": False}, {"status": "validated"}):
            with self.subTest(field=next(iter(update))):
                candidate = copy.deepcopy(report)
                candidate["records"][0].update(update)
                with self.assertRaises(adapter.AdapterError):
                    self.export(ledger, candidate)
        candidate = copy.deepcopy(report)
        candidate["records"].reverse()
        with self.assertRaises(adapter.AdapterError):
            self.export(ledger, candidate)

    def test_nine_probability_vectors_and_writer_math_are_required(self):
        ledger, report = self.fixture()
        for update in ({"track_deltas": None}, {"track_ref_probabilities": [0.5] * 8},
                       {"track_alt_probabilities": [True] * 9}, {"track_alt_probabilities": [float("nan")] * 9},
                       {"track_ref_probabilities": [-0.1] * 9}, {"track_alt_probabilities": [1.1] * 9},
                       {"track_deltas": [0.1] * 9}, {"score": 0.1}, {"score": True}):
            with self.subTest(field=next(iter(update))):
                candidate = copy.deepcopy(report)
                candidate["records"][0].update(update)
                with self.assertRaises(adapter.AdapterError):
                    self.export(ledger, candidate)

    def test_metrics_are_recomputed_with_exact_denominators_and_json_types(self):
        ledger, report = self.fixture()
        for mutate in (lambda m: m.update(scored_effect_pairs=9),
                       lambda m: m["primary_sign_agreement"].update(fraction=1.0),
                       lambda m: m["primary_sign_agreement"].update(denominator=10.0),
                       lambda m: m["spearman"].update(correlation=0.99),
                       lambda m: m.update(exact_zero_effects=False),
                       lambda m: m.update(raw_mae_against_beta=0.0)):
            candidate = copy.deepcopy(report)
            mutate(candidate["metrics"])
            with self.assertRaisesRegex(public.ExportError, "metrics_mismatch"):
                self.export(ledger, candidate)

    def test_invented_uncertainty_cannot_be_hidden_by_recomputing_metrics(self):
        ledger, report = self.fixture()
        for fields in ({"standard_error": 0.12},
                       {"confidence_interval_raw": [-0.1, 0.4],
                        "confidence_interval_alt_minus_ref": [-0.1, 0.4]}):
            candidate = copy.deepcopy(report)
            candidate["records"][0].update(fields)
            candidate["metrics"] = adapter.biological_metrics(candidate["records"])
            with self.assertRaisesRegex(public.ExportError, "uncertainty_not_from_source"):
                self.export(ledger, candidate)

    def test_supervisor_and_timing_cannot_promote_a_failed_run(self):
        ledger, report = self.fixture()
        for update in ({"returncode": 1}, {"returncode": False}, {"seconds": True},
                       {"seconds": 0.0}, {"cpu_time_total_limit_seconds": True},
                       {"rss_ceiling_bytes": 4 << 30}, {"seconds_per_phase": 120.0},
                       {"watchdog_peak_rss_bytes": True}, {"watchdog_peak_rss_bytes": 4 << 30},
                       {"memory_enforcement": "kernel memory cap"}):
            candidate = copy.deepcopy(report)
            candidate["supervisor"].update(update)
            with self.assertRaises(adapter.AdapterError):
                self.export(ledger, candidate)
        for mutate in (lambda r: r.update(load_seconds=121.0),
                       lambda r: r.update(peak_rss_bytes=True),
                       lambda r: r["records"][0].update(seconds=121.0),
                       lambda r: r["records"][0].update(repeat_seconds=-1.0)):
            candidate = copy.deepcopy(report)
            mutate(candidate)
            with self.assertRaises(adapter.AdapterError):
                self.export(ledger, candidate)

    def test_evaluation_revalidates_prior_configuration_beyond_narrow_gate_counts(self):
        ledger, report = self.fixture("evaluation")
        self.parent_report["source_commit"] = "d" * 40
        prior_sha = self.write(self.parent_report_path, self.parent_report)
        ledger["split_metadata"]["adapter_receipt_sha256"] = prior_sha
        ledger_sha = self.write(self.ledger_path, ledger)
        report["ledger_sha256"] = ledger_sha
        # The old narrow receipt gate still validates this parent's counts; the
        # exporter must independently reject its changed runtime source commit.
        self.assertTrue(adapter.validate_ledger(ledger, self.prefix)["ready_for_inference"])
        with self.assertRaisesRegex(public.ExportError, "configuration_mismatch"):
            self.export(ledger, report)

    def test_wrong_sha_symlink_or_parentless_evaluation_never_exports(self):
        ledger, report = self.fixture()
        ledger_sha = self.write(self.ledger_path, ledger)
        report_sha = self.write(self.report_path, report)
        with self.assertRaises(adapter.AdapterError):
            public.export_receipt(self.prefix, self.ledger_path, ledger_sha, self.report_path, "0" * 64)
        link = self.prefix / "linked-report.json"
        link.symlink_to(self.report_path)
        with self.assertRaises(adapter.AdapterError):
            public.export_receipt(self.prefix, self.ledger_path, ledger_sha, link, report_sha)
        ledger, report = self.fixture("evaluation")
        parent_sha = self.parent_report["ledger_sha256"]
        (self.prefix / "datasets" / ("kumasaka-adapter-ledger-" + parent_sha + ".json")).unlink()
        with self.assertRaises(adapter.AdapterError):
            self.export(ledger, report)

    def test_cli_failure_reveals_no_private_exception_or_path(self):
        ledger, report = self.fixture()
        ledger_sha = self.write(self.ledger_path, ledger)
        arguments = ["--prefix", str(self.prefix), "--ledger", str(self.ledger_path),
                     "--ledger-sha256", ledger_sha, "--report", str(self.prefix / "PRIVATE_CANARY.json"),
                     "--report-sha256", "a" * 64]
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = public.main(arguments)
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(stdout.getvalue()),
                         {"status": "failed", "error_code": "biological_export_input_invalid"})
        self.assertNotIn("PRIVATE_CANARY", stdout.getvalue())
        self.assertNotIn(str(self.prefix), stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
