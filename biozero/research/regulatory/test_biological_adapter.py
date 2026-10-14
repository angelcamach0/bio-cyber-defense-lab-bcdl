"""Contract/input tests; fixture DNA/effects are not biological validation."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import biological_adapter as adapter


def sha(data):
    return hashlib.sha256(data).hexdigest()


def case(index=0, position=None, effect=True):
    position = 10000 + index * 5000 if position is None else position
    dna = "A" * 2048 + "C" + "A" * 2047
    row = {"case_id": "case-" + str(index), "origin_row_id": "row-" + str(index),
           "genome_build": "hg38", "chrom": "chr1", "position_1based": position, "ref": "C", "alt": "G",
           "window": {"chrom": "chr1", "genome_build": "hg38", "start_zero_based": position - 1 - 2048,
                      "end_zero_based": position - 1 + 2048, "sequence": dna, "sha256": sha(dna.encode()),
                      "strand": "+", "padding": False, "source_url": "https://example.org/reference",
                      "provenance": {"fixture_only": True}}}
    if effect:
        row["effect"] = {"value": 0.25, "effect_allele": "G", "other_allele": "C", "orientation_known": True,
                         "definition": "private test fixture beta", "orientation_source": "fixture allele dictionary"}
    return row


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.prefix = Path(self.temp.name) / "assets"
        self.datasets = self.prefix / "datasets"
        self.datasets.mkdir(parents=True)
        self.protocol = adapter.load_protocol()

    def tearDown(self):
        self.temp.cleanup()

    def write(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = json.dumps(value, sort_keys=True).encode()
        path.write_bytes(raw)
        return str(path), sha(raw)

    def ledger(self, phase="control"):
        source = self.datasets / "fixture.raw"
        source.write_bytes(b"private fixture source, not an acquired biological dataset")
        biological = phase != "control"
        ledger = {"schema_version": 1, "protocol_id": adapter.PROTOCOL_ID, "phase": phase,
                  "dataset": {"id": "fixture", "version": "fixture-1", "kind": "biological" if biological else "instrumentation_control",
                              "source_path": str(source), "sha256": sha(source.read_bytes()), "schema_definition": "private normalized fixture",
                              "permission": {"status": "authorized", "scope": "internal_research"}},
                  "split_metadata": {"frozen": True, "selection_id": "fixture-split", "selection_rule": "frozen fixture only"},
                  "cases": [case(effect=biological)]}
        if not biological:
            return ledger
        dataset = ledger["dataset"]
        receipt = {"schema_version": 1, "dataset_id": "fixture", "dataset_version": "fixture-1", "dataset_sha256": dataset["sha256"],
                   "review_status": "approved", "reviewed_by": "fixture reviewer", "permission_scope": "internal_research",
                   "schema_verified": True, "effect_orientation_verified": True, "license_verified": True,
                   "license_source_url": "https://example.org/license", "effect_source_url": "https://example.org/schema"}
        dataset["verification_receipt_path"], dataset["verification_receipt_sha256"] = self.write(self.prefix / "review.json", receipt)
        pool = [case(index) for index in range(113)]
        normalization = {"schema_version": 1, "dataset_sha256": dataset["sha256"], "protocol_sha256": adapter.PROTOCOL_SHA256,
                         "normalization": {"reviewed_before_predictions": True, "schema_definition": "fixture only", "filters": "technical SNV",
                                           "orientation_definition": "explicit fixture E/O"}, "cases": pool}
        split = ledger["split_metadata"]
        split["source_normalization_ledger_path"], split["source_normalization_ledger_sha256"] = self.write(self.datasets / "normalized.json", normalization)
        receipt["normalization_sha256"] = split["source_normalization_ledger_sha256"]
        dataset["verification_receipt_path"], dataset["verification_receipt_sha256"] = self.write(self.prefix / "review.json", receipt)
        selected, unused = adapter.deterministic_selection(pool, self.protocol["selection"]["seed"])
        frozen = {"schema_version": 1, "dataset_sha256": dataset["sha256"], "protocol_sha256": adapter.PROTOCOL_SHA256,
                  "normalization_sha256": split["source_normalization_ledger_sha256"], "frozen_before_predictions": True, "selected": selected}
        split["frozen_selection_path"], split["frozen_selection_sha256"] = self.write(self.datasets / "selected.json", frozen)
        split["adapter_loci"], split["evaluation_loci"] = selected[:10], selected[10:]
        lookup = {row["case_id"]: row for row in pool}
        ledger["cases"] = [copy.deepcopy(lookup[row["case_id"]]) for row in (selected[:10] if phase == "adapter" else selected[10:])]
        return ledger

    def validate(self, ledger):
        return adapter.validate_ledger(ledger, self.prefix, self.protocol)

    def test_control_without_effect_is_ready_but_biology_pending(self):
        report = self.validate(self.ledger())
        self.assertTrue(report["ready_for_inference"])
        self.assertEqual(report["counts"], {"submitted": 1, "validated": 1, "rejected": 0, "pending": 0, "inferred": 0})
        self.assertEqual(report["scientific_feasibility"], "pending")
        self.assertNotIn(str(self.prefix), json.dumps(report))
        self.assertNotIn("A" * 100, json.dumps(report))

    def test_coordinate_ref_hash_dna_padding_and_mixed_locus_rejected(self):
        mutations = [("start_zero_based", 1, "window_coordinates_mismatch"), ("sha256", "0" * 64, "window_sha_mismatch"),
                     ("sequence", "A" * 4096, "window_sha_mismatch"), ("sequence", "N" * 4096, "window_dna_invalid"),
                     ("sequence", "A" * 4095, "window_dna_invalid"), ("padding", True, "window_orientation_or_padding_invalid"),
                     ("strand", "-", "window_orientation_or_padding_invalid"), ("chrom", "chr2", "window_locus_mismatch")]
        for field, value, reason in mutations:
            with self.subTest(field=field, reason=reason):
                row = case()
                row["window"][field] = value
                record = adapter.case_record(row, 0, True)
                self.assertEqual(record["status"], "rejected")
                self.assertIn(reason, record["reasons"])
        row = case()
        row["ref"] = "A"
        self.assertIn("window_ref_mismatch", adapter.case_record(row, 0, True)["reasons"])

    def test_effect_flip_once_and_uncertainty_preserved(self):
        effect = case()["effect"]
        effect.update(effect_allele="C", other_allele="G", confidence_interval=[-0.1, 0.4], standard_error=0.12,
                      beta_alt_minus_ref=999)  # Caller hints never override raw explicit alleles.
        normalized = adapter.normalize_effect(effect, "C", "G")
        self.assertEqual(normalized["beta_raw"], 0.25)
        self.assertEqual(normalized["beta_alt_minus_ref"], -0.25)
        self.assertEqual(normalized["confidence_interval_alt_minus_ref"], [-0.4, 0.1])
        self.assertEqual(normalized["standard_error"], 0.12)
        effect.update(effect_allele="G", other_allele="C")
        self.assertEqual(adapter.normalize_effect(effect, "C", "G")["beta_alt_minus_ref"], 0.25)

    def test_unknown_or_wrong_effect_allele_rejected_and_definition_pending(self):
        for change, code in [({"orientation_known": False}, "effect_orientation_unknown"),
                             ({"effect_allele": "T"}, "effect_alleles_mismatch"),
                             ({"value": float("nan")}, "effect_nonfinite"),
                             ({"standard_error": -1}, "effect_standard_error_invalid")]:
            row = case()
            row["effect"].update(change)
            self.assertIn(code, adapter.case_record(row, 0, True)["reasons"])
        row = case()
        row["effect"]["definition"] = ""
        self.assertEqual(adapter.case_record(row, 0, True)["status"], "pending")

    def test_every_invalid_row_accounted_and_duplicate_all_rejected(self):
        ledger = self.ledger()
        ledger["cases"] = [case(effect=False), case(effect=False), None, {"ref": ["bad"]}]
        report = self.validate(ledger)
        self.assertEqual(len(report["records"]), 4)
        self.assertEqual(report["counts"]["submitted"], 4)
        self.assertEqual(report["counts"]["rejected"], 4)
        for row in report["records"][:2]:
            self.assertIn("duplicate_case_id", row["reasons"])
            self.assertIn("duplicate_locus", row["reasons"])

    def test_missing_identity_permission_or_raw_source_blocks(self):
        for mutation in (lambda l: l["dataset"].pop("version"), lambda l: l["dataset"].pop("sha256"),
                         lambda l: l["dataset"]["permission"].update(status="unknown"),
                         lambda l: l["dataset"].update(source_path=str(self.datasets / "missing.raw"))):
            ledger = self.ledger()
            mutation(ledger)
            report = self.validate(ledger)
            self.assertEqual(report["status"], "pending")
            self.assertFalse(report["ready_for_inference"])
        ledger = self.ledger()
        ledger["dataset"]["permission"]["status"] = "denied"
        self.assertEqual(self.validate(ledger)["status"], "rejected")

    def test_actual_raw_bytes_hash_and_path_boundary(self):
        ledger = self.ledger()
        Path(ledger["dataset"]["source_path"]).write_bytes(b"changed source")
        self.assertIn("private_file_sha_mismatch", self.validate(ledger)["records"][0]["reasons"])
        outside = Path(self.temp.name) / "outside.raw"
        outside.write_bytes(b"outside")
        ledger["dataset"].update(source_path=str(outside), sha256=sha(b"outside"))
        self.assertIn("private_path_escape", self.validate(ledger)["records"][0]["reasons"])
        link = self.datasets / "link.raw"
        link.symlink_to(outside)
        ledger["dataset"]["source_path"] = str(link)
        self.assertIn("private_path_symlink", self.validate(ledger)["records"][0]["reasons"])
        with self.assertRaisesRegex(adapter.AdapterError, "document_size_exceeded"):
            adapter.private_file(outside, outside.parent, sha(b"outside"), maximum=3)

    def test_selection_deterministic_outcome_independent_and_nonoverlapping(self):
        pool = [case(index) for index in range(113)]
        selected, records = adapter.deterministic_selection(pool, self.protocol["selection"]["seed"])
        reversed_selected, unused = adapter.deterministic_selection(list(reversed(pool)), self.protocol["selection"]["seed"])
        self.assertEqual(selected, reversed_selected)
        for row in pool:
            row["effect"]["value"] *= -4
        self.assertEqual(selected, adapter.deterministic_selection(pool, self.protocol["selection"]["seed"])[0])
        self.assertEqual(len(selected), 110)
        duplicate = [case(0), case(0), case(1, position=10002)]
        admitted, outcomes = adapter.deterministic_selection(duplicate, self.protocol["selection"]["seed"])
        self.assertEqual(len(admitted), 1)
        self.assertEqual([r["status"] for r in outcomes], ["rejected", "rejected", "validated"])
        overlap = [case(0), case(1, position=10002)]
        admitted, outcomes = adapter.deterministic_selection(overlap, self.protocol["selection"]["seed"])
        self.assertEqual(len(admitted), 1)
        self.assertEqual(sum("overlapping_selection_window" in r["reasons"] for r in outcomes), 1)

    def test_adapter_frozen_slots_no_replacement(self):
        ledger = self.ledger("adapter")
        report = self.validate(ledger)
        self.assertTrue(report["ready_for_inference"])
        ledger["cases"][0]["window"]["sequence"] = "N" * 4096
        report = self.validate(ledger)
        self.assertEqual(report["counts"]["submitted"], 10)
        self.assertEqual(report["counts"]["rejected"], 1)
        self.assertEqual(report["records"][0]["case_id"], ledger["cases"][0]["case_id"])
        self.assertFalse(report["ready_for_inference"])
        ledger["cases"][0] = case(999)
        self.assertIn("frozen_case_slot_mismatch", self.validate(ledger)["records"][0]["reasons"])

    def test_biological_review_and_frozen_snapshot_required(self):
        ledger = self.ledger("adapter")
        ledger["dataset"].pop("verification_receipt_path")
        self.assertEqual(self.validate(ledger)["status"], "pending")
        ledger = self.ledger("adapter")
        ledger["split_metadata"].pop("frozen_selection_path")
        self.assertEqual(self.validate(ledger)["status"], "pending")
        ledger = self.ledger("adapter")
        ledger["split_metadata"]["adapter_loci"].reverse()
        self.assertIn("selection_split_mismatch", self.validate(ledger)["records"][0]["reasons"])

    def test_review_receipt_requires_exact_scalar_types(self):
        changes = [("schema_version", True), ("schema_version", 1.0)]
        changes += [(name, alias) for name in
                    ("schema_verified", "effect_orientation_verified", "license_verified")
                    for alias in (1, 1.0)]
        for name, alias in changes:
            with self.subTest(field=name, alias=alias):
                ledger = self.ledger("adapter")
                dataset = ledger["dataset"]
                receipt, _ = adapter.read_json(dataset["verification_receipt_path"])
                receipt[name] = alias
                dataset["verification_receipt_path"], dataset["verification_receipt_sha256"] = self.write(self.prefix / "review.json", receipt)
                report = self.validate(ledger)
                self.assertFalse(report["ready_for_inference"])
                self.assertIn("dataset_review_receipt_mismatch", report["records"][0]["reasons"])

    def test_ledgers_and_selection_require_integer_versions(self):
        for alias in (True, 1.0):
            ledger = self.ledger()
            ledger["schema_version"] = alias
            self.assertIn("ledger_protocol_mismatch", self.validate(ledger)["records"][0]["reasons"])
        for document_name in ("normalization", "selection"):
            for alias in (True, 1.0):
                with self.subTest(document=document_name, alias=alias):
                    ledger = self.ledger("adapter")
                    split = ledger["split_metadata"]
                    normalized, _ = adapter.read_json(split["source_normalization_ledger_path"])
                    frozen, _ = adapter.read_json(split["frozen_selection_path"])
                    (normalized if document_name == "normalization" else frozen)["schema_version"] = alias
                    split["source_normalization_ledger_path"], split["source_normalization_ledger_sha256"] = self.write(self.datasets / "normalized.json", normalized)
                    frozen["normalization_sha256"] = split["source_normalization_ledger_sha256"]
                    split["frozen_selection_path"], split["frozen_selection_sha256"] = self.write(self.datasets / "selected.json", frozen)
                    with self.assertRaisesRegex(adapter.AdapterError, "selection_source_identity_mismatch"):
                        adapter.verify_selection(ledger, self.protocol, self.prefix)

    def test_prior_receipt_counts_and_frozen_payload_types_preserved(self):
        for name, alias in (("schema_version", True), ("schema_version", 1.0), ("validated", 10.0), ("rejected", False)):
            with self.subTest(field=name, alias=alias):
                ledger = self.ledger("evaluation")
                receipt = {"schema_version": 1, "phase": "adapter", "dataset_kind": "biological", "status": "passed",
                           "dataset_sha256": ledger["dataset"]["sha256"], "protocol_sha256": adapter.PROTOCOL_SHA256,
                           "weights_sha256": adapter.weights_pins(), "selection_sha256": ledger["split_metadata"]["frozen_selection_sha256"],
                           "counts": {"submitted": 10, "validated": 10, "rejected": 0, "pending": 0, "inferred": 10}}
                (receipt if name == "schema_version" else receipt["counts"])[name] = alias
                split = ledger["split_metadata"]
                split["adapter_receipt_path"], split["adapter_receipt_sha256"] = self.write(self.prefix / "prior.json", receipt)
                with self.assertRaisesRegex(adapter.AdapterError, "prior_biological_adapter_receipt_mismatch"):
                    adapter.verify_adapter_receipt(ledger, self.prefix, split["frozen_selection_sha256"])
        ledger = self.ledger("adapter")
        ledger["cases"][0]["window"]["provenance"]["fixture_only"] = 1
        self.assertIn("frozen_case_payload_mismatch", self.validate(ledger)["records"][0]["reasons"])

    def test_frozen_pool_binds_effect_and_provenance_not_only_id(self):
        for mutation in (lambda row: row["effect"].update(value=-123),
                         lambda row: row["effect"].update(effect_allele="C", other_allele="G"),
                         lambda row: row["effect"].update(definition="changed after prediction"),
                         lambda row: row["window"]["provenance"].update(changed=True)):
            ledger = self.ledger("adapter")
            mutation(ledger["cases"][0])
            report = self.validate(ledger)
            self.assertFalse(report["ready_for_inference"])
            self.assertEqual(report["counts"]["rejected"], 1)
            self.assertIn("frozen_case_payload_mismatch", report["records"][0]["reasons"])
        ledger = self.ledger("adapter")
        receipt, unused = adapter.read_json(ledger["dataset"]["verification_receipt_path"])
        receipt["normalization_sha256"] = "0" * 64
        ledger["dataset"]["verification_receipt_path"], ledger["dataset"]["verification_receipt_sha256"] = self.write(self.prefix / "review.json", receipt)
        self.assertIn("dataset_review_receipt_mismatch", self.validate(ledger)["records"][0]["reasons"])

    def test_execution_failure_keeps_finished_and_unavailable_slots(self):
        ledger = self.ledger("adapter")
        validation = self.validate(ledger)
        partial = copy.deepcopy(validation)
        partial.update(status="running", trained_weights_loaded=True, ledger_sha256="1" * 64)
        partial["records"][0].update(status="inferred", score=0.2)
        path, unused = self.write(self.prefix / "progress.json", partial)
        failed = adapter.merge_execution_failure(validation, {"status": "failed", "error_code": "phase_deadline_exceeded"}, path, "1" * 64)
        self.assertEqual(failed["status"], "failed")
        self.assertEqual(failed["counts"]["inferred"], 1)
        self.assertEqual(failed["counts"]["failed"], 9)
        self.assertEqual(len(failed["records"]), 10)
        self.assertEqual(failed["records"][0]["status"], "inferred")
        self.assertEqual(failed["records"][1]["reasons"], ["phase_deadline_exceeded"])
        missing = adapter.merge_execution_failure(self.validate(ledger), {"status": "failed", "error_code": "worker_failed_or_report_missing"},
                                                  self.prefix / "missing.json", "1" * 64)
        self.assertEqual(missing["counts"]["inferred"], 0)
        self.assertEqual(missing["counts"]["failed"], 10)

    def test_evaluation_requires_same_passed_biological_adapter(self):
        ledger = self.ledger("evaluation")
        report = self.validate(ledger)
        self.assertEqual(report["status"], "pending")
        split = ledger["split_metadata"]
        receipt = {"schema_version": 1, "phase": "adapter", "dataset_kind": "biological", "status": "passed",
                   "counts": {"submitted": 10, "validated": 10, "rejected": 0, "pending": 0, "inferred": 10},
                   "dataset_sha256": ledger["dataset"]["sha256"], "protocol_sha256": adapter.PROTOCOL_SHA256,
                   "weights_sha256": adapter.weights_pins(), "selection_sha256": split["frozen_selection_sha256"]}
        for bad in ({"dataset_kind": "instrumentation_control"}, {"status": "failed"}, {"dataset_sha256": "0" * 64}, {"weights_sha256": {}}, {"selection_sha256": "0" * 64}):
            invalid = {**receipt, **bad}
            split["adapter_receipt_path"], split["adapter_receipt_sha256"] = self.write(self.prefix / "adapter.json", invalid)
            self.assertFalse(self.validate(ledger)["ready_for_inference"])
        split["adapter_receipt_path"], split["adapter_receipt_sha256"] = self.write(self.prefix / "adapter.json", receipt)
        self.assertTrue(self.validate(ledger)["ready_for_inference"])

    def test_sign_zero_tie_and_constant_semantics(self):
        rows = [{"score": 0.0, "beta_alt_minus_ref": 0.0}, {"score": 0.0, "beta_alt_minus_ref": 1.0},
                {"score": -1.0, "beta_alt_minus_ref": -1.0}, {"score": 1.0, "beta_alt_minus_ref": 0.0}]
        report = adapter.biological_metrics(rows)
        self.assertEqual(report["primary_sign_agreement"], {"agreed": 2, "denominator": 4, "fraction": 0.5})
        self.assertEqual(report["secondary_nonzero_effect_sign_agreement"], {"agreed": 1, "denominator": 2, "fraction": 0.5})
        self.assertEqual(report["exact_zero_effects"], 2)
        self.assertEqual(adapter.average_ranks([1, 1, 3]), [1.5, 1.5, 3])
        constant = adapter.biological_metrics([{"score": 1, "beta_alt_minus_ref": 2}, {"score": 1, "beta_alt_minus_ref": 3}])
        self.assertIsNone(constant["spearman"]["correlation"])
        self.assertEqual(constant["spearman"]["undefined_reason"], "constant_ranked_vector")
        increasing = adapter.biological_metrics([{"score": s, "beta_alt_minus_ref": b} for s, b in [(1, 2), (1, 2), (3, 9)]])
        self.assertAlmostEqual(increasing["spearman"]["correlation"], 1)

    def test_validate_only_does_not_import_torch_or_load_weights(self):
        ledger_path, unused = self.write(self.datasets / "ledger.json", self.ledger())
        code = "import sys; import biological_adapter as a; sys.argv=['adapter','--ledger',sys.argv[1],'--prefix',sys.argv[2],'--validate-only']; result=a.main(); assert 'torch' not in sys.modules; raise SystemExit(result)"
        process = subprocess.run([sys.executable, "-c", code, ledger_path, str(self.prefix)], cwd=adapter.HERE,
                                 capture_output=True, text=True, timeout=10)
        self.assertEqual(process.returncode, 0, process.stderr)
        summary = json.loads(process.stdout)
        report = json.loads(Path(summary["report"]).read_text())
        self.assertFalse(report["trained_weights_loaded"])
        self.assertEqual(os.stat(summary["report"]).st_mode & 0o777, 0o600)

    def test_run_pending_never_launches_requested_interpreter(self):
        ledger = self.ledger()
        ledger["dataset"]["permission"]["status"] = "unknown"
        ledger_path, unused = self.write(self.datasets / "pending-ledger.json", ledger)
        process = subprocess.run([sys.executable, str(adapter.HERE / "biological_adapter.py"), "--ledger", ledger_path,
                                  "--prefix", str(self.prefix), "--python", "/definitely/missing/interpreter", "--run"],
                                 capture_output=True, text=True, timeout=10)
        self.assertEqual(process.returncode, 2, process.stderr)
        report = json.loads(Path(json.loads(process.stdout)["report"]).read_text())
        self.assertEqual(report["status"], "pending")
        self.assertNotIn("execution", report)
        self.assertFalse(report["trained_weights_loaded"])

    def test_worker_missing_source_fails_without_model_and_keeps_case(self):
        ledger_path, unused = self.write(self.datasets / "run-ledger.json", self.ledger())
        process = subprocess.run([sys.executable, str(adapter.HERE / "biological_adapter.py"), "--ledger", ledger_path,
                                  "--prefix", str(self.prefix), "--source", str(self.prefix / "missing-source"), "--run"],
                                 capture_output=True, text=True, timeout=10)
        self.assertEqual(process.returncode, 1, process.stderr)
        report = json.loads(Path(json.loads(process.stdout)["report"]).read_text())
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["counts"]["submitted"], 1)
        self.assertEqual(report["counts"]["failed"], 1)
        self.assertEqual(report["counts"]["inferred"], 0)
        self.assertFalse(report["trained_weights_loaded"])
        self.assertNotIn(str(self.prefix), json.dumps(report))

    def test_malformed_metadata_records_reason_instead_of_crashing(self):
        template = self.ledger()
        for field in template["dataset"]:
            for value in (None, [], {}, True, 1, ""):
                with self.subTest(field=field, kind=type(value).__name__):
                    ledger = copy.deepcopy(template)
                    ledger["dataset"][field] = value
                    report = self.validate(ledger)
                    self.assertFalse(report["ready_for_inference"])
                    self.assertEqual(len(report["records"]), 1)
        for value in (None, [], {}, True, 1, ""):
            ledger = copy.deepcopy(template)
            ledger["split_metadata"] = value
            self.assertFalse(self.validate(ledger)["ready_for_inference"])

    def test_protocol_pin_and_json_duplicate_or_nonfinite_rejected(self):
        path = self.datasets / "bad.json"
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}'):
            path.write_bytes(raw)
            with self.assertRaises(adapter.AdapterError):
                adapter.read_json(path)
        path.write_text('{}')
        with self.assertRaisesRegex(adapter.AdapterError, "protocol_not_frozen_pin"):
            adapter.load_protocol(path)

    def test_json_fifo_and_symlink_rejected_without_blocking(self):
        fifo = self.datasets / "fifo.json"
        os.mkfifo(fifo)
        with self.assertRaisesRegex(adapter.AdapterError, "document_not_regular"):
            adapter.read_json(fifo)
        source, unused = self.write(self.datasets / "regular.json", {"fixture": True})
        link = self.datasets / "alias.json"
        link.symlink_to(source)
        with self.assertRaises(OSError):
            adapter.read_json(link)


if __name__ == "__main__":
    unittest.main()
