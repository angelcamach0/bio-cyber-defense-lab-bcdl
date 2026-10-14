# SPDX-License-Identifier: AGPL-3.0-only
import importlib.util
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("evaluate", HERE / "evaluate_variants.py")
evaluate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evaluate)
fixture_path = HERE.parent / "fixtures" / "variant-smoke"
spec = importlib.util.spec_from_file_location("generate", fixture_path / "generate.py")
generate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generate)


class VariantEvaluationTests(unittest.TestCase):
    def test_counts_and_reproducibility_detect_errors(self):
        a, b, c = ("chr", 1, "A", "C"), ("chr", 2, "A", "G"), ("chr", 3, "A", "T")
        report = evaluate.evaluate({a, b}, {a, c}, {a})
        self.assertEqual((report["tp"], report["fp"], report["fn"]), (1, 1, 1))
        self.assertEqual(report["evaluation_status"], "failed")
        self.assertFalse(report["reproducible_callset"])

    def test_equivalent_padded_snp_and_indel_are_normalized(self):
        reference = {"chr": "CAAAAAGT"}
        self.assertEqual(evaluate.normalize_variant("chr", 6, "AG", "AT", reference), ("chr", 7, "G", "T"))
        self.assertEqual(evaluate.normalize_variant("chr", 3, "A", "AA", reference), ("chr", 1, "C", "CA"))

    def test_reference_mismatch_and_symbolic_alleles_are_rejected(self):
        for ref, alt in (("T", "G"), ("A", "<DEL>")):
            with self.subTest(ref=ref, alt=alt), self.assertRaises(ValueError):
                evaluate.normalize_variant("chr", 1, ref, alt, {"chr": "ACGT"})

    def test_fixture_regenerates_identically_and_has_three_truth_variants(self):
        with tempfile.TemporaryDirectory() as directory:
            generate.generate(directory)
            for name in ("reference.fa", "reads.fastq", "expected.vcf", "manifest.json"):
                self.assertEqual((Path(directory) / name).read_bytes(), (fixture_path / name).read_bytes())
            reference = evaluate.read_reference(Path(directory) / "reference.fa")
            expected = evaluate.read_variants(Path(directory) / "expected.vcf", reference)
            self.assertEqual(len(expected), 3)
            self.assertEqual(evaluate.evaluate(expected, expected, expected)["evaluation_status"], "passed")


if __name__ == "__main__":
    unittest.main()
