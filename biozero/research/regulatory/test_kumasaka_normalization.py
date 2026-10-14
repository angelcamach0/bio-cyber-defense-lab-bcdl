"""Toy source-to-prepool regressions; no downloads, reference DNA or inference."""
import gzip
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import kumasaka_normalization as norm

PLUS = "chain 99 chr8 1000 + 10 30 chr8 2000 + 100 120 1\n20\n"
MINUS = "chain 99 chr8 1000 + 10 30 chr8 2000 - 100 120 1\n20\n"


def source(peak=1, pos=11, chrom="8", ref="C", alt="T", beta="1", se="0.2",
           af="0.3", loc="1", p_lead="0.1"):
    return [str(peak), chrom, str(pos), "rs" + str(pos), ref, alt, af, loc, p_lead, beta, se, "0.01"]


def peak(identifier=1, chrom="8", left=10, right=30, p_caqtl="0.2"):
    return [chrom, str(left), str(right), str(identifier), "50", "100", p_caqtl, "0.3", "0.1"]


def table(header, rows):
    return "\t".join(header) + "\n" + "".join("\t".join(row) + "\n" for row in rows)


class NormalizationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.base = Path(self.directory.name)

    def fixture(self, rows=None, peaks=None, chain=PLUS, source_header=norm.SOURCE_HEADER,
                peak_header=norm.PEAK_HEADER):
        values = (table(source_header, rows if rows is not None else [source()]),
                  table(peak_header, peaks if peaks is not None else [peak()]), chain)
        paths, hashes = [], []
        for name, text in zip(("source.gz", "peaks.gz", "chain.gz"), values):
            path = self.base / name
            raw = gzip.compress(text.encode("ascii"), mtime=0)
            path.write_bytes(raw)
            path.chmod(0o600)
            paths.append(path)
            hashes.append(hashlib.sha256(raw).hexdigest())
        return paths, dict(zip(("source_sha256", "peaks_sha256", "chain_sha256"), hashes))

    def prepare(self, **kwargs):
        paths, pins = self.fixture(**kwargs)
        return norm.prepare_precandidates(*paths, **pins)

    def fails(self, code, paths, pins, **kwargs):
        with self.assertRaises(norm.NormalizationError) as context:
            norm.prepare_precandidates(*paths, **pins, **kwargs)
        self.assertEqual(context.exception.code, code)
        self.assertEqual(str(context.exception), code)

    def test_plus_zero_beta_and_probabilities_preserved_without_effect_filter(self):
        result = self.prepare(rows=[source(beta="0", p_lead="0", af="1")],
                              peaks=[peak(p_caqtl="0")])
        candidate = result["precandidates"][0]
        self.assertEqual(candidate["source_chrom"], "chr8")
        self.assertEqual(candidate["mapped_position_1based"], 101)
        self.assertEqual(candidate["source_effect"]["value"], 0)
        self.assertEqual(candidate["source_effect"]["standard_error"], 0.2)
        self.assertEqual(candidate["source_p_lead"], 0)
        self.assertEqual(candidate["source_af"], 1)
        self.assertEqual(candidate["peak"]["p_caqtl"], 0)
        self.assertEqual(result["status"], "insufficient_precandidates")
        self.assertEqual(result["counts"]["biological_loci_inferred"], 0)
        self.assertNotIn("review_status", result)
        self.assertNotIn("window", candidate)
        self.assertNotIn("ref", candidate)

    def test_minus_complements_names_without_beta_negation(self):
        candidate = self.prepare(chain=MINUS, rows=[source(beta="-2")])["precandidates"][0]
        self.assertEqual(candidate["source_ref"], "C")
        self.assertEqual(candidate["source_alt"], "T")
        self.assertEqual(candidate["oriented_source_ref"], "G")
        self.assertEqual(candidate["oriented_source_alt"], "A")
        self.assertEqual(candidate["source_effect"]["value"], -2)
        self.assertEqual(candidate["source_effect"]["effect_allele"], "T")
        self.assertEqual(candidate["mapped_position_1based"], 1900)

    def test_optional_missing_or_invalid_annotations_preserve_peak_and_raw_values(self):
        peak_values = peak()
        peak_values[4:] = ["NA", "", ".", "nan", "unparsed"]
        source_values = source(p_lead="NA")
        source_values[-1] = "inf"
        result = self.prepare(rows=[source_values], peaks=[peak_values])
        self.assertEqual(len(result["precandidates"]), 1)
        candidate = result["precandidates"][0]
        for name in ("gc", "height", "p_caqtl", "pmr", "p_eqtl_coloc"):
            self.assertIsNone(candidate["peak"][name])
        self.assertEqual(candidate["peak"]["raw_values"], peak_values)
        self.assertEqual(candidate["source_raw_values"], source_values)
        self.assertIsNone(candidate["source_p_lead"])
        self.assertIsNone(candidate["source_log10_bf"])
        self.assertEqual(candidate["source_annotation_states"], {"p_lead": "missing", "log_bf": "invalid"})
        self.assertEqual(candidate["peak"]["annotation_states"]["p_eqtl_coloc"], "invalid")
        self.assertEqual(result["outcomes"][0]["reasons"], [])
        self.assertEqual(result["counts"]["source_annotation_state_counts"]["log_bf:invalid"], 1)

    def test_every_row_outcome_retains_origin_raw_values_and_denominator(self):
        rows = [source(), source(peak=2, pos=12, loc="0"), source(peak=3, pos=13, ref="CC"),
                source(peak=4, pos=14, chrom="7"), ["malformed"]]
        result = self.prepare(rows=rows)
        self.assertEqual(result["counts"]["source_rows"], 5)
        self.assertEqual(sum(result["counts"]["status_counts"].values()), 5)
        self.assertEqual(result["counts"]["precandidates"], 1)
        for number, record in enumerate(result["outcomes"], 1):
            self.assertEqual(record["source_row_number"], number)
            self.assertEqual(record["raw_values"], rows[number-1])
            self.assertTrue(record["origin_row_id"].endswith(":row:" + str(number)))
            self.assertEqual(len(record["source_row_sha256"]), 64)
        self.assertIn("column_count_invalid", result["outcomes"][-1]["reasons"])

    def test_all_rows_of_tied_focal_peak_reject_without_effect_choice(self):
        result = self.prepare(rows=[source(pos=11, beta="-100"), source(pos=12, beta="100"),
                                    source(pos=13, loc="0")])
        self.assertEqual(result["counts"]["tied_focal_peaks"], 1)
        self.assertEqual(result["precandidates"], [])
        self.assertTrue(all("tied_focal_peak" in row["reasons"] for row in result["outcomes"]))
        self.assertEqual(result["counts"]["reason_counts"]["tied_focal_peak"], 3)
        self.assertEqual(result["status"], "no_precandidates")

    def test_multiple_focal_peaks_for_same_snp_reject_every_association(self):
        result = self.prepare(rows=[source(peak=1), source(peak=2, beta="-1")],
                              peaks=[peak(identifier=1), peak(identifier=2)])
        self.assertEqual(result["counts"]["multiple_focal_peak_snp_loci"], 1)
        self.assertEqual(result["precandidates"], [])
        self.assertTrue(all("multiple_focal_peaks_for_snp" in row["reasons"] for row in result["outcomes"]))

    def test_duplicate_rows_and_duplicate_peak_metadata_cannot_be_rescued(self):
        duplicate = self.prepare(rows=[source(), source()])
        self.assertEqual(duplicate["precandidates"], [])
        self.assertTrue(all("duplicate_source_association" in row["reasons"] for row in duplicate["outcomes"]))
        result = self.prepare(peaks=[peak(), peak(right=29)])
        self.assertEqual(result["counts"]["duplicate_peak_ids"], 1)
        self.assertEqual(result["precandidates"], [])
        self.assertIn("duplicate_peak_id", result["outcomes"][0]["reasons"])
        self.assertTrue(all(row["status"] == "excluded" for row in result["peak_outcomes"]))

    def test_membership_uses_pos_minus_one_and_half_open_peak_end(self):
        result = self.prepare(rows=[source(peak=1, pos=11), source(peak=2, pos=31)],
                              peaks=[peak(identifier=1), peak(identifier=2)])
        self.assertEqual(len(result["precandidates"]), 1)
        self.assertIn("source_snp_outside_focal_peak", result["outcomes"][1]["reasons"])

    def test_whole_peak_gap_and_ambiguous_chains_reject(self):
        gap = "chain 99 chr8 1000 + 10 30 chr8 2000 + 100 135 1\n10 0 15\n10\n"
        result = self.prepare(chain=gap)
        self.assertEqual(result["precandidates"], [])
        self.assertIn("mapping_gapped_interval", result["outcomes"][0]["reasons"])
        second = PLUS.replace("120 1\n", "120 2\n")
        result = self.prepare(chain=PLUS + "\n" + second)
        self.assertIn("mapping_ambiguous_mapping", result["outcomes"][0]["reasons"])

    def test_type_enums_and_finite_effect_requirements_are_row_exclusions(self):
        invalid = [source(loc="3"), source(beta="nan"), source(se="0"), source(se="inf"),
                   source(af="1.1"), source(chrom="chr8"), source(chrom="08"),
                   source(pos=True), source(ref="a"), source(ref="C", alt="C")]
        result = self.prepare(rows=invalid)
        self.assertEqual(result["counts"]["source_rows"], len(invalid))
        self.assertEqual(result["precandidates"], [])
        self.assertTrue(all(row["reasons"] for row in result["outcomes"]))

    def test_presample_256_is_deterministic_and_does_not_use_beta(self):
        rows = [source(peak=i+1, pos=101+i*10) for i in range(270)]
        peaks = [peak(identifier=i+1, left=100+i*10, right=101+i*10) for i in range(270)]
        long_chain = "chain 99 chr8 10000 + 0 5000 chr8 10000 + 100 5100 1\n5000\n"
        paths, pins = self.fixture(rows=rows, peaks=peaks, chain=long_chain)
        first = norm.prepare_precandidates(*paths, **pins)
        second = norm.prepare_precandidates(*paths, **pins)
        self.assertEqual(first["freeze_sha256"], second["freeze_sha256"])
        self.assertEqual(len(first["precandidates"]), 256)
        self.assertEqual(first["counts"]["status_counts"]["mapped_not_presampled"], 14)
        self.assertEqual(first["status"], "precandidates_frozen_awaiting_references")
        self.assertEqual(first["freeze_sha256"], hashlib.sha256(norm.canonical_bytes(first["freeze"])).hexdigest())
        ranks = [row["prepool_rank_sha256"] for row in first["precandidates"]]
        self.assertEqual(ranks, sorted(ranks))
        candidate = dict(first["precandidates"][0])
        original = norm.prepool_rank(candidate, pins["source_sha256"])
        candidate["source_effect"] = {"value": -1000000}
        self.assertEqual(norm.prepool_rank(candidate, pins["source_sha256"]), original)
        # Source digest is deliberately bound: editing source bytes requires a new freeze.
        candidate["oriented_source_alt"] = "A"
        self.assertNotEqual(norm.prepool_rank(candidate, pins["source_sha256"]), original)

    def test_presample_hash_matches_frozen_field_order_and_domain_golden(self):
        pin = "0" * 64
        candidate = {"origin_row_id": pin + ":row:1", "mapped_chrom": "chr8",
                     "mapped_position_1based": 101, "oriented_source_ref": "C",
                     "oriented_source_alt": "T"}
        self.assertEqual(norm.prepool_rank(candidate, pin),
                         "7a5ddd90c0c2fd8ba136946b693906e7506c5331b697b5c21bc51a946b7af037")

    def test_schema_digest_seed_permissions_and_ancestor_symlink_gates(self):
        paths, pins = self.fixture()
        bad = dict(pins, source_sha256="0" * 64)
        self.fails("sha256_mismatch", paths, bad)
        self.fails("sha256_invalid", paths, dict(pins, chain_sha256=True))
        self.fails("seed_not_frozen", paths, pins, seed="another-seed")
        paths[0].chmod(0o644)
        self.fails("private_file_not_owned_600", paths, pins)
        paths[0].chmod(0o600)
        alias = self.base / "alias"
        alias.symlink_to(self.base, target_is_directory=True)
        bad_paths = [alias / paths[0].name, *paths[1:]]
        self.fails("private_path_open_failed", bad_paths, pins)
        with mock.patch.object(norm.os, "getuid", return_value=os.getuid()+1):
            self.fails("chain_file_not_private_owned", paths, pins)
        paths, pins = self.fixture(source_header=(*norm.SOURCE_HEADER[:-1], "wrong"))
        self.fails("table_header_mismatch", paths, pins)

    def test_crc_line_and_aggregate_resource_caps_are_enforced(self):
        paths, pins = self.fixture()
        total_compressed = paths[0].stat().st_size + paths[1].stat().st_size
        self.fails("compressed_size_exceeded", paths, pins, max_compressed_bytes=total_compressed-1)
        total_expanded = sum(len(gzip.decompress(p.read_bytes())) for p in paths[:2])
        self.fails("expanded_size_exceeded", paths, pins, max_expanded_bytes=total_expanded-1)
        self.fails("row_limit_exceeded", paths, pins, max_rows=1)
        self.fails("limit_invalid", paths, pins, max_rows=True)
        damaged = bytearray(paths[0].read_bytes())
        damaged[-8] ^= 1
        paths[0].write_bytes(damaged)
        pins["source_sha256"] = hashlib.sha256(damaged).hexdigest()
        self.fails("gzip_invalid", paths, pins)
        huge = source()
        huge[3] = "r" * 8193
        paths, pins = self.fixture(rows=[huge])
        self.fails("line_size_exceeded", paths, pins)

    def test_source_mutation_after_first_hash_rejects_even_valid_new_gzip(self):
        paths, pins = self.fixture()
        original = norm.gzip.GzipFile
        changed = gzip.compress(table(norm.SOURCE_HEADER, [source(beta="2")]).encode("ascii"), mtime=0)
        opened_tables = []
        def replacing_reader(*args, **kwargs):
            if isinstance(kwargs.get("fileobj"), norm._Compressed):
                opened_tables.append(True)
                if len(opened_tables) == 2:
                    paths[0].write_bytes(changed)
            return original(*args, **kwargs)
        with mock.patch.object(norm.gzip, "GzipFile", side_effect=replacing_reader):
            self.fails("source_changed_during_read", paths, pins)


if __name__ == "__main__":
    unittest.main()
