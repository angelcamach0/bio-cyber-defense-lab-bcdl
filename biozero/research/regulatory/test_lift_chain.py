"""Coordinate and rejection regressions with toy alignments, never biological data."""
import gzip
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import lift_chain as chain


PLUS = "chain 99 chr8 1000 + 10 30 chr8 2000 + 100 120 1\n20\n"
MINUS = "chain 99 chr8 1000 + 10 30 chr8 2000 - 100 120 1\n20\n"
GAPS = "chain 99 chr8 1000 + 10 40 chr8 2000 + 100 135 1\n10 10 15\n10\n"


class MappingTests(unittest.TestCase):
    def fails(self, code, function, *args, **kwargs):
        with self.assertRaises(chain.ChainError) as context:
            function(*args, **kwargs)
        self.assertEqual(context.exception.code, code)
        self.assertEqual(str(context.exception), code)

    def test_plus_endpoints_are_half_open(self):
        index = chain.parse_chain(PLUS)
        for start, end, target in ((10, 11, (100, 101)), (29, 30, (119, 120)),
                                   (10, 30, (100, 120))):
            result = index.map_interval("chr8", start, end)
            self.assertEqual((result["target_start"], result["target_end"]), target)
            self.assertEqual(result["source_size"], 1000)
            self.assertEqual(result["target_size"], 2000)
            self.assertEqual(result["chain_id"], 1)
        self.fails("no_mapping", index.map_interval, "chr8", 30, 31)
        self.fails("gapped_interval", index.map_interval, "chr8", 9, 11)

    def test_minus_uses_query_size_and_interval_end(self):
        index = chain.parse_chain(MINUS)
        for start, end, target in ((10, 11, (1899, 1900)), (29, 30, (1880, 1881)),
                                   (10, 30, (1880, 1900)), (15, 18, (1892, 1895))):
            result = index.map_interval("chr8", start, end)
            self.assertEqual((result["target_start"], result["target_end"]), target)
            self.assertEqual(result["strand"], "-")

    def test_variant_peak_converts_vcf_position_once(self):
        mapped = chain.parse_chain(MINUS).map_variant_peak("chr8", 11, 10, 30)
        self.assertEqual(mapped["snp"]["source_start"], 10)
        self.assertEqual(mapped["snp"]["target_start"], 1899)
        self.assertEqual(mapped["peak"]["target_start"], 1880)
        self.assertEqual(mapped["peak"]["target_end"], 1900)
        self.fails("snp_outside_peak", chain.parse_chain(PLUS).map_variant_peak,
                   "chr8", 31, 10, 30)

    def test_source_and_target_gaps_cannot_be_bridged(self):
        index = chain.parse_chain(GAPS)
        self.assertEqual(index.map_interval("chr8", 30, 31)["target_start"], 125)
        for start, end in ((19, 31), (20, 30), (15, 35)):
            self.fails("gapped_interval", index.map_interval, "chr8", start, end)
        target_gap = chain.parse_chain(
            "chain 99 chr8 1000 + 10 30 chr8 2000 + 100 125 1\n10 0 5\n10\n")
        self.fails("gapped_interval", target_gap.map_interval, "chr8", 19, 21)
        adjacent = chain.parse_chain(
            "chain 99 chr8 1000 + 10 30 chr8 2000 + 100 120 1\n10 0 0\n10\n")
        self.fails("gapped_interval", adjacent.map_interval, "chr8", 19, 21)

    def test_duplicate_mapping_chains_are_ambiguous_even_identical_targets(self):
        second = PLUS.replace("120 1\n", "120 2\n")
        index = chain.parse_chain(PLUS + "\n" + second)
        self.fails("ambiguous_mapping", index.map_interval, "chr8", 10, 11)
        partial = "chain 99 chr8 1000 + 15 20 chr8 2000 + 500 505 2\n5\n"
        index = chain.parse_chain(PLUS + "\n" + partial)
        self.fails("ambiguous_mapping", index.map_interval, "chr8", 10, 30)
        self.fails("ambiguous_mapping", index.map_variant_peak, "chr8", 11, 10, 30)

    def test_contigs_are_explicit_and_interchromosomal_maps_reject(self):
        toy = chain.parse_chain(PLUS.replace("chr8", "toy"))
        self.assertEqual(toy.map_interval("toy", 10, 11)["target_start"], 100)
        self.fails("contig_not_allowed", toy.map_variant_peak, "toy", 11, 10, 30)
        self.assertEqual(toy.map_variant_peak("toy", 11, 10, 30,
                                             allowed_chromosomes=None)["snp"]["chain_id"], 1)
        other = chain.parse_chain(PLUS.replace("chr8 2000", "chr9 2000"))
        self.fails("interchromosomal_mapping", other.map_interval, "chr8", 10, 11)
        self.assertEqual(other.map_interval("chr8", 10, 11,
                         require_same_chromosome=False)["target_chrom"], "chr9")

    def test_unknown_and_invalid_intervals_do_not_map(self):
        index = chain.parse_chain(PLUS)
        self.fails("no_mapping", index.map_interval, "chr9", 10, 11)
        for start, end in ((True, 20), (-1, 20), (20, 20), (20, 19), (10, 11.0)):
            self.fails("interval_invalid", index.map_interval, "chr8", start, end)
        self.fails("interval_invalid", index.map_variant_peak, "chr8", True, 10, 30)
        self.fails("option_invalid", index.map_interval, "chr8", 10, 11,
                   allowed_chromosomes="chr8")


class ParseTests(unittest.TestCase):
    def fails(self, code, text, **kwargs):
        with self.assertRaises(chain.ChainError) as context:
            chain.parse_chain(text, **kwargs)
        self.assertEqual(context.exception.code, code)

    def test_headers_strands_limits_and_integer_spellings_are_strict(self):
        for text in (PLUS.replace("1000 +", "1000 -"),
                     PLUS.replace("2000 +", "2000 ?"),
                     PLUS.replace("10 30", "30 10"),
                     PLUS.replace("1000", "20"),
                     PLUS.replace("chain 99", "chain 99 extra")):
            self.fails("header_invalid", text)
        for token in ("-1", "+99", "99.0"):
            self.fails("integer_invalid", PLUS.replace("chain 99", "chain " + token))

    def test_complete_final_blocks_and_total_spans_are_required(self):
        self.fails("chain_end_mismatch", PLUS.replace("\n20\n", "\n19\n"))
        self.fails("block_exceeds_header", PLUS.replace("\n20\n", "\n21\n"))
        self.fails("block_invalid", PLUS.replace("\n20\n", "\n0\n"))
        self.fails("block_invalid", PLUS.replace("\n20\n", "\n10 0\n"))
        self.fails("chain_unterminated", PLUS.replace("\n20\n", "\n10 0 0\n"))
        self.fails("integer_invalid", GAPS.replace("10 10 15", "10 -1 15"))

    def test_ids_sizes_separators_and_trailing_input_are_checked(self):
        self.fails("duplicate_chain_id", PLUS + "\n" + PLUS)
        second = PLUS.replace("120 1\n", "120 2\n")
        self.fails("chain_separator_missing", PLUS + second)
        self.fails("chromosome_size_conflict", PLUS + "\n" + second.replace("1000", "1001"))
        self.fails("header_invalid", PLUS + "\ntrailing junk\n")
        self.fails("chain_unterminated", PLUS.replace("\n20", "\n\n20"))
        self.fails("chain_empty", "\n")

    def test_all_resource_caps_and_nonascii_are_rejected(self):
        second = PLUS.replace("120 1\n", "120 2\n")
        self.fails("chain_count_exceeded", PLUS + "\n" + second, max_chains=1)
        self.fails("block_count_exceeded", GAPS, max_blocks=1)
        self.fails("expanded_size_exceeded", PLUS, max_expanded_bytes=10)
        self.fails("line_size_exceeded", " " * 8193 + "\n")
        self.fails("encoding_invalid", PLUS.replace("chr8", "chré"))
        for kwargs in ({"max_blocks": True}, {"max_chains": 1.0}, {"max_expanded_bytes": 0}):
            self.fails("limit_invalid", PLUS, **kwargs)


class LoaderTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "toy.chain.gz"
        self.raw = gzip.compress(PLUS.encode("ascii"), mtime=0)
        self.path.write_bytes(self.raw)
        self.path.chmod(0o600)
        self.sha = hashlib.sha256(self.raw).hexdigest()

    def fails(self, code, **kwargs):
        with self.assertRaises(chain.ChainError) as context:
            chain.load_chain(self.path, **kwargs)
        self.assertEqual(context.exception.code, code)

    def test_loader_pins_private_gzip_and_reuses_descriptor(self):
        original = chain.gzip.GzipFile
        recorded = []
        def gzip_reader(*args, **kwargs):
            recorded.append((kwargs["fileobj"].fileno(), kwargs["fileobj"].tell()))
            return original(*args, **kwargs)
        with mock.patch.object(chain.gzip, "GzipFile", side_effect=gzip_reader):
            index = chain.load_chain(self.path, expected_sha256=self.sha)
        self.assertEqual(index.source_sha256, self.sha)
        self.assertEqual(len(recorded), 1)
        self.assertEqual(recorded[0][1], 0)
        self.assertEqual(index.map_interval("chr8", 10, 11)["target_start"], 100)

    def test_wrong_digest_modes_symlinks_and_special_files_reject(self):
        self.fails("sha256_mismatch", expected_sha256="0" * 64)
        self.fails("sha256_invalid", expected_sha256=True)
        self.path.chmod(0o644)
        self.fails("file_not_private_owned")
        self.path.chmod(0o600)
        owner = os.getuid()
        with mock.patch.object(chain.os, "getuid", return_value=owner + 1):
            self.fails("file_not_private_owned")
        link = Path(self.directory.name) / "alias.gz"
        link.symlink_to(self.path)
        with self.assertRaises(chain.ChainError) as context:
            chain.load_chain(link)
        self.assertEqual(context.exception.code, "file_open_failed")
        fifo = Path(self.directory.name) / "fifo"
        os.mkfifo(fifo, 0o600)
        with self.assertRaises(chain.ChainError) as context:
            chain.load_chain(fifo)
        self.assertEqual(context.exception.code, "file_not_regular")

    def test_crc_truncation_and_bounded_inflation_reject(self):
        damaged = bytearray(self.raw)
        damaged[-8] ^= 1
        malformed_deflate = self.raw[:10] + b"\x07" + b"\x00" * 8
        for raw in (damaged, self.raw[:-4], b"not gzip", malformed_deflate):
            self.path.write_bytes(raw)
            self.fails("gzip_invalid")
        self.path.write_bytes(self.raw)
        self.fails("compressed_size_exceeded", max_compressed_bytes=len(self.raw)-1)
        self.fails("expanded_size_exceeded", max_expanded_bytes=10)

    def test_mutation_after_hash_is_detected_even_when_new_gzip_is_valid(self):
        original = chain.gzip.GzipFile
        changed = gzip.compress(PLUS.replace("chain 99", "chain 88").encode("ascii"), mtime=0)
        def replacing_reader(*args, **kwargs):
            self.path.write_bytes(changed)
            return original(*args, **kwargs)
        with mock.patch.object(chain.gzip, "GzipFile", side_effect=replacing_reader):
            self.fails("source_changed_during_read", expected_sha256=self.sha)

    def test_second_compressed_pass_remains_bounded_after_mutation(self):
        original = chain.gzip.GzipFile
        def growing_reader(*args, **kwargs):
            self.path.write_bytes(self.raw + b"\x00" * 500)
            return original(*args, **kwargs)
        with mock.patch.object(chain.gzip, "GzipFile", side_effect=growing_reader):
            self.fails("compressed_size_exceeded", expected_sha256=self.sha,
                       max_compressed_bytes=len(self.raw))


if __name__ == "__main__":
    unittest.main()
