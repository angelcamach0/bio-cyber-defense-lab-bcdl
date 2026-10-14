# SPDX-License-Identifier: AGPL-3.0-only
import gzip
import pathlib
import tempfile
import unittest

from public_vcf import export_alleles, _MODULE


class PublicExportTest(unittest.TestCase):
    def test_paths_samples_annotations_removed_alleles_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            reference = base / 'reference.fa'
            reference.write_text('>synthetic\nACGTACGT\n')
            content = ('##fileformat=VCFv4.2\n##reference=/private/reference.fa\n'
                       '##bcftoolsCommand=call /private/invitation.json\n'
                       '#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\tFORMAT\t/private/sample.bam\n'
                       'synthetic\t2\tprivate-id\tC\tA,G\t40\tPASS\tSECRET=private\tGT\t1/2\n')
            for compressed in (False, True):
                with self.subTest(compressed=compressed):
                    source = base / ('source.vcf.gz' if compressed else 'source.vcf')
                    if compressed:
                        with gzip.open(source, 'wt') as stream:
                            stream.write(content)
                    else:
                        source.write_text(content)
                    out = base / 'public.vcf'
                    report = export_alleles(source, reference, out)
                    self.assertEqual(report['normalized_allele_count'], 2)
                    self.assertNotIn('private', out.read_text())
                    self.assertNotIn('GT', out.read_text())
                    self.assertTrue(all(len(row.split('\t')) == 8 for row in out.read_text().splitlines() if not row.startswith('#')))
                    self.assertEqual(_MODULE.read_variants(source, _MODULE.read_reference(reference)),
                                     _MODULE.read_variants(out, _MODULE.read_reference(reference)))
                    self.assertEqual(content, gzip.open(source, 'rt').read() if compressed else source.read_text())
                    out.unlink()

    def test_existing_original_or_alias_never_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            reference, source = base / 'r.fa', base / 'source.vcf'
            reference.write_text('>synthetic\nACGT\n')
            source.write_text('#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\nsynthetic\t2\t.\tC\tG\t.\t.\t.\n')
            original, ref_original = source.read_bytes(), reference.read_bytes()
            link = base / 'alias.vcf'
            link.symlink_to(source)
            hardlink = base / 'hardlink.vcf'
            __import__('os').link(source, hardlink)
            for destination in (source, reference, link, hardlink):
                with self.subTest(destination=destination.name):
                    with self.assertRaises(FileExistsError):
                        export_alleles(source, reference, destination)
                    self.assertEqual(source.read_bytes(), original)
                    self.assertEqual(reference.read_bytes(), ref_original)

    def test_reference_mismatch_rejected_before_export(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            reference, source, out = base / 'r.fa', base / 'source.vcf', base / 'public.vcf'
            reference.write_text('>synthetic\nACGT\n')
            source.write_text('#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\nsynthetic\t2\t.\tA\tG\t.\t.\t.\n')
            with self.assertRaisesRegex(ValueError, 'mismatch'):
                export_alleles(source, reference, out)
            self.assertFalse(out.exists())

    def test_contig_path_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            reference, source, out = base / 'r.fa', base / 'source.vcf', base / 'public.vcf'
            reference.write_text('>/private/contig\nACGT\n')
            source.write_text('#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n/private/contig\t2\t.\tC\tG\t.\t.\t.\n')
            with self.assertRaisesRegex(ValueError, 'unsafe'):
                export_alleles(source, reference, out)
            self.assertFalse(out.exists())


if __name__ == '__main__':
    unittest.main()
