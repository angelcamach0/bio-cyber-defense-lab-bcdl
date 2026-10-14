"""Synthetic reference swaps and strands; no real biological predictions."""
import copy
import hashlib
import unittest

import biological_adapter as adapter
import reference_normalization as normalizer
import reference_windows


class ReferenceNormalizationTests(unittest.TestCase):
    def fixture(self,strand='+',swap=False,beta=0.5):
        oriented_ref,oriented_alt=('T','G') if strand=='-' else ('A','C')
        snp={'chain_id':1,'strand':strand,'source_chrom':'chr8','source_start':9,'source_end':10,'source_size':100000,
             'target_chrom':'chr8','target_start':9999,'target_end':10000,'target_size':100000}
        mapped_peak=dict(snp,source_start=0,source_end=20,target_start=9990,target_end=10010)
        if strand=='-':
            mapped_peak.update(target_start=9989,target_end=10009)
        candidate={'candidate_id':'toy-row-1','origin_row_id':'toy-source:row:1','source_row_sha256':'a'*64,
                   'source_chrom':'chr8','source_position_1based':10,'source_ref':'A','source_alt':'C',
                   'mapped_chrom':'chr8','mapped_position_1based':10000,
                   'oriented_source_ref':oriented_ref,'oriented_source_alt':oriented_alt,
                   'mapping':{'snp':snp,'peak':mapped_peak},'peak':{'chrom':'chr8','start':0,'end':20},
                   'source_af':0.2,'source_p_lead':0.0,'source_log10_bf':-1.0,
                   'source_effect':{'value':beta,'standard_error':0.1,'effect_allele':'C','other_allele':'A',
                                    'orientation_source':'https://example.org/toy-effect-definition',
                                    'definition':'Synthetic source ALT-minus-REF toy slope'}}
        def receipt(genome,chrom,start,end,dna):
            spec=reference_windows.request_spec(genome,chrom,start,end)
            return {'schema_version':1,'status':'verified','genome_build':genome,'chrom':chrom,
                    'start_zero_based':start,'end_zero_based':end,'strand':'+','padding':False,
                    'source_url':spec['source_url'],'source_response_sha256':'b'*64,'sequence':dna,
                    'sha256':hashlib.sha256(dna.encode()).hexdigest()}
        observed=oriented_alt if swap else oriented_ref
        dna='A'*2048+observed+'A'*2047
        return candidate,receipt('hg19','chr8',9,10,'A'),receipt('hg38','chr8',7951,12047,dna)

    def normalize(self,fixture):
        return normalizer.normalize_precandidate(*fixture,prepool_sha256='c'*64)

    def test_both_strands_and_reference_swaps_convert_beta_once(self):
        for strand in ('+','-'):
            for swapped in (False,True):
                with self.subTest(strand=strand,swapped=swapped):
                    case=self.normalize(self.fixture(strand,swapped))
                    record=adapter.case_record(case,0,True)
                    self.assertEqual(record['status'],'validated')
                    self.assertEqual(record['beta_raw'],0.5)
                    self.assertEqual(record['beta_alt_minus_ref'],-0.5 if swapped else 0.5)
                    self.assertEqual(record['standard_error'],0.1)
                    self.assertEqual(case['effect']['value'],0.5)
                    self.assertEqual(case['source_provenance']['target_reference_swap'],swapped)
                    self.assertAlmostEqual(case['source_provenance']['target_alt_af'],0.8 if swapped else 0.2)

    def test_exact_zero_is_preserved_on_every_orientation(self):
        for strand in ('+','-'):
            for swap in (False,True):
                record=adapter.case_record(self.normalize(self.fixture(strand,swap,beta=0.0)),0,True)
                self.assertEqual(record['status'],'validated')
                self.assertEqual(record['beta_raw'],0.0)
                self.assertEqual(record['beta_alt_minus_ref'],0.0)

    def test_source_reference_and_target_third_allele_reject(self):
        candidate,source,target=self.fixture()
        source.update(sequence='T',sha256=hashlib.sha256(b'T').hexdigest())
        with self.assertRaisesRegex(adapter.AdapterError,'source_reference_allele_mismatch'):
            self.normalize((candidate,source,target))
        candidate,source,target=self.fixture()
        dna=target['sequence'][:2048]+'G'+target['sequence'][2049:]
        target.update(sequence=dna,sha256=hashlib.sha256(dna.encode()).hexdigest())
        with self.assertRaisesRegex(adapter.AdapterError,'target_reference_third_allele'):
            self.normalize((candidate,source,target))

    def test_receipt_types_flags_coordinates_and_pins_are_strict(self):
        for key,value in (('schema_version',True),('start_zero_based',7951.0),('padding',0),
                          ('status','pending'),('strand','-'),('sha256','d'*64),
                          ('source_response_sha256',None),('source_url','https://other.example')):
            with self.subTest(key=key,value=value):
                candidate,source,target=self.fixture();target[key]=value
                with self.assertRaises(adapter.AdapterError):
                    self.normalize((candidate,source,target))

    def test_mapping_and_complement_must_match_frozen_candidate(self):
        for mutate in (lambda c:c.update(oriented_source_ref='A'),
                       lambda c:c['mapping']['snp'].update(source_start=9.0),
                       lambda c:c['mapping']['peak'].update(chain_id=2),
                       lambda c:c['mapping']['peak'].update(target_end=9999),
                       lambda c:c['mapping']['snp'].update(target_size=10000)):
            candidate,source,target=self.fixture('-')
            mutate(candidate)
            with self.assertRaises(adapter.AdapterError):
                self.normalize((candidate,source,target))

    def test_containment_alone_does_not_prove_single_block_offsets(self):
        for strand in ('+','-'):
            for change in ({'target_start':9980},{'target_start':9988,'target_end':10008}):
                with self.subTest(strand=strand,change=change):
                    candidate,source,target=self.fixture(strand)
                    candidate['mapping']['peak'].update(change)
                    with self.assertRaisesRegex(adapter.AdapterError,'ungapped_'):
                        self.normalize((candidate,source,target))

    def test_effect_and_frequency_inputs_cannot_be_invented_or_flipped_early(self):
        for mutate in (lambda c:c['source_effect'].update(value=True),
                       lambda c:c['source_effect'].update(effect_allele='A',other_allele='C'),
                       lambda c:c['source_effect'].update(standard_error=0),
                       lambda c:c.update(source_af=1.1)):
            candidate,source,target=self.fixture();mutate(candidate)
            with self.assertRaises(adapter.AdapterError):
                self.normalize((candidate,source,target))


if __name__=='__main__':
    unittest.main()
