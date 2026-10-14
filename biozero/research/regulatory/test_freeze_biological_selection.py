"""Final selection gates with synthetic DNA/effects, no biological inference."""
import copy
import hashlib
import unittest

import freeze_biological_selection as freezing
import test_biological_adapter as toy


class FinalFreezeTests(unittest.TestCase):
    def fixture(self,count=113):
        cases=[toy.case(i) for i in range(count)]
        for case in cases:
            case['chrom']='chr8';case['window']['chrom']='chr8'
        self.frozen={'precandidates':[{'candidate_id':c['case_id'],'origin_row_id':c['origin_row_id'],
                                      'mapped_chrom':c['chrom'],'mapped_position_1based':c['position_1based']}
                                     for c in cases]}
        prepool_sha=hashlib.sha256(freezing.preparation.canonical_bytes(self.frozen)).hexdigest()
        pool={'schema_version':1,'dataset_sha256':freezing.references.SOURCE_SHA,
              'protocol_sha256':freezing.adapter.PROTOCOL_SHA256,'prepool_sha256':prepool_sha,
              'biological_loci_inferred':0,'scientific_review_approved':False,
              'status':'normalized_reference_pool_pending_review','cases':cases,
              'outcomes':[{'candidate_id':c['case_id'],'origin_row_id':c['origin_row_id'],'status':'normalized'} for c in cases]}
        review={'schema_version':1,'review_status':'approved','scope':'source_and_reference_input_review_only',
                'dataset_sha256':freezing.references.SOURCE_SHA,'reference_pool_sha256':'b'*64,
                'prepool_sha256':prepool_sha,'protocol_sha256':freezing.adapter.PROTOCOL_SHA256,
                'permission_scope':'internal_research','reviewed_before_predictions':True,
                'license_verified':True,'schema_verified':True,'effect_orientation_verified':True,
                'source_ref_verified':True,'target_window_verified':True,'fixed_prepool_verified':True,
                'all_precandidate_outcomes_accounted':True,'biological_accuracy_approved':False,
                'rank64_verified_heldout':False,'reviewed_by':'synthetic fixture reviewer',
                'reviewed_at_utc':'2026-10-14T00:00:00Z'}
        return pool,review

    def build(self,pool,review):
        return freezing.build_documents(pool,'b'*64,review,'c'*64,frozen_prepool=self.frozen)

    def test_truncated_or_reordered_pool_cannot_hide_frozen_slots(self):
        for reorder in (False,True):
            pool,review=self.fixture()
            if reorder:
                pool['cases'].reverse();pool['outcomes'].reverse()
            else:
                pool['cases']=pool['cases'][:110];pool['outcomes']=pool['outcomes'][:110]
            with self.assertRaisesRegex(freezing.adapter.AdapterError,'frozen_'):
                self.build(pool,review)

    def test_complete_110_is_frozen_and_full_payloads_match_original_pool(self):
        pool,review=self.fixture();docs=self.build(pool,review)
        selected=docs['selection']['selected']
        self.assertEqual(len(selected),110)
        self.assertEqual(len(docs['ledgers']['adapter']['cases']),10)
        self.assertEqual(len(docs['ledgers']['evaluation']['cases']),100)
        self.assertEqual(len(docs['normalization']['cases']),113)
        lookup={c['case_id']:c for c in pool['cases']}
        for phase,slots in (('adapter',selected[:10]),('evaluation',selected[10:])):
            self.assertEqual(docs['ledgers'][phase]['cases'],[lookup[s['case_id']] for s in slots])
        self.assertIs(docs['selection']['frozen_before_predictions'],True)
        self.assertIs(docs['selection']['replacements_allowed'],False)
        self.assertNotIn('adapter_receipt_path',docs['ledgers']['evaluation']['split_metadata'])

    def test_review_type_aliases_and_false_scientific_claims_reject(self):
        for key,value in (('schema_version',True),('reviewed_before_predictions',1),('license_verified',1.0),
                          ('source_ref_verified',False),('biological_accuracy_approved',0),
                          ('rank64_verified_heldout',True),('reference_pool_sha256','d'*64)):
            with self.subTest(key=key,value=value):
                pool,review=self.fixture();review[key]=value
                with self.assertRaisesRegex(freezing.adapter.AdapterError,'review_mismatch'):
                    self.build(pool,review)

    def test_shortfall_and_overlapping_windows_do_not_produce_substitute_cases(self):
        for overlapping in (False,True):
            pool,review=self.fixture(110 if overlapping else 109)
            if overlapping:
                pool['cases'][1]['position_1based']=pool['cases'][0]['position_1based']+1
                window=pool['cases'][1]['window'];window['start_zero_based']-=4999;window['end_zero_based']-=4999
                self.frozen['precandidates'][1]['mapped_position_1based']=pool['cases'][1]['position_1based']
                pool['prepool_sha256']=hashlib.sha256(freezing.preparation.canonical_bytes(self.frozen)).hexdigest()
                review['prepool_sha256']=pool['prepool_sha256']
            with self.assertRaisesRegex(freezing.adapter.AdapterError,'110_disjoint' if overlapping else 'cardinality_invalid'):
                self.build(pool,review)

    def test_effect_magnitude_and_zero_do_not_change_final_rank(self):
        pool,review=self.fixture();first=self.build(pool,review)['selection']['selected']
        for i,case in enumerate(pool['cases']):
            case['effect']['value']=0.0 if i%2 else -999.0
        second=self.build(pool,review)['selection']['selected']
        self.assertEqual(first,second)

    def test_outcome_identity_status_or_chromosome_cannot_contradict_cases(self):
        for mutate in (lambda p:p['outcomes'].pop(),lambda p:p['outcomes'][0].update(candidate_id='other'),
                       lambda p:p['outcomes'][0].update(status='pending'),
                       lambda p:p['cases'][0].update(chrom='chr1'),
                       lambda p:p.update(biological_loci_inferred=True)):
            pool,review=self.fixture();mutate(pool)
            with self.assertRaises(freezing.adapter.AdapterError):
                self.build(pool,review)


if __name__=='__main__':
    unittest.main()
