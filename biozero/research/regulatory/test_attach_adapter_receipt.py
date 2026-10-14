"""Adapter/evaluation binding contracts; synthetic reports, no inference."""
import copy
import unittest

import attach_adapter_receipt as binding
import test_biological_adapter as toy


class ReceiptBindingTests(unittest.TestCase):
    def fixture(self):
        cases=[toy.case(i) for i in range(110)]
        for case in cases:
            case['effect']['standard_error']=0.12
        selected=[];records=[]
        for index,case in enumerate(cases[:10]):
            descriptor=binding.adapter.canonical(case)
            descriptor['window_sha256']=case['window']['sha256']
            selected.append(descriptor)
            record=binding.adapter.case_record(case,index,True)
            record.update(status='inferred',repeat_identical=True,score=0.0,
                          track_ref_probabilities=[0.5]*9,track_alt_probabilities=[0.5]*9,track_deltas=[0.0]*9)
            records.append(record)
        ledger={'schema_version':1,'phase':'evaluation','protocol_id':binding.adapter.PROTOCOL_ID,'dataset':{'sha256':'a'*64},
                'split_metadata':{'adapter_loci':selected,'frozen_selection_sha256':'b'*64},'cases':cases[10:]}
        report={'schema_version':1,'phase':'adapter','dataset_kind':'biological','status':'passed',
                'dataset_sha256':'a'*64,'protocol_sha256':binding.adapter.PROTOCOL_SHA256,
                'selection_sha256':'b'*64,'weights_sha256':binding.adapter.weights_pins(),
                'ledger_sha256':'e'*64,'source_commit':binding.adapter.SOURCE_COMMIT,
                'protocol_id':binding.adapter.PROTOCOL_ID,'ready_for_inference':True,'channel_order':'ACGT',
                'strand_handling':'pinned upstream forward: mean forward and reverse-complement head probabilities',
                'supervisor':{'returncode':0},
                'counts':{'submitted':10,'validated':10,'rejected':0,'pending':0,'inferred':10},
                'trained_weights_loaded':True,'strict_state_dict':True,'weights_only':True,
                'projection':False,'head_outputs':21907,'annotation_sha256':binding.adapter.ANNOTATION_SHA256,
                'track_ids':binding.adapter.TRACK_IDS.copy(),'track_indices_zero_based':binding.adapter.TRACK_INDICES.copy(),
                'threads':1,'batch':1,'checks':{'full_head_shape_1x21907':True,
                  'all_head_probabilities_finite_and_in_unit_interval':True,'repeat_identical_all_head_outputs':True,
                  'exact_nine_tracks':True,'projection_disabled':True,'batch_one':True},'records':records}
        self.parent=copy.deepcopy(ledger)
        self.parent.update(phase='adapter',cases=cases[:10])
        return ledger,report

    def bind(self,ledger,report):
        return binding.bind_report(ledger,report,'synthetic-adapter-report.json','c'*64,self.parent,'e'*64)

    def test_only_binding_fields_added_without_changing_any_frozen_case(self):
        ledger,report=self.fixture();original=copy.deepcopy(ledger)
        result=self.bind(ledger,report)
        self.assertEqual(result['cases'],original['cases'])
        self.assertEqual(ledger,original)
        self.assertEqual(result['split_metadata']['adapter_loci'],original['split_metadata']['adapter_loci'])
        self.assertEqual(result['split_metadata']['adapter_receipt_sha256'],'c'*64)

    def test_control_partial_failed_or_alias_flags_cannot_open_evaluation(self):
        for mutate in (lambda r:r.update(dataset_kind='instrumentation_control'),lambda r:r.update(status='failed'),
                       lambda r:r['counts'].update(inferred=9),lambda r:r['counts'].update(submitted=10.0),
                       lambda r:r.update(projection=0),lambda r:r.update(trained_weights_loaded=1),
                       lambda r:r.update(head_outputs=21907.0),lambda r:r['checks'].update(exact_nine_tracks=1)):
            ledger,report=self.fixture();mutate(report)
            with self.assertRaises(binding.adapter.AdapterError):
                self.bind(ledger,report)

    def test_parent_weights_track_or_slot_changes_reject(self):
        for mutate in (lambda r:r.update(selection_sha256='d'*64),lambda r:r.update(dataset_sha256='d'*64),
                       lambda r:r['weights_sha256'].update(head64_fp32='d'*64),
                       lambda r:r['track_ids'].reverse(),lambda r:r['records'].reverse(),
                       lambda r:r['records'][0].update(window_sha256='d'*64)):
            ledger,report=self.fixture();mutate(report)
            with self.assertRaises(binding.adapter.AdapterError):
                self.bind(ledger,report)

    def test_unfinished_nonfinite_or_unrepeated_record_rejects(self):
        for update in ({'status':'validated'},{'repeat_identical':1},{'repeat_identical':False},
                       {'score':float('nan')},{'score':True}):
            ledger,report=self.fixture();report['records'][0].update(update)
            with self.assertRaises(binding.adapter.AdapterError):
                self.bind(ledger,report)

    def test_wrong_parent_runtime_or_supervisor_cannot_open_evaluation(self):
        for update in ({'ledger_sha256':'d'*64},{'source_commit':'d'*40},{'ready_for_inference':False},
                       {'ready_for_inference':1},{'channel_order':'TGCA'},{'strand_handling':'forward only'},
                       {'supervisor':{'returncode':1}},{'supervisor':{'returncode':False}}):
            with self.subTest(update=update):
                ledger,report=self.fixture();report.update(update)
                with self.assertRaises(binding.adapter.AdapterError):
                    self.bind(ledger,report)
        ledger,report=self.fixture();self.parent['cases'].reverse()
        with self.assertRaises(binding.adapter.AdapterError):
            self.bind(ledger,report)

    def test_vectors_must_be_nine_finite_probabilities_and_coherent_score(self):
        for update in ({'track_deltas':None},{'track_ref_probabilities':[0.5]*8},
                       {'track_alt_probabilities':[True]*9},{'track_alt_probabilities':[float('nan')]*9},
                       {'track_ref_probabilities':[-0.1]*9},{'track_alt_probabilities':[1.1]*9},
                       {'track_deltas':[0.1]*9},{'score':0.1}):
            with self.subTest(update=update):
                ledger,report=self.fixture();report['records'][0].update(update)
                with self.assertRaises(binding.adapter.AdapterError):
                    self.bind(ledger,report)

    def test_effect_or_original_slot_changes_cannot_be_attached(self):
        for update in ({'beta_raw':123.0},{'beta_alt_minus_ref':123.0},{'standard_error':123.0},
                       {'row_index':True},{'window_start_zero_based':123}):
            ledger,report=self.fixture();report['records'][0].update(update)
            with self.assertRaises(binding.adapter.AdapterError):
                self.bind(ledger,report)


if __name__=='__main__':
    unittest.main()
