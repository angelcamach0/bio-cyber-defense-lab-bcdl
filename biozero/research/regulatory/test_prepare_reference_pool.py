"""Frozen-slot orchestration tests; synthetic receipts, no HTTP/model."""
import copy
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import json
import time

import prepare_reference_pool as pool
import test_reference_normalization as toy
import test_reference_windows as acquisition_toy
from test_small_dataset_fetch import Opener,Response


class Client:
    def __init__(self,source,target,fail=None):
        self.source=source;self.target=target;self.fail=fail;self.calls=[]
    def acquire(self,genome,chrom,start,end,*,fetch):
        self.calls.append((genome,chrom,start,end,fetch))
        if self.fail:
            raise pool.source.common.FetchError(self.fail)
        return self.source if genome=='hg19' else self.target


class OrchestrationTests(unittest.TestCase):
    def valid_freeze(self):
        candidates=self.fixture(110)[0]['precandidates']
        for candidate in candidates:
            candidate['prepool_rank_sha256']=pool.preparation.prepool_rank(candidate,pool.SOURCE_SHA)
        candidates.sort(key=lambda c:(c['prepool_rank_sha256'],c['origin_row_id']))
        return {'schema_version':1,'status':'precandidates_frozen_awaiting_references',
                'inputs':{k:{'sha256':sha} for k,sha in (('source',pool.SOURCE_SHA),('peaks',pool.PEAKS_SHA),('chain',pool.CHAIN_SHA))},
                'policy':{'domain':pool.preparation.PREPOOL_DOMAIN,'seed':pool.preparation.PROTOCOL_SEED,
                          'maximum_precandidates':256,'chromosomes':['chr8','chr9'],'replenishment':False,
                          'references_checked':False,'final_selection_produced':False},
                'producer_sha256':hashlib.sha256(Path(pool.preparation.__file__).read_bytes()).hexdigest(),
                'lift_chain_sha256':hashlib.sha256(Path(pool.lift_chain.__file__).read_bytes()).hexdigest(),
                'precandidates':candidates}

    def test_freeze_gate_checks_digest_canonical_types_order_and_producers(self):
        frozen=self.valid_freeze();raw=pool.preparation.canonical_bytes(frozen)
        self.assertEqual(pool.checked_freeze(raw,hashlib.sha256(raw).hexdigest()),frozen)
        with self.assertRaisesRegex(pool.adapter.AdapterError,'sha_mismatch'):
            pool.checked_freeze(raw,'d'*64)
        pretty=json.dumps(frozen,indent=2).encode()
        with self.assertRaisesRegex(pool.adapter.AdapterError,'not_canonical'):
            pool.checked_freeze(pretty,hashlib.sha256(pretty).hexdigest())
        for mutate in (lambda f:f.update(schema_version=True),lambda f:f.update(inputs=[]),
                       lambda f:f['policy'].update(replenishment=0),lambda f:f.update(producer_sha256='d'*64),
                       lambda f:f['precandidates'].reverse(),
                       lambda f:f['precandidates'][0].update(prepool_rank_sha256='d'*64)):
            broken=copy.deepcopy(frozen);mutate(broken);encoded=pool.preparation.canonical_bytes(broken)
            with self.assertRaises(pool.adapter.AdapterError):
                pool.checked_freeze(encoded,hashlib.sha256(encoded).hexdigest())

    def test_prepare_prior_attempt_without_plan_fails_before_any_get_or_plan_write(self):
        with tempfile.TemporaryDirectory() as prefix:
            folder=Path(prefix)/'datasets';folder.mkdir(mode=0o700)
            frozen,client=self.fixture(1)
            raw=b'{"toy":true}';sha=hashlib.sha256(raw).hexdigest()
            pool.source.publish_private(folder,'kumasaka-prepool-'+sha+'.json',raw)
            plan=pool.reference_plan(frozen,sha)
            with pool.source.common.TransferLedger(folder,pool.source.LIMIT) as ledger:
                pool.source.seed_control_charge(ledger)
                pool.source.publish_private(folder,'zenodo-1405945-metadata.json',b'{}')
                ledger.data.update(charged_bytes=2,body_bytes_observed=2,http_exchanges=1,
                    attempts=[{'kind':'reference_window','source_url':plan['requests'][0]['source']['source_url'],
                               'status':'failed_or_interrupted','charged_at_end':2,'body_at_end':2}]);ledger.save()
            before=(folder/'transfer-ledger.json').read_bytes();opener=Opener([])
            with mock.patch.object(pool,'checked_freeze',return_value=frozen), \
                 mock.patch.object(pool.source,'acquire'),mock.patch.object(pool.mapping_assets,'acquire'), \
                 mock.patch.object(pool.urllib.request,'build_opener',return_value=opener):
                with self.assertRaisesRegex(pool.adapter.AdapterError,'not_prospective_requires_review'):
                    pool.prepare(prefix,sha,fetch=True)
            self.assertEqual(opener.requests,[])
            self.assertFalse((folder/('kumasaka-reference-plan-'+sha+'.json')).exists())
            self.assertEqual((folder/'transfer-ledger.json').read_bytes(),before)

    def test_prepare_existing_plan_recovers_matching_cached_receipts_with_no_get(self):
        with tempfile.TemporaryDirectory() as prefix:
            folder=Path(prefix)/'datasets';folder.mkdir(mode=0o700)
            frozen,toy_client=self.fixture(3)
            raw=b'{"toy":true}';sha=hashlib.sha256(raw).hexdigest()
            pool.source.publish_private(folder,'kumasaka-prepool-'+sha+'.json',raw)
            plan=pool.reference_plan(frozen,sha)
            responses=[]
            for receipt in (toy_client.source,toy_client.target):
                value={'genome':receipt['genome_build'],'chrom':receipt['chrom'],
                       'start':receipt['start_zero_based'],'end':receipt['end_zero_based'],'dna':receipt['sequence']}
                body=json.dumps(value).encode();responses.append(Response(body,receipt['source_url'],len(body)))
            with pool.source.common.TransferLedger(folder,pool.source.LIMIT) as ledger:
                pool.source.seed_control_charge(ledger)
                pool.source.publish_private(folder,'zenodo-1405945-metadata.json',b'{}')
                ledger.data.update(charged_bytes=2,body_bytes_observed=2);ledger.save()
                plan_sha=pool.bind_prospective_plan(folder,ledger,plan,sha)
                clock=acquisition_toy.Clock();opener=Opener(responses)
                reader=pool.source.common.DownloadClient(ledger,time.monotonic()+30)
                client=pool.reference_windows.SequenceClient(folder,ledger,reader,opener,clock=clock,sleep=clock.sleep,
                                                            reference_plan_sha256=plan_sha)
                for kind in ('source','target'):
                    spec=plan['requests'][0][kind]
                    client.acquire(spec['genome'],spec['chrom'],spec['start'],spec['end'],fetch=True)
            before=(folder/'transfer-ledger.json').read_bytes();cached_opener=Opener([])
            with mock.patch.object(pool,'checked_freeze',return_value=frozen), \
                 mock.patch.object(pool.source,'acquire'),mock.patch.object(pool.mapping_assets,'acquire'), \
                 mock.patch.object(pool.urllib.request,'build_opener',return_value=cached_opener):
                report=pool.prepare(prefix,sha,fetch=False)
            self.assertEqual(report['counts'],{'normalized':3})
            self.assertEqual(report['status'],'normalized_reference_pool_pending_review')
            self.assertIs(report['scientific_review_approved'],False)
            self.assertEqual(cached_opener.requests,[])
            self.assertEqual((folder/'transfer-ledger.json').read_bytes(),before)

    def test_new_plan_cannot_bless_prior_attempt_or_untracked_cache(self):
        for prior in ('attempt','cache'):
            with self.subTest(prior=prior),tempfile.TemporaryDirectory() as directory:
                folder=Path(directory);frozen,client=self.fixture(1)
                plan=pool.reference_plan(frozen,'c'*64)
                with pool.source.common.TransferLedger(folder,pool.source.LIMIT) as ledger:
                    if prior=='attempt':
                        ledger.data['attempts'].append({'kind':'reference_window',
                            'source_url':plan['requests'][0]['source']['source_url']})
                        ledger.save()
                    else:
                        pool.source.publish_private(folder,plan['requests'][0]['source']['filename'],b'{}')
                    before=(folder/'transfer-ledger.json').read_bytes()
                    with self.assertRaisesRegex(pool.adapter.AdapterError,'not_prospective_requires_review'):
                        pool.bind_prospective_plan(folder,ledger,plan,'c'*64)
                    self.assertEqual((folder/'transfer-ledger.json').read_bytes(),before)
                    self.assertFalse((folder/('kumasaka-reference-plan-'+'c'*64+'.json')).exists())
                    self.assertEqual(client.calls,[])

    def test_existing_plan_requires_matching_attempt_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            folder=Path(directory);frozen,client=self.fixture(1);plan=pool.reference_plan(frozen,'c'*64)
            with pool.source.common.TransferLedger(folder,pool.source.LIMIT) as ledger:
                sha=pool.bind_prospective_plan(folder,ledger,plan,'c'*64)
                ledger.data['attempts'].append({'kind':'reference_window',
                    'source_url':plan['requests'][0]['source']['source_url'],'reference_plan_sha256':sha})
                ledger.save()
                self.assertEqual(pool.bind_prospective_plan(folder,ledger,plan,'c'*64),sha)
                ledger.data['attempts'][0]['reference_plan_sha256']='d'*64;ledger.save()
                with self.assertRaisesRegex(pool.adapter.AdapterError,'previous_attempt_plan_mismatch'):
                    pool.bind_prospective_plan(folder,ledger,plan,'c'*64)

    def fixture(self,count=3):
        candidate,source,target=toy.ReferenceNormalizationTests().fixture()
        candidates=[]
        for i in range(count):
            row=copy.deepcopy(candidate);row.update(candidate_id='toy-'+str(i),origin_row_id='toy-source:'+str(i))
            candidates.append(row)
        return {'precandidates':candidates},Client(source,target)

    def test_every_frozen_slot_kept_and_both_references_requested(self):
        frozen,client=self.fixture()
        result=pool.process_candidates(frozen,'c'*64,client,fetch=True)
        self.assertEqual(result['counts'],{'normalized':3})
        self.assertEqual(len(client.calls),6)
        self.assertEqual([c['case_id'] for c in result['cases']],['toy-0','toy-1','toy-2'])
        self.assertTrue(all(c['effect']['value']==0.5 for c in result['cases']))
        self.assertIsNone(result['stop_code'])

    def test_access_denial_stops_network_and_retains_unattempted_slots(self):
        frozen,client=self.fixture();client.fail='reference_access_denied'
        result=pool.process_candidates(frozen,'c'*64,client,fetch=True)
        self.assertEqual(len(client.calls),1)
        self.assertEqual(result['counts'],{'pending':3})
        self.assertEqual(result['stop_code'],'reference_access_denied')
        self.assertTrue(all(c['window'] is None for c in result['cases']))
        self.assertEqual(len(result['outcomes']),3)
        self.assertEqual(result['outcomes'][2]['reference_outcomes']['source']['status'],'unattempted')

    def test_cached_only_missing_records_all_outcomes_and_never_fetches(self):
        frozen,client=self.fixture();client.fail='reference_missing_explicit_fetch_required'
        result=pool.process_candidates(frozen,'c'*64,client,fetch=False)
        self.assertEqual(len(client.calls),6)
        self.assertTrue(all(call[-1] is False for call in client.calls))
        self.assertEqual(result['counts'],{'pending':3})
        self.assertIsNone(result['stop_code'])

    def test_reference_mismatch_retains_same_slot_without_replacement(self):
        frozen,client=self.fixture()
        client.source=copy.deepcopy(client.source)
        client.source.update(sequence='T',sha256=hashlib.sha256(b'T').hexdigest())
        result=pool.process_candidates(frozen,'c'*64,client,fetch=True)
        self.assertEqual(result['counts'],{'rejected':3})
        self.assertEqual([o['candidate_id'] for o in result['outcomes']],['toy-0','toy-1','toy-2'])
        self.assertTrue(all(o['reasons']==['source_reference_allele_mismatch'] for o in result['outcomes']))
        self.assertEqual(len(client.calls),6)

    def test_boundary_invalid_request_stays_in_frozen_plan(self):
        frozen,client=self.fixture(1)
        frozen['precandidates'][0]['mapped_position_1based']=10
        plan=pool.reference_plan(frozen,'c'*64)
        self.assertEqual(plan['maximum_requests'],2)
        self.assertEqual(plan['requests'][0]['candidate_id'],'toy-0')
        self.assertEqual(plan['requests'][0]['target']['status'],'invalid_request')
        self.assertEqual(len(plan['requests']),1)


if __name__=='__main__':
    unittest.main()
