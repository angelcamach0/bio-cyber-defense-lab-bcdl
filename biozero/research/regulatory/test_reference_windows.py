"""Offline reference acquisition and accounting; synthetic DNA, no network."""
import hashlib
import io
import json
from pathlib import Path
import tempfile
import time
import unittest
import urllib.error

import reference_windows as reference
from test_small_dataset_fetch import Opener, Response


class Clock:
    def __init__(self):
        self.now=0.0
        self.sleeps=[]
    def __call__(self):
        return self.now
    def sleep(self,seconds):
        self.sleeps.append(seconds)
        self.now+=seconds


class ReferenceTests(unittest.TestCase):
    def test_acquisition_and_cached_response_are_bound_to_the_plan(self):
        spec,raw,response=self.response()
        with tempfile.TemporaryDirectory() as directory:
            client,ledger,opener,clock=self.fixture(directory,[response])
            bound=reference.SequenceClient(Path(directory),ledger,client.reader,opener,
                                          clock=clock,sleep=clock.sleep,reference_plan_sha256='c'*64)
            bound.acquire('hg19','chr8',10,11,fetch=True)
            self.assertEqual(ledger.data['attempts'][0]['reference_plan_sha256'],'c'*64)
            self.assertEqual(bound.acquire('hg19','chr8',10,11)['status'],'verified_cached')
            other=reference.SequenceClient(Path(directory),ledger,client.reader,opener,
                                          clock=clock,sleep=clock.sleep,reference_plan_sha256='d'*64)
            with self.assertRaisesRegex(reference.source.common.FetchError,'cached_plan_mismatch'):
                other.acquire('hg19','chr8',10,11)
            self.assertEqual(len(opener.requests),1)

    def test_reader_cannot_charge_a_different_budget(self):
        with tempfile.TemporaryDirectory() as directory,tempfile.TemporaryDirectory() as other:
            client,ledger,opener,clock=self.fixture(directory,[])
            with reference.source.common.TransferLedger(other,reference.source.LIMIT) as different:
                reader=reference.source.common.DownloadClient(different,time.monotonic()+30)
                with self.assertRaisesRegex(reference.source.common.FetchError,'existing_dataset_ledger_required'):
                    reference.SequenceClient(Path(directory),ledger,reader,opener)
            self.assertEqual(ledger.data['http_exchanges'],0)

    def test_slow_accounting_cannot_compress_actual_request_cadence(self):
        first_spec,first_raw,first=self.response()
        second_spec,second_raw,second=self.response('hg38','chr9',100)
        with tempfile.TemporaryDirectory() as directory:
            client,ledger,opener,clock=self.fixture(directory,[first,second])
            starts=[];original_open=opener.open;original_save=ledger.save
            def observed_open(request,timeout):
                starts.append(clock())
                return original_open(request,timeout)
            def slow_first_save():
                if not getattr(ledger,'delayed',False):
                    ledger.delayed=True;clock.now+=2.0
                original_save()
            opener.open=observed_open;ledger.save=slow_first_save
            client.acquire('hg19','chr8',10,11,fetch=True)
            client.acquire('hg38','chr9',100,4196,fetch=True)
            self.assertEqual(len(starts),2)
            self.assertGreaterEqual(starts[1]-starts[0],1.0)

    def test_partial_read_keeps_reservation_and_blocks_retry(self):
        spec,raw,response=self.response()
        class Partial(Response):
            def read1(self,size):
                if not getattr(self,'delivered',False):
                    self.delivered=True
                    return b'abc'
                raise OSError('synthetic interrupted read')
        with tempfile.TemporaryDirectory() as directory:
            client,ledger,opener,clock=self.fixture(directory,[Partial(b'',spec['source_url'])])
            with self.assertRaises(OSError):
                client.acquire('hg19','chr8',10,11,fetch=True)
            self.assertEqual(ledger.data['charged_bytes'],2+reference.MAX_RESPONSE_BYTES+1)
            self.assertEqual(ledger.data['body_bytes_observed'],5)
            self.assertEqual(ledger.data['attempts'][0]['charged_at_end'],ledger.data['charged_bytes'])
            self.assertEqual(reference.source.dataset_history_guard(Path(directory))['charged_bytes'],ledger.data['charged_bytes'])
            with self.assertRaisesRegex(reference.source.common.FetchError,'previous_outcome_requires_review'):
                client.acquire('hg19','chr8',10,11,fetch=True)
            self.assertEqual(len(opener.requests),1)

    def test_budget_rejects_before_response_body_read_and_flags_are_exact(self):
        spec,raw,response=self.response()
        class Counted(Response):
            calls=0
            def read1(self,size):
                self.calls+=1
                return super().read1(size)
        response=Counted(raw,spec['source_url'],len(raw))
        with tempfile.TemporaryDirectory() as directory:
            client,ledger,opener,clock=self.fixture(directory,[response])
            with self.assertRaisesRegex(reference.source.common.FetchError,'fetch_flag_invalid'):
                client.acquire('hg19','chr8',10,11,fetch=1)
            self.assertEqual(len(opener.requests),0)
            ledger.data['charged_bytes']=reference.source.LIMIT-1;ledger.save()
            with self.assertRaisesRegex(reference.source.common.FetchError,'budget exhausted'):
                client.acquire('hg19','chr8',10,11,fetch=True)
            self.assertEqual(response.calls,0)
            self.assertEqual(ledger.data['charged_bytes'],reference.source.LIMIT-1)
            self.assertEqual(ledger.data['body_bytes_observed'],2)
            self.assertFalse((Path(directory)/spec['filename']).exists())

    def fixture(self, directory, responses):
        folder=Path(directory)
        ledger=reference.source.common.TransferLedger(folder,reference.source.LIMIT)
        self.addCleanup(ledger.close)
        reference.source.seed_control_charge(ledger)
        reference.source.publish_private(folder,'zenodo-1405945-metadata.json',b'{}')
        ledger.data.update(charged_bytes=2,body_bytes_observed=2);ledger.save()
        clock=Clock();opener=Opener(responses)
        reader=reference.source.common.DownloadClient(ledger,time.monotonic()+30)
        client=reference.SequenceClient(folder,ledger,reader,opener,clock=clock,sleep=clock.sleep)
        return client,ledger,opener,clock

    def response(self,genome='hg19',chrom='chr8',start=10):
        end=start+(1 if genome=='hg19' else 4096)
        spec=reference.request_spec(genome,chrom,start,end)
        raw=json.dumps({'genome':genome,'chrom':chrom,'start':start,'end':end,
                        'dna':'a'*(end-start)}).encode()
        return spec,raw,Response(raw,spec['source_url'],len(raw))

    def test_request_types_and_scope_are_exact(self):
        for args in (('hg38','chr1',0,4096),('hg19','chr8',True,2),('hg19','chr8',0.0,1),
                     ('hg19','chr8',0,1.0),('hg19','chr8',-1,0),('hg38','chr9',0,4095),
                     ('hg19','chr8;genome=hg38',0,1)):
            with self.subTest(args=args),self.assertRaisesRegex(reference.source.common.FetchError,'request_invalid'):
                reference.request_spec(*args)

    def test_cache_pin_and_same_ledger_retains_charge_without_new_request(self):
        spec,raw,response=self.response()
        with tempfile.TemporaryDirectory() as directory:
            client,ledger,opener,clock=self.fixture(directory,[response])
            receipt=client.acquire('hg19','chr8',10,11,fetch=True)
            self.assertEqual(receipt['sequence'],'A')
            self.assertEqual(receipt['source_response_sha256'],hashlib.sha256(raw).hexdigest())
            self.assertEqual(ledger.data['charged_bytes'],2+len(raw))
            cached=client.acquire('hg19','chr8',10,11)
            self.assertEqual(cached['status'],'verified_cached')
            self.assertEqual(len(opener.requests),1)
            self.assertEqual(clock.sleeps,[1.0])
            self.assertEqual(reference.source.dataset_history_guard(Path(directory))['charged_bytes'],2+len(raw))

    def test_failed_slot_and_lost_published_file_never_retry(self):
        spec,raw,response=self.response()
        for failure in (False,True):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                client,ledger,opener,clock=self.fixture(directory,[OSError('offline') if failure else response])
                if failure:
                    with self.assertRaises(OSError):
                        client.acquire('hg19','chr8',10,11,fetch=True)
                else:
                    client.acquire('hg19','chr8',10,11,fetch=True)
                    (Path(directory)/spec['filename']).unlink()
                with self.assertRaisesRegex(reference.source.common.FetchError,'previous_outcome_requires_review'):
                    client.acquire('hg19','chr8',10,11,fetch=True)
                self.assertEqual(len(opener.requests),1)
                self.assertEqual(len(ledger.data['attempts']),1)

    def test_size_limit_exact_and_one_extra_retains_failed_charge(self):
        spec,raw,response=self.response()
        padded=raw+b' '*(reference.MAX_RESPONSE_BYTES-len(raw))
        for extra in (0,1):
            with self.subTest(extra=extra),tempfile.TemporaryDirectory() as directory:
                client,ledger,opener,clock=self.fixture(directory,[Response(padded+b'X'*extra,spec['source_url'])])
                if extra:
                    with self.assertRaisesRegex(reference.source.common.FetchError,'size_exceeded'):
                        client.acquire('hg19','chr8',10,11,fetch=True)
                    self.assertFalse((Path(directory)/spec['filename']).exists())
                    self.assertEqual(ledger.data['attempts'][0]['status'],'failed_or_interrupted')
                else:
                    self.assertEqual(client.acquire('hg19','chr8',10,11,fetch=True)['status'],'verified')
                self.assertEqual(ledger.data['charged_bytes'],2+reference.MAX_RESPONSE_BYTES+extra)

    def test_wrong_coordinates_types_duplicates_and_bad_dna_fail(self):
        spec,raw,response=self.response()
        original=json.loads(raw)
        for value in (dict(original,start=10.0),dict(original,end=True),dict(original,genome='hg38'),
                      dict(original,dna='N'),dict(original,dna='AA'),dict(original,dna=1)):
            with self.subTest(value=value), self.assertRaises(reference.source.common.FetchError):
                reference.validate_response(json.dumps(value).encode(),spec)
        with self.assertRaisesRegex(reference.source.common.FetchError,'duplicate_json_key'):
            reference.validate_response(raw[:-1]+b',"start":10}',spec)
        with self.assertRaisesRegex(reference.source.common.FetchError,'nonfinite_json'):
            reference.validate_response(raw[:-1]+b',"extra":NaN}',spec)

    def test_http_denial_body_is_charged_and_has_no_retry(self):
        spec,raw,response=self.response()
        error=urllib.error.HTTPError(spec['source_url'],403,'denied',None,io.BytesIO(b'denied-body'))
        with tempfile.TemporaryDirectory() as directory:
            client,ledger,opener,clock=self.fixture(directory,[error])
            with self.assertRaisesRegex(reference.source.common.FetchError,'access_denied'):
                client.acquire('hg19','chr8',10,11,fetch=True)
            self.assertEqual(ledger.data['charged_bytes'],2+len(b'denied-body'))
            self.assertEqual(ledger.data['attempts'][0]['charged_at_end'],ledger.data['charged_bytes'])
            self.assertEqual(len(opener.requests),1)
            self.assertFalse((Path(directory)/spec['filename']).exists())

    def test_redirect_encoding_declared_size_and_unpinned_cache_reject(self):
        spec,raw,response=self.response()
        for bad in (Response(raw,'https://other.example'),Response(raw,spec['source_url'],encoding='gzip'),
                    Response(raw,spec['source_url'],reference.MAX_RESPONSE_BYTES+1)):
            with self.subTest(bad=bad), tempfile.TemporaryDirectory() as directory:
                client,ledger,opener,clock=self.fixture(directory,[bad])
                with self.assertRaises(reference.source.common.FetchError):
                    client.acquire('hg19','chr8',10,11,fetch=True)
                self.assertFalse((Path(directory)/spec['filename']).exists())
        with tempfile.TemporaryDirectory() as directory:
            client,ledger,opener,clock=self.fixture(directory,[])
            reference.source.publish_private(Path(directory),spec['filename'],raw)
            with self.assertRaisesRegex(reference.source.common.FetchError,'cached_pin_missing'):
                client.acquire('hg19','chr8',10,11)
            self.assertEqual(len(opener.requests),0)

    def test_cadence_and_missing_explicit_permission(self):
        spec,raw,first=self.response()
        other,other_raw,second=self.response('hg38','chr9',100)
        with tempfile.TemporaryDirectory() as directory:
            client,ledger,opener,clock=self.fixture(directory,[first,second])
            with self.assertRaisesRegex(reference.source.common.FetchError,'explicit_fetch_required'):
                client.acquire('hg19','chr8',10,11)
            self.assertEqual(ledger.data['http_exchanges'],0)
            client.acquire('hg19','chr8',10,11,fetch=True)
            client.acquire('hg38','chr9',100,4196,fetch=True)
            self.assertEqual(clock.sleeps,[1.0,1.0])
            self.assertEqual(len(opener.requests),2)


if __name__=='__main__':
    unittest.main()
