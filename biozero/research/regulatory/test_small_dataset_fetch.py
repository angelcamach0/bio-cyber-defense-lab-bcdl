"""Offline bounded-source acquisition tests; no dataset network or inference."""
import email.message
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location('small_dataset_fetch', HERE / 'small_dataset_fetch.py')
source = importlib.util.module_from_spec(spec)
spec.loader.exec_module(source)


class Response(io.BytesIO):
    def __init__(self, raw, url, length=None, encoding=None):
        super().__init__(raw)
        self.url = url
        self.headers = email.message.Message()
        self.headers['Content-Type'] = 'application/octet-stream'
        if length is not None:
            self.headers['Content-Length'] = str(length)
        if encoding is not None:
            self.headers['Content-Encoding'] = encoding

    def geturl(self):
        return self.url


class Opener:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def open(self, request, timeout):
        self.requests.append(request)
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class SmallSourceTests(unittest.TestCase):
    def test_missing_ledger_with_mapping_reference_or_baseline_history_refuses_reset(self):
        for name in ('peaks.bed.gz','hg19ToHg38.over.chain.gz',source.BASELINE_RECEIPT,
                     'reference-'+'a'*64+'.json'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                folder=Path(directory)/'datasets';folder.mkdir(mode=0o700)
                retained=folder/name;retained.write_bytes(b'KEEP');retained.chmod(0o600)
                with self.assertRaisesRegex(source.common.FetchError,'existing_data_requires_ledger'):
                    source.acquire(directory,fetch=True)
                self.assertEqual(retained.read_bytes(),b'KEEP')
                self.assertFalse((folder/'transfer-ledger.json').exists())
                self.assertFalse((folder/'transfer-ledger.lock').exists())

    def test_source_entrypoint_rejects_lowered_pinned_charge_before_any_write(self):
        with tempfile.TemporaryDirectory() as directory:
            folder=Path(directory)/'datasets';folder.mkdir(mode=0o700)
            source.publish_control_baseline(folder,None,'initial_empty')
            source.publish_private(folder,'zenodo-1405945-metadata.json',b'{}')
            data={'schema_version':1,'limit_bytes':source.LIMIT,'charged_bytes':2,
                  'body_bytes_observed':2,'http_exchanges':2,
                  'baseline_control_imported':True,'baseline_control_bytes':0,
                  'attempts':[{'status':'verified','size_bytes':10,'sha256':'a'*64}]}
            path=folder/'transfer-ledger.json'
            source.publish_private(folder,path.name,json.dumps(data).encode())
            before=path.read_bytes()
            with self.assertRaisesRegex(source.common.FetchError,'charge_would_decrease'):
                source.acquire(directory)
            self.assertEqual(path.read_bytes(),before)
            self.assertFalse((folder/'transfer-ledger.lock').exists())
            path.write_bytes(b' ' * ((1<<20)+1))
            with self.assertRaisesRegex(source.common.FetchError,'cache_unsafe'):
                source.acquire(directory)
            self.assertFalse((folder/'transfer-ledger.lock').exists())

    def test_baseline_receipt_is_private_immutable_and_required_after_import(self):
        with tempfile.TemporaryDirectory() as directory:
            with source.common.TransferLedger(directory, source.LIMIT) as ledger:
                source.seed_control_charge(ledger)
                proof=Path(directory)/source.BASELINE_RECEIPT
                before=proof.read_bytes()
                self.assertEqual(proof.stat().st_mode & 0o777,0o600)
                self.assertEqual(source.control_baseline_receipt(Path(directory))['baseline_control_bytes'],0)
                source.seed_control_charge(ledger)
                self.assertEqual(proof.read_bytes(),before)
                proof.unlink()
                with self.assertRaisesRegex(source.common.FetchError,'receipt_required'):
                    source.seed_control_charge(ledger)
                self.assertFalse(proof.exists())

    def test_baseline_crash_recovery_keeps_charge_without_cached_control(self):
        with tempfile.TemporaryDirectory() as directory:
            folder=Path(directory)
            receipt={'schema_version':1,'initialization':'initial_control','baseline_control_bytes':4251,
                     'source_response_sha256':source.CONTROL_SHA,'source_url':source.control_fixture.URL,
                     'reference_dna_sha256':source.control_fixture.DNA_SHA}
            source.publish_private(folder,source.BASELINE_RECEIPT,json.dumps(receipt).encode())
            with source.common.TransferLedger(folder,source.LIMIT) as ledger:
                source.seed_control_charge(ledger)
                self.assertEqual(ledger.data['charged_bytes'],4251)
                self.assertEqual(ledger.data['body_bytes_observed'],4251)
                ledger.data.update(baseline_control_bytes=0,charged_bytes=0,body_bytes_observed=0)
                with self.assertRaisesRegex(source.common.FetchError,'history_mismatch'):
                    source.seed_control_charge(ledger)

    def test_control_response_timestamps_vary_but_reference_pin_and_response_bind(self):
        dna='A'*4096  # Synthetic reference used only by this offline test.
        with mock.patch.object(source.control_fixture,'DNA_SHA',hashlib.sha256(dna.encode()).hexdigest()):
            for timestamp in ('first','second'):
                with self.subTest(timestamp=timestamp), tempfile.TemporaryDirectory() as directory:
                    folder=Path(directory)
                    value={'genome':'hg38','chrom':'chr1','start':1000000,'end':1004096,
                           'dna':dna,'downloadTime':timestamp}
                    raw=json.dumps(value).encode()
                    source.publish_private(folder,'control-ucsc-hg38-chr1.json',raw)
                    with source.common.TransferLedger(folder,source.LIMIT) as ledger:
                        source.seed_control_charge(ledger)
                        receipt=source.control_baseline_receipt(folder)
                        self.assertEqual(receipt['source_response_sha256'],hashlib.sha256(raw).hexdigest())
                        self.assertEqual(ledger.data['charged_bytes'],len(raw))
                        path=folder/'control-ucsc-hg38-chr1.json'
                        path.write_bytes(raw+b' ')
                        with self.assertRaisesRegex(source.common.FetchError,'cache_mismatch'):
                            source.seed_control_charge(ledger)

    def test_baseline_strict_types_duplicates_and_unknown_legacy_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            folder=Path(directory)
            with source.common.TransferLedger(folder,source.LIMIT) as ledger:
                source.seed_control_charge(ledger)
                proof=folder/source.BASELINE_RECEIPT
                original=json.loads(proof.read_bytes())
                for key,alias in (('schema_version',True),('schema_version',1.0),
                                  ('baseline_control_bytes',False),('baseline_control_bytes',0.0)):
                    with self.subTest(key=key,alias=alias):
                        proof.write_text(json.dumps(dict(original,**{key:alias})))
                        with self.assertRaisesRegex(source.common.FetchError,'receipt_invalid'):
                            source.seed_control_charge(ledger)
                proof.write_text('{"schema_version":1,"schema_version":1}')
                with self.assertRaisesRegex(source.common.FetchError,'duplicate_json_key'):
                    source.seed_control_charge(ledger)
                proof.write_text('{"schema_version":NaN}')
                with self.assertRaisesRegex(source.common.FetchError,'nonfinite_json'):
                    source.seed_control_charge(ledger)
                proof.unlink()
                with self.assertRaisesRegex(source.common.FetchError,'legacy_baseline_requires_review'):
                    source.adopt_legacy_control_baseline(ledger)
                ledger.data.update(baseline_control_imported=0)
                with self.assertRaisesRegex(source.common.FetchError,'missing_baseline_refusing_reset'):
                    source.seed_control_charge(ledger)

    def fixture(self, directory, body=b'source'):
        entry = dict(source.CATALOG[0], size_bytes=len(body), md5=hashlib.md5(body).hexdigest())
        ledger = source.common.TransferLedger(directory, source.LIMIT)
        self.addCleanup(ledger.close)
        source.seed_control_charge(ledger)
        reader = source.common.DownloadClient(ledger, time.monotonic() + 10)
        return entry, ledger, reader

    def test_exact_and_one_over_size_preserve_charges(self):
        for extra in (0, 1):
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as directory:
                entry, ledger, reader = self.fixture(directory)
                opener = Opener([Response(b'', entry['url'], len(b'source')),
                                 Response(b'source'+b'x'*extra, entry['url'])])
                if extra:
                    with self.assertRaises(source.common.FetchError):
                        source.acquire_entry(entry, Path(directory), ledger, reader, opener, True)
                    self.assertFalse((Path(directory)/entry['filename']).exists())
                    self.assertEqual(ledger.data['attempts'][0]['status'], 'failed_or_interrupted')
                    self.assertEqual(ledger.data['charged_bytes'], 7)
                else:
                    receipt = source.acquire_entry(entry, Path(directory), ledger, reader, opener, True)
                    self.assertEqual(receipt['sha256'], hashlib.sha256(b'source').hexdigest())
                    self.assertEqual(ledger.data['charged_bytes'], 6)
                    cached = source.acquire_entry(entry, Path(directory), ledger, reader, opener, False)
                    self.assertEqual(cached['status'], 'verified_cached')
                    self.assertEqual(len(opener.requests), 2)
                    self.assertEqual(ledger.data['charged_bytes'], 6)

    def test_digest_mismatch_never_publishes_or_resets(self):
        with tempfile.TemporaryDirectory() as directory:
            entry, ledger, reader = self.fixture(directory)
            opener = Opener([Response(b'', entry['url']), Response(b'broken', entry['url'])])
            with self.assertRaises(source.common.FetchError):
                source.acquire_entry(entry, Path(directory), ledger, reader, opener, True)
            self.assertEqual(ledger.data['charged_bytes'], 6)
            self.assertFalse((Path(directory)/entry['filename']).exists())
            self.assertFalse(list(Path(directory).glob('.dataset-unverified-*')))
            ledger.close()
            with source.common.TransferLedger(directory, source.LIMIT) as recovered:
                self.assertEqual(recovered.data['charged_bytes'], 6)
                self.assertEqual(recovered.data['attempts'][0]['status'], 'failed_or_interrupted')

    def test_redirect_encoding_and_unapproved_url_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            entry, ledger, reader = self.fixture(directory)
            for response in [Response(b'', 'https://unrelated.example/file'),
                             Response(b'', entry['url'], encoding='gzip')]:
                with self.subTest(response=response), self.assertRaises(source.common.FetchError):
                    source.request_response(entry['url'], ledger, reader, Opener([response]))
            opener = Opener([])
            with self.assertRaises(source.common.FetchError):
                source.request_response('https://unrelated.example/file', ledger, reader, opener)
            self.assertFalse(opener.requests)

    def test_cache_corruption_symlink_and_missing_ledger_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            entry, ledger, reader = self.fixture(directory)
            target = Path(directory)/entry['filename']
            target.write_bytes(b'broken'); target.chmod(0o600)
            with self.assertRaises(source.common.FetchError):
                source.acquire_entry(entry, Path(directory), ledger, reader, Opener([]), False)
            target.unlink(); target.symlink_to(Path(directory)/'missing')
            with self.assertRaises(source.common.FetchError):
                source.acquire_entry(entry, Path(directory), ledger, reader, Opener([]), False)
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)/'datasets'; folder.mkdir(mode=0o700)
            (folder/source.CATALOG[0]['filename']).write_bytes(b'old')
            with self.assertRaises(source.common.FetchError):
                source.acquire(directory)
            self.assertFalse((folder/'transfer-ledger.json').exists())

    def test_private_publication_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            source.publish_private(folder, 'metadata.json', b'original')
            self.assertEqual((folder/'metadata.json').stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                source.publish_private(folder, 'metadata.json', b'changed')
            self.assertEqual((folder/'metadata.json').read_bytes(), b'original')
            self.assertFalse(list(folder.glob('.dataset-metadata-*')))


if __name__ == '__main__':
    unittest.main()
