"""Offline mapping-input acquisition boundaries; no network or inference."""
import hashlib
import json
from pathlib import Path
import tempfile
import time
import unittest

import mapping_assets as assets
from test_small_dataset_fetch import Opener, Response


class MappingAssetTests(unittest.TestCase):
    def test_history_guard_rejects_scalar_aliases_reset_and_ambiguous_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            metadata = folder/'zenodo-1405945-metadata.json'
            metadata.write_bytes(b'{}'); metadata.chmod(0o600)
            assets.source.publish_control_baseline(folder, None, 'initial_empty')
            original = {'schema_version':1,'limit_bytes':assets.source.LIMIT,
                        'charged_bytes':12,'body_bytes_observed':12,'http_exchanges':4,
                        'baseline_control_imported':True,'baseline_control_bytes':0,
                        'attempts':[{'filename':'source','status':'verified','size_bytes':10,'sha256':'a'*64}]}
            ledger=folder/'transfer-ledger.json'
            def write(data):
                ledger.write_text(json.dumps(data));ledger.chmod(0o600)
            write(original)
            self.assertEqual(assets.history_guard(folder)['charged_bytes'],12)
            for key, alias in (('schema_version',True),('schema_version',1.0),('charged_bytes',True),
                               ('body_bytes_observed',False),('http_exchanges',4.0),('baseline_control_imported',1)):
                with self.subTest(key=key,alias=alias):
                    broken=dict(original);broken[key]=alias;write(broken)
                    with self.assertRaisesRegex(assets.source.common.FetchError,'strict_schema_invalid'):
                        assets.history_guard(folder)
            broken=dict(original,charged_bytes=1,body_bytes_observed=1);write(broken)
            before=ledger.read_bytes()
            with self.assertRaisesRegex(assets.source.common.FetchError,'charge_would_decrease'):
                assets.history_guard(folder)
            self.assertEqual(ledger.read_bytes(),before)
            write(original)
            ledger.write_text(ledger.read_text().replace('"charged_bytes": 12','"charged_bytes": 12, "charged_bytes": 1'))
            with self.assertRaisesRegex(assets.source.common.FetchError,'duplicate_key'):
                assets.history_guard(folder)
            for failed in ({'status':'started'}, {'status':'failed_or_interrupted'},
                           {'status':'failed_or_interrupted','charged_at_end':20,'body_at_end':19}):
                broken=dict(original,attempts=original['attempts']+[failed]);write(broken)
                with self.assertRaises(assets.source.common.FetchError):
                    assets.history_guard(folder)
            write(dict(original,charged_bytes=20,body_bytes_observed=19,
                       attempts=original['attempts']+[{'status':'failed_or_interrupted','charged_at_end':20,'body_at_end':19}]))
            self.assertEqual(assets.history_guard(folder)['charged_bytes'],20)

    def test_removed_control_cannot_reduce_imported_baseline(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            assets.source.publish_private(folder, 'zenodo-1405945-metadata.json', b'{}')
            receipt = {'schema_version':1,'initialization':'reviewed_legacy_control',
                       'baseline_control_bytes':4251,'source_response_sha256':assets.source.CONTROL_SHA,
                       'source_url':assets.source.control_fixture.URL,
                       'reference_dna_sha256':assets.source.control_fixture.DNA_SHA}
            assets.source.publish_private(folder, assets.source.BASELINE_RECEIPT, json.dumps(receipt).encode())
            data = {'schema_version':1,'limit_bytes':assets.source.LIMIT,'charged_bytes':4253,
                    'body_bytes_observed':4253,'http_exchanges':1,'attempts':[],
                    'baseline_control_imported':True,'baseline_control_bytes':4251}
            path=folder/'transfer-ledger.json'
            def write(value):
                path.write_text(json.dumps(value));path.chmod(0o600)
            write(data)
            self.assertEqual(assets.history_guard(folder)['charged_bytes'],4253)
            write(dict(data,baseline_control_bytes=0,charged_bytes=2,body_bytes_observed=2))
            before=path.read_bytes()
            with self.assertRaisesRegex(assets.source.common.FetchError,'control_history_mismatch'):
                assets.history_guard(folder)
            self.assertEqual(path.read_bytes(),before)
            (folder/assets.source.BASELINE_RECEIPT).unlink()
            write(data)
            with self.assertRaisesRegex(assets.source.common.FetchError,'receipt_required'):
                assets.history_guard(folder)

    def test_oversized_ledger_and_removed_asset_preserve_history(self):
        with tempfile.TemporaryDirectory() as directory:
            folder=Path(directory)
            assets.source.publish_control_baseline(folder,None,'initial_empty')
            assets.source.publish_private(folder,'zenodo-1405945-metadata.json',b'{}')
            path=folder/'transfer-ledger.json'
            path.write_bytes(b' ' * ((1<<20)+1));path.chmod(0o600)
            with self.assertRaisesRegex(assets.source.common.FetchError,'cache_unsafe'):
                assets.history_guard(folder)
            data={'schema_version':1,'limit_bytes':assets.source.LIMIT,
                  'charged_bytes':32,'body_bytes_observed':32,'http_exchanges':2,
                  'baseline_control_imported':True,'baseline_control_bytes':0,
                  'attempts':[{'filename':'removed.gz','status':'verified','size_bytes':10,'sha256':'a'*64,
                               'charged_at_end':32,'body_at_end':32}]}
            path.write_text(json.dumps(data))
            self.assertEqual(assets.history_guard(folder)['charged_bytes'],32)
            data.update(charged_bytes=12,body_bytes_observed=12)
            path.write_text(json.dumps(data));before=path.read_bytes()
            with self.assertRaisesRegex(assets.source.common.FetchError,'charge_would_decrease'):
                assets.history_guard(folder)
            self.assertEqual(path.read_bytes(),before)

    def fixture(self, directory):
        body = b'\x1f\x8bDATA'
        entry = dict(assets.ASSETS[1], size_bytes=len(body))
        ledger = assets.source.common.TransferLedger(directory, assets.source.LIMIT)
        self.addCleanup(ledger.close)
        assets.source.seed_control_charge(ledger)
        reader = assets.source.common.DownloadClient(ledger, time.monotonic() + 10)
        return entry, body, ledger, reader

    def test_exact_pin_and_one_over_retains_failed_charge(self):
        for extra in (0, 1):
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as directory:
                entry, body, ledger, reader = self.fixture(directory)
                opener = Opener([Response(b'', entry['url'], len(body)), Response(body+b'X'*extra, entry['url'])])
                if extra:
                    with self.assertRaisesRegex(assets.source.common.FetchError, 'actual_size_exceeded'):
                        assets.acquire_entry(entry, Path(directory), ledger, reader, opener, True)
                    self.assertFalse((Path(directory)/entry['filename']).exists())
                    self.assertEqual(ledger.data['charged_bytes'], len(body)+1)
                    self.assertEqual(ledger.data['attempts'][0]['status'], 'failed_or_interrupted')
                else:
                    result = assets.acquire_entry(entry, Path(directory), ledger, reader, opener, True)
                    self.assertEqual(result['sha256'], hashlib.sha256(body).hexdigest())
                    self.assertFalse(result['publisher_digest_verified'])
                    self.assertEqual(ledger.data['charged_bytes'], len(body))
                    cached = assets.acquire_entry(entry, Path(directory), ledger, reader, opener, False)
                    self.assertEqual(cached['status'], 'verified_cached')
                    self.assertEqual(len(opener.requests), 2)

    def test_unpinned_or_tampered_cache_never_adopted(self):
        with tempfile.TemporaryDirectory() as directory:
            entry, body, ledger, reader = self.fixture(directory)
            target = Path(directory)/entry['filename']
            target.write_bytes(body); target.chmod(0o600)
            with self.assertRaisesRegex(assets.source.common.FetchError, 'cached_pin_missing'):
                assets.acquire_entry(entry, Path(directory), ledger, reader, Opener([]), False)
            ledger.data['attempts'].append({'kind':'mapping_asset','filename':entry['filename'],
                'source_url':entry['url'],'size_bytes':len(body),'sha256':hashlib.sha256(body).hexdigest()})
            target.write_bytes(b'\x1f\x8bDIFF')
            with self.assertRaisesRegex(assets.source.common.FetchError, 'cached_pin_missing'):
                assets.acquire_entry(entry, Path(directory), ledger, reader, Opener([]), False)
            target.unlink(); target.symlink_to(Path(directory)/'missing')
            with self.assertRaisesRegex(assets.source.common.FetchError, 'destination_symlink'):
                assets.acquire_entry(entry, Path(directory), ledger, reader, Opener([]), False)

    def test_publisher_digest_and_request_boundary(self):
        with tempfile.TemporaryDirectory() as directory:
            entry, body, ledger, reader = self.fixture(directory)
            with self.assertRaisesRegex(assets.source.common.FetchError, 'publisher_digest_mismatch'):
                assets.entry_receipt(dict(entry,published_md5='0'*32), body, 'fixture')
            opener = Opener([])
            with self.assertRaisesRegex(assets.source.common.FetchError, 'url_not_allowed'):
                assets.response_for(dict(entry,url='https://unrelated.example/file'), 'GET', ledger, reader, opener)
            self.assertFalse(opener.requests)
            for response in (Response(b'', 'https://unrelated.example/file'), Response(b'',entry['url'],encoding='gzip')):
                with self.assertRaisesRegex(assets.source.common.FetchError, 'redirect_or_encoding'):
                    assets.response_for(entry, 'GET', ledger, reader, Opener([response]))

    def test_extension_requires_original_ledger(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)/'datasets'; folder.mkdir(mode=0o700)
            original=folder/'retained';original.write_bytes(b'KEEP')
            with self.assertRaisesRegex(assets.source.common.FetchError, 'existing_dataset_ledger_required'):
                assets.acquire(directory, True)
            self.assertFalse((folder/'transfer-ledger.json').exists())
            self.assertEqual(original.read_bytes(), b'KEEP')


if __name__ == '__main__':
    unittest.main()
