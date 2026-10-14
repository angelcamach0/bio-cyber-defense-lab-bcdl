"""Offline bounded-source acquisition tests; no dataset network or inference."""
import email.message
import hashlib
import importlib.util
import io
from pathlib import Path
import sys
import tempfile
import time
import unittest

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
