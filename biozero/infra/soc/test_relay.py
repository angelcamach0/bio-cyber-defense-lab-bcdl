import hashlib
import io
import json
import os
from pathlib import Path
import ssl
import tempfile
import unittest
from unittest import mock
import urllib.request

import relay


def fixture():
    job = '123456789abcdef0'
    code = 'signature_required'
    return {'schema_version': 1,
        'alert_id': 'evt-' + hashlib.sha256(f'enclave-runner/{job}/{code}'.encode()).hexdigest(),
        'source': 'enclave-runner', 'event_code': code, 'severity': 'high',
        'timestamp': '2026-10-14T00:00:00Z', 'indicators': {'job_id': job},
        'actions': ['quarantine']}


class Response(io.BytesIO):
    status = 200


class RelayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.event = fixture()
        self.path = self.root / 'event.json'
        self.path.write_bytes(relay.canonical_event(self.event))
        self.path.chmod(0o600)
        self.endpoint = 'https://127.0.0.1:8090/alert'
        self.digest = hashlib.sha256(relay.canonical_event(self.event)).hexdigest()
        self.ack = {'status': 'recorded', 'mode': 'simulation', 'enforced': False,
            'alert_id': self.event['alert_id'], 'payload_sha256': self.digest,
            'replay': False, 'actions': [{'action': 'quarantine',
                'target': self.event['indicators']['job_id'], 'status': 'simulated', 'enforced': False}]}

    def tearDown(self):
        self.temp.cleanup()

    def deliver(self, ack=None):
        opener = mock.Mock()
        opener.open.return_value = Response(json.dumps(self.ack if ack is None else ack).encode())
        with mock.patch.object(relay, 'make_opener', return_value=opener):
            return relay.deliver(self.path, self.endpoint, 'test-ca', 'x' * 32,
                                 self.root / 'receipts')

    def test_private_reader_rejects_links_fifo_permissions_and_oversize(self):
        target = self.root / 'target'
        target.symlink_to(self.path)
        with self.assertRaises(relay.RelayError):
            relay.private_read(target)
        target.unlink()
        os.mkfifo(target)
        with self.assertRaises(relay.RelayError):
            relay.private_read(target)
        self.path.chmod(0o644)
        with self.assertRaises(relay.RelayError):
            relay.private_read(self.path)
        self.path.chmod(0o600)
        with self.assertRaises(relay.RelayError):
            relay.private_read(self.path, 5)

    def test_worker_contract_rejects_forged_id_extra_data_and_bool_version(self):
        for change in ({'alert_id': 'evt-' + '0' * 64}, {'raw_dna': 'ACGT'},
                       {'schema_version': True}, {'timestamp': '2026-02-30T00:00:00Z'},
                       {'actions': ['block_ip']}, {'indicators': {'job_id': '12345678', 'ip': '127.0.0.1'}}):
            with self.subTest(change=change), self.assertRaises(relay.RelayError):
                relay.canonical_event({**self.event, **change})

    def test_duplicate_and_nonfinite_json_rejected(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{}{}'):
            with self.assertRaises(relay.RelayError):
                relay.decode(raw)

    def test_https_required_and_redirect_does_not_forward_secret(self):
        for endpoint in ('http://127.0.0.1/alert', 'https://a:b@localhost/alert',
                         'https://localhost/alert?x=1', 'https://localhost:invalid/alert'):
            with self.assertRaises(relay.RelayError):
                relay.make_opener(endpoint, '/not-read')
        request = urllib.request.Request(self.endpoint, data=b'{}', headers={'X-Webhook-Secret': 'private'})
        with self.assertRaises(relay.RelayError):
            relay.NoRedirect().redirect_request(request, None, 302, '', {}, 'https://example.org/alert')

    def test_transport_keeps_certificate_and_hostname_verification(self):
        context = ssl.create_default_context()
        with mock.patch.object(relay.ssl, 'create_default_context', return_value=context), \
             mock.patch.object(relay.urllib.request, 'build_opener') as builder:
            relay.make_opener(self.endpoint, 'test-ca')
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
        self.assertTrue(any(isinstance(handler, relay.NoRedirect) for handler in builder.call_args.args))

    def test_acknowledgment_requires_simulation_digest_and_exact_target(self):
        for change in ({'enforced': True}, {'mode': 'production'}, {'payload_sha256': '0' * 64},
                       {'replay': 1}, {'actions': [{**self.ack['actions'][0], 'enforced': 0}]},
                       {'actions': [{'action': 'quarantine', 'target': 'other',
                                                  'status': 'simulated', 'enforced': False}]}):
            with self.subTest(change=change), self.assertRaises(relay.RelayError):
                self.deliver({**self.ack, **change})
        self.assertFalse((self.root / 'receipts').exists())

    def test_receipt_private_durable_and_idempotent(self):
        self.deliver()
        path = self.root / 'receipts' / (self.event['alert_id'] + '.json')
        first = path.read_bytes()
        self.deliver({**self.ack, 'replay': True})
        self.assertEqual(first, path.read_bytes())
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
        self.assertEqual(len(list(path.parent.iterdir())), 1)

    def test_receipt_failure_never_returns_success_and_keeps_event(self):
        with mock.patch.object(relay.os, 'fsync', side_effect=OSError('disk fault')):
            with self.assertRaises(relay.RelayError):
                self.deliver()
        self.assertTrue(self.path.is_file())
        self.assertFalse(list((self.root / 'receipts').glob('*.json')))

    def test_new_receipt_directory_parent_is_synced_before_ack(self):
        real_sync = os.fsync
        synced = []
        def observe(fd):
            synced.append(Path(os.readlink('/proc/self/fd/' + str(fd))))
            real_sync(fd)
        with mock.patch.object(relay.os, 'fsync', side_effect=observe):
            self.deliver()
        self.assertIn(self.root, synced)
        self.assertIn(self.root / 'receipts', synced)

    def test_existing_receipt_conflict_and_corruption_never_overwritten(self):
        self.deliver()
        path = self.root / 'receipts' / (self.event['alert_id'] + '.json')
        for value in ({'schema_version': 1, 'payload_sha256': '0' * 64}, {'bad': True}):
            path.write_text(json.dumps(value))
            original = path.read_bytes()
            with self.assertRaises(relay.RelayError):
                self.deliver()
            self.assertEqual(path.read_bytes(), original)


if __name__ == '__main__':
    unittest.main()
