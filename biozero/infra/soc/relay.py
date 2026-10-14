#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Deliver one retained worker event over verified HTTPS; never enforce actions."""
import argparse
from datetime import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import ssl
import stat
import tempfile
import urllib.error
import urllib.parse
import urllib.request

LIMIT = 65536
FIELDS = ('schema_version', 'alert_id', 'source', 'event_code', 'severity',
          'timestamp', 'indicators', 'actions')
CODES = frozenset(('upload_integrity_failed', 'signature_required',
    'signature_algorithm_invalid', 'signature_invalid', 'encryption_required',
    'encryption_metadata_invalid', 'key_unwrap_failed', 'decryption_failed'))


class RelayError(Exception):
    """A fixed code safe to print; no input, credential or remote body."""


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise RelayError('duplicate_json_field')
        result[key] = value
    return result


def decode(raw):
    try:
        return json.loads(raw, object_pairs_hook=_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(RelayError('invalid_json')))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise RelayError('invalid_json') from exc


def _read_descriptor(fd, limit):
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_uid != os.getuid() or info.st_size > limit):
            raise RelayError('private_file_invalid')
        raw = stream.read(limit + 1)
        if len(raw) > limit:
            raise RelayError('private_file_invalid')
        return raw


def private_read(path, limit=LIMIT):
    """Reject links, FIFOs, excessive sizes and shared files before reading."""
    path = Path(path).absolute()
    if path.resolve() != path:
        raise RelayError('private_file_invalid')
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        return _read_descriptor(fd, limit)
    except OSError as exc:
        raise RelayError('private_file_unreadable') from exc


def canonical_event(event):
    if not isinstance(event, dict) or set(event) != set(FIELDS):
        raise RelayError('event_contract_invalid')
    indicators = event['indicators']
    if not isinstance(indicators, dict) or set(indicators) != {'job_id'}:
        raise RelayError('event_contract_invalid')
    job = indicators['job_id']
    if not isinstance(job, str) or not re.fullmatch(r'[0-9a-f]{8,64}', job):
        raise RelayError('event_contract_invalid')
    code = event['event_code']
    if not isinstance(code, str) or code not in CODES:
        raise RelayError('event_contract_invalid')
    identifier = 'evt-' + hashlib.sha256(f'enclave-runner/{job}/{code}'.encode()).hexdigest()
    if (type(event['schema_version']) is not int or event['schema_version'] != 1
            or event['alert_id'] != identifier or event['source'] != 'enclave-runner'
            or event['severity'] != 'high' or event['actions'] != ['quarantine']):
        raise RelayError('event_contract_invalid')
    timestamp = event['timestamp']
    if not isinstance(timestamp, str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', timestamp):
        raise RelayError('event_contract_invalid')
    try:
        datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%SZ')
    except ValueError as exc:
        raise RelayError('event_contract_invalid') from exc
    # This field order equals Go's alertPayload marshal order; all values are ASCII.
    value = {field: event[field] for field in FIELDS}
    return json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RelayError('redirect_refused')


def make_opener(endpoint, ca_file):
    url = urllib.parse.urlsplit(endpoint)
    if (url.scheme != 'https' or not url.hostname or url.username or url.password
            or url.path != '/alert' or url.query or url.fragment):
        raise RelayError('endpoint_invalid')
    try:
        port = url.port
    except ValueError as exc:
        raise RelayError('endpoint_invalid') from exc
    if port is not None and not 1 <= port <= 65535:
        raise RelayError('endpoint_invalid')
    try:
        local = ipaddress.ip_address(url.hostname).is_loopback
    except ValueError:
        local = False
    context = ssl.create_default_context(cafile=str(ca_file))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    handlers = [NoRedirect(), urllib.request.HTTPSHandler(context=context)]
    if local:
        handlers.append(urllib.request.ProxyHandler({}))
    return urllib.request.build_opener(*handlers)


def validate_ack(response, event, digest):
    if (not isinstance(response, dict) or response.get('status') != 'recorded'
            or response.get('mode') != 'simulation' or response.get('enforced') is not False
            or response.get('alert_id') != event['alert_id']
            or response.get('payload_sha256') != digest or type(response.get('replay')) is not bool):
        raise RelayError('acknowledgment_invalid')
    actions = response.get('actions')
    expected = {'action': 'quarantine', 'target': event['indicators']['job_id'],
                'status': 'simulated', 'enforced': False}
    if (not isinstance(actions, list) or len(actions) != 1
            or not isinstance(actions[0], dict) or actions[0].get('enforced') is not False
            or actions != [expected]):
        raise RelayError('acknowledgment_invalid')
    return response


def _receipt_directory(directory):
    """Anchor a no-symlink directory and fsync every ancestor entry on retry."""
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in directory.parts[1:]:
            try:
                os.mkdir(component, mode=0o700, dir_fd=fd)
            except FileExistsError:
                pass
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                os.fsync(fd)
            except BaseException:
                os.close(child)
                raise
            os.close(fd)
            fd = child
        info = os.fstat(fd)
        if stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.getuid():
            raise RelayError('receipt_directory_invalid')
        return fd
    except BaseException:
        os.close(fd)
        raise


def retain_receipt(directory, value, event):
    directory = Path(directory).absolute()
    if directory.resolve() != directory:
        raise RelayError('receipt_directory_invalid')
    try:
        fd = _receipt_directory(directory)
        try:
            anchored = Path('/proc/self/fd') / str(fd)
            destination = event['alert_id'] + '.json'
            raw = json.dumps(value, separators=(',', ':')).encode() + b'\n'
            temp_fd, temp_name = tempfile.mkstemp(prefix='.receipt-', dir=anchored)
            try:
                with os.fdopen(temp_fd, 'wb') as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
                try:
                    os.link(temp_name, destination, dst_dir_fd=fd, follow_symlinks=False)
                except FileExistsError:
                    old_fd = os.open(destination, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                    old = decode(_read_descriptor(old_fd, LIMIT))
                    if (not isinstance(old, dict) or old.get('schema_version') != 1
                            or old.get('payload_sha256') != value['payload_sha256']
                            or old.get('endpoint_sha256') != value['endpoint_sha256']):
                        raise RelayError('receipt_conflict')
                    validate_ack(old.get('response'), event, value['payload_sha256'])
                os.unlink(temp_name)
                os.fsync(fd)
            finally:
                if os.path.lexists(temp_name):
                    os.unlink(temp_name)
        finally:
            os.close(fd)
    except OSError as exc:
        raise RelayError('receipt_persistence_failed') from exc


def deliver(event_path, endpoint, ca_file, secret, receipt_dir):
    event = decode(private_read(event_path))
    wire = canonical_event(event)
    if not isinstance(secret, str) or not 32 <= len(secret.encode()) <= 512 or any(c in secret for c in '\r\n'):
        raise RelayError('secret_invalid')
    digest = hashlib.sha256(wire).hexdigest()
    transport = make_opener(endpoint, ca_file)
    req = urllib.request.Request(endpoint, data=wire, method='POST',
        headers={'Content-Type': 'application/json', 'Accept': 'application/json',
                 'X-Webhook-Secret': secret})
    try:
        with transport.open(req, timeout=10) as result:
            if result.status != 200:
                raise RelayError('delivery_not_acknowledged')
            raw = result.read(LIMIT + 1)
            if len(raw) > LIMIT:
                raise RelayError('acknowledgment_too_large')
    except urllib.error.HTTPError as exc:
        exc.close()
        raise RelayError('delivery_not_acknowledged') from exc
    except (OSError, urllib.error.URLError) as exc:
        raise RelayError('delivery_transport_failed') from exc
    response = validate_ack(decode(raw), event, digest)
    retain_receipt(receipt_dir, {'schema_version': 1, 'payload_sha256': digest,
        'endpoint_sha256': hashlib.sha256(endpoint.encode()).hexdigest(),
        'response': response}, event)
    return response


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--event', required=True, type=Path)
    parser.add_argument('--endpoint', required=True)
    parser.add_argument('--ca', required=True, type=Path)
    parser.add_argument('--secret-file', required=True, type=Path)
    parser.add_argument('--receipts', required=True, type=Path)
    args = parser.parse_args()
    try:
        secret = private_read(args.secret_file, 512).decode('ascii')
        response = deliver(args.event, args.endpoint, args.ca, secret, args.receipts)
        print(json.dumps({'status': response['status'], 'mode': response['mode'],
                          'enforced': False, 'replay': response['replay']}))
        return 0
    except (RelayError, OSError, UnicodeError, ValueError):
        print('Security event delivery failed; inspect private inputs and service health.')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
