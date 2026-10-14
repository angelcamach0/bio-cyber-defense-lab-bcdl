#!/usr/bin/env python3
"""Explicit acquisition of one licensed, pinned small caQTL source; no inference.

The separate 50 MiB dataset ledger includes the previously acquired UCSC control.
It never resets the checkpoint ledger, retries errors, follows redirects, expands
the complete gzip, changes the biological protocol or maps GRCh37 to hg38.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import ssl
import stat
import tempfile
import time
import urllib.request

import checkpoint_fetch as common
import control_fixture

LIMIT = 50 << 20
METADATA_URL = 'https://zenodo.org/api/records/1405945'
CONTROL_SHA = 'b76938b9aabdf417c1b7377f941c7a2e930f83acc4cb0747e85bd4a65fb9c1d8'
BASELINE_RECEIPT = 'control-baseline-receipt.json'
CATALOG = [
    {'filename': 'lead_caQTL_variants.tsv.gz', 'size_bytes': 10497915,
     'md5': '4b05a81465935729056828712e3e2fcf'},
    {'filename': 'README.txt', 'size_bytes': 5043,
     'md5': 'ef718ea6b0c2c598fb3c8737f417f41d'},
]
for entry in CATALOG:
    entry['url'] = 'https://zenodo.org/api/records/1405945/files/' + entry['filename'] + '/content'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *unused):
        return None


def private_read(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > maximum):
            raise common.FetchError('dataset_cache_unsafe')
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise common.FetchError('dataset_cache_size_exceeded')
    return data


def publish_private(directory, filename, raw):
    fd, temporary = tempfile.mkstemp(prefix='.dataset-metadata-', dir=directory)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, directory / filename)
        os.unlink(temporary)
        temporary = None
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        if temporary is not None:
            os.unlink(temporary)


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise common.FetchError('dataset_duplicate_json_key')
            result[key] = value
        return result
    def nonfinite(unused):
        raise common.FetchError('dataset_nonfinite_json')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=nonfinite)


def control_baseline_receipt(directory):
    """Read immutable history independently of the mutable transfer totals.

    This protects against accidental history loss, not a host actor rewriting
    both the ledger and every trusted receipt. Callers hold the ledger lock.
    """
    path = directory / BASELINE_RECEIPT
    if not path.exists() and not path.is_symlink():
        raise common.FetchError('dataset_control_baseline_receipt_required')
    receipt = strict_json(private_read(path, 4096))
    if (type(receipt) is not dict or type(receipt.get('schema_version')) is not int
            or receipt['schema_version'] != 1
            or type(receipt.get('baseline_control_bytes')) is not int
            or not 0 <= receipt['baseline_control_bytes'] <= 16384
            or receipt.get('initialization') not in ('initial_empty', 'initial_control', 'reviewed_legacy_control')):
        raise common.FetchError('dataset_control_baseline_receipt_invalid')
    size = receipt['baseline_control_bytes']
    sha = receipt.get('source_response_sha256')
    if size:
        if (type(sha) is not str or len(sha) != 64 or any(c not in '0123456789abcdef' for c in sha)
                or receipt.get('source_url') != control_fixture.URL
                or receipt.get('reference_dna_sha256') != control_fixture.DNA_SHA
                or receipt['initialization'] == 'initial_empty'):
            raise common.FetchError('dataset_control_baseline_receipt_invalid')
    elif (receipt['initialization'] != 'initial_empty' or any(receipt.get(k) is not None
            for k in ('source_response_sha256', 'source_url', 'reference_dna_sha256'))):
        raise common.FetchError('dataset_control_baseline_receipt_invalid')
    control = directory / 'control-ucsc-hg38-chr1.json'
    if control.exists() or control.is_symlink():
        raw = private_read(control, 16384)
        if not size or len(raw) != size or hashlib.sha256(raw).hexdigest() != sha:
            raise common.FetchError('dataset_control_baseline_cache_mismatch')
    return receipt


def publish_control_baseline(directory, raw, initialization):
    if raw is not None:
        # API timestamps can change; the fixed assembly/coordinates/DNA pin
        # prove the control, while each response's own SHA is retained.
        value = strict_json(raw)
        if (type(value) is not dict or type(value.get('start')) is not int
                or type(value.get('end')) is not int):
            raise common.FetchError('dataset_control_baseline_coordinates_invalid')
        try:
            control_fixture.checked_reference(raw)
        except (ValueError, TypeError, AttributeError) as exc:
            raise common.FetchError('dataset_control_baseline_reference_invalid') from exc
    receipt = {'schema_version': 1, 'initialization': initialization,
               'baseline_control_bytes': len(raw) if raw is not None else 0,
               'source_response_sha256': hashlib.sha256(raw).hexdigest() if raw is not None else None,
               'reference_dna_sha256': control_fixture.DNA_SHA if raw is not None else None,
               'source_url': control_fixture.URL if raw is not None else None}
    publish_private(directory, BASELINE_RECEIPT,
                    (json.dumps(receipt, sort_keys=True) + '\n').encode())
    return control_baseline_receipt(directory)


def adopt_legacy_control_baseline(ledger):
    """Explicit migration of the one previously reviewed pinned control.

    Missing control/empty legacy history never establishes a zero baseline.
    Existing totals and attempts are preserved byte for byte by this helper.
    """
    data = ledger.data
    if (data.get('baseline_control_imported') is not True
            or type(data.get('baseline_control_bytes')) is not int
            or data['baseline_control_bytes'] <= 0
            or any(type(data.get(k)) is not int or data[k] < data['baseline_control_bytes']
                   for k in ('charged_bytes', 'body_bytes_observed'))):
        raise common.FetchError('dataset_legacy_baseline_requires_review')
    raw = private_read(ledger.prefix / 'control-ucsc-hg38-chr1.json', 16384)
    if len(raw) != data['baseline_control_bytes'] or hashlib.sha256(raw).hexdigest() != CONTROL_SHA:
        raise common.FetchError('dataset_legacy_control_pin_mismatch')
    return publish_control_baseline(ledger.prefix, raw, 'reviewed_legacy_control')


def dataset_history_guard(directory):
    """Reject a reset/ambiguous existing history before the shared writer runs.

    Pins/history belong to the trusted research operator. This does not claim
    tamper resistance against a host actor rewriting every pin and receipt.
    Unresolved interrupted histories require review; they are never reset here.
    """
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise common.FetchError('dataset_ledger_duplicate_key')
            value[key] = item
        return value
    raw = private_read(directory / 'transfer-ledger.json', 1 << 20)
    data = json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda unused: (_ for _ in ()).throw(common.FetchError('dataset_ledger_nonfinite')))
    numbers = ('schema_version', 'limit_bytes', 'charged_bytes', 'body_bytes_observed',
               'http_exchanges', 'baseline_control_bytes')
    if (not isinstance(data, dict) or any(type(data.get(k)) is not int or data[k] < 0 for k in numbers)
            or data['schema_version'] != 1 or data['limit_bytes'] != LIMIT
            or data.get('baseline_control_imported') is not True or data['baseline_control_bytes'] > 16384
            or not isinstance(data.get('attempts'), list)
            or not 0 <= data['body_bytes_observed'] <= data['charged_bytes'] <= LIMIT):
        raise common.FetchError('dataset_ledger_strict_schema_invalid')
    baseline = control_baseline_receipt(directory)
    if data['baseline_control_bytes'] != baseline['baseline_control_bytes']:
        raise common.FetchError('dataset_control_history_mismatch')
    metadata = directory / 'zenodo-1405945-metadata.json'
    if metadata.exists() or metadata.is_symlink():
        metadata_bytes = len(private_read(metadata, 131072))
    elif data['attempts'] or data['http_exchanges']:
        raise common.FetchError('dataset_metadata_history_missing_requires_review')
    else:
        metadata_bytes = 0
    floor = data['baseline_control_bytes'] + metadata_bytes
    charged_floor = body_floor = floor
    for attempt in data['attempts']:
        if not isinstance(attempt, dict):
            raise common.FetchError('dataset_attempt_invalid')
        if attempt.get('status') in ('verified', 'verified_bytes') and attempt.get('sha256') is None:
            raise common.FetchError('dataset_attempt_pin_missing')
        if attempt.get('sha256') is not None:
            if (type(attempt.get('size_bytes')) is not int or attempt['size_bytes'] < 0
                    or not isinstance(attempt['sha256'], str) or len(attempt['sha256']) != 64
                    or any(c not in '0123456789abcdef' for c in attempt['sha256'])):
                raise common.FetchError('dataset_attempt_pin_invalid')
            floor += attempt['size_bytes']
        if attempt.get('status') not in ('verified', 'verified_bytes', 'failed_or_interrupted'):
            raise common.FetchError('dataset_interrupted_history_requires_review')
        if attempt['status'] == 'failed_or_interrupted' and not all(
                k in attempt for k in ('charged_at_end', 'body_at_end')):
            raise common.FetchError('dataset_failed_history_requires_review')
        for key, target in (('charged_at_end', 'charged'), ('body_at_end', 'body')):
            if key in attempt:
                if type(attempt[key]) is not int or attempt[key] < 0:
                    raise common.FetchError('dataset_attempt_accounting_invalid')
                if target == 'charged':
                    charged_floor = max(charged_floor, attempt[key])
                else:
                    body_floor = max(body_floor, attempt[key])
    if data['charged_bytes'] < max(floor, charged_floor) or data['body_bytes_observed'] < max(floor, body_floor):
        raise common.FetchError('dataset_history_charge_would_decrease')
    return data


def seed_control_charge(ledger):
    if ledger.data.get('baseline_control_imported') is True:
        receipt = control_baseline_receipt(ledger.prefix)
        size = receipt['baseline_control_bytes']
        if (type(ledger.data.get('baseline_control_bytes')) is not int
                or ledger.data['baseline_control_bytes'] != size
                or any(type(ledger.data.get(k)) is not int or ledger.data[k] < size
                       for k in ('charged_bytes', 'body_bytes_observed'))):
            raise common.FetchError('dataset_control_baseline_history_mismatch')
        return
    if ((ledger.data.get('baseline_control_imported') is not None
            and ledger.data.get('baseline_control_imported') is not False)
            or any(type(ledger.data.get(k)) is not int or ledger.data[k] != 0
                   for k in ('charged_bytes', 'body_bytes_observed', 'http_exchanges'))
            or ledger.data['attempts'] != []):
        raise common.FetchError('dataset_ledger_missing_baseline_refusing_reset')
    proof = ledger.prefix / BASELINE_RECEIPT
    if proof.exists() or proof.is_symlink():
        # Receipt publication precedes ledger mutation; preserve that charge
        # even if the cached response disappeared between those two writes.
        receipt = control_baseline_receipt(ledger.prefix)
    else:
        path = ledger.prefix / 'control-ucsc-hg38-chr1.json'
        raw = private_read(path, 16384) if path.exists() or path.is_symlink() else None
        receipt = publish_control_baseline(ledger.prefix, raw,
                    'initial_control' if raw is not None else 'initial_empty')
    size = receipt['baseline_control_bytes']
    ledger.data.update(baseline_control_imported=True, charged_bytes=size,
                       body_bytes_observed=size, baseline_control_bytes=size)
    ledger.save()


def request_response(url, ledger, reader, opener, method='GET'):
    if url not in {METADATA_URL, *(e['url'] for e in CATALOG)}:
        raise common.FetchError('dataset_url_not_allowed')
    ledger.data['http_exchanges'] += 1
    ledger.save()
    response = opener.open(urllib.request.Request(url, method=method,
        headers={'Accept-Encoding': 'identity', 'User-Agent': 'BioZero-SCI02-source-verification/1'}),
        timeout=min(30, reader.remaining()))
    if response.geturl() != url or response.headers.get('Content-Encoding', 'identity').lower() != 'identity':
        response.close()
        raise common.FetchError('dataset_response_redirect_or_encoding')
    return response


def acquire_entry(entry, directory, ledger, reader, opener, fetch=False):
    target = directory / entry['filename']
    if target.is_symlink():
        raise common.FetchError('dataset_destination_symlink')
    if target.exists():
        data = private_read(target, entry['size_bytes'])
        if len(data) != entry['size_bytes'] or hashlib.md5(data).hexdigest() != entry['md5']:
            raise common.FetchError('dataset_cached_pin_mismatch')
        return {'filename': entry['filename'], 'status': 'verified_cached',
                'size_bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'published_md5': entry['md5']}
    if not fetch:
        raise common.FetchError('dataset_cache_missing_explicit_fetch_required')
    attempt = {'filename': entry['filename'], 'status': 'started', 'started_unix': time.time()}
    ledger.data['attempts'].append(attempt)
    ledger.save()
    temporary = None
    try:
        with request_response(entry['url'], ledger, reader, opener, 'HEAD') as response:
            length = response.headers.get('Content-Length')
            if length is not None and int(length) != entry['size_bytes']:
                raise common.FetchError('dataset_head_size_mismatch')
        with request_response(entry['url'], ledger, reader, opener) as response:
            if response.headers.get_content_type() == 'text/html':
                raise common.FetchError('dataset_html_response')
            length = response.headers.get('Content-Length')
            if length is not None and int(length) != entry['size_bytes']:
                raise common.FetchError('dataset_get_size_mismatch')
            fd, temporary = tempfile.mkstemp(prefix='.dataset-unverified-', dir=directory)
            count, md5, sha = 0, hashlib.md5(), hashlib.sha256()
            with os.fdopen(fd, 'wb') as stream:
                while count <= entry['size_bytes']:
                    block = reader.read(response, min(1 << 20, entry['size_bytes'] + 1 - count))
                    if not block:
                        break
                    count += len(block)
                    if count > entry['size_bytes']:
                        raise common.FetchError('dataset_get_size_exceeded')
                    stream.write(block)
                    md5.update(block)
                    sha.update(block)
                if count != entry['size_bytes'] or md5.hexdigest() != entry['md5']:
                    raise common.FetchError('dataset_pin_mismatch')
                stream.flush()
                os.fsync(stream.fileno())
            os.link(temporary, target)
            os.unlink(temporary)
            temporary = None
            directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        attempt.update(status='verified', size_bytes=count, sha256=sha.hexdigest())
        ledger.save()
        return {'filename': entry['filename'], 'status': 'verified', 'size_bytes': count,
                'sha256': sha.hexdigest(), 'published_md5': entry['md5']}
    except BaseException:
        attempt['status'] = 'failed_or_interrupted'
        ledger.save()
        raise
    finally:
        if temporary is not None:
            os.unlink(temporary)


def acquire(prefix, fetch=False):
    directory = Path(prefix).absolute() / 'datasets'
    if any(path.is_symlink() for path in [directory, *directory.parents]):
        raise common.FetchError('dataset_prefix_symlink')
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    for name in ('transfer-ledger.json', 'transfer-ledger.lock'):
        if (directory / name).is_symlink():
            raise common.FetchError('dataset_ledger_symlink')
    if (directory / 'transfer-ledger.json').exists():
        existing = strict_json(private_read(directory / 'transfer-ledger.json', 1 << 20))
        if type(existing) is not dict:
            raise common.FetchError('dataset_ledger_strict_schema_invalid')
        if existing.get('baseline_control_imported') is True:
            dataset_history_guard(directory)
        elif (type(existing.get('schema_version')) is not int or existing['schema_version'] != 1
                or type(existing.get('limit_bytes')) is not int or existing['limit_bytes'] != LIMIT
                or any(type(existing.get(k)) is not int or existing[k] != 0
                       for k in ('charged_bytes', 'body_bytes_observed', 'http_exchanges'))
                or existing.get('attempts') != []
                or (existing.get('baseline_control_imported') is not None
                    and existing.get('baseline_control_imported') is not False)):
            raise common.FetchError('dataset_ledger_uninitialized_history_requires_review')
    if not (directory / 'transfer-ledger.json').exists() and any(
            (directory / name).exists() or (directory / name).is_symlink()
            for name in [BASELINE_RECEIPT, 'zenodo-1405945-metadata.json',
                         'peaks.bed.gz', 'hg19ToHg38.over.chain.gz',
                         *(e['filename'] for e in CATALOG),
                         *(p.name for p in directory.glob('reference-*.json'))]):
        raise common.FetchError('dataset_existing_data_requires_ledger')
    with common.TransferLedger(directory, LIMIT) as ledger:
        seed_control_charge(ledger)
        guarded = dataset_history_guard(directory)
        if json.dumps(ledger.data, sort_keys=True) != json.dumps(guarded, sort_keys=True):
            raise common.FetchError('dataset_ledger_changed_before_lock')
        opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
        reader = common.DownloadClient(ledger, time.monotonic() + 180, opener=opener)
        metadata_path = directory / 'zenodo-1405945-metadata.json'
        if metadata_path.is_symlink():
            raise common.FetchError('dataset_metadata_symlink')
        if metadata_path.exists():
            metadata_raw = private_read(metadata_path, 131072)
        elif fetch:
            with request_response(METADATA_URL, ledger, reader, opener) as response:
                metadata_raw = reader.read(response, 131073)
            if len(metadata_raw) > 131072:
                raise common.FetchError('dataset_metadata_size_exceeded')
            publish_private(directory, metadata_path.name, metadata_raw)
        else:
            raise common.FetchError('dataset_metadata_missing_explicit_fetch_required')
        metadata = json.loads(metadata_raw)
        if (metadata.get('id') != 1405945 or metadata.get('metadata', {}).get('access_right') != 'open'
                or metadata.get('metadata', {}).get('license', {}).get('id', '').lower() != 'cc-by-4.0'):
            raise common.FetchError('dataset_permission_unverified')
        published = {entry['key']: entry for entry in metadata['files']}
        for entry in CATALOG:
            pin = published.get(entry['filename'], {})
            if pin.get('size') != entry['size_bytes'] or pin.get('checksum') != 'md5:' + entry['md5']:
                raise common.FetchError('dataset_catalog_disagrees_with_primary')
        receipts = [acquire_entry(entry, directory, ledger, reader, opener, fetch) for entry in CATALOG]
        with gzip.open(directory / CATALOG[0]['filename'], 'rb') as stream:
            header = stream.readline(8193)
        if len(header) > 8192 or not header.endswith(b'\n'):
            raise common.FetchError('dataset_header_size_or_format')
        columns = header.decode('utf-8').rstrip('\r\n').split('\t')
        return {'schema_version': 1, 'status': 'acquired_and_pinned', 'source_record': 1405945,
                'source_url': 'https://zenodo.org/records/1405945', 'license': 'CC-BY-4.0',
                'permission_scope': 'internal_research', 'files': receipts,
                'source_metadata_sha256': hashlib.sha256(metadata_raw).hexdigest(),
                'dataset_transfer_limit_bytes': LIMIT, 'dataset_transfer_charged_bytes': ledger.data['charged_bytes'],
                'baseline_control_bytes': ledger.data['baseline_control_bytes'], 'header_columns': columns,
                'source_build': 'GRCh37', 'target_protocol_build': 'hg38',
                'normalization_status': 'pending_reviewed_build_and_peak_mapping',
                'biological_loci_inferred': 0, 'scope': 'Source acquisition and first header only; no complete gzip validation, normalization, selection or inference.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prefix', type=Path, required=True)
    parser.add_argument('--fetch', action='store_true')
    args = parser.parse_args()
    try:
        report = acquire(args.prefix, args.fetch)
    except Exception as exc:
        print(json.dumps({'status': 'failed', 'error_type': type(exc).__name__,
                         'error_code': str(exc) if isinstance(exc, common.FetchError) else 'dataset_acquisition_failed',
                         'scope': 'No inference; private attempts retained'}))
        return 1
    print(json.dumps(report, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
