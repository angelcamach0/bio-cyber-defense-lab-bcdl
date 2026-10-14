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

LIMIT = 50 << 20
METADATA_URL = 'https://zenodo.org/api/records/1405945'
CONTROL_SHA = 'b76938b9aabdf417c1b7377f941c7a2e930f83acc4cb0747e85bd4a65fb9c1d8'
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


def seed_control_charge(ledger):
    if ledger.data.get('baseline_control_imported') is True:
        return
    if ledger.data['charged_bytes'] or ledger.data['attempts']:
        raise common.FetchError('dataset_ledger_missing_baseline_refusing_reset')
    path = ledger.prefix / 'control-ucsc-hg38-chr1.json'
    size = 0
    if path.exists():
        data = private_read(path, 16384)
        if hashlib.sha256(data).hexdigest() != CONTROL_SHA:
            raise common.FetchError('dataset_control_baseline_digest_mismatch')
        size = len(data)
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
    if not (directory / 'transfer-ledger.json').exists() and any(
            (directory / name).exists() or (directory / name).is_symlink()
            for name in ['zenodo-1405945-metadata.json', *(e['filename'] for e in CATALOG)]):
        raise common.FetchError('dataset_existing_data_requires_ledger')
    with common.TransferLedger(directory, LIMIT) as ledger:
        seed_control_charge(ledger)
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
