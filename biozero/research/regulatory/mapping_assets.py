#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Acquire only the reviewed small peak/chain inputs; never normalize or infer.

Uses the existing dataset ledger, not a new budget or the checkpoint ledger.
Chain SHA is a local pin of the official download, not a publisher digest.
"""
import argparse
import hashlib
import json
from pathlib import Path
import ssl
import time
import urllib.request

import small_dataset_fetch as source

ASSETS = [
    {'filename': 'peaks.bed.gz', 'size_bytes': 10705038,
     'url': 'https://zenodo.org/api/records/1405945/files/peaks.bed.gz/content',
     'published_md5': 'edfc80787bd9efb90ea6c259de14d70f'},
    {'filename': 'hg19ToHg38.over.chain.gz', 'size_bytes': 227698,
     'url': 'https://hgdownload.soe.ucsc.edu/goldenPath/hg19/liftOver/hg19ToHg38.over.chain.gz',
     'published_md5': None},
]
METADATA_SHA = '22bbbcba0b4108b2be3c9cfc871a5655f77f2d5be273e88c6bf03d52b511cb4b'


def history_guard(directory):
    return source.dataset_history_guard(directory)


def response_for(entry, method, ledger, reader, opener):
    if entry['url'] not in {asset['url'] for asset in ASSETS} or method not in ('GET', 'HEAD'):
        raise source.common.FetchError('mapping_asset_url_not_allowed')
    ledger.data['http_exchanges'] += 1
    ledger.save()
    response = opener.open(urllib.request.Request(entry['url'], method=method,
        headers={'Accept-Encoding': 'identity', 'User-Agent': 'BioZero-SCI02-mapping-inputs/1'}),
        timeout=min(30, reader.remaining()))
    if response.geturl() != entry['url'] or response.headers.get('Content-Encoding', 'identity').lower() != 'identity':
        response.close()
        raise source.common.FetchError('mapping_asset_redirect_or_encoding')
    length = response.headers.get('Content-Length')
    if length is not None and length != str(entry['size_bytes']):
        response.close()
        raise source.common.FetchError('mapping_asset_declared_size_mismatch')
    return response


def entry_receipt(entry, raw, status):
    if len(raw) != entry['size_bytes'] or not raw.startswith(b'\x1f\x8b'):
        raise source.common.FetchError('mapping_asset_size_or_magic_mismatch')
    md5 = hashlib.md5(raw).hexdigest()
    if entry['published_md5'] is not None and md5 != entry['published_md5']:
        raise source.common.FetchError('mapping_asset_publisher_digest_mismatch')
    return {'filename': entry['filename'], 'source_url': entry['url'], 'status': status,
            'size_bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'publisher_md5': entry['published_md5'], 'publisher_digest_verified': entry['published_md5'] is not None,
            'pin_scope': 'publisher size/MD5 plus local SHA' if entry['published_md5'] else 'official URL/size plus local SHA; publisher digest unavailable'}


def acquire_entry(entry, directory, ledger, reader, opener, fetch):
    target = directory / entry['filename']
    if target.is_symlink():
        raise source.common.FetchError('mapping_asset_destination_symlink')
    if target.exists():
        raw = source.private_read(target, entry['size_bytes'])
        receipt = entry_receipt(entry, raw, 'verified_cached')
        matches = [a for a in ledger.data['attempts'] if a.get('kind') == 'mapping_asset'
                   and a.get('filename') == entry['filename'] and a.get('source_url') == entry['url']
                   and a.get('size_bytes') == entry['size_bytes'] and a.get('sha256') == receipt['sha256']]
        if not matches:
            raise source.common.FetchError('mapping_asset_cached_pin_missing')
        return receipt
    if not fetch:
        raise source.common.FetchError('mapping_asset_missing_explicit_fetch_required')
    attempt = {'kind': 'mapping_asset', 'filename': entry['filename'], 'source_url': entry['url'],
               'status': 'started', 'started_unix': time.time(),
               'charged_at_start': ledger.data['charged_bytes'], 'body_at_start': ledger.data['body_bytes_observed']}
    ledger.data['attempts'].append(attempt)
    ledger.save()
    try:
        with response_for(entry, 'HEAD', ledger, reader, opener):
            pass
        with response_for(entry, 'GET', ledger, reader, opener) as response:
            if response.headers.get_content_type() == 'text/html':
                raise source.common.FetchError('mapping_asset_html_response')
            raw = bytearray()
            while len(raw) <= entry['size_bytes']:
                block = reader.read(response, min(1 << 20, entry['size_bytes'] + 1 - len(raw)))
                if not block:
                    break
                raw.extend(block)
                if len(raw) > entry['size_bytes']:
                    raise source.common.FetchError('mapping_asset_actual_size_exceeded')
        receipt = entry_receipt(entry, raw, 'verified')
        # Record the exact pin before publishing; a publication failure cannot
        # turn later cache recovery into a new uncharged/unpinned baseline.
        attempt.update(status='verified_bytes', size_bytes=len(raw), sha256=receipt['sha256'],
                       charged_at_end=ledger.data['charged_bytes'], body_at_end=ledger.data['body_bytes_observed'])
        ledger.save()
        source.publish_private(directory, entry['filename'], raw)
        attempt.update(status='verified', finished_unix=time.time())
        ledger.save()
        return receipt
    except BaseException:
        attempt.update(status='failed_or_interrupted', charged_at_end=ledger.data['charged_bytes'],
                       body_at_end=ledger.data['body_bytes_observed'])
        ledger.save()
        raise


def acquire(prefix, fetch=False):
    directory = Path(prefix).absolute() / 'datasets'
    if any(p.is_symlink() for p in (directory, *directory.parents)):
        raise source.common.FetchError('mapping_asset_prefix_symlink')
    # This is an extension of acquired source history, not an installer that
    # silently creates a new ledger over old data or invents publisher metadata.
    if not (directory / 'transfer-ledger.json').is_file():
        raise source.common.FetchError('mapping_asset_existing_dataset_ledger_required')
    for name in ('transfer-ledger.json', 'transfer-ledger.lock'):
        if (directory / name).is_symlink():
            raise source.common.FetchError('mapping_asset_ledger_symlink')
    history_guard(directory)
    metadata_raw = source.private_read(directory / 'zenodo-1405945-metadata.json', 131072)
    if hashlib.sha256(metadata_raw).hexdigest() != METADATA_SHA:
        raise source.common.FetchError('mapping_asset_primary_metadata_pin_mismatch')
    metadata = json.loads(metadata_raw)
    if (metadata.get('id') != 1405945 or metadata['metadata'].get('access_right') != 'open'
            or metadata['metadata']['license'].get('id') != 'cc-by-4.0'):
        raise source.common.FetchError('mapping_asset_source_permission_unverified')
    peak = next((e for e in metadata['files'] if e['key'] == 'peaks.bed.gz'), {})
    if peak.get('size') != ASSETS[0]['size_bytes'] or peak.get('checksum') != 'md5:' + ASSETS[0]['published_md5']:
        raise source.common.FetchError('mapping_asset_primary_catalog_mismatch')
    opener = urllib.request.build_opener(source.NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    with source.common.TransferLedger(directory, source.LIMIT) as ledger:
        guarded = history_guard(directory)
        if json.dumps(ledger.data, sort_keys=True) != json.dumps(guarded, sort_keys=True):
            raise source.common.FetchError('mapping_asset_ledger_changed_before_lock')
        source.seed_control_charge(ledger)
        reader = source.common.DownloadClient(ledger, time.monotonic() + 180, opener=opener)
        with source.common.deadline_alarm(180):
            files = [acquire_entry(e, directory, ledger, reader, opener, fetch) for e in ASSETS]
        return {'schema_version': 1, 'status': 'mapping_inputs_acquired_and_pinned', 'files': files,
                'dataset_transfer_limit_bytes': source.LIMIT,
                'dataset_transfer_charged_bytes': ledger.data['charged_bytes'],
                'dataset_http_exchanges': ledger.data['http_exchanges'],
                'license_basis': {'peaks': 'https://zenodo.org/records/1405945',
                                  'chain': 'https://hgdownload.soe.ucsc.edu/downloads.html#terms'},
                'scope': 'Acquisition pins only; no complete gzip validation, peak mapping, reference retrieval, selection or inference.',
                'biological_loci_inferred': 0, 'raw_assets_published': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prefix', type=Path, required=True)
    parser.add_argument('--fetch', action='store_true')
    args = parser.parse_args()
    try:
        report = acquire(args.prefix, args.fetch)
    except Exception as exc:
        print(json.dumps({'status': 'failed', 'error_type': type(exc).__name__,
                          'error_code': str(exc) if isinstance(exc, source.common.FetchError) else 'mapping_asset_acquisition_failed',
                          'biological_loci_inferred': 0}))
        return 1
    print(json.dumps(report, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
