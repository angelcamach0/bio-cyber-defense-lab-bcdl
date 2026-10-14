#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Prepare one pinned reference/artificial-SNV control; no measured biology.

Cached input is used by default. --fetch permits one bounded HTTPS acquisition
from the fixed public UCSC endpoint; it never fetches weights or datasets.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import urllib.request

ROOT = Path(__file__).resolve().parents[3]
URL = 'https://api.genome.ucsc.edu/getData/sequence?genome=hg38;chrom=chr1;start=1000000;end=1004096'
DNA_SHA = '99279a104d299f7fe1f147072c631b3041d0c27464dac169966a99eb5b70e439'
MAX_BYTES = 16384


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


def bounded_regular_read(path, maximum):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError('control_input_not_regular')
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError('control_source_size_limit')
    return raw


def checked_reference(raw):
    if len(raw) > MAX_BYTES:
        raise ValueError('control_source_size_limit')
    value = json.loads(raw)
    if (value.get('genome'), value.get('chrom'), value.get('start'), value.get('end')) != ('hg38', 'chr1', 1000000, 1004096):
        raise ValueError('control_source_coordinates_mismatch')
    dna = value.get('dna', '').upper()
    if len(dna) != 4096 or set(dna) - set('ACGT') or hashlib.sha256(dna.encode()).hexdigest() != DNA_SHA:
        raise ValueError('control_reference_digest_mismatch')
    return dna


def immutable_write(path, raw):
    if path.is_symlink():
        raise ValueError('control_output_symlink')
    try:
        with path.open('xb') as stream:
            stream.write(raw)
        path.chmod(0o600)
    except FileExistsError:
        if bounded_regular_read(path, len(raw)) != raw:
            raise ValueError('control_existing_output_differs') from None


def prepare(prefix, fetch=False):
    prefix = Path(prefix).resolve()
    directory = prefix / 'datasets'
    if directory.is_symlink():
        raise ValueError('control_dataset_directory_symlink')
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory.chmod(0o700)
    source = directory / 'control-ucsc-hg38-chr1.json'
    if source.is_symlink():
        raise ValueError('control_source_symlink')
    if source.exists():
        raw = bounded_regular_read(source, MAX_BYTES)
    elif fetch:
        opener = urllib.request.build_opener(NoRedirect())
        with opener.open(URL, timeout=20) as response:
            if response.geturl().split('?', 1)[0] != URL.split('?', 1)[0]:
                raise ValueError('control_unexpected_redirect')
            raw = response.read(MAX_BYTES + 1)
        checked_reference(raw)
        immutable_write(source, raw)
    else:
        raise ValueError('control_cached_source_missing_explicit_fetch_required')
    dna = checked_reference(raw)
    source_sha = hashlib.sha256(raw).hexdigest()
    ledger = {'schema_version': 1, 'protocol_id': 'SCI02-GM12878-ATAC-FP32-v1', 'phase': 'control',
              'dataset': {'id': 'ucsc-hg38-chr1-instrumentation-control',
                          'version': 'hg38-fixed-window-control-2026-10-14', 'sha256': source_sha,
                          'kind': 'instrumentation_control', 'source_path': str(source), 'source_url': URL,
                          'permission': {'status': 'authorized', 'scope': 'internal_research',
                                         'basis': 'Public UCSC reference API; no experimental subject data; public usage/citation documented by source.'},
                          'schema_definition': 'UCSC getData/sequence JSON dna converted to uppercase. A central C to G mutation is artificial and has no experimental effect.'},
              'split_metadata': {'frozen': True, 'selection_id': 'control-hg38-chr1-1000000-1004096-v1',
                                 'selection_rule': 'One fixed public window chosen before head predictions; mutate center C to G; no labels or biological selection',
                                 'adapter_loci': [], 'evaluation_loci': []},
              'cases': [{'case_id': 'ucsc-hg38-chr1-1002049-C-G-control', 'origin_row_id': 'instrumentation-window-only',
                         'genome_build': 'hg38', 'chrom': 'chr1', 'position_1based': 1002049, 'ref': 'C', 'alt': 'G',
                         'window': {'genome_build': 'hg38', 'chrom': 'chr1', 'start_zero_based': 1000000,
                                    'end_zero_based': 1004096, 'sequence': dna, 'sha256': DNA_SHA,
                                    'strand': '+', 'padding': False, 'source_url': URL,
                                    'provenance': {'source_response_sha256': source_sha, 'assembly': 'hg38',
                                                   'coordinate_convention': 'zero-based half-open'}}, 'effect': None}]}
    output = directory / 'control-case-ledger.json'
    immutable_write(output, (json.dumps(ledger, indent=2) + '\n').encode())
    return {'status': 'prepared', 'kind': 'instrumentation_control', 'ledger': str(output),
            'ledger_sha256': hashlib.sha256(output.read_bytes()).hexdigest(), 'source_bytes': len(raw),
            'reference_window_sha256': DNA_SHA, 'experimental_truth_cases': 0,
            'scientific_feasibility': 'pending', 'scope': 'Public reference with artificial ALT; not a measured caQTL.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prefix', type=Path, default=ROOT / '.biozero/regulatory-assets')
    parser.add_argument('--fetch', action='store_true')
    args = parser.parse_args()
    try:
        report = prepare(args.prefix, args.fetch)
    except (OSError, ValueError) as exc:
        print(json.dumps({'status': 'failed', 'error_type': type(exc).__name__, 'scientific_feasibility': 'pending'}))
        return 1
    print(json.dumps(report, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
