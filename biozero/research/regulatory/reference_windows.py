#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded, explicitly requested UCSC reference receipts; no model inference.

Callers freeze their complete precandidate pool before using this module. Cache
responses and all failed read reservations remain in the existing dataset budget.
There is no automatic retry, pool expansion or replacement of failed candidates.
"""
import hashlib
import json
from pathlib import Path
import time
import urllib.request
import urllib.error

import small_dataset_fetch as source

MAX_RESPONSE_BYTES = 16384
ENDPOINT = 'https://api.genome.ucsc.edu/getData/sequence'


def request_spec(genome, chrom, start, end):
    if (type(genome) is not str or genome not in ('hg19', 'hg38')
            or type(chrom) is not str or chrom not in ('chr8', 'chr9')
            or type(start) is not int or type(end) is not int or start < 0
            or end - start != (1 if genome == 'hg19' else 4096)):
        raise source.common.FetchError('reference_request_invalid')
    url = f'{ENDPOINT}?genome={genome};chrom={chrom};start={start};end={end}'
    return {'genome':genome, 'chrom':chrom, 'start':start, 'end':end, 'source_url':url,
            'filename':'reference-' + hashlib.sha256(url.encode()).hexdigest() + '.json'}


def validate_response(raw, spec):
    if len(raw) > MAX_RESPONSE_BYTES:
        raise source.common.FetchError('reference_response_size_exceeded')
    try:
        value = source.strict_json(raw)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise source.common.FetchError('reference_response_json_invalid') from exc
    if (type(value) is not dict or any(type(value.get(k)) is not type(spec[k]) or value[k] != spec[k]
                                     for k in ('genome', 'chrom', 'start', 'end'))):
        raise source.common.FetchError('reference_response_coordinates_mismatch')
    if type(value.get('dna')) is not str:
        raise source.common.FetchError('reference_response_dna_invalid')
    dna = value['dna'].upper()
    if len(dna) != spec['end'] - spec['start'] or set(dna) - set('ACGT'):
        raise source.common.FetchError('reference_response_dna_invalid')
    return {'schema_version':1, 'genome_build':spec['genome'], 'chrom':spec['chrom'],
            'start_zero_based':spec['start'], 'end_zero_based':spec['end'],
            'strand':'+', 'padding':False, 'sequence':dna,
            'sha256':hashlib.sha256(dna.encode()).hexdigest(), 'source_url':spec['source_url'],
            'source_response_sha256':hashlib.sha256(raw).hexdigest(), 'source_response_bytes':len(raw)}


class SequenceClient:
    """Sequential calls sharing the caller's ledger, deadline and TLS opener."""
    def __init__(self, directory, ledger, reader, opener, *, clock=time.monotonic, sleep=time.sleep,
                 reference_plan_sha256=None):
        self.directory = Path(directory)
        self.ledger = ledger
        self.reader = reader
        self.opener = opener
        self.clock = clock
        self.sleep = sleep
        self.last_start = None
        if reference_plan_sha256 is not None and (type(reference_plan_sha256) is not str
                or len(reference_plan_sha256)!=64
                or any(c not in '0123456789abcdef' for c in reference_plan_sha256)):
            raise source.common.FetchError('reference_plan_sha_invalid')
        self.reference_plan_sha256=reference_plan_sha256
        if self.directory.absolute() != ledger.prefix.absolute() or reader.ledger is not ledger:
            raise source.common.FetchError('reference_existing_dataset_ledger_required')

    def acquire(self, genome, chrom, start, end, *, fetch=False):
        if type(fetch) is not bool:
            raise source.common.FetchError('reference_explicit_fetch_flag_invalid')
        spec = request_spec(genome, chrom, start, end)
        if any(p.is_symlink() for p in (self.directory, *self.directory.parents)):
            raise source.common.FetchError('reference_cache_directory_symlink')
        guarded = source.dataset_history_guard(self.directory)
        if json.dumps(guarded, sort_keys=True) != json.dumps(self.ledger.data, sort_keys=True):
            raise source.common.FetchError('reference_ledger_changed_under_lock')
        target = self.directory / spec['filename']
        previous = [a for a in self.ledger.data['attempts'] if a.get('kind') == 'reference_window'
                    and a.get('source_url') == spec['source_url']]
        if target.exists() or target.is_symlink():
            raw = source.private_read(target, MAX_RESPONSE_BYTES)
            receipt = validate_response(raw, spec)
            pins = [a for a in previous if a.get('status') in ('verified', 'verified_bytes')
                    and type(a.get('size_bytes')) is int and a['size_bytes'] == len(raw)
                    and a.get('sha256') == receipt['source_response_sha256']]
            if len(pins) != 1 or len(previous) != 1:
                raise source.common.FetchError('reference_cached_pin_missing_or_ambiguous')
            if self.reference_plan_sha256 is not None and pins[0].get('reference_plan_sha256')!=self.reference_plan_sha256:
                raise source.common.FetchError('reference_cached_plan_mismatch')
            return dict(receipt, status='verified_cached')
        if previous:
            # Even verified bytes with a lost publication require explicit
            # recovery. Do not turn a lost/failed frozen slot into another GET.
            raise source.common.FetchError('reference_previous_outcome_requires_review')
        if not fetch:
            raise source.common.FetchError('reference_missing_explicit_fetch_required')
        # Waiting also on the first call preserves cadence when a new client
        # takes over the same exclusive ledger immediately after another one.
        delay = 1.0 if self.last_start is None else max(0.0, self.last_start + 1.0 - self.clock())
        if self.reader.remaining() <= delay:
            raise source.common.FetchError('reference_deadline_before_rate_limit')
        if delay:
            self.sleep(delay)
        self.reader.remaining()
        attempt = {'kind':'reference_window', 'status':'started', 'source_url':spec['source_url'],
                   'filename':spec['filename'], 'genome':genome, 'chrom':chrom, 'start':start, 'end':end,
                   'charged_at_start':self.ledger.data['charged_bytes'],
                   'body_at_start':self.ledger.data['body_bytes_observed']}
        if self.reference_plan_sha256 is not None:
            attempt['reference_plan_sha256']=self.reference_plan_sha256
        self.ledger.data['attempts'].append(attempt)
        self.ledger.data['http_exchanges'] += 1
        self.ledger.save()
        try:
            request = urllib.request.Request(spec['source_url'], method='GET', headers={
                'Accept-Encoding':'identity', 'User-Agent':'BioZero-SCI02-reference-windows/1'})
            # Record the actual opening boundary after durable accounting;
            # a slow fsync must not consume the following request's spacing.
            delay = 0.0 if self.last_start is None else max(0.0,self.last_start+1.0-self.clock())
            if self.reader.remaining() <= delay:
                raise source.common.FetchError('reference_deadline_before_rate_limit')
            if delay:
                self.sleep(delay)
            request_timeout=min(30,self.reader.remaining())
            self.last_start = self.clock()
            try:
                response = self.opener.open(request, timeout=request_timeout)
            except urllib.error.HTTPError as exc:
                # Charge bounded error bodies too; never retry or interpret
                # a login/challenge/denial page as a reference response.
                with exc:
                    self.reader.read(exc, MAX_RESPONSE_BYTES + 1)
                raise source.common.FetchError('reference_access_denied' if exc.code in (401,403,429)
                                               else 'reference_http_failure') from None
            with response:
                if (response.geturl() != spec['source_url']
                        or response.headers.get('Content-Encoding','identity').lower() != 'identity'):
                    raise source.common.FetchError('reference_redirect_or_encoding')
                length = response.headers.get('Content-Length')
                if length is not None and (not length.isdecimal() or int(length) > MAX_RESPONSE_BYTES):
                    raise source.common.FetchError('reference_declared_size_exceeded')
                if response.headers.get_content_type() == 'text/html':
                    raise source.common.FetchError('reference_html_response')
                raw = bytearray()
                while len(raw) <= MAX_RESPONSE_BYTES:
                    block = self.reader.read(response, MAX_RESPONSE_BYTES + 1 - len(raw))
                    if not block:
                        break
                    raw.extend(block)
                    if len(raw) > MAX_RESPONSE_BYTES:
                        raise source.common.FetchError('reference_response_size_exceeded')
                if length is not None and len(raw) != int(length):
                    raise source.common.FetchError('reference_actual_size_mismatch')
            receipt = validate_response(raw, spec)
            attempt.update(status='verified_bytes', size_bytes=len(raw),
                           sha256=receipt['source_response_sha256'],
                           charged_at_end=self.ledger.data['charged_bytes'],
                           body_at_end=self.ledger.data['body_bytes_observed'])
            self.ledger.save()
            source.publish_private(self.directory, spec['filename'], raw)
            attempt['status'] = 'verified'
            self.ledger.save()
            return dict(receipt, status='verified')
        except BaseException:
            attempt.update(status='failed_or_interrupted',
                           charged_at_end=self.ledger.data['charged_bytes'],
                           body_at_end=self.ledger.data['body_bytes_observed'])
            self.ledger.save()
            raise
