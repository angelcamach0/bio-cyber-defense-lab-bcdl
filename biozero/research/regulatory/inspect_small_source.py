#!/usr/bin/env python3
"""Offline descriptive structure of the pinned caQTL file; never normalizes or infers."""
import argparse
import collections
import csv
import gzip
import hashlib
import json
import math
import os
from pathlib import Path
import resource
import stat
import time

SOURCE_SHA = 'b7a1e169153eff1fbf700270260bc7225f0c4585b1066ab2e2a65583c33a5d2e'
COLUMNS = ['Peak', 'Chr', 'Pos', 'RsID', 'Ref', 'Alt', 'AF', 'Inside_Peak', 'P_Lead', 'Beta', 'SE', 'Log10_BF']
MAX_EXPANDED = 512 << 20


def inspect(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    started = time.monotonic()
    inside, errors, peaks = collections.Counter(), collections.Counter(), collections.Counter()
    loci = collections.defaultdict(set)
    rows = expanded = snvs = finite = positive_se = 0
    with os.fdopen(descriptor, 'rb') as source:
        info = os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size != 10497915):
            raise ValueError('source_file_unsafe_or_size_changed')
        digest = hashlib.sha256()
        for block in iter(lambda: source.read(1 << 20), b''):
            digest.update(block)
        if digest.hexdigest() != SOURCE_SHA:
            raise ValueError('source_pin_changed')
        source.seek(0)
        with gzip.GzipFile(fileobj=source, mode='rb') as stream:
            header = stream.readline(8193)
            expanded += len(header)
            if header.decode('ascii').rstrip('\r\n').split('\t') != COLUMNS:
                raise ValueError('source_schema_changed')
            while True:
                raw = stream.readline(8193)
                if not raw:
                    break
                expanded += len(raw)
                if len(raw) > 8192 or expanded > MAX_EXPANDED:
                    raise ValueError('source_expansion_limit')
                fields = next(csv.reader([raw.decode('ascii').rstrip('\r\n')], delimiter='\t'))
                rows += 1
                if len(fields) != len(COLUMNS):
                    errors['column_count'] += 1
                    continue
                peak, chrom, pos, _, ref, alt, _, local, _, beta, se, _ = fields
                if local not in {'0', '1', '2'}:
                    errors['unexpected_inside_peak'] += 1
                else:
                    inside[local] += 1
                peaks[peak] += 1
                try:
                    position = int(pos)
                    if position < 1:
                        errors['position_nonpositive'] += 1
                    loci[(chrom, position, ref, alt)].add(peak)
                except ValueError:
                    errors['position_type'] += 1
                snvs += int(len(ref) == len(alt) == 1 and ref in 'ACGT' and alt in 'ACGT' and ref != alt)
                try:
                    b, s = float(beta), float(se)
                    finite += int(math.isfinite(b) and math.isfinite(s))
                    positive_se += int(math.isfinite(s) and s > 0)
                except ValueError:
                    errors['effect_numeric'] += 1
    return {'schema_version': 1, 'status': 'source_structure_inspected', 'source_sha256': SOURCE_SHA,
            'actual_header_columns': COLUMNS, 'gzip_complete_crc_read': True,
            'expanded_bytes': expanded, 'expanded_read_limit_bytes': MAX_EXPANDED,
            'rows_read': rows, 'column_or_type_errors': dict(errors), 'inside_peak_values': dict(inside),
            'unique_loci': len(loci), 'loci_with_multiple_peak_ids': sum(len(p) > 1 for p in loci.values()),
            'unique_peaks': len(peaks), 'peaks_with_multiple_lead_rows': sum(n > 1 for n in peaks.values()),
            'technical_biallelic_snv_rows': snvs, 'finite_beta_and_se_rows': finite,
            'positive_se_rows': positive_se, 'elapsed_seconds': round(time.monotonic()-started, 4),
            'self_max_rss_kib': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            'interpretation': 'Descriptive structure only; no genome REF, liftover, peak correspondence, context, selection, normalization or model predictions verified.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    args = parser.parse_args()
    try:
        report = inspect(args.source)
    except (OSError, ValueError, EOFError) as exc:
        print(json.dumps({'status': 'failed', 'error_type': type(exc).__name__, 'biological_loci_inferred': 0}))
        return 1
    print(json.dumps(report, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
