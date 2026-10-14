#!/usr/bin/env python3
"""Create private, fresh reviewer configuration for the local synthetic demo."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
from urllib.parse import urlsplit


def prepare(destination, origin):
    url = urlsplit(origin)
    if (url.scheme != 'https' or url.hostname not in ('localhost', '127.0.0.1')
            or url.username or url.password or url.path or url.query or url.fragment):
        raise ValueError('Use an HTTPS loopback origin, e.g. https://localhost:8083')
    # Atomic mkdir refuses replacement, including symlinks, to preserve invitation codes.
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    reviewers, invitations = [], []
    for suffix in ('a', 'b'):
        identity = 'reviewer-' + suffix
        principal = 'researcher-' + suffix
        code = secrets.token_urlsafe(32)
        reviewers.append(dict(id=identity, principal=principal,
                              cert='/pki/' + principal + '.crt',
                              key='/pki/' + principal + '.key',
                              access_code_sha256=hashlib.sha256(code.encode()).hexdigest(),
                              enabled=True))
        invitations.append(dict(id=identity, access_code=code, origin=origin))
    config = dict(listen_address=':8083', public_origin=origin,
                  tls_cert='/pki/server.crt', tls_key='/pki/server.key',
                  allow_insecure_loopback=False, upload_url='https://upload-api:8081/upload',
                  results_url='https://results-api:8082/results', ca_cert='/pki/ca.crt',
                  encryption_cert='/pki/decrypt.crt', signing_key='/pki/signer.key',
                  run_registry_path='/state/runs.json', ui_dir='/ui',
                  reviewers=reviewers, experiments=[
                      dict(id='variant-smoke', label='Three known synthetic SNPs',
                           file='/fixtures/reads.fastq', reference='/fixtures/reference.fa', scope='synthetic'),
                      dict(id='invalid-fastq', label='Synthetic malformed FASTQ failure',
                           file='/fixtures/invalid.fastq', reference='/fixtures/reference.fa', scope='synthetic')])
    for name, contents in (('config.json', config), ('invitations.json', invitations)):
        fd = os.open(str(destination / name), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump(contents, stream, indent=2)
            stream.write('\n')
    return destination


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--origin', default='https://localhost:8083')
    args = parser.parse_args()
    try:
        prepare(args.out, args.origin)
    except (ValueError, OSError) as exc:
        parser.exit(1, 'Reviewer setup refused: ' + str(exc) + '\n')
    print('Private reviewer configuration created. Invitations remain in invitations.json; do not publish them.')
