#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Acquire references for an already frozen prepool; produce an unapproved pool.

Default mode uses cached responses only. --fetch permits the finite planned
requests through verified HTTPS; no model is loaded and failed slots never refill.
All DNA, source rows and case outcomes stay in private research storage.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import ssl
import time
import urllib.request

import biological_adapter as adapter
import kumasaka_normalization as preparation
import lift_chain
import mapping_assets
import reference_normalization
import reference_windows
import small_dataset_fetch as source

SOURCE_SHA = 'b7a1e169153eff1fbf700270260bc7225f0c4585b1066ab2e2a65583c33a5d2e'
PEAKS_SHA = '1c626aea07016c98fac06dd413fa6cb75df1b035a8bb867785eb0e17ca267885'
CHAIN_SHA = '5c0598e500ceb5a78c73086929e8ef993aec309bcafb595139b53d440b125a1d'
DEADLINE_SECONDS = 900


def immutable_document(directory, filename, value):
    raw=preparation.canonical_bytes(value)
    if len(raw)>adapter.MAX_LEDGER_BYTES:
        raise adapter.AdapterError('reference_pool_document_size_exceeded')
    path=directory/filename
    if path.exists() or path.is_symlink():
        if source.private_read(path,adapter.MAX_LEDGER_BYTES)!=raw:
            raise adapter.AdapterError('reference_pool_existing_document_differs')
    else:
        source.publish_private(directory,filename,raw)
    return hashlib.sha256(raw).hexdigest()


def checked_freeze(raw,expected_sha):
    if not adapter.is_sha(expected_sha) or hashlib.sha256(raw).hexdigest()!=expected_sha:
        raise adapter.AdapterError('reference_prepool_sha_mismatch')
    frozen=source.strict_json(raw)
    if (type(frozen) is not dict or not adapter.exact_json_equal(frozen.get('schema_version'),1)
            or frozen.get('status')!='precandidates_frozen_awaiting_references'):
        raise adapter.AdapterError('reference_prepool_not_ready')
    if preparation.canonical_bytes(frozen)!=raw:
        raise adapter.AdapterError('reference_prepool_not_canonical')
    inputs=frozen.get('inputs',{})
    if type(inputs) is not dict or any(type(inputs.get(k)) is not dict or inputs[k].get('sha256')!=sha
           for k,sha in (('source',SOURCE_SHA),('peaks',PEAKS_SHA),('chain',CHAIN_SHA))):
        raise adapter.AdapterError('reference_prepool_inputs_mismatch')
    policy=frozen.get('policy',{})
    expected={'domain':preparation.PREPOOL_DOMAIN,'seed':preparation.PROTOCOL_SEED,
              'maximum_precandidates':256,'chromosomes':['chr8','chr9'],
              'replenishment':False,'references_checked':False,'final_selection_produced':False}
    if type(policy) is not dict or any(not adapter.exact_json_equal(policy.get(k),v) for k,v in expected.items()):
        raise adapter.AdapterError('reference_prepool_policy_mismatch')
    for key,module in (('producer_sha256',preparation),('lift_chain_sha256',lift_chain)):
        if frozen.get(key)!=hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest():
            raise adapter.AdapterError('reference_prepool_producer_changed')
    candidates=frozen.get('precandidates')
    if type(candidates) is not list or not 110<=len(candidates)<=256:
        raise adapter.AdapterError('reference_prepool_cardinality_invalid')
    if any(type(c) is not dict or not adapter.text(c.get('candidate_id')) or not adapter.text(c.get('origin_row_id'))
           for c in candidates):
        raise adapter.AdapterError('reference_prepool_identity_invalid')
    if len({c['candidate_id'] for c in candidates})!=len(candidates) or len({c['origin_row_id'] for c in candidates})!=len(candidates):
        raise adapter.AdapterError('reference_prepool_duplicate_identity')
    if any(c.get('prepool_rank_sha256')!=preparation.prepool_rank(c,SOURCE_SHA) for c in candidates):
        raise adapter.AdapterError('reference_prepool_rank_mismatch')
    if candidates!=sorted(candidates,key=lambda c:(c['prepool_rank_sha256'],c['origin_row_id'])):
        raise adapter.AdapterError('reference_prepool_order_invalid')
    return frozen


def reference_plan(frozen,sha):
    requests=[]
    for candidate in frozen['precandidates']:
        if any(type(candidate.get(k)) is not int for k in ('source_position_1based','mapped_position_1based')):
            raise adapter.AdapterError('reference_prepool_position_invalid')
        source_q=candidate['source_position_1based']-1;target_q=candidate['mapped_position_1based']-1
        request={'candidate_id':candidate['candidate_id']}
        for kind,args in (('source',('hg19',candidate['source_chrom'],source_q,source_q+1)),
                          ('target',('hg38',candidate['mapped_chrom'],target_q-2048,target_q+2048))):
            try:
                request[kind]=reference_windows.request_spec(*args)
            except source.common.FetchError as exc:
                request[kind]={'status':'invalid_request','reason':str(exc)}
        requests.append(request)
    modules=(reference_windows,reference_normalization)
    return {'schema_version':1,'prepool_sha256':sha,'protocol_sha256':adapter.PROTOCOL_SHA256,
            'frozen_before_requests':True,'maximum_requests':2*len(requests),'requests':requests,
            'replenishment':False,'automatic_retries':False,'deadline_seconds':DEADLINE_SECONDS,
            'maximum_response_bytes':reference_windows.MAX_RESPONSE_BYTES,
            'minimum_request_spacing_seconds':1,'api_conditions_url':'https://genome.ucsc.edu/goldenPath/help/api.html',
            'implementation_sha256':{Path(m.__file__).name:hashlib.sha256(Path(m.__file__).read_bytes()).hexdigest()
                                     for m in modules},
            'orchestrator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}


def process_candidates(frozen,sha,client,*,fetch):
    outcomes=[];cases=[];stop_code=None
    for candidate in frozen['precandidates']:
        outcome={'candidate_id':candidate['candidate_id'],'origin_row_id':candidate['origin_row_id'],
                 'status':'pending','reasons':[],'reference_outcomes':{}}
        case={'case_id':candidate['candidate_id'],'origin_row_id':candidate['origin_row_id'],
              'genome_build':'hg38','chrom':candidate['mapped_chrom'],
              'position_1based':candidate['mapped_position_1based'],
              'ref':candidate['oriented_source_ref'],'alt':candidate['oriented_source_alt'],
              'window':None,'effect':None}
        receipts={}
        for kind in ('source','target'):
            if stop_code:
                outcome['reference_outcomes'][kind]={'status':'unattempted','reason':stop_code}
                continue
            q=candidate['source_position_1based']-1 if kind=='source' else candidate['mapped_position_1based']-1
            args=('hg19',candidate['source_chrom'],q,q+1) if kind=='source' else ('hg38',candidate['mapped_chrom'],q-2048,q+2048)
            try:
                receipt=client.acquire(*args,fetch=fetch)
                receipts[kind]=receipt
                outcome['reference_outcomes'][kind]={'status':receipt['status'],'receipt':receipt}
            except Exception as exc:
                code=str(exc) if isinstance(exc,(source.common.FetchError,adapter.AdapterError)) else 'reference_io_failed'
                outcome['reference_outcomes'][kind]={'status':'unavailable','reason':code}
                outcome['reasons'].append(kind+':'+code)
                if (code in ('reference_access_denied','reference_html_response','reference_redirect_or_encoding')
                        or 'deadline' in code or 'budget exhausted' in code
                        or code in ('reference_ledger_changed_under_lock','reference_io_failed')):
                    stop_code=code
        if len(receipts)==2:
            try:
                case=reference_normalization.normalize_precandidate(candidate,receipts['source'],receipts['target'],prepool_sha256=sha)
                outcome['status']='normalized'
            except (adapter.AdapterError,source.common.FetchError) as exc:
                outcome.update(status='rejected',reasons=[str(exc)])
        elif not outcome['reasons']:
            outcome['reasons']=[stop_code or 'reference_receipts_incomplete']
        cases.append(case);outcomes.append(outcome)
    return {'cases':cases,'outcomes':outcomes,'stop_code':stop_code,
            'counts':dict(sorted(Counter(o['status'] for o in outcomes).items()))}


def bind_prospective_plan(directory,ledger,plan,prepool_sha256):
    """The caller holds the ledger flock across this check and all acquisitions."""
    sha=hashlib.sha256(preparation.canonical_bytes(plan)).hexdigest()
    filename='kumasaka-reference-plan-'+prepool_sha256+'.json'
    path=directory/filename
    specs=[r[k] for r in plan['requests'] for k in ('source','target') if 'source_url' in r[k]]
    urls={s['source_url'] for s in specs}
    previous=[a for a in ledger.data['attempts'] if a.get('kind')=='reference_window' and a.get('source_url') in urls]
    if not path.exists() and not path.is_symlink():
        if previous or any((directory/s['filename']).exists() or (directory/s['filename']).is_symlink() for s in specs):
            raise adapter.AdapterError('reference_plan_not_prospective_requires_review')
    elif any(a.get('reference_plan_sha256')!=sha for a in previous):
        raise adapter.AdapterError('reference_previous_attempt_plan_mismatch')
    return immutable_document(directory,filename,plan)


def prepare(prefix,prepool_sha256,*,fetch=False):
    if type(fetch) is not bool:
        raise adapter.AdapterError('reference_explicit_fetch_flag_invalid')
    directory=Path(prefix).absolute()/'datasets'
    if any(p.is_symlink() for p in (directory,*directory.parents)):
        raise adapter.AdapterError('reference_prefix_symlink')
    filename='kumasaka-prepool-'+prepool_sha256+'.json' if adapter.is_sha(prepool_sha256) else ''
    if not filename:
        raise adapter.AdapterError('reference_prepool_sha_invalid')
    frozen=checked_freeze(source.private_read(directory/filename,adapter.MAX_LEDGER_BYTES),prepool_sha256)
    # These existing-source verifiers run cached-only; they never initialize a
    # new ledger over missing history or silently reacquire an absent source.
    source.acquire(prefix,False)
    mapping_assets.acquire(prefix,False)
    plan=reference_plan(frozen,prepool_sha256)
    opener=urllib.request.build_opener(source.NoRedirect(),urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    with source.common.TransferLedger(directory,source.LIMIT) as ledger:
        source.seed_control_charge(ledger)
        guarded=source.dataset_history_guard(directory)
        if json.dumps(guarded,sort_keys=True)!=json.dumps(ledger.data,sort_keys=True):
            raise adapter.AdapterError('reference_ledger_changed_before_lock')
        plan_sha=bind_prospective_plan(directory,ledger,plan,prepool_sha256)
        reader=source.common.DownloadClient(ledger,time.monotonic()+DEADLINE_SECONDS,opener=opener)
        client=reference_windows.SequenceClient(directory,ledger,reader,opener,reference_plan_sha256=plan_sha)
        with source.common.deadline_alarm(DEADLINE_SECONDS):
            processed=process_candidates(frozen,prepool_sha256,client,fetch=fetch)
        document={'schema_version':1,'dataset_sha256':SOURCE_SHA,'protocol_sha256':adapter.PROTOCOL_SHA256,
                  'prepool_sha256':prepool_sha256,'reference_plan_sha256':plan_sha,
                  'status':'normalized_reference_pool_pending_review','scientific_review_approved':False,
                  'source_context':'GBR100 population LCL; descriptive transfer to fixed GM12878 ATAC tracks',
                  'rank64_verified_heldout':False,'biological_loci_inferred':0,**processed}
        raw=preparation.canonical_bytes(document);sha=hashlib.sha256(raw).hexdigest()
        output='kumasaka-reference-pool-'+sha+'.json'
        immutable_document(directory,output,document)
        return {'status':document['status'],'prepool_sha256':prepool_sha256,'reference_plan_sha256':plan_sha,
                'pool_filename':output,'pool_sha256':sha,'pool_bytes':len(raw),'counts':processed['counts'],
                'submitted_precandidates':len(frozen['precandidates']),'stop_code':processed['stop_code'],
                'dataset_transfer_charged_bytes':ledger.data['charged_bytes'],
                'dataset_http_exchanges':ledger.data['http_exchanges'],'biological_loci_inferred':0,
                'scientific_review_approved':False,'raw_dna_published':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prefix',type=Path,required=True)
    parser.add_argument('--prepool-sha256',required=True)
    parser.add_argument('--fetch',action='store_true')
    args=parser.parse_args()
    try:
        report=prepare(args.prefix,args.prepool_sha256,fetch=args.fetch)
    except Exception as exc:
        report={'status':'failed','error_code':str(exc) if isinstance(exc,(adapter.AdapterError,source.common.FetchError))
                else 'reference_pool_preparation_failed','biological_loci_inferred':0}
        print(json.dumps(report));return 1
    print(json.dumps(report,indent=2));return 0


if __name__=='__main__':
    raise SystemExit(main())
