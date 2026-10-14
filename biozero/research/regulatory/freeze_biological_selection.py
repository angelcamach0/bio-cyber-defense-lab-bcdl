#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Freeze final 10+100 inputs only with an independently approved input review.

Creates private normalization, selection and case ledgers. No predictions,
automatic review approval or replacements after the freeze are performed.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path

import biological_adapter as adapter
import kumasaka_normalization as preparation
import prepare_reference_pool as references
import small_dataset_fetch as source

DATASET_ID='kumasaka2018-zenodo1405945-focal-caqtl'
DATASET_VERSION='GRCh37-to-hg38-chr8-chr9-fixed-prepool-v1'


def checked_review(review,pool,pool_sha256):
    expected={'schema_version':1,'review_status':'approved',
              'scope':'source_and_reference_input_review_only','dataset_sha256':references.SOURCE_SHA,
              'reference_pool_sha256':pool_sha256,'prepool_sha256':pool.get('prepool_sha256'),
              'protocol_sha256':adapter.PROTOCOL_SHA256,'permission_scope':'internal_research',
              'reviewed_before_predictions':True,'license_verified':True,'schema_verified':True,
              'effect_orientation_verified':True,'source_ref_verified':True,'target_window_verified':True,
              'fixed_prepool_verified':True,'all_precandidate_outcomes_accounted':True,
              'biological_accuracy_approved':False,'rank64_verified_heldout':False}
    if type(review) is not dict or any(not adapter.exact_json_equal(review.get(k),v) for k,v in expected.items()):
        raise adapter.AdapterError('reference_input_review_mismatch')
    if not all(adapter.text(review.get(k)) for k in ('reviewed_by','reviewed_at_utc')):
        raise adapter.AdapterError('reference_input_review_incomplete')
    return review


def build_documents(pool,pool_sha256,review,review_sha256,*,frozen_prepool):
    checked_review(review,pool,pool_sha256)
    expected={'schema_version':1,'dataset_sha256':references.SOURCE_SHA,
              'protocol_sha256':adapter.PROTOCOL_SHA256,'biological_loci_inferred':0,
              'scientific_review_approved':False,'status':'normalized_reference_pool_pending_review'}
    if type(pool) is not dict or any(not adapter.exact_json_equal(pool.get(k),v) for k,v in expected.items()):
        raise adapter.AdapterError('reference_pool_identity_mismatch')
    cases=pool.get('cases');outcomes=pool.get('outcomes')
    if (type(cases) is not list or type(outcomes) is not list or len(cases)!=len(outcomes)
            or not 110<=len(cases)<=256 or not adapter.is_sha(review_sha256)
            or not adapter.is_sha(pool.get('prepool_sha256'))):
        raise adapter.AdapterError('reference_pool_outcome_cardinality_invalid')
    if (type(frozen_prepool) is not dict
            or hashlib.sha256(preparation.canonical_bytes(frozen_prepool)).hexdigest()!=pool['prepool_sha256']
            or type(frozen_prepool.get('precandidates')) is not list
            or len(frozen_prepool['precandidates'])!=len(cases)):
        raise adapter.AdapterError('reference_pool_frozen_denominator_mismatch')
    for candidate,case,outcome in zip(frozen_prepool['precandidates'],cases,outcomes):
        if (type(candidate) is not dict or type(case) is not dict or type(outcome) is not dict
                or any(not adapter.exact_json_equal(case.get(k),candidate.get(v))
                       for k,v in (('case_id','candidate_id'),('origin_row_id','origin_row_id'),
                                   ('chrom','mapped_chrom'),('position_1based','mapped_position_1based')))
                or not adapter.exact_json_equal(outcome.get('candidate_id'),candidate.get('candidate_id'))
                or not adapter.exact_json_equal(outcome.get('origin_row_id'),candidate.get('origin_row_id'))):
            raise adapter.AdapterError('reference_pool_frozen_slot_mismatch')
    for case,outcome in zip(cases,outcomes):
        if (type(case) is not dict or type(outcome) is not dict
                or case.get('case_id')!=outcome.get('candidate_id')
                or case.get('origin_row_id')!=outcome.get('origin_row_id')
                or case.get('chrom') not in ('chr8','chr9')
                or outcome.get('status') not in ('normalized','rejected','pending')):
            raise adapter.AdapterError('reference_pool_outcome_identity_mismatch')
        valid=adapter.case_record(case,0,True)['status']=='validated'
        if valid != (outcome['status']=='normalized'):
            raise adapter.AdapterError('reference_pool_outcome_validation_mismatch')
    selected,records=adapter.deterministic_selection(cases,preparation.PROTOCOL_SEED)
    if len(selected)!=110:
        raise adapter.AdapterError('selection_requires_110_disjoint_windows')
    normalization={'schema_version':1,'dataset_sha256':references.SOURCE_SHA,
                   'protocol_sha256':adapter.PROTOCOL_SHA256,'reference_pool_sha256':pool_sha256,
                   'input_review_sha256':review_sha256,'prepool_sha256':pool['prepool_sha256'],
                   'normalization':{'reviewed_before_predictions':True,
                       'schema_definition':'Pinned Kumasaka lead/peak source; unique focal SNP/full ungapped peak, source hg19 REF and target hg38 forward 4096 window verified.',
                       'filters':'Fixed source-only chr8/9 eligibility/tie exclusions and prospective first256 prepool; all slots accounted; technical reference/allele/window checks; no prediction/effect-value selection or replenishment.',
                       'orientation_definition':'Complement E/O without source-Beta negation on minus mapping; target REF/ALT swap handled once by explicit oriented E/O. Preserve SE and source AF; no invented CI.'},
                   'cases':cases,'reference_outcomes':outcomes,'selection_pool_outcomes':records,
                   'source_context':'GBR100 population LCL; descriptive transfer to fixed GM12878 ATAC tracks',
                   'rank64_verified_heldout':False,'biological_loci_inferred':0}
    normalization_sha=hashlib.sha256(preparation.canonical_bytes(normalization)).hexdigest()
    frozen={'schema_version':1,'dataset_sha256':references.SOURCE_SHA,
            'protocol_sha256':adapter.PROTOCOL_SHA256,'normalization_sha256':normalization_sha,
            'prepool_sha256':pool['prepool_sha256'],'frozen_before_predictions':True,
            'selected':selected,'allocation':'first10_adapter_next100_evaluation','replacements_allowed':False}
    selection_sha=hashlib.sha256(preparation.canonical_bytes(frozen)).hexdigest()
    verification={'schema_version':1,'dataset_id':DATASET_ID,'dataset_version':DATASET_VERSION,
                  'dataset_sha256':references.SOURCE_SHA,'review_status':'approved',
                  'permission_scope':'internal_research','schema_verified':True,
                  'effect_orientation_verified':True,'license_verified':True,
                  'normalization_sha256':normalization_sha,'reviewed_by':review['reviewed_by'],
                  'license_source_url':'https://zenodo.org/records/1405945',
                  'effect_source_url':preparation.EFFECT_SOURCE_URL,'input_review_sha256':review_sha256,
                  'scope':'Input review only; no causal, clinical or accuracy approval.',
                  'biological_accuracy_approved':False}
    verification_sha=hashlib.sha256(preparation.canonical_bytes(verification)).hexdigest()
    names={'normalization':'kumasaka-normalization-'+normalization_sha+'.json',
           'selection':'kumasaka-selection-'+selection_sha+'.json',
           'verification':'kumasaka-verification-'+verification_sha+'.json'}
    dataset={'id':DATASET_ID,'version':DATASET_VERSION,'sha256':references.SOURCE_SHA,'kind':'biological',
             'source_path':'lead_caQTL_variants.tsv.gz','source_url':'https://zenodo.org/records/1405945',
             'permission':{'status':'authorized','scope':'internal_research','basis':'Verified public CC-BY-4.0 source metadata; input-only independent review.'},
             'schema_definition':normalization['normalization']['schema_definition'],
             'verification_receipt_path':'datasets/'+names['verification'],'verification_receipt_sha256':verification_sha}
    split={'frozen':True,'selection_id':'kumasaka-'+selection_sha,
           'selection_rule':'Prospective first256 then existing fixed SCI02 final rank; first10+next100 complete disjoint windows; no replacements.',
           'adapter_loci':selected[:10],'evaluation_loci':selected[10:],
           'source_normalization_ledger_path':names['normalization'],'source_normalization_ledger_sha256':normalization_sha,
           'frozen_selection_path':names['selection'],'frozen_selection_sha256':selection_sha,
           'original_sei_partition':'chr8_chr9_test','rank64_verified_heldout':False}
    by_id={c['case_id']:c for c in cases if type(c) is dict and adapter.text(c.get('case_id'))}
    ledgers={}
    for phase,slots in (('adapter',selected[:10]),('evaluation',selected[10:])):
        ledgers[phase]={'schema_version':1,'protocol_id':adapter.PROTOCOL_ID,'phase':phase,
                        'dataset':copy.deepcopy(dataset),'split_metadata':copy.deepcopy(split),
                        'cases':[by_id[d['case_id']] for d in slots]}
    return {'normalization':normalization,'selection':frozen,'verification':verification,
            'ledgers':ledgers,'names':names,'selection_sha256':selection_sha,
            'normalization_sha256':normalization_sha,'verification_sha256':verification_sha}


def prepare(prefix,pool_sha256,review_path,review_sha256):
    directory=Path(prefix).absolute()/'datasets'
    if any(p.is_symlink() for p in (directory,*directory.parents)):
        raise adapter.AdapterError('selection_prefix_symlink')
    if not adapter.is_sha(pool_sha256) or not adapter.is_sha(review_sha256):
        raise adapter.AdapterError('selection_input_sha_invalid')
    raw=source.private_read(directory/('kumasaka-reference-pool-'+pool_sha256+'.json'),adapter.MAX_LEDGER_BYTES)
    if hashlib.sha256(raw).hexdigest()!=pool_sha256:
        raise adapter.AdapterError('selection_reference_pool_sha_mismatch')
    review_raw=source.private_read(Path(review_path),16384)
    if hashlib.sha256(review_raw).hexdigest()!=review_sha256:
        raise adapter.AdapterError('selection_reference_review_sha_mismatch')
    pool=source.strict_json(raw);review=source.strict_json(review_raw)
    prepool_sha=pool.get('prepool_sha256') if type(pool) is dict else None
    if not adapter.is_sha(prepool_sha):
        raise adapter.AdapterError('selection_prepool_sha_invalid')
    frozen_raw=source.private_read(directory/('kumasaka-prepool-'+prepool_sha+'.json'),adapter.MAX_LEDGER_BYTES)
    frozen_prepool=references.checked_freeze(frozen_raw,prepool_sha)
    adapter.load_protocol()
    adapter.private_file('lead_caQTL_variants.tsv.gz',directory,references.SOURCE_SHA)
    documents=build_documents(pool,pool_sha256,review,review_sha256,frozen_prepool=frozen_prepool)
    for key in ('normalization','selection','verification'):
        references.immutable_document(directory,documents['names'][key],documents[key])
    ledger_receipts={}
    for phase,ledger in documents['ledgers'].items():
        raw=preparation.canonical_bytes(ledger);sha=hashlib.sha256(raw).hexdigest()
        name='kumasaka-'+phase+'-ledger-'+sha+'.json'
        references.immutable_document(directory,name,ledger)
        validation=adapter.validate_ledger(ledger,prefix)
        ledger_receipts[phase]={'filename':name,'sha256':sha,'counts':validation['counts'],
                                'status':validation['status'],'ready_for_inference':validation['ready_for_inference']}
    if not ledger_receipts['adapter']['ready_for_inference']:
        raise adapter.AdapterError('frozen_adapter_validation_not_ready')
    return {'status':'final_110_inputs_frozen','selection_sha256':documents['selection_sha256'],
            'normalization_sha256':documents['normalization_sha256'],'ledgers':ledger_receipts,
            'biological_loci_inferred':0,'evaluation_requires_passed_adapter':True,
            'scientific_feasibility':'pending','raw_dna_published':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prefix',type=Path,required=True)
    parser.add_argument('--pool-sha256',required=True)
    parser.add_argument('--reference-review',type=Path,required=True)
    parser.add_argument('--review-sha256',required=True)
    args=parser.parse_args()
    try:
        report=prepare(args.prefix,args.pool_sha256,args.reference_review,args.review_sha256)
    except Exception as exc:
        print(json.dumps({'status':'failed','error_code':str(exc) if isinstance(exc,adapter.AdapterError)
                          else 'selection_preparation_failed','biological_loci_inferred':0}));return 1
    print(json.dumps(report,indent=2));return 0


if __name__=='__main__':
    raise SystemExit(main())
