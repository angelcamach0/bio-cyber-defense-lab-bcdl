#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Bind a passed biological adapter report to the already frozen100 ledger.

Creates a derivative evaluation ledger without changing any case or slot. This
does not run evaluation, approve biological accuracy or replace a failed adapter.
"""
import argparse
import copy
import hashlib
import json
import math
from pathlib import Path

import biological_adapter as adapter
import kumasaka_normalization as preparation
import prepare_reference_pool as references


def bind_report(ledger,report,report_relative_path,report_sha256,adapter_ledger,adapter_sha256):
    if (type(ledger) is not dict or ledger.get('phase')!='evaluation'
            or not adapter.is_sha(report_sha256) or not adapter.is_sha(adapter_sha256)
            or type(adapter_ledger) is not dict or adapter_ledger.get('phase')!='adapter'):
        raise adapter.AdapterError('evaluation_binding_identity_invalid')
    for key in ('schema_version','protocol_id','dataset','split_metadata'):
        if not adapter.exact_json_equal(adapter_ledger.get(key),ledger.get(key)):
            raise adapter.AdapterError('adapter_parent_frozen_inputs_mismatch')
    parent_cases=adapter_ledger.get('cases')
    if type(parent_cases) is not list or len(parent_cases)!=10:
        raise adapter.AdapterError('adapter_parent_slots_invalid')
    selected=ledger.get('split_metadata',{}).get('adapter_loci')
    expected={'schema_version':1,'phase':'adapter','dataset_kind':'biological','status':'passed',
              'dataset_sha256':ledger.get('dataset',{}).get('sha256'),
              'protocol_sha256':adapter.PROTOCOL_SHA256,
              'protocol_id':adapter.PROTOCOL_ID,'ledger_sha256':adapter_sha256,
              'source_commit':adapter.SOURCE_COMMIT,'ready_for_inference':True,
              'channel_order':'ACGT',
              'strand_handling':'pinned upstream forward: mean forward and reverse-complement head probabilities',
              'selection_sha256':ledger.get('split_metadata',{}).get('frozen_selection_sha256'),
              'weights_sha256':adapter.weights_pins(),
              'counts':{'submitted':10,'validated':10,'rejected':0,'pending':0,'inferred':10},
              'trained_weights_loaded':True,'strict_state_dict':True,'weights_only':True,
              'projection':False,'head_outputs':21907,'annotation_sha256':adapter.ANNOTATION_SHA256,
              'track_ids':adapter.TRACK_IDS,'track_indices_zero_based':adapter.TRACK_INDICES,
              'threads':1,'batch':1}
    if type(report) is not dict or any(not adapter.exact_json_equal(report.get(k),v) for k,v in expected.items()):
        raise adapter.AdapterError('biological_adapter_execution_receipt_mismatch')
    checks={'full_head_shape_1x21907':True,'all_head_probabilities_finite_and_in_unit_interval':True,
            'repeat_identical_all_head_outputs':True,'exact_nine_tracks':True,
            'projection_disabled':True,'batch_one':True}
    if not adapter.exact_json_equal(report.get('checks'),checks):
        raise adapter.AdapterError('biological_adapter_execution_checks_invalid')
    supervisor=report.get('supervisor')
    if type(supervisor) is not dict or not adapter.exact_json_equal(supervisor.get('returncode'),0):
        raise adapter.AdapterError('biological_adapter_execution_supervisor_invalid')
    records=report.get('records')
    if type(selected) is not list or len(selected)!=10 or type(records) is not list or len(records)!=10:
        raise adapter.AdapterError('biological_adapter_execution_slots_invalid')
    for index,(descriptor,record,parent_case) in enumerate(zip(selected,records,parent_cases)):
        parent_record=adapter.case_record(parent_case,index,True)
        if parent_record['status']!='validated':
            raise adapter.AdapterError('adapter_parent_case_invalid')
        if (type(descriptor) is not dict or type(record) is not dict or record.get('status')!='inferred'
                or record.get('repeat_identical') is not True or not adapter.finite(record.get('score'))
                or not adapter.exact_json_equal(adapter.canonical(record),{k:descriptor[k] for k in adapter.CASE_FIELDS})
                or record.get('window_sha256')!=descriptor.get('window_sha256')):
            raise adapter.AdapterError('biological_adapter_execution_record_invalid')
        # Bind the normalized effect, coordinates and row order as well as the
        # selected descriptor. Private probability vectors remain in the report.
        if any(not adapter.exact_json_equal(record.get(k),v)
               for k,v in parent_record.items() if k!='status'):
            raise adapter.AdapterError('biological_adapter_execution_parent_record_mismatch')
        vectors=[record.get(k) for k in ('track_ref_probabilities','track_alt_probabilities','track_deltas')]
        if any(type(v) is not list or len(v)!=9 or not all(adapter.finite(x) for x in v) for v in vectors):
            raise adapter.AdapterError('biological_adapter_execution_vectors_invalid')
        ref,alt,deltas=vectors
        if (any(not 0<=v<=1 for v in ref+alt) or deltas!=[a-r for r,a in zip(ref,alt)]
                or record['score']!=math.fsum(deltas)/9):
            raise adapter.AdapterError('biological_adapter_execution_score_mismatch')
    result=copy.deepcopy(ledger)
    result['split_metadata'].update(adapter_receipt_path=report_relative_path,adapter_receipt_sha256=report_sha256)
    if not adapter.exact_json_equal(result['cases'],ledger['cases']):
        raise adapter.AdapterError('evaluation_binding_changed_frozen_cases')
    return result


def prepare(prefix,evaluation_ledger,evaluation_sha256,adapter_report,report_sha256,adapter_ledger,adapter_sha256):
    prefix=Path(prefix).absolute()
    report_path=Path(adapter_report).absolute()
    try:
        relative=report_path.relative_to(prefix)
    except ValueError as exc:
        raise adapter.AdapterError('adapter_report_path_escape') from exc
    ledger=adapter.private_file(Path(evaluation_ledger).absolute(),prefix/'datasets',evaluation_sha256,json_document=True)
    parent=adapter.private_file(Path(adapter_ledger).absolute(),prefix/'datasets',adapter_sha256,json_document=True)
    parent_validation=adapter.validate_ledger(parent,prefix)
    if parent_validation['ready_for_inference'] is not True:
        raise adapter.AdapterError('adapter_parent_not_ready')
    report=adapter.private_file(report_path,prefix,report_sha256,json_document=True)
    bound=bind_report(ledger,report,str(relative),report_sha256,parent,adapter_sha256)
    adapter.verify_adapter_receipt(bound,prefix,bound['split_metadata']['frozen_selection_sha256'])
    validation=adapter.validate_ledger(bound,prefix)
    if validation['ready_for_inference'] is not True:
        raise adapter.AdapterError('evaluation_binding_not_ready')
    raw=preparation.canonical_bytes(bound);sha=hashlib.sha256(raw).hexdigest()
    name='kumasaka-evaluation-bound-'+sha+'.json'
    references.immutable_document(prefix/'datasets',name,bound)
    return {'status':'frozen_evaluation_bound_to_passed_adapter','filename':name,'sha256':sha,
            'adapter_report_sha256':report_sha256,'counts':validation['counts'],
            'ready_for_inference':True,'biological_loci_inferred_in_evaluation':0,
            'scientific_feasibility':'pending','raw_dna_published':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prefix',type=Path,required=True)
    parser.add_argument('--evaluation-ledger',type=Path,required=True)
    parser.add_argument('--evaluation-sha256',required=True)
    parser.add_argument('--adapter-report',type=Path,required=True)
    parser.add_argument('--report-sha256',required=True)
    parser.add_argument('--adapter-ledger',type=Path,required=True)
    parser.add_argument('--adapter-ledger-sha256',required=True)
    args=parser.parse_args()
    try:
        report=prepare(args.prefix,args.evaluation_ledger,args.evaluation_sha256,args.adapter_report,args.report_sha256,
                       args.adapter_ledger,args.adapter_ledger_sha256)
    except Exception as exc:
        print(json.dumps({'status':'failed','error_code':str(exc) if isinstance(exc,adapter.AdapterError)
                          else 'evaluation_binding_failed'}));return 1
    print(json.dumps(report,indent=2));return 0


if __name__=='__main__':
    raise SystemExit(main())
