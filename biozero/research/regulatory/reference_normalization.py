# SPDX-License-Identifier: AGPL-3.0-only
"""Normalize a frozen candidate only after both reference receipts are verified.

Minus-strand mapping complements alleles without changing source Beta. A target
reference swap is converted once by the existing adapter's explicit E/O rule.
This helper produces no review approval, selection or model prediction.
"""
import hashlib

import biological_adapter as adapter
import reference_windows

COMPLEMENT = str.maketrans('ACGT','TGCA')


def _receipt(receipt, genome, chrom, start, end):
    expected = {'schema_version':1,'genome_build':genome,'chrom':chrom,
                'start_zero_based':start,'end_zero_based':end,'strand':'+','padding':False}
    if (type(receipt) is not dict or any(not adapter.exact_json_equal(receipt.get(k),v)
                                       for k,v in expected.items())
            or receipt.get('status') not in ('verified','verified_cached')):
        raise adapter.AdapterError('reference_receipt_coordinates_or_status_invalid')
    spec=reference_windows.request_spec(genome,chrom,start,end)
    if receipt.get('source_url') != spec['source_url'] or not adapter.is_sha(receipt.get('source_response_sha256')):
        raise adapter.AdapterError('reference_receipt_provenance_invalid')
    dna=receipt.get('sequence')
    if (type(dna) is not str or len(dna)!=end-start or set(dna)-set('ACGT')
            or hashlib.sha256(dna.encode()).hexdigest()!=receipt.get('sha256')):
        raise adapter.AdapterError('reference_receipt_dna_invalid')
    return dna


def normalize_precandidate(candidate, source_receipt, target_receipt, *, prepool_sha256):
    if type(candidate) is not dict or not adapter.is_sha(prepool_sha256):
        raise adapter.AdapterError('reference_candidate_or_freeze_invalid')
    for key in ('source_position_1based','mapped_position_1based'):
        if type(candidate.get(key)) is not int or candidate[key]<=0:
            raise adapter.AdapterError('reference_candidate_position_invalid')
    for key in ('source_ref','source_alt','oriented_source_ref','oriented_source_alt'):
        if candidate.get(key) not in tuple('ACGT'):
            raise adapter.AdapterError('reference_candidate_allele_invalid')
    ref,alt=candidate['source_ref'],candidate['source_alt']
    if ref==alt:
        raise adapter.AdapterError('reference_candidate_allele_invalid')
    mapping=candidate.get('mapping',{})
    snp=mapping.get('snp',{}) if type(mapping) is dict else {}
    strand=snp.get('strand') if type(snp) is dict else None
    if strand not in ('+','-'):
        raise adapter.AdapterError('reference_candidate_strand_invalid')
    oriented_ref=ref.translate(COMPLEMENT) if strand=='-' else ref
    oriented_alt=alt.translate(COMPLEMENT) if strand=='-' else alt
    if (candidate['oriented_source_ref'],candidate['oriented_source_alt'])!=(oriented_ref,oriented_alt):
        raise adapter.AdapterError('reference_candidate_complement_mismatch')
    source_q=candidate['source_position_1based']-1
    target_q=candidate['mapped_position_1based']-1
    if candidate.get('source_chrom')!=candidate.get('mapped_chrom'):
        raise adapter.AdapterError('reference_candidate_chromosome_mismatch')
    geometry={'source_chrom':candidate['source_chrom'],'source_start':source_q,'source_end':source_q+1,
              'target_chrom':candidate['mapped_chrom'],'target_start':target_q,'target_end':target_q+1}
    if any(not adapter.exact_json_equal(snp.get(k),v) for k,v in geometry.items()):
        raise adapter.AdapterError('reference_candidate_snp_mapping_mismatch')
    mapped_peak=mapping.get('peak',{})
    peak=candidate.get('peak',{})
    if (type(mapped_peak) is not dict or type(peak) is not dict
            or type(snp.get('chain_id')) is not int
            or not adapter.exact_json_equal(mapped_peak.get('chain_id'),snp['chain_id'])
            or mapped_peak.get('strand')!=strand
            or mapped_peak.get('source_chrom')!=candidate['source_chrom']
            or mapped_peak.get('target_chrom')!=candidate['mapped_chrom']
            or any(type(mapped_peak.get(k)) is not int for k in ('source_start','source_end','target_start','target_end'))
            or not mapped_peak['source_start']<=source_q<mapped_peak['source_end']
            or not mapped_peak['target_start']<=target_q<mapped_peak['target_end']
            or not adapter.exact_json_equal(peak.get('start'),mapped_peak['source_start'])
            or not adapter.exact_json_equal(peak.get('end'),mapped_peak['source_end'])
            or peak.get('chrom')!=candidate['source_chrom']):
        raise adapter.AdapterError('reference_candidate_peak_mapping_mismatch')
    if target_q<2048 or type(snp.get('target_size')) is not int or target_q+2048>snp['target_size']:
        raise adapter.AdapterError('reference_target_window_out_of_bounds')
    if (type(snp.get('source_size')) is not int or source_q>=snp['source_size']
            or any(not adapter.exact_json_equal(mapped_peak.get(k),snp[k])
                   for k in ('source_size','target_size'))
            or not 0<=mapped_peak['source_start']<mapped_peak['source_end']<=snp['source_size']
            or not 0<=mapped_peak['target_start']<mapped_peak['target_end']<=snp['target_size']
            or mapped_peak['source_end']-mapped_peak['source_start'] != mapped_peak['target_end']-mapped_peak['target_start']):
        raise adapter.AdapterError('reference_candidate_ungapped_geometry_invalid')
    offset=source_q-mapped_peak['source_start']
    projected=mapped_peak['target_start']+offset if strand=='+' else mapped_peak['target_end']-1-offset
    if projected!=target_q:
        raise adapter.AdapterError('reference_candidate_ungapped_offset_mismatch')
    source_dna=_receipt(source_receipt,'hg19',candidate.get('source_chrom'),source_q,source_q+1)
    target_dna=_receipt(target_receipt,'hg38',candidate.get('mapped_chrom'),target_q-2048,target_q+2048)
    if source_dna!=ref:
        raise adapter.AdapterError('source_reference_allele_mismatch')
    observed=target_dna[2048]
    if observed==oriented_ref:
        target_ref,target_alt,swapped=oriented_ref,oriented_alt,False
    elif observed==oriented_alt:
        target_ref,target_alt,swapped=oriented_alt,oriented_ref,True
    else:
        raise adapter.AdapterError('target_reference_third_allele')
    raw_effect=candidate.get('source_effect')
    if (type(raw_effect) is not dict or (raw_effect.get('effect_allele'),raw_effect.get('other_allele'))!=(alt,ref)
            or not adapter.finite(raw_effect.get('standard_error')) or raw_effect['standard_error']<=0):
        raise adapter.AdapterError('source_effect_orientation_or_error_invalid')
    effect=dict(raw_effect, effect_allele=oriented_alt, other_allele=oriented_ref, orientation_known=True)
    normalized=adapter.normalize_effect(effect,target_ref,target_alt)
    af=candidate.get('source_af')
    if not adapter.finite(af) or not 0<=af<=1:
        raise adapter.AdapterError('source_allele_frequency_invalid')
    window={k:v for k,v in target_receipt.items() if k!='status'}
    window['provenance']={'source_response_sha256':target_receipt['source_response_sha256'],
                          'assembly':'hg38','coordinate_convention':'zero-based half-open',
                          'prepool_sha256':prepool_sha256}
    case={'case_id':candidate.get('candidate_id'),'origin_row_id':candidate.get('origin_row_id'),
          'genome_build':'hg38','chrom':candidate['mapped_chrom'],
          'position_1based':candidate['mapped_position_1based'],'ref':target_ref,'alt':target_alt,
          'window':window,'effect':effect,
          'source_provenance':{'source_row_sha256':candidate.get('source_row_sha256'),
              'source_build':'hg19','source_chrom':candidate['source_chrom'],
              'source_position_1based':candidate['source_position_1based'],
              'source_ref':ref,'source_alt':alt,'mapping':mapping,'peak':candidate.get('peak'),
              'source_reference_response_sha256':source_receipt['source_response_sha256'],
              'source_reference_dna_sha256':source_receipt['sha256'],'prepool_sha256':prepool_sha256,
              'mapping_strand':strand,'oriented_source_ref':oriented_ref,'oriented_source_alt':oriented_alt,
              'target_reference_swap':swapped,'source_beta':raw_effect.get('value'),
              'source_af':af,'target_alt_af':1-af if swapped else af,
              'af_transformation':'1-source_AF' if swapped else 'source_AF',
              'source_p_lead':candidate.get('source_p_lead'),
              'source_log10_bf':candidate.get('source_log10_bf'),
              'effect_conversion':normalized}}
    record=adapter.case_record(case,0,True)
    if record['status']!='validated':
        raise adapter.AdapterError('normalized_case_invalid')
    return case
