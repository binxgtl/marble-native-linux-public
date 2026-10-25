#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""O3-only comparison-v3; legacy comparator-v2 remains byte-preserved."""
import argparse
import json
from pathlib import Path
import contract
from compat import o3,legacy_compare,restrictions

def safe_value(row):
    value=row['value'];path=row['path'];group=row['group']
    if o3.legacy.optional_field(row):
        if not row['value_valid']:raise ValueError('optional format failure')
        return o3.legacy.format_value(group,path,value)
    if group=='power_supply':
        if path=='usb/type':
            if value not in o3.USB_SUPPLY_TYPES:raise ValueError('invalid O3 supply class')
            return value
        if path=='usb/usb_type':return o3.legacy.o1.selected(value)
        if o3.legacy.o1.POWER_FIELDS[path]!='text':return o3.legacy.o1.integer(value)
        options={'battery/type':{'Battery'},'battery/status':{'Charging','Full','Not charging','Discharging','Unknown'},
                 'battery/health':{'Unknown','Good','Overheat','Dead','Over voltage','Unspecified failure',
                                   'Cold','Watchdog timer expire','Safety timer expire','Warm','Cool','Hot'}}
    else:
        path=path.split('/')[-1]
        options={'power_role':{'source','sink','[source] sink','source [sink]','[sink] source','sink [source]'},
                 'data_role':{'host','device','[host] device','host [device]','[device] host','device [host]'},
                 'power_operation_mode':{'default','1.5A','3.0A','usb_power_delivery'}}
    if value not in options[path]:raise ValueError('unrecognized reported enum')
    return value

def observations(raw):
    rows=o3.legacy.load(raw)[:-1];origin=rows[0]['mono_ms']
    samples=[{} for _ in range(rows[0]['samples'])];pending={}
    for row in rows:
        if row['kind'] not in ('read_begin','read_end'):continue
        key=(row['sample'],row['group'],row['path'])
        if row['kind']=='read_begin':pending[key]=row['mono_ms'];continue
        value=None;status='IO_ERROR' if row['rc'] else 'OBSERVED'
        if not row['rc']:
            try:value=safe_value(row)
            except ValueError:status='INVALID_FORMAT'
        begin=pending.pop(key)
        samples[row['sample']][row['group']+'/'+row['path']]={
            'group':row['group'],'path':row['path'],'unit':row['unit'],'status':status,'value':value,
            'rc':row['rc'],'errno':row['errno'],'relative_begin_ms':begin-origin,
            'read_duration_ms':row['mono_ms']-begin}
    return samples

def relative(raw):
    rows=o3.legacy.load(raw)[:-1];origin=rows[0]['mono_ms']
    return {'duration_ms':rows[-1]['mono_ms']-origin,'sample_starts_ms':[
        row['mono_ms']-origin for row in rows if row['kind']=='read_begin'
        and row['group']=='power_supply' and row['path']=='battery/type']}

def compare(android_raw,native_raw,android_context,native_context):
    ah,android=contract.verify_context(android_context,android_raw,'android')
    nh,native=contract.verify_context(native_context,native_raw,'native')
    reasons=[]
    if ah!=nh:reasons.append('TOPOLOGY_MISMATCH')
    if android['telemetry']!='READABLE':reasons.append('ANDROID_CORE_UNREADABLE')
    if native['telemetry']!='READABLE':reasons.append('NATIVE_CORE_UNREADABLE')
    a_values=observations(android_raw);n_values=observations(native_raw)
    return {'schema':'M15-comparison-v3','observation_schema':contract.OBSERVATION,
            'power_supply_contract':contract.POWER_CONTRACT,
            'comparison_eligibility':'BLOCKED' if reasons else 'ELIGIBLE','blocked_reasons':reasons,
            'topology_equal':ah==nh,'android_topology_sha256':ah,'native_topology_sha256':nh,
            'topology_semantics':'declared eligibility only, not physical attestation or negotiated PD/PPS equivalence',
            'capture_bindings':{name:{'sha256':ctx['capture_sha256'],'bytes':ctx['capture_bytes'],
                                      'original_raw_binding_verified':True,'framing_complete':True,
                                      'sender_seal_verified':False,'environment_authenticity':'UNKNOWN'}
                                for name,ctx in (('android',android_context),('native',native_context))},
            'core_telemetry':{name:{'status':report['telemetry'],'sample_errors':[s['errors'] for s in report['samples']],
                                    'reported_supply_types':[s['reported_supply_type'] for s in report['samples']]}
                              for name,report in (('android',android),('native',native))},
            'timing_semantics':'relative within each capture only; separate clock origins are never aligned',
            'android_relative_timing':relative(android_raw),'native_relative_timing':relative(native_raw),
            'pairing_semantics':'sample ordinal and exact sysfs path only; no physical port remapping',
            'sample_pairs':legacy_compare.sample_pairs(a_values,n_values) if not reasons else [],
            'sample_counts':{'android':len(a_values),'native':len(n_values)},
            'unpaired_samples':{'android':max(0,len(a_values)-len(n_values)),
                                'native':max(0,len(n_values)-len(a_values))},
            'value_semantics':'reported values only; matching values do not establish PD/PPS negotiation, protection or delivered power',
            'sealed_baseline':False,'evidence_class':contract.EVIDENCE_CLASS,
            'transport_integrity':'ORIGINAL_RAW_CONTEXT_BINDING_ONLY',**restrictions()}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('android-capture','native-capture','android-context','native-context'):p.add_argument('--'+name,required=True,type=Path)
    a=p.parse_args()
    try:
        r=compare(a.android_capture.read_bytes(),a.native_capture.read_bytes(),
                  contract.load_json(a.android_context),contract.load_json(a.native_context))
    except (ValueError,TypeError,KeyError,OSError,RecursionError):
        print(json.dumps({'schema':'M15-comparison-v3','comparison_eligibility':'BLOCKED',
                          'error':'invalid local O3 comparison input','sealed_baseline':False,**restrictions()}));return 1
    print(json.dumps(r,indent=2));return 0 if r['comparison_eligibility']=='ELIGIBLE' else 2

if __name__=='__main__':raise SystemExit(main())
