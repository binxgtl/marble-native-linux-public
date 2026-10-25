#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Offline comparison eligibility and within-capture timing; never invokes a runner."""
import argparse
import json
from pathlib import Path
import replay
import topology

CONTEXT_KEYS=topology.CONTEXT_KEYS
TOPOLOGY_KEYS=topology.TOPOLOGY_KEYS
topology_digest=topology.topology_digest

def _safe_value(row):
    """Known diagnostic values only; never dump arbitrary malformed sysfs text."""
    value=row['value'];path=row['path'];group=row['group']
    if replay.optional_field(row):
        if not row['value_valid']:raise ValueError('optional format failure')
        return replay.format_value(group,path,value)
    if group=='power_supply':
        if path=='usb/usb_type':return replay.o1.selected(value)
        if replay.o1.POWER_FIELDS[path]!='text':return replay.o1.integer(value)
        allowed={'battery/type':{'Battery'},'usb/type':{'USB'},
                 'battery/status':{'Charging','Full','Not charging','Discharging','Unknown'},
                 'battery/health':{'Unknown','Good','Overheat','Dead','Over voltage','Unspecified failure',
                                   'Cold','Watchdog timer expire','Safety timer expire','Warm','Cool','Hot'}}
        if value not in allowed[path]:raise ValueError('unrecognized enum')
        return value
    role=path.split('/')[-1]
    options={'power_role':{'source','sink','[source] sink','source [sink]','[sink] source','sink [source]'},
             'data_role':{'host','device','[host] device','host [device]','[device] host','device [host]'},
             'power_operation_mode':{'default','1.5A','3.0A','usb_power_delivery'}}
    if value not in options[role]:raise ValueError('unrecognized role')
    return value

def observations(raw):
    rows=replay.load(raw)[:-1];origin=rows[0]['mono_ms'];samples=[{} for _ in range(rows[0]['samples'])]
    pending={}
    for row in rows:
        if row['kind'] not in ('read_begin','read_end'):continue
        key=(row['sample'],row['group'],row['path'])
        if row['kind']=='read_begin':pending[key]=row['mono_ms'];continue
        value=None;status='IO_ERROR' if row['rc'] else 'OBSERVED'
        if not row['rc']:
            try:value=_safe_value(row)
            except ValueError:status='INVALID_FORMAT'
        begin=pending.pop(key)
        samples[row['sample']][row['group']+'/'+row['path']]={
            'group':row['group'],'path':row['path'],'unit':row['unit'],
            'status':status,'value':value,'rc':row['rc'],'errno':row['errno'],
            'relative_begin_ms':begin-origin,'read_duration_ms':row['mono_ms']-begin}
    return samples

def sample_pairs(android,native):
    pairs=[]
    for i in range(min(len(android),len(native))):
        fields=[]
        for key in sorted(set(android[i])|set(native[i])):
            a=android[i].get(key);n=native[i].get(key);relation='UNAVAILABLE'
            if (a and n and a['status']==n['status']=='OBSERVED' and a['unit']==n['unit']):
                relation='VALUE_MATCH' if type(a['value']) is type(n['value']) and a['value']==n['value'] else 'VALUE_DIFF'
            fields.append({'field':key,'android':a,'native':n,'relation':relation})
        pairs.append({'sample_ordinal':i,'fields':fields})
    return pairs

def compare(android_raw,native_raw,android_context,native_context):
    android=replay.analyze(android_raw);native=replay.analyze(native_raw)
    ah=topology_digest(android_context,android_raw,'android')
    nh=topology_digest(native_context,native_raw,'native')
    def relative(raw):
        rows=replay.load(raw)[:-1];origin=rows[0]['mono_ms']
        return {'duration_ms':rows[-1]['mono_ms']-origin,
                'sample_starts_ms':[r['mono_ms']-origin for r in rows
                                    if r['kind']=='read_begin' and r['group']=='power_supply'
                                    and r['path']=='battery/type']}
    reasons=[]
    if ah!=nh:reasons.append('TOPOLOGY_MISMATCH')
    if android['telemetry']!='READABLE':reasons.append('ANDROID_CORE_UNREADABLE')
    if native['telemetry']!='READABLE':reasons.append('NATIVE_CORE_UNREADABLE')
    eligible=not reasons
    a_values=observations(android_raw);n_values=observations(native_raw)
    return {'schema':'M15-comparison-v2','comparison_eligibility':'ELIGIBLE' if eligible else 'BLOCKED',
            'blocked_reasons':reasons,
            'core_telemetry':{name:{'status':report['telemetry'],
                                    'sample_errors':[s['errors'] for s in report['samples']]}
                              for name,report in (('android',android),('native',native))},
            'topology_equal':ah==nh,'android_topology_sha256':ah,'native_topology_sha256':nh,
            'topology_semantics':'declared inventory checksum; eligibility only, not physical attestation or PD/PPS equivalence',
            'timing_semantics':'relative within each capture; separate clock origins are never aligned',
            'android_relative_timing':relative(android_raw),'native_relative_timing':relative(native_raw),
            'android_capture_sha256':android['raw_sha256'],'native_capture_sha256':native['raw_sha256'],
            'pairing_semantics':'sample ordinal and exact sysfs path only; no clock synchronization or physical port remapping',
            'value_semantics':'reported observations only; matches/differences do not establish PD/PPS equivalence or safety',
            'sample_pairs':sample_pairs(a_values,n_values) if eligible else [],
            'sample_counts':{'android':len(a_values),'native':len(n_values)},
            'unpaired_samples':{'android':max(0,len(a_values)-len(n_values)),
                                'native':max(0,len(n_values)-len(a_values))},
            'freshness':'UNKNOWN','negotiated_contract':'UNKNOWN','protection_active':'UNKNOWN',
            'android_observer_compatibility':'UNKNOWN','control_permitted':False,'charging_hardware_pass':False}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('android-capture','native-capture','android-context','native-context'):p.add_argument('--'+name,required=True,type=Path)
    a=p.parse_args()
    try:
        ac=topology.load_json(a.android_context)
        nc=topology.load_json(a.native_context)
        r=compare(a.android_capture.read_bytes(),a.native_capture.read_bytes(),ac,nc)
    except (ValueError,TypeError,KeyError,OSError,RecursionError):
        print(json.dumps({'comparison_eligibility':'BLOCKED','error':'invalid comparison input','control_permitted':False,
                          'freshness':'UNKNOWN','negotiated_contract':'UNKNOWN','protection_active':'UNKNOWN',
                          'android_observer_compatibility':'UNKNOWN','charging_hardware_pass':False}));return 1
    print(json.dumps(r,indent=2));return 0 if r['comparison_eligibility']=='ELIGIBLE' else 2

if __name__=='__main__':raise SystemExit(main())
