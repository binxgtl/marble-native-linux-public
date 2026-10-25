#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Offline comparison eligibility and within-capture timing; never invokes a runner."""
import argparse
import hashlib
import json
import re
from pathlib import Path
import replay

CONTEXT_KEYS={'schema','environment','capture_sha256','topology'}
TOPOLOGY_KEYS={'schema','charger_inventory_sha256','cable_inventory_sha256',
               'instrumentation_inventory_sha256','power_source','evidence_path'}

def topology_digest(context,raw,environment):
    if (type(context)!=dict or set(context)!=CONTEXT_KEYS or context['schema']!='M15-context-v1'
        or context['environment']!=environment):raise ValueError('invalid comparison context')
    if context['capture_sha256']!=hashlib.sha256(raw).hexdigest():raise ValueError('capture binding mismatch')
    topology=context['topology']
    if type(topology)!=dict or set(topology)!=TOPOLOGY_KEYS or topology['schema']!='M15-topology-v1':
        raise ValueError('topology schema drift/private metadata')
    for key in ('charger_inventory_sha256','cable_inventory_sha256','instrumentation_inventory_sha256'):
        if not isinstance(topology[key],str) or not re.fullmatch('[0-9a-f]{64}',topology[key]):
            raise ValueError('invalid inventory hash')
    if (topology['power_source'] not in ('pc-usb','wall-charger','pd-analyzer-source')
        or topology['evidence_path'] not in ('direct-usb','ram-offline','external-analyzer')):
        raise ValueError('invalid topology enum')
    canonical=json.dumps(topology,sort_keys=True,separators=(',',':')).encode()
    return hashlib.sha256(canonical).hexdigest()

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
    eligible=ah==nh and android['telemetry']=='READABLE' and native['telemetry']=='READABLE'
    return {'schema':'M15-comparison-v1','comparison_eligibility':'ELIGIBLE' if eligible else 'BLOCKED',
            'topology_equal':ah==nh,'android_topology_sha256':ah,'native_topology_sha256':nh,
            'topology_semantics':'declared inventory checksum; eligibility only, not physical attestation or PD/PPS equivalence',
            'timing_semantics':'relative within each capture; separate clock origins are never aligned',
            'android_relative_timing':relative(android_raw),'native_relative_timing':relative(native_raw),
            'android_capture_sha256':android['raw_sha256'],'native_capture_sha256':native['raw_sha256'],
            'freshness':'UNKNOWN','negotiated_contract':'UNKNOWN','protection_active':'UNKNOWN',
            'android_observer_compatibility':'UNKNOWN','control_permitted':False,'charging_hardware_pass':False}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('android-capture','native-capture','android-context','native-context'):p.add_argument('--'+name,required=True,type=Path)
    a=p.parse_args()
    try:
        ac=json.loads(a.android_context.read_bytes(),object_pairs_hook=replay.o1.no_duplicate_keys)
        nc=json.loads(a.native_context.read_bytes(),object_pairs_hook=replay.o1.no_duplicate_keys)
        r=compare(a.android_capture.read_bytes(),a.native_capture.read_bytes(),ac,nc)
    except (ValueError,TypeError,KeyError,OSError):
        print(json.dumps({'comparison_eligibility':'BLOCKED','error':'invalid comparison input','control_permitted':False}));return 1
    print(json.dumps(r,indent=2));return 0 if r['comparison_eligibility']=='ELIGIBLE' else 2

if __name__=='__main__':raise SystemExit(main())
