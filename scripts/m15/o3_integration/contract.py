#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""M15-topology-v2/context-v2: explicit O3 contract and exact original-file binding."""
import argparse
import hashlib
import json
from pathlib import Path
from compat import o3,legacy_topology,restrictions

OBSERVATION='M15O3'
POWER_CONTRACT='usb-or-usb-pd-v1'
EVIDENCE_CLASS='local-framed-unsealed'
TOPOLOGY_KEYS=legacy_topology.TOPOLOGY_KEYS|{'observation_schema','power_supply_contract'}
CONTEXT_KEYS={'schema','environment','capture_sha256','capture_bytes','topology','topology_sha256',
              'observation_schema','power_supply_contract','sealed_baseline','evidence_class'}

def canonical(manifest):
    if (type(manifest)!=dict or set(manifest)!=TOPOLOGY_KEYS or manifest['schema']!='M15-topology-v2'
        or manifest['observation_schema']!=OBSERVATION or manifest['power_supply_contract']!=POWER_CONTRACT):
        raise ValueError('invalid O3 topology contract')
    # Reuse only the closed physical-inventory validation. The digest below
    # covers the original v2 manifest, never this validation projection.
    old=manifest.copy();old['schema']='M15-topology-v1'
    old.pop('observation_schema');old.pop('power_supply_contract')
    legacy_topology.canonical(old)
    return json.dumps(manifest,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()

def digest(manifest):return hashlib.sha256(canonical(manifest)).hexdigest()

def analyze_o3(raw):
    rows=o3.legacy.load(raw)
    if rows[0].get('schema')!=OBSERVATION or rows[0].get('power_supply_contract')!=POWER_CONTRACT:
        raise ValueError('O3 contract required; no implicit O1/O2 or exploratory upgrade')
    report=o3.analyze(raw)
    if report['observation_schema']!=OBSERVATION:raise ValueError('observation contract drift')
    return report

def make_context(manifest,raw,environment):
    topology_sha=digest(manifest)
    if environment not in legacy_topology.ENVIRONMENTS:raise ValueError('invalid environment label')
    analyze_o3(raw)
    return {'schema':'M15-context-v2','environment':environment,'capture_sha256':hashlib.sha256(raw).hexdigest(),
            'capture_bytes':len(raw),'topology':json.loads(canonical(manifest)),'topology_sha256':topology_sha,
            'observation_schema':OBSERVATION,'power_supply_contract':POWER_CONTRACT,
            'sealed_baseline':False,'evidence_class':EVIDENCE_CLASS}

def verify_context(context,raw,environment):
    if (type(context)!=dict or set(context)!=CONTEXT_KEYS or context['schema']!='M15-context-v2'
        or environment not in legacy_topology.ENVIRONMENTS or context['environment']!=environment
        or context['observation_schema']!=OBSERVATION or context['power_supply_contract']!=POWER_CONTRACT
        or context['sealed_baseline'] is not False or context['evidence_class']!=EVIDENCE_CLASS):
        raise ValueError('invalid context contract')
    # Verify the context against untouched input bytes BEFORE any JSON projection
    # by a replay implementation. Raw bytes, whitespace and trailing newline bind.
    if (not legacy_topology.is_hash(context['capture_sha256'])
        or context['capture_sha256']!=hashlib.sha256(raw).hexdigest()
        or type(context['capture_bytes'])!=int or not 0<context['capture_bytes']<=2_000_000
        or context['capture_bytes']!=len(raw)):raise ValueError('original capture digest/size mismatch')
    actual_topology=digest(context['topology'])
    if not legacy_topology.is_hash(context['topology_sha256']) or context['topology_sha256']!=actual_topology:
        raise ValueError('topology digest mismatch')
    report=analyze_o3(raw)
    return actual_topology,report

def _nonfinite(_):raise ValueError('non-finite JSON metadata')
def load_json(path):
    with path.open('rb') as f:raw=f.read(16385)
    if len(raw)>16384:raise ValueError('oversized metadata')
    return json.loads(raw,object_pairs_hook=o3.legacy.o1.no_duplicate_keys,parse_constant=_nonfinite)

def main():
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='operation',required=True)
    validate=sub.add_parser('validate');validate.add_argument('--manifest',required=True,type=Path)
    context=sub.add_parser('context');context.add_argument('--manifest',required=True,type=Path)
    context.add_argument('--capture',required=True,type=Path);context.add_argument('--environment',required=True,choices=legacy_topology.ENVIRONMENTS)
    a=p.parse_args()
    try:
        manifest=load_json(a.manifest)
        if a.operation=='context':result=make_context(manifest,a.capture.read_bytes(),a.environment)
        else:result={'schema':'M15-topology-validation-v2','valid':True,'topology_sha256':digest(manifest),
                     'observation_schema':OBSERVATION,'power_supply_contract':POWER_CONTRACT,
                     'sealed_baseline':False,**restrictions()}
    except (ValueError,TypeError,KeyError,OSError,RecursionError):
        print(json.dumps({'valid':False,'error':'invalid local O3 input','sealed_baseline':False,**restrictions()}));return 1
    print(json.dumps(result,indent=2,sort_keys=True));return 0

if __name__=='__main__':raise SystemExit(main())
