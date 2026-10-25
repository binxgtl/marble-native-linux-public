#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Closed topology/context contracts and local-file CLI. No device execution."""
import argparse
import hashlib
import json
import re
from pathlib import Path
import replay

CONTEXT_KEYS={'schema','environment','capture_sha256','topology'}
INVENTORIES=('charger_inventory_sha256','cable_inventory_sha256','instrumentation_inventory_sha256')
TOPOLOGY_KEYS={'schema','power_source','evidence_path',*INVENTORIES}
POWER_SOURCES=('pc-usb','wall-charger','pd-analyzer-source')
EVIDENCE_PATHS=('direct-usb','ram-offline','external-analyzer')
ENVIRONMENTS=('android','native')

def sha256(raw):return hashlib.sha256(raw).hexdigest()
def is_hash(value):return type(value)==str and re.fullmatch('[0-9a-f]{64}',value) is not None

def canonical(manifest):
    if (type(manifest)!=dict or set(manifest)!=TOPOLOGY_KEYS
        or manifest['schema']!='M15-topology-v1'):raise ValueError('invalid topology schema')
    if any(not is_hash(manifest[key]) for key in INVENTORIES):raise ValueError('invalid inventory hash')
    if manifest['power_source'] not in POWER_SOURCES or manifest['evidence_path'] not in EVIDENCE_PATHS:
        raise ValueError('invalid topology enum')
    # No case folding, whitespace trimming, environment fields or timestamps.
    # Encoding is canonical JSON UTF-8, ASCII keys/values, no trailing newline.
    return json.dumps(manifest,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('utf-8')

def digest(manifest):return sha256(canonical(manifest))

def topology_digest(context,raw,environment):
    if environment not in ENVIRONMENTS:raise ValueError('invalid expected environment')
    if (type(context)!=dict or set(context)!=CONTEXT_KEYS or context['schema']!='M15-context-v1'
        or context['environment']!=environment):raise ValueError('invalid comparison context')
    if not is_hash(context['capture_sha256']) or context['capture_sha256']!=sha256(raw):
        raise ValueError('capture binding mismatch')
    return digest(context['topology'])

def make_context(manifest,raw,environment):
    canonical(manifest)
    if environment not in ENVIRONMENTS:raise ValueError('invalid environment label')
    replay.analyze(raw)  # Validate complete captured bytes, never execute the producer.
    return {'schema':'M15-context-v1','environment':environment,
            'capture_sha256':sha256(raw),'topology':json.loads(canonical(manifest))}

def _nonfinite(_):raise ValueError('non-finite JSON number')
def load_json(path):
    # Contexts are small metadata documents, not arbitrary capture containers.
    with path.open('rb') as f:raw=f.read(16385)
    if len(raw)>16384:raise ValueError('oversized metadata')
    return json.loads(raw,object_pairs_hook=replay.o1.no_duplicate_keys,parse_constant=_nonfinite)

def restrictions():
    return {'control_permitted':False,'freshness':'UNKNOWN','negotiated_contract':'UNKNOWN',
            'protection_active':'UNKNOWN','android_observer_compatibility':'UNKNOWN','charging_hardware_pass':False}

def main():
    p=argparse.ArgumentParser(description=__doc__);subs=p.add_subparsers(dest='operation',required=True)
    validate=subs.add_parser('validate');validate.add_argument('--manifest',required=True,type=Path)
    context=subs.add_parser('context');context.add_argument('--manifest',required=True,type=Path)
    context.add_argument('--capture',required=True,type=Path)
    context.add_argument('--environment',required=True,choices=ENVIRONMENTS)
    a=p.parse_args()
    try:
        manifest=load_json(a.manifest)
        if a.operation=='context':result=make_context(manifest,a.capture.read_bytes(),a.environment)
        else:result={'schema':'M15-topology-validation-v1','valid':True,'topology_sha256':digest(manifest),
                     'semantics':'declared inventory identity only; not physical attestation or negotiated equivalence',
                     **restrictions()}
    except (ValueError,TypeError,KeyError,OSError,RecursionError):
        print(json.dumps({'valid':False,'error':'invalid local input',**restrictions()}));return 1
    print(json.dumps(result,indent=2,sort_keys=True));return 0

if __name__=='__main__':raise SystemExit(main())
