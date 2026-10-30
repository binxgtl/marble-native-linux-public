#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Local-files-only verification of a long.sh capture; never calls adb, su or a producer."""
import argparse
import json
from pathlib import Path
import re

import verify as base

HERE=Path(__file__).resolve().parent
contract=base.contract

def verify(session,topology_sha,*,observer_sha=base.OBSERVER_SHA,runner_sha=None):
    if not base.HASH.fullmatch(topology_sha):raise ValueError('invalid expected contract')
    if session.is_symlink() or (session/'long').is_symlink():raise ValueError('linked session')
    runner_sha=runner_sha or base.sha((HERE/'long.sh').read_bytes())
    binary=base.read(session/'observer');topology=base.read(session/'topology.json',16384);runner=base.read(session/'long.sh',16384)
    if base.sha(binary)!=observer_sha or base.sha(topology)!=topology_sha or base.sha(runner)!=runner_sha:raise ValueError('payload binding mismatch')
    manifest=contract.load_json(session/'topology.json');topology_digest=contract.digest(manifest)
    if manifest['power_source']!='wall-charger' or manifest['evidence_path']!='ram-offline':raise ValueError('wrong acquisition topology')
    folder=session/'long';index=base.read(folder/'SHA256SUMS',2048);entries={}
    for line in index.decode('ascii').splitlines():
        match=re.fullmatch(r'([0-9a-f]{64})  ([a-zA-Z0-9.-]+)',line)
        if not match or match[2] in entries:raise ValueError('invalid hash index')
        entries[match[2]]=match[1]
    if set(entries)!=base.FILES or not index.endswith(b'\n'):raise ValueError('incomplete hash index')
    data={name:base.read(folder/name,16384 if name!='capture.raw' else 2_000_000) for name in entries}
    if any(base.sha(data[name])!=digest for name,digest in entries.items()):raise ValueError('original file digest mismatch')
    if data['input-binding.txt']!=f'{observer_sha}\n{topology_sha}\n{runner_sha}\n'.encode():raise ValueError('session binding mismatch')
    if data['capture.exit']!=b'0\n' or data['capture.stderr']:raise ValueError('observer process failure')
    record=contract.load_json(folder/'record.json')
    if record!={'schema':'M15-Termux-capture-v1','phase':'long','process_rc':0,'sealed_baseline':False,
                'control_permitted':False,'freshness':'UNKNOWN','negotiated_contract':'UNKNOWN','protection_active':'UNKNOWN'}:
        raise ValueError('invalid capture record')
    if type(record['process_rc']) is not int or record['sealed_baseline'] is not False or record['control_permitted'] is not False:
        raise ValueError('invalid capture record types')
    raw=data['capture.raw'];report=contract.analyze_o3(raw)
    if not report['transcript_complete'] or contract.o3.legacy.load(raw)[0]['samples']!=10:raise ValueError('wrong sample contract')
    return {'schema':'M15-Termux-long-verification-v1','phase':'long','samples':10,'transcript_complete':True,
            'observer_sha256':observer_sha,'wrapper_sha256':runner_sha,'topology_file_sha256':topology_sha,
            'raw_sha256':base.sha(raw),'raw_bytes':len(raw),'process_rc':0,'hash_index_sha256':base.sha(index),
            'topology_canonical_sha256':topology_digest,'telemetry':report['telemetry'],
            'readiness':'OFFLINE_FORMAT_VERIFIED_RUNTIME_ORIGIN_UNATTESTED','sender_seal_verified':False,
            'sealed_baseline':False,'control_permitted':False,'freshness':'UNKNOWN',
            'negotiated_contract':'UNKNOWN','protection_active':'UNKNOWN'}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--session',required=True,type=Path)
    p.add_argument('--topology-file-sha256',required=True);a=p.parse_args()
    try:
        result=verify(a.session,a.topology_file_sha256)
        print(json.dumps(result,indent=2))
        return 0 if result['telemetry']=='READABLE' else 2
    except (ValueError,TypeError,KeyError,OSError,UnicodeError,RecursionError):
        print(json.dumps({'valid':False,'error':'invalid local acquisition evidence','sealed_baseline':False,
                          'control_permitted':False,'freshness':'UNKNOWN','negotiated_contract':'UNKNOWN',
                          'protection_active':'UNKNOWN'}));return 1

if __name__=='__main__':raise SystemExit(main())
