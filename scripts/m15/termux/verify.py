#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Local-files-only verification/admission; never calls adb, su or a producer."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent/'o3_integration'))
import contract

OBSERVER_SHA='5d061f9ca33b985c659c1bd76c130505a58d8b89c0861f3df5aa4e78b028ec12'
FILES={'input-binding.txt','record.json','capture.raw','capture.stderr','capture.exit'}
NOARGS={'noargs.raw','noargs.stderr','noargs.exit'}
HASH=re.compile(r'[0-9a-f]{64}')

def sha(raw):return hashlib.sha256(raw).hexdigest()

def read(path,limit=2_000_000):
    if path.is_symlink() or not path.is_file():raise ValueError('missing or linked input')
    with path.open('rb') as f:raw=f.read(limit+1)
    if len(raw)>limit:raise ValueError('oversized input')
    return raw

def verify(session,phase,topology_sha,*,observer_sha=OBSERVER_SHA,runner_sha=None):
    if phase not in ('qualify','acquire') or not HASH.fullmatch(topology_sha):raise ValueError('invalid expected contract')
    if session.is_symlink() or (session/phase).is_symlink():raise ValueError('linked session')
    runner_sha=runner_sha or sha((HERE/'capture.sh').read_bytes())
    binary=read(session/'observer');topology=read(session/'topology.json',16384);runner=read(session/'capture.sh',16384)
    if sha(binary)!=observer_sha or sha(topology)!=topology_sha or sha(runner)!=runner_sha:raise ValueError('payload binding mismatch')
    manifest=contract.load_json(session/'topology.json');topology_digest=contract.digest(manifest)
    if manifest['power_source']!='wall-charger' or manifest['evidence_path']!='ram-offline':raise ValueError('wrong acquisition topology')
    folder=session/phase;index=read(folder/'SHA256SUMS',2048);entries={}
    for line in index.decode('ascii').splitlines():
        match=re.fullmatch(r'([0-9a-f]{64})  ([a-zA-Z0-9.-]+)',line)
        if not match or match[2] in entries:raise ValueError('invalid hash index')
        entries[match[2]]=match[1]
    expected=FILES|(NOARGS if phase=='qualify' else set())
    if set(entries)!=expected or not index.endswith(b'\n'):raise ValueError('incomplete hash index')
    data={name:read(folder/name,16384 if name!='capture.raw' else 2_000_000) for name in entries}
    if any(sha(data[name])!=digest for name,digest in entries.items()):raise ValueError('original file digest mismatch')
    binding=f'{observer_sha}\n{topology_sha}\n{runner_sha}\n'.encode()
    if data['input-binding.txt']!=binding:raise ValueError('session binding mismatch')
    if data['capture.exit']!=b'0\n' or data['capture.stderr']:raise ValueError('observer process failure')
    record=contract.load_json(folder/'record.json')
    if record!={'schema':'M15-Termux-capture-v1','phase':phase,'process_rc':0,'sealed_baseline':False,
                'control_permitted':False,'freshness':'UNKNOWN','negotiated_contract':'UNKNOWN','protection_active':'UNKNOWN'}:
        raise ValueError('invalid capture record')
    # Avoid Python equality accepting bool/int interchange in safety fields.
    if type(record['process_rc']) is not int or record['sealed_baseline'] is not False or record['control_permitted'] is not False:
        raise ValueError('invalid capture record types')
    raw=data['capture.raw'];report=contract.analyze_o3(raw)
    rows=contract.o3.legacy.load(raw)
    if rows[0]['samples']!=(1 if phase=='qualify' else 3):raise ValueError('wrong sample contract')
    if phase=='qualify':
        if data['noargs.exit']!=b'64\n' or data['noargs.raw'] or data['noargs.stderr']!=b'Explicit --sysfs or --fixture-root required; observations only\n':
            raise ValueError('noargs qualification failed')
        reads=[r for r in rows if r.get('kind')=='read_end']
        if report['telemetry']!='BLOCKED' or len(reads)!=22 or any(r['rc']!=-1 or r['errno']!=2 or r['value']!='' for r in reads):
            raise ValueError('qualification was not an empty RAM tree')
        if report['samples'][0]['typec_census_errno']!=2:raise ValueError('invalid empty census')
    else:
        qualification=verify(session,'qualify',topology_sha,observer_sha=observer_sha,runner_sha=runner_sha)
        if read(session/'qualification.ok',65)!=(qualification['hash_index_sha256']+'\n').encode():raise ValueError('missing qualification admission')
    return {'schema':'M15-Termux-verification-v1','phase':phase,'transcript_complete':True,
            'raw_sha256':sha(raw),'raw_bytes':len(raw),'process_rc':0,'hash_index_sha256':sha(index),
            'topology_canonical_sha256':topology_digest,'telemetry':report['telemetry'],
            'readiness':'OFFLINE_FORMAT_VERIFIED_RUNTIME_ORIGIN_UNATTESTED',
            'android_termux_launch':'UNKNOWN','sender_seal_verified':False,'sealed_baseline':False,
            'control_permitted':False,'freshness':'UNKNOWN','negotiated_contract':'UNKNOWN','protection_active':'UNKNOWN'}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--session',required=True,type=Path)
    p.add_argument('--phase',required=True,choices=['qualify','acquire']);p.add_argument('--topology-file-sha256',required=True)
    p.add_argument('--admit-qualified-launch',action='store_true');a=p.parse_args()
    try:
        result=verify(a.session,a.phase,a.topology_file_sha256)
        if a.admit_qualified_launch:
            if a.phase!='qualify':raise ValueError('only qualification may be admitted')
            with (a.session/'qualification.ok').open('xb') as f:f.write((result['hash_index_sha256']+'\n').encode())
        print(json.dumps(result,indent=2))
        return 2 if a.phase=='acquire' and result['telemetry']!='READABLE' else 0
    except (ValueError,TypeError,KeyError,OSError,UnicodeError,RecursionError):
        print(json.dumps({'valid':False,'error':'invalid local acquisition evidence','sealed_baseline':False,
                          'control_permitted':False,'freshness':'UNKNOWN','negotiated_contract':'UNKNOWN',
                          'protection_active':'UNKNOWN','android_termux_launch':'UNKNOWN'}));return 1

if __name__=='__main__':raise SystemExit(main())
