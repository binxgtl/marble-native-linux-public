#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Independent strict finite-file decoder; no receiver/device or resynchronization."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent/'o3_integration'))
import contract

NAMES=('capture.raw','capture.stderr','lifecycle.txt','metadata.json','status.txt','kernel.txt')
LIMITS=(2_000_000,262144,1048576,8192,256,8388608)
FIELDS={'schema','synthetic_only','launcher','evidence_path','observation_schema','power_supply_contract',
        'freshness','negotiated_contract','protection_active','sealed_baseline','control_permitted'}
def sha(p):return hashlib.sha256(p).hexdigest()

def decode(raw):
    if len(raw)>16*1024*1024:raise ValueError('wire-budget')
    at=0
    def line():
        nonlocal at
        end=raw.find(b'\n',at,at+1024)
        if end<0:raise ValueError('missing-line-boundary')
        result=raw[at:end];at=end+1;return result
    def number(p):
        if not re.fullmatch(rb'0|[1-9][0-9]{0,9}',p):raise ValueError('noncanonical-integer')
        return int(p)
    first=re.fullmatch(rb'M15E1 ([0-9a-f]{32}) ([0-9a-f]{64}) 6',line())
    if not first or first[1]==b'0'*32:raise ValueError('version-or-nonce')
    manifest=[]
    for i in range(6):
        row=line().split(b' ')
        if len(row)!=4 or row[0]!=b'I' or row[1]!=str(i).encode() or not re.fullmatch(rb'[0-9a-f]{64}',row[3]):
            raise ValueError('manifest-contract')
        size=number(row[2])
        if size>LIMITS[i]:raise ValueError('file-budget')
        manifest.append((size,row[3].decode()))
    if line()!=b'END':raise ValueError('manifest-end')
    manifest_hash=sha(raw[:at]);files=[bytearray() for _ in range(6)];seq=0
    for file,(size,digest) in enumerate(manifest):
        while len(files[file])<size:
            row=line().split(b' ')
            if len(row)!=5 or row[0]!=b'D':raise ValueError('frame-header')
            s,f,off,n=map(number,row[1:])
            if s!=seq or f!=file or off!=len(files[file]) or n!=min(1024,size-off):raise ValueError('sequence-file-offset-length')
            if at+n>len(raw):raise ValueError('truncated-file')
            files[file].extend(raw[at:at+n]);at+=n;seq+=1
        if sha(files[file])!=digest:raise ValueError('original-file-digest')
    prefix=at
    final=line().split(b' ')
    if len(final)!=5 or final[0]!=b'F' or at!=len(raw):raise ValueError('missing-final-or-trailing-data')
    if number(final[1])!=seq or number(final[2])!=prefix or final[3]!=manifest_hash.encode():raise ValueError('final-count-manifest')
    suffix=f'M15E1 FINAL\nframes={seq} bytes={prefix} manifest={manifest_hash}\n'.encode()
    digest=sha(raw[:prefix]+suffix)
    if final[4]!=digest.encode():raise ValueError('transfer-digest')
    data=dict(zip(NAMES,map(bytes,files)))
    if sha(data['metadata.json'])!=first[2].decode():raise ValueError('native-instrumentation-binding')
    metadata=json.loads(data['metadata.json'],object_pairs_hook=contract.o3.legacy.o1.no_duplicate_keys)
    if set(metadata)!=FIELDS or metadata['schema']!='M15-native-phase1-metadata-v1' or metadata['synthetic_only'] is not True:
        raise ValueError('phase1-synthetic-metadata-only')
    if metadata['launcher']!='offline-subreaper' or metadata['evidence_path']!='ram-escrow-deferred-export':raise ValueError('instrumentation-mismatch')
    if metadata['observation_schema']!='M15O3' or metadata['power_supply_contract']!='usb-or-usb-pd-v1':raise ValueError('observation-version')
    if metadata['sealed_baseline'] is not False or metadata['control_permitted'] is not False:raise ValueError('safety-flags')
    if any(metadata[k]!='UNKNOWN' for k in ('freshness','negotiated_contract','protection_active')):raise ValueError('unknowns-promoted')
    if data['capture.stderr']:raise ValueError('collector-stderr')
    status=re.fullmatch(rb'wait_status=0\ntracked=([1-9][0-9]?)\nreaped=([1-9][0-9]?)\ncensus_closed=1\n',data['status.txt'])
    if not status or int(status[1])!=int(status[2]) or int(status[1])>16:raise ValueError('owner-status')
    phase='PC_WAIT';owners={};previous=-1
    for row in data['lifecycle.txt'].splitlines():
        m=re.fullmatch(rb'(0|[1-9][0-9]*) ([A-Z_]+) (0|[1-9][0-9]*) (0|[1-9][0-9]*)',row)
        if not m:raise ValueError('lifecycle-format')
        time,event,identity,wait=int(m[1]),m[2].decode(),int(m[3]),int(m[4])
        if time<previous or wait!=0:raise ValueError('lifecycle-time-or-failure')
        previous=time
        if event in ('PC_WAIT','PC_ACK','ISOLATED','COLLECT'):
            order=['PC_WAIT','PC_ACK','ISOLATED','COLLECT']
            if event!=phase or identity!=0:raise ValueError('lifecycle-order')
            phase=order[order.index(event)+1] if event!='COLLECT' else 'OWNERS'
        elif event=='OWN':
            if phase!='OWNERS' or not identity or identity in owners:raise ValueError('lifecycle-owner')
            owners[identity]=False
        elif event=='REAP':
            if phase!='OWNERS' or identity not in owners or owners[identity]:raise ValueError('lifecycle-reap')
            owners[identity]=True
        elif event=='FREEZE':
            if phase!='OWNERS' or not owners or not all(owners.values()) or identity!=0:raise ValueError('lifecycle-freeze')
            phase='FROZEN'
        else:raise ValueError('lifecycle-event')
    if phase!='FROZEN' or len(owners)!=int(status[1]) or not data['lifecycle.txt'].endswith(b'\n'):raise ValueError('lifecycle-incomplete')
    # Structurally independent O3 replay, never trust the sender's receipt-tail check.
    report=contract.analyze_o3(data['capture.raw'])
    if not report['transcript_complete']:raise ValueError('incomplete-o3')
    if contract.o3.legacy.load(data['capture.raw'])[0]['samples']!=3:raise ValueError('three-sample-contract')
    ack=f'M15ACK1 {first[1].decode()} {manifest_hash} {digest}\n'.encode()
    return data,{'schema':'M15-native-phase1-host-verification-v1','files':{k:{'bytes':len(v),'sha256':sha(v)} for k,v in data.items()},
                 'manifest_sha256':manifest_hash,'transfer_sha256':digest,'frames':seq,'wire_bytes':len(raw),
                 'telemetry':report['telemetry'],'framing_complete':True,'synthetic_only':True,
                 'device_safety':'UNKNOWN','physical_usb_delivery':'UNKNOWN','sender_authentication':'UNKNOWN',
                 'sealed_baseline':False,'control_permitted':False,'freshness':'UNKNOWN',
                 'negotiated_contract':'UNKNOWN','protection_active':'UNKNOWN'},ack

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('wire',type=Path)
    p.add_argument('--ack',type=Path);a=p.parse_args()
    try:
        with a.wire.open('rb') as f:raw=f.read(16*1024*1024+1)
        _,report,ack=decode(raw)
        if a.ack:
            with a.ack.open('xb') as f:f.write(ack)
        print(json.dumps(report,indent=2));return 0
    except (ValueError,TypeError,KeyError,OSError,RecursionError):
        print(json.dumps({'valid':False,'error':'invalid finite-file evidence','control_permitted':False,'sealed_baseline':False}));return 1
if __name__=='__main__':raise SystemExit(main())
