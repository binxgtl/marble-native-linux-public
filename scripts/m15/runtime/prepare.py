#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Offline inventory gate for a LOCAL overlay; never builds or boots an image."""
import argparse,csv,hashlib,json,os,stat,struct
from pathlib import Path
from provenance import inventory
ROOT=Path(__file__).resolve().parents[3]
LAYOUT={'observer':'sbin/m15-observe-o3','pid1':'sbin/m15-runtime','custodian':'sbin/m15-custodian',
        'display':'sbin/m15-display','connector':'sbin/m15-connector','bootstrap':'init',
        'bootstrap_worker':'m15/bootstrap','bootstrap_supervisor':'sbin/m15-bootstrap-supervisor',
        'busybox':'bin/busybox','phase0_loader':'sbin/m10-load-phase0','tail_loader':'sbin/m15-load-m8-tail',
        'closure':'m15/closure.tsv','firmware_inventory':'m15/firmware-inventory.json',
        'topology':'m15/topology.json','source_lock':'m15/sources.lock'}
def sha(b):return hashlib.sha256(b).hexdigest()
def qualify(root,kernel,experiment="pc-admission-only"):
    root=root.resolve();paths={k:root/v for k,v in LAYOUT.items()};paths['kernel']=kernel
    for role,p in paths.items():
        if p.is_symlink() or not p.is_file() or (role!='kernel' and not p.resolve().is_relative_to(root)):raise ValueError('missing/nonregular '+role)
    for role in ('bootstrap','bootstrap_worker'):
        b=paths[role].read_bytes()
        if not b.startswith(b'#!/bin/busybox sh\n') or b'\r' in b:raise ValueError('bootstrap LF/shebang '+role)
    for role in ('observer','pid1','custodian','display','connector','bootstrap_supervisor','busybox','phase0_loader','tail_loader'):
        p=paths[role];b=p.read_bytes()
        if b[:6]!=b'\x7fELF\x02\x01' or struct.unpack_from('<H',b,18)[0]!=183:raise ValueError('ARM64 ELF '+role)
        off=struct.unpack_from('<Q',b,32)[0];size,count=struct.unpack_from('<HH',b,54)
        if size!=56 or count<1 or off+size*count>len(b):raise ValueError('ELF headers '+role)
        if any(struct.unpack_from('<I',b,off+i*size)[0]==3 for i in range(count)):raise ValueError('dynamic interpreter '+role)
        if any(marker in b for marker in (b'M15_FIXTURE_ROOT\0',b'M15_TEST_BUDGET\0',b'M15_BOOT_WORKER\0')):raise ValueError('fixture binary '+role)
        # Windows local staging sets CPIO modes independently of NTFS metadata.
        if os.name!='nt' and not p.stat().st_mode&stat.S_IXUSR:raise ValueError('executable mode '+role)
    if sha(paths['observer'].read_bytes())!='5d061f9ca33b985c659c1bd76c130505a58d8b89c0861f3df5aa4e78b028ec12':raise ValueError('frozen O3 identity')
    if paths['closure'].read_bytes()!=(ROOT/'manifests/m8-usb-battery-closure.tsv').read_bytes():raise ValueError('M8 closure drift')
    rows=list(csv.DictReader(paths['closure'].read_text().splitlines(),delimiter='\t'))
    if len(rows)!=100:raise ValueError('closure count')
    modules=root/'lib/modules'
    if {p.name for p in modules.iterdir()}!={r['module'] for r in rows}:raise ValueError('exact module set')
    for r in rows:
        p=modules/r['module']
        if p.is_symlink() or not p.is_file():raise ValueError('module path')
        b=p.read_bytes()
        if len(b)!=int(r['size']) or sha(b)!=r['sha256']:raise ValueError('module inventory '+r['module'])
    fw=json.loads(paths['firmware_inventory'].read_text())
    if set(fw)!={'schema','files','source_sha256'} or fw['schema']!='M15-firmware-inventory-v1' or not fw['files']:raise ValueError('firmware inventory')
    if type(fw['source_sha256'])!=str or len(fw['source_sha256'])!=64 or any(c not in '0123456789abcdef' for c in fw['source_sha256']):raise ValueError('firmware source hash')
    known=set()
    for r in fw['files']:
        if set(r)!={'path','bytes','sha256'} or r['path'] in known:raise ValueError('firmware entry')
        known.add(r['path']);p=root/r['path']
        if not r['path'].startswith('m6/modem/image/') or p.resolve().is_relative_to(root) is False or p.is_symlink():raise ValueError('firmware path')
        b=p.read_bytes()
        if len(b)!=r['bytes'] or sha(b)!=r['sha256']:raise ValueError('firmware hash')
    if 'm6/modem/image/adsp2.mdt' not in known:raise ValueError('ADSP firmware identity')
    return inventory(paths,experiment=experiment)
if __name__=='__main__':
    a=argparse.ArgumentParser(description=__doc__);a.add_argument('--root',type=Path,required=True);a.add_argument('--kernel',type=Path,required=True);a.add_argument('--experiment',choices=('pc-admission-only','pc-wall-pc'),default='pc-admission-only');x=a.parse_args()
    m=qualify(x.root,x.kernel,x.experiment)
    meta=x.root/'m15/metadata.json'
    with meta.open('x',encoding='utf-8',newline='\n') as f:json.dump(m,f,sort_keys=True,separators=(',',':'));f.write('\n')
    with (x.root/'m15/experiment').open('x',encoding='ascii',newline='\n') as f:f.write(x.experiment+'\n')
    files=[]
    for p in sorted(x.root.rglob('*')):
        if p.is_symlink():raise ValueError('overlay symlink')
        if p.is_file():files.append((p.relative_to(x.root).as_posix(),sha(p.read_bytes())))
    with (x.root/'m15/files.sha256').open('x',encoding='ascii',newline='\n') as f:
        for p,h in files:f.write(h+'  '+p+'\n')
    print(json.dumps({'inventory_complete':True,'candidate_ready':False,'recovery_review_required':True,'control_permitted':False}))
