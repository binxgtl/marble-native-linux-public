#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Native runtime metadata. Expected build identity is not runtime attestation."""
import argparse,hashlib,json
from pathlib import Path
ROLES={'observer','pid1','custodian','display','connector','bootstrap','busybox',
       'bootstrap_worker','bootstrap_supervisor','phase0_loader','tail_loader','kernel','closure','firmware_inventory','topology','source_lock'}
EXECUTABLES={'observer','pid1','custodian','display','connector','bootstrap','busybox',
             'bootstrap_worker','bootstrap_supervisor','phase0_loader','tail_loader'}
FIELDS={'schema','synthetic_only','launcher','evidence_path','observation_schema',
        'power_supply_contract','freshness','negotiated_contract','protection_active',
        'sealed_baseline','control_permitted','connector_contract','charger_identity',
        'runtime_kernel_identity_verified','inventory','kernel_coverage','experiment'}
def validate(m,allow_fixture=False):
    if type(m)!=dict or set(m)!=FIELDS:raise ValueError('native-metadata-fields')
    fixed={'schema':'M15-native-runtime-metadata-v1','launcher':'dedicated-custodian',
           'evidence_path':'same-boot-ram-escrow-acm','observation_schema':'M15O3',
           'power_supply_contract':'usb-or-usb-pd-v1','connector_contract':'kernel-typec-partner-v1',
           'charger_identity':'operator-reported','kernel_coverage':'startup-backlog-through-pre-freeze'}
    if any(m[k]!=v for k,v in fixed.items()):raise ValueError('native-metadata-contract')
    if m['experiment'] not in ('pc-admission-only','pc-wall-pc'):raise ValueError('native-experiment')
    if type(m['synthetic_only'])!=bool or (m['synthetic_only'] and not allow_fixture):raise ValueError('fixture-not-runtime')
    if any(m[k] is not False for k in ('sealed_baseline','control_permitted','runtime_kernel_identity_verified')):raise ValueError('native-flags')
    if any(m[k]!='UNKNOWN' for k in ('freshness','negotiated_contract','protection_active')):raise ValueError('native-unknown-promoted')
    if type(m['inventory'])!=dict or set(m['inventory'])!=ROLES:raise ValueError('native-inventory-roles')
    for role,v in m['inventory'].items():
        if type(v)!=dict or set(v)!={'bytes','sha256','expected_cpio_mode'} or type(v['bytes'])!=int or not 0<v['bytes']<2**32:raise ValueError('native-inventory-size')
        mode=None if role=='kernel' else '0755' if role in EXECUTABLES else '0644'
        if v['expected_cpio_mode']!=mode:raise ValueError('native-inventory-mode')
        h=v['sha256']
        if type(h)!=str or len(h)!=64 or any(c not in '0123456789abcdef' for c in h):raise ValueError('native-inventory-hash')
    return m
def inventory(paths,fixture=False,experiment="pc-admission-only"):
    if set(paths)!=ROLES:raise ValueError('native-role-set')
    facts={}
    for role,path in paths.items():
        p=Path(path)
        if p.is_symlink() or not p.is_file():raise ValueError('native-regular-input')
        b=p.read_bytes();facts[role]={'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),
                                    'expected_cpio_mode':None if role=='kernel' else '0755' if role in EXECUTABLES else '0644'}
    m={'experiment':experiment,'schema':'M15-native-runtime-metadata-v1','synthetic_only':fixture,'launcher':'dedicated-custodian',
       'evidence_path':'same-boot-ram-escrow-acm','observation_schema':'M15O3','power_supply_contract':'usb-or-usb-pd-v1',
       'freshness':'UNKNOWN','negotiated_contract':'UNKNOWN','protection_active':'UNKNOWN','sealed_baseline':False,
       'control_permitted':False,'connector_contract':'kernel-typec-partner-v1','charger_identity':'operator-reported',
       'runtime_kernel_identity_verified':False,'inventory':facts,'kernel_coverage':'startup-backlog-through-pre-freeze'}
    return validate(m,fixture)
if __name__=='__main__':
    a=argparse.ArgumentParser(description=__doc__);a.add_argument('--paths',type=Path,required=True);a.add_argument('--out',type=Path,required=True);x=a.parse_args()
    m=inventory(json.loads(x.paths.read_text(encoding='utf-8')))
    with x.out.open('x',encoding='utf-8',newline='\n') as f:json.dump(m,f,sort_keys=True,separators=(',',':'));f.write('\n')
