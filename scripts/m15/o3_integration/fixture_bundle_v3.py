#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Versioned synthetic O3 fixture bundle. No exploratory-to-baseline conversion."""
import argparse
import copy
import json
from pathlib import Path
import contract
from compat import M15

HERE=Path(__file__).resolve().parent
def pretty(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
def capture(environment):
    src=M15/'phaseb/topology/fixtures'/f'{environment}.synthetic.jsonl'
    rows=contract.o3.legacy.load(src.read_bytes())
    for row in rows:
        row['schema']=row['schema'].replace('M15O2','M15O3')
        if row.get('kind')=='start':row['power_supply_contract']=contract.POWER_CONTRACT
        if row.get('kind')!='read_end':continue
        changes={'usb/type':'USB_PD','usb/usb_type':'Unknown SDP [PD_PPS]','battery/capacity':'35',
                 'battery/temp':'367' if environment=='android' else '368',
                 'usb/voltage_now':'8432000' if environment=='android' else '8477000',
                 'battery/current_now':'-3668000' if environment=='android' else '-4127000',
                 'usb/current_now':'0','usb/current_max':'4500000','pdo2':'0002d12c','apdo_max':'33'}
        if row['path'] in changes:row.update(value=changes[row['path']],rc=0,errno=0)
    raw=b''.join((json.dumps(row,separators=(',',':'))+'\n').encode() for row in rows)
    contract.analyze_o3(raw)
    return raw

def bundle():
    manifest={'schema':'M15-topology-v2','charger_inventory_sha256':'1'*64,'cable_inventory_sha256':'2'*64,
              'instrumentation_inventory_sha256':'3'*64,'power_source':'pc-usb','evidence_path':'direct-usb',
              'observation_schema':contract.OBSERVATION,'power_supply_contract':contract.POWER_CONTRACT}
    other=copy.deepcopy(manifest);other['power_source']='wall-charger'
    a=capture('android');n=capture('native')
    data={'topology.synthetic.json':pretty(manifest),'topology-mismatch.synthetic.json':pretty(other),
          'android.synthetic.jsonl':a,'native.synthetic.jsonl':n,
          'android.context.synthetic.json':pretty(contract.make_context(manifest,a,'android')),
          'native.context.synthetic.json':pretty(contract.make_context(manifest,n,'native')),
          'native-mismatch.context.synthetic.json':pretty(contract.make_context(other,n,'native')),
          'expected.synthetic.json':pretty({'schema':'M15O3-integration-fixture-expectations-v1','synthetic_only':True,
                                           'reported_supply_type':'USB_PD','eligible_result':'ELIGIBLE',
                                           'mismatch_result':'BLOCKED','field_count':27,'duration_ms':112,
                                           'unavailable':['qcom-battery/power_max']})}
    data['provenance.synthetic.json']=pretty({'schema':'M15O3-integration-fixture-bundle-v1','synthetic_only':True,
                                            'sealed_baseline':False,'source':'Previously qualified synthetic O2 scaffolding, with explicit O3 headers and synthetic endpoint values. No phone execution or reconstructed Termux samples.',
                                            'environment_labels':'Synthetic comparison roles only; not evidence of Android execution.',
                                            'files':{name:{'bytes':len(raw),'sha256':contract.legacy_topology.sha256(raw)}
                                                     for name,raw in sorted(data.items())}})
    return data

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',required=True,type=Path);a=p.parse_args()
    if a.out.exists() and any(a.out.iterdir()):p.error('output directory must be empty')
    data=bundle();a.out.mkdir(parents=True,exist_ok=True)
    for name,raw in data.items():(a.out/name).write_bytes(raw)
    print(json.dumps({'synthetic_only':True,'files':len(data),'sealed_baseline':False,**contract.restrictions()}));return 0

if __name__=='__main__':raise SystemExit(main())
