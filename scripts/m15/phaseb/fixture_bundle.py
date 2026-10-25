#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Generate only deterministic synthetic topology/captures; no baseline runner."""
import argparse
import copy
import json
from pathlib import Path
import replay
import topology

HERE=Path(__file__).resolve().parent
def pretty(obj):return (json.dumps(obj,sort_keys=True,indent=2)+'\n').encode()

def capture(environment):
    # Source is the locked synthetic O1 fixture, never a live /sys snapshot.
    old=replay.load((HERE/'fixtures/m15o1-synthetic.jsonl').read_bytes())
    values={r['path']:r['value'] for r in old if r.get('kind')=='read_end'}
    origin=1000 if environment=='android' else 987655321
    rows=[]
    def record(kind,**fields):
        row={'schema':'M15O2','seq':len(rows),'kind':kind,'sample':0,'mono_ms':origin+len(rows)*2}
        row.update(fields);rows.append(row)
    def pair(group,path,unit,value,rc=0,err=0,optional=False):
        record('read_begin',group=group,path=path)
        result={'group':group,'path':path,'unit':unit,'value':value,'rc':rc,'errno':err}
        if optional:result['value_valid']=not rc
        record('read_end',**result)
    record('start',samples=1,power_fields=19,control_permitted=False,
           extension='vendor-partner-v1',vendor_fields=3,partner_fields_per_port=2)
    for path,unit in replay.o1.POWER_FIELDS.items():
        value='350000' if environment=='native' and path=='usb/current_now' else values[path]
        pair('power_supply',path,unit,value)
    for name,unit in replay.VENDOR.items():
        value='00019032' if name=='pdo2' else ('32' if environment=='native' else '33')
        error=environment=='native' and name=='power_max'
        pair('qcom-battery',name,unit,'' if error else value,rc=-1 if error else 0,err=5 if error else 0,optional=True)
    for name,value in zip(replay.ROLES,('[sink] source','[device] host','usb_power_delivery')):
        pair('typec','port0/'+name,'text',value)
    for name,value in zip(replay.PARTNER,('yes','3.0')):
        pair('typec','port0-partner/'+name,'text',value,optional=True)
    record('typec_inventory',ports=1,errno=0)
    record('end',records=len(rows)+1,control_permitted=False)
    rows.append({'schema':'M15O2-supervisor','reaped':True,'raw_status':0,'errno':0,'control_permitted':False})
    raw=b''.join((json.dumps(row,separators=(',',':'))+'\n').encode() for row in rows)
    replay.analyze(raw)
    return raw

def bundle():
    manifest={'schema':'M15-topology-v1','charger_inventory_sha256':'1'*64,'cable_inventory_sha256':'2'*64,
              'instrumentation_inventory_sha256':'3'*64,'power_source':'pc-usb','evidence_path':'direct-usb'}
    other=copy.deepcopy(manifest);other['power_source']='wall-charger'
    a=capture('android');n=capture('native')
    data={'topology-pc.synthetic.json':pretty(manifest),'topology-wall.synthetic.json':pretty(other),
          'android.synthetic.jsonl':a,'native.synthetic.jsonl':n,
          'android.context.synthetic.json':pretty(topology.make_context(manifest,a,'android')),
          'native.context.synthetic.json':pretty(topology.make_context(manifest,n,'native')),
          'native-mismatch.context.synthetic.json':pretty(topology.make_context(other,n,'native')),
          'expected.synthetic.json':pretty({'schema':'M15-fixture-expectations-v1','synthetic_only':True,
                                           'eligible_result':'ELIGIBLE','mismatch_result':'BLOCKED',
                                           'observed_differences':['power_supply/usb/current_now','qcom-battery/apdo_max'],
                                           'unavailable':['qcom-battery/power_max'],
                                           'field_count':27,'duration_ms':112})}
    data['provenance.synthetic.json']=pretty({'schema':'M15-fixture-bundle-v1','synthetic_only':True,
                                            'description':'No Android/native device was executed; labels are synthetic comparison roles.',
                                            'files':{name:{'bytes':len(raw),'sha256':topology.sha256(raw)}
                                                     for name,raw in sorted(data.items())}})
    return data

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',required=True,type=Path);a=p.parse_args()
    if a.out.exists() and any(a.out.iterdir()):p.error('output directory must be empty')
    a.out.mkdir(parents=True,exist_ok=True)
    data=bundle()
    for name,raw in data.items():(a.out/name).write_bytes(raw)
    print(json.dumps({'synthetic_only':True,'files':len(data),**topology.restrictions()}))
    return 0

if __name__=='__main__':raise SystemExit(main())
