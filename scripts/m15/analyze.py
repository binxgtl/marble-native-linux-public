#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Strict offline M15O1 observation replay. Never grants a charger control gate."""
import argparse
import hashlib
import json
import re
from pathlib import Path

POWER_FIELDS = {
    'battery/type':'text', 'battery/present':'bool', 'battery/status':'text',
    'battery/health':'text', 'battery/capacity':'percent', 'battery/voltage_now':'uV',
    'battery/current_now':'uA', 'battery/temp':'deciC',
    'battery/charge_control_limit':'index', 'battery/charge_control_limit_max':'index',
    'usb/type':'text', 'usb/online':'bool', 'usb/usb_type':'selection',
    'usb/voltage_now':'uV', 'usb/current_now':'uA', 'usb/voltage_max':'uV',
    'usb/current_max':'uA', 'usb/input_current_limit':'uA', 'usb/temp':'deciC',
}
USB_TYPES = {'Unknown','SDP','DCP','CDP','ACA','C','PD','PD_DRP','PD_PPS','BrickID','USB_FLOAT'}

def integer(text):
    if not re.fullmatch(r'-?(0|[1-9][0-9]*)',text):
        raise ValueError('invalid integer')
    value=int(text)
    if not -(2**31)<=value<2**31:
        raise ValueError('integer overflow')
    return value

def selected(text):
    tokens=text.split(' ')
    active=[]
    if not tokens or len(tokens)!=len(set(tokens)):
        raise ValueError('duplicate/empty USB type list')
    seen=set()
    for token in tokens:
        bracket=token.startswith('[') and token.endswith(']')
        value=token[1:-1] if bracket else token
        if value not in USB_TYPES or value in seen:
            raise ValueError('unknown/duplicate USB type')
        seen.add(value)
        if bracket:active.append(value)
    if len(active)!=1:raise ValueError('USB type has no unique selection')
    return active[0]

def no_duplicate_keys(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError('duplicate JSON key')
        result[key]=value
    return result

def analyze(raw):
    if not raw.endswith(b'\n') or len(raw)>2_000_000:
        raise ValueError('truncated/oversized transcript')
    lines=raw.decode('utf-8',errors='strict').splitlines()
    rows=[json.loads(line,object_pairs_hook=no_duplicate_keys) for line in lines]
    if any(not isinstance(row,dict) for row in rows):raise ValueError('record is not an object')
    expected={'schema':'M15O1-supervisor','reaped':True,'raw_status':0,'errno':0,'control_permitted':False}
    if not rows or rows[-1]!=expected:raise ValueError('missing/invalid supervisor receipt')
    rows.pop()
    if len(rows)<2 or rows[0].get('kind')!='start' or rows[-1].get('kind')!='end':
        raise ValueError('missing start/end')
    samples=rows[0].get('samples')
    if type(samples)!=int or not 1<=samples<=10 or rows[0].get('power_fields')!=len(POWER_FIELDS):
        raise ValueError('invalid observation contract')
    if rows[0].get('control_permitted') is not False or rows[-1].get('control_permitted') is not False:
        raise ValueError('control permission forbidden')
    if rows[-1].get('records')!=len(rows) or rows[-1].get('sample')!=samples-1:
        raise ValueError('final count mismatch')
    current=0;pending=None;previous=-1;data=[{} for _ in range(samples)];inventory=set();census=[]
    ports=[set() for _ in range(samples)]
    for seq,row in enumerate(rows):
        if row.get('schema')!='M15O1' or type(row.get('seq'))!=int or row['seq']!=seq:
            raise ValueError(f'sequence/schema at record {seq}')
        stamp=row.get('mono_ms')
        if type(stamp)!=int or stamp<previous:raise ValueError('nonmonotonic time')
        previous=stamp
        if seq in (0,len(rows)-1):continue
        sample=row.get('sample')
        if type(sample)!=int or sample!=current or sample>=samples:
            raise ValueError('invalid sample order')
        kind=row.get('kind')
        if kind=='typec_inventory':
            if pending or sample in inventory:raise ValueError('inventory order')
            count=row.get('ports');err=row.get('errno')
            if type(count)!=int or type(err)!=int or count<0 or count>8 or err<0:
                raise ValueError('bad Type-C census')
            if count!=len(ports[sample]):raise ValueError('incomplete Type-C census')
            if set(POWER_FIELDS)-set(data[sample]):raise ValueError('missing power field')
            for port in ports[sample]:
                if any(f'{port}/{n}' not in data[sample] for n in ('power_role','data_role','power_operation_mode')):
                    raise ValueError('missing port field')
            inventory.add(sample);census.append(row);current+=1;continue
        group=row.get('group');path=row.get('path')
        if group=='power_supply' and path in POWER_FIELDS:unit=POWER_FIELDS[path]
        elif group=='typec' and isinstance(path,str) and re.fullmatch(r'port[0-9]+/(power_role|data_role|power_operation_mode)',path):
            unit='text';ports[sample].add(path.split('/')[0])
        else:raise ValueError('non-allowlisted field')
        if kind=='read_begin':
            if pending or path in data[sample]:raise ValueError('duplicate/busy field')
            pending=(sample,group,path)
        elif kind=='read_end':
            if pending!=(sample,group,path):raise ValueError('unmatched read')
            rc,err,value=row.get('rc'),row.get('errno'),row.get('value')
            if type(rc)!=int or type(err)!=int or not isinstance(value,str) or row.get('unit')!=unit:
                raise ValueError('invalid read result')
            if not ((rc==0 and err==0) or (rc==-1 and 0<err<4096 and value=='')):
                raise ValueError('inconsistent read errno')
            if len(value)>512 or '\0' in value:raise ValueError('invalid value')
            data[sample][path]=row;pending=None
        else:raise ValueError('unexpected record')
    if pending or inventory!=set(range(samples)):raise ValueError('incomplete acquisition')
    details=[];telemetry=True
    for sample,snapshot in enumerate(data):
        errors=[];values={}
        for path,unit in POWER_FIELDS.items():
            row=snapshot[path]
            if row['rc']:
                errors.append(f'{path}: errno={row["errno"]}');continue
            try:values[path]=integer(row['value']) if unit not in ('text','selection') else row['value']
            except ValueError:errors.append(f'{path}: invalid integer')
        def require(condition,message):
            if not condition:errors.append(message)
        require(values.get('battery/type')=='Battery','battery type unverified')
        require(values.get('usb/type')=='USB','USB supply type unverified')
        require(values.get('battery/present')==1,'battery not present')
        require(values.get('usb/online')==1,'USB not online')
        require(values.get('battery/health')=='Good','battery health not Good')
        require(values.get('battery/status') in ('Charging','Full','Not charging','Discharging'),'battery status unknown')
        require(0<=values.get('battery/capacity',-1)<=100,'capacity invalid')
        # Plausibility is not a safe operating envelope or permission to charge.
        require(0<values.get('battery/voltage_now',0)<20_000_000,'battery voltage implausible')
        require(-1000<values.get('battery/temp',-1001)<2000,'battery temperature implausible')
        require(0<=values.get('battery/charge_control_limit',-1)<values.get('battery/charge_control_limit_max',-2),'thermal index invalid')
        for name in ('voltage_now','voltage_max','current_max','input_current_limit'):
            require(values.get('usb/'+name,-1)>=0,'USB '+name+' invalid')
        try:active=selected(values.get('usb/usb_type',''))
        except ValueError:active=None;errors.append('USB type selection invalid')
        if errors:telemetry=False
        details.append({'reported_usb_type':active,'errors':errors,
                        'reported_pd_type':active in ('PD','PD_DRP','PD_PPS'),
                        'typec_census_errno':census[sample]['errno'],
                        'typec_fields':{p:{'value':r['value'],'errno':r['errno']}
                                        for p,r in snapshot.items() if p.startswith('port')}})
    return {'schema':'M15-observation-report-v1','raw_sha256':hashlib.sha256(raw).hexdigest(),
            'raw_bytes':len(raw),'records':len(rows),'samples':details,
            'transcript_complete':True,'telemetry':'READABLE' if telemetry else 'BLOCKED',
            'freshness':'UNKNOWN','negotiated_contract':'UNKNOWN','protection_active':'UNKNOWN',
            'charging_hardware_pass':False,'control_permitted':False,
            'limit_semantics':'reported values and thermal indices; not PDO/APDO, RDO or safety limits'}

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('capture',type=Path);args=parser.parse_args()
    try:result=analyze(args.capture.read_bytes())
    except (ValueError,KeyError,TypeError) as error:
        print(json.dumps({'transcript_complete':False,'error':str(error),'control_permitted':False}));return 1
    print(json.dumps(result,indent=2));return 0 if result['telemetry']=='READABLE' else 2

if __name__=='__main__':raise SystemExit(main())
