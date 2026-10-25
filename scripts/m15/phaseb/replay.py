#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""M15O2 strict extension; O1 replay delegates to the byte-preserved O1 decoder."""
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import analyze as o1

VENDOR={'pdo2':'hex32','apdo_max':'vendor_raw_u32','power_max':'vendor_raw_u32'}
PARTNER=('supports_usb_power_delivery','usb_power_delivery_revision')
ROLES=('power_role','data_role','power_operation_mode')
COMMON={'schema','seq','kind','sample','mono_ms'}

def load(raw):
    if not raw.endswith(b'\n') or len(raw)>2_000_000:raise ValueError('truncated/oversized transcript')
    rows=[json.loads(line,object_pairs_hook=o1.no_duplicate_keys) for line in raw.decode('utf-8',errors='strict').splitlines()]
    if not rows or any(type(row)!=dict for row in rows):raise ValueError('record is not an object')
    return rows

def optional_field(row):
    group,path=row.get('group'),row.get('path')
    if group=='qcom-battery' and path in VENDOR:return VENDOR[path]
    if (group=='typec' and isinstance(path,str)
        and re.fullmatch(r'port[0-9]+-partner/('+'|'.join(PARTNER)+')',path)):return 'text'
    return None

def format_value(group,path,value):
    if group=='qcom-battery':
        if path=='pdo2':
            if not re.fullmatch(r'[a-fA-F0-9]{8}',value):raise ValueError('invalid vendor hex32')
            return int(value,16)
        if not re.fullmatch(r'0|[1-9][0-9]*',value) or int(value)>2**32-1:
            raise ValueError('invalid vendor u32')
        return int(value)
    if path.endswith('/supports_usb_power_delivery'):
        if value not in ('yes','no'):raise ValueError('invalid partner flag')
        return value=='yes'
    if not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)',value):raise ValueError('invalid partner revision')
    major,minor=map(int,value.split('.'))
    if major>255 or minor>15:raise ValueError('invalid partner revision range')
    return value

def analyze(raw):
    rows=load(raw)
    if rows[0].get('schema')=='M15O1':
        # Compatibility: exact O1 success/error behavior and result shape.
        return o1.analyze(raw)
    if rows[0].get('schema')!='M15O2':raise ValueError('unsupported schema')
    terminal={'schema':'M15O2-supervisor','reaped':True,'raw_status':0,'errno':0,'control_permitted':False}
    if rows[-1]!=terminal or any(type(rows[-1][k]) is not type(v) for k,v in terminal.items()):
        raise ValueError('missing/invalid O2 supervisor receipt')
    body=rows[:-1]
    if len(body)<2 or body[0].get('kind')!='start' or body[-1].get('kind')!='end':raise ValueError('missing start/end')
    samples=body[0].get('samples')
    if type(samples)!=int or not 1<=samples<=10:raise ValueError('invalid samples')
    start=body[0]
    if (set(start)!=COMMON|{'samples','power_fields','control_permitted','extension','vendor_fields','partner_fields_per_port'}
        or start['extension']!='vendor-partner-v1' or type(start['vendor_fields'])!=int
        or start['vendor_fields']!=len(VENDOR) or type(start['partner_fields_per_port'])!=int
        or start['partner_fields_per_port']!=len(PARTNER)):raise ValueError('extension contract drift')
    if (set(body[-1])!=COMMON|{'records','control_permitted'} or type(body[-1]['records'])!=int
        or body[-1]['records']!=len(body)):raise ValueError('final count/structure drift')
    if start['control_permitted'] is not False or body[-1]['control_permitted'] is not False:
        raise ValueError('control permission forbidden')
    retained=[];pending=None;seen=[{} for _ in range(samples)];current=0;previous=-1
    ports=[set() for _ in range(samples)];read_order=[[] for _ in range(samples)]
    elapsed=[];origin=start.get('mono_ms')
    for seq,row in enumerate(body):
        if row.get('schema')!='M15O2' or type(row.get('seq'))!=int or row['seq']!=seq:raise ValueError('O2 sequence/schema')
        stamp=row.get('mono_ms');sample=row.get('sample');kind=row.get('kind')
        if type(stamp)!=int or stamp<0 or stamp<previous:raise ValueError('nonmonotonic timestamp')
        previous=stamp
        if type(sample)!=int or sample!=min(current,samples-1):raise ValueError('sample order')
        if seq in (0,len(body)-1):
            if pending:raise ValueError('unclosed read')
            retained.append(row.copy());continue
        if current>=samples:raise ValueError('extra sample')
        if kind=='typec_inventory':
            if set(row)!=COMMON|{'ports','errno'} or pending:raise ValueError('invalid census')
            expected=[('power_supply',p) for p in o1.POWER_FIELDS]
            expected += [('qcom-battery',p) for p in VENDOR]
            for port in sorted(ports[sample]):
                expected += [('typec',f'{port}/{p}') for p in ROLES]
                expected += [('typec',f'{port}-partner/{p}') for p in PARTNER]
            if read_order[sample]!=expected:raise ValueError('missing/duplicate/reordered required or optional pair')
            current+=1;retained.append(row.copy());continue
        group,path=row.get('group'),row.get('path');unit=optional_field(row)
        if not unit:
            if group=='power_supply' and path in o1.POWER_FIELDS:unit=o1.POWER_FIELDS[path]
            elif group=='typec' and isinstance(path,str) and re.fullmatch(r'port[0-9]+/('+'|'.join(ROLES)+')',path):
                unit='text';ports[sample].add(path.split('/')[0])
            else:raise ValueError('non-allowlisted/private field')
        optional=optional_field(row) is not None
        key=(group,path)
        if kind=='read_begin':
            if set(row)!=COMMON|{'path','group'} or pending or key in seen[sample]:raise ValueError('invalid/duplicate begin')
            pending=(key,stamp);read_order[sample].append(key)
        elif kind=='read_end':
            keys=COMMON|{'path','group','unit','rc','errno','value'}|({'value_valid'} if optional else set())
            if set(row)!=keys or pending is None or pending[0]!=key:raise ValueError('unmatched/extended read')
            if row['unit']!=unit:raise ValueError('unit drift')
            rc,err,value=row['rc'],row['errno'],row['value']
            if (type(rc)!=int or type(err)!=int or type(value)!=str or len(value)>512 or '\0' in value
                or not ((rc==0 and err==0) or (rc==-1 and 0<err<4096 and value==''))):raise ValueError('invalid read status')
            if optional:
                valid=row['value_valid']
                if type(valid)!=bool or (rc and valid) or (not valid and value):raise ValueError('invalid optional format/status')
                parsed=None;problem=None
                if rc:problem='io_error'
                elif not valid:problem='invalid_format'
                else:parsed=format_value(group,path,value)
                seen[sample][key]={'rc':rc,'errno':err,'value':parsed,'problem':problem,
                                   'relative_begin_ms':pending[1]-origin,'read_duration_ms':stamp-pending[1]}
            else:seen[sample][key]=None
            elapsed.append({'sample':sample,'group':group,'path':path,'relative_begin_ms':pending[1]-origin,
                            'read_duration_ms':stamp-pending[1]})
            pending=None
        else:raise ValueError('unexpected kind')
        if not optional:retained.append(row.copy())
    if current!=samples:raise ValueError('missing census')
    # Independently apply unchanged O1 required-field semantics after validating
    # every O2 pair, optional completeness, units, count and schema first.
    for seq,row in enumerate(retained):row['schema']='M15O1';row['seq']=seq
    for key in ('extension','vendor_fields','partner_fields_per_port'):retained[0].pop(key)
    retained[-1]['records']=len(retained)
    old_terminal=terminal.copy();old_terminal['schema']='M15O1-supervisor'
    normalized=b''.join((json.dumps(row)+'\n').encode() for row in retained+[old_terminal])
    result=o1.analyze(normalized)
    result.update(schema='M15-observation-report-v2',raw_sha256=hashlib.sha256(raw).hexdigest(),
                  raw_bytes=len(raw),records=len(body),extension='vendor-partner-v1',
                  relative_timing=elapsed,timing_semantics='within-capture relative only',
                  android_observer_compatibility='UNKNOWN')
    for i in range(samples):
        result['samples'][i]['optional']={g+'/'+p:v for (g,p),v in seen[i].items() if v is not None}
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('capture',type=Path);a=p.parse_args()
    try:r=analyze(a.capture.read_bytes())
    except (ValueError,TypeError,KeyError,OSError):
        # Do not echo malformed or privacy-sensitive raw input in errors.
        print(json.dumps({'transcript_complete':False,'error':'invalid transcript','control_permitted':False,
                          'freshness':'UNKNOWN','negotiated_contract':'UNKNOWN','protection_active':'UNKNOWN',
                          'android_observer_compatibility':'UNKNOWN','charging_hardware_pass':False}));return 1
    print(json.dumps(r,indent=2));return 0 if r['telemetry']=='READABLE' else 2

if __name__=='__main__':raise SystemExit(main())
