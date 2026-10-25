#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Explicit M15O3 USB/USB_PD supply contract. Old O1/O2 verdicts never change."""
import argparse
import copy
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

PHASEB=Path(__file__).resolve().parents[1]/'phaseb'
sys.path.insert(0,str(PHASEB))
spec=importlib.util.spec_from_file_location('m15_legacy_o2_replay',PHASEB/'replay.py')
legacy=importlib.util.module_from_spec(spec);spec.loader.exec_module(legacy)
CONTRACT='usb-or-usb-pd-v1'
USB_SUPPLY_TYPES=('USB','USB_PD')

def analyze(raw):
    rows=legacy.load(raw)
    if rows[0].get('schema') in ('M15O1','M15O2'):return legacy.analyze(raw)
    if rows[0].get('schema')!='M15O3':raise ValueError('unsupported schema')
    if rows[0].get('power_supply_contract')!=CONTRACT:raise ValueError('missing/unknown O3 supply contract')
    projected=copy.deepcopy(rows)
    for row in projected:
        if row.get('schema')=='M15O3':row['schema']='M15O2'
        elif row.get('schema')=='M15O3-supervisor':row['schema']='M15O2-supervisor'
        else:raise ValueError('mixed observation schema')
    projected[0].pop('power_supply_contract')
    # Reuse the frozen complete-frame/pair/order/errno validator with raw field
    # values intact. USB_PD is NEVER rewritten to USB. Legacy semantics remain
    # visible below, while ONLY the explicitly versioned O3 class check changes.
    result=legacy.analyze(b''.join((json.dumps(row)+'\n').encode() for row in projected))
    old_status=result['telemetry'];raw_types={}
    for row in rows:
        if row.get('kind')=='read_end' and row.get('group')=='power_supply' and row.get('path')=='usb/type':
            raw_types[row['sample']]=row
    for sample,snapshot in enumerate(result['samples']):
        source=raw_types[sample];value=source['value'] if source['rc']==0 else None
        snapshot['legacy_o2_errors']=list(snapshot['errors'])
        snapshot['reported_supply_type']=value if value in USB_SUPPLY_TYPES else None
        snapshot['supply_type_accepted']=source['rc']==0 and value in USB_SUPPLY_TYPES
        if source['rc']==0 and value=='USB_PD':
            marker='USB supply type unverified'
            if snapshot['errors'].count(marker)!=1:raise ValueError('frozen class-check contract drift')
            snapshot['errors'].remove(marker)
    result.update(schema='M15-observation-report-v3',observation_schema='M15O3',power_supply_contract=CONTRACT,
                  accepted_usb_supply_types=list(USB_SUPPLY_TYPES),raw_sha256=hashlib.sha256(raw).hexdigest(),
                  raw_bytes=len(raw),legacy_o2_telemetry=old_status,
                  telemetry='BLOCKED' if any(s['errors'] for s in result['samples']) else 'READABLE',
                  freshness='UNKNOWN',negotiated_contract='UNKNOWN',protection_active='UNKNOWN',
                  android_observer_compatibility='UNKNOWN',control_permitted=False,charging_hardware_pass=False,
                  sealed_baseline=False,transport_integrity='NOT_ESTABLISHED',
                  semantics='reported power_supply descriptor class only; no negotiated PD/PPS, draw or protection proof')
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('capture',type=Path);a=p.parse_args()
    try:r=analyze(a.capture.read_bytes())
    except (ValueError,TypeError,KeyError,OSError,RecursionError):
        print(json.dumps({'transcript_complete':False,'error':'invalid observation transcript','control_permitted':False,
                          'freshness':'UNKNOWN','negotiated_contract':'UNKNOWN','protection_active':'UNKNOWN',
                          'android_observer_compatibility':'UNKNOWN','charging_hardware_pass':False,
                          'sealed_baseline':False}));return 1
    print(json.dumps(r,indent=2));return 0 if r['telemetry']=='READABLE' else 2

if __name__=='__main__':raise SystemExit(main())
