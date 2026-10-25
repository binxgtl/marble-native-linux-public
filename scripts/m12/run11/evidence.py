"""Successor verifier for native M12DN and inherited M12D3 breadcrumbs.

The frozen Run3/Run4 verifier is unchanged. Completeness is not Wi-Fi PASS.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re


def validate_diagnostics(data):
    counts = {'M12DN': 0, 'M12D3': 0}
    for line in data.splitlines(keepends=True):
        match = re.fullmatch(rb'(M12DN|M12D3) ([0-9]+) ([a-zA-Z0-9_./-]+) (-?[0-9]+)\n', line)
        if not match:
            raise ValueError('incomplete/malformed breadcrumb')
        stamp, rc = int(match[2]), int(match[4])
        if stamp > (1 << 64)-1 or not -(1 << 63) <= rc < (1 << 63):
            raise ValueError('breadcrumb integer out of range')
        if match[1] == b'M12DN' and stamp == 0:
            raise ValueError('native breadcrumb clock invalid')
        counts[match[1].decode()] += 1
    return counts


def validate_prequery(journal, row, nonce, identity):
    m = re.fullmatch(rb'M12I2 ([0-9]+) ([0-9]+)\.([0-9]{9}) session pre_query metadata 0 ([0-9a-f]+)\n', row)
    if not m or len(row) >= 1024 or int(m[1]) < 1:
        return None
    expected = f'pre-query {nonce} {identity} amplifier_enable_permitted=0'.encode().hex().encode()
    if m[4] != expected:
        return None
    lines = journal.splitlines(keepends=True)
    for seq, line in enumerate(lines[:int(m[1])+1]):
        h = re.fullmatch(rb'M12I2 ([0-9]+) [0-9]+\.[0-9]+ [a-z_0-9]+ [a-z_0-9]+ [a-z_0-9]+ -?[0-9]+ (?:-|(?:[0-9a-f]{2})+)\n', line)
        if not h or int(h[1]) != seq:
            return None
    seq = int(m[1])
    return seq if seq < len(lines) and lines[seq] == row else None


def decode_capture(data, nonce, identity):
    report = dict(capture_complete=False, kernel_complete=False, records=[],
                  raw_sha256=hashlib.sha256(data).hexdigest(), raw_bytes=len(data),
                  wifi_ready='UNKNOWN', firmware_ready='UNKNOWN',
                  amplifier_enable_permitted=False, rf_scan_permitted=True,
                  association_permitted=True, post_seal_cleanup='UNKNOWN',
                  host_ack_delivery_proven_by_prefix=False)
    journal = bytearray(); diagnostics = bytearray(); counts = {}
    try:
        if not re.fullmatch('[0-9a-f]{32}', nonce) or not re.fullmatch('[0-9a-f]{64}', identity):
            raise ValueError('invalid expected identity')
        if len(data) > 64*1024*1024:
            raise ValueError('capture budget exceeded')
        hello = f'M12I2R H 98\n{nonce} {identity}\n'.encode()
        if not data.startswith(hello):
            raise ValueError('missing/truncated/mismatched identity prefix')
        pos = len(hello); counts['H'] = 1; barrier = None; final = None
        while pos < len(data):
            m = re.match(rb'M12I2R ([KEWDBF]) ([0-9]{1,6})\n', data[pos:pos+48])
            if not m or final is not None:
                raise ValueError('frame header mismatch or data after final')
            n = int(m[2]); end = pos+m.end()+n
            if not 0 < n <= 16384 or end > len(data):
                raise ValueError('truncated/oversized frame')
            kind = m[1].decode(); payload = data[pos+m.end():end]
            counts[kind] = counts.get(kind,0)+1
            if kind == 'E':
                journal.extend(payload)
                if len(journal)>2097152: raise ValueError('journal budget exceeded')
            elif kind == 'D': diagnostics.extend(payload)
            elif kind == 'B':
                if barrier is not None or validate_prequery(bytes(journal),payload,nonce,identity) is None:
                    raise ValueError('invalid prequery checkpoint or B before E')
                barrier = payload
            elif kind == 'F':
                final = re.fullmatch(rb'events=([0-9]+) kernel_drops=([0-9]+)\n',payload)
                if not final: raise ValueError('invalid relay final frame')
            pos = end
        if final is None: raise ValueError('missing relay final frame')
        if int(final[1]) != len(journal): raise ValueError('relay journal byte count mismatch')
        lines = bytes(journal).splitlines(keepends=True)
        if not lines: raise ValueError('journal absent')
        footer = re.fullmatch(rb'M12I2 END ([0-9]+) ([0-9a-f]{64})\n',lines[-1])
        if not footer or int(footer[1]) != len(lines)-1 or hashlib.sha256(b''.join(lines[:-1])).hexdigest().encode()!=footer[2]:
            raise ValueError('journal count/digest mismatch or missing footer')
        previous = -1
        for seq, line in enumerate(lines[:-1]):
            m = re.fullmatch(rb'M12I2 ([0-9]+) ([0-9]+)\.([0-9]+) ([a-z_0-9]+) ([a-z_0-9]+) ([a-z_0-9]+) (-?[0-9]+) (-|(?:[0-9a-f]{2})+)\n',line)
            if not m or int(m[1])!=seq: raise ValueError('journal sequence/format mismatch')
            stamp = int(m[2])*1000000000+int(m[3].ljust(9,b'0'))
            if len(m[3])>9 or stamp<previous: raise ValueError('regressing/invalid journal time')
            previous = stamp
            text = b'' if m[8]==b'-' else bytes.fromhex(m[8].decode())
            report['records'].append(dict(seq=seq, operation=m[5].decode(),
                                          condition=m[4].decode(), impact=m[6].decode(),
                                          raw_rc=int(m[7]), payload_hex=m[8].decode(),
                                          payload=text.decode('utf-8','replace')))
        records = report['records']
        if not records or records[0]['operation']!='identity' or records[0]['payload']!=nonce+' '+identity:
            raise ValueError('journal identity differs')
        if barrier is None: raise ValueError('missing prequery checkpoint')
        checkpoints = [r for r in records if r['operation']=='pre_query']
        acks = [r for r in records if r['operation']=='pre_query_ack']
        if len(checkpoints)!=1 or len(acks)!=1 or acks[0]['seq']<=checkpoints[0]['seq'] or acks[0]['raw_rc']!=0 or acks[0]['payload']!='PID1 accepted exact PC receipt of pre_query; amplifier_enable_permitted=0':
            raise ValueError('missing/invalid PID1 startup acceptance')
        # USB suppliers precede receipt. Wi-Fi insertion must follow it.
        wifi = {'msm_qmp.ko','pci-msm-drv.ko','mhi.ko','qrtr-mhi.ko','cnss_plat_ipc_qmi_svc.ko','hwid.ko','memory_dump_v2.ko','wlan_firmware_service.ko','cnss2.ko'}
        if any(r['operation']=='module_begin' and any('name='+n+' ' in r['payload'] for n in wifi) and r['seq']<=acks[0]['seq'] for r in records):
            raise ValueError('Wi-Fi module evidence before PID1 receipt acceptance')
        dialects = validate_diagnostics(bytes(diagnostics))
        digests = [r for r in records if r['operation']=='diagnostics_digest']
        proof = f'{len(diagnostics)} {hashlib.sha256(diagnostics).hexdigest()}'
        if len(digests)!=1 or digests[0]['raw_rc'] or digests[0]['payload']!=proof:
            raise ValueError('diagnostic byte count/digest mismatch')
        finals = [r for r in records if r['operation']=='final_state']
        if len(finals)!=1 or finals[0]!=records[-1] or finals[0]['payload']!='amplifier_enable_permitted=0 rf_scan_permitted=1 association_permitted=1 wifi_ready=UNKNOWN':
            raise ValueError('invalid final safety contract')
        report.update(journal_complete=True, pid1_startup_receipt_recorded=True,
                      kernel_complete=int(final[2])==0 and not counts.get('W') and not any(r['operation']=='kernel_privacy' for r in records),
                      kernel_drops=int(final[2]), diagnostic_bytes=len(diagnostics),
                      diagnostic_text=diagnostics.decode('ascii','replace'),
                      diagnostic_dialects=dialects)
        if int(final[2]) or counts.get('W'): raise ValueError('unexpected kernel records lost')
        report['capture_complete'] = True
        report['kernel_privacy_cutoff']=any(r['operation']=='kernel_privacy' for r in records)
        connections=[r for r in records if r['operation']=='connectivity']
        if len(connections)==1 and connections[0]['payload'].startswith('M12NET '):
            r=connections[0];statuses={}
            for line in r['payload'].splitlines():
                m=re.fullmatch(r'M12NET (firmware|interface|scan|association|wpa|dhcp|ping|disconnect|lease_reset|reconnect|reassociation|rewpa|redhcp|reping|network_cleanup) (PASS|FAIL|BLOCKED|UNKNOWN) rc=(-?[0-9]+)',line)
                if not m or m[1] in statuses: raise ValueError('invalid/duplicate network proof row')
                statuses[m[1]]={'status':m[2],'rc':int(m[3])}
            report['connectivity_stages']=statuses
            if r['raw_rc']==0:
                required={'firmware','interface','scan','association','wpa','dhcp','ping','disconnect','lease_reset','reconnect','reassociation','rewpa','redhcp','reping','network_cleanup'}
                if set(statuses)!=required or any(v!={'status':'PASS','rc':0} for v in statuses.values()) or not report['kernel_privacy_cutoff']:
                    raise ValueError('success missing exact connectivity proof/privacy cutoff')
                crumbs=[]
                for line in diagnostics.decode('ascii').splitlines():
                    _,_,stage,rc=line.split(' ');crumbs.append((stage,int(rc)))
                # Independent host replay of the successful helper's actual
                # control-flow boundaries; a digest alone cannot prove that
                # required breadcrumbs were produced in the first place.
                previous=-1
                for stage in ('config','firmware','interface','supplicant_spawn','scan',
                              'association','wpa','dhcp','ping','disconnect','lease_reset','reconnect','reassociation','rewpa','redhcp','reping','cleanup'):
                    begins=[i for i,c in enumerate(crumbs) if c==(stage+'_begin',0)]
                    returns=[i for i,c in enumerate(crumbs) if c==(stage+'_return',0)]
                    if len(begins)!=1 or len(returns)!=1 or not previous<begins[0]<returns[0]:
                        raise ValueError('success missing/invalid ordered network boundary: '+stage)
                    previous=returns[0]
                starts=[i for i,c in enumerate(crumbs) if c==('network_begin',0)]
                ends=[i for i,c in enumerate(crumbs) if c==('network_return',0)]
                if len(starts)!=1 or len(ends)!=1 or not starts[0]<previous<ends[0]:
                    raise ValueError('success missing network entry/return evidence')
                inner=('disconnect_ack','disconnect_event','disconnect_status','disconnect_dwell')
                inner_at=[]
                for name in inner:
                    positions=[i for i,c in enumerate(crumbs) if c==(name,0)]
                    if len(positions)!=1:raise ValueError('missing unique disconnect proof: '+name)
                    inner_at.append(positions[0])
                db=crumbs.index(('disconnect_begin',0));dr=crumbs.index(('disconnect_return',0))
                if not db<inner_at[0]<inner_at[1]<inner_at[2]<inner_at[3]<dr:raise ValueError('disconnect proof order')
                timed={line.split()[2]:int(line.split()[1]) for line in diagnostics.decode('ascii').splitlines() if line.split()[2] in inner}
                if timed['disconnect_dwell']-timed['disconnect_status']<2000000000:raise ValueError('disconnect dwell shorter than 2s')
                report['wifi_ready']='RECONNECTIVITY_PASS'
                report['reconnect_verified']=True
                report['firmware_ready']='HOST_VISIBLE_DRIVER_READY; firmware internals not independently queried'

    except ValueError as exc:
        report['capture_complete']=False
        report['wifi_ready']='UNKNOWN'
        report['error'] = str(exc)
    # A failed run still needs its last observable boundary. Retain complete
    # rows from the received prefix explicitly UNSEALED; they cannot qualify
    # capture completeness, Wi-Fi readiness or cleanup. Never invent bytes.
    unsealed=[]
    if not report['capture_complete']:
        for seq, line in enumerate(bytes(journal).splitlines(keepends=True)):
            m=re.fullmatch(rb'M12I2 ([0-9]+) ([0-9]+)\.([0-9]+) ([a-z_0-9]+) ([a-z_0-9]+) ([a-z_0-9]+) (-?[0-9]+) (-|(?:[0-9a-f]{2})+)\n',line)
            if not m or int(m[1])!=seq: break
            payload=b'' if m[8]==b'-' else bytes.fromhex(m[8].decode())
            unsealed.append(dict(seq=seq,operation=m[5].decode(),raw_rc=int(m[7]),payload=payload.decode('utf-8','replace')))
        report.update(unsealed_prefix_records=unsealed,unsealed_diagnostic_text=diagnostics.decode('ascii','replace'))
    report.update(frame_counts=counts, journal_bytes=len(journal))
    return report


def main():
    p = argparse.ArgumentParser(); p.add_argument('capture',type=Path)
    p.add_argument('--nonce',required=True); p.add_argument('--identity',required=True)
    p.add_argument('--output',type=Path,required=True); a = p.parse_args()
    with a.capture.open('rb') as f: data = f.read(64*1024*1024+1)
    report = decode_capture(data,a.nonce,a.identity)
    a.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    return 0 if report['capture_complete'] else 1


if __name__=='__main__': raise SystemExit(main())
