"""Strict HOST-only inspector. Completeness never grants amplifier permission."""
import argparse
import hashlib
import json
import re
from pathlib import Path

CONDITIONS = (
    'runtime_transport', 'graph_topology', 'amp_disabled', 'runtime_route',
    'calibration_applied', 'protection_active', 'gain_valid', 'teardown',
)
IMPACTS = {'metadata', 'filesystem_read', 'driver_query', 'dsp_action', 'hardware_action'}
REQUIRED_ACTIONS = {
    'runtime_transport': 'Matched transport/DMA/PDR adapters; full TX/RX packet, token, opcode, domain, byte count, raw rc, timeout/cancel and DOWN evidence',
    'graph_topology': 'Resolved live key vectors, graph IDs, modules/instances, connections and feedback topology; matched firmware response',
    'amp_disabled': 'Audited physical mute/power-state observation in addition to both cached switches; before/after each DSP preparation stage',
    'runtime_route': 'Allowlisted route enum/value readbacks, DAI bindings and exact no-enable preparation sequence',
    'calibration_applied': 'Exact channel/instance payloads, successful token-matched DSP ACK and decoded Re readback for both channels',
    'protection_active': 'Actual protection/feedback status, freshness, sensor/fault validity and fault-injection/disable handling',
    'gain_valid': 'Reviewed limits/profile/limiter policy plus actual per-channel DSP/amp gain readback; cache profile alone insufficient',
    'teardown': 'Every acquired graph/feedback/mapper/notifier resource released on success, error, timeout/cancel and DOWN; final amp-off observation',
}


def inspect_journal(data, nonce, identity):
    if not re.fullmatch('[0-9a-f]{32}', nonce) or not re.fullmatch('[0-9a-f]{64}', identity):
        raise ValueError('invalid expected session identity')
    if len(data) > 1048704:
        raise ValueError('journal budget exceeded')
    lines = data.splitlines(keepends=True)
    if not lines or not lines[-1].endswith(b'\n'):
        raise ValueError('missing complete footer')
    footer = re.fullmatch(rb'M11I1 END ([0-9]+) ([0-9a-f]{64})\n', lines[-1])
    if not footer:
        raise ValueError('missing final digest')
    prefix = b''.join(lines[:-1])
    if hashlib.sha256(prefix).hexdigest().encode() != footer[2]:
        raise ValueError('journal digest mismatch')
    if int(footer[1]) != len(lines)-1:
        raise ValueError('journal record count mismatch')
    records, last_time = [], -1.0
    unsupported = set()
    for seq, line in enumerate(lines[:-1]):
        match = re.fullmatch(rb'M11I1 ([0-9]+) ([0-9]+[.][0-9]+) ([a-z_0-9]+) ([a-z_0-9]+) ([a-z_0-9]+) (-?[0-9]+) (-|[0-9a-f]+)\n', line)
        if not match or int(match[1]) != seq:
            raise ValueError('journal framing/sequence mismatch')
        now = float(match[2])
        if now < last_time:
            raise ValueError('monotonic timestamp regressed')
        last_time = now
        condition, op, impact = (match[i].decode() for i in (3, 4, 5))
        if condition not in (*CONDITIONS, 'session') or impact not in IMPACTS:
            raise ValueError('unknown condition/impact')
        payload = b'' if match[7] == b'-' else bytes.fromhex(match[7].decode())
        if len(payload)>32768:
            raise ValueError('payload budget exceeded')
        rc = int(match[6])
        if op == 'unsupported':
            if condition not in CONDITIONS or condition in unsupported or rc != 95 or impact != 'metadata':
                raise ValueError('invalid/duplicate capability record')
            unsupported.add(condition)
        records.append(dict(seq=seq, uptime=now, condition=condition, operation=op,
                            impact=impact, raw_rc=rc, payload_hex=payload.hex()))
    if not records or records[0]['operation']!='identity' or records[0]['condition']!='session' or records[0]['raw_rc']!=0 or bytes.fromhex(records[0]['payload_hex']) != (nonce+' '+identity).encode():
        raise ValueError('session identity mismatch')
    if records[-1]['operation'] != 'final_state' or records[-1]['condition']!='session' or records[-1]['raw_rc']!=0 or bytes.fromhex(records[-1]['payload_hex']) != b'amp_enable_permitted=0 actuator_implemented=0':
        raise ValueError('missing fail-closed final state')
    if unsupported != set(CONDITIONS):
        raise ValueError('missing runtime capability declaration')
    if any(r['impact'] in ('dsp_action','hardware_action') for r in records):
        raise ValueError('hardware-impacting operation in observation-only journal')
    return dict(event_stream_complete=True, records=records,
                conditions={key: dict(status='UNKNOWN', required_probe=REQUIRED_ACTIONS[key],
                                      observation_records=[r['seq'] for r in records if r['condition']==key and r['operation']!='unsupported']) for key in CONDITIONS},
                runtime_proof_coverage=0, capability_declarations=8,
                amplifier_enable_permitted=False, actuator_implemented=False)


def decode_capture(data, nonce, identity):
    report = dict(raw_sha256=hashlib.sha256(data).hexdigest(), raw_bytes=len(data),
                  event_stream_complete=False, kernel_stream_complete=False,
                  capture_complete=False, conditions={key: dict(status='UNKNOWN', required_probe=REQUIRED_ACTIONS[key], observation_records=[]) for key in CONDITIONS}, amplifier_enable_permitted=False,
                  actuator_implemented=False, error=None)
    try:
        if len(data)>64*1024*1024:
            raise ValueError('capture budget exceeded')
        pos=0; event=bytearray(); kseq=[]; warnings=0; final=None
        while pos<len(data):
            m=re.match(rb'M11I1R ([KEWF]) ([0-9]{1,6})\n',data[pos:])
            if not m: raise ValueError('capture frame header mismatch')
            n=int(m[2]); pos+=m.end()
            if not 0<n<=16384 or pos+n>len(data): raise ValueError('capture frame payload truncated/oversized')
            payload=data[pos:pos+n];pos+=n
            if m[1]==b'E':
                event.extend(payload)
                if len(event)>1048704: raise ValueError('event budget exceeded')
            elif m[1]==b'K':
                h=re.match(rb'[0-9]+,([0-9]+),[0-9]+,[^;]*;',payload)
                if not h: raise ValueError('invalid native kmsg record')
                seq=int(h[1])
                if kseq and seq!=kseq[-1]+1: raise ValueError('kmsg sequence gap/duplicate/reorder')
                kseq.append(seq)
            elif m[1]==b'W': warnings+=1
            else:
                final=re.fullmatch(rb'events=([0-9]+) kernel_drops=([0-9]+)\n',payload)
                if not final or pos!=len(data): raise ValueError('invalid final frame/trailing bytes')
        if final is None: raise ValueError('missing relay final frame')
        if int(final[1])!=len(event): raise ValueError('relay event byte boundary mismatch')
        report.update(inspect_journal(bytes(event),nonce,identity))
        report['kernel_drops']=int(final[2]);report['kernel_warnings']=warnings
        report['kernel_first_sequence']=kseq[0] if kseq else None
        report['kernel_last_sequence']=kseq[-1] if kseq else None
        report['kernel_records']=len(kseq)
        report['kernel_stream_complete']=bool(kseq) and not warnings and int(final[2])==0
        report['capture_complete']=report['event_stream_complete'] and report['kernel_stream_complete']
        if not report['capture_complete']: raise ValueError('kernel loss/warning/empty stream')
    except (ValueError, IndexError) as exc:
        report['error']=str(exc)
        report['capture_complete']=False
    return report


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('capture',type=Path);ap.add_argument('--nonce',required=True)
    ap.add_argument('--identity',required=True);ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args()
    # Bounded host input; preserve raw capture unchanged.
    with args.capture.open('rb') as src: data=src.read(64*1024*1024+1)
    result=decode_capture(data,args.nonce,args.identity)
    args.output.write_text(json.dumps(result,indent=2)+'\n')
    return 0 if result['capture_complete'] else 1

if __name__=='__main__': raise SystemExit(main())
