"""M11I3 strict validator. Independent hashlib; no healing or resynchronization.

Run21: the E stream is the runner journal; it must pass instrumentation/evidence.py
inspect_journal against the on-device nonce/identity (fail closed when not supplied)."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re

MAX_CAPTURE=64*1024*1024
HEADER=re.compile(rb'M11I3 ([SKEWF]) (0|[1-9][0-9]{0,8}) ([1-9][0-9]{0,4})\n\Z')
START=re.compile(rb'run=M11R21 nonce=([0-9a-f]{32})\n\Z')
def _load_inspect_journal():
    path=Path(__file__).resolve().parent.parent/'instrumentation'/'evidence.py'
    spec=importlib.util.spec_from_file_location('m11_instrumentation_evidence',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module.inspect_journal
inspect_journal=_load_inspect_journal()
FINAL=re.compile(rb'frames=(0|[1-9][0-9]*) bytes=(0|[1-9][0-9]*) events=(0|[1-9][0-9]*) kernel_drops=(0|[1-9][0-9]*) sha256=([0-9a-f]{64}) tty_sha256=([0-9a-f]{64})\n\Z')
def decode(data,journal_nonce=None,journal_identity=None):
    journal_error=None;journal_records=None
    streams={k:bytearray() for k in 'SKEWF'};offset=0;frames=0;kernels=0;prior=None;final=False;nonce=None;error=None;category=None;covered=0;digest=None
    try:
        if len(data)>MAX_CAPTURE: raise ValueError('capture-budget')
        while offset<len(data):
            if final: raise ValueError('trailing-bytes')
            nl=data.find(b'\n',offset,offset+64)
            if nl<0: raise ValueError('incomplete-header')
            m=HEADER.fullmatch(data[offset:nl+1])
            if not m: raise ValueError('invalid-header')
            kind=m[1].decode();seq=int(m[2]);size=int(m[3])
            if seq!=frames: raise ValueError('sequence-gap-or-duplicate')
            if not 0<size<=16384: raise ValueError('invalid-length')
            end=nl+1+size
            if end>len(data): raise ValueError('incomplete-payload')
            body=data[nl+1:end]
            if frames==0 and kind!='S': raise ValueError('start-missing')
            if kind=='S':
                start=START.fullmatch(body)
                if frames or not start or start[1]==b'0'*32: raise ValueError('invalid-start')
                nonce=start[1].decode()
            if kind=='K':
                meta=body.partition(b';')[0].split(b',')
                if (not body.endswith(b'\n') or len(meta) not in (4,5) or any(not x.isdigit() for x in meta[:3]) or
                    meta[3] not in (b'-',b'c') or (len(meta)==5 and not re.fullmatch(rb'caller=[TC][0-9]+',meta[4]))):
                    raise ValueError('kernel-record-invalid')
                kseq=int(meta[1])
                if prior is not None and kseq!=prior+1: raise ValueError('kernel-sequence-gap-or-duplicate')
                prior=kseq;kernels+=1
            if kind=='W': raise ValueError('sender-loss-warning')
            if kind=='F':
                f=FINAL.fullmatch(body)
                if not f: raise ValueError('invalid-final')
                n,b,e,d=map(int,f.groups()[:4])
                metadata=(f'frames={n} bytes={b} events={e} kernel_drops={d}\n').encode()
                digest=hashlib.sha256(data[:offset]+b'M11I3 SEAL\n'+metadata).hexdigest()
                if n!=frames or b!=offset or e!=len(streams['E']): raise ValueError('final-count-mismatch')
                if d: raise ValueError('sender-kernel-loss')
                if f[5].decode()!=digest or f[6].decode()!=digest: raise ValueError('sender-digest-mismatch')
                covered=offset;final=True
            streams[kind].extend(body);offset=end;frames+=1
        if not final: raise ValueError('missing-final')
        if not kernels: raise ValueError('kernel-evidence-missing')
        # Run21 terminal rule: the E stream is a complete runner journal bound to the on-device identity.
        if journal_nonce is None or journal_identity is None: raise ValueError('journal-identity-missing')
        try: journal_records=len(inspect_journal(bytes(streams['E']),journal_nonce,journal_identity)['records'])
        except (ValueError,TypeError) as exc: journal_error=str(exc);raise ValueError('journal-invalid')
    except ValueError as exc: category=str(exc);error=f'{category} at byte {offset}'
    return streams,dict(protocol='M11I3',raw_sha256=hashlib.sha256(data).hexdigest(),raw_bytes=len(data),parsed_bytes=offset,
        error=error,error_category=category,error_offset=offset if error else None,frames=frames,kernel_records=kernels,
        last_kernel_sequence=prior,nonce=nonce,covered_bytes=covered,sender_sha256=digest,final_frame_received=final,
        event_bytes=len(streams['E']),journal_records=journal_records,journal_error=journal_error,event_stream_complete=error is None,host_receipt_valid=False,resynchronization=False)
def validate_receipt(report,receipt):
    r=receipt.get('receipt') or {}
    ok=(report['event_stream_complete'] and receipt.get('errors')==[] and not receipt.get('failure') and
        receipt.get('shutdown_clean') is True and receipt.get('flush_clean') is True and
        receipt.get('raw_sha256')==report['raw_sha256'] and r.get('Bytes')==report['raw_bytes'] and r.get('Reason')=='terminal-frame')
    report['host_receipt_valid']=bool(ok)
    if not ok and not report['error']: report.update(error='receiver-receipt-invalid',error_category='receiver-receipt-invalid',error_offset=report['raw_bytes'])
    return bool(ok)
def main():
    p=argparse.ArgumentParser();p.add_argument('raw',type=Path);p.add_argument('--receipt',type=Path,required=True);p.add_argument('--out',type=Path,required=True)
    p.add_argument('--journal-nonce',required=True);p.add_argument('--journal-identity',required=True);a=p.parse_args()
    with a.raw.open('rb') as f: data=f.read(MAX_CAPTURE+1)
    streams,r=decode(data,a.journal_nonce,a.journal_identity)
    try: ok=validate_receipt(r,json.loads(a.receipt.read_text(encoding='utf-8-sig')))
    except (OSError,ValueError): ok=False;r.update(error='receipt-missing-or-malformed',error_category='receipt-missing-or-malformed')
    a.out.mkdir(parents=True,exist_ok=False)
    for k in streams: (a.out/(k+'.bin')).write_bytes(streams[k])
    (a.out/'report.json').write_text(json.dumps(r,indent=2)+'\n',encoding='utf-8');print(json.dumps(r,indent=2))
    return 0 if ok else 1
if __name__=='__main__': raise SystemExit(main())
