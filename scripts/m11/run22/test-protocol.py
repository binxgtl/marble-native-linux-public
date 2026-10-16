"""Independent wire oracle; no credentials, device or resynchronization."""
import hashlib
import importlib.util
import json
from pathlib import Path
import random
import subprocess
import sys
import tempfile

HERE=Path(__file__).resolve().parent
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
checker=load('checker',HERE/'check-capture.py')
evidence=load('m11_test_evidence',HERE.parent/'instrumentation'/'evidence.py')
# On-device /m11/instrumentation/nonce and identity used by every synthetic journal (also embedded in the C tests).
JN='7'*32
JI='9'*64
def frame(kind,seq,body): return f'M11I3 {kind} {seq} {len(body)}\n'.encode()+body
def journal(pad=0,nonce=JN,identity=JI):
    """Complete runner journal accepted by evidence.inspect_journal; pad adds ~2 KiB observation records."""
    rows=[('session','identity','metadata',0,(nonce+' '+identity).encode())]
    rows+=[('runtime_transport','observe','metadata',0,b'p'*1000)]*pad
    rows+=[(c,'unsupported','metadata',95,b'not_implemented') for c in evidence.CONDITIONS]
    rows+=[('session','final_state','metadata',0,b'amp_enable_permitted=0 actuator_implemented=0')]
    raw=b''.join(f'M11I1 {s} 1.00 {c} {op} {impact} {rc} {p.hex()}\n'.encode() for s,(c,op,impact,rc,p) in enumerate(rows))
    return raw+f'M11I1 END {len(rows)} {hashlib.sha256(raw).hexdigest()}\n'.encode()
def stream(drops=0,ev=None):
    ev=journal() if ev is None else ev
    pieces=[frame('S',0,b'run=M11R22 nonce=0123456789abcdef0123456789abcdef\n')]
    for i in range(40):
        pieces.append(frame('K',len(pieces),f'6,{i},123,-,caller=T20;'.encode()+b'x'*200+b'\n'))
    for at in range(0,len(ev),16000):
        pieces.append(frame('E',len(pieces),ev[at:at+16000]))
    covered=b''.join(pieces);metadata=f'frames={len(pieces)} bytes={len(covered)} events={len(ev)} kernel_drops={drops}\n'.encode()
    h=hashlib.sha256(covered+b'M11I3 SEAL\n'+metadata).hexdigest()
    final=frame('F',len(pieces),f'frames={len(pieces)} bytes={len(covered)} events={len(ev)} kernel_drops={drops} sha256={h} tty_sha256={h}\n'.encode())
    return covered+final,pieces,final
data,pieces,final=stream()
def decode(data,nonce=JN,identity=JI): return checker.decode(data,nonce,identity)
def check(data,good=False,category=None):
    _,r=decode(data)
    assert bool(r['event_stream_complete'])==good,r
    if category is not None: assert r['error_category']==category,r
    return r
r=check(data,True);assert r['journal_records']==10 and r['journal_error'] is None,r
# Truthful loss footer binds its counter. Flipping only1->0 must FAIL.
loss,_,_=stream(1);check(loss,False,'sender-kernel-loss')
check(loss.replace(b'kernel_drops=1',b'kernel_drops=0'),False,'sender-digest-mismatch')
hash_at=final.index(b'sha256=')+7
bad_final=final[:hash_at]+(b'0' if final[hash_at:hash_at+1]!=b'0' else b'1')+final[hash_at+1:]
cases={'missing-final':data[:-len(final)],'partial-final':data[:-1],
       'trailing':data+b'x','digest':data[:-3]+b'00\n',
       'constructed-digest':data[:-len(final)]+bad_final,
       'header':b'x'+data[1:],'duplicate':pieces[0]+pieces[0]+b''.join(pieces[1:])+final,
       'skipped':data.replace(b'M11I3 K 1 ',b'M11I3 K 2 ',1),
       'length':data.replace(b'M11I3 S 0 50',b'M11I3 S 0 49',1),
       'run20-start':data.replace(b'run=M11R22 ',b'run=M11R20 ',1),
       'deleted1536':data[:512]+data[2048:]}
for name,raw in cases.items():
    if raw==data: continue
    check(raw);print('PASS reject',name)
rng=random.Random(21)
for n in [1,2,6,7,31,511,512,513,1536,2048]:
    at=rng.randrange(1,len(data)-n);check(data[:at]+data[at+n:])
for cut in range(len(data)-len(final),len(data)): check(data[:cut])
# Run22 terminal rule: E must be a complete runner journal bound to the on-device identity (fail closed).
def sealed(ev): return stream(0,ev)[0]
good=journal()
check(sealed(good),True)
end=good.rindex(b'M11I1 END ')
broken_digest=good[:-2]+(b'0' if good[-2:-1]!=b'0' else b'1')+b'\n'
assert broken_digest!=good
check(sealed(broken_digest),False,'journal-invalid');print('PASS reject journal with broken END digest (M11I3 seal valid)')
assert decode(sealed(broken_digest))[1]['journal_error']=='journal digest mismatch'
for name,ev in [('no-end-line',good[:end]),('truncated-end',good[:-1]),('empty-event-stream',b''),
                ('run20-terminal-only',b'[M11R19 event] FINAL_EVIDENCE result=switches-disabled\n'),
                ('count-mismatch',good.replace(b'M11I1 END 10 ',b'M11I1 END 11 ')),
                ('sequence-gap',good.replace(b'M11I1 3 ',b'M11I1 4 ',1)),
                ('trailing-after-end',good+b'x\n')]:
    check(sealed(ev),False,'journal-invalid');print('PASS reject journal',name)
check(sealed(journal(nonce='8'*32)),False,'journal-invalid')
check(sealed(journal(identity='a'*64)),False,'journal-invalid')
for args in [(None,None),(JN,None),(None,JI),('7'*31,JI),(JN,'9'*63),('G'*32,JI)]:
    _,r=checker.decode(data,*args);assert not r['event_stream_complete'] and r['error_category'] in ('journal-identity-missing','journal-invalid'),r
_,r=checker.decode(data);assert r['error_category']=='journal-identity-missing',r
_,r=decode(data,'8'*32,JI);assert r['error_category']=='journal-invalid' and r['journal_error']=='session identity mismatch',r
print('PASS reject journal nonce/identity missing, malformed or different from the on-device files')
# Event boundary: Run20 stopped at 131072 bytes; Run22 accepts a journal up to the 1 MiB cap (journal.sh) and
# inspect_journal still enforces its own 1048704-byte budget.
mid=journal(pad=100);assert 131072<len(mid)<=1048704,len(mid)
r=check(sealed(mid),True);assert r['event_bytes']==len(mid) and r['journal_records']==110
full=journal(pad=500);assert 1000000<len(full)<=1048704,len(full)
r=check(sealed(full),True);assert r['event_bytes']==len(full)
over=journal(pad=520);assert len(over)>1048704,len(over)
check(sealed(over),False,'journal-invalid');assert decode(sealed(over))[1]['journal_error']=='journal budget exceeded'
print('PASS journal accepted above Run20 131072-byte reserve, up to the 1 MiB cap; over budget rejected')
_,report=decode(data)
receipt={'errors':[],'shutdown_clean':True,'flush_clean':True,'raw_sha256':hashlib.sha256(data).hexdigest(),
         'receipt':{'Bytes':len(data),'Reason':'terminal-frame'}}
assert checker.validate_receipt(report,receipt)
for key,value in [('errors',['RXOver']),('errors',['Frame']),('errors',None),('raw_sha256','0'*64),('shutdown_clean',False),('flush_clean',False)]:
    _,r=decode(data);bad=dict(receipt);bad[key]=value;assert not checker.validate_receipt(r,bad)
for reason in ['deadline','eof','read-error','raw-write-error']:
    _,r=decode(data);bad=dict(receipt,receipt={'Bytes':len(data),'Reason':reason});assert not checker.validate_receipt(r,bad)
# Sanitized immutable Run19 bytes still reject; historical wire is never v2 PASS.
fixture=json.loads((HERE.parent/'run19-evidence/fixtures/run19-boundary.json').read_text())
raw=bytes.fromhex(fixture['bytes_hex']);check(raw)
# Exact clean received K1792 metadata/body qualifies when genuinely v2-framed.
# This synthetic translation never repairs or qualifies the original capture.
nl=raw.index(b'\n');real=raw[nl+1:nl+1+211]
assert real.startswith(b'7,1792,7333331,-,caller=T233;')
translated=[frame('S',0,b'run=M11R22 nonce=0123456789abcdef0123456789abcdef\n'),frame('K',1,real),frame('E',2,good)]
covered=b''.join(translated);metadata=f'frames=3 bytes={len(covered)} events={len(good)} kernel_drops=0\n'.encode();h=hashlib.sha256(covered+b'M11I3 SEAL\n'+metadata).hexdigest()
check(covered+frame('F',3,f'frames=3 bytes={len(covered)} events={len(good)} kernel_drops=0 sha256={h} tty_sha256={h}\n'.encode()),True)
check(b'M11R12 F 24\nevents=0 kernel_drops=0\n')
with tempfile.TemporaryDirectory() as d:
    p=Path(d);(p/'raw.bin').write_bytes(data);(p/'receipt.json').write_text(json.dumps(receipt))
    ident=['--journal-nonce',JN,'--journal-identity',JI]
    cli=[sys.executable,str(HERE/'check-capture.py'),str(p/'raw.bin'),'--receipt',str(p/'receipt.json'),'--out',str(p/'good')]
    result=subprocess.run(cli+ident,capture_output=True);assert result.returncode==0,result.stderr
    # Missing journal identity arguments fail closed (argparse usage error, nothing decoded).
    result=subprocess.run(cli[:-1]+[str(p/'noident')],capture_output=True);assert result.returncode!=0 and not (p/'noident').exists()
    result=subprocess.run(cli[:-1]+[str(p/'wrong')]+['--journal-nonce',JN,'--journal-identity','a'*64],capture_output=True);assert result.returncode==1,result.stderr
    rejected=json.loads((p/'wrong/report.json').read_text());assert rejected['error_category']=='journal-invalid' and not rejected['host_receipt_valid']
    (p/'raw.bin').write_bytes(data[:-1]);cli[-1]=str(p/'bad')
    result=subprocess.run(cli+ident,capture_output=True);assert result.returncode==1,result.stderr
    rejected=json.loads((p/'bad/report.json').read_text());assert rejected['error_category']=='incomplete-payload' and rejected['error_offset']>0
print('PASS v3 metadata-bound seal + runner journal rule, all EOF final cuts, deletions, sequences, local receipt/error fail-closed; synthetic only')
if len(sys.argv)>1:
    raw=Path(sys.argv[1]).read_bytes();streams,r=decode(raw)
    if len(sys.argv)>2 and sys.argv[2]=='loss':
        assert r['error_category']=='sender-kernel-loss',r
        assert raw.count(b'kernel_drops=1')==1
        _,r=decode(raw.replace(b'kernel_drops=1',b'kernel_drops=0'))
        assert r['error_category']=='sender-digest-mismatch',r
        print('PASS actual C truthful-loss footer corrupted1->0 REJECTED by independent SHA; no hardware')
    else:
        assert r['event_stream_complete'],r
        assert bytes(streams['E'])==journal(),'C journal literal differs from the Python reference journal'
        print('PASS actual C producer -> independent hashlib seal validator + runner journal inspection')
