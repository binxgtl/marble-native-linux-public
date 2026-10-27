#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual C namespace PID1 + dedicated custodian/O3 over PTY. No devices."""
import os,sys,pty,select,signal,subprocess,time,tempfile,re,json
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'native3'))
from receiver import Receiver,host
pid1,custodian,observer,wire,out=map(lambda x:Path(x).resolve(),sys.argv[1:])
out.mkdir(parents=True,exist_ok=True)
display=Path(__file__).with_name('fake-display.py').resolve()
for mode in ('complete','wrong-admission','wrong-final','disconnect','display-exit','custodian-exit','missing-admission','missing-final'):
    with tempfile.TemporaryDirectory() as tmp:
        root=Path(tmp);journal=root/'journal'
        files,_,_=host.decode(wire.read_bytes())
        for row in host.contract.o3.legacy.load(files['capture.raw']):
            if row.get('kind')=='read_end' and row['rc']==0:
                p=root/'fixture'/'class'/row['group']/row['path'];p.parent.mkdir(parents=True,exist_ok=True);p.write_text(row['value']+'\n')
        master,slave=pty.openpty();os.set_blocking(master,False)
        screen='/bin/false' if mode=='display-exit' else str(display)
        owner='/bin/false' if mode=='custodian-exit' else str(custodian)
        log=(out/(mode+'.process.txt')).open('wb')
        p=subprocess.Popen(['unshare','--mount','--pid','--fork','--mount-proc',str(pid1),'--namespace-smoke',owner,str(observer),str(root/'fixture'),screen,os.ttyname(slave),str(journal)],stdout=log,stderr=log,start_new_session=True)
        raw=bytearray();admitted=False;ack=False;closed=False;limit=time.monotonic()+20
        try:
            while time.monotonic()<limit:
                assert p.poll() is None,'PID1 exited instead of HOLD'
                text=journal.read_text() if journal.exists() else ''
                if 'RED_HOLD' in text:
                    assert mode!='complete',text
                    assert 'PARENT_RECEIPT' not in text
                    break
                if 'COMPLETE evidence only' in text:
                    assert mode=='complete' and ack
                    assert 'release_permitted=false' in text
                    time.sleep(.1);assert p.poll() is None
                    break
                if closed:time.sleep(.01);continue
                if not select.select([master],[],[],.01)[0]:continue
                chunk=os.read(master,65536);assert chunk;raw.extend(chunk)
                if not admitted and b'\n' in raw:
                    header,rest=bytes(raw).split(b'\n',1);assert not rest
                    m=re.fullmatch(rb'M15PCSMOKE1 ([0-9a-f]{32}) ([0-9a-f]{64})',header);assert m
                    raw.clear();admitted=True
                    if mode=='missing-admission':continue
                    if mode=='disconnect':os.close(master);closed=True;continue
                    reply=b'M15PC1 '+m[1]+b' '+m[2]+b'\n'
                    if mode=='wrong-admission':reply=reply.replace(b'M15PC1',b'M15BAD')
                    os.write(master,reply)
                elif admitted and not ack and re.search(rb'\nF [0-9]+ [0-9]+ [0-9a-f]{64} [0-9a-f]{64}\n$',raw):
                    r=Receiver(out/(mode+'.raw'));r.feed(bytes(raw));answer=r.finish(len(raw))
                    if mode=='missing-final':ack=True;continue
                    if mode=='wrong-final':answer=answer[:-2]+b'g\n'
                    # Fragmented host ACK exercises independent stream boundaries.
                    for x in answer:os.write(master,bytes([x]))
                    ack=True
            else:raise AssertionError('fixture deadline: '+text)
            (out/(mode+'.journal')).write_bytes(journal.read_bytes())
        finally:
            os.killpg(p.pid,signal.SIGKILL);p.wait(timeout=5) # test-only namespace disposal
            log.close();os.close(slave)
            if not closed:os.close(master)
            # Synthetic CI artifacts only: production Receiver still creates
            # private 0600 files. Permit the non-root upload action to read them.
            for artifact in out.iterdir():
                if artifact.is_file():artifact.chmod(0o644)
        print('PASS',mode,flush=True)
print('PASS 8 actual PID1/PTTY/Custodian/O3 integration cases; synthetic telemetry; no hardware')
