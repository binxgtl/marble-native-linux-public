#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Real namespace PID1 with unchanged O3, separate custodian and saved-file ACK.
Only fixture paths. Test completion exits namespace, never a production PID1.
"""
import os,sys,selectors,subprocess,tempfile,time,json
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'native3'))
from receiver import Receiver,host
assert os.getpid()==1,'PID namespace is mandatory; do not substitute subreaper'
custodian,observer,wire=map(lambda s:Path(s).resolve(),sys.argv[1:])
with tempfile.TemporaryDirectory() as d:
    root=Path(d);files,_,_=host.decode(wire.read_bytes())
    for row in host.contract.o3.legacy.load(files['capture.raw']):
        if row.get('kind')=='read_end' and row['rc']==0:
            path=root/'fixture'/'class'/row['group']/row['path'];path.parent.mkdir(parents=True,exist_ok=True)
            path.write_text(row['value']+'\n')
    logger=subprocess.Popen(['sleep','1'])
    p=subprocess.Popen([str(custodian),'--offline-fixture',str(observer),str(root/'fixture'),'collect'],
                       stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    selector=selectors.DefaultSelector();lines=[];pending=b'';raw=bytearray()
    for stream in (p.stdout,p.stderr):
        os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ)
    def until(prefix):
        global pending
        deadline=time.monotonic()+15
        while time.monotonic()<deadline:
            for i,line in enumerate(lines):
                if line.startswith(prefix):return lines.pop(i)
            for key,_ in selector.select(.02):
                chunk=os.read(key.fileobj.fileno(),4096)
                if not chunk:selector.unregister(key.fileobj);continue
                if key.fileobj is p.stdout:raw.extend(chunk)
                else:
                    pending+=chunk
                    while b'\n' in pending:
                        line,pending=pending.split(b'\n',1);lines.append(line)
            if p.poll() is not None:raise AssertionError('custodian-lost; escrow/safety UNKNOWN')
        raise AssertionError('deadline; no release permission')
    ready=until(b'READY ').split();nonce,binding=ready[1:]
    assert nonce!=b'0102030405060708090a0b0c0d0e0f10'
    def command(seq,body):
        p.stdin.write(b'M15IPC1 '+nonce+b' '+str(seq).encode()+b' '+body);p.stdin.flush()
    command(0,b'M15PC1 '+nonce+b' '+binding+b'\n');until(b'ISOLATE_BEGIN')
    command(1,b'ISOLATED 1 1\n');until(b'WALL_WAIT')
    command(2,b'WALL 1 1\n');until(b'FROZEN')
    # Parent owns its logger; custodian must not consume its wait fact.
    assert logger.wait(timeout=2)==0
    command(3,b'PC 1\n');length=int(until(b'WAIT_ACK ').split()[1])
    deadline=time.monotonic()+2
    while len(raw)<length and time.monotonic()<deadline:
        for key,_ in selector.select(.02):
            chunk=os.read(key.fileobj.fileno(),4096)
            assert key.fileobj is p.stdout and chunk;raw.extend(chunk)
    assert len(raw)==length
    r=Receiver(root/'raw');r.feed(bytes(raw));ack=r.finish(length)
    command(4,ack);until(b'RECOVERED')
    assert p.poll() is None,'custodian exited before parent release'
    with (root/'parent-receipt').open('xb') as f:
        f.write(json.dumps({'evidence_recovered':True,'nonce':nonce.decode(),'control_permitted':False}).encode());f.flush();os.fsync(f.fileno())
    command(5,b'RELEASE evidence_only\n');assert p.wait(timeout=3)==0
    try:os.waitpid(-1,os.WNOHANG)
    except ChildProcessError:pass
    else:raise AssertionError('parent census unresolved')
    for f in (p.stdin,p.stdout,p.stderr):f.close()
    selector.close()
print('PASS actual PID1 -> custodian -> unchanged O3 -> saved-file ACK -> parent receipt -> release; hardware UNKNOWN')
