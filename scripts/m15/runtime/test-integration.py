#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual production event loop, fake physical adapter; no hardware claims."""
import os,pty,select,signal,subprocess,sys,tempfile,time,re,json
from pathlib import Path
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE));import provenance,verify
pid1,custodian,observer,wire,out=map(lambda x:Path(x).resolve(),sys.argv[1:]);out.mkdir(parents=True,exist_ok=True)
files,_,_=verify.host.decode(wire.read_bytes())
for mode in ('complete','green-retained','wrong-reconnect','wrong-ack','connector-failure','missing-ack','pc-only','connector-start-failure','display-error'):
    with tempfile.TemporaryDirectory() as tmp:
        root=Path(tmp)
        for row in verify.host.contract.o3.legacy.load(files['capture.raw']):
            if row.get('kind')=='read_end' and row['rc']==0:
                p=root/'fixture'/'class'/row['group']/row['path'];p.parent.mkdir(parents=True,exist_ok=True);p.write_text(row['value']+'\n')
        paths={}
        for role in provenance.ROLES:
            p=root/role;p.write_bytes(('fixture-'+role).encode());paths[role]=str(p)
        meta=root/'metadata.json';meta.write_text(json.dumps(provenance.inventory(paths,True,"pc-admission-only" if mode=="pc-only" else "pc-wall-pc")),encoding='utf-8')
        km=root/'kmsg';km.write_bytes(b'6,100,1000,-;fixture kernel\n')
        fifo=root/'events';os.mkfifo(fifo);events=os.open(fifo,os.O_RDWR|os.O_NONBLOCK)
        master,slave=pty.openpty();os.set_blocking(master,False)
        env=dict(os.environ,M15_RUN=str(root),M15_CUSTODIAN=str(custodian),M15_DISPLAY=str(HERE.parent/'native6/fake-display.py'),M15_CONNECTOR=str(HERE/'fake-connector.py'),M15_OBSERVER=str(observer),M15_TTY=os.ttyname(slave),M15_KMSG=str(km),M15_FIXTURE_ROOT=str(root/'fixture'),M15_EVENTS=str(fifo))
        if mode=='connector-start-failure':env['M15_FAKE_CONNECTOR_START']='CONNECTOR_FAILED'
        if mode=='display-error':env['M15_FAKE_DISPLAY_ERROR']='1'
        log=(out/(mode+'.process')).open('wb')
        process=subprocess.Popen(['unshare','--mount','--pid','--fork','--mount-proc',str(pid1),str(meta),'pc-admission-only' if mode=='pc-only' else 'pc-wall-pc'],env=env,stdout=log,stderr=log,start_new_session=True)
        journal=root/'pid1.journal';pending=bytearray()
        def text():return journal.read_text() if journal.exists() else ''
        def until(s,seconds=12):
            end=time.monotonic()+seconds
            while time.monotonic()<end:
                assert process.poll() is None,'PID1 unexpectedly exited'
                if s in text():return
                assert 'RED_HOLD' not in text() or s=='RED_HOLD',text()
                time.sleep(.01)
            raise AssertionError('deadline '+s+'\n'+text())
        def line():
            end=time.monotonic()+12
            while b'\n' not in pending:
                assert time.monotonic()<end,text()
                if select.select([master],[],[],.02)[0]:pending.extend(os.read(master,65536))
            answer,rest=bytes(pending).split(b'\n',1);pending[:]=rest;return answer
        try:
            if mode=='connector-start-failure':
                # Run2's path: no USB, no host. RED must now reach the screen before any admission.
                until('RED_HOLD');assert re.search(r'^\d+ RED$',text(),re.M) and 'M15NATIVE1' not in text()
                assert process.poll() is None
                (out/(mode+'.journal')).write_bytes(journal.read_bytes())
                print('PASS',mode,flush=True);continue
            header=line().split();assert header[0]==b'M15NATIVE1';nonce,binding=header[1:3];experiment=b'pc-admission-only' if mode=='pc-only' else b'pc-wall-pc';assert header[3]==experiment
            assert binding.decode()==verify.host.sha(meta.read_bytes())
            os.write(master,b'M15PC1 '+nonce+b' '+binding+b'\n')
            if mode=='display-error':
                until('RED_HOLD');assert 'M15DISPLAY ERROR' in text() and 'BLUE mapped' not in text()
                (out/(mode+'.journal')).write_bytes(journal.read_bytes())
                print('PASS',mode,flush=True);continue
            until('M15DISPLAY 0 WAIT committed');until('M15DISPLAY 1 BLUE mapped')
            assert 'COLLECT_BEGIN' not in text()
            if mode=='pc-only':
                time.sleep(.2);assert 'PC_ONLY retain_no_wall_admission' in text();os.write(events,b'REMOVED\n');until('RED_HOLD');assert 'COLLECT_BEGIN' not in text()
            elif mode=='connector-failure':
                os.write(events,b'CONNECTOR_FAILED\n');until('RED_HOLD')
            else:
                os.write(events,b'REMOVED\n');until('M15DISPLAY 2 YELLOW mapped')
                os.write(events,b'ATTACHED\n');until('M15DISPLAY 3 GREEN mapped')
                time.sleep(.3);assert 'CYAN' not in text(),'GREEN advanced without PC'
                if mode!='green-retained':
                    os.write(events,b'REMOVED\n');time.sleep(.1);assert 'CYAN' not in text()
                    os.write(events,b'ATTACHED\n');header=line().split();assert header==[b'M15RETURN1',nonce,binding,experiment]
                    answer=b'M15PC2 '+nonce+b' '+binding+b'\n'
                    if mode=='wrong-reconnect':
                        os.write(master,answer.replace(nonce,b'0'*32));until('RED_HOLD');assert 'CYAN' not in text()
                    else:
                        os.write(master,answer);raw=bytearray()
                        end=time.monotonic()+10
                        while not re.search(rb'\nF [0-9]+ [0-9]+ [0-9a-f]{64} [0-9a-f]{64}\n$',raw):
                            assert time.monotonic()<end,text()
                            if pending:raw.extend(pending);pending.clear()
                            elif select.select([master],[],[],.02)[0]:raw.extend(os.read(master,65536))
                        data,report,ack=verify.decode(bytes(raw),allow_fixture=True)
                        assert report['synthetic_only'] and not report['native_runtime_proven']
                        try:verify.decode(bytes(raw))
                        except ValueError:pass
                        else:raise AssertionError('fixture accepted as native')
                        (out/(mode+'.raw')).write_bytes(raw)
                        if mode=='missing-ack':until('RED_HOLD',15)
                        else:
                            os.write(master,ack if mode=='complete' else ack[:-2]+b'g\n')
                            if mode=='wrong-ack':until('RED_HOLD')
                            else:
                                terminal=line();assert terminal==b'M15DONE1 '+ack[8:].rstrip(b'\n')
                                (out/(mode+'.terminal')).write_bytes(terminal+b'\n')
                                until('COMPLETE retain_RAM_ADSP_USB_display')
            assert process.poll() is None
            (out/(mode+'.journal')).write_bytes(journal.read_bytes())
        finally:
            os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=5)
            log.close();os.close(events);os.close(master);os.close(slave)
            for p in out.iterdir():
                if p.is_file():p.chmod(0o644)
        print('PASS',mode,flush=True)
print('PASS 9 native-loop cases; real display NOT executed; fixture only')
