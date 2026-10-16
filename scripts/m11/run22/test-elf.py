"""Execute canonical ARM64 ELF in an isolated synthetic root with own PTY.

Root required for chroot/temporary bind of the test's private PTY. No phone,
kernel log device, USB, mixer, real modules or firmware are opened.
"""
import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import select
import shutil
import subprocess
import tempfile
import time
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('checker',HERE/'check-capture.py');checker=importlib.util.module_from_spec(spec);spec.loader.exec_module(checker)
JN='7'*32;JI='9'*64
def journal():
    # Minimal complete runner journal accepted by evidence.inspect_journal for JN/JI.
    conditions=('runtime_transport','graph_topology','amp_disabled','runtime_route','calibration_applied','protection_active','gain_valid','teardown')
    rows=[('session','identity',0,(JN+' '+JI).encode())]+[(c,'unsupported',95,b'not_implemented') for c in conditions]
    rows.append(('session','final_state',0,b'amp_enable_permitted=0 actuator_implemented=0'))
    raw=b''.join(f'M11I1 {n} 1.00 {c} {op} metadata {rc} {x.hex()}\n'.encode() for n,(c,op,rc,x) in enumerate(rows))
    return raw+f'M11I1 END {len(rows)} {hashlib.sha256(raw).hexdigest()}\n'.encode()
p=argparse.ArgumentParser();p.add_argument('elf',type=Path);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
assert os.geteuid()==0
with tempfile.TemporaryDirectory(prefix='m11-relay-pty-') as d:
    root=Path(d);(root/'dev').mkdir();(root/'run/m11-instrumentation').mkdir(parents=True);(root/'sbin').mkdir()
    binary=root/'sbin/relay';shutil.copyfile(a.elf,binary);binary.chmod(0o755)
    # Files model single complete devkmsg record and bounded event journal.
    (root/'dev/kmsg').write_bytes(b'6,42,123,-;synthetic PTY only\n')
    event=journal()
    (root/'run/m11-instrumentation/journal').write_bytes(event);(root/'run/m11-instrumentation/usb.ready').write_text('1\n')
    master,slave=os.openpty();node=root/'dev/ttyGS0';node.touch();proc=None;data=bytearray();mounted=False
    try:
        subprocess.run(['mount','--bind',os.ttyname(slave),str(node)],check=True);mounted=True
        proc=subprocess.Popen(['chroot',str(root),'/sbin/relay'],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        deadline=time.monotonic()+12;requested=False
        while time.monotonic()<deadline:
            ready,_,_=select.select([master],[],[],0.1)
            if ready:data.extend(os.read(master,65536))
            if not requested and b'synthetic PTY only\n' in data:
                stop=root/'run/m11-instrumentation/logger.stop.tmp';stop.write_text(str(len(event))+'\n');stop.rename(root/'run/m11-instrumentation/logger.stop');requested=True
            if proc.poll() is not None:break
        assert proc.poll()==0,(proc.poll(),bytes(data),proc.stderr.read() if proc.poll() is not None else 'timeout')
        while select.select([master],[],[],0)[0]:data.extend(os.read(master,65536))
        streams,r=checker.decode(bytes(data),JN,JI);assert r['event_stream_complete'] and bytes(streams['E'])==event,r
        assert requested and (root/'run/m11-instrumentation/logger.done').read_bytes()==b'1\n'
        a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_bytes(data)
        print('PASS actual pinned ARM64 ELF getrandom/termios/tty/stop/seal/done -> independent SHA256 + runner journal inspection; private PTY only')
    finally:
        if proc is not None and proc.poll() is None:proc.kill();proc.wait()
        os.close(master);os.close(slave)
        if mounted:subprocess.run(['umount',str(node)],check=True)
