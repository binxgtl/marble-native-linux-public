#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""RED log pages through a real QR reader. Synthetic logs; proves encoding, not panel scanning."""
import shutil,struct,subprocess,sys,tempfile,zlib
from pathlib import Path
binary,keep=sys.argv[1],Path(sys.argv[2]);keep.mkdir(parents=True,exist_ok=True)
def chunk(kind,data):return struct.pack('>I',len(data))+kind+data+struct.pack('>I',zlib.crc32(kind+data))
def png(raw,path):
    width,height=1080,2400
    rows=bytearray()
    for y in range(height):
        rows.append(0)
        row=raw[y*width*4:(y+1)*width*4]
        rgb=bytearray(width*3);rgb[0::3]=row[2::4];rgb[1::3]=row[1::4];rgb[2::3]=row[0::4]
        rows+=rgb
    path.write_bytes(b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('>IIBBBBB',width,height,8,2,0,0,0))+chunk(b'IDAT',zlib.compress(bytes(rows),6))+chunk(b'IEND',b''))
def read(image):
    return subprocess.run(['zbarimg','--raw','-q','-Sdisable','-Sqrcode.enable','-Sbinary',str(image)],check=True,capture_output=True).stdout.rstrip(b'\n')
def run(name,journal,kernel,boot=b'M15 bootstrap OWN pid=2\n'):
    with tempfile.TemporaryDirectory() as tmp:
        d=Path(tmp)/'logs';out=Path(tmp)/'pages';d.mkdir();out.mkdir()
        if journal is not None:(d/'pid1.journal').write_bytes(journal)
        if kernel is not None:(d/'kernel.raw').write_bytes(kernel)
        (d/'bootstrap.log').write_bytes(boot)
        pages=int(subprocess.check_output([binary,str(d),str(out)]))
        text=b''
        for i in range(pages):
            want=(out/f'page-{i:02d}.txt').read_bytes()
            got=read(out/f'page-{i:02d}.pbm')
            assert got==want.rstrip(b'\n'),(i,got[:80],want[:80])
            head=f'M15 RED {i+1}/{pages}\n'.encode();assert want.startswith(head)
            text+=want[len(head):]
        frame=keep/f'{name}.png';png((out/'frame.raw').read_bytes(),frame)
        assert read(frame)==(out/'page-00.txt').read_bytes().rstrip(b'\n'),'full frame unreadable'
        print('PASS',name,pages,'pages',len(text),'bytes decoded')
        return text,pages,(out/'error.txt').read_text()
lines=b''.join(b'%d line %d\n'%(1000+i,i) for i in range(50))
journal=lines+b'2000 HOLD retained nonexclusive-process-scope\n2001 RED\n2002 RED_HOLD retain_no_teardown_no_reboot\n'
kernel=bytearray()
for i in range(4000):
    level=3 if i%50==0 else 6
    kernel+=b'%d,%d,%d,-,caller=T1;message %d level %d \\x0a\n SUBSYSTEM=fixture\n'%(level,i,1000000+i*12345,i,level)
text,_,error=run('full',journal,bytes(kernel))
assert error=='HOLD retained nonexclusive-process-scope'
assert text.startswith(b'--error HOLD retained nonexclusive-process-scope\n')
assert b'M15 bootstrap OWN' in text
assert b'--kernel-errors' in text and b'message 3950 level 3' in text
assert b'message 3999 level 6' in text and b'SUBSYSTEM' not in text
assert text.index(b'--kernel-errors')<text.index(b'--kernel-tail')
assert b'caller=T1' not in text
_,_,error=run('connector',lines+b'M15 connector failure errno=110\n3000 CONNECTOR_FAILED\n3001 RED\n3002 RED_HOLD x\n',b'')
assert error=='M15 connector failure errno=110'
text,pages,error=run('missing-files',None,None)
assert pages==1 and error=='no PID1 journal' and b'--journal 0' in text and b'--kernel-tail 0' in text
_,_,error=run('no-red',b'1000 alpha\n1001 beta\n',b'');assert error=='beta'
text,_,error=run('hostile-bytes',b'1 a\xff\x00b\n2 RED\n',b'3,1,5,-;x\xc3\xa9\n');assert error=='a??b' and b'x??' in text
print('PASS RED log pages and full frame read back; phone scanning UNKNOWN')
