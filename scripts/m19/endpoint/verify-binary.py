#!/usr/bin/env python3
"""Static Android endpoint-artifact boundary check. Never runs the target ELF."""
import argparse,hashlib,json,re,struct,subprocess
from pathlib import Path

SYMBOLS=('AParcel_markSensitive','AServiceManager_checkService','AIBinder_Class_define',
         'AIBinder_associateClass','AIBinder_getClass','AIBinder_Class_getDescriptor','AIBinder_decStrong')
FORBIDDEN_IMPORTS={'ioctl','syscall','mount','umount','umount2','execve','execv','system','popen','posix_spawn',
                   'creat','mkdir','unlink','rename','truncate','pwrite','pwrite64','fopen','getenv','dlclose'}
FORBIDDEN_BYTES=(b'/metadata',b'/data/',b'keymaster_key_blob',b'secdiscardable',b'getSecurityLevel',
                 b'createOperation',b'convertStorageKey',b'AIBinder_new',b'AIBinder_transact',
                 b'AIBinder_prepareTransaction',b'AServiceManager_getService',b'AServiceManager_waitForService',
                 b'M19_ENDPOINT_TEST_FAULT',b'M19_ENDPOINT_HOSTILE',b'm19_fake_binder_verify')

def inspect(binary,readelf):
    raw=binary.read_bytes()
    assert raw[:6]==b'\x7fELF\x02\x01'
    assert struct.unpack_from('<HH',raw,16)==(3,183),'require Android ARM64 PIE'
    def read(*args):return subprocess.check_output([str(readelf),*args,str(binary)],text=True)
    dynamic=read('-d');symbols=read('--dyn-syms','--wide');programs=read('-l')
    needed=re.findall(r'\(NEEDED\).*?\[([^\]]+)\]',dynamic)
    assert set(needed)=={'libdl.so','libc.so'},needed
    imports=[]
    for line in symbols.splitlines():
        fields=line.split()
        if len(fields)>=8 and fields[6]=='UND':imports.append(fields[7].split('@')[0])
    assert imports and not FORBIDDEN_IMPORTS.intersection(imports),imports
    assert not any(name.startswith(('AIBinder_','AParcel_','AServiceManager_')) for name in imports),imports
    assert {'dlopen','dlsym','fork','waitpid','kill','prctl','clock_gettime','poll','pipe2'}.issubset(imports)
    assert '/system/bin/linker64' in programs
    for name in SYMBOLS:assert name.encode()+b'\0' in raw,name
    assert b'libbinder_ndk.so\0' in raw
    for value in FORBIDDEN_BYTES:assert value not in raw,value
    assert b'android.system.keystore2.IKeystoreService/default\0' in raw
    assert b'M19_ENDPOINT1 final=' in raw
    # Inspect all executable load segments, including the PLT, for direct syscalls.
    phoff=struct.unpack_from('<Q',raw,32)[0];entsize,count=struct.unpack_from('<HH',raw,54)
    executable=[]
    for n in range(count):
        kind,flags,offset,vaddr,_,size,_,_=struct.unpack_from('<IIQQQQQQ',raw,phoff+n*entsize)
        if kind==1 and flags&1:
            executable.append({'vaddr':vaddr,'bytes':size})
            for i in range(offset,offset+size-3,4):
                word=struct.unpack_from('<I',raw,i)[0]
                assert word&0xffe0001f!=0xd4000001,('direct SVC',hex(vaddr+i-offset))
    return {'schema':'M19-endpoint-static-boundary-v1','bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
            'needed':needed,'imports':imports,'dynamic_binder_symbol_allowlist':list(SYMBOLS),
            'direct_syscall_instructions':False,'forbidden_imports_and_literals_absent':True,
            'executable_segments':executable,'binary_executed':False,
            'real_Binder_or_device_qualified':False,'remote_logging_or_system_writes_excluded':False}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--binary',type=Path,required=True)
    p.add_argument('--readelf',type=Path,required=True);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
    report=inspect(a.binary,a.readelf)
    a.report.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k not in ('imports','executable_segments')},indent=2))
