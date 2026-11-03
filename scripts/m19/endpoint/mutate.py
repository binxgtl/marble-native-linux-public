#!/usr/bin/env python3
"""Restore critical endpoint defects. Every compiled mutation must fail its test."""
import argparse,os,shutil,subprocess,sys,tempfile
from pathlib import Path
HERE=Path(__file__).resolve().parent
MUTANTS=(
    ('endpoint.c','if (!api.associate_class(binder, associated_class)) {','if (0) {','wrongremote',5),
    ('endpoint.c','if (!descriptor_matches(actual_descriptor)) {','if (0) {','wrongdesc',6),
    ('endpoint.c','binder = api.check_service(k_instance);','binder = api.check_service(k_instance);\n    binder = api.check_service(k_instance);','',0),
    ('endpoint.c','api.dec_strong(binder);','(void)binder;','',0),
    ('endpoint.c','result->detail_errno = captured_errno;','result->detail_errno = 0;','associatefalse',5),
    ('supervisor.c','return next == 5 && p->stage == 4 && p->flags == 31 && !p->detail_errno;','return 1;','protocol',None),
    ('supervisor.c','if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) || getppid() != parent) _exit(125);','(void)parent;','parent-death',None),
)
def run(cmd,**kwargs):return subprocess.run(cmd,capture_output=True,timeout=10,**kwargs)
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--out',type=Path,required=True);a=parser.parse_args()
    output=a.out.resolve();output.mkdir(exist_ok=True,parents=True)
    library=output/'fake-normal.so';assert library.is_file()
    flags=['gcc','-std=c11','-O1','-w','-DM19_ENDPOINT_WORK_MS=500','-DM19_ENDPOINT_REAP_MS=300']
    survivors=[]
    for n,(name,old,new,fault,status) in enumerate(MUTANTS):
        source=(HERE/name).read_text();assert old in source,(n,'mutation does not apply')
        with tempfile.TemporaryDirectory(prefix='endpoint-mutant-') as path:
            root=Path(path)
            for f in HERE.iterdir():
                if f.suffix in ('.c','.h','.py'):shutil.copy(f,root/f.name)
            (root/name).write_text(source.replace(old,new))
            if name=='endpoint.c':
                executable=root/'core'
                built=run([*flags,f'-DM19_ENDPOINT_LIBRARY="{library}"',str(root/'endpoint.c'),str(root/'test-core.c'),'-ldl','-o',str(executable)])
                if built.returncode:raise SystemExit(f'mutant{n} compile failed: '+built.stderr.decode())
                result=run([str(executable),str(status)],env=dict(os.environ,M19_ENDPOINT_TEST_FAULT=fault))
            else:
                executable=root/'hostile-normal'
                built=run([*flags,str(root/'test-supervisor.c'),'-o',str(executable)])
                if built.returncode:raise SystemExit(f'mutant{n} compile failed: '+built.stderr.decode())
                result=run([sys.executable,str(HERE/'test.py'),'--out',str(root),'--variant','normal','--case',fault])
                assert result.returncode==1 and b'FAIL:' in result.stderr and b'ERROR:' not in result.stderr,result.stderr
            (output/f'mutant-{n}.txt').write_bytes(result.stdout+result.stderr)
            if not result.returncode:survivors.append(n)
        print(f'endpoint mutant {n}: '+('SURVIVED' if n in survivors else 'rejected'),flush=True)
    print(f'{len(MUTANTS)-len(survivors)} of {len(MUTANTS)} endpoint mutants rejected')
    return bool(survivors)
if __name__=='__main__':sys.exit(main())
