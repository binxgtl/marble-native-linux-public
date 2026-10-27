#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
import os,signal,subprocess,sys,tempfile,time
from pathlib import Path
binary=Path(sys.argv[1]).resolve()
with tempfile.TemporaryDirectory() as d:
    root=Path(d)
    runtime=root/'runtime';runtime.write_text('#!/bin/sh\necho RUNTIME_ENTERED\nwhile :; do sleep 1; done\n');runtime.chmod(0o755)
    for name,body in [('success','exit 0'),('error','exit 1'),('blocked','sleep 10'),('orphan','sleep 10 &\nexit 0')]:
        worker=root/name;worker.write_text('#!/bin/sh\n'+body+'\n');worker.chmod(0o755)
        log=root/(name+'.log')
        with log.open('wb') as f:
            p=subprocess.Popen(['unshare','--mount','--pid','--fork','--mount-proc',str(binary)],stdout=f,stderr=f,env=dict(os.environ,M15_BOOT_WORKER=str(worker),M15_BOOT_RUNTIME=str(runtime)),start_new_session=True)
            try:
                end=time.monotonic()+4
                while time.monotonic()<end:
                    s=log.read_text()
                    if 'RUNTIME_ENTERED' in s or 'bootstrap HOLD' in s:break
                    assert p.poll() is None;time.sleep(.01)
                else:raise AssertionError(name+' deadline')
                assert ('RUNTIME_ENTERED' in s)==(name=='success'),s
                assert p.poll() is None
            finally:os.killpg(p.pid,signal.SIGKILL);p.wait(timeout=5)
        print('PASS bootstrap',name)
