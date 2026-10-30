#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
import os,selectors,sys
fd=os.open(os.environ['M15_EVENTS'],os.O_RDWR|os.O_NONBLOCK)
s=selectors.DefaultSelector();s.register(0,selectors.EVENT_READ);s.register(fd,selectors.EVENT_READ)
print(os.environ.get('M15_FAKE_CONNECTOR_START','CONNECTOR_READY'),flush=True)
pending={0:b'',fd:b''}
while True:
    for key,_ in s.select():
        n=key.fd;b=os.read(n,4096)
        if not b:raise SystemExit(2)
        pending[n]+=b
        while b'\n' in pending[n]:
            line,pending[n]=pending[n].split(b'\n',1)
            if n==0:
                assert line in (b'UNBIND',b'BIND')
                print('UNBOUND' if line==b'UNBIND' else 'BOUND',flush=True)
            else:print(line.decode(),flush=True)
