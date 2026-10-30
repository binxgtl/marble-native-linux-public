#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
import os,sys
if os.environ.get('M15_FAKE_DISPLAY_ERROR'):
    os.write(3,b'M15DISPLAY ERROR\n')
    for line in sys.stdin:pass
    raise SystemExit(0)
os.write(3,b'M15DISPLAY 0 WAIT committed\n' if sys.argv[1:]==['wait'] else b'M15DISPLAY 0 BLUE committed\n')
for line in sys.stdin:
    tag,seq,color=line.strip().split()
    assert tag=='M15COLOR'
    os.write(3,f'M15DISPLAY {seq} {color} mapped\n'.encode())
