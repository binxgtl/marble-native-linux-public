#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
import os,sys
os.write(3,b'M15DISPLAY 0 BLUE committed\n')
for line in sys.stdin:
    tag,seq,color=line.strip().split()
    assert tag=='M15COLOR'
    os.write(3,f'M15DISPLAY {seq} {color} mapped\n'.encode())
