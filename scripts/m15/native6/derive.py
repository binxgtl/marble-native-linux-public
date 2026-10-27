#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Derive narrowly reviewed successors; never edit frozen sources."""
import hashlib
import sys
from pathlib import Path
root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]); out.mkdir(parents=True, exist_ok=True)

def load(name, digest):
    s = (root/name).read_text()
    if hashlib.sha256(s.encode()).hexdigest() != digest:
        raise ValueError('frozen source drift: '+name)
    return s

def replace(s, old, new):
    if s.count(old) != 1: raise ValueError('ambiguous derivation')
    return s.replace(old, new)

s = load('scripts/m9-kms.c', '1686b9ce32edef809c511fd2a2572fcb69e27a1c4dfd5b6667411e97becae424')
s = replace(s, '#include "m9-kms.h"', '#include "m9-kms.h"\n#include "display-loop.h"')
s = replace(s, '\tsleep_ms(hold_ms);',
            '\t(void)sleep_ms;\n\tm15_display_loop(cpu_map, dumb.pitch); /* never returns; retains active DRM objects */')
(out/'display-kms.c').write_text(s)
s = load('scripts/m15/native4/custodian.c', 'df39e964715508bbf5d6a850ad54d12b45c2b08d4cea08ad2762337198798601')
s = replace(s, '#include "../native1/escrow.h"', '#include "escrow.h"')
s = replace(s, '#include "../native1/supervise.h"', '#include "supervise.h"')
s = replace(s, 'uint64_t deadline=now()+3000;', 'uint64_t deadline=now()+300000;')
s = replace(s, 'm15_supervise(s,collect,&a,10000,now(),&r)', 'm15_supervise(s,collect,&a,100000,now(),&r)')
start = s.index(' command(s,5,cmd);')
s = s[:start] + ' /* PC smoke retains original escrow after ACK. No release/reboot. */\n for(;;)pause();\n}\n'
(out/'custodian.c').write_text(s)
