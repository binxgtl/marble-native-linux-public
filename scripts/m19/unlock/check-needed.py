#!/usr/bin/env python3
"""Refuse a client that needs a library outside the set the recovery ramdisk provides."""
import re
import sys
from pathlib import Path

ALLOWED = {'libbinder_ndk.so', 'libc.so', 'libdl.so', 'libm.so'}

needed = set(re.findall(r'\[(lib[^\]]+)\]', Path(sys.argv[1]).read_text(encoding='utf-8')))
extra = needed - ALLOWED
if extra or 'libbinder_ndk.so' not in needed:
    sys.exit(f'unexpected libraries: {sorted(extra)}, found {sorted(needed)}')
print('needed libraries PASS:', ' '.join(sorted(needed)))
