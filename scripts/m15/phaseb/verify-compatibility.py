#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Lock O1 production/test bytes and credential-free golden replay, offline."""
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent
j=json.loads((HERE/'compatibility-lock.json').read_bytes())
assert j['schema']=='M15O1-compatibility-lock-v1'
assert len(j['sha256'])==7
for name,digest in j['sha256'].items():
    assert hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==digest,name
print('M15O1 compatibility PASS: five original production/test files and two synthetic golden replay files exact')
