#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""O1/O2/comparator-v2 and O3 producer/decoder source preservation, offline."""
import hashlib
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
lock=json.loads((HERE/'legacy-lock.json').read_bytes())
assert lock['schema']=='M15-O3-integration-legacy-lock-v1'
assert len(lock['sha256'])==39
for name,digest in lock['sha256'].items():assert hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==digest,name
print('Legacy M15 integration lock PASS: all39 prior source/test/fixture files exact, including O1/O2, comparator v2 and O3 producer/replay')
