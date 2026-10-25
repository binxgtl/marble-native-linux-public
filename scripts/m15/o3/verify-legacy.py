#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Keep all original O1/O2 files byte-identical; O3 acquisition changes headers only."""
import hashlib
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
lock=json.loads((HERE/'legacy-lock.json').read_bytes())
assert lock['schema']=='M15-legacy-observation-lock-v1'
for name,digest in lock['sha256'].items():
    assert hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==digest,name
old=(ROOT/'scripts/m15/phaseb/observe.c').read_text()
needle='samples,NF);printf(",\\\"extension'
replacement='samples,NF);printf(",\\\"power_supply_contract\\\":\\\"usb-or-usb-pd-v1\\\"");printf(",\\\"extension'
expected=old.replace('M15O2','M15O3').replace(needle,replacement,1)
assert (HERE/'observe.c').read_text()==expected,'O3 acquisition changed beyond version/contract declaration'
print(f"Legacy M15 source/fixture lock PASS: {len(lock['sha256'])} files; O3 producer changes only schema/contract header")
