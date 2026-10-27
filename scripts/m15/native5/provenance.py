#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Offline native build inventory. Never substitutes for a runtime receipt."""
import argparse
import hashlib
import json
from pathlib import Path

ROLES = ('observer', 'pid1', 'custodian', 'display', 'kernel', 'closure',
         'firmware_inventory', 'topology', 'source_lock')

def inventory(paths):
    if set(paths) != set(ROLES):
        raise ValueError('exact-native-role-set-required')
    files = {}
    for role in ROLES:
        path = Path(paths[role])
        if not path.is_file() or path.is_symlink():
            raise ValueError('regular-local-file-required')
        raw = path.read_bytes()
        if not raw:
            raise ValueError('empty-input')
        files[role] = {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
    return {'schema': 'M15-native-build-inventory-v1', 'files': files,
            'runtime_identity_verified': False, 'comparison_eligible': False,
            'candidate_ready': False, 'sealed_baseline': False,
            'control_permitted': False,
            'freshness': 'UNKNOWN', 'negotiated_contract': 'UNKNOWN',
            'protection_active': 'UNKNOWN', 'device_safety': 'UNKNOWN'}

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--paths', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    args = p.parse_args()
    report = inventory(json.loads(args.paths.read_text()))
    with args.out.open('x', encoding='utf-8', newline='\n') as f:
        json.dump(report, f, sort_keys=True, indent=2)
        f.write('\n')

if __name__ == '__main__':
    main()
