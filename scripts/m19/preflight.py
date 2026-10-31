#!/usr/bin/env python3
"""Offline M19 preflight. Combines the survey, the TWRP audit and the module closures.

PASS here means a candidate may be designed. It proves nothing about hardware.
"""
import json
import re
import sys
from pathlib import Path

import fbe
import plan
import rootfs

ROOT = Path(__file__).resolve().parents[2]
CLOSURES = ('manifests/m16-run1-closure.tsv', 'manifests/m9-run2w-closure.tsv')


def closure_names():
    names = set()
    for path in CLOSURES:
        names.update(re.findall(r'[\w-]+\.ko', (ROOT / path).read_text(encoding='utf-8')))
    return names


def evaluate(survey, audit, names):
    gates = plan.preflight(survey, audit, names)
    try:
        fbe.userdata_contract(fbe.parse_fstab_entry(survey.get('fstab_userdata', '')))
        gates.append(plan.Gate('USERDATA_CONTRACT', 'PASS'))
    except fbe.Stop as stop:
        gates.append(plan.Gate('USERDATA_CONTRACT', 'STOP', str(stop)))
    try:
        rootfs.check_mountpoints(rootfs.plan(), set(survey.get('rootfs_paths', ())))
        gates.append(plan.Gate('ROOTFS_MOUNTPOINTS', 'PASS'))
    except fbe.Stop as stop:
        gates.append(plan.Gate('ROOTFS_MOUNTPOINTS', 'STOP', str(stop)))
    return gates


def main():
    survey = json.loads((ROOT / 'manifests/m19-device-survey.json').read_text(encoding='utf-8'))
    audit = json.loads((ROOT / 'manifests/m19-twrp-audit.json').read_text(encoding='utf-8'))
    gates = evaluate(survey, audit, closure_names())
    for gate in gates:
        print(f'{gate.verdict:4} {gate.name} {gate.detail}'.rstrip())
    sys.exit(1 if plan.blocking(gates) else 0)


if __name__ == '__main__':
    main()
