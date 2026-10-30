#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Keeps the closure delta honest. Checks the ROM hash only where a local ROM exists."""
import hashlib
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def cpio_file(data, wanted):
    pos = 0
    while pos + 110 <= len(data):
        fields = [int(data[pos + 6 + i * 8:pos + 14 + i * 8], 16) for i in range(13)]
        size, name_size = fields[6], fields[11]
        name = data[pos + 110:pos + 110 + name_size - 1].decode('latin1')
        body = (pos + 110 + name_size + 3) & ~3
        if name == 'TRAILER!!!':
            break
        if name == wanted:
            return data[body:body + size]
        pos = (body + size + 3) & ~3
    raise SystemExit(f'{wanted} not in ramdisk')


def main():
    delta = json.loads((HERE / 'closure-delta.json').read_text(encoding='utf-8'))
    assert delta['schema'] == 'm16-closure-delta-v1'
    assert delta['status'].startswith('OFFLINE RECOMMENDATION'), 'a delta is never a candidate'
    assert not delta['base_closure']['frozen_manifests_changed']
    assert [entry['module'] for entry in delta['add']] == ['rtc-pm8xxx.ko'], 'one causal variable'
    entry = delta['add'][0]
    kmi = entry['kmi']
    assert not kmi['unresolved'] and not kmi['crc_mismatch']
    assert kmi['resolved_in_vmlinux'] == kmi['undefined_symbols']
    assert all(supplier['in_base_closure'] for supplier in entry['suppliers'])
    assert not entry['dt_supplier_properties_seen']
    assert delta['not_proven'], 'limits must stay stated'
    checked = 'skipped, no local ROM'
    ramdisk = os.environ.get('M16_VENDOR_RAMDISK_CPIO')
    if ramdisk:
        blob = cpio_file(Path(ramdisk).read_bytes(), 'lib/modules/' + entry['module'])
        assert len(blob) == entry['size'] and hashlib.sha256(blob).hexdigest() == entry['sha256']
        checked = 'matches the canonical ROM ramdisk'
    print(json.dumps({'module': entry['module'], 'rom': checked}))
    return 0


if __name__ == '__main__':
    sys.exit(main())
