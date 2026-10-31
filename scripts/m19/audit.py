#!/usr/bin/env python3
"""Audit a local recovery image against the M19 TEE environment.

Output holds names, sizes, hashes and selected build properties only, so it is safe to
commit. The image itself is proprietary and stays in artifacts/.
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path

import bootimage
import elfdeps
import plan

ROOT = Path(__file__).resolve().parents[2]
LIBRARY_DIRS = ('system/lib64', 'vendor/lib64', 'vendor/lib64/hw', 'system/lib64/hw')
# qseecomd loads these with dlopen, so DT_NEEDED cannot find them. Names from a live maps file.
DLOPEN_SEEDS = ('vendor/lib64/librpmb.so', 'vendor/lib64/libssd.so', 'vendor/lib64/libops.so',
                'vendor/lib64/libdrmfs.so', 'vendor/lib64/libqisl.so', 'vendor/lib64/libGPreqcancel_svc.so')
DATA_SEEDS = ('sepolicy', 'file_contexts.bin', 'plat_property_contexts', 'system/etc/ld.config.txt',
              'system/etc/ueventd.rc', 'system/etc/selinux/plat_hwservice_contexts',
              'system/etc/selinux/plat_service_contexts', 'system/etc/selinux/plat_keystore2_key_contexts',
              'system/etc/init/keystore2.rc', 'system/etc/init/servicemanager.rc', 'system/etc/init/hwservicemanager.rc',
              'system/etc/init/vndservicemanager.rc', 'vendor/etc/init/qseecomd.rc',
              'vendor/etc/init/android.hardware.keymaster@4.1-service-qti.rc', 'prop.default')
PROPERTIES = ('ro.build.version.release', 'ro.build.version.security_patch', 'ro.vendor.build.security_patch',
              'ro.build.version.sdk', 'ro.twrp.version.skkk.code', 'ro.vndk.version', 'ro.build.date')


def seeds():
    binaries = [path.lstrip('/') for _, path in (*plan.TEE_SERVICES, *plan.CE_ONLY_SERVICES)]
    return (*binaries, 'system/bin/init', 'system/bin/linker64', *DLOPEN_SEEDS)


def properties(text):
    found = {}
    for line in text.splitlines():
        name, _, value = line.partition('=')
        if name in PROPERTIES:
            found[name] = value
    return found


def audit(image, carrier=None):
    header = bootimage.parse_header(image)
    files, links = {}, {}
    for name, mode, data in bootimage.newc(bootimage.ramdisk(image)):
        kind = mode & bootimage.S_IFMT
        if kind == bootimage.S_IFREG:
            files[name] = data
        elif kind == bootimage.S_IFLNK:
            links[name] = data.decode('utf-8', 'replace')
    resolved, unresolved = elfdeps.closure([path for path in seeds() if path in files], files, LIBRARY_DIRS)
    missing = sorted({*(path for path in (*seeds(), *DATA_SEEDS) if path not in files), *unresolved})
    scripts = [data.decode('utf-8', 'replace') for name, data in files.items()
               if name.endswith('.rc') and name != plan.RC_REPLACED and name not in plan.RECOVERY_REMOVED]
    report = {
        'schema': 1,
        'image_sha256': hashlib.sha256(image).hexdigest(),
        'image_bytes': len(image),
        'header': {'version': header.version, 'kernel_size': header.kernel_size, 'os_version': header.os_version,
                   'os_patch': header.os_patch},
        'ramdisk_entries': len(files) + len(links),
        'properties': properties(files.get('prop.default', b'').decode('utf-8', 'replace')),
        'missing_seeds': missing,
        'removed_at_staging_present': [path for path in plan.RECOVERY_REMOVED if path in files],
        'rc_starts': sorted(set().union(*map(plan.rc_starts, scripts))),
        'forbidden_binaries': [path for path in plan.FORBIDDEN_BINARIES if path in files or path in links],
        'closure_bytes': sum(len(files[path]) for path in resolved),
        'closure': [{'path': path, 'bytes': len(files[path]), 'sha256': hashlib.sha256(files[path]).hexdigest()}
                    for path in resolved],
    }
    if carrier is not None:
        fields = bootimage.parse_header(carrier)
        report['carrier_header'] = {'os_version': fields.os_version, 'os_patch': fields.os_patch}
        report['carrier_sha256'] = hashlib.sha256(carrier).hexdigest()
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--image', type=Path, default=ROOT / 'artifacts/m19/survey/recovery_a.img')
    parser.add_argument('--carrier', type=Path, default=ROOT / 'artifacts/m15/pc-run1-preparation/pinned-carrier.img')
    parser.add_argument('--out', type=Path, default=ROOT / 'manifests/m19-twrp-audit.json')
    arguments = parser.parse_args()
    report = audit(arguments.image.read_bytes(), arguments.carrier.read_bytes())
    arguments.out.write_text(json.dumps(report, indent=1, sort_keys=True) + '\n', encoding='utf-8', newline='\n')
    print(f'audit: {len(report["closure"])} closure files, {report["closure_bytes"]} bytes, missing {report["missing_seeds"]}')
    sys.exit(1 if report['missing_seeds'] else 0)


if __name__ == '__main__':
    main()
