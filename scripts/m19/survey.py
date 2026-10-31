#!/usr/bin/env python3
"""Read-only Android survey for M19. Writes sanitized JSON and prints nothing secret.

The device script lists names, sizes and policy modes. It never reads key material, lock
screen state or the serial. Run it on an unlocked phone so CE paths are visible.
"""
import argparse
import base64
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import bootimage

ADB = os.environ.get('ADB', 'adb')
ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'artifacts/m19/survey/device.json'
MANIFEST = ROOT / 'manifests/m19-device-survey.json'
HEX = re.compile(r'[0-9a-fA-F]{24,}')
PROPERTIES = ('ro.build.version.release', 'ro.build.version.security_patch', 'ro.vendor.build.security_patch',
              'ro.build.version.incremental', 'ro.crypto.state', 'ro.crypto.type', 'ro.crypto.metadata.enabled',
              'ro.product.first_api_level', 'ro.vendor.api_level')
POLICY_PATHS = ('/data', '/data/ubuntu', '/data/ubuntu/usr', '/data/ubuntu/usr/bin', '/data/ubuntu/root',
                '/data/ubuntu/var/lib/dpkg', '/data/ubuntu/tmp', '/data/media', '/data/media/0', '/data/misc',
                '/data/misc/vold', '/data/misc/keystore', '/data/system', '/data/system_de/0', '/data/system_ce/0',
                '/data/user/0', '/data/user_de/0', '/data/unencrypted')
KEY_DIRS = ('/metadata/vold/metadata_encryption/key', '/data/unencrypted/key', '/data/misc/vold/user_keys/ce/0/current')
ROOTFS_DIRS = ('/tmp', '/var/tmp', '/var/log', '/var/cache', '/var/spool', '/var/lib/systemd', '/var/lib/NetworkManager',
               '/var/lib/upower', '/usr/lib/xorg/Xorg', '/usr/lib/xorg/modules/drivers/modesetting_drv.so',
               '/usr/lib/xorg/modules/input/libinput_drv.so', '/usr/lib/systemd/systemd', '/usr/bin/startxfce4',
               '/usr/bin/dbus-run-session', '/root/.config/xfce4')
SP_SUFFIXES = ('handle', 'milock', 'metrics', 'pwd', 'secdis', 'spblob', 'weaver')
PROBE = '''
import errno, fcntl, os, struct, sys
keys = {}
for path in sys.argv[1:]:
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError as error:
        print('POLICY', path, 'open:' + errno.errorcode[error.errno], sep='\\t')
        continue
    buffer = bytearray(32)
    struct.pack_into('<Q', buffer, 0, 24)
    try:
        fcntl.ioctl(fd, 0xC0096616, buffer, True)
        group = keys.setdefault(bytes(buffer[16:32]), chr(65 + len(keys)))
        print('POLICY', path, 'v%d' % buffer[8], buffer[9], buffer[10], buffer[11], group, sep='\\t')
    except OSError as error:
        print('POLICY', path, 'none' if error.errno == errno.ENODATA else errno.errorcode[error.errno], sep='\\t')
    os.close(fd)
'''


def device_script():
    props = ' '.join(PROPERTIES)
    keys = ' '.join(KEY_DIRS)
    probe = base64.b64encode(PROBE.encode()).decode()
    return f'''
T=/data/data/com.termux/files/usr
R=/data/ubuntu
echo "STATE	$(dumpsys user 2>/dev/null | grep -m1 -o 'RUNNING_[A-Z]*')"
for p in {props}; do echo "PROP	$p	$(getprop $p)"; done
grep -E '[[:space:]]/data[[:space:]]' /vendor/etc/fstab.qcom | sed 's/^/FSTAB	/'
D=$(grep -m1 ' /data f2fs ' /proc/mounts | cut -d' ' -f1)
echo "FEATURES	$(cat /sys/fs/f2fs/${{D##*/}}/features 2>/dev/null)"
echo "TABLE	$(dmctl table userdata 2>/dev/null | tail -n 1)"
echo "SHA	$(sha256sum /dev/block/by-name/recovery_a | cut -d' ' -f1)"
[ -e /metadata/vold/checkpoint ] && echo "CHECKPOINT	yes" || echo "CHECKPOINT	no"
for d in {keys}; do for f in $d/*; do [ -e "$f" ] && echo "KEY	$d	${{f##*/}}"; done; done
for f in /data/system_de/0/spblob/*; do echo "SP	${{f##*.}}"; done
grep -E 'verifiedbootstate|vbmeta.device_state' /proc/bootconfig | sed 's/ = /	/; s/"//g; s/^/BOOTCONFIG	/'
echo "OS	$(grep -m1 '^VERSION_ID=' $R/etc/os-release | cut -d'"' -f2)"
echo "PACKAGES	$(grep -c '^Package: ' $R/var/lib/dpkg/status)"
for p in {' '.join(ROOTFS_DIRS)}; do [ -e "$R$p" ] && echo "ROOTFS	$p"; done
LD_LIBRARY_PATH=$T/lib $T/bin/python -c "$(echo {probe} | base64 -d)" {' '.join(POLICY_PATHS)}
'''


def assert_read_only(script):
    """Refuse a device script that could write or read a secret."""
    forbidden = (r'\bmount\b', r'\bumount\b', r'\brm\b', r'\bof=', r'\bsetprop\b', r'\bsetenforce\b', r'\bdd\b',
                 r'locksettings', r'persistent\.sqlite', r'cat [^|\n]*(encrypted_key|keymaster_key_blob|secdiscardable)',
                 r'serial', r'--showkeys', r'getprop\s*$', r'\bchmod\b', r'\bchown\b')
    for pattern in forbidden:
        if re.search(pattern, script, re.M):
            raise ValueError(f'forbidden in device script: {pattern}')
    return True


def sanitize(value):
    return HEX.sub('<hex>', value) if isinstance(value, str) else value


def parse(text):
    survey = {'properties': {}, 'policies': {}, 'key_dirs': {}, 'rootfs_paths': [], 'bootconfig': {}, 'sp_suffixes': []}
    for line in text.splitlines():
        fields = line.split('\t')
        kind = fields[0]
        if kind == 'STATE':
            survey['user_state'] = fields[1]
        elif kind == 'PROP':
            survey['properties'][fields[1]] = fields[2]
        elif kind == 'FSTAB':
            survey['fstab_userdata'] = fields[1]
        elif kind == 'FEATURES':
            survey['f2fs_features'] = [name.strip() for name in fields[1].split(',') if name.strip()]
        elif kind == 'TABLE':
            survey['dm_table'] = sanitize(fields[1]).strip()
        elif kind == 'SHA' and re.fullmatch('[0-9a-f]{64}', fields[1]):
            survey['recovery_a_sha256'] = fields[1]
        elif kind == 'CHECKPOINT':
            survey['checkpoint_pending'] = fields[1] == 'yes'
        elif kind == 'KEY':
            survey['key_dirs'].setdefault(fields[1], []).append(fields[2])
        elif kind == 'SP' and fields[1] in SP_SUFFIXES:
            survey['sp_suffixes'].append(fields[1])
        elif kind == 'BOOTCONFIG':
            survey['bootconfig'][fields[1].strip()] = fields[2].strip()
        elif kind == 'OS':
            survey['rootfs_version'] = fields[1]
        elif kind == 'PACKAGES':
            survey['rootfs_packages'] = int(fields[1])
        elif kind == 'ROOTFS':
            survey['rootfs_paths'].append(fields[1])
        elif kind == 'POLICY':
            survey['policies'][fields[1]] = _policy(fields[2:])
    _name_key_groups(survey['policies'])
    survey['sp_suffixes'].sort()
    return survey


def _policy(fields):
    if fields[0] != 'v2':
        return {'policy': fields[0]}
    return {'policy': 'v2', 'contents': int(fields[1]), 'filenames': int(fields[2]), 'flags': int(fields[3]), 'group': fields[4]}


def _name_key_groups(policies):
    """Turn opaque key groups into CE or DE classes, then drop the groups."""
    names = {}
    for anchor, name in (('/data/media/0', 'ce'), ('/data/user_de/0', 'de-user'), ('/data/misc', 'de-system')):
        group = policies.get(anchor, {}).get('group')
        if group:
            names[group] = name
    for entry in policies.values():
        group = entry.pop('group', None)
        if group:
            entry['class'] = names.get(group, 'unknown')


def run(arguments):
    return subprocess.run([ADB, *arguments], capture_output=True, check=True, timeout=120).stdout


def collect():
    script = device_script()
    assert_read_only(script)
    encoded = base64.b64encode(script.encode()).decode()
    text = run(['shell', f"su -c 'echo {encoded} | base64 -d | sh'"]).decode('utf-8', 'replace')
    survey = parse(text)
    header = bootimage.parse_header(run(['exec-out', "su -c 'dd if=/dev/block/by-name/boot_a bs=4096 count=1 2>/dev/null'"]))
    survey['boot_a_header'] = {'os_version': header.os_version, 'os_patch': header.os_patch}
    return survey


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, default=OUT)
    parser.add_argument('--manifest', type=Path, default=MANIFEST)
    arguments = parser.parse_args()
    survey = collect()
    if survey.get('user_state') != 'RUNNING_UNLOCKED':
        sys.exit('STOP: unlock the phone first, CE paths are not visible while locked')
    arguments.out.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(survey, indent=1, sort_keys=True) + '\n'
    arguments.out.write_text(text, encoding='utf-8', newline='\n')
    arguments.manifest.write_text(text, encoding='utf-8', newline='\n')
    print(f'survey: {len(survey["policies"])} policies, {len(survey["rootfs_paths"])} rootfs paths')


if __name__ == '__main__':
    main()
