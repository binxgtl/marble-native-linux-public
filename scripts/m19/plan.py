#!/usr/bin/env python3
"""Read-only unlock plan: device-mapper table, mounts, Android-init config and preflight.

The plan is data. No function here accepts a key, and the table carries a placeholder that
only the future native client replaces in memory.
"""
import re
from dataclasses import dataclass

from fbe import Stop, classify_key_dir

KEY_PLACEHOLDER = '<ephemeral-wrapped-key>'
DM_READONLY_FLAG = 1
SECTOR = 512
USERDATA_SECTORS = 470183896
TABLE_FEATURES = ('sector_size:4096', 'iv_large_sectors', 'wrappedkey_v0')
ANDROID_RELEASE, ANDROID_PATCH = '15', '2026-08-05'
RECOVERY_SHA256 = 'fa40e1eb92ea3e27b0996fe5b32ef6768b888bccab423353a673b47d69b3dd4f'
HEADER_VERSION, HEADER_PATCH = '12.0.0', '2025-09'
F2FS_FORBIDDEN = {'discard', 'gc_merge', 'atgc', 'age_extent_cache', 'compress_cache', 'rw', 'remount',
                  'checkpoint=enable', 'fsync_mode=nobarrier', 'background_gc=on', 'reserve_root=32768'}

# Stock modules the unlock path needs. All are KMI-checked members of existing closures.
TEE_MODULES = ('qseecom-mod.ko', 'hwkm.ko', 'crypto-qti-hwkm.ko', 'crypto-qti-common.ko',
               'ufshcd-crypto-qti.ko', 'ufs_qcom.ko', 'secure_buffer.ko', 'mem_buf_dev.ko',
               'qcom_dma_heaps.ko')

# Services, in start order, and the exact binaries TWRP runs them from.
TEE_SERVICES = (
    ('servicemanager', '/system/bin/servicemanager'),
    ('hwservicemanager', '/system/bin/hwservicemanager'),
    ('vndservicemanager', '/system/bin/vndservicemanager'),
    ('vendor.qseecomd', '/vendor/bin/qseecomd'),
    ('vendor.keymaster-4-1', '/vendor/bin/hw/android.hardware.keymaster@4.1-service-qti'),
    ('keystore2', '/system/bin/keystore2'),
)
CE_ONLY_SERVICES = (('gatekeeper-1-0', '/vendor/bin/hw/android.hardware.gatekeeper@1.0-service-qti'),)
RC_FORBIDDEN = re.compile(r'\b(recovery|vold|fsck|mkfs|format|wipe|remount|adbd|update_engine)\b|/data\b|/metadata\b|\brw\b')
RECOVERY_REMOVED = ('system/bin/recovery', 'system/bin/twrp', 'init.recovery.service.rc',
                    'init.recovery.usb.rc', 'init.recovery.hlthchrg.rc', 'init.recovery.qcom.rc')
# Android init reads prop.default only when this path exists, so an empty file takes its place.
RECOVERY_MARKER = 'system/bin/recovery'
READ_ONLY_NODES = ('recovery_a', 'metadata', 'userdata', 'ssd')
RC_EXTRA_SERVICES = ('ueventd', 'logd', 'm19.logcat')


def patched_properties(text):
    """TWRP ships patch level 2099-12-31. The HAL must see the values Android runs with."""
    overrides = {'ro.build.version.security_patch': ANDROID_PATCH, 'ro.vendor.build.security_patch': ANDROID_PATCH}
    seen, lines = set(), []
    for line in text.splitlines():
        name = line.partition('=')[0]
        if name in overrides:
            line = f'{name}={overrides[name]}'
            seen.add(name)
        lines.append(line)
    if seen != set(overrides):
        raise Stop('PROP_OVERRIDE')
    return '\n'.join(lines) + '\n'


def default_key_table(sectors, device):
    """dm-default-key parameters. Discards stay off and the device opens read-only."""
    if sectors <= 0 or sectors % 8:
        raise Stop('TABLE_SECTORS')
    if sectors != USERDATA_SECTORS:
        raise Stop('TABLE_SIZE_CHANGED')
    if not device.startswith('/dev/') or ':' in device:
        raise Stop('TABLE_DEVICE')
    parameters = f'aes-xts-plain64 {KEY_PLACEHOLDER} 0 {device} 0 {len(TABLE_FEATURES)} ' + ' '.join(TABLE_FEATURES)
    return {'name': 'm19-userdata', 'target': 'default-key', 'start': 0, 'sectors': sectors,
            'parameters': parameters, 'flags': DM_READONLY_FLAG}


def parse_live_table(line):
    """Parse dmctl output and compare with the table this plan would build."""
    match = re.fullmatch(r'0-(\d+): default-key, (\S+) - 0 (\d+:\d+) 0 (\d+) (.+)', line.strip())
    if not match:
        raise Stop('LIVE_TABLE_SHAPE')
    sectors, cipher, _, count, features = match.groups()
    names = features.split()
    if cipher != 'aes-xts-plain64' or int(count) != len(names):
        raise Stop('LIVE_TABLE_CIPHER')
    if set(names) - {'allow_discards'} != set(TABLE_FEATURES):
        raise Stop('LIVE_TABLE_FEATURES')
    return int(sectors)


def data_mount(options=()):
    """f2fs mount of the unlocked device. Only additions from the caller are checked."""
    extra = list(options)
    for option in extra:
        if option in F2FS_FORBIDDEN or option.split('=')[0] in ('checkpoint', 'discard'):
            raise Stop('MOUNT_OPTION')
    return {'type': 'f2fs', 'read_only': True, 'data': ','.join(['norecovery', 'inlinecrypt', *extra]),
            'nosuid': False, 'nodev': False}


def metadata_mount():
    return {'type': 'ext4', 'read_only': True, 'data': 'noload', 'nosuid': True, 'nodev': True}


def init_rc():
    """The Android init script for the transient TEE environment.

    It replaces TWRP's init.rc. PID 1 mounts /tmp and everything durable before init starts, so
    this file mounts only binderfs and the empty persist bind. Markers under /tmp/m19 tell PID 1
    how far the services got.
    """
    lines = ['# Generated by scripts/m19/plan.py. Transient TEE environment, no durable mounts.',
             'on early-init', '    copy /system/etc/ld.config.txt /linkerconfig/ld.config.txt',
             '    chmod 444 /linkerconfig/ld.config.txt', '    start ueventd', '', 'on init',
             '    export PATH /sbin:/system/bin', '    export LD_LIBRARY_PATH /system/lib64:/vendor/lib64/hw',
             '    export ANDROID_ROOT /system', '    symlink /system/bin /bin', '    symlink /system/etc /etc',
             '    mkdir /tmp/misc 0700 root root', '    mkdir /tmp/misc/keystore 0700 root root',
             '    mkdir /tmp/persist 0775 shell system', '    mkdir /mnt/vendor 0775 shell system',
             '    mkdir /mnt/vendor/persist 0775 shell system', '    mount none /tmp/persist /mnt/vendor/persist bind rec',
             '    mkdir /dev/binderfs', '    mount binder binder /dev/binderfs stats=global', '    chmod 0755 /dev/binderfs',
             '    chmod 0666 /dev/binderfs/hwbinder', '    chmod 0666 /dev/binderfs/binder', '    chmod 0666 /dev/binderfs/vndbinder',
             '    symlink /dev/binderfs/binder /dev/binder', '    symlink /dev/binderfs/hwbinder /dev/hwbinder',
             '    symlink /dev/binderfs/vndbinder /dev/vndbinder', '    install_keyring', '    start logd', '    start m19.logcat',
             '    wait /dev/block/platform/soc/${ro.boot.bootdevice}',
             '    symlink /dev/block/platform/soc/${ro.boot.bootdevice} /dev/block/bootdevice',
             '    start servicemanager', '    start hwservicemanager', '    start vndservicemanager', '',
             'on property:hwservicemanager.ready=true', '    write /tmp/m19/hwservicemanager 1', '    start vendor.qseecomd', '',
             'on property:vendor.sys.listeners.registered=true', '    write /tmp/m19/listeners 1',
             '    start vendor.keymaster-4-1', '    start keystore2', '',
             'service ueventd /system/bin/ueventd', '    seclabel u:r:ueventd:s0', '',
             'service logd /system/bin/logd', '    socket logdr seqpacket 0666 root root',
             '    socket logdw dgram+passcred 0222 root root', '    file /proc/kmsg r', '    file /dev/kmsg w',
             '    user root', '    group root', '    capabilities SYSLOG AUDIT_CONTROL SETGID SETUID', '    seclabel u:r:logd:s0', '',
             'service m19.logcat /system/bin/logcat -b all -v threadtime -f /tmp/m19/logcat.txt', '    user root', '    group root',
             '    seclabel u:r:logd:s0', '']
    text = '\n'.join(lines)
    check_rc(text)
    return text


def check_rc(text):
    if RC_FORBIDDEN.search(text):
        raise Stop('RC_FORBIDDEN')
    allowed = {name for name, _ in TEE_SERVICES} | set(RC_EXTRA_SERVICES)
    started = set(re.findall(r'^\s*start (\S+)$', text, re.M))
    if started - allowed:
        raise Stop('RC_SERVICE')
    return True


@dataclass(frozen=True)
class Gate:
    name: str
    verdict: str
    detail: str = ''


def preflight(survey, audit, closure_names):
    """Evaluate everything checkable before a run. Any STOP blocks a candidate."""
    gates = []

    def gate(name, passed, detail=''):
        gates.append(Gate(name, 'PASS' if passed else 'STOP', detail))

    header, carrier = survey.get('boot_a_header', {}), audit.get('carrier_header', {})
    gate('BOOT_HEADER_PAIR', header == carrier and header.get('os_version') == HEADER_VERSION
         and header.get('os_patch') == HEADER_PATCH, 'boot_a and carrier must present the same OS fields')
    properties = survey.get('properties', {})
    gate('ANDROID_VERSION', properties.get('ro.build.version.release') == ANDROID_RELEASE
         and properties.get('ro.build.version.security_patch') == ANDROID_PATCH, 'HAL properties are pinned to these')
    gate('VENDOR_PATCH', properties.get('ro.vendor.build.security_patch') == ANDROID_PATCH)
    gate('RECOVERY_PINNED', survey.get('recovery_a_sha256') == audit.get('image_sha256'), 'TWRP on the device is the audited image')
    policies = survey.get('policies', {})
    roots = [path for path in policies if path == '/data/ubuntu' or path.startswith('/data/ubuntu/')]
    gate('ROOTFS_NO_POLICY', bool(roots) and all(policies[path].get('policy') == 'none' for path in roots))
    media = policies.get('/data/media/0', {})
    gate('MEDIA_CE', media.get('policy') == 'v2' and media.get('flags') == 0x0a)
    keys = survey.get('key_dirs', {})
    for path, expected in (('/metadata/vold/metadata_encryption/key', 'keystore'), ('/data/unencrypted/key', 'keystore'),
                           ('/data/misc/vold/user_keys/ce/0/current', 'secret')):
        names = keys.get(path)
        if names is None:
            gate('KEY_DIR', False, f'{path} absent')
            continue
        try:
            gate('KEY_DIR', classify_key_dir(names) == expected, path)
        except Stop as stop:
            gate('KEY_DIR', False, f'{path}: {stop}')
    gate('NO_CHECKPOINT', survey.get('checkpoint_pending') is False, 'a pending checkpoint must never be mounted')
    try:
        gate('LIVE_TABLE', parse_live_table(survey.get('dm_table', '')) == USERDATA_SECTORS)
    except Stop as stop:
        gate('LIVE_TABLE', False, str(stop))
    known = {'encryption', 'extra_attr', 'projquota', 'quota_ino', 'verity', 'casefold', 'pin_file'}
    gate('F2FS_FEATURES', set(survey.get('f2fs_features', ['?'])) == known, 'compression absent on this image')
    missing = [name for name in TEE_MODULES if name not in closure_names]
    gate('TEE_MODULES', not missing, ','.join(missing))
    gate('TWRP_SEEDS', not audit.get('missing_seeds', ['?']))
    return gates


def blocking(gates):
    return [gate for gate in gates if gate.verdict != 'PASS']
