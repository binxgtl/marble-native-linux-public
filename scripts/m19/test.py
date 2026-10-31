#!/usr/bin/env python3
"""M19 offline tests. All inputs are synthetic; no phone, image or secret is used."""
import copy
import hashlib
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import audit
import bootimage
import elfdeps
import fbe
import plan
import preflight
import rootfs
import survey

FSTAB = ('/dev/block/bootdevice/by-name/userdata /data f2fs noatime,nosuid,nodev,discard,inlinecrypt '
         'latemount,wait,check,formattable,fileencryption=aes-256-xts:aes-256-cts:v2+inlinecrypt_optimized+wrappedkey_v0,'
         'keydirectory=/metadata/vold/metadata_encryption,metadata_encryption=aes-256-xts:wrappedkey_v0,quota,checkpoint=fs')
TABLE = '0-470183896: default-key, aes-xts-plain64 - 0 259:17 0 4 allow_discards sector_size:4096 iv_large_sectors wrappedkey_v0'


def newc_entry(name, mode, data=b''):
    raw = name.encode() + b'\0'
    fields = [0, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(raw), 0]
    header = b'070701' + b''.join(b'%08x' % field for field in fields)
    body = header + raw
    body += b'\0' * (-len(body) % 4) + data
    return body + b'\0' * (-len(body) % 4)


def newc_archive(entries):
    return b''.join(newc_entry(*entry) for entry in entries) + newc_entry('TRAILER!!!', 0)


def lz4_legacy(data):
    """Literal-only LZ4 block in a legacy frame."""
    length = len(data)
    token = bytes([min(length, 15) << 4])
    extra = b''
    if length >= 15:
        rest = length - 15
        extra = b'\xff' * (rest // 255) + bytes([rest % 255])
    block = token + extra + data
    return bootimage.LZ4_LEGACY + struct.pack('<I', len(block)) + block


def boot_image(ramdisk, kernel=0, version=4, raw_os=None):
    raw_os = bootimage.encode_os_version('15.0.0', '2099-12') if raw_os is None else raw_os
    header = bytearray(bootimage.PAGE)
    header[:8] = bootimage.MAGIC
    struct.pack_into('<3I', header, 8, kernel, len(ramdisk), raw_os)
    struct.pack_into('<I', header, 40, version)
    pad = -kernel % bootimage.PAGE
    return bytes(header) + b'K' * kernel + b'\0' * pad + ramdisk + b'\0' * (-len(ramdisk) % bootimage.PAGE)


def elf(needed_names):
    """Smallest ELF64 with .dynamic and .dynstr that elfdeps can read."""
    strings = b'\0'
    tags = b''
    for name in needed_names:
        tags += struct.pack('<qQ', elfdeps.DT_NEEDED, len(strings))
        strings += name.encode() + b'\0'
    tags += struct.pack('<qQ', 0, 0)
    header = bytearray(64)
    header[:6] = b'\x7fELF\x02\x01'
    table_offset = 64 + len(tags) + len(strings)
    struct.pack_into('<Q', header, 40, table_offset)
    struct.pack_into('<HH', header, 58, 64, 3)
    section = struct.Struct(elfdeps.SECTION)
    table = section.pack(*[0] * 10)
    table += section.pack(0, elfdeps.SHT_DYNAMIC, 0, 0, 64, len(tags), 2, 0, 0, 16)
    table += section.pack(0, 3, 0, 0, 64 + len(tags), len(strings), 0, 0, 0, 0)
    return bytes(header) + tags + strings + table


def good_survey():
    return {
        'boot_a_header': {'os_version': '12.0.0', 'os_patch': '2025-09'},
        'properties': {'ro.build.version.release': '15', 'ro.build.version.security_patch': '2026-08-05',
                       'ro.vendor.build.security_patch': '2026-08-05'},
        'recovery_a_sha256': 'a' * 64,
        'policies': {'/data/ubuntu': {'policy': 'none'}, '/data/ubuntu/usr': {'policy': 'none'},
                     '/data/media/0': {'policy': 'v2', 'contents': 1, 'filenames': 4, 'flags': 0x0a, 'class': 'ce'}},
        'key_dirs': {'/metadata/vold/metadata_encryption/key': sorted(fbe.KEYSTORE_FILES),
                     '/data/unencrypted/key': sorted(fbe.KEYSTORE_FILES),
                     '/data/misc/vold/user_keys/ce/0/current': sorted(fbe.CE_FILES)},
        'checkpoint_pending': False,
        'dm_table': TABLE,
        'f2fs_features': ['encryption', 'extra_attr', 'projquota', 'quota_ino', 'verity', 'casefold', 'pin_file'],
        'fstab_userdata': FSTAB,
        'rootfs_paths': list(rootfs.TMPFS),
    }


def good_audit():
    return {'image_sha256': 'a' * 64, 'carrier_header': {'os_version': '12.0.0', 'os_patch': '2025-09'}, 'missing_seeds': []}


class BootImage(unittest.TestCase):
    def test_version_round_trip_matches_real_fields(self):
        for version, patch in (('15.0.0', '2099-12'), ('12.0.0', '2025-09')):
            self.assertEqual(bootimage.decode_os_version(bootimage.encode_os_version(version, patch)), (version, patch))

    def test_header_fields(self):
        header = bootimage.parse_header(boot_image(b'R' * 10, kernel=5000))
        self.assertEqual((header.version, header.kernel_size, header.ramdisk_size), (4, 5000, 10))
        self.assertEqual(header.ramdisk_offset, 3 * bootimage.PAGE)

    def test_rejects_bad_magic_and_old_versions(self):
        with self.assertRaises(bootimage.ImageError):
            bootimage.parse_header(b'NOTBOOT!' + bytes(4096))
        with self.assertRaises(bootimage.ImageError):
            bootimage.parse_header(boot_image(b'', version=2))

    def test_rejects_short_header(self):
        with self.assertRaises(bootimage.ImageError):
            bootimage.parse_header(bootimage.MAGIC)

    def test_ramdisk_outside_image_refused(self):
        image = bytearray(boot_image(b'R' * 10))
        struct.pack_into('<I', image, 12, 1 << 30)
        with self.assertRaisesRegex(bootimage.ImageError, 'outside'):
            bootimage.ramdisk(bytes(image))

    def test_empty_ramdisk_refused(self):
        with self.assertRaisesRegex(bootimage.ImageError, 'outside'):
            bootimage.ramdisk(boot_image(b''))

    def test_lz4_python_literals_and_overlap(self):
        block = bytes([0x12]) + b'a' + bytes([1, 0]) + bytes([0x10]) + b'b'
        self.assertEqual(bootimage._lz4_block_python(block, 100), b'a' * 7 + b'b')

    def test_lz4_python_bad_offset(self):
        with self.assertRaises(bootimage.ImageError):
            bootimage._lz4_block_python(bytes([0x10]) + b'a' + bytes([9, 0, 0]), 100)

    def test_lz4_python_zero_offset(self):
        with self.assertRaises(bootimage.ImageError):
            bootimage._lz4_block_python(bytes([0x10]) + b'a' + bytes([0, 0, 0]), 100)

    def test_lz4_python_truncated(self):
        with self.assertRaises(bootimage.ImageError):
            bootimage._lz4_block_python(bytes([0x50]) + b'ab', 100)

    def test_lz4_python_size_limit(self):
        block = bytes([0x1f]) + b'a' + bytes([1, 0]) + bytes([255, 255, 0])
        with self.assertRaises(bootimage.ImageError):
            bootimage._lz4_block_python(block, 16)

    def test_truncated_lz4_frame(self):
        with self.assertRaises(bootimage.ImageError):
            bootimage.decompress(bootimage.LZ4_LEGACY + struct.pack('<I', 100) + b'ab')

    def test_unknown_compression(self):
        with self.assertRaises(bootimage.ImageError):
            bootimage.decompress(b'\x00\x01\x02\x03')

    def test_newc_round_trip(self):
        entries = [('system/bin/x', 0o100755, b'hello'), ('link', 0o120777, b'target')]
        self.assertEqual(list(bootimage.newc(newc_archive(entries))), entries)

    def test_newc_refuses_traversal_and_absolute(self):
        for name in ('../evil', 'a/../../evil', '/abs'):
            with self.assertRaises(bootimage.ImageError):
                list(bootimage.newc(newc_archive([(name, 0o100644, b'x')])))

    def test_newc_needs_trailer(self):
        with self.assertRaises(bootimage.ImageError):
            list(bootimage.newc(newc_entry('a', 0o100644, b'x')))

    def test_newc_bad_magic(self):
        with self.assertRaises(bootimage.ImageError):
            list(bootimage.newc(b'x' * 200))

    def test_newc_truncated_body(self):
        archive = bytearray(newc_entry('a', 0o100644, b'hello'))
        archive[6 + 8 * 6:6 + 8 * 7] = b'%08x' % 1000
        with self.assertRaises(bootimage.ImageError):
            list(bootimage.newc(bytes(archive)))


class ElfDeps(unittest.TestCase):
    def test_needed(self):
        self.assertEqual(elfdeps.needed(elf(['liba.so', 'libb.so'])), ['liba.so', 'libb.so'])

    def test_rejects_non_elf(self):
        with self.assertRaises(elfdeps.ElfError):
            elfdeps.needed(b'#!/bin/sh\n')

    def test_rejects_bad_section_table(self):
        data = bytearray(elf([]))
        struct.pack_into('<Q', data, 40, 1 << 40)
        with self.assertRaises(elfdeps.ElfError):
            elfdeps.needed(bytes(data))

    def test_closure_follows_and_reports_missing(self):
        files = {'bin/a': elf(['liba.so']), 'lib/liba.so': elf(['libb.so', 'libgone.so']), 'lib/libb.so': elf([])}
        self.assertEqual(elfdeps.closure(['bin/a'], files, ['lib']), (['bin/a', 'lib/liba.so', 'lib/libb.so'], ['libgone.so']))

    def test_closure_survives_cycle(self):
        files = {'lib/a.so': elf(['b.so']), 'lib/b.so': elf(['a.so'])}
        self.assertEqual(elfdeps.closure(['lib/a.so'], files, ['lib'])[1], [])

    def test_closure_reports_missing_seed(self):
        self.assertEqual(elfdeps.closure(['bin/none'], {}, ['lib']), ([], ['bin/none']))

    def test_first_library_dir_wins(self):
        files = {'bin/a': elf(['x.so']), 'one/x.so': elf([]), 'two/x.so': elf([])}
        self.assertEqual(elfdeps.closure(['bin/a'], files, ['one', 'two'])[0], ['bin/a', 'one/x.so'])


class Fbe(unittest.TestCase):
    def test_contract_accepts_marble_entry(self):
        self.assertEqual(fbe.userdata_contract(fbe.parse_fstab_entry(FSTAB)), {'checkpoint': 'fs', 'wrapped': True})

    def test_contract_rejects_each_change(self):
        for old, new, gate in (('v2+inlinecrypt_optimized+wrappedkey_v0', 'v2', 'USERDATA_FILEENCRYPTION'),
                               ('metadata_encryption=aes-256-xts:wrappedkey_v0', 'metadata_encryption=aes-256-xts', 'USERDATA_METADATA_ENCRYPTION'),
                               ('keydirectory=/metadata/vold/metadata_encryption', 'keydirectory=/metadata/x', 'USERDATA_KEYDIRECTORY'),
                               (' f2fs ', ' ext4 ', 'USERDATA_NOT_F2FS'), (',inlinecrypt ', ' ', 'USERDATA_NO_INLINECRYPT')):
            with self.subTest(gate=gate), self.assertRaisesRegex(fbe.Stop, gate):
                fbe.userdata_contract(fbe.parse_fstab_entry(FSTAB.replace(old, new)))

    def test_fstab_shape(self):
        with self.assertRaisesRegex(fbe.Stop, 'FSTAB_SHAPE'):
            fbe.parse_fstab_entry('/dev/x /data f2fs')

    def test_policy_decodes_inlinecrypt_optimized(self):
        policy = fbe.decode_policy(2, 1, 4, 0x0a)
        self.assertEqual((policy['contents'], policy['filenames'], policy['padding']), ('aes-256-xts', 'aes-256-cts', 16))
        self.assertTrue(policy['iv_ino_lblk_64'])
        self.assertFalse(policy['direct_key'] or policy['iv_ino_lblk_32'])

    def test_policy_refuses_v1_and_unknown_modes(self):
        with self.assertRaisesRegex(fbe.Stop, 'POLICY_NOT_V2'):
            fbe.decode_policy(1, 1, 4, 0)
        with self.assertRaisesRegex(fbe.Stop, 'POLICY_MODE'):
            fbe.decode_policy(2, 9, 4, 0)

    def test_classify_paths(self):
        self.assertEqual(fbe.classify_path({'policy': 'none'}), 'metadata')
        self.assertEqual(fbe.classify_path({'policy': 'v2', 'class': 'ce'}), 'ce')
        with self.assertRaisesRegex(fbe.Stop, 'POLICY_UNCLASSIFIED'):
            fbe.classify_path({'policy': 'v2', 'class': 'unknown'})

    def test_key_dir_layouts(self):
        self.assertEqual(fbe.classify_key_dir(fbe.KEYSTORE_FILES), 'keystore')
        self.assertEqual(fbe.classify_key_dir(fbe.CE_FILES), 'secret')

    def test_pending_upgrade_stops(self):
        with self.assertRaisesRegex(fbe.Stop, 'KEY_UPGRADE_PENDING'):
            fbe.classify_key_dir([*fbe.KEYSTORE_FILES, fbe.UPGRADED_BLOB])

    def test_unknown_layout_stops(self):
        for names in (['version'], [*fbe.CE_FILES, 'extra']):
            with self.subTest(names=names), self.assertRaisesRegex(fbe.Stop, 'KEY_DIR_LAYOUT'):
                fbe.classify_key_dir(names)

    def test_hash_matches_vold_construction(self):
        prefix = b'Android secdiscardable SHA512'
        expected = hashlib.sha512(prefix + bytes(128 - len(prefix)) + b'data').digest()
        self.assertEqual(fbe.hash_with_prefix(prefix, b'data'), expected)

    def test_app_id_size_gate(self):
        self.assertEqual(len(fbe.keystore_app_id(bytes(16384))), 64)
        with self.assertRaisesRegex(fbe.Stop, 'SECDISCARDABLE_SIZE'):
            fbe.keystore_app_id(bytes(100))


class Plan(unittest.TestCase):
    def table(self):
        return plan.default_key_table(plan.USERDATA_SECTORS, '/dev/block/sda33')

    def test_table_is_read_only_without_discards(self):
        table = self.table()
        self.assertEqual(table['flags'], plan.DM_READONLY_FLAG)
        self.assertNotIn('allow_discards', table['parameters'])
        self.assertIn(' 3 sector_size:4096 iv_large_sectors wrappedkey_v0', table['parameters'])

    def test_table_carries_only_a_placeholder(self):
        self.assertIn(plan.KEY_PLACEHOLDER, self.table()['parameters'])

    def test_table_refuses_bad_size(self):
        for sectors, gate in ((7, 'TABLE_SECTORS'), (0, 'TABLE_SECTORS'), (plan.USERDATA_SECTORS - 8, 'TABLE_SIZE_CHANGED')):
            with self.assertRaisesRegex(fbe.Stop, gate):
                plan.default_key_table(sectors, '/dev/block/sda33')

    def test_table_refuses_major_minor_device(self):
        with self.assertRaisesRegex(fbe.Stop, 'TABLE_DEVICE'):
            plan.default_key_table(plan.USERDATA_SECTORS, '259:17')

    def test_live_table(self):
        self.assertEqual(plan.parse_live_table(TABLE), plan.USERDATA_SECTORS)

    def test_live_table_refuses_changes(self):
        for line, gate in (('garbage', 'LIVE_TABLE_SHAPE'), (TABLE.replace('aes-xts-plain64', 'adiantum'), 'LIVE_TABLE_CIPHER'),
                           (TABLE.replace(' wrappedkey_v0', ''), 'LIVE_TABLE_CIPHER'),
                           (TABLE.replace(' 4 allow_discards', ' 3').replace(' wrappedkey_v0', ' other'), 'LIVE_TABLE_FEATURES')):
            with self.subTest(line=line), self.assertRaisesRegex(fbe.Stop, gate):
                plan.parse_live_table(line)

    def test_data_mount_is_read_only_with_norecovery(self):
        mount = plan.data_mount()
        self.assertTrue(mount['read_only'])
        self.assertEqual(mount['data'], 'norecovery,inlinecrypt')
        self.assertFalse(mount['nosuid'] or mount['nodev'])

    def test_data_mount_refuses_write_options(self):
        for option in ('discard', 'rw', 'gc_merge', 'checkpoint=disable', 'checkpoint=enable', 'atgc'):
            with self.subTest(option=option), self.assertRaisesRegex(fbe.Stop, 'MOUNT_OPTION'):
                plan.data_mount([option])

    def test_metadata_mount_skips_the_journal(self):
        self.assertEqual(plan.metadata_mount()['data'], 'noload')
        self.assertTrue(plan.metadata_mount()['read_only'])

    def test_rc_order_and_content(self):
        text = plan.init_rc()
        self.assertLess(text.index('start hwservicemanager'), text.index('start vendor.qseecomd'))
        self.assertLess(text.index('listeners.registered'), text.index('start vendor.keymaster-4-1'))
        self.assertNotIn('gatekeeper', text)

    def test_rc_refuses_forbidden_lines(self):
        for line in ('    start recovery', '    start vold', '    mount f2fs /dev/x /data', '    mkdir /metadata',
                     '    mount ext4 /dev/x /tmp rw', '    exec /system/bin/fsck.f2fs', '    wipe'):
            with self.subTest(line=line), self.assertRaisesRegex(fbe.Stop, 'RC_FORBIDDEN'):
                plan.check_rc(plan.init_rc() + line + '\n')

    def test_rc_refuses_unlisted_service(self):
        with self.assertRaisesRegex(fbe.Stop, 'RC_SERVICE'):
            plan.check_rc(plan.init_rc() + '    start adb_shell\n')

    def test_preflight_passes_on_good_state(self):
        names = set(plan.TEE_MODULES)
        self.assertEqual(plan.blocking(plan.preflight(good_survey(), good_audit(), names)), [])

    def test_preflight_stops_each_failure(self):
        def edit(path, value):
            def apply(state):
                node = state
                for key in path[:-1]:
                    node = node[key]
                node[path[-1]] = value
            return apply
        cases = (('BOOT_HEADER_PAIR', edit(['boot_a_header', 'os_patch'], '2026-08')),
                 ('ANDROID_VERSION', edit(['properties', 'ro.build.version.security_patch'], '2026-09-05')),
                 ('VENDOR_PATCH', edit(['properties', 'ro.vendor.build.security_patch'], '2026-09-05')),
                 ('RECOVERY_PINNED', edit(['recovery_a_sha256'], 'b' * 64)),
                 ('ROOTFS_NO_POLICY', edit(['policies', '/data/ubuntu/usr', 'policy'], 'v2')),
                 ('MEDIA_CE', edit(['policies', '/data/media/0', 'flags'], 0)),
                 ('KEY_DIR', edit(['key_dirs', '/data/unencrypted/key'], ['version'])),
                 ('KEY_DIR', edit(['key_dirs', '/metadata/vold/metadata_encryption/key'], [*fbe.KEYSTORE_FILES, fbe.UPGRADED_BLOB])),
                 ('NO_CHECKPOINT', edit(['checkpoint_pending'], True)),
                 ('LIVE_TABLE', edit(['dm_table'], '')),
                 ('F2FS_FEATURES', edit(['f2fs_features'], ['compression'])))
        for name, change in cases:
            state = copy.deepcopy(good_survey())
            change(state)
            with self.subTest(name=name):
                self.assertIn(name, [gate.name for gate in plan.blocking(plan.preflight(state, good_audit(), set(plan.TEE_MODULES)))])

    def test_preflight_stops_when_only_the_carrier_differs(self):
        state = good_audit()
        state['carrier_header']['os_patch'] = '2026-08'
        names = [gate.name for gate in plan.blocking(plan.preflight(good_survey(), state, set(plan.TEE_MODULES)))]
        self.assertEqual(names, ['BOOT_HEADER_PAIR'])

    def test_properties_get_android_patch_level(self):
        text = 'ro.a=1\nro.build.version.security_patch=2099-12-31\nro.vendor.build.security_patch=2099-12-31\n'
        result = plan.patched_properties(text)
        self.assertNotIn('2099', result)
        self.assertEqual(result.count(plan.ANDROID_PATCH), 2)
        self.assertIn('ro.a=1', result)

    def test_properties_stop_when_a_line_is_absent(self):
        with self.assertRaisesRegex(fbe.Stop, 'PROP_OVERRIDE'):
            plan.patched_properties('ro.build.version.security_patch=2099-12-31\n')

    def test_preflight_treats_missing_data_as_stop(self):
        self.assertTrue(plan.blocking(plan.preflight({}, {}, set())))

    def test_preflight_names_missing_module(self):
        names = set(plan.TEE_MODULES) - {'qcom_dma_heaps.ko'}
        gate = [g for g in plan.blocking(plan.preflight(good_survey(), good_audit(), names))]
        self.assertEqual([(g.name, g.detail) for g in gate], [('TEE_MODULES', 'qcom_dma_heaps.ko')])

    def test_full_evaluate_adds_contract_and_mountpoints(self):
        names = set(plan.TEE_MODULES)
        self.assertEqual(plan.blocking(preflight.evaluate(good_survey(), good_audit(), names)), [])
        state = good_survey()
        state['fstab_userdata'] = FSTAB.replace(',quota', ',quota,other').replace('metadata_encryption=aes-256-xts:wrappedkey_v0', 'x')
        state['rootfs_paths'] = []
        self.assertEqual({g.name for g in plan.blocking(preflight.evaluate(state, good_audit(), names))},
                         {'USERDATA_CONTRACT', 'ROOTFS_MOUNTPOINTS'})


class Rootfs(unittest.TestCase):
    def test_plan_writes_only_under_run(self):
        value = rootfs.plan()
        self.assertTrue(value['root_read_only'])
        for path in (*value['files'], *value['links']):
            self.assertTrue(path.startswith('/run/'), path)

    def test_plan_is_deterministic(self):
        self.assertEqual(rootfs.plan(), rootfs.plan())

    def test_units_do_not_mount_or_use_lightdm(self):
        for text in rootfs.units().values():
            self.assertNotIn('mount', text)
            self.assertNotIn('lightdm', text)

    def test_home_copy_is_allowlisted(self):
        self.assertEqual(rootfs.home_copies(), [('/root/.config/xfce4', '/run/m19/session/.config/xfce4')])

    def test_home_refuses_private_paths(self):
        for path in ('.gemini', '.ssh', '.ssh/id', '.bash_history', '.config'):
            with self.subTest(path=path), self.assertRaisesRegex(fbe.Stop, 'HOME_PATH'):
                rootfs.home_copies([path])

    def test_sleep_and_absent_hardware_are_masked(self):
        links = rootfs.plan()['links']
        for name in ('suspend.target', 'sleep.target', 'lightdm.service', 'display-manager.service', 'NetworkManager.service'):
            self.assertEqual(links[f'/run/systemd/system/{name}'], '/dev/null')

    def test_xorg_uses_kms_without_acceleration(self):
        text = rootfs.xorg_conf(120)
        for needle in ('Driver "modesetting"', '"AccelMethod" "none"', '"PreferredMode" "1080x2400x120vid"', '"Monitor-DSI-1"'):
            self.assertIn(needle, text)

    def test_xorg_refuses_unknown_refresh(self):
        with self.assertRaisesRegex(fbe.Stop, 'REFRESH_MODE'):
            rootfs.xorg_conf(144)

    def test_mountpoints_checked(self):
        value = rootfs.plan()
        self.assertTrue(rootfs.check_mountpoints(value, set(rootfs.TMPFS)))
        with self.assertRaisesRegex(fbe.Stop, 'TMPFS_MOUNTPOINT'):
            rootfs.check_mountpoints(value, {'/tmp'})

    def test_run_tmpfs_needs_no_existing_check(self):
        self.assertTrue(rootfs.check_mountpoints(rootfs.plan(), set(rootfs.TMPFS) - {'/run'}))


class Survey(unittest.TestCase):
    def test_device_script_is_read_only(self):
        self.assertTrue(survey.assert_read_only(survey.device_script()))

    def test_guard_refuses_writes_and_secrets(self):
        for line in ('mount -o rw /data', 'rm -rf /data/x', 'dd if=/x of=/y', 'cat /data/unencrypted/key/encrypted_key',
                     'cat /metadata/vold/metadata_encryption/key/keymaster_key_blob', 'cat locksettings.db',
                     'sqlite3 persistent.sqlite', 'getprop ro.serialno', 'dmctl table userdata --showkeys', 'setprop a b'):
            with self.subTest(line=line), self.assertRaises(ValueError):
                survey.assert_read_only(line)

    def test_sanitize_masks_long_hex(self):
        self.assertEqual(survey.sanitize('key ' + 'ab' * 32 + ' end'), 'key <hex> end')
        self.assertEqual(survey.sanitize('259:17'), '259:17')

    def test_parse_builds_classes_without_key_groups(self):
        text = '\n'.join(('STATE\tRUNNING_UNLOCKED', 'PROP\tro.crypto.state\tencrypted', f'FSTAB\t{FSTAB}',
                          'FEATURES\tencryption, casefold', f'TABLE\t{TABLE}', 'SHA\t' + 'f' * 64, 'CHECKPOINT\tno',
                          'KEY\t/k\tversion', 'SP\tspblob', 'SP\tunknown', 'OS\t24.04', 'PACKAGES\t1581', 'ROOTFS\t/tmp',
                          'POLICY\t/data/ubuntu\tnone', 'POLICY\t/data/media/0\tv2\t1\t4\t10\tA',
                          'POLICY\t/data/user_de/0\tv2\t1\t4\t10\tB', 'POLICY\t/data/misc\tv2\t1\t4\t10\tC'))
        result = survey.parse(text)
        self.assertEqual(result['policies']['/data/media/0'], {'policy': 'v2', 'contents': 1, 'filenames': 4, 'flags': 10, 'class': 'ce'})
        self.assertEqual(result['policies']['/data/misc']['class'], 'de-system')
        self.assertEqual(result['policies']['/data/ubuntu'], {'policy': 'none'})
        self.assertEqual(result['f2fs_features'], ['encryption', 'casefold'])
        self.assertEqual(result['sp_suffixes'], ['spblob'])
        self.assertNotIn('group', str(result))

    def test_parse_drops_a_bad_hash_and_masks_the_table(self):
        result = survey.parse('SHA\tnot-a-hash\nTABLE\t0-8: default-key, x ' + 'ab' * 32)
        self.assertNotIn('recovery_a_sha256', result)
        self.assertIn('<hex>', result['dm_table'])


class Audit(unittest.TestCase):
    def image(self, drop=()):
        entries = [(path, 0o100755, elf(['libc.so'])) for path in audit.seeds() if path not in drop]
        entries += [(path, 0o100644, b'data') for path in audit.DATA_SEEDS if path != 'prop.default' and path not in drop]
        entries += [('vendor/lib64/libc.so', 0o100755, elf([])),
                    ('prop.default', 0o100644, b'ro.build.version.release=15\nro.twrp.version.skkk.code=900\nro.secret=x\n'),
                    ('system/bin/recovery', 0o100755, b'SECRET-PAYLOAD'), ('init', 0o120777, b'init.real')]
        return boot_image(lz4_legacy(newc_archive(entries)))

    def test_clean_image_has_no_missing_seeds(self):
        report = audit.audit(self.image())
        self.assertEqual(report['missing_seeds'], [])
        self.assertEqual(report['properties'], {'ro.build.version.release': '15', 'ro.twrp.version.skkk.code': '900'})
        self.assertEqual(report['removed_at_staging_present'], ['system/bin/recovery'])

    def test_missing_seed_reported(self):
        report = audit.audit(self.image(drop=('vendor/bin/qseecomd', 'sepolicy')))
        self.assertEqual(report['missing_seeds'], ['sepolicy', 'vendor/bin/qseecomd'])

    def test_report_carries_no_payload(self):
        self.assertNotIn('SECRET-PAYLOAD', str(audit.audit(self.image())))

    def test_carrier_fields_recorded(self):
        carrier = boot_image(b'R', kernel=8, raw_os=bootimage.encode_os_version('12.0.0', '2025-09'))
        report = audit.audit(self.image(), carrier)
        self.assertEqual(report['carrier_header'], {'os_version': '12.0.0', 'os_patch': '2025-09'})

    def test_seeds_cover_every_service(self):
        for _, path in (*plan.TEE_SERVICES, *plan.CE_ONLY_SERVICES):
            self.assertIn(path.lstrip('/'), audit.seeds())


if __name__ == '__main__':
    unittest.main(verbosity=1)
