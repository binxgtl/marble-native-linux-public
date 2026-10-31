#!/usr/bin/env python3
"""Drive the compiled M19 helpers on synthetic images and cross-check them against Python."""
import argparse
import hashlib
import importlib.util
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import fbe
import plan

specification = importlib.util.spec_from_file_location('m19_offline_tests', HERE.parent / 'test.py')
builders = importlib.util.module_from_spec(specification)
specification.loader.exec_module(builders)

RDX = CORE = None
RC_PATH = 'system/etc/init/hw/init.rc'
PATCH = 'ro.build.version.security_patch=2026-08-05'
VENDOR_PATCH = 'ro.vendor.build.security_patch=2026-08-05'
PROPERTIES = b'ro.a=1\nro.build.version.security_patch=2099-12-31\nro.vendor.build.security_patch=2099-12-31\n'


def entries():
    return [('system', 0o40755, b''), ('system/bin', 0o40755, b''), ('system/bin/keystore2', 0o100755, b'ELF'),
            (RC_PATH, 0o100644, b'old rc'), ('prop.default', 0o100644, PROPERTIES), ('vendor/lib/modules/x.ko', 0o100644, b'KO'),
            ('twres/fonts/a', 0o100644, b'F'), ('link', 0o120777, b'system/bin/keystore2'),
            *((name, 0o100755, b'REMOVED') for name in plan.RECOVERY_REMOVED)]


def image(items=None, compressed=None):
    return builders.boot_image(compressed if compressed is not None else builders.lz4_legacy(builders.newc_archive(items or entries())))


class Rdx(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.base = Path(self.directory.name)
        self.dest = self.base / 'tree'
        self.dest.mkdir()
        (self.base / 'init.rc').write_text('new rc\n')

    def run_rdx(self, data, digest=None, overrides=(PATCH, VENDOR_PATCH), rc=None):
        path = self.base / 'recovery.img'
        path.write_bytes(data)
        digest = hashlib.sha256(data).hexdigest() if digest is None else digest
        command = [RDX, str(path), digest, str(self.dest), str(rc or self.base / 'init.rc'), *overrides]
        return subprocess.run(command, capture_output=True, text=True, timeout=60)

    def assert_status(self, result, status, code=1):
        self.assertEqual(result.stdout.strip(), f'M19_RDX status={status}')
        self.assertEqual(result.returncode, code)

    def test_extracts_and_applies_overrides(self):
        self.assert_status(self.run_rdx(image()), 'OK', 0)
        self.assertEqual((self.dest / 'system/bin/keystore2').read_bytes(), b'ELF')
        self.assertTrue(stat.S_IMODE((self.dest / 'system/bin/keystore2').stat().st_mode) & 0o100)
        self.assertEqual(os.readlink(self.dest / 'link'), 'system/bin/keystore2')
        self.assertEqual((self.dest / RC_PATH).read_text(), 'new rc\n')
        text = (self.dest / 'prop.default').read_text()
        self.assertEqual(text, 'ro.a=1\n' + PATCH + '\n' + VENDOR_PATCH + '\n')

    def test_patch_output_matches_python(self):
        self.assert_status(self.run_rdx(image()), 'OK', 0)
        self.assertEqual((self.dest / 'prop.default').read_text(), plan.patched_properties(PROPERTIES.decode()))

    def test_leaves_out_recovery_and_modules(self):
        self.assert_status(self.run_rdx(image()), 'OK', 0)
        for name in (*plan.RECOVERY_REMOVED, 'vendor/lib/modules/x.ko', 'twres/fonts/a'):
            if name != plan.RECOVERY_MARKER:
                self.assertFalse((self.dest / name).exists(), name)

    def test_marker_is_empty_and_not_executable(self):
        self.assert_status(self.run_rdx(image()), 'OK', 0)
        marker = self.dest / plan.RECOVERY_MARKER
        self.assertEqual(marker.read_bytes(), b'')
        self.assertFalse(stat.S_IMODE(marker.stat().st_mode) & 0o111)

    def test_wrong_hash_writes_nothing(self):
        self.assert_status(self.run_rdx(image(), digest='0' * 64), 'HASH')
        self.assertEqual(list(self.dest.iterdir()), [])

    def test_bad_hash_argument(self):
        self.assert_status(self.run_rdx(image(), digest='xyz'), 'ARGUMENTS', 2)

    def test_not_a_boot_image(self):
        self.assert_status(self.run_rdx(b'NOTBOOT!' + bytes(8192)), 'HEADER')

    def test_short_file(self):
        self.assert_status(self.run_rdx(b'ANDROID!'), 'HEADER')

    def test_ramdisk_past_the_end(self):
        data = bytearray(image())
        data[12:16] = (1 << 30).to_bytes(4, 'little')
        self.assert_status(self.run_rdx(bytes(data)), 'HEADER')

    def test_unknown_compression(self):
        self.assert_status(self.run_rdx(image(compressed=b'\x1f\x8b' + bytes(64))), 'RAMDISK')

    def test_truncated_lz4_block(self):
        self.assert_status(self.run_rdx(image(compressed=bytes.fromhex('02214c18') + (100).to_bytes(4, 'little') + b'abc')), 'RAMDISK')

    def test_bad_lz4_offset(self):
        block = bytes([0x10]) + b'a' + bytes([9, 0, 0])
        self.assert_status(self.run_rdx(image(compressed=bytes.fromhex('02214c18') + len(block).to_bytes(4, 'little') + block)), 'RAMDISK')

    def test_traversal_refused(self):
        result = self.run_rdx(image([('../outside', 0o100644, b'x')]))
        self.assert_status(result, 'CPIO')
        self.assertFalse((self.base / 'outside').exists())

    def test_absolute_name_refused(self):
        self.assert_status(self.run_rdx(image([('/etc/x', 0o100644, b'x')])), 'CPIO')

    def test_missing_trailer_refused(self):
        self.assert_status(self.run_rdx(image(compressed=builders.lz4_legacy(builders.newc_entry('a', 0o100644, b'x')))), 'CPIO')

    def test_missing_property_stops(self):
        self.assert_status(self.run_rdx(image(), overrides=('ro.absent=1',)), 'PROPERTY')

    def test_override_without_equals_refused(self):
        self.assert_status(self.run_rdx(image(), overrides=('ro.x',)), 'ARGUMENTS', 2)

    def test_image_without_rc_stops(self):
        items = [item for item in entries() if item[0] != RC_PATH]
        self.assert_status(self.run_rdx(image(items)), 'RC')

    def test_missing_rc_file_stops(self):
        self.assert_status(self.run_rdx(image(), rc=self.base / 'none'), 'RC')

    def test_missing_image_stops(self):
        result = subprocess.run([RDX, str(self.base / 'none'), '0' * 64, str(self.dest), str(self.base / 'init.rc')], capture_output=True, text=True)
        self.assert_status(result, 'READ')

    def test_real_lz4_matches(self):
        """A block with matches, from the python-lz4 codec when it is installed."""
        try:
            import lz4.block
        except ImportError:
            self.skipTest('python-lz4 is optional')
        archive = builders.newc_archive(entries() + [('big', 0o100644, b'abcd' * 50000)])
        block = lz4.block.compress(archive, store_size=False)
        compressed = bytes.fromhex('02214c18') + len(block).to_bytes(4, 'little') + block
        self.assert_status(self.run_rdx(image(compressed=compressed)), 'OK', 0)
        self.assertEqual((self.dest / 'big').read_bytes(), b'abcd' * 50000)


class Vectors(unittest.TestCase):
    def test_hashes_and_table_match_python(self):
        lines = subprocess.run([CORE, 'vectors'], capture_output=True, text=True, check=True).stdout.splitlines()
        position = 0
        for size in range(0, 300, 7):
            data = bytes([size & 0xff]) * size
            self.assertEqual(lines[position], hashlib.sha256(data).hexdigest())
            self.assertEqual(lines[position + 1], hashlib.sha512(data).hexdigest())
            position += 2
        self.assertEqual(lines[position], fbe.keystore_app_id(b'\x5a' * 16384).hex())
        table = plan.default_key_table(plan.USERDATA_SECTORS, '/dev/block/sda33')['parameters']
        self.assertEqual(lines[position + 1], table.replace(plan.KEY_PLACEHOLDER, '01fe'))


def main():
    global RDX, CORE
    parser = argparse.ArgumentParser()
    parser.add_argument('--rdx', required=True)
    parser.add_argument('--core', required=True)
    arguments = parser.parse_args()
    RDX, CORE = os.path.abspath(arguments.rdx), os.path.abspath(arguments.core)
    program = unittest.main(argv=['test-native'], exit=False, verbosity=1)
    sys.exit(not program.result.wasSuccessful())


if __name__ == '__main__':
    main()
