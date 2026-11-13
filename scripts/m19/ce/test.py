#!/usr/bin/env python3
"""The CE core (ce.c, crypto.c, fscrypt.c's layout) against model.py's synthetic fixtures. No device, PIN or key."""
import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import model  # noqa: E402

ARGS = None
PIN = '482916'


def run(*arguments):
    result = subprocess.run([ARGS.binary, ARGS.libcrypto, *arguments], capture_output=True, text=True, timeout=120)
    return result.returncode, result.stdout.strip()


def fields(line):
    head, *rest = line.split()
    return head, dict(item.split('=', 1) for item in rest)


class Unlock(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def unlock(self, pin=PIN, fault=None):
        code, out = run('unlock', str(self.root), pin, *([fault] if fault else []))
        head, values = fields(out)
        self.assertEqual(head, 'CE', out)
        self.assertEqual(values['residue'], '0', 'a secret outlived the call')
        return code, values

    def test_v3_unlocks_and_installs_the_ce_key(self):
        model.build(self.root, PIN, version=3)
        code, out = self.unlock()
        self.assertEqual((code, out['status'], out['installed'], out['match']), (0, 'OK', '1', '1'), out)
        self.assertEqual((out['gk_calls'], out['auth_added'], out['sp_calls'], out['order'], out['version']), ('1', '1', '1', '1', '3'))

    def test_v2_uses_the_personalized_hash(self):
        model.build(self.root, PIN, version=2, seed=7)
        code, out = self.unlock()
        self.assertEqual((code, out['status'], out['match'], out['version']), (0, 'OK', '1', '2'), out)

    def test_a_leading_zero_protector_keeps_aosp_alias(self):
        model.build(self.root, PIN, protector='00a1b2c3d4e5f607')
        code, out = self.unlock()
        self.assertEqual((code, out['status']), (0, 'OK'), out)

    def test_wrong_pin_is_one_rejected_attempt(self):
        model.build(self.root, PIN)
        code, out = self.unlock(pin='482917')
        self.assertEqual((code, out['status'], out['gk_calls'], out['sp_calls'], out['installed']), (1, 'GK_REJECTED', '1', '0', '0'))

    def test_gatekeeper_retry_and_error(self):
        model.build(self.root, PIN)
        code, out = self.unlock(fault='gk-retry')
        self.assertEqual((out['status'], out['timeout'], out['sp_calls']), ('GK_RETRY', '30000', '0'))
        code, out = self.unlock(fault='gk-error')
        self.assertEqual((out['status'], out['sp_calls']), ('GK_CONNECT', '0'))

    def test_connection_failures_stop_before_gatekeeper(self):
        model.build(self.root, PIN)
        for fault, status in (('gk-connect', 'GK_CONNECT'), ('ks-connect', 'KS_CONNECT'), ('storage-connect', 'KS_CONNECT')):
            code, out = self.unlock(fault=fault)
            self.assertEqual((code, out['status'], out['gk_calls']), (1, status, '0'), fault)

    def test_auth_token_problems_stop_before_the_sp_key(self):
        model.build(self.root, PIN)
        for fault in ('auth-reject', 'gk-short-token'):
            code, out = self.unlock(fault=fault)
            self.assertEqual((out['status'], out['sp_calls'], out['gk_calls']), ('AUTH_TOKEN', '0', '1'), fault)

    def test_bad_pins_never_reach_gatekeeper(self):
        model.build(self.root, PIN)
        for pin in ('123', '12345678901234567', '12a456', ''):
            code, out = self.unlock(pin=pin)
            self.assertEqual((code, out['status'], out['gk_calls']), (1, 'ARGUMENTS', '0'), pin)

    def tamper(self, suffix, offset):
        path = next((self.root / 'spblob').glob(f'*{suffix}'))
        data = bytearray(path.read_bytes())
        data[offset] ^= 1
        path.write_bytes(bytes(data))

    def test_tampered_spblob_fails_at_keystore(self):
        model.build(self.root, PIN)
        self.tamper('.spblob', -1)
        code, out = self.unlock()
        self.assertEqual((out['status'], out['installed']), ('SP_UNWRAP', '0'))

    def test_tampered_secdis_fails_the_inner_tag(self):
        model.build(self.root, PIN)
        self.tamper('.secdis', 100)
        code, out = self.unlock()
        self.assertEqual((out['status'], out['installed']), ('SP_TAG', '0'))

    def test_tampered_ce_key_fails_its_tag(self):
        model.build(self.root, PIN)
        path = self.root / 'ce' / 'current' / 'encrypted_key'
        data = bytearray(path.read_bytes())
        data[20] ^= 1
        path.write_bytes(bytes(data))
        code, out = self.unlock()
        self.assertEqual((out['status'], out['installed']), ('CE_TAG', '0'))

    def test_spblob_shape_is_checked_before_gatekeeper(self):
        for offset, value in ((0, 4), (0, 1), (1, 1)):
            with self.subTest(offset=offset, value=value):
                shutil.rmtree(self.root, ignore_errors=True)
                model.build(self.root, PIN)
                path = next((self.root / 'spblob').glob('*.spblob'))
                data = bytearray(path.read_bytes())
                data[offset] = value
                path.write_bytes(bytes(data))
                code, out = self.unlock()
                self.assertEqual((out['status'], out['gk_calls']), ('SPBLOB', '0'))

    def test_protector_must_be_unique_and_complete(self):
        model.build(self.root, PIN)
        spblob = self.root / 'spblob'
        for path in list(spblob.glob('*')):
            if path.suffix in ('.pwd', '.spblob', '.secdis'):
                shutil.copy(path, spblob / ('1111111111111111' + path.suffix))
        code, out = self.unlock()
        self.assertEqual((out['status'], out['gk_calls']), ('PROTECTOR', '0'))
        for suffix in ('.pwd', '.spblob', '.secdis'):
            (spblob / ('1111111111111111' + suffix)).unlink()
        next(spblob.glob('*.secdis')).unlink()
        code, out = self.unlock()
        self.assertEqual((out['status'], out['gk_calls']), ('PROTECTOR', '0'))

    def test_uppercase_or_linked_protector_is_refused(self):
        model.build(self.root, PIN, protector='abcdef0123456789')
        spblob = self.root / 'spblob'
        for suffix in ('.pwd', '.spblob', '.secdis'):
            os.rename(spblob / ('abcdef0123456789' + suffix), spblob / ('ABCDEF0123456789' + suffix))
        code, out = self.unlock()
        self.assertEqual(out['status'], 'PROTECTOR')
        shutil.rmtree(self.root)
        model.build(self.root, PIN)
        pwd = next((self.root / 'spblob').glob('*.pwd'))
        target = self.root / 'elsewhere.pwd'
        os.rename(pwd, target)
        os.symlink(target, pwd)
        code, out = self.unlock()
        self.assertIn(out['status'], ('PROTECTOR', 'PASSWORD_DATA'))
        self.assertEqual(out['gk_calls'], '0')

    def test_password_data_bounds(self):
        for change in ('salt0', 'salt-long', 'handle0', 'logn0', 'logn16', 'short'):
            with self.subTest(change=change):
                shutil.rmtree(self.root, ignore_errors=True)
                model.build(self.root, PIN)
                path = next((self.root / 'spblob').glob('*.pwd'))
                data = bytearray(path.read_bytes())
                if change == 'salt0':
                    data[7:11] = (0).to_bytes(4, 'big')
                elif change == 'salt-long':
                    data[7:11] = (65).to_bytes(4, 'big')
                elif change == 'handle0':
                    data[27:31] = (0).to_bytes(4, 'big')
                elif change == 'logn0':
                    data[4] = 0
                elif change == 'logn16':
                    data[4] = 16
                else:
                    data = data[:10]
                path.write_bytes(bytes(data))
                code, out = self.unlock()
                self.assertEqual((out['status'], out['gk_calls']), ('PASSWORD_DATA', '0'))

    def test_ce_directory_layout_is_checked_before_gatekeeper(self):
        for change in ('extra', 'version', 'short', 'missing'):
            with self.subTest(change=change):
                shutil.rmtree(self.root, ignore_errors=True)
                model.build(self.root, PIN)
                ce = self.root / 'ce' / 'current'
                if change == 'extra':
                    (ce / 'keymaster_key_blob').write_bytes(b'x')
                elif change == 'version':
                    (ce / 'version').write_bytes(b'2')
                elif change == 'short':
                    (ce / 'encrypted_key').write_bytes(bytes(28))
                else:
                    (ce / 'encrypted_key').unlink()
                code, out = self.unlock()
                self.assertEqual((out['status'], out['gk_calls']), ('CE_LAYOUT', '0'))

    def test_install_and_ephemeral_failures(self):
        model.build(self.root, PIN)
        code, out = self.unlock(fault='eph-fail')
        self.assertEqual((out['status'], out['installed']), ('EPHEMERAL', '0'))
        code, out = self.unlock(fault='install-fail')
        self.assertEqual((out['status'], out['installed']), ('INSTALL', '0'))


class Parts(unittest.TestCase):
    def test_personalized_hash_matches_the_model(self):
        for label, data in (('user-gk-authentication', bytes(range(32))), ('application-id', bytes(96)), ('fbe-key', b'\xff' * 33)):
            code, out = run('hash', label, data.hex())
            self.assertEqual(out, 'HASH ' + model.personalized(label, data).hex())

    def test_sp800_matches_the_model(self):
        key = bytes(range(32))
        code, out = run('sp800', key.hex(), 'fbe-key', 'android-synthetic-password-personalization-context')
        self.assertEqual(out, 'SP800 ' + model.sp800(key, 'fbe-key', 'android-synthetic-password-personalization-context').hex())

    def test_auth_token_fields(self):
        token = bytes([0]) + (1).to_bytes(8, 'little') + (2).to_bytes(8, 'little') + (3).to_bytes(8, 'little') + \
            (2).to_bytes(4, 'big') + (123456789).to_bytes(8, 'big') + bytes(range(32))
        code, out = run('auth', token.hex())
        self.assertEqual(out, 'AUTH 1 2 3 2 123456789 ' + bytes(range(32)).hex())
        self.assertEqual(run('auth', (b'\1' + token[1:]).hex())[1], 'AUTH bad')
        self.assertEqual(run('auth', token[:-1].hex())[1], 'AUTH bad')

    def test_pin_rules(self):
        for pin, result in (('1234', '0'), ('1234567890123456', '0'), ('123', '-1'), ('12345678901234567', '-1'), ('12 4', '-1'),
                            ('٣٤٥٦', '-1')):
            self.assertEqual(run('pin', pin)[1], f'PIN {result}', pin)

    def test_add_key_layout(self):
        code, out = run('layout')
        head, length, data = out.split()
        data = bytes.fromhex(data)
        self.assertEqual((head, length, len(data)), ('LAYOUT', '83', 83))
        self.assertEqual(int.from_bytes(data[0:4], 'little'), 2)
        self.assertEqual(int.from_bytes(data[0x28:0x2c], 'little'), 3)
        self.assertEqual(int.from_bytes(data[0x4c:0x50], 'little'), 1)
        self.assertEqual(data[0x50:], bytes([0xa1, 0xa2, 0xa3]))
        self.assertEqual(data[4:0x28] + data[0x2c:0x4c], bytes(0x24 + 0x20))


class DeAndCopy(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_keystore_key_directory_is_installed(self):
        expected = model.build_keystore_dir(self.root / 'key')
        code, out = run('de', str(self.root / 'key'), expected.hex())
        self.assertEqual((code, out), (0, 'DE status=OK installed=1 match=1 upgraded=0 residue=0'))
        code, out = run('de', str(self.root / 'key'), expected.hex(), 'upgrade')
        self.assertEqual((code, out), (0, 'DE status=OK installed=1 match=1 upgraded=1 residue=0'))

    def test_keystore_key_failures(self):
        expected = model.build_keystore_dir(self.root / 'key')
        self.assertEqual(run('de', str(self.root / 'key'), expected.hex(), 'eph-fail')[1], 'DE status=EPHEMERAL installed=0 match=0 upgraded=0 residue=0')
        self.assertEqual(run('de', str(self.root / 'key'), expected.hex(), 'install-fail')[1], 'DE status=INSTALL installed=0 match=0 upgraded=0 residue=0')
        (self.root / 'key' / 'keymaster_key_blob_upgraded').write_bytes(b'x')
        self.assertEqual(run('de', str(self.root / 'key'), expected.hex())[1], 'DE status=DE_LAYOUT installed=0 match=0 upgraded=0 residue=0')
        (self.root / 'key' / 'keymaster_key_blob_upgraded').unlink()
        data = bytearray((self.root / 'key' / 'encrypted_key').read_bytes())
        data[-1] ^= 1
        (self.root / 'key' / 'encrypted_key').write_bytes(bytes(data))
        self.assertEqual(run('de', str(self.root / 'key'), expected.hex())[1], 'DE status=DE_DECRYPT installed=0 match=0 upgraded=-1 residue=0')

    def test_database_copy_rewrites_the_same_inode(self):
        source, target = self.root / 'source.sqlite', self.root / 'target.sqlite'
        source.write_bytes(os.urandom(200000))
        target.write_bytes(b'old database' * 30000)
        code, out = run('copy', str(source), str(target))
        self.assertEqual((code, out), (0, 'COPY status=OK same_inode=1'))
        self.assertEqual(target.read_bytes(), source.read_bytes())
        empty = self.root / 'empty.sqlite'
        empty.write_bytes(b'')
        self.assertEqual(run('copy', str(empty), str(target))[1], 'COPY status=DB_COPY same_inode=1')
        link = self.root / 'link.sqlite'
        os.symlink(source, link)
        original = source.read_bytes()
        self.assertEqual(run('copy', str(link), str(target))[1], 'COPY status=DB_COPY same_inode=1')
        self.assertEqual(run('copy', str(source), str(link))[1], 'COPY status=DB_COPY same_inode=1')
        self.assertEqual(source.read_bytes(), original, 'a link target was written through')


def main():
    global ARGS
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True)
    parser.add_argument('--libcrypto', default='libcrypto.so.3')
    ARGS, rest = parser.parse_known_args()
    model.self_check()
    unittest.main(argv=[sys.argv[0], *rest], verbosity=1)


if __name__ == '__main__':
    main()
