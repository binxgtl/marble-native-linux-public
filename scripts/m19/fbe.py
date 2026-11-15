#!/usr/bin/env python3
"""Offline FBE and metadata-encryption facts for marble.

Everything here works on layout and metadata. No function accepts a key, a PIN or a
synthetic password, and nothing here reads key file contents from a device.
"""
import hashlib

CE_FILES = frozenset({'version', 'encrypted_key'})
KEYSTORE_FILES = frozenset({'version', 'encrypted_key', 'keymaster_key_blob', 'secdiscardable'})
UPGRADED_BLOB = 'keymaster_key_blob_upgraded'
FSCRYPT_MODES = {1: 'aes-256-xts', 4: 'aes-256-cts'}
FLAG_PAD_MASK, FLAG_DIRECT_KEY, FLAG_IV_INO_LBLK_64, FLAG_IV_INO_LBLK_32 = 0x03, 0x04, 0x08, 0x10
HASH_PREFIX_SECDISCARDABLE = b'Android secdiscardable SHA512'
HASH_PREFIX_KEYGEN = b'Android key wrapping key generation SHA512'
SHA512_BLOCK = 128


class Stop(Exception):
    """A safety gate refused. The message names the gate, never a value of a secret."""


def parse_fstab_entry(line):
    fields = line.split()
    if len(fields) != 5:
        raise Stop('FSTAB_SHAPE')
    device, mount, fs_type, mount_options, manager_options = fields
    manager = {}
    for option in manager_options.split(','):
        name, _, value = option.partition('=')
        manager[name] = value
    return {'device': device, 'mount': mount, 'type': fs_type,
            'mount_options': mount_options.split(','), 'manager': manager}


def userdata_contract(entry):
    """Check the userdata fstab entry matches the path this milestone was designed for."""
    manager = entry['manager']
    expected = {
        'fileencryption': 'aes-256-xts:aes-256-cts:v2+inlinecrypt_optimized+wrappedkey_v0',
        'metadata_encryption': 'aes-256-xts:wrappedkey_v0',
        'keydirectory': '/metadata/vold/metadata_encryption',
    }
    if entry['mount'] != '/data' or entry['type'] != 'f2fs':
        raise Stop('USERDATA_NOT_F2FS')
    for name, value in expected.items():
        if manager.get(name) != value:
            raise Stop(f'USERDATA_{name.upper()}')
    if 'inlinecrypt' not in entry['mount_options']:
        raise Stop('USERDATA_NO_INLINECRYPT')
    return {'checkpoint': manager.get('checkpoint', ''), 'wrapped': True}


def decode_policy(version, contents, filenames, flags):
    if version != 2:
        raise Stop('POLICY_NOT_V2')
    if contents not in FSCRYPT_MODES or filenames not in FSCRYPT_MODES:
        raise Stop('POLICY_MODE')
    return {'contents': FSCRYPT_MODES[contents], 'filenames': FSCRYPT_MODES[filenames],
            'padding': 4 << (flags & FLAG_PAD_MASK), 'iv_ino_lblk_64': bool(flags & FLAG_IV_INO_LBLK_64),
            'direct_key': bool(flags & FLAG_DIRECT_KEY), 'iv_ino_lblk_32': bool(flags & FLAG_IV_INO_LBLK_32)}


def classify_path(survey_entry):
    """Map one surveyed path to the secret needed to read it."""
    if survey_entry.get('policy') == 'none':
        return 'metadata'
    key = survey_entry.get('class')
    if key not in ('ce', 'de-user', 'de-system'):
        raise Stop('POLICY_UNCLASSIFIED')
    return key


def classify_key_dir(names):
    """Name the protection of a vold key directory from its file names alone."""
    names = frozenset(names)
    if UPGRADED_BLOB in names:
        raise Stop('KEY_UPGRADE_PENDING')
    if names == KEYSTORE_FILES:
        return 'keystore'
    if names == CE_FILES:
        return 'secret'
    raise Stop('KEY_DIR_LAYOUT')


def hash_with_prefix(prefix, data):
    """Same construction as hashWithPrefix() in AOSP vold KeyStorage.cpp."""
    return hashlib.sha512(prefix.ljust(SHA512_BLOCK, b'\0') + data).digest()


def keystore_app_id(secdiscardable):
    """TAG_APPLICATION_ID for a keystore-bound directory with empty authentication."""
    if len(secdiscardable) != 16384:
        raise Stop('SECDISCARDABLE_SIZE')
    return hash_with_prefix(HASH_PREFIX_SECDISCARDABLE, secdiscardable)
