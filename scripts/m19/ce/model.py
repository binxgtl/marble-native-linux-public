#!/usr/bin/env python3
"""Independent model of TWRP's CE path (docs/m19-r7.md), for synthetic fixtures only.

AES-256 and GCM are written here from FIPS-197 and SP 800-38D, so the C core's libcrypto use is checked against
code that shares nothing with it. No device file, PIN or key is ever read: every input is generated from a seed.
"""
import hashlib
import hmac
import random
from pathlib import Path

SBOX = []


def _sbox():
    inverse = [0] * 256
    for value in range(1, 256):
        result, base, power = 1, value, 254
        while power:
            if power & 1:
                result = _mul(result, base)
            base = _mul(base, base)
            power >>= 1
        inverse[value] = result
    table = []
    for value in range(256):
        x = inverse[value]
        y = x
        for _ in range(4):
            x = ((x << 1) | (x >> 7)) & 0xff
            y ^= x
        table.append(y ^ 0x63)
    return table


def _mul(a, b):
    product = 0
    while b:
        if b & 1:
            product ^= a
        a = ((a << 1) ^ 0x1b) & 0xff if a & 0x80 else a << 1
        b >>= 1
    return product


SBOX = _sbox()


def _expand(key):
    assert len(key) == 32
    words = [list(key[i:i + 4]) for i in range(0, 32, 4)]
    rcon = 1
    for i in range(8, 60):
        word = list(words[i - 1])
        if i % 8 == 0:
            word = word[1:] + word[:1]
            word = [SBOX[b] for b in word]
            word[0] ^= rcon
            rcon = _mul(rcon, 2)
        elif i % 8 == 4:
            word = [SBOX[b] for b in word]
        words.append([a ^ b for a, b in zip(words[i - 8], word)])
    return [sum(words[4 * r:4 * r + 4], []) for r in range(15)]


def _encrypt_block(rounds, block):
    state = [a ^ b for a, b in zip(block, rounds[0])]
    for number in range(1, 15):
        state = [SBOX[b] for b in state]
        state = [state[(c * 4 + r + 4 * r) % 16] for c in range(4) for r in range(4)]
        if number != 14:
            mixed = []
            for c in range(4):
                a = state[4 * c:4 * c + 4]
                mixed += [_mul(a[0], 2) ^ _mul(a[1], 3) ^ a[2] ^ a[3], a[0] ^ _mul(a[1], 2) ^ _mul(a[2], 3) ^ a[3],
                          a[0] ^ a[1] ^ _mul(a[2], 2) ^ _mul(a[3], 3), _mul(a[0], 3) ^ a[1] ^ a[2] ^ _mul(a[3], 2)]
            state = mixed
        state = [a ^ b for a, b in zip(state, rounds[number])]
    return bytes(state)


def _gf_mul(x, y):
    r, z, v = 0xe1 << 120, 0, x
    for bit in range(127, -1, -1):
        if (y >> bit) & 1:
            z ^= v
        v = (v >> 1) ^ r if v & 1 else v >> 1
    return z


def _ghash(h, data):
    y = 0
    for i in range(0, len(data), 16):
        y = _gf_mul(y ^ int.from_bytes(data[i:i + 16], 'big'), h)
    return y


def _pad16(data):
    return data + bytes(-len(data) % 16)


def _gcm(key, nonce, data):
    assert len(nonce) == 12
    rounds = _expand(key)
    h = int.from_bytes(_encrypt_block(rounds, bytes(16)), 'big')
    j0 = nonce + b'\0\0\0\1'
    out = bytearray()
    for i in range(0, len(data), 16):
        counter = nonce + (2 + i // 16).to_bytes(4, 'big')
        stream = _encrypt_block(rounds, counter)
        out += bytes(a ^ b for a, b in zip(data[i:i + 16], stream))
    return rounds, h, j0, bytes(out)


def gcm_seal(key, nonce, plain):
    rounds, h, j0, cipher = _gcm(key, nonce, plain)
    s = _ghash(h, _pad16(cipher) + (0).to_bytes(8, 'big') + (len(cipher) * 8).to_bytes(8, 'big'))
    tag = (s ^ int.from_bytes(_encrypt_block(rounds, j0), 'big')).to_bytes(16, 'big')
    return cipher + tag


def gcm_open(key, nonce, sealed):
    rounds, h, j0, plain = _gcm(key, nonce, sealed[:-16])
    cipher = sealed[:-16]
    s = _ghash(h, _pad16(cipher) + (0).to_bytes(8, 'big') + (len(cipher) * 8).to_bytes(8, 'big'))
    tag = (s ^ int.from_bytes(_encrypt_block(rounds, j0), 'big')).to_bytes(16, 'big')
    if not hmac.compare_digest(tag, sealed[-16:]):
        raise ValueError('tag')
    return plain


def personalized(label, data):
    return hashlib.sha512(label.encode().ljust(128, b'\0') + data).digest()


def sp800(key, label, context):
    message = (1).to_bytes(4, 'big') + label.encode() + b'\0' + context.encode() + (len(context) * 8).to_bytes(4, 'big') + \
        (256).to_bytes(4, 'big')
    return hmac.new(key, message, hashlib.sha256).digest()


def storage_wrap_key(secret):
    return hashlib.sha512(b'Android key wrapping key generation SHA512'.ljust(128, b'\0') + secret).digest()[:32]


def secdis_app_id(secdis):
    return hashlib.sha512(b'Android secdiscardable SHA512'.ljust(128, b'\0') + secdis).digest()


def fake_blob_key(blob, app_id):
    """The fake Keystore's DE key: bound to the blob and the application id, as KeyMint binds APPLICATION_ID."""
    return hashlib.sha256(b'm19-fake-keymint' + blob + app_id).digest()


def fake_ephemeral(storage):
    return b'EPH' + hashlib.sha256(storage).digest()


def build(root, pin, seed=1, version=3, logs=(11, 3, 1), protector=None):
    """Write a synthetic spblob and CE key directory under root and return the values the fakes check."""
    rng = random.Random(seed)
    take = lambda n: bytes(rng.randrange(256) for _ in range(n))
    protector = protector or ''.join(rng.choice('0123456789abcdef') for _ in range(16))
    log_n, log_r, log_p = logs
    salt, handle, secdis = take(16), take(58), take(16384)
    keystore_key, sp = take(32), take(32)
    token = hashlib.scrypt(pin.encode(), salt=salt, n=1 << log_n, r=1 << log_r, p=1 << log_p, dklen=32, maxmem=1 << 26)
    provided = personalized('user-gk-authentication', token)
    app_key = personalized('application-id', token + personalized('secdiscardable-transform', secdis))[:32]
    inner_nonce, outer_nonce, ce_nonce = take(12), take(12), take(12)
    intermediate = inner_nonce + gcm_seal(app_key, inner_nonce, sp)
    spblob = bytes([version, 0]) + outer_nonce + gcm_seal(keystore_key, outer_nonce, intermediate)
    if version == 3:
        secret = sp800(sp, 'fbe-key', 'android-synthetic-password-personalization-context')
    else:
        secret = personalized('fbe-key', sp)
    storage = take(254)
    encrypted = ce_nonce + gcm_seal(storage_wrap_key(secret), ce_nonce, storage)
    auth = bytes([0]) + take(8) + take(8) + take(8) + (2).to_bytes(4, 'big') + take(8) + take(32)
    pwd = (2).to_bytes(4, 'big') + bytes([log_n, log_r, log_p]) + len(salt).to_bytes(4, 'big') + salt + \
        len(handle).to_bytes(4, 'big') + handle + (len(pin)).to_bytes(4, 'big')
    spdir = Path(root) / 'spblob'
    cedir = Path(root) / 'ce' / 'current'
    spdir.mkdir(parents=True, exist_ok=True)
    cedir.mkdir(parents=True, exist_ok=True)
    (spdir / f'{protector}.pwd').write_bytes(pwd)
    (spdir / f'{protector}.spblob').write_bytes(spblob)
    (spdir / f'{protector}.secdis').write_bytes(secdis)
    (spdir / '0000000000000000.handle').write_bytes(take(58))
    (spdir / '0000000000000000.milock').write_bytes(b'\1')
    (spdir / f'{protector}.metrics').write_bytes(take(72))
    (cedir / 'version').write_bytes(b'1')
    (cedir / 'encrypted_key').write_bytes(encrypted)
    alias = 'synthetic_password_' + (protector.lstrip('0') or '0')
    values = {'handle': handle, 'provided': provided, 'auth': auth, 'keystore_key': keystore_key, 'storage': storage,
              'ephemeral': fake_ephemeral(storage), 'alias': alias.encode()}
    lines = [f'{name}={value.hex()}' for name, value in values.items()]
    (Path(root) / 'fixture.txt').write_text('\n'.join(lines) + '\n', encoding='ascii')
    return values


def build_keystore_dir(directory, seed=2):
    """A keystore-bound key directory (DE system or user) with the fake Keystore's binding."""
    rng = random.Random(seed)
    take = lambda n: bytes(rng.randrange(256) for _ in range(n))
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    blob, secdis, storage, nonce = take(214), take(16384), take(254), take(12)
    key = fake_blob_key(blob, secdis_app_id(secdis))
    (directory / 'version').write_bytes(b'1')
    (directory / 'keymaster_key_blob').write_bytes(blob)
    (directory / 'secdiscardable').write_bytes(secdis)
    (directory / 'encrypted_key').write_bytes(nonce + gcm_seal(key, nonce, storage))
    return fake_ephemeral(storage)


def self_check():
    # FIPS-197 C.3 and the GCM spec's test case 16 (AES-256, 96-bit IV, no AAD).
    key = bytes(range(32))
    assert _encrypt_block(_expand(key), bytes.fromhex('00112233445566778899aabbccddeeff')).hex() == '8ea2b7ca516745bfeafc49904b496089'
    key = bytes.fromhex('feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308')
    nonce = bytes.fromhex('cafebabefacedbaddecaf888')
    plain = bytes.fromhex('d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255')
    sealed = gcm_seal(key, nonce, plain)
    assert sealed[-16:].hex() == 'b094dac5d93471bdec1a502270e3cc6c', sealed[-16:].hex()
    assert gcm_open(key, nonce, sealed) == plain


if __name__ == '__main__':
    self_check()
    print('model self-check PASS')
