#!/usr/bin/env python3
"""Fetch the frozen Keystore2 and KeyMint V1 AIDL plus the C++ binder headers, and check both
against aidl.lock.json. The NDK sysroot ships only the public C binder API."""
import argparse
import hashlib
import io
import json
import tarfile
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
LOCK = HERE / 'aidl.lock.json'
TAG = 'android-12.1.0_r27'
HEADER_TAG = 'android-16.0.0_r1'
SOURCES = (
    ('keymint', 'platform/hardware/interfaces', TAG, 'security/keymint/aidl/aidl_api/android.hardware.security.keymint/1', '.aidl'),
    ('secureclock', 'platform/hardware/interfaces', TAG, 'security/secureclock/aidl/aidl_api/android.hardware.security.secureclock/1', '.aidl'),
    ('keystore2', 'platform/system/hardware/interfaces', TAG, 'keystore2/aidl/aidl_api/android.system.keystore2/1', '.aidl'),
    ('binder_cpp', 'platform/frameworks/native', HEADER_TAG, 'libs/binder/ndk/include_cpp', '.h'),
    ('binder_platform', 'platform/frameworks/native', HEADER_TAG, 'libs/binder/ndk/include_platform', '.h'),
)


def fetch(name, repository, tag, path, suffix):
    url = f'https://android.googlesource.com/{repository}/+archive/refs/tags/{tag}/{path}.tar.gz'
    with urllib.request.urlopen(url, timeout=120) as response:
        archive = response.read()
    files = {}
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as tar:
        for member in tar.getmembers():
            if member.isfile() and member.name.endswith(suffix):
                relative = member.name.removeprefix('./')
                if relative.startswith('/') or '..' in relative.split('/'):
                    raise SystemExit(f'unsafe member {relative}')
                files[f'{name}/{relative}'] = tar.extractfile(member).read()
    return files


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path)
    parser.add_argument('--write-lock', action='store_true')
    arguments = parser.parse_args()
    files = {}
    for source in SOURCES:
        files.update(fetch(*source))
    hashes = {path: hashlib.sha256(data).hexdigest() for path, data in sorted(files.items())}
    if arguments.write_lock:
        LOCK.write_text(json.dumps({'tag': TAG, 'header_tag': HEADER_TAG, 'files': hashes}, indent=1) + '\n', encoding='utf-8', newline='\n')
    elif json.loads(LOCK.read_text(encoding='utf-8'))['files'] != hashes:
        raise SystemExit('AIDL does not match aidl.lock.json')
    if arguments.out:
        for path, data in files.items():
            target = arguments.out / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
    print(f'AIDL: {len(files)} files at {TAG} and {HEADER_TAG}')


if __name__ == '__main__':
    main()
