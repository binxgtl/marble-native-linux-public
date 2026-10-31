#!/usr/bin/env python3
"""Fetch the frozen Keystore2 and KeyMint V1 AIDL and check it against aidl.lock.json."""
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
SOURCES = (
    ('keymint', 'platform/hardware/interfaces', 'security/keymint/aidl/aidl_api/android.hardware.security.keymint/1'),
    ('secureclock', 'platform/hardware/interfaces', 'security/secureclock/aidl/aidl_api/android.hardware.security.secureclock/1'),
    ('keystore2', 'platform/system/hardware/interfaces', 'keystore2/aidl/aidl_api/android.system.keystore2/1'),
)


def fetch(name, repository, path):
    url = f'https://android.googlesource.com/{repository}/+archive/refs/tags/{TAG}/{path}.tar.gz'
    with urllib.request.urlopen(url, timeout=120) as response:
        archive = response.read()
    files = {}
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as tar:
        for member in tar.getmembers():
            if member.isfile() and member.name.endswith('.aidl'):
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
        LOCK.write_text(json.dumps({'tag': TAG, 'files': hashes}, indent=1) + '\n', encoding='utf-8', newline='\n')
    elif json.loads(LOCK.read_text(encoding='utf-8'))['files'] != hashes:
        raise SystemExit('AIDL does not match aidl.lock.json')
    if arguments.out:
        for path, data in files.items():
            target = arguments.out / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
    print(f'AIDL: {len(files)} files at {TAG}')


if __name__ == '__main__':
    main()
