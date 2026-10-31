#!/usr/bin/env python3
"""Mutation check for the M19 safety gates: every mutant must make test.py fail."""
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
MUTANTS = (
    ('plan.py', "'flags': DM_READONLY_FLAG}", "'flags': 0}"),
    ('plan.py', "TABLE_FEATURES = ('sector_size:4096', 'iv_large_sectors', 'wrappedkey_v0')", "TABLE_FEATURES = ('allow_discards', 'sector_size:4096', 'iv_large_sectors', 'wrappedkey_v0')"),
    ('plan.py', "if sectors != USERDATA_SECTORS:", "if False:"),
    ('plan.py', "'read_only': True, 'data': ','.join(['norecovery', 'inlinecrypt', *extra])", "'read_only': False, 'data': ','.join(['norecovery', 'inlinecrypt', *extra])"),
    ('plan.py', "['norecovery', 'inlinecrypt', *extra]", "['inlinecrypt', *extra]"),
    ('plan.py', "if option in F2FS_FORBIDDEN or option.split('=')[0] in ('checkpoint', 'discard'):", "if False:"),
    ('plan.py', "'read_only': True, 'data': 'noload'", "'read_only': True, 'data': ''"),
    ('plan.py', "if seen != set(overrides):", "if False:"),
    ('plan.py', "line = f'{name}={overrides[name]}'", "pass"),
    ('plan.py', "if RC_FORBIDDEN.search(text):", "if False:"),
    ('plan.py', "if started - allowed:", "if False:"),
    ('plan.py', "gate('NO_CHECKPOINT', survey.get('checkpoint_pending') is False,", "gate('NO_CHECKPOINT', True,"),
    ('plan.py', "survey.get('recovery_a_sha256') == audit.get('image_sha256')", "True"),
    ('plan.py', "header == carrier and ", ""),
    ('plan.py', "bool(roots) and all(", "bool(roots) or all("),
    ('plan.py', "if set(names) - {'allow_discards'} != set(TABLE_FEATURES):", "if False:"),
    ('fbe.py', "if UPGRADED_BLOB in names:", "if False:"),
    ('fbe.py', "if names == CE_FILES:", "if CE_FILES <= names:"),
    ('fbe.py', "if len(secdiscardable) != 16384:", "if False:"),
    ('fbe.py', "prefix.ljust(SHA512_BLOCK, b'\\0') + data", "prefix + data"),
    ('fbe.py', "if version != 2:", "if False:"),
    ('rootfs.py', "if path not in HOME_ALLOWED or any(", "if any(path == 'x' for x in ()) or any("),
    ('rootfs.py', "if not path.startswith('/run/'):\n            raise Stop('WRITE_OUTSIDE_RUN')", "if False:\n            pass\n        tree.setdefault('/etc/x', '')"),
    ('rootfs.py', "'hybrid-sleep.target', 'suspend-then-hibernate.target')", "'hybrid-sleep.target')[:-6]"),
    ('survey.py', "return HEX.sub('<hex>', value) if isinstance(value, str) else value", "return value"),
    ('survey.py', "entry.pop('group', None)", "entry.get('group')"),
    ('survey.py', "r'cat [^|\\n]*(encrypted_key|keymaster_key_blob|secdiscardable)',", ""),
    ('bootimage.py', "if name.startswith('/') or '..' in name.split('/'):", "if False:"),
    ('bootimage.py', "if offset == 0 or offset > len(out):", "if False:"),
    ('bootimage.py', "if size == 0 or start + size > len(image):", "if False:"),
    ('elfdeps.py', "missing.add(name)", "pass"),
    ('audit.py', "if name in PROPERTIES:", "if True:"),
)


def main():
    survivors = []
    for number, (name, old, new) in enumerate(MUTANTS):
        source = (HERE / name).read_text(encoding='utf-8')
        if old not in source:
            sys.exit(f'mutant {number} does not apply to {name}: {old}')
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'scripts' / 'm19'
            target.mkdir(parents=True)
            for path in HERE.glob('*.py'):
                shutil.copy(path, target)
            (target / name).write_text(source.replace(old, new), encoding='utf-8')
            result = subprocess.run([sys.executable, 'test.py'], cwd=target, capture_output=True, timeout=120)
        if result.returncode == 0:
            survivors.append((number, name, old))
    print(f'{len(MUTANTS) - len(survivors)} of {len(MUTANTS)} mutants killed')
    for survivor in survivors:
        print('SURVIVED', survivor)
    sys.exit(1 if survivors else 0)


if __name__ == '__main__':
    main()
