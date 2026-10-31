#!/usr/bin/env python3
"""Mutation check for the native M19 helpers: every mutant must fail a compiled test."""
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
PARENT = HERE.parent
MUTANTS = (
    ('core.c', 'return M19_UPGRADE_PENDING;', 'continue;'),
    ('core.c', 'return seen == sizeof(KEY_FILES) / sizeof(KEY_FILES[0]) ? M19_OK : M19_LAYOUT;', 'return M19_OK;'),
    ('core.c', "if (size != 1 || version[0] != '1') {", 'if (0) {'),
    ('core.c', 'size != M19_SECDISCARDABLE_BYTES)', '0)'),
    ('core.c', 'if (keys->encrypted_size <= M19_NONCE_BYTES + M19_MAC_BYTES)', 'if (0)'),
    ('core.c', 'status = result == M19_KS_UPGRADE ? M19_UPGRADE_REQUIRED : M19_DECRYPT;', 'status = M19_DECRYPT;'),
    ('core.c', 'status = result == M19_KS_UPGRADE ? M19_UPGRADE_REQUIRED : M19_EPHEMERAL;', 'status = M19_EPHEMERAL;'),
    ('core.c', 'if ((sectors & ~(uint64_t)7) != target->sectors)', 'if (0)'),
    ('core.c', '!strchr(target->device, \':\') && ', ''),
    ('core.c', '3 sector_size:4096 iv_large_sectors wrappedkey_v0', '4 allow_discards sector_size:4096 iv_large_sectors wrappedkey_v0'),
    ('core.c', 'm19_wipe(ephemeral, sizeof(ephemeral));', ''),
    ('core.c', 'm19_wipe(storage, sizeof(storage));', ''),
    ('core.c', 'if (created)\n        dm->remove(dm_context, target->name);', ''),
    ('core.c', 'keys.encrypted + M19_NONCE_BYTES, keys.encrypted_size - M19_NONCE_BYTES', 'keys.encrypted, keys.encrypted_size'),
    ('rdx.c', 'if (memcmp(actual, expected, sizeof(actual)))', 'if (0)'),
    ('rdx.c', 'if (!safe_name(name))', 'if (0)'),
    ('rdx.c', 'if (offset == 0 || offset > o)', 'if (offset == 0)'),
    ('rdx.c', 'if (skipped(name) || !strcmp(name, "."))', 'if (!strcmp(name, "."))'),
    ('rdx.c', 'if (!wanted.seen[i])', 'if (0)'),
    ('rdx.c', 'if (!rc_seen)', 'if (0)'),
    ('rdx.c', 'if (write_file(root, RC_PATH, rc, rc_size, 0644))', 'if (0)'),
    ('rdx.c', 'write_file(root, RECOVERY_MARKER, (const uint8_t *)"", 0, 0600)', 'write_file(root, RECOVERY_MARKER, (const uint8_t *)"X", 1, 0755)'),
    ('rdx.c', 'if (!ramdisk || start + ramdisk > image_size)', 'if (!ramdisk)'),
    ('hash.c', '0x5be0cd19137e2179ULL', '0x5be0cd19137e2178ULL'),
    ('hash.c', 'tail_size = rest < 56 ? 64 : 128', 'tail_size = rest < 55 ? 64 : 128'),
)


def run(command, directory):
    return subprocess.run(command, cwd=directory, capture_output=True, timeout=120)


def main():
    survivors = []
    flags = ['gcc', '-std=c11', '-O1', '-w']
    for number, (name, old, new) in enumerate(MUTANTS):
        source = (HERE / name).read_text(encoding='utf-8')
        if old not in source:
            sys.exit(f'mutant {number} does not apply to {name}: {old}')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'm19'
            target = root / 'unlock'
            target.mkdir(parents=True)
            for path in PARENT.glob('*.py'):
                shutil.copy(path, root)
            for path in HERE.iterdir():
                if path.suffix in ('.c', '.h', '.py'):
                    shutil.copy(path, target)
            (target / name).write_text(source.replace(old, new), encoding='utf-8')
            if run([*flags, 'core.c', 'hash.c', 'test-core.c', '-o', 'test-core'], target).returncode:
                sys.exit(f'mutant {number} does not compile')
            if run([*flags, 'hash.c', 'rdx.c', '-o', 'rdx'], target).returncode:
                sys.exit(f'mutant {number} does not compile')
            core = run(['./test-core'], target).returncode
            native = run([sys.executable, 'test-native.py', '--rdx', 'rdx', '--core', 'test-core'], target).returncode
        if not core and not native:
            survivors.append((number, name, old))
    print(f'{len(MUTANTS) - len(survivors)} of {len(MUTANTS)} native mutants killed')
    for survivor in survivors:
        print('SURVIVED', survivor)
    sys.exit(1 if survivors else 0)


if __name__ == '__main__':
    main()
