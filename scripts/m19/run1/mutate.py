#!/usr/bin/env python3
"""Mutation check for R1: every mutant of the PID 1 or of a T script must fail test.py."""
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
MUTANTS = (
    ('r1.c', 'if (bring_up_link(r)) {', 'if (bring_up_link(r) && 0) {'),
    ('r1.c', 'if (rc || status)\n        return M19_END_BOOTSTRAP;', ''),
    ('r1.c', 'if ((stopped || r->link_lost) && !(step->flags & M19_STEP_ALWAYS))', 'if (r->link_lost)'),
    ('r1.c', 'if ((stopped || r->link_lost) && !(step->flags & M19_STEP_ALWAYS))', 'if (stopped || r->link_lost)'),
    ('r1.c', 'if (run_step(r, i) && (step->flags & M19_STEP_REQUIRED)) {', 'if (run_step(r, i)) {'),
    ('r1.c', 'if (run_step(r, i) && (step->flags & M19_STEP_REQUIRED)) {', 'if (run_step(r, i) && 0) {'),
    ('r1.c', 'rc = status ? -1 : 0;', 'rc = 0;'),
    ('r1.c', 'if (now >= end) {\n            rc = -ETIMEDOUT;', 'if (0) {\n            rc = -ETIMEDOUT;'),
    ('r1.c', 'if (memmem(log_bytes + kernel, size - kernel,', 'if (memmem(log_bytes, 0,'),
    ('r1.c', 'if (strcmp(r->line, "CONNECTOR_READY"))', 'if (0)'),
    ('r1.c', 'if (got && !strcmp(r->line, M19_HOST_HELLO))', 'if (got)'),
    ('r1.c', 'paint(r, r->all_ok ? GREEN : YELLOW, r->final_ms)', 'paint(r, GREEN, r->final_ms)'),
    ('r1.c', 'if (!rc)\n        rc = send_paced(r, log_bytes, size, end);', ''),
    ('t0-extract', '[ "$($BB blockdev --getro "$R/dev/m19-$1")" = 1 ] || fail "read-only check $1"', ':'),
    ('t0-extract', '$BB blockdev --setro "$R/dev/m19-$1" || fail "set read-only $1"', ':'),
    ('t0-extract', 'read_only_node ssd ssd', ':'),
    ('t1-start', 'ro,noload', 'ro'),
    ('t1-start', 'bs="$size" count=1', 'bs=512'),
    ('t1-start', 'wait_marker listeners', ':'),
    ('t2-unlock', '"M19_UNLOCK status=OK "*) exit 0;;', '"M19_UNLOCK status="*) exit 0;;'),
    ('t2-unlock', 'exit 1;;', 'exit 0;;'),
    ('t5-mount', 'ro,noatime,norecovery,inlinecrypt', 'ro,noatime,inlinecrypt'),
    ('t5-mount', '*[!0-9:]*|:*|*:|\'\') fail device-number;;', 'zz) fail device-number;;'),
    ('t6-read', '[ "${hash%% *}" = "$ROOTFS_PROBE_SHA256" ] || fail probe-hash', ':'),
    ('t6-read', '|| fail os-release', '|| :'),
    ('t7-overlay', 'upperdir=$base/upper', 'upperdir=$R/m19-data/upper'),
    ('t8-writes', '[ "$writes" = 0 ] && [ "$sectors" = 0 ] && [ "$discards" = 0 ] && [ "$discarded" = 0 ] || fail=1', '[ "$writes" = 0 ] || fail=1'),
    ('t8-writes', 'for name in userdata metadata recovery_a ssd; do', 'for name in metadata; do'),
)


def main():
    survivors = []
    for number, (name, old, new) in enumerate(MUTANTS):
        source = (HERE / name).read_text(encoding='utf-8')
        if old not in source:
            sys.exit(f'mutant {number} does not apply to {name}: {old}')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'm19'
            target = root / 'run1'
            (root / 'unlock').mkdir(parents=True)
            shutil.copytree(HERE, target, ignore=shutil.ignore_patterns('__pycache__'))
            for path in HERE.parent.glob('*.py'):
                shutil.copy(path, root)
            for item in ('core.h', 'hash.c'):
                shutil.copy(HERE.parent / 'unlock' / item, root / 'unlock')
            (target / name).write_text(source.replace(old, new), encoding='utf-8')
            built = subprocess.run(['gcc', '-std=c11', '-O1', '-w', '../unlock/hash.c', 'r1.c', 'test-r1.c', '-o', 'driver'], cwd=target, capture_output=True, timeout=120)
            if built.returncode:
                sys.exit(f'mutant {number} does not compile')
            result = subprocess.run([sys.executable, 'test.py', '--driver', 'driver'], cwd=target, capture_output=True, timeout=300)
        if result.returncode == 0:
            survivors.append((number, name, old))
    print(f'{len(MUTANTS) - len(survivors)} of {len(MUTANTS)} R1 mutants killed')
    for survivor in survivors:
        print('SURVIVED', survivor)
    sys.exit(1 if survivors else 0)


if __name__ == '__main__':
    main()
