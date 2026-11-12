#!/usr/bin/env python3
"""Mutation check for R1: every mutant of the PID 1 or of a T script must fail test.py."""
import concurrent.futures
import os
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
    ('r1.c', 'if (cancel && kill(-pid, SIGKILL) && errno != ESRCH)', 'if (0 && kill(-pid, SIGKILL) && errno != ESRCH)'),
    ('r1.c', 'if (r->ownership_unresolved) {', 'if (0) {'),
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
    ('t6-read', '"$release" || fail os-release\n', '"$release" || :\n'),
    ('t6-read', 'release=$root/etc/os-release', 'release=$root/usr/lib/os-release'),
    ('t6-read', "case \"$R\" in ''|/*) ;; *) fail root;; esac", "[ -n \"$R\" ] || fail root"),
    ('t6-read', '[ -z "$R" ] || [ ! -L "$R" ] || fail root', ':'),
    ('t6-read', '../usr/lib/os-release|/usr/lib/os-release) ;;', '*) ;;'),
    ('t6-read', '[ ! -L "$release" ] && [ -f "$release" ] || fail os-release-target', ':'),
    ('t6-read', 'safe_dir "$root/etc" || fail os-release-parent', ':'),
    ('t7-overlay', 'upperdir=$base/upper', 'upperdir=$R/m19-data/upper'),
    ('t8-writes', '[ "$writes" = 0 ] && [ "$sectors" = 0 ] && [ "$discards" = 0 ] && [ "$discarded" = 0 ] || fail=1', '[ "$writes" = 0 ] || fail=1'),
    ('t8-writes', 'for name in userdata metadata recovery_a ssd; do', 'for name in metadata; do'),
    ('t8-writes', '[ "$5" = 0 ] && [ "$7" = 0 ] && [ "${12:-0}" = 0 ] && [ "${14:-0}" = 0 ] || fail=1', '[ "$5" = 0 ] || fail=1'),
    ('t8-writes', '[ -n "$seen" ] || { printf \'M19 T8 no disk\\n\' >&2; fail=1; }', ':'),
    ('t0-extract', '"ro.vendor.build.security_patch=$VENDOR_PATCH"', '"ro.vendor.build.security_patch=$SYSTEM_PATCH"'),
)


class Broken(Exception):
    """A mutant that does not apply or does not build: the check itself is wrong."""


def run(number, name, old, new, fixed_objs, base_drv):
    source = (HERE / name).read_text(encoding='utf-8')
    if old not in source:
        raise Broken(f'mutant {number} does not apply to {name}: {old}')
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory) / 'm19'
        target = root / 'run1'
        (root / 'unlock').mkdir(parents=True)
        shutil.copytree(HERE, target, ignore=shutil.ignore_patterns('__pycache__'))
        for path in HERE.parent.glob('*.py'):
            shutil.copy(path, root)
        for item in ('core.h', 'hash.c'):
            shutil.copy(HERE.parent / 'unlock' / item, root / 'unlock')
        (target / name).write_text(source.replace(old, new), encoding='utf-8', newline='\n')
        drv_path = str(base_drv)
        if name == 'r1.c':
            built = subprocess.run(
                ['gcc', '-std=c11', '-O1', '-w', 'r1.c', *fixed_objs, '-Wl,--wrap=waitpid', '-o', 'driver'],
                cwd=target, capture_output=True, timeout=120)
            if built.returncode:
                raise Broken(f'mutant {number} does not compile:\n{built.stderr.decode("utf-8", "replace")}')
            drv_path = 'driver'
        # Only the classes that exercise the mutated file: the pty bench is the slow part and
        # sees no T script. Static runs for both and costs nothing.
        classes = ('Run', 'Static') if name == 'r1.c' else ('Scripts', 'Static')
        try:
            result = subprocess.run(
                [sys.executable, 'test.py', '--failfast', '--driver', drv_path, *classes],
                cwd=target, stdin=subprocess.DEVNULL, capture_output=True, timeout=180, start_new_session=True)
            return result.returncode != 0
        except subprocess.TimeoutExpired:
            return True


def main():
    for number, (name, old, _) in enumerate(MUTANTS):
        source = (HERE / name).read_text(encoding='utf-8')
        if old not in source:
            sys.exit(f'mutant {number} does not apply to {name}: {old}')
    with tempfile.TemporaryDirectory() as obj_tmp:
        obj_dir = Path(obj_tmp)
        os.chmod(obj_dir, 0o755)
        hash_o = obj_dir / 'hash.o'
        test_o = obj_dir / 'test-r1.o'
        base_drv = obj_dir / 'base-driver'
        for cmd in (
            ['gcc', '-std=c11', '-O1', '-w', '-c', str(HERE.parent / 'unlock/hash.c'), '-o', str(hash_o)],
            ['gcc', '-std=c11', '-O1', '-w', f'-I{HERE}', '-c', str(HERE / 'test-r1.c'), '-o', str(test_o)],
            ['gcc', '-std=c11', '-O1', '-w', f'-I{HERE}', str(HERE / 'r1.c'), str(hash_o), str(test_o), '-Wl,--wrap=waitpid', '-o', str(base_drv)],
        ):
            built = subprocess.run(cmd, capture_output=True, timeout=120)
            if built.returncode:
                sys.exit(f'baseline compile failed:\n{built.stderr.decode("utf-8", "replace")}')
        baseline = subprocess.run(
            [sys.executable, str(HERE / 'test.py'), '--failfast', '--driver', str(base_drv)],
            cwd=HERE, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=180, start_new_session=True)
        if baseline.returncode != 0:
            sys.exit(f'baseline test.py failed (rc={baseline.returncode}):\n{baseline.stdout}{baseline.stderr}')
        fixed_objs = (str(hash_o), str(test_o))
        workers = max(1, min(8, (os.cpu_count() or 1) * 2))
        killed = [False] * len(MUTANTS)
        with concurrent.futures.ThreadPoolExecutor(workers) as pool:
            future_to_num = {pool.submit(run, number, *mutant, fixed_objs, base_drv): number for number, mutant in enumerate(MUTANTS)}
            done = 0
            try:
                for future in concurrent.futures.as_completed(future_to_num):
                    number = future_to_num[future]
                    dead = future.result()
                    killed[number] = dead
                    done += 1
                    print(f'[{done}/{len(MUTANTS)}] mutant {number} ({MUTANTS[number][0]}) {"killed" if dead else "SURVIVED"}', flush=True)
            except Broken as error:
                for future in future_to_num:
                    future.cancel()
                sys.exit(str(error))
    survivors = [(number, name, old) for number, ((name, old, _), dead) in enumerate(zip(MUTANTS, killed)) if not dead]
    print(f'{len(MUTANTS) - len(survivors)} of {len(MUTANTS)} R1 mutants killed, {workers} at a time')
    for survivor in survivors:
        print('SURVIVED', survivor)
    sys.exit(1 if survivors else 0)


if __name__ == '__main__':
    main()
