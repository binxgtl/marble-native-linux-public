#!/usr/bin/env python3
"""Mutation check for R2: every mutant of the hand-off, the reporter, T9, the plan or PID 1 must fail test.py."""
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
HANDOFF = ('Kthread', 'Sweep', 'Handoff')
MUTANTS = (
    ('handoff.c', 'if (left)\n        return fail(tty, h, "survivors", left);', 'if (0)\n        return fail(tty, h, "survivors", left);', HANDOFF),
    ('handoff.c', 'if (umount2(h->android, MNT_DETACH))', 'if (umount2(h->android, MNT_DETACH) && 0)', HANDOFF),
    ('handoff.c', 'parent.st_dev == root.st_dev', '0', HANDOFF),
    ('handoff.c', 'if (access(path, X_OK))', 'if (0 && access(path, X_OK))', HANDOFF),
    ('handoff.c', 'return !!(flags & PF_KTHREAD_FLAG);', 'return 0;', HANDOFF),
    ('handoff.c', 'if (kill_them)\n            (void)h->signal((pid_t)pid, SIGKILL);', '', HANDOFF),
    ('handoff.c', 'pid <= 1 || pid == (long)h->self', 'pid < 1 || pid == (long)h->self', HANDOFF),
    ('handoff.c', 'if (!(n < 0 && error == ESRCH))\n                count++;', '', HANDOFF),
    ('handoff.c', '(void)m19_wire_line(tty, h->pace_ms, M19_DEVICE_STEP " T10-handoff OK 0 0");', '', HANDOFF),
    ('handoff.c', 'mount(".", "/", NULL, MS_MOVE, NULL)', 'mount(".", "/", NULL, MS_BIND, NULL)', HANDOFF),
    ('handoff.c', '*moved = 1;', '', HANDOFF),
    ('report.c', 'int state_ok = !strcmp(state, "running") || !strcmp(state, "degraded");', 'int state_ok = 1;', ('Report',)),
    ('report.c', 'int init_ok = n > 0 && !strcmp(exe, c->expected_init);', 'int init_ok = 1;', ('Report',)),
    ('report.c', 'section(active, SECTION_CAP, c->command_ms) == 0;', 'section(active, SECTION_CAP, c->command_ms) >= 0;', ('Report',)),
    ('report.c', 'return count >= 7 && !field[4] && !field[6] && !field[11] && !field[13];', 'return count >= 7 && !field[4];', ('Report',)),
    ('report.c', 'if (!ro)\n        *ro_ok = 0;', '', ('Report',)),
    ('report.c', 'if (read_small(inner, flag, sizeof(flag)) || strcmp(flag, "1\\n")) {', 'if (0) {', ('Report',)),
    ('report.c', 'if (!disks) {', 'if (0) {', ('Report',)),
    ('report.c', 'if (!starts_ro(options) || !starts_ro(super)) {', 'if (!starts_ro(options)) {', ('Report',)),
    ('report.c', 'return ok && root && lines > 0;', 'return ok && lines > 0;', ('Report',)),
    ('report.c', 'int write_warning = memmem(', 'int write_warning = 0 && memmem(', ('Report',)),
    ('report.c', 'if (taken == limit)', 'if (0)', ('Report',)),
    ('report.c', 'all_ok ? GREEN : YELLOW', 'GREEN', ('Report',)),
    ('report.c', '"tmpfs", "proc"', '"f2fs", "tmpfs", "proc"', ('Report',)),
    ('t9-root', '$BB blockdev --setro "$node" || fail "set read-only $name"', ':', ('Script',)),
    ('t9-root', '[ "$($BB blockdev --getro "$node")" = 1 ] || fail "read-only check $name"', ':', ('Script',)),
    ('t9-root', '$BB mount -o remount,bind,ro "$new" || fail root-read-only', ':', ('Script',)),
    ('t9-root', 'case "$options" in ro|ro,*) ;; *) fail "root-read-only-check $options";; esac', ':', ('Script',)),
    ('t9-root', '  safe_dir "$at" || return 1', '  :', ('Script',)),
    ('t9-root', 'machine=uninitialized; : >"$new/etc/machine-id" || fail machine-id', 'machine=uninitialized', ('Script',)),
    ('t9-root', 'selinux=hidden; $BB rm -f "$new/etc/selinux/config" || fail selinux-config', 'selinux=hidden', ('Script',)),
    ('t9-root', '$BB ln -s m19-r2.target "$new/etc/systemd/system/default.target" || fail default-target', ':', ('Script',)),
    ('t9-root', '$BB ln -s /dev/null "$path" || fail "mask $unit"', ':', ('Script',)),
    ('t9-root', '$BB ln -s /dev/null "$path" || fail "mask generator $name"', ':', ('Script',)),
    ('t9-root', 'case "$class" in mem/*|tty/*|drm/*) ;; *) fail "node class $name";; esac', ':', ('Script',)),
    ('t9-root', '[ "${hash%% *}" = "$ROOTFS_PROBE_SHA256" ] || fail probe-hash', ':', ('Script',)),
    ('t9-root', '[ ! -e "$new" ] && [ ! -L "$new" ] || fail newroot-exists', ':', ('Script',)),
    ('t9-root', '$BB rm -f "$new/etc/crypttab" || fail crypttab', ':', ('Script',)),
    ('t9-root', '[ "$blocks" -gt 0 ] || fail no-block-device', ':', ('Script',)),
    ('t9-root', "[ -z \"$R\" ] || [ ! -L \"$R\" ] || fail root", ':', ('Script',)),
    ('r2plan.py', "'udisks2.service', ", '', ('Plan',)),
    ('r2plan.py', "('ttyGS0', 'tty/ttyGS0', '600'), ", "('ttyGS0', 'tty/ttyGS0', '600'), ('sg0', 'scsi_generic/sg0', '600'), ", ('Plan',)),
    ('r2plan.py', 'IgnoreOnIsolate=yes\n', '', ('Plan',)),
    ('r2plan.py', 'ReadKMsg=no\n', '', ('Plan',)),
    ('r2plan.py', "'systemd-fstab-generator', ", '', ('Plan',)),
    ('pid2.c', '{"T9-root", "/m19/t9-root", 120000, M19_STEP_REQUIRED},', '{"T9-root", "/m19/t9-root", 120000, 0},', ('Static',)),
    ('pid2.c', 'if (m19_run_main(&run) == M19_END_PASS) {', 'if (m19_run_main(&run) != M19_END_BOOTSTRAP) {', ('Static',)),
)


def main():
    survivors = []
    for number, (name, old, new, classes) in enumerate(MUTANTS):
        source = (HERE / name).read_text(encoding='utf-8')
        if old not in source:
            sys.exit(f'mutant {number} does not apply to {name}: {old}')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'm19'
            target = root / 'run2'
            (root / 'unlock').mkdir(parents=True)
            (root / 'run1').mkdir()
            shutil.copytree(HERE, target, ignore=shutil.ignore_patterns('__pycache__'))
            for path in HERE.parent.glob('*.py'):
                shutil.copy(path, root)
            for item in ('core.h', 'hash.c'):
                shutil.copy(HERE.parent / 'unlock' / item, root / 'unlock')
            for item in ('r1.h', 'pins'):
                shutil.copy(HERE.parent / 'run1' / item, root / 'run1')
            (target / name).write_text(source.replace(old, new), encoding='utf-8', newline='\n')
            built = subprocess.run(['gcc', '-std=c11', '-O1', '-w', '../unlock/hash.c', 'wire.c', 'handoff.c', 'report.c', 'test-r2.c',
                                    '-Wl,--wrap=umount2,--wrap=mount,--wrap=chroot,--wrap=chdir,--wrap=execve,--wrap=stat', '-o', 'driver'],
                                   cwd=target, capture_output=True, timeout=120)
            if built.returncode:
                sys.exit(f'mutant {number} does not compile')
            try:
                result = subprocess.run([sys.executable, 'test.py', '--driver', 'driver', *classes], cwd=target, capture_output=True, timeout=300)
                killed = result.returncode != 0
            except subprocess.TimeoutExpired:
                killed = True
        if not killed:
            survivors.append((number, name, old))
    print(f'{len(MUTANTS) - len(survivors)} of {len(MUTANTS)} R2 mutants killed')
    for survivor in survivors:
        print('SURVIVED', survivor)
    sys.exit(1 if survivors else 0)


if __name__ == '__main__':
    main()
