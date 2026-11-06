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
    ('t9-root', '$BB ln -s "$default_unit" "$new/etc/systemd/system/default.target" || fail default-target', ':', ('Script',)),
    ('t9-root', 'case "$default_unit" in m19-r[0-9].target) ;; *) fail "default target $default_unit";; esac', ':', ('Script',)),
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
    ('pid2.c', 'if (m19_run_main(&run) == M19_END_PASS) {', 'if (m19_run_main(&run) != M19_END_BOOTSTRAP) {', ('Static',)),    ('report.c', 'd->mode_ok = d->xrandr_hz > c->want_hz - 1.0 && d->xrandr_hz < c->want_hz + 1.0;', 'd->mode_ok = 1;', ('Desktop',)),
    ('report.c', 'd->vblank_ok = d->crtc >= 0 && d->vblank_hz > c->want_hz * 0.96 && d->vblank_hz < c->want_hz * 1.04;', 'd->vblank_ok = d->crtc >= 0;', ('Desktop',)),
    ('report.c', 'd->touch_ok = d->touch_device && d->irq_delta > 0 && d->events > 0;', 'd->touch_ok = d->touch_device && d->events > 0;', ('Desktop',)),
    ('report.c', 'd->touch_ok = d->touch_device && d->irq_delta > 0 && d->events > 0;', 'd->touch_ok = d->irq_delta > 0 && d->events > 0;', ('Desktop',)),
    ('report.c', 'd->touch_ok = d->touch_device && d->irq_delta > 0 && d->events > 0;', 'd->touch_ok = d->touch_device && d->irq_delta > 0;', ('Desktop',)),
    ('report.c', 'desktop_ok = d.x_ok && d.session_ok && d.mode_ok && d.vblank_ok && d.touch_ok && guard_ok;', 'desktop_ok = d.x_ok;', ('Desktop',)),
    ('report.c', 'if (c->desktop && d.x_ok)\n        return 0;', '', ('Desktop',)),
    ('report.c', "|| line[n - name - 1] != ' ')", '|| 0)', ('Desktop',)),
    ('report.c', 'return seen[0] && seen[1] && seen[2];', 'return seen[0];', ('Desktop',)),
    ('report.c', "if (*end == '*') {", 'if (1) {', ('Desktop',)),
    ('t9-desktop', '$BB grep -qx "$mode" "$panel/modes" || fail "panel mode $mode"', ':', ('DesktopScript',)),
    ('t9-desktop', '[ -z "$found" ] || fail "touch duplicate"', ':', ('DesktopScript',)),
    ('t9-desktop', '[ "$($BB cat "$panel/status")" = connected ] || fail panel-status', ':', ('DesktopScript',)),
    ('t9-desktop', 'safe_dir "$src/root" && safe_dir "$src/root/.config" && safe_dir "$src/root/.config/xfce4" || fail xfce-settings', ':', ('DesktopScript',)),
    ('t9-desktop', '$BB chmod 700 "$home" || fail home', ':', ('DesktopScript',)),
    ('t9-desktop', 'Hidden=true', 'Hidden=false', ('DesktopScript',)),
    ('t9-desktop', '  $BB rm -f "$path" || fail "prune $path"', '  :', ('DesktopScript',)),
    ('t9-desktop', 'for kind in l p s c b; do', 'for kind in p s c b; do', ('DesktopScript',)),
    ('t9-desktop', 'case "$touch" in \'\'|*[!a-z0-9_]*) fail "touch name $touch";; esac', ':', ('DesktopScript',)),
    ('t9-desktop', 'safe_dir "$new/run/m19" && safe_dir "$new/dev" || fail newroot', ':', ('DesktopScript',)),
    ('r3plan.py', "'light-locker', ", '', ('Plan3',)),
    ('r3plan.py', "'poweroff.target', ", '', ('Plan3',)),
    ('r3plan.py', "lines.append('OnFailure=marble-xorg-fallback.service')", 'pass', ('Plan3',)),
    ('r3plan.py', 'TimeoutStartSec=150\n', '', ('Plan3',)),
    ('r3plan.py', 'i=$$((i+1)); [ "$$i" -lt 600 ]', 'i=$((i+1)); [ "$i" -lt 600 ]', ('Plan3',)),
    ('pid3.c', '{"T9-desktop", "/m19/t9-desktop", 60000, M19_STEP_REQUIRED},', '', ('Static',)),
    ('report.c', 'if (battery != LONG_MIN && battery >= g->battery_limit)', 'if (0)', ('Guard',)),
    ('report.c', 'else if (zone != LONG_MIN && zone >= g->zone_limit)', 'else if (0)', ('Guard',)),
    ('report.c', 'else if (busy_since && now - busy_since >= g->busy_ms)', 'else if (0)', ('Guard',)),
    ('report.c', 'else if (now - start >= g->session_ms)', 'else if (0)', ('Guard',)),
    ('report.c', 'int status = capture(stop, out, sizeof(out), &taken, g->command_ms);', 'int status = 0;', ('Guard',)),
    ('report.c', 'if (status)\n                (void)capture(kill_units', 'if (0)\n                (void)capture(kill_units', ('Guard',)),
    ('report.c', 'execv(g->display, argv);\n            return 70;', 'return 70;', ('Guard',)),
    ('report.c', '*busy = sum - field[3] - field[4]; /* idle and iowait */', '*busy = 0;', ('Guard',)),
    ('report.c', 'if (read_long(path, &value) || value <= -40000 || value >= 200000)', 'if (read_long(path, &value))', ('Guard',)),
    ('report.c', 'int guard_ok = guard_active && !tripped;', 'int guard_ok = 1;', ('Desktop',)),
    ('r3plan.py', 'm19-r3-guard.service marble-xorg.service', 'marble-xorg.service', ('Plan3',)),
    ('pid3.c', '.battery_limit = 420', '.battery_limit = 4200', ('Static',)),
    ('r3plan.py', ', \'    Option "Monitor-Virtual-1" "writeback"\'', '', ('Plan3',)),
    ('r3plan.py', ', \'    Option "Ignore" "true"\'', '', ('Plan3',)),
    ('t9-desktop', ' printf off >"$R/sys/class/drm/$writeback/status" || fail writeback-off', ' :', ('DesktopScript',)),
    ('t9-desktop', ' [ "$($BB cat "$R/sys/class/drm/$writeback/status")" = disconnected ] || fail writeback-still-connected', ' :', ('DesktopScript',)),
    ('t9-desktop', 'case "$writeback" in card0-Virtual-[0-9]) ;; *) fail "writeback name $writeback";; esac', ':', ('DesktopScript',)),
    ('r3plan.py', ', \'    Option "NoTrapSignals" "true"\'', '', ('Plan3',)),
    ('r3plan.py', "'LimitCORE=0', ", '', ('Plan3',)),
    ('r3plan.py', "              'sysctl.d/m19-r3.conf': SYSCTL,\n", '', ('Plan3',)),
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
                                    '-Wl,--wrap=umount2,--wrap=mount,--wrap=chroot,--wrap=chdir,--wrap=execve,--wrap=stat,--wrap=ioctl', '-o', 'driver'],
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
