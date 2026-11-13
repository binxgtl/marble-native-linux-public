#!/usr/bin/env python3
"""Mutation check for R8's read-write steps: every mutant of scripts/m19/run8's steps must fail run8/test.py."""
import concurrent.futures
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent

MUTANTS = (
    # T2-unlock: the read-write table, and nothing else accepted.
    ('t2-unlock', '/m19/m19-unlock --rw', '/m19/m19-unlock'),
    ('t2-unlock', '"M19_UNLOCK status=OK "*" table=rw dev="*) exit 0;;', '"M19_UNLOCK status=OK "*) exit 0;;'),
    # T5-mount: read-write, no discard, checked.
    ('t5-mount', 'rw,noatime,nodiscard,inlinecrypt', 'rw,noatime,inlinecrypt'),
    ('t5-mount', 'case "$options" in rw|rw,*) ;; *) fail "read-write-check $options";; esac\n', ''),
    ('t5-mount', 'case "$line" in "M19_UNLOCK status=OK "*" table=rw dev="*) ;; *) fail table;; esac\n', ''),
    # T8-writes: the data path only, no discard.
    ('t8-writes', '  nodiscard\n else\n  zero\n fi\ndone\nseen=', '  :\n else\n  zero\n fi\ndone\nseen='),
    ('t8-writes', '[ "$name" = m19-userdata ]', '[ -n "$name" ]'),
    ('t8-writes', '[ "$dm" = 1 ]', '[ "$dm" -ge 0 ]'),
    ('t8-writes', '   [ "${part##*/}" = "$data" ] && continue\n', '   continue\n'),
    ('t8-writes', '  nodiscard\n  for part in', '  for part in'),
    ('t8-writes', '[ -z "$found" ] || { printf', 'false && { printf'),
    # T9-root: the data pair writable, the rest read-only; the root read-write; M19's files in RAM only.
    ('t9-root', '[ "$number" = "$data_number" ] || ', ''),
    ('t9-root', '[ "$writable" -eq 2 ]', '[ "$writable" -ge 1 ]'),
    ('t9-root', 'case "$options" in rw|rw,*) ;; *) fail "root-read-write-check $options";; esac\n', ''),
    ('t9-root', '! $BB grep -qx uninitialized "$new/etc/machine-id" || fail machine-id\n', ''),
    ('t9-root', '[ ! -e "$new/etc/selinux/config" ] && [ ! -L "$new/etc/selinux/config" ] || fail selinux-config\n', ''),
    ('t9-root', ' [ "$tmpfs" -gt 0 ] || [ "$point" = /run ] || fail "tmpfs order $point"\n', ''),
    ('t9-root', '  $BB cp -a "$src$point/." "$new$point/" || fail "copy $point"\n', ''),
    ('t9-root', '   [ ! -e "$twin" ] && [ ! -L "$twin" ] || fail "etc outranks $file";;', '   :;;'),
    ('t9-root', '   case "$ram" in *" /${file%/*} "*) ;; *) fail "etc file outside RAM $file";; esac;;', '   :;;'),
    ('t9-root', ' [ ! -e "$control/$unit" ] && [ ! -L "$control/$unit" ] || fail "mask over plan unit $unit"\n', ''),
    ('t9-root', ' [ ! -e "$new/etc/systemd/system-generators/$name" ] && [ ! -L "$new/etc/systemd/system-generators/$name" ] || '
                'fail "etc generator $name"\n', ''),
    ('t9-root', '[ -f "$control/$default_unit" ] && [ ! -L "$control/$default_unit" ] || fail "default target missing $default_unit"\n', ''),
    ('t9-root', 'control=$new/run/systemd/system.control', 'control=$new/etc/systemd/system'),
    ('t9-root', "$BB grep -q 'libsystemd-shared-255\\.so' \"$probe\" || fail probe-major", ':'),
    ('t9-root', '[ -f "$probe" ] && [ ! -L "$probe" ] && [ -x "$probe" ] || fail probe-read', '[ -f "$probe" ] || fail probe-read'),
    ('t9-root', '[ "${hash%% *}" != "$ROOTFS_PROBE_SHA256" ] || systemd=pinned', ':'),
    # T6-read: systemd 255, pinned or updated.
    ('t6-read', "$BB grep -q 'libsystemd-shared-255\\.so' \"$probe\" || fail probe-major", ':'),
    ('t6-read', '[ -f "$probe" ] && [ ! -L "$probe" ] && [ -x "$probe" ] || fail probe-read', '[ -e "$probe" ] || fail probe-read'),
    ('t6-read', '[ "${hash%% *}" != "$ROOTFS_PROBE_SHA256" ] || state=pinned', ':'),
    ('t6-read', '$BB grep -qx "VERSION_ID=\\"$ROOTFS_VERSION\\"" "$release" || fail os-release', ':'),
    ('t9-root', " case \"$kind\" in ''|empty|copy) ;; *) fail \"tmpfs kind $point\";; esac\n", ''),
    ('t9-root', '[ "$($BB blockdev --getro "$node")" = 1 ] || fail "read-only check $name"', ':'),
    # T9-desktop: /root as the home, the hidden entries in RAM.
    ('t9-desktop', 'autostart=$new/run/m19/xdg-config/autostart', 'autostart=$new/root/.config/autostart'),
    ('t9-desktop', 'safe_dir "$new/root" || fail home\n', ''),
    ('t9-desktop', '$BB mkdir -m 700 "$new/run/m19/session" "$new/run/m19/xdg"', '$BB mkdir -m 700 "$new/run/m19/xdg"'),
    # T9-ce: user 0's storage read-only at /media/Android.
    ('t9-ce', '$BB mount -o remount,bind,ro "$new/media/Android" || fail view-read-only\n', ''),
    ('t9-ce', 'case "$options" in ro|ro,*) ;; *) fail "view-read-only-check $options";; esac\n', ''),
    ('t9-ce', '$BB mount -o bind "$R/m19-data/media/0" "$new/media/Android"', '$BB mount -o bind "$R/m19-data/media" "$new/media/Android"'),
    ('t9-ce', '[ ! -e "$new/media/Android" ] && [ ! -L "$new/media/Android" ] || fail view-point', '[ ! -L "$new/media/Android" ] || fail view-point'),
    ('t9-ce', '$BB mkdir -m 0755 "$new/media/Android"', '$BB mkdir -m 0700 "$new/media/Android"'),
    ('t9-ce', '[ -d "$R/m19-data/media/0" ] && [ ! -L "$R/m19-data/media/0" ] || fail user0\n', ''),
)


def tree(base):
    """A copy of scripts/m19, so test.py finds the plan, pins and client sources it reads."""
    shutil.copytree(HERE.parent, base / 'm19', ignore=shutil.ignore_patterns('__pycache__'))
    return base / 'm19/run8'


def run(number, name, old, new):
    with tempfile.TemporaryDirectory() as directory:
        target = tree(Path(directory))
        path = target / name
        text = path.read_text()
        assert text.count(old) == 1, f'mutant {number} does not apply exactly once to {name}: {old!r}'
        path.write_text(text.replace(old, new))
        try:
            result = subprocess.run([sys.executable, str(target / 'test.py')], stdin=subprocess.DEVNULL, capture_output=True, timeout=600,
                                    start_new_session=True)
            return result.returncode != 0
        except subprocess.TimeoutExpired:
            return True


def main():
    with tempfile.TemporaryDirectory() as directory:
        target = tree(Path(directory))
        check = subprocess.run([sys.executable, str(target / 'test.py')], stdin=subprocess.DEVNULL, capture_output=True, timeout=600)
        if check.returncode:
            print(check.stdout.decode('utf-8', 'replace') + check.stderr.decode('utf-8', 'replace'))
            raise SystemExit('the unmutated tests fail')
    survivors = []
    with concurrent.futures.ThreadPoolExecutor(max(1, min(4, os.cpu_count() or 1))) as pool:
        futures = {pool.submit(run, number, name, old, new): (number, name, old) for number, (name, old, new) in enumerate(MUTANTS, 1)}
        for future in concurrent.futures.as_completed(futures):
            number, name, old = futures[future]
            if not future.result():
                survivors.append((number, name, old))
    for number, name, old in sorted(survivors):
        print(f'SURVIVED {number} {name}: {old!r}')
    print(f'R8 mutants killed: {len(MUTANTS) - len(survivors)} of {len(MUTANTS)}')
    return 1 if survivors else 0


if __name__ == '__main__':
    sys.exit(main())
