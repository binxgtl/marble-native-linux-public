#!/usr/bin/env python3
"""R8's read-write steps on synthetic trees (docs/m19-r8.md): T2-unlock, T5-mount, T8-writes, T9-root, T9-desktop and
T9-ce of scripts/m19/run8, with a fake busybox. No device, no real mount; nothing is written outside a temporary
directory."""
import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent / 'run2'))
import r8plan  # noqa: E402

FAKE_BB = r'''#!/bin/sh
echo "$*" >> "$M19_TEST/bb.log"
command=$1; shift
case "$command" in
 mount)
  case "$*" in *"${M19_FAIL_MOUNT:-@@}"*) exit 1;; esac
  case "$1" in
   -o) if [ "$2" = bind ]; then cp -a "$3/." "$4/"; fi;;
   -t) if [ "$2" = tmpfs ]; then eval "last=\${$#}"; find "$last" -mindepth 1 -delete; fi;;
  esac
  exit 0;;
 mknod) case "${M19_FAIL:-}" in mknod) exit 1;; esac; : > "$3"; exit 0;;
 blockdev) case "$1" in --getro) echo "${M19_GETRO:-1}";; esac; exit 0;;
 chroot) echo "${M19_UNLOCK_LINE:-}"; exit "${M19_UNLOCK_RC:-0}";;
 setsid) [ -z "${M19_NO_BROKER:-}" ] || exit 0
  exec python3 -c 'import socket, sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])' "$M19_SOCKET";;
 *) exec "$command" "$@";;
esac
'''
OK_LINE = 'M19_UNLOCK status=OK detail=0 upgraded=0 table=rw dev=254:5'
PROBE = b'\x7fELF systemd, NEEDED libsystemd-shared-255.so libsystemd-core-255.so, bytes'


class Fixture(unittest.TestCase):
    script = None

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name) / 'root'
        self.test = Path(self.directory.name) / 'test'
        self.test.mkdir()
        (self.test / 'bb').write_text(FAKE_BB)
        (self.test / 'bb').chmod(0o755)
        for name in ('m19', 'dev', 'run/m19', 'proc/self'):
            (self.root / name).mkdir(parents=True, exist_ok=True)
        self.mounts = {}

    @property
    def new(self):
        return self.root / 'newroot'

    def mount(self, point, options):
        self.mounts[str(point)] = options
        lines = ''.join(f'{30 + i} 25 254:5 /x {p} {o} - f2fs /dev/m19-dm rw\n' for i, (p, o) in enumerate(self.mounts.items()))
        (self.root / 'proc/self/mountinfo').write_text(lines)

    def run_script(self, **env):
        environment = dict(os.environ, M19_ROOT=str(self.root), M19_BB=str(self.test / 'bb'), M19_TEST=str(self.test), **env)
        return subprocess.run(['sh', str(HERE / self.script)], capture_output=True, text=True, env=environment, timeout=60)

    def bb_log(self):
        path = self.test / 'bb.log'
        return path.read_text() if path.exists() else ''


def block_tree(root, disks, dms, data='sda5'):
    """sysfs as the steps read it: /sys/block/<disk>/<part>, /sys/class/block/* links to each, dm/name and uevent. disks is
    {disk: (stat, {part: (partname, stat)})}, dms {dm: (name, stat)}."""
    numbers = iter(range(1, 1000))
    for disk, (stat, parts) in disks.items():
        base = root / 'sys/block' / disk
        base.mkdir(parents=True)
        (base / 'stat').write_text(stat)
        (base / 'dev').write_text(f'8:{next(numbers)}\n')
        (base / 'uevent').write_text(f'DEVNAME={disk}\nDEVTYPE=disk\n')
        (root / 'sys/class/block').mkdir(parents=True, exist_ok=True)
        os.symlink(f'../../block/{disk}', root / 'sys/class/block' / disk)
        for part, (partname, pstat) in parts.items():
            (base / part).mkdir()
            (base / part / 'stat').write_text(pstat)
            (base / part / 'dev').write_text(f'8:{next(numbers)}\n')
            (base / part / 'uevent').write_text(f'DEVNAME={part}\nDEVTYPE=partition\nPARTNAME={partname}\n')
            os.symlink(f'../../block/{disk}/{part}', root / 'sys/class/block' / part)
    for dm, (name, stat) in dms.items():
        base = root / 'sys/block' / dm
        (base / 'dm').mkdir(parents=True)
        (base / 'dm/name').write_text(name + '\n')
        (base / 'stat').write_text(stat)
        (base / 'dev').write_text('254:5\n' if name == 'm19-userdata' else f'254:{next(numbers)}\n')
        (base / 'uevent').write_text(f'DEVNAME={dm}\n')
        os.symlink(f'../../block/{dm}', root / 'sys/class/block' / dm)


def stat(writes=0, sectors=0, discards=0, discarded=0):
    values = ['3'] * 4 + ['0'] * 13
    values[4], values[6], values[11], values[13] = str(writes), str(sectors), str(discards), str(discarded)
    return ' '.join(values) + '\n'


class Unlock(Fixture):
    """T2-unlock: R1's client, its table read-write."""
    script = 't2-unlock'

    def setUp(self):
        super().setUp()
        (self.root / 'm19/pins').write_text('USERDATA_SECTORS=123456\n')
        (self.root / 'sys/class/misc/device-mapper').mkdir(parents=True)
        (self.root / 'sys/class/misc/device-mapper/dev').write_text('10:236\n')

    def test_the_read_write_table_passes_and_is_recorded(self):
        result = self.run_script(M19_UNLOCK_LINE=OK_LINE)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f'chroot {self.root}/tee /m19/m19-unlock --rw /metadata/vold/metadata_encryption/key m19-userdata /dev/m19-userdata 123456\n',
                      self.bb_log())
        self.assertEqual((self.root / 'run/m19/unlock.line').read_text(), OK_LINE + '\n')
        self.assertIn(f'M19 {OK_LINE}\n', result.stderr)

    def test_anything_else_fails(self):
        for line in ('M19_UNLOCK status=OK detail=0 upgraded=0 dev=254:5', 'M19_UNLOCK status=DECRYPT detail=1 upgraded=0 table=rw dev=0:0',
                     '', 'M19_UNLOCK status=OK detail=0 upgraded=0 table=ro dev=254:5'):
            with self.subTest(line=line):
                self.setUp()
                self.assertEqual(self.run_script(M19_UNLOCK_LINE=line).returncode, 1)


class Mount(Fixture):
    """T5-mount: /data read-write, checked in mountinfo."""
    script = 't5-mount'

    def setUp(self):
        super().setUp()
        (self.root / 'run/m19/unlock.line').write_text(OK_LINE + '\n')
        self.mount(self.root / 'm19-data', 'rw,noatime')

    def test_mounts_read_write_without_discard(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        log = self.bb_log()
        self.assertIn(f'mknod -m 600 {self.root}/dev/m19-dm b 254 5\n', log)
        self.assertIn(f'mount -t f2fs -o rw,noatime,nodiscard,inlinecrypt {self.root}/dev/m19-dm {self.root}/m19-data\n', log)
        self.assertNotIn('norecovery', log)
        self.assertIn('M19 T5 /data read-write\n', result.stderr)

    def assertFails(self, reason, **env):
        result = self.run_script(**env)
        self.assertEqual(result.returncode, 1)
        self.assertIn(f'M19 T5 failed: {reason}\n', result.stderr)

    def test_a_read_only_result_fails(self):
        self.mount(self.root / 'm19-data', 'ro,noatime')
        self.assertFails('read-write-check ro,noatime')

    def test_a_read_only_table_or_bad_number_fails(self):
        for line, reason in (('M19_UNLOCK status=OK detail=0 upgraded=0 dev=254:5', 'table'),
                             ('M19_UNLOCK status=OK detail=0 upgraded=0 table=rw dev=254:5:1', 'device-number'),
                             ('M19_UNLOCK status=OK detail=0 upgraded=0 table=rw dev=:5', 'device-number')):
            with self.subTest(line=line):
                (self.root / 'run/m19/unlock.line').write_text(line + '\n')
                self.assertFails(reason)
                self.assertNotIn('mount -t f2fs', self.bb_log())

    def test_a_failed_mount_fails(self):
        self.assertFails('mount', M19_FAIL_MOUNT='f2fs')


class Read(Fixture):
    """T6-read: os-release, and Ubuntu 24.04's systemd 255 as PID 1's init, pinned or updated."""
    script = 't6-read'

    def setUp(self):
        super().setUp()
        tree = self.root / 'm19-data/ubuntu'
        (tree / 'etc').mkdir(parents=True)
        (tree / 'usr/lib/systemd').mkdir(parents=True)
        (tree / 'etc/os-release').write_text('NAME="Ubuntu"\nVERSION_ID="24.04"\n')
        self.init = tree / 'usr/lib/systemd/systemd'
        self.init.write_bytes(PROBE)
        self.init.chmod(0o755)
        pins = (HERE.parent / 'run1/pins').read_text()
        pins = re.sub(r'ROOTFS_PROBE_SHA256=.*', 'ROOTFS_PROBE_SHA256=' + hashlib.sha256(PROBE).hexdigest(), pins)
        (self.root / 'm19/pins').write_text(pins)

    def test_pinned_and_updated_systemd_255_pass(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f'M19 T6 rootfs 24.04, systemd 255 pinned sha256={hashlib.sha256(PROBE).hexdigest()}\n', result.stderr)
        self.init.write_bytes(PROBE + b' patched')
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('systemd 255 updated', result.stderr)

    def test_anything_else_stops(self):
        for change, reason in (('major', 'probe-major'), ('mode', 'probe-read'), ('link', 'probe-read'), ('missing', 'probe-read'),
                               ('release', 'os-release')):
            with self.subTest(change=change):
                self.setUp()
                if change == 'major':
                    self.init.write_bytes(PROBE.replace(b'-255.so', b'-256.so'))
                elif change == 'mode':
                    self.init.chmod(0o644)
                elif change == 'link':
                    self.init.unlink()
                    (self.init.parent / 'systemd.real').write_bytes(PROBE)
                    (self.init.parent / 'systemd.real').chmod(0o755)
                    os.symlink('systemd.real', self.init)
                elif change == 'missing':
                    self.init.unlink()
                else:
                    (self.root / 'm19-data/ubuntu/etc/os-release').write_text('VERSION_ID="24.10"\n')
                result = self.run_script()
                self.assertEqual(result.returncode, 1)
                self.assertIn(f'M19 T6 failed: {reason}\n', result.stderr)


class Writes(Fixture):
    """T8-writes: writes only on the userdata partition, its disk and its dm device; no discard anywhere."""
    script = 't8-writes'

    def build(self, data=stat(7, 56), disk=stat(7, 56), other_part=stat(), metadata=stat(), dm=stat(7, 56), other_dm=stat(), sdb=stat(),
              dm_name='m19-userdata', persist=stat()):
        block_tree(self.root, {'sda': (disk, {'sda5': ('userdata', data), 'sda6': ('ssd', other_part), 'sda7': ('persist', persist)}),
                               'sdb': (sdb, {'sdb1': ('metadata', metadata), 'sdb2': ('recovery_a', stat())})},
                   {'dm-5': (dm_name, dm), 'dm-0': ('other', other_dm)})

    def test_writes_on_the_data_path_only_pass(self):
        self.build()
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('M19 T8 userdata writes=7 sectors=56 discards=0 discarded=0', result.stderr)
        self.assertIn('M19 T8 dm-5:m19-userdata writes=7', result.stderr)
        self.assertIn('M19 T8 sda6 writes=0', result.stderr)

    def test_any_other_write_or_a_discard_fails(self):
        for change, kwargs in (('metadata', {'metadata': stat(1, 8), 'sdb': stat(1, 8)}), ('ssd', {'other_part': stat(1, 8)}),
                               ('other disk', {'sdb': stat(1, 8)}), ('persist', {'persist': stat(1, 8)}), ('other dm', {'other_dm': stat(1, 8)}),
                               ('data discard', {'data': stat(7, 56, 1, 8)}), ('disk discard', {'disk': stat(7, 56, 1, 8)}),
                               ('dm discard', {'dm': stat(7, 56, 1, 8)}), ('no data dm', {'dm_name': 'other2', 'dm': stat()})):
            with self.subTest(change=change):
                self.setUp()
                self.build(**kwargs)
                self.assertEqual(self.run_script().returncode, 1, change)

    def test_a_missing_or_duplicate_partition_fails(self):
        block_tree(self.root, {'sda': (stat(), {'sda5': ('userdata', stat()), 'sda6': ('userdata', stat())}),
                               'sdb': (stat(), {'sdb1': ('metadata', stat()), 'sdb2': ('recovery_a', stat()), 'sdb3': ('ssd', stat())})},
                   {'dm-5': ('m19-userdata', stat())})
        result = self.run_script()
        self.assertEqual(result.returncode, 1)
        self.assertIn('M19 T8 duplicate partition userdata', result.stderr)
        shutil.rmtree(self.root / 'sys')
        block_tree(self.root, {'sda': (stat(), {'sda5': ('userdata', stat())})}, {'dm-5': ('m19-userdata', stat())})
        result = self.run_script()
        self.assertEqual(result.returncode, 1)
        self.assertIn('M19 T8 no partition metadata', result.stderr)


class Root(Fixture):
    """T9-root: the tree read-write as the root; M19's files only in RAM; every other block device read-only."""
    script = 't9-root'

    def setUp(self):
        super().setUp()
        tree = self.root / 'm19-data/ubuntu'
        probe = PROBE
        pins = (HERE.parent / 'run1/pins').read_text()
        pins = re.sub(r'ROOTFS_PROBE_SHA256=.*', 'ROOTFS_PROBE_SHA256=' + hashlib.sha256(probe).hexdigest(), pins)
        (self.root / 'm19/pins').write_text(pins)
        for name, data in r8plan.render().items():
            if name.startswith('m19/r8/'):
                path = self.root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
        for name in ('dev', 'proc', 'sys', 'run', 'tmp', 'media', 'root', 'usr/bin', 'usr/lib/systemd', 'var/tmp', 'var/log', 'var/cache',
                     'var/lib/systemd', 'var/lib/NetworkManager', 'var/lib/upower', 'etc/systemd/system/multi-user.target.wants',
                     'etc/NetworkManager/system-connections', 'etc/udev/rules.d', 'etc/pulse/default.pa.d', 'etc/systemd/journald.conf.d'):
            (tree / name).mkdir(parents=True, exist_ok=True)
        (tree / 'usr/lib/systemd/systemd').write_bytes(probe)
        (tree / 'usr/lib/systemd/systemd').chmod(0o755)
        for tool in ('systemctl', 'journalctl', 'systemd-analyze'):
            (tree / 'usr/bin' / tool).write_text('#!/bin/sh\n')
            (tree / 'usr/bin' / tool).chmod(0o755)
        (tree / 'etc/fstab').write_text('# comment\n/swap.img none swap sw 0 0\n')
        (tree / 'etc/machine-id').write_text('0123456789abcdef0123456789abcdef\n')
        (tree / 'etc/hostname').write_text('marble\n')
        (tree / 'etc/udev/rules.d/99-owner.rules').write_text('# the owner\'s\n')
        (tree / 'etc/systemd/journald.conf.d/owner.conf').write_text('[Journal]\n')
        (tree / 'etc/NetworkManager/system-connections/home.nmconnection').write_text('[wifi]\nssid=x\n')
        (tree / 'root/notes.txt').write_text('mine\n')
        os.symlink('/lib/systemd/system/graphical.target', tree / 'etc/systemd/system/default.target')
        os.symlink('/lib/systemd/system/lightdm.service', tree / 'etc/systemd/system/display-manager.service')
        os.symlink('/lib/systemd/system/ssh.service', tree / 'etc/systemd/system/multi-user.target.wants/ssh.service')
        for name in ('sbin/m19-pid1', 'sbin/m16-display'):
            (self.root / name).parent.mkdir(parents=True, exist_ok=True)
            (self.root / name).write_text('elf\n')
        (self.root / 'run/m19/unlock.line').write_text(OK_LINE + '\n')
        block_tree(self.root, {'sda': (stat(), {'sda5': ('userdata', stat()), 'sda6': ('ssd', stat())}), 'sdb': (stat(), {'sdb1': ('metadata', stat())})},
                   {'dm-5': ('m19-userdata', stat()), 'dm-0': ('other', stat())})
        for line in (self.root / 'm19/r8/nodes').read_text().splitlines():
            name, kind, _ = line.split()
            entry = self.root / 'sys/class' / kind
            entry.mkdir(parents=True, exist_ok=True)
            (entry / 'dev').write_text('5:1\n')
        self.mount(self.new, 'rw,noatime')

    def tmpfs(self):
        return [line.split() for line in (self.root / 'm19/r8/tmpfs').read_text().splitlines()]

    def test_builds_the_read_write_root(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        log = self.bb_log()
        for name in ('sda6', 'sdb', 'sdb1', 'dm-0'):
            self.assertIn(f'blockdev --setro {self.root}/dev/m19-ro-{name}\n', log)
        # R8b: the data disk keeps its flag, or the kernel counts its partitions read-only too.
        for name in ('sda', 'sda5', 'dm-5'):
            self.assertNotIn(f'm19-ro-{name}', log)
        self.assertIn(f'mount -o bind {self.root}/m19-data/ubuntu {self.new}\n', log)
        self.assertNotIn(f'remount,bind,ro {self.new}\n', log)
        points = [f[0] for f in self.tmpfs()]
        self.assertEqual(points[0], '/run')
        for fields in self.tmpfs():
            self.assertIn(f'mount -t tmpfs -o mode={fields[1]},nosuid,nodev,size={fields[2]} tmpfs {self.new}{fields[0]}\n', log)
        self.assertLess(log.index(f'tmpfs {self.new}/run\n'), log.index(f'tmpfs {self.new}/tmp\n'))
        self.assertIn('M19 T9 new root: read-write blocks-read-only=4 writable=3 machine-id=present fstab-lines=1 selinux-config=absent '
                      'default-was=/lib/systemd/system/graphical.target systemd=pinned\n', result.stderr)
        files = (self.root / 'm19/r8/files').read_text().split()
        self.assertIn(f'M19 T9 masks={len((self.root / "m19/r8/masks").read_text().split())} '
                      f'generators={len((self.root / "m19/r8/generators").read_text().split())} files={len(files)} tmpfs={len(points)} copied=2 ',
                      result.stderr)
        self.assertIn(' etc-masked-generators=0\n',
                      result.stderr)
        self.assertIn('multi-user wants: ssh.service', result.stderr)

    def test_m19_files_are_in_ram_where_they_outrank_the_tree(self):
        self.assertEqual(self.run_script().returncode, 0)
        control = self.new / 'run/systemd/system.control'
        self.assertEqual(os.readlink(control / 'default.target'), 'm19-r8.target')
        for unit in (self.root / 'm19/r8/masks').read_text().split():
            self.assertEqual(os.readlink(control / unit), '/dev/null', unit)
        for name in (self.root / 'm19/r8/generators').read_text().split():
            self.assertEqual(os.readlink(self.new / 'run/systemd/system-generators' / name), '/dev/null', name)
        for where in (self.root / 'm19/r8/files').read_text().split():
            self.assertEqual((self.new / where).read_bytes(), (self.root / 'm19/r8/root' / where).read_bytes(), where)
        self.assertIn('PrivateUsers=no', (control / 'upower.service.d/m19.conf').read_text())
        # The RAM copies keep the tree's files; the connections start empty.
        self.assertEqual((self.new / 'etc/udev/rules.d/99-owner.rules').read_text(), "# the owner's\n")
        self.assertTrue((self.new / 'etc/udev/rules.d/70-m19-usb-input.rules').exists())
        self.assertEqual(list((self.new / 'etc/NetworkManager/system-connections').iterdir()), [])
        self.assertEqual((self.new / 'run/m19/m19-report').read_text(), 'elf\n')

    def test_everything_m19_changed_is_under_a_ram_mount(self):
        self.assertEqual(self.run_script().returncode, 0)
        tree = self.root / 'm19-data/ubuntu'
        ram = [Path(fields[0][1:]) for fields in self.tmpfs()] + [Path('dev'), Path('proc'), Path('sys')]

        def snapshot(base):
            out = {}
            for path in base.rglob('*'):
                rel = path.relative_to(base)
                out[rel] = (path.is_symlink() and os.readlink(path), path.is_file() and not path.is_symlink() and path.read_bytes())
            return out
        before, after = snapshot(tree), snapshot(self.new)
        changed = {rel for rel in set(before) | set(after) if before.get(rel) != after.get(rel)}
        outside = sorted(str(rel) for rel in changed if not any(rel == point or point in rel.parents for point in ram))
        self.assertEqual(outside, [])
        self.assertEqual((self.new / 'root/notes.txt').read_text(), 'mine\n')

    def assertFails(self, reason, **env):
        result = self.run_script(**env)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(f'M19 T9 failed: {reason}\n', result.stderr)
        return result

    def test_a_root_that_is_not_read_write_stops(self):
        self.mount(self.new, 'ro,noatime')
        self.assertFails('root-read-write-check ro,noatime')
        self.assertNotIn('tmpfs', self.bb_log())

    def test_first_boot_or_selinux_states_stop(self):
        for change, reason in (('missing', 'machine-id'), ('empty', 'machine-id'), ('uninitialized', 'machine-id'), ('link', 'machine-id'),
                               ('selinux', 'selinux-config')):
            with self.subTest(change=change):
                self.setUp()
                etc = self.root / 'm19-data/ubuntu/etc'
                if change == 'missing':
                    (etc / 'machine-id').unlink()
                elif change == 'empty':
                    (etc / 'machine-id').write_text('')
                elif change == 'uninitialized':
                    (etc / 'machine-id').write_text('uninitialized\n')
                elif change == 'link':
                    (etc / 'machine-id').unlink()
                    os.symlink('/run/machine-id', etc / 'machine-id')
                else:
                    (etc / 'selinux').mkdir()
                    (etc / 'selinux/config').write_text('SELINUX=enforcing\n')
                self.assertFails(reason)
                self.assertNotIn('tmpfs', self.bb_log())

    def test_a_namesake_in_the_trees_etc_stops(self):
        etc = self.root / 'm19-data/ubuntu/etc'
        (etc / 'systemd/journald.conf.d/m19-r2.conf').write_text('[Journal]\nStorage=persistent\n')
        self.assertFails('etc outranks run/systemd/journald.conf.d/m19-r2.conf')
        self.setUp()
        (self.root / 'm19-data/ubuntu/etc/systemd/system-generators').mkdir(parents=True)
        name = (self.root / 'm19/r8/generators').read_text().split()[0]
        (self.root / f'm19-data/ubuntu/etc/systemd/system-generators/{name}').write_text('#!/bin/sh\n')
        self.assertFails(f'etc generator {name}')

    def test_the_trees_own_generator_mask_passes(self):
        # R8a: the tree has systemd-gpt-auto-generator -> /dev/null; a link anywhere else still stops.
        generators = self.root / 'm19-data/ubuntu/etc/systemd/system-generators'
        generators.mkdir(parents=True)
        os.symlink('/dev/null', generators / 'systemd-gpt-auto-generator')
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(' etc-masked-generators=1\n', result.stderr)
        self.assertEqual(os.readlink(self.new / 'run/systemd/system-generators/systemd-gpt-auto-generator'), '/dev/null')
        self.setUp()
        generators = self.root / 'm19-data/ubuntu/etc/systemd/system-generators'
        generators.mkdir(parents=True)
        os.symlink('/usr/lib/systemd/system-generators/systemd-gpt-auto-generator', generators / 'systemd-gpt-auto-generator')
        self.assertFails('etc generator systemd-gpt-auto-generator')

    def test_the_writable_devices_must_be_the_data_pair(self):
        (self.root / 'run/m19/unlock.line').write_text(OK_LINE.replace('254:5', '254:9') + '\n')
        self.assertFails('writable devices sda sda5')
        self.setUp()
        (self.root / 'run/m19/unlock.line').write_text(OK_LINE.replace(' table=rw', '') + '\n')
        self.assertFails('unlock-table')
        self.setUp()
        (self.root / 'sys/block/sda/sda6/uevent').write_text('PARTNAME=userdata\n')
        self.assertFails('data-partitions')

    def test_read_only_that_did_not_take_stops(self):
        self.assertFails('read-only check dm-0', M19_GETRO='0')
        self.assertNotIn(f'mount -o bind', self.bb_log())

    def test_bad_plan_lines_stop(self):
        for name, text, reason in (('tmpfs', '/tmp 1777 512m\n/run 0755 256m\n', 'tmpfs order /tmp'), ('tmpfs', '/run 0755 256m rw\n', 'tmpfs kind /run'),
                                   ('tmpfs', '/run 0755 256m\n/media 0755 1m\n/etc/hosts.d 0755 1m copy\n', 'mount point /etc/hosts.d'),
                                   ('files', 'etc/hostname\n', 'etc file outside RAM etc/hostname'), ('files', 'usr/bin/x\n', 'plan file usr/bin/x'),
                                   ('files', 'run/../etc/passwd\n', 'plan file run/../etc/passwd'),
                                   ('masks', 'm19-r8.target\n', 'mask over plan unit m19-r8.target'),
                                   ('default', 'graphical.target\n', 'default target graphical.target'),
                                   ('default', 'm19-r9.target\n', 'default target missing m19-r9.target')):
            with self.subTest(name=name, text=text):
                self.setUp()
                (self.root / 'm19/r8' / name).write_text(text)
                self.assertFails(reason)

    def test_a_linked_copy_source_stops(self):
        tree = self.root / 'm19-data/ubuntu'
        shutil.rmtree(tree / 'etc/udev/rules.d')
        (self.root / 'elsewhere').mkdir()
        os.symlink(self.root / 'elsewhere', tree / 'etc/udev/rules.d')
        self.assertFails('mount point /etc/udev/rules.d')

    def test_an_updated_systemd_255_boots_and_another_major_stops(self):
        init = self.root / 'm19-data/ubuntu/usr/lib/systemd/systemd'
        init.write_bytes(PROBE.replace(b'bytes', b'newer bytes'))
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(' systemd=updated\n', result.stderr)
        for data, mode, reason in ((b'\x7fELF libsystemd-shared-256.so', 0o755, 'probe-major'), (PROBE, 0o644, 'probe-read')):
            with self.subTest(reason=reason):
                self.setUp()
                init = self.root / 'm19-data/ubuntu/usr/lib/systemd/systemd'
                init.write_bytes(data)
                init.chmod(mode)
                self.assertFails(reason)

    def test_an_existing_new_root_stops(self):
        self.new.mkdir()
        self.assertFails('newroot-exists')


class Desktop(Fixture):
    """T9-desktop: R3's display and touch, the tree's /root as home, the hidden entries in RAM."""
    script = 't9-desktop'

    def setUp(self):
        super().setUp()
        (self.root / 'm19/m19-xorg-shim.so').write_bytes(b'\x7fELF shim')
        for name, data in r8plan.render().items():
            if name.startswith('m19/r3/'):
                path = self.root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
        for name in ('run/m19', 'dev', 'root'):
            (self.new / name).mkdir(parents=True, exist_ok=True)
        (self.new / 'root/notes.txt').write_text('mine\n')
        for tool in ('usr/lib/xorg/Xorg', 'usr/lib/xorg/modules/drivers/modesetting_drv.so', 'usr/lib/xorg/modules/input/libinput_drv.so',
                     'usr/bin/startxfce4', 'usr/bin/dbus-run-session', 'usr/bin/xfwm4', 'usr/bin/xfce4-panel', 'usr/bin/xfdesktop',
                     'usr/bin/xdpyinfo', 'usr/bin/xrandr', 'usr/bin/xinput', 'usr/bin/ps'):
            (self.new / tool).parent.mkdir(parents=True, exist_ok=True)
            (self.new / tool).write_text('x\n')
        panel = self.root / 'sys/class/drm/card0-DSI-1'
        panel.mkdir(parents=True)
        (panel / 'status').write_text('connected\n')
        (panel / 'modes').write_text('1080x2400x60vid\n1080x2400x120vid\n1080x2400x90vid\n')
        for name, device, number in (('event0', 'pmic_pwrkey', '13:64'), ('event7', 'goodix_ts', '13:71')):
            entry = self.root / 'sys/class/input' / name
            (entry / 'device').mkdir(parents=True)
            (entry / 'device/name').write_text(device + '\n')
            (entry / 'dev').write_text(number + '\n')

    def test_home_is_root_and_hidden_entries_are_in_ram(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        autostart = self.new / 'run/m19/xdg-config/autostart'
        hidden = sorted(path.name for path in autostart.iterdir())
        self.assertEqual(hidden, sorted(f'{name}.desktop' for name in r8plan.HIDDEN))
        self.assertNotIn('xfce4-power-manager.desktop', hidden)
        self.assertEqual((autostart / 'light-locker.desktop').read_text(), '[Desktop Entry]\nHidden=true\n')
        self.assertEqual([path.name for path in (self.new / 'root').iterdir()], ['notes.txt'])
        for name in ('session', 'xdg'):
            self.assertEqual((self.new / 'run/m19' / name).stat().st_mode & 0o777, 0o700)
        self.assertIn(f'M19 T9 desktop: touch=goodix_ts node=event7 home=/root hidden={len(r8plan.HIDDEN)}\n', result.stderr)
        self.assertIn(f'mknod -m 600 {self.new}/dev/input/event7 c 13 71', self.bb_log())

    def test_a_missing_home_stops(self):
        shutil.rmtree(self.new / 'root')
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('M19 T9 desktop failed: home\n', result.stderr)


class Ce(Fixture):
    """T9-ce: R7's broker and media view, and user 0's storage read-only at /media/Android."""
    script = 't9-ce'

    def setUp(self):
        super().setUp()
        for name in ('m19-data/media/0/DCIM', 'tee/tmp/m19', 'tee/m19', 'newroot/run/m19', 'newroot/media'):
            (self.root / name).mkdir(parents=True, exist_ok=True)
        (self.root / 'm19/m19-ce-prompt').write_text('elf\n')
        self.mount(self.new / 'run/m19/android', 'ro,nosuid')
        self.mount(self.new / 'media/Android', 'ro,nosuid')
        self.socket = self.new / 'run/m19/ce/ce.sock'

    def test_the_view_is_read_only_beside_the_broker(self):
        result = self.run_script(M19_SOCKET=str(self.socket))
        self.assertEqual(result.returncode, 0, result.stderr)
        log = self.bb_log()
        self.assertIn(f'mount -o bind {self.root}/m19-data/media/0 {self.new}/media/Android\n', log)
        self.assertIn(f'mount -o remount,bind,ro {self.new}/media/Android\n', log)
        self.assertIn(f'mount -o remount,bind,ro {self.new}/run/m19/android\n', log)
        self.assertTrue((self.new / 'media/Android/DCIM').is_dir())
        self.assertIn('M19 T9-ce broker listening, media read-only, view /media/Android\n', result.stderr)

    def test_a_writable_view_or_a_bad_point_stops(self):
        self.mount(self.new / 'media/Android', 'rw,nosuid')
        result = self.run_script(M19_SOCKET=str(self.socket))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('M19 T9-ce failed: view-read-only-check rw,nosuid\n', result.stderr)
        for change, reason in (('existing', 'view-point'), ('no-media', 'view-point'), ('no-user0', 'user0')):
            with self.subTest(change=change):
                self.setUp()
                if change == 'existing':
                    (self.new / 'media/Android').mkdir()
                elif change == 'no-media':
                    (self.new / 'media').rmdir()
                else:
                    shutil.rmtree(self.root / 'm19-data/media/0')
                result = self.run_script(M19_SOCKET=str(self.socket))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f'M19 T9-ce failed: {reason}\n', result.stderr)
                self.assertNotIn('setsid', self.bb_log())


class SystemdPaths(unittest.TestCase):
    """The runner's systemd (255 on Ubuntu 24.04, the tree's release) on a fake root: what T9-root puts in
    /run/systemd/system.control outranks the tree's /etc, for a mask over an alias, for the default target, and for a
    unit file; the tree's own unit and links are untouched."""

    def setUp(self):
        if not shutil.which('systemctl'):
            self.skipTest('no systemctl on this host')
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        lib = self.root / 'usr/lib/systemd/system'
        etc = self.root / 'etc/systemd/system'
        control = self.root / 'run/systemd/system.control'
        for path in (lib, etc, control):
            path.mkdir(parents=True)
        (lib / 'lightdm.service').write_text('[Service]\nExecStart=/usr/sbin/lightdm\n')
        (lib / 'graphical.target').write_text('[Unit]\nDescription=Graphical\n')
        os.symlink('/usr/lib/systemd/system/lightdm.service', etc / 'display-manager.service')
        os.symlink('/usr/lib/systemd/system/graphical.target', etc / 'default.target')
        (etc / 'marble-xfce.service').write_text('[Service]\nExecStart=/bin/false\n')
        os.symlink('/dev/null', control / 'display-manager.service')
        (control / 'm19-r8.target').write_text('[Unit]\nDescription=M19 R8\n')
        os.symlink('m19-r8.target', control / 'default.target')
        (control / 'marble-xfce.service').write_text('[Service]\nExecStart=/bin/true\n[Install]\nWantedBy=multi-user.target\n')

    def systemctl(self, *args):
        return subprocess.run(['systemctl', f'--root={self.root}', *args], capture_output=True, text=True, timeout=60)

    def test_control_outranks_the_trees_etc(self):
        state = self.systemctl('is-enabled', 'display-manager.service').stdout.strip()
        self.assertTrue(state.startswith('masked'), state)
        self.assertEqual(self.systemctl('get-default').stdout.strip(), 'm19-r8.target')
        # The tree's file has no [Install] (static); only M19's, in control, has one (disabled): control's is the one read.
        self.assertEqual(self.systemctl('is-enabled', 'marble-xfce.service').stdout.strip(), 'disabled')
        # Found, with no [Install] of its own; default.target's link makes it an alias's target.
        self.assertIn(self.systemctl('is-enabled', 'm19-r8.target').stdout.strip(), ('static', 'indirect'))
        self.assertEqual(os.readlink(self.root / 'etc/systemd/system/display-manager.service'), '/usr/lib/systemd/system/lightdm.service')

    def test_the_search_path_puts_control_before_etc(self):
        paths = subprocess.run(['systemd-analyze', 'unit-paths'], capture_output=True, text=True, timeout=60).stdout.split()
        self.assertLess(paths.index('/run/systemd/system.control'), paths.index('/etc/systemd/system'))


class Static(unittest.TestCase):
    """What only run8's steps say, and what they must not."""

    def test_each_step_starts_as_busybox_and_is_executable(self):
        for name in ('t2-unlock', 't5-mount', 't6-read', 't8-writes', 't9-root', 't9-desktop', 't9-ce'):
            data = (HERE / name).read_bytes()
            self.assertTrue(data.startswith(b'#!/bin/busybox sh\n') and b'\r' not in data, name)
            self.assertTrue(os.access(HERE / name, os.X_OK), name)

    def test_nothing_writes_the_owner_storage_or_the_trees_etc(self):
        root = (HERE / 't9-root').read_text()
        self.assertNotIn('rm -f "$new/etc', root)
        self.assertNotIn('>"$new/etc', root)
        for name in ('t9-root', 't9-desktop', 't9-ce'):
            self.assertNotRegex((HERE / name).read_text(), r'mount -o bind[^\n]*media[^\n]*\n(?![^\n]*remount,bind,ro)', name)

    def test_the_client_keeps_a_read_only_table_by_default(self):
        dm = (HERE.parent / 'unlock/dm.c').read_text()
        self.assertIn('return load(context, name, sectors, target, parameters, DM_READONLY_FLAG);', dm)
        self.assertIn('const struct m19_dm_ops m19_dm_real_ops = {device_sectors, device_create, device_load, device_resume, device_remove};', dm)
        main = (HERE.parent / 'unlock/main.cpp').read_text()
        self.assertIn('const int rw = argc == 6 && !std::strcmp(argv[1], "--rw");', main)
        self.assertIn('rw ? &m19_dm_real_rw_ops : &m19_dm_real_ops', main)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('names', nargs='*')
    args = parser.parse_args()
    program = unittest.main(argv=['test', *args.names], exit=False, verbosity=1)
    result = program.result
    print(f'R8 steps tests: {result.testsRun} run, {len(result.failures)} failures, {len(result.errors)} errors')
    sys.exit(0 if result.wasSuccessful() else 1)


if __name__ == '__main__':
    main()
