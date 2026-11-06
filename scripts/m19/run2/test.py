#!/usr/bin/env python3
"""R2 on synthetic trees: the hand-off, the reporter, T9 and the plan. No device, no real mount."""
import argparse
import hashlib
import os
import re
import select
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
import r2plan  # noqa: E402
import r3plan  # noqa: E402
import rootfs  # noqa: E402

ARGS = None
GREEN, YELLOW = '0000ff00', '00ffff00'
KTHREAD = 0x00200000


def stat_line(pid, comm, flags):
    return f'{pid} ({comm}) S 2 0 0 0 -1 {flags} 0 0 0 0 0 0 0 0 20 0 1 0 5 0 0 18446744073709551615 0 0 0 0 0 0 0 2147483647 0 0 0 0 17 0 0 0 0 0 0\n'


class Wire:
    """A pty standing in for the USB serial line."""

    def __init__(self):
        import pty
        import tty
        self.master, self.slave = pty.openpty()
        tty.setraw(self.slave)
        self.path = os.ttyname(self.slave)
        self.buffer, self.stop = bytearray(), threading.Event()
        self.thread = threading.Thread(target=self.read)
        self.thread.start()

    def read(self):
        while not self.stop.is_set():
            ready, _, _ = select.select([self.master], [], [], 0.02)
            if ready:
                try:
                    self.buffer.extend(os.read(self.master, 65536))
                except OSError:
                    return

    def close(self):
        time.sleep(0.1)
        self.stop.set()
        self.thread.join()
        os.close(self.master)
        os.close(self.slave)
        return bytes(self.buffer)


def fake_proc(root, entries):
    proc = Path(root) / 'proc'
    proc.mkdir(parents=True, exist_ok=True)
    for pid, (comm, flags) in entries.items():
        (proc / str(pid)).mkdir()
        (proc / str(pid) / 'stat').write_text(stat_line(pid, comm, flags))
    (proc / 'self').mkdir(exist_ok=True)
    (proc / 'sys').mkdir(exist_ok=True)
    return proc


class Kthread(unittest.TestCase):
    def test_flags_after_the_last_parenthesis(self):
        lines = [stat_line(2, 'kthreadd', KTHREAD), stat_line(77, 'qseecomd', 4194560), stat_line(9, 'a) S 1 1 (b', KTHREAD | 0x40),
                 stat_line(10, 'x y', 0), 'garbage\n', '5 (short) S 1\n']
        done = subprocess.run([ARGS.driver, 'kthread'], input=''.join(lines), capture_output=True, text=True, timeout=10)
        self.assertEqual(done.stdout.split(), ['1', '0', '1', '0', '-1', '-1'])


class Sweep(unittest.TestCase):
    def run_sweep(self, entries, kill, self_pid=99999):
        with tempfile.TemporaryDirectory() as directory:
            proc = fake_proc(directory, entries)
            done = subprocess.run([ARGS.driver, 'sweep', str(proc), str(self_pid), str(kill)], capture_output=True, text=True, timeout=10)
            return done.stdout

    def test_counts_and_kills_user_processes_only(self):
        out = self.run_sweep({1: ('init', 0), 2: ('kthreadd', KTHREAD), 300: ('init', 4194560), 301: ('qseecomd', 0),
                              302: ('kworker/0:1', KTHREAD), 303: ('m16-display', 0)}, 1)
        self.assertIn('count 3', out)
        self.assertEqual(sorted(re.findall(r'signal (\d+) 9', out)), ['300', '301', '303'])

    def test_counting_alone_signals_nothing(self):
        out = self.run_sweep({300: ('init', 0)}, 0)
        self.assertIn('count 1', out)
        self.assertNotIn('signal', out)

    def test_self_and_pid_1_are_never_signalled(self):
        out = self.run_sweep({1: ('systemd', 0), 4242: ('pid1', 0), 5: ('x', 0)}, 1, self_pid=4242)
        self.assertEqual(re.findall(r'signal (\d+)', out), ['5'])

    def test_an_unreadable_entry_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            proc = fake_proc(directory, {})
            (proc / '700').mkdir()
            (proc / '700' / 'stat').mkdir()  # read fails with EISDIR
            done = subprocess.run([ARGS.driver, 'sweep', str(proc), '99999', '1'], capture_output=True, text=True, timeout=10)
            self.assertIn('count 1', done.stdout)


class Handoff(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.proc = fake_proc(self.root, {2: ('kthreadd', KTHREAD), 300: ('init', 0), 301: ('qseecomd', 0)})
        self.newroot = self.root / 'newroot'
        init = self.newroot / 'usr/lib/systemd/systemd'
        init.parent.mkdir(parents=True)
        init.write_text('#!/bin/sh\n')
        init.chmod(0o755)
        (self.root / 'kmsg').write_text('')

    def run_handoff(self, fail=None):
        wire = Wire()
        env = dict(os.environ, ASAN_OPTIONS='detect_leaks=0')
        if fail:
            env['M19_FAIL'] = fail
        record = self.root / 'record'
        done = subprocess.run([ARGS.driver, 'handoff', str(self.proc), str(self.newroot), str(self.root / 'tee'), str(self.root / 'kmsg'), wire.path,
                               str(record)], capture_output=True, text=True, timeout=30, env=env)
        lines = [line for line in wire.close().decode().split('\n') if line.startswith('M19STEP')]
        calls = record.read_text().splitlines() if record.exists() else []
        return done.returncode, lines, calls

    def test_order_kill_detach_move_chroot_exec(self):
        rc, lines, calls = self.run_handoff()
        self.assertEqual(rc, 0)
        self.assertEqual(lines, ['M19STEP T10-handoff START', 'M19STEP T10-handoff OK 0 0'])
        actions = [call.split()[0] for call in calls if not call.startswith(('argv', 'envp'))]
        self.assertEqual(actions, ['signal', 'signal', 'umount2', 'chdir', 'mount', 'chroot', 'chdir', 'execve', 'exec-done'])
        self.assertIn(f'umount2 {self.root}/tee 2', calls)  # MNT_DETACH
        self.assertIn('mount . / - 8192', calls)  # MS_MOVE
        self.assertIn('chroot .', calls)
        self.assertEqual([call for call in calls if call.startswith('argv')], ['argv /usr/lib/systemd/systemd'])
        self.assertIn('envp PATH=/usr/sbin:/usr/bin:/sbin:/bin', calls)
        self.assertNotIn('signal 2 9', calls)

    def test_survivors_stop_before_any_mount(self):
        rc, lines, calls = self.run_handoff('survivor')
        self.assertEqual(lines[-1], 'M19STEP T10-handoff FAIL survivors 2')
        self.assertFalse([call for call in calls if call.startswith(('umount2', 'mount', 'chroot', 'execve'))])
        self.assertIn('returned -1 moved 0', calls)

    def test_detach_failure_stops_before_the_move(self):
        rc, lines, calls = self.run_handoff('umount2')
        self.assertEqual(lines[-1], f'M19STEP T10-handoff FAIL android-detach {16}')
        self.assertFalse([call for call in calls if call.startswith(('mount ', 'chroot', 'execve'))])

    def test_a_new_root_that_is_not_a_mount_stops(self):
        rc, lines, calls = self.run_handoff('newroot')
        self.assertTrue(lines[-1].startswith('M19STEP T10-handoff FAIL newroot-not-mounted'))
        self.assertFalse([call for call in calls if call.startswith(('mount ', 'chroot', 'execve'))])

    def test_a_missing_init_stops(self):
        (self.newroot / 'usr/lib/systemd/systemd').unlink()
        rc, lines, calls = self.run_handoff()
        self.assertTrue(lines[-1].startswith('M19STEP T10-handoff FAIL init'))
        self.assertFalse([call for call in calls if call.startswith(('mount ', 'chroot', 'execve'))])

    def test_a_failed_move_reports_and_has_not_moved(self):
        rc, lines, calls = self.run_handoff('mount')
        self.assertTrue(lines[-1].startswith('M19STEP T10-handoff FAIL move'))
        self.assertIn('returned -1 moved 0', calls)

    def test_a_failed_chroot_reports_moved(self):
        rc, lines, calls = self.run_handoff('chroot')
        self.assertTrue(lines[-1].startswith('M19STEP T10-handoff FAIL chroot'))
        self.assertIn('returned -1 moved 1', calls)

    def test_a_failed_exec_reports_after_ok(self):
        rc, lines, calls = self.run_handoff('execve')
        self.assertEqual(lines[-2:], ['M19STEP T10-handoff OK 0 0', 'M19STEP T10-handoff FAIL exec 2'])
        self.assertIn('returned -1 moved 1', calls)


SYSTEMCTL = '''#!/bin/sh
case "$1" in
 is-system-running) cat "$(dirname "$0")/state"; exit 0;;
 is-active) echo active; echo active; exit "${M19_ACTIVE_RC:-0}";;
 --failed) echo "foo.service loaded failed failed Foo";;
 list-jobs) ;;
 --version) echo "systemd 255 (255.4-1ubuntu8)";;
 list-units) echo "m19-r2.target loaded active active M19";;
esac
exit 0
'''
JOURNAL = '#!/bin/sh\necho "[    1.000000] host systemd[1]: journal line"\n'
ANALYZE = '#!/bin/sh\necho "Startup finished"\n'
DISPLAY = '#!/bin/sh\necho "$1 $2" > "$(dirname "$0")/colour"\nexit 0\n'
MOUNTINFO = ('22 1 254:0 /ubuntu / ro,noatime - f2fs /dev/m19-dm ro,lazytime\n'
             '23 22 0:5 / /dev rw,nosuid - tmpfs tmpfs rw,mode=755\n'
             '24 22 0:22 / /proc rw - proc proc rw\n'
             '25 22 0:30 / /etc rw,nosuid,nodev - tmpfs tmpfs rw\n'
             '26 22 0:31 / /sys/fs/cgroup rw shared:4 - cgroup2 cgroup2 rw\n')


class ReportBase(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.test = self.root / 'test'
        self.test.mkdir()
        for name, text in (('systemctl', SYSTEMCTL), ('journalctl', JOURNAL), ('analyze', ANALYZE), ('display', DISPLAY)):
            (self.test / name).write_text(text)
            (self.test / name).chmod(0o755)
        (self.test / 'state').write_text('running\n')
        (self.test / 'kmsg').write_text('<6>kernel line\n')
        os.symlink('/usr/lib/systemd/systemd', self.root / 'proc1-exe')
        (self.root / 'mountinfo').write_text(MOUNTINFO)
        for name, parts in (('sda', ('sda1', 'sda33')), ('sdb', ('sdb1',)), ('dm-0', ())):
            disk = self.root / 'block' / name
            disk.mkdir(parents=True)
            (disk / 'stat').write_text(' '.join(['5'] * 4 + ['0'] * 13) + '\n')
            (disk / 'ro').write_text('1\n')
            for part in parts:
                (disk / part).mkdir()
                (disk / part / 'ro').write_text('1\n')
        (self.root / 'block' / 'loop0').mkdir()
        (self.root / 'block' / 'loop0' / 'stat').write_text(' '.join(['9'] * 17) + '\n')
        (self.root / 'block' / 'loop0' / 'ro').write_text('0\n')

    def run_report(self, settle_ms=300, command_ms=5000, env=None):
        wire = Wire()
        environment = dict(os.environ, ASAN_OPTIONS='detect_leaks=0', **(env or {}))
        subprocess.run([ARGS.driver, 'report', str(self.root), wire.path, str(settle_ms), str(command_ms)], capture_output=True, timeout=60,
                       env=environment)
        data = wire.close()
        colour = (self.test / 'colour').read_text().split()[0] if (self.test / 'colour').exists() else None
        return data, colour

    def parse(self, data):
        at = data.index(b'M19LOG1 ')
        end = data.index(b'\n', at)
        fields = data[at:end].decode().split()
        log = data[end + 1:end + 1 + int(fields[1])]
        self.assertEqual(len(log), int(fields[1]))
        self.assertEqual(hashlib.sha256(log).hexdigest(), fields[2])
        steps = [line.decode() for line in data[:at].split(b'\n') if line.startswith((b'M19STEP', b'M19BEAT'))]
        return fields, log.decode(errors='replace'), steps

    def verdict(self, log):
        return dict(item.split('=') for item in re.search(r'M19 R2 verdict (.*)\n', log).group(1).split())

    def counter(self, name, index):
        values = ['0'] * 17
        values[index] = '1'
        (self.root / 'block' / name / 'stat').write_text(' '.join(values) + '\n')


class Report(ReportBase):
    def test_pass_running(self):
        data, colour = self.run_report()
        fields, log, steps = self.parse(data)
        self.assertEqual(fields[3:], ['1', '0'])
        self.assertEqual((steps[0], steps[-1]), ('M19STEP T11-systemd START', 'M19STEP T11-systemd OK 0 0'))
        self.assertEqual(colour, GREEN)
        self.assertIn('M19 R2 state running', log)
        self.assertIn('M19 R2 pid1 /usr/lib/systemd/systemd', log)
        for text in ('is-active basic.target multi-user.target', '--failed', 'list-jobs', 'blame', 'journal line', 'kernel line', 'M19 mountinfo'):
            self.assertIn(text, log)

    def test_degraded_still_passes(self):
        (self.test / 'state').write_text('degraded\n')
        fields, log, _ = self.parse(self.run_report()[0])
        self.assertEqual(fields[3], '1')

    def test_maintenance_fails(self):
        (self.test / 'state').write_text('maintenance\n')
        data, colour = self.run_report()
        fields, log, steps = self.parse(data)
        self.assertEqual((fields[3], colour, steps[-1]), ('0', YELLOW, 'M19STEP T11-systemd FAIL -1 0'))

    def test_a_boot_that_never_settles_fails_after_beats(self):
        (self.test / 'state').write_text('starting\n')
        data, colour = self.run_report(settle_ms=400)
        fields, log, steps = self.parse(data)
        self.assertEqual(fields[3], '0')
        self.assertTrue(any(line.startswith('M19BEAT T11-systemd') and line.endswith('starting') for line in steps))

    def test_garbage_state_is_not_running(self):
        (self.test / 'state').write_text('running; rm -rf\n')
        fields, log, _ = self.parse(self.run_report(settle_ms=100)[0])
        self.assertEqual(self.verdict(log)['state'], 'invalid')
        self.assertEqual(fields[3], '0')

    def test_wrong_pid1_fails(self):
        (self.root / 'proc1-exe').unlink()
        os.symlink('/sbin/m19-pid1', self.root / 'proc1-exe')
        fields, log, _ = self.parse(self.run_report()[0])
        self.assertEqual((fields[3], self.verdict(log)['init']), ('0', '0'))

    def test_inactive_targets_fail(self):
        fields, log, _ = self.parse(self.run_report(env={'M19_ACTIVE_RC': '3'})[0])
        self.assertEqual((fields[3], self.verdict(log)['targets']), ('0', '0'))

    def test_any_write_or_discard_counter_fails(self):
        for name, index in (('sda', 4), ('sdb', 6), ('dm-0', 11), ('sda', 13)):
            with self.subTest(name=name, index=index):
                self.setUp()
                self.counter(name, index)
                fields, log, _ = self.parse(self.run_report()[0])
                self.assertEqual((fields[3], self.verdict(log)['writes']), ('0', '0'))

    def test_reads_and_loop_devices_do_not_count(self):
        fields, log, _ = self.parse(self.run_report()[0])
        self.assertEqual(fields[3], '1')
        self.assertNotIn('loop0', log)

    def test_a_writable_disk_or_partition_fails(self):
        for path in ('sda/ro', 'sda/sda33/ro', 'dm-0/ro'):
            with self.subTest(path=path):
                self.setUp()
                (self.root / 'block' / path).write_text('0\n')
                fields, log, _ = self.parse(self.run_report()[0])
                self.assertEqual((fields[3], self.verdict(log)['read_only']), ('0', '0'))

    def test_no_disk_fails(self):
        for name in ('sda', 'sdb'):
            shutil.rmtree(self.root / 'block' / name)
        fields, log, _ = self.parse(self.run_report()[0])
        self.assertEqual((fields[3], self.verdict(log)['writes']), ('0', '0'))

    def test_writable_storage_mounts_fail(self):
        for line in ('30 22 254:0 /ubuntu /mnt rw - f2fs /dev/m19-dm ro\n', '31 22 8:17 / /metadata ro - ext4 /dev/sda17 rw\n',
                     '32 22 0:40 / /run/user/0/doc rw - fuse.portal portal rw\n'):
            with self.subTest(line=line):
                (self.root / 'mountinfo').write_text(MOUNTINFO + line)
                fields, log, _ = self.parse(self.run_report()[0])
                self.assertEqual((fields[3], self.verdict(log)['mounts']), ('0', '0'))

    def test_root_must_be_the_read_only_f2fs_bind(self):
        for root in ('22 1 0:44 / / rw - tmpfs tmpfs rw\n', '22 1 254:0 /ubuntu / rw - f2fs /dev/m19-dm ro\n'):
            with self.subTest(root=root):
                (self.root / 'mountinfo').write_text(root + MOUNTINFO.split('\n', 1)[1])
                fields, log, _ = self.parse(self.run_report()[0])
                self.assertEqual(self.verdict(log)['mounts'], '0')

    def test_write_warning_in_kernel_log_fails(self):
        (self.test / 'kmsg').write_text('<4>Trying to write to read-only block-device sda33\n')
        fields, log, _ = self.parse(self.run_report()[0])
        self.assertEqual(fields[3:], ['0', '1'])

    def test_warning_text_in_the_journal_alone_is_not_a_kernel_finding(self):
        (self.test / 'journalctl').write_text('#!/bin/sh\necho "Trying to write to read-only block-device"\n')
        fields, log, _ = self.parse(self.run_report()[0])
        self.assertEqual(fields[3:], ['1', '0'])

    def test_a_hung_command_is_killed_and_the_report_still_goes(self):
        (self.test / 'analyze').write_text('#!/bin/sh\nexec sleep 30\n')
        start = time.monotonic()
        data, colour = self.run_report(command_ms=300)
        fields, log, _ = self.parse(data)
        self.assertLess(time.monotonic() - start, 20)
        self.assertIn('M19 status -1', log)

    def test_a_huge_journal_is_truncated(self):
        (self.test / 'journalctl').write_text('#!/bin/sh\nhead -c 3000000 /dev/zero | tr "\\0" a\n')
        fields, log, _ = self.parse(self.run_report()[0])
        self.assertIn('M19 output truncated at', log)
        self.assertLessEqual(int(fields[1]), 1536 * 1024)


FAKE_BB = '''#!/bin/sh
echo "$*" >> "$M19_TEST/bb.log"
command=$1; shift
case "$command" in
 mount)
  case "${M19_FAIL:-}" in mount) exit 1;; esac
  case "$*" in *"${M19_FAIL_MOUNT:-@@}"*) exit 1;; esac
  case "$1" in
   -o) if [ "$2" = bind ]; then cp -a "$3/." "$4/"; fi;;
   -t) if [ "$2" = tmpfs ]; then eval "last=\\${$#}"; find "$last" -mindepth 1 -delete; fi;;
  esac
  exit 0;;
 mknod)
  case "${M19_FAIL:-}" in mknod) exit 1;; esac
  : > "$3"; exit 0;;
 blockdev)
  case "$1" in --getro) echo "${M19_GETRO:-1}";; esac
  exit 0;;
 *) exec "$command" "$@";;
esac
'''


class Script(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name) / 'root'
        self.test = Path(self.directory.name) / 'test'
        self.test.mkdir()
        (self.test / 'bb').write_text(FAKE_BB)
        (self.test / 'bb').chmod(0o755)
        tree = self.root / 'm19-data/ubuntu'
        probe = b'systemd bytes'
        pins = (HERE.parent / 'run1/pins').read_text()
        pins = re.sub(r'ROOTFS_PROBE_SHA256=.*', 'ROOTFS_PROBE_SHA256=' + hashlib.sha256(probe).hexdigest(), pins)
        (self.root / 'm19').mkdir(parents=True)
        (self.root / 'dev').mkdir()
        (self.root / 'm19/pins').write_text(pins)
        for name, data in r2plan.render().items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        for name in ('dev', 'sbin', 'proc/self', 'etc/systemd/system/multi-user.target.wants', 'etc/selinux', 'usr/bin', 'usr/lib/systemd', 'run', 'tmp',
                     'var/tmp', 'var/log', 'var/cache', 'var/spool', 'var/lib/systemd', 'var/lib/NetworkManager', 'var/lib/upower', 'proc', 'sys'):
            (tree / name).mkdir(parents=True, exist_ok=True)
        (tree / 'usr/lib/systemd/systemd').write_bytes(probe)
        for tool in ('systemctl', 'journalctl', 'systemd-analyze'):
            (tree / 'usr/bin' / tool).write_text('#!/bin/sh\n')
            (tree / 'usr/bin' / tool).chmod(0o755)
        (tree / 'etc/fstab').write_text('# comment\n\nUUID=x / ext4 defaults 0 1\n/swap.img none swap sw 0 0\n')
        (tree / 'etc/machine-id').write_text('0123456789abcdef0123456789abcdef\n')
        (tree / 'etc/selinux/config').write_text('SELINUX=disabled\n')
        (tree / 'etc/crypttab').write_text('x\n')
        (tree / 'etc/hostname').write_text('marble\n')
        os.symlink('/lib/systemd/system/graphical.target', tree / 'etc/systemd/system/default.target')
        os.symlink('/lib/systemd/system/lightdm.service', tree / 'etc/systemd/system/display-manager.service')
        os.symlink('/lib/systemd/system/ssh.service', tree / 'etc/systemd/system/multi-user.target.wants/ssh.service')
        for name in ('sbin/m19-pid1', 'sbin/m16-display'):
            (self.root / name).parent.mkdir(parents=True, exist_ok=True)
            (self.root / name).write_text('elf\n')
        for name, number in (('sda', '8:0'), ('sda33', '8:33'), ('dm-0', '254:0')):
            entry = self.root / 'sys/class/block' / name
            entry.mkdir(parents=True)
            (entry / 'dev').write_text(number + '\n')
        for name, kind, _ in r2plan.NODES:
            entry = self.root / 'sys/class' / kind
            entry.mkdir(parents=True)
            (entry / 'dev').write_text('5:1\n')
        self.mountinfo('ro,noatime')

    def mountinfo(self, options):
        (self.root / 'proc/self').mkdir(parents=True, exist_ok=True)
        (self.root / 'proc/self/mountinfo').write_text(f'36 25 254:0 /ubuntu {self.root}/newroot {options} - f2fs /dev/m19-dm ro\n')

    def run_script(self, **env):
        environment = dict(os.environ, M19_ROOT=str(self.root), M19_BB=str(self.test / 'bb'), M19_TEST=str(self.test), **env)
        return subprocess.run(['sh', str(HERE / 't9-root')], capture_output=True, text=True, env=environment, timeout=60)

    def bb_log(self):
        path = self.test / 'bb.log'
        return path.read_text() if path.exists() else ''

    @property
    def new(self):
        return self.root / 'newroot'

    def test_builds_the_root(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        log = self.bb_log()
        for name in ('sda', 'sda33', 'dm-0'):
            self.assertIn(f'mknod -m 400 {self.root}/dev/m19-ro-{name} b', log)
            self.assertIn(f'blockdev --setro {self.root}/dev/m19-ro-{name}', log)
            self.assertIn(f'blockdev --getro {self.root}/dev/m19-ro-{name}', log)
        self.assertIn(f'mount -o bind {self.root}/m19-data/ubuntu {self.new}\n', log)
        self.assertIn(f'mount -o remount,bind,ro {self.new}\n', log)
        self.assertIn(f'mount -t tmpfs -o mode=0755,nosuid,nodev,size=512m tmpfs {self.new}/etc\n', log)
        for point, mode, size in r2plan.TMPFS:
            self.assertIn(f'mount -t tmpfs -o mode={mode},nosuid,nodev,size={size} tmpfs {self.new}{point}\n', log)
        self.assertIn(f'mount -t proc -o nosuid,nodev,noexec proc {self.new}/proc', log)
        self.assertIn(f'mount -t sysfs -o nosuid,nodev,noexec sysfs {self.new}/sys', log)
        nodes = re.findall(r'mknod -m (\d+) (\S+) (\w) ', log)
        self.assertEqual(sorted(path for mode, path, kind in nodes if path.startswith(str(self.new))),
                         sorted(f'{self.new}/dev/{name}' for name, _, _ in r2plan.NODES))
        self.assertFalse([path for mode, path, kind in nodes if path.startswith(str(self.new)) and kind != 'c'])
        self.assertIn('M19 T9 new root: blocks-read-only=3 etc=', result.stderr)
        self.assertIn('machine-id=present fstab-lines=2 selinux-config=hidden default-was=/lib/systemd/system/graphical.target', result.stderr)
        self.assertIn('multi-user wants: ssh.service', result.stderr)

    def test_etc_in_ram_carries_the_plan(self):
        self.assertEqual(self.run_script().returncode, 0)
        etc = self.new / 'etc'
        self.assertEqual(os.readlink(etc / 'systemd/system/default.target'), 'm19-r2.target')
        for unit in r2plan.MASKED:
            self.assertEqual(os.readlink(etc / 'systemd/system' / unit), '/dev/null', unit)
        for name in r2plan.GENERATORS:
            self.assertEqual(os.readlink(etc / 'systemd/system-generators' / name), '/dev/null', name)
        for name, text in r2plan.FILES.items():
            self.assertEqual((etc / name).read_text(), text)
        self.assertFalse((etc / 'selinux/config').exists())
        self.assertFalse((etc / 'crypttab').exists())
        self.assertEqual((etc / 'hostname').read_text(), 'marble\n')
        self.assertEqual((etc / 'machine-id').read_text(), '0123456789abcdef0123456789abcdef\n')
        self.assertEqual((self.new / 'run/m19/m19-report').read_text(), 'elf\n')
        self.assertTrue(os.access(self.new / 'run/m19/m16-display', os.X_OK))

    def test_the_tree_itself_is_untouched(self):
        tree = self.root / 'm19-data/ubuntu'
        before = {str(p): (p.is_symlink(), p.read_bytes() if p.is_file() and not p.is_symlink() else None) for p in tree.rglob('*')}
        self.assertEqual(self.run_script().returncode, 0)
        after = {str(p): (p.is_symlink(), p.read_bytes() if p.is_file() and not p.is_symlink() else None) for p in tree.rglob('*')}
        self.assertEqual(before, after)

    def test_machine_id_that_would_mean_first_boot_becomes_empty(self):
        for text, state in (('uninitialized\n', 'uninitialized'), (None, 'missing'), ('', 'empty')):
            with self.subTest(state=state):
                self.setUp()
                path = self.root / 'm19-data/ubuntu/etc/machine-id'
                if text is None:
                    path.unlink()
                else:
                    path.write_text(text)
                result = self.run_script()
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f'machine-id={state} ', result.stderr)
                self.assertEqual((self.new / 'etc/machine-id').read_text(), '')

    def assertFails(self, reason, **env):
        result = self.run_script(**env)
        self.assertNotEqual(result.returncode, 0)
        # The whole line: 'root' must not match 'root-read-only-check'.
        self.assertIn(f'M19 T9 failed: {reason}\n', result.stderr)
        return result

    def test_read_only_that_did_not_take_stops(self):
        self.assertFails('read-only check dm-0', M19_GETRO='0')
        self.assertNotIn('mount', self.bb_log())

    def test_no_block_device_stops(self):
        shutil.rmtree(self.root / 'sys/class/block')
        self.assertFails('no-block-device')

    def test_a_bad_block_number_stops(self):
        (self.root / 'sys/class/block/sda/dev').write_text('8:0:1\n')
        self.assertFails('block number sda')

    def test_a_root_that_is_not_read_only_stops(self):
        self.mountinfo('rw,noatime')
        self.assertFails('root-read-only-check rw,noatime')
        self.assertNotIn('tmpfs', self.bb_log())

    def test_an_existing_new_root_stops(self):
        self.new.mkdir()
        self.assertFails('newroot-exists')

    def test_a_missing_or_linked_mount_point_stops(self):
        tree = self.root / 'm19-data/ubuntu'
        for change in ('missing', 'link', 'parent'):
            with self.subTest(change=change):
                self.setUp()
                tree = self.root / 'm19-data/ubuntu'
                if change == 'missing':
                    (tree / 'var/lib/upower').rmdir()
                    reason = 'mount point /var/lib/upower'
                elif change == 'link':
                    (tree / 'var/log').rmdir()
                    os.symlink('/tmp', tree / 'var/log')
                    reason = 'mount point /var/log'
                else:
                    shutil.rmtree(tree / 'var')
                    (self.root / 'elsewhere/tmp').mkdir(parents=True)
                    os.symlink(self.root / 'elsewhere', tree / 'var')
                    reason = 'mount point /var/tmp'
                self.assertFails(reason)

    def test_a_wrong_init_hash_stops(self):
        (self.root / 'm19-data/ubuntu/usr/lib/systemd/systemd').write_bytes(b'other')
        self.assertFails('probe-hash')

    def test_a_missing_tool_stops(self):
        (self.root / 'm19-data/ubuntu/usr/bin/journalctl').unlink()
        self.assertFails('missing usr/bin/journalctl')

    def test_a_missing_character_class_stops(self):
        shutil.rmtree(self.root / 'sys/class/tty/ttyGS0')
        self.assertFails('char number ttyGS0')

    def test_bad_plan_lines_stop(self):
        for name, text, reason in (('masks', 'foo/../bar.service\n', 'unit name foo/../bar.service'), ('masks', 'foo.device\n', 'unit type foo.device'),
                                   ('generators', '../x\n', 'generator name ../x'), ('files', '../passwd\n', 'plan file ../passwd'),
                                   ('tmpfs', 'var/x 0755 1m\n', 'tmpfs path var/x'), ('tmpfs', '/var/tmp 755 1m\n', 'tmpfs mode /var/tmp'),
                                   ('nodes', 'sda block/sda 600\n', 'node class sda'), ('nodes', '../x mem/null 600\n', 'node name ../x'),
                                   ('default', 'graphical.target\n', 'default target graphical.target')):
            with self.subTest(name=name, text=text):
                self.setUp()
                (self.root / 'm19/r2' / name).write_text(text)
                self.assertFails(reason)

    def test_a_relative_or_linked_test_root_is_refused(self):
        link = Path(self.directory.name) / 'link'
        os.symlink(self.root, link)
        for root in ('relative/root', str(link)):
            environment = dict(os.environ, M19_ROOT=root, M19_BB=str(self.test / 'bb'), M19_TEST=str(self.test))
            done = subprocess.run(['sh', str(HERE / 't9-root')], capture_output=True, text=True, env=environment, timeout=30)
            self.assertIn('M19 T9 failed: root\n', done.stderr)


class Plan(unittest.TestCase):
    def test_render_is_consistent(self):
        files = r2plan.render()
        self.assertEqual(files['m19/r2/files'].decode().split(), list(r2plan.FILES))
        self.assertEqual(tuple(line.split()[0] for line in files['m19/r2/tmpfs'].decode().splitlines()), rootfs.TMPFS)

    def test_storage_and_serial_units_are_masked(self):
        for unit in ('udisks2.service', 'fwupd.service', 'fstrim.timer', 'systemd-pstore.service', 'systemd-repart.service', 'snapd.service',
                     'systemd-tmpfiles-setup-dev.service', 'kmod-static-nodes.service', 'lvm2-monitor.service', 'multipathd.service',
                     'zfs-import-scan.service', 'cloud-init.service', 'ModemManager.service', 'serial-getty@ttyGS0.service',
                     'systemd-remount-fs.service', 'systemd-fsck-root.service', 'display-manager.service', 'plymouth-start.service',
                     'cron.service', 'anacron.timer'):
            self.assertIn(unit, r2plan.MASKED)
        for name in ('systemd-gpt-auto-generator', 'systemd-fstab-generator', 'systemd-cryptsetup-generator', 'systemd-getty-generator',
                     'systemd-hibernate-resume-generator'):
            self.assertIn(name, r2plan.GENERATORS)

    def test_dev_holds_no_storage_tee_input_or_watchdog_node(self):
        names = {name for name, _, _ in r2plan.NODES}
        classes = {kind.split('/')[0] for _, kind, _ in r2plan.NODES}
        self.assertEqual(classes, {'mem', 'tty', 'drm'})
        for bad in ('mem', 'kmem', 'port', 'qseecom', 'smcinvoke', 'watchdog', 'watchdog0', 'mapper/control', 'loop-control', 'sg0', 'rtc0'):
            self.assertNotIn(bad, names)
        self.assertFalse([name for name in names if name.startswith(('sd', 'dm-', 'block', 'bsg', 'input', 'ufs'))])

    def test_reporter_runs_early_and_survives_isolation(self):
        text = r2plan.REPORT
        for line in ('DefaultDependencies=no', 'IgnoreOnIsolate=yes', 'Type=exec', 'ExecStart=/run/m19/m19-report report'):
            self.assertIn(line + '\n', text)
        self.assertIn('Wants=multi-user.target m19-r2-report.service\n', r2plan.TARGET)
        self.assertIn('HandlePowerKey=ignore\n', r2plan.LOGIN)
        self.assertIn('Storage=volatile\n', r2plan.JOURNAL)
        # R2a stalled with journald stuck reading kernel records; the reporter reads /dev/kmsg itself.
        self.assertIn('ReadKMsg=no\n', r2plan.JOURNAL)
        self.assertNotRegex(r2plan.MANAGER, r'(?m)^(CrashReboot=yes|RuntimeWatchdogSec=[1-9])')


class Static(unittest.TestCase):
    def test_pid2_runs_t9_before_the_write_counters_and_drops_t7(self):
        text = (HERE / 'pid2.c').read_text()
        names = re.findall(r'\{"(T\d+-[a-z]+)", "/m19/(t\d-[a-z]+)"', text)
        self.assertEqual([name for name, _ in names], ['T0-extract', 'T1-services', 'T2-unlock', 'T5-mount', 'T6-read', 'T9-root', 'T8-writes'])
        self.assertIn('{"T2-unlock", "/m19/t2-unlock", 90000, M19_STEP_REQUIRED | M19_STEP_OWNED}', text)
        self.assertIn('{"T9-root", "/m19/t9-root", 120000, M19_STEP_REQUIRED}', text)
        self.assertIn('{"T8-writes", "/m19/t8-writes", 30000, M19_STEP_REQUIRED | M19_STEP_ALWAYS}', text)
        self.assertIn('if (m19_run_main(&run) == M19_END_PASS) {', text)
        self.assertIn('.expected_init = "/usr/lib/systemd/systemd"', text)
        self.assertNotRegex(text, r'\breboot\(|RB_AUTOBOOT|LINUX_REBOOT')

    def test_no_reboot_and_no_block_write_anywhere_in_r2(self):
        for name in ('handoff.c', 'report.c', 'wire.c', 'pid2.c', 't9-root'):
            text = (HERE / name).read_text()
            self.assertNotRegex(text, r'\b(reboot|poweroff|mkfs|fsck|blkdiscard|fstrim|setrw|wipe|sgdisk|parted)\b|\bof=/dev|O_WRONLY[^\n]*/dev/(sd|block|dm)', name)
        text = (HERE / 't9-root').read_text()
        self.assertEqual(re.findall(r'remount[^ ]*', text), ['remount,bind,ro'])
        self.assertNotRegex(text, r'mknod[^\n]* b "\$\{number%%:\*\}"[^\n]*\$new')

    def test_t9_reads_no_lock_screen_data(self):
        text = (HERE / 't9-root').read_text()
        for word in ('locksettings', 'spblob', 'gatekeeper', '/data/media', 'shadow', '.ssh'):
            self.assertNotIn(word, text)

    def test_scripts_parse(self):
        for name in ('t9-root', 't9-desktop'):
            self.assertEqual(subprocess.run(['sh', '-n', str(HERE / name)]).returncode, 0, name)

    def test_pid3_adds_t9_desktop_and_reports_the_desktop(self):
        text = (HERE / 'pid3.c').read_text()
        names = re.findall(r'\{"(T\d+-[a-z]+)", "/m19/(t\d-[a-z]+)"', text)
        self.assertEqual([name for name, _ in names],
                         ['T0-extract', 'T1-services', 'T2-unlock', 'T5-mount', 'T6-read', 'T9-root', 'T9-desktop', 'T8-writes'])
        self.assertIn('{"T9-desktop", "/m19/t9-desktop", 60000, M19_STEP_REQUIRED}', text)
        self.assertIn('{"T8-writes", "/m19/t8-writes", 30000, M19_STEP_REQUIRED | M19_STEP_ALWAYS}', text)
        for field in ('.desktop = 1', '.want_hz = 120.0', '.touch_name = "goodix_ts"', '.card = "/dev/dri/card0"', '.touch_ms = 60000',
                      '.battery_limit = 420, ', '.zone_limit = 80000,', '.busy_limit = 90, ', '.busy_ms = 60000, ', '.session_ms = 900000, ',
                      '.run_ms = 0, ',
                      'if (argc == 2 && !strcmp(argv[1], "guard"))', '.guard_unit = "m19-r3-guard.service"',
                      '.units = {"marble-xfce.service", "marble-xorg.service", "marble-xorg-fallback.service"}'):
            self.assertIn(field, text)
        self.assertNotRegex(text, r'\breboot\(|RB_AUTOBOOT|LINUX_REBOOT')
        steps = len(names)
        self.assertLessEqual(steps, int(re.search(r'#define M19_STEPS_MAX (\d+)', (HERE.parent / 'run1/r1.h').read_text()).group(1)))

    def test_t9_desktop_writes_nothing_outside_the_new_root(self):
        text = (HERE / 't9-desktop').read_text()
        self.assertNotRegex(text, r'\b(reboot|poweroff|mkfs|fsck|blkdiscard|fstrim|remount|setrw)\b|\bof=/dev')
        for line in text.splitlines():
            if re.search(r'\$BB (cp|mkdir|mknod|chmod)\b|>"', line):
                self.assertRegex(line, r'"\$(new|home)[/"]', line)
        for word in ('.ssh', '.gnupg', '.gemini', 'shadow', 'spblob', '/data/media'):
            self.assertNotIn(word, text)


class Plan3(unittest.TestCase):
    def test_render_carries_r2_and_the_desktop(self):
        files = r3plan.render()
        self.assertEqual(files['m19/r2/default'], b'm19-r3.target\n')
        self.assertEqual(r2plan.render()['m19/r2/default'], b'm19-r2.target\n')
        self.assertEqual(files['m19/r2/files'].decode().split(), list(r3plan.FILES))
        self.assertFalse([name for name in files if name.startswith('m19/r2/etc/systemd/system/m19-r2')])
        self.assertIn('ReadKMsg=no\n', r3plan.FILES['systemd/journald.conf.d/m19-r2.conf'])
        self.assertEqual(files['m19/r3/modes'], b'1080x2400x120vid\n1080x2400x60vid\n')
        self.assertEqual(files['m19/r3/touch'], b'goodix_ts\n')

    def test_power_targets_and_lockers_are_gone(self):
        for unit in ('poweroff.target', 'reboot.target', 'halt.target', 'systemd-poweroff.service', 'systemd-reboot.service',
                     'udisks2.service', 'ModemManager.service', 'serial-getty@ttyGS0.service'):
            self.assertIn(unit, r3plan.MASKED)
        for name in ('light-locker', 'xscreensaver', 'xfce4-power-manager', 'pulseaudio'):
            self.assertIn(name, r3plan.HIDDEN)

    def test_xorg_configurations(self):
        for mode, conf in ((r3plan.MODE_120, r3plan.render()['m19/r3/xorg.conf']), (r3plan.MODE_60, r3plan.render()['m19/r3/xorg-60.conf'])):
            text = conf.decode()
            self.assertIn(f'Option "PreferredMode" "{mode}"', text)
            for option in ('"Driver "modesetting"', '"kmsdev" "/dev/dri/card0"', '"AccelMethod" "none"', '"BlankTime" "0"', '"OffTime" "0"',
                           '"Monitor-DSI-1" "marble-panel"'):
                self.assertIn(option.lstrip('"'), text)
        self.assertEqual(r3plan.MODE_120, '1080x2400x120vid')

    def test_units(self):
        self.assertIn('OnFailure=marble-xorg-fallback.service\n', r3plan.XORG)
        self.assertNotIn('OnFailure', r3plan.XORG_60)
        for text, conf in ((r3plan.XORG, '/run/m19/xorg.conf'), (r3plan.XORG_60, '/run/m19/xorg-60.conf')):
            self.assertIn(f'-config {conf} ', text)
            for flag in ('-nolisten tcp', '-noreset', '-novtswitch', '-s 0 -dpms'):
                self.assertIn(flag, text)
        self.assertIn("i=$$((i+1)); [ \"$$i\" -lt 600 ]", r3plan.XFCE)
        self.assertNotRegex(r3plan.XFCE.replace('$$', ''), r'\$[a-z(]')
        self.assertIn('TimeoutStartSec=150\n', r3plan.XFCE)
        self.assertIn('Environment=DISPLAY=:0 HOME=/run/m19/session XDG_RUNTIME_DIR=/run/m19/xdg', r3plan.XFCE)
        self.assertIn('Wants=multi-user.target m19-r3-report.service m19-r3-guard.service marble-xorg.service marble-xfce.service\n', r3plan.TARGET)
        self.assertEqual(r3plan.FILES['systemd/system/m19-r3-guard.service'], r3plan.GUARD)
        for line in ('DefaultDependencies=no', 'IgnoreOnIsolate=yes', 'ExecStart=/run/m19/m19-report guard', 'Restart=on-failure'):
            self.assertIn(line + '\n', r3plan.GUARD)
        for line in ('DefaultDependencies=no', 'IgnoreOnIsolate=yes', 'ExecStart=/run/m19/m19-report report'):
            self.assertIn(line + '\n', r3plan.REPORT)


class DesktopScript(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name) / 'root'
        self.test = Path(self.directory.name) / 'test'
        self.test.mkdir()
        (self.test / 'bb').write_text(FAKE_BB)
        (self.test / 'bb').chmod(0o755)
        for name, data in r3plan.render().items():
            if name.startswith('m19/r3/'):
                path = self.root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
        self.new = self.root / 'newroot'
        for name in ('run/m19', 'dev'):
            (self.new / name).mkdir(parents=True)
        for tool in ('usr/lib/xorg/Xorg', 'usr/lib/xorg/modules/drivers/modesetting_drv.so', 'usr/lib/xorg/modules/input/libinput_drv.so',
                     'usr/bin/startxfce4', 'usr/bin/dbus-run-session', 'usr/bin/xfwm4', 'usr/bin/xfce4-panel', 'usr/bin/xfdesktop',
                     'usr/bin/xdpyinfo', 'usr/bin/xrandr', 'usr/bin/xinput', 'usr/bin/ps'):
            (self.new / tool).parent.mkdir(parents=True, exist_ok=True)
            (self.new / tool).write_text('x\n')
        xfce = self.root / 'm19-data/ubuntu/root/.config/xfce4/xfconf'
        xfce.mkdir(parents=True)
        (xfce / 'xfwm4.xml').write_text('<channel/>\n')
        os.symlink('/root/.ssh/id', xfce / 'latest.rc')
        os.mkfifo(xfce / 'pipe')
        (self.root / 'm19-data/ubuntu/root/.ssh').mkdir()
        (self.root / 'm19-data/ubuntu/root/.ssh/id').write_text('secret\n')
        panel = self.root / 'sys/class/drm/card0-DSI-1'
        panel.mkdir(parents=True)
        (panel / 'status').write_text('connected\n')
        (panel / 'modes').write_text('1080x2400x60vid\n1080x2400x120vid\n1080x2400x90vid\n1080x2400x30vid\n')
        for name, device, number in (('event0', 'pmic_pwrkey', '13:64'), ('event4', 'gpio-keys', '13:68'), ('event7', 'goodix_ts', '13:71')):
            entry = self.root / 'sys/class/input' / name
            (entry / 'device').mkdir(parents=True)
            (entry / 'device/name').write_text(device + '\n')
            (entry / 'dev').write_text(number + '\n')

    def run_script(self, **env):
        environment = dict(os.environ, M19_ROOT=str(self.root), M19_BB=str(self.test / 'bb'), M19_TEST=str(self.test), **env)
        return subprocess.run(['sh', str(HERE / 't9-desktop')], capture_output=True, text=True, env=environment, timeout=60)

    def bb_log(self):
        path = self.test / 'bb.log'
        return path.read_text() if path.exists() else ''

    def assertFails(self, reason):
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(f'M19 T9 desktop failed: {reason}\n', result.stderr)

    def test_prepares_the_desktop(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.new / 'run/m19/xorg.conf').read_bytes(), r3plan.render()['m19/r3/xorg.conf'])
        self.assertEqual((self.new / 'run/m19/xorg-60.conf').read_bytes(), r3plan.render()['m19/r3/xorg-60.conf'])
        nodes = re.findall(r'mknod -m (\d+) (\S+) (\w) (\d+) (\d+)', self.bb_log())
        self.assertEqual(nodes, [('600', f'{self.new}/dev/input/event7', 'c', '13', '71')])
        home = self.new / 'run/m19/session'
        self.assertEqual((home / '.config/xfce4/xfconf/xfwm4.xml').read_text(), '<channel/>\n')
        self.assertFalse((home / '.ssh').exists())
        copied = home / '.config/xfce4/xfconf'
        self.assertFalse(os.path.lexists(copied / 'latest.rc') or os.path.lexists(copied / 'pipe'))
        self.assertTrue(all(p.is_file() or p.is_dir() for p in (home / '.config/xfce4').rglob('*')))
        self.assertIn(' pruned=2 ', result.stderr)
        for name in r3plan.HIDDEN:
            self.assertEqual((home / f'.config/autostart/{name}.desktop').read_text(), '[Desktop Entry]\nHidden=true\n')
        self.assertEqual(oct(home.stat().st_mode & 0o777), '0o700')
        self.assertEqual(oct((self.new / 'run/m19/xdg').stat().st_mode & 0o777), '0o700')
        self.assertIn('M19 T9 desktop: touch=goodix_ts node=event7', result.stderr)
        self.assertIn('panel modes 1080x2400x60vid 1080x2400x120vid', result.stderr)

    def test_a_missing_mode_stops(self):
        (self.root / 'sys/class/drm/card0-DSI-1/modes').write_text('1080x2400x60vid\n1080x2400x90vid\n')
        self.assertFails('panel mode 1080x2400x120vid')

    def test_a_disconnected_panel_stops(self):
        (self.root / 'sys/class/drm/card0-DSI-1/status').write_text('disconnected\n')
        self.assertFails('panel-status')

    def test_touch_must_exist_once(self):
        shutil.rmtree(self.root / 'sys/class/input/event7')
        self.assertFails('touch missing')
        self.setUp()
        entry = self.root / 'sys/class/input/event9'
        (entry / 'device').mkdir(parents=True)
        (entry / 'device/name').write_text('goodix_ts\n')
        (entry / 'dev').write_text('13:73\n')
        self.assertFails('touch duplicate')

    def test_xfce_settings_must_be_a_real_directory(self):
        shutil.rmtree(self.root / 'm19-data/ubuntu/root/.config/xfce4')
        os.symlink('/etc', self.root / 'm19-data/ubuntu/root/.config/xfce4')
        self.assertFails('xfce-settings')

    def test_a_missing_tool_stops(self):
        (self.new / 'usr/bin/xinput').unlink()
        self.assertFails('missing usr/bin/xinput')

    def test_bad_plan_lines_stop(self):
        for name, text, reason in (('hidden', '../x\n', 'hidden name ../x'), ('touch', 'goodix ts\n', 'touch name goodix ts'),
                                   ('modes', '1080x2400x120vid;\n', 'mode name 1080x2400x120vid;')):
            with self.subTest(name=name):
                self.setUp()
                (self.root / 'm19/r3' / name).write_text(text)
                self.assertFails(reason)

    def test_without_the_new_root_nothing_happens(self):
        shutil.rmtree(self.new / 'run')
        self.assertFails('newroot')
        self.assertEqual(self.bb_log(), '')


XINPUT = '''#!/bin/sh
d=$(dirname "$0")
case "$1" in
 list) if [ "$2" = --name-only ]; then cat "$d/xinput-names"; else echo "Virtual core pointer"; fi;;
 test-xi2) [ ! -e "$d/interrupts-after" ] || cp "$d/interrupts-after" "$d/../interrupts"; cat "$d/xi2"; exec sleep 30;;
esac
'''
XRANDR = '''#!/bin/sh
d=$(dirname "$0")
case "$1" in
 --query) cat "$d/xrandr-query";;
 *) echo verbose;;
esac
'''
INTERRUPTS = ('           CPU0       CPU1\n'
              ' 299:          5          0   msmgpio  20 Edge      xgoodix_ts\n'
              ' 300:        {0}          {1}   msmgpio  21 Edge      goodix_ts\n'
              ' 301:          7          0   msmgpio  22 Edge      goodix_ts_extra\n')


class Desktop(ReportBase):
    def setUp(self):
        super().setUp()
        for name, text in (('xdpyinfo', '#!/bin/sh\n[ -e "$(dirname "$0")/x-up" ]\n'), ('xrandr', XRANDR), ('xinput', XINPUT),
                           ('ps', '#!/bin/sh\necho "PID COMMAND"\n')):
            (self.test / name).write_text(text)
            (self.test / name).chmod(0o755)
        (self.test / 'x-up').write_text('')
        (self.test / 'xrandr-query').write_text('DSI-1 connected primary 1080x2400+0+0\n   1080x2400x60vid  60.00 +\n   1080x2400x120vid 90.00   120.00*\n')
        (self.test / 'xinput-names').write_text('Virtual core pointer\ngoodix_ts\n')
        (self.test / 'xi2').write_text('EVENT type 22 (RawTouchBegin)\nEVENT type 18 (TouchBegin)\n')
        (self.root / 'interrupts').write_text(INTERRUPTS.format(290, 0))
        (self.test / 'interrupts-after').write_text(INTERRUPTS.format(300, 2))
        (self.root / 'card').write_text('')
        for pid, comm in ((101, 'xfwm4'), (102, 'xfce4-panel'), (103, 'xfdesktop'), (104, 'Xorg')):
            (self.root / 'proc' / str(pid)).mkdir(parents=True)
            (self.root / 'proc' / str(pid) / 'comm').write_text(comm + '\n')
        (self.root / 'xorg0.log').write_text('(II) modeset(0): Output DSI-1 connected\n')
        (self.root / 'battery-temp').write_text('341\n')
        (self.root / 'thermal/thermal_zone0').mkdir(parents=True)
        (self.root / 'thermal/thermal_zone0/temp').write_text('45000\n')

    def run_desktop(self, hz='120', touch_ms=300):
        wire = Wire()
        environment = dict(os.environ, ASAN_OPTIONS='detect_leaks=0')
        if hz:
            environment['M19_VBLANK_HZ'] = hz
        subprocess.run([ARGS.driver, 'report-desktop', str(self.root), wire.path, '300', '5000', str(touch_ms)], capture_output=True, timeout=60,
                       env=environment)
        data = wire.close()
        colour = (self.test / 'colour').read_text().split()[0] if (self.test / 'colour').exists() else None
        return data, colour

    def desktop(self, log):
        return dict(item.split('=') for item in re.search(r'M19 R3 desktop (.*)\n', log).group(1).split())

    def test_desktop_pass_leaves_the_panel_to_x(self):
        data, colour = self.run_desktop()
        fields, log, steps = self.parse(data)
        self.assertEqual(fields[3:], ['1', '0'])
        self.assertIsNone(colour)
        d = self.desktop(log)
        self.assertEqual((d['x'], d['session'], d['mode'], d['mode_ok'], d['vblank_ok'], d['touch_device'], d['touch_irqs'], d['touch_ok']),
                         ('1', '1', '1080x2400x120vid', '1', '1', '1', '12', '1'))
        self.assertEqual(d['xrandr_hz'], '120.00')
        self.assertAlmostEqual(float(d['vblank_hz']), 120.0, places=1)
        self.assertEqual(d['crtc'], '0')
        self.assertEqual((d['guard'], d['tripped'], d['battery'], d['zones'], d['hottest']), ('1', '0', '341', '1', '45000'))
        self.assertIn('M19STEP T12-desktop OK 1 1', steps)
        self.assertIn('M19STEP T12-touch START 0', steps)
        self.assertIn('M19STEP T12-touch END 12 2', steps)
        for text in ('Output DSI-1 connected', 'goodix_ts', 'M19 $', 'verbose'):
            self.assertIn(text, log)

    def test_sixty_hertz_fails_the_mode_and_vblank_checks(self):
        (self.test / 'xrandr-query').write_text('DSI-1 connected\n   1080x2400x60vid  60.00*+\n   1080x2400x120vid 120.00\n')
        fields, log, _ = self.parse(self.run_desktop(hz='60')[0])
        d = self.desktop(log)
        self.assertEqual((fields[3], d['mode'], d['mode_ok'], d['vblank_ok']), ('0', '1080x2400x60vid', '0', '0'))

    def test_no_vblank_fails(self):
        fields, log, _ = self.parse(self.run_desktop(hz=None)[0])
        d = self.desktop(log)
        self.assertEqual((fields[3], d['crtc'], d['vblank_ok']), ('0', '-1', '0'))

    def test_no_x_paints_yellow_and_skips_the_touch_window(self):
        (self.test / 'x-up').unlink()
        data, colour = self.run_desktop()
        fields, log, steps = self.parse(data)
        self.assertEqual((fields[3], colour, self.desktop(log)['x']), ('0', YELLOW, '0'))
        self.assertIn('M19STEP T12-desktop FAIL 0 0', steps)
        self.assertFalse([line for line in steps if 'T12-touch' in line])

    def test_a_missing_xfce_piece_fails_the_session(self):
        shutil.rmtree(self.root / 'proc/103')
        fields, log, _ = self.parse(self.run_desktop()[0])
        self.assertEqual((fields[3], self.desktop(log)['session']), ('0', '0'))

    def test_touch_needs_the_device_interrupts_and_x_events(self):
        for change in ('device', 'irq', 'events'):
            with self.subTest(change=change):
                self.setUp()
                if change == 'device':
                    (self.test / 'xinput-names').write_text('Virtual core pointer\ngoodix_ts_extra\n')
                elif change == 'irq':
                    (self.test / 'interrupts-after').unlink()
                else:
                    (self.test / 'xi2').write_text('EVENT type 6 (Motion)\n')
                fields, log, _ = self.parse(self.run_desktop()[0])
                self.assertEqual((fields[3], self.desktop(log)['touch_ok']), ('0', '0'))

    def test_a_tripped_or_stopped_guard_fails_the_run(self):
        (self.root / 'guard-tripped').write_text('battery')
        fields, log, _ = self.parse(self.run_desktop()[0])
        self.assertEqual((fields[3], self.desktop(log)['guard'], self.desktop(log)['tripped']), ('0', '0', '1'))
        self.setUp()
        fields, log, _ = self.parse(self.run_desktop_env(M19_ACTIVE_RC='3')[0])
        self.assertEqual((fields[3], self.desktop(log)['guard']), ('0', '0'))

    def run_desktop_env(self, **extra):
        wire = Wire()
        environment = dict(os.environ, ASAN_OPTIONS='detect_leaks=0', M19_VBLANK_HZ='120', **extra)
        subprocess.run([ARGS.driver, 'report-desktop', str(self.root), wire.path, '300', '5000', '300'], capture_output=True, timeout=60,
                       env=environment)
        data = wire.close()
        return data, None

    def test_r2_failures_still_fail_the_desktop_run(self):
        self.counter('sda', 4)
        fields, log, _ = self.parse(self.run_desktop()[0])
        self.assertEqual((fields[3], self.verdict(log)['writes'], self.desktop(log)['touch_ok']), ('0', '0', '1'))


GUARD_SYSTEMCTL = '''#!/bin/sh
echo "$*" >> "$(dirname "$0")/systemctl.log"
case "$1" in stop) exit "${M19_STOP_RC:-0}";; esac
exit 0
'''


class Guard(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.test = self.root / 'test'
        self.test.mkdir()
        for name, text in (('systemctl', GUARD_SYSTEMCTL), ('display', DISPLAY)):
            (self.test / name).write_text(text)
            (self.test / name).chmod(0o755)
        (self.test / 'kmsg').write_text('')
        (self.root / 'battery-temp').write_text('341\n')
        zone = self.root / 'thermal/thermal_zone0'
        zone.mkdir(parents=True)
        (zone / 'temp').write_text('45000\n')
        (self.root / 'thermal/cooling_device0').mkdir()
        self.stat(0)

    def stat(self, busy):
        (self.root / 'stat').write_text(f'cpu  {100 + busy} 0 100 800 0 0 0 0 0 0\ncpu0 1 0 0 0\n')

    def run_guard(self, session_ms=100000, run_ms=300, busy_ms=60000, env=None, busy=False):
        stop = threading.Event()

        def burn():
            step = 0
            while not stop.is_set():
                step += 100
                self.stat(step)
                time.sleep(0.002)

        thread = threading.Thread(target=burn)
        if busy:
            thread.start()
        environment = dict(os.environ, ASAN_OPTIONS='detect_leaks=0', **(env or {}))
        done = subprocess.run([ARGS.driver, 'guard', str(self.root), str(session_ms), str(run_ms), str(busy_ms)], capture_output=True, text=True,
                              timeout=60, env=environment)
        stop.set()
        if busy:
            thread.join()
        calls = (self.test / 'systemctl.log').read_text() if (self.test / 'systemctl.log').exists() else ''
        colour = (self.test / 'colour').read_text().split()[0] if (self.test / 'colour').exists() else None
        marker = (self.root / 'guard-tripped').read_text() if (self.root / 'guard-tripped').exists() else None
        return done.returncode, calls, colour, marker, (self.test / 'kmsg').read_text()

    def assertTripped(self, reason, **kwargs):
        rc, calls, colour, marker, kmsg = self.run_guard(**kwargs)
        self.assertIn('stop marble-xfce.service marble-xorg.service marble-xorg-fallback.service', calls)
        self.assertEqual((colour, marker), (YELLOW, reason))
        self.assertIn(f'M19: guard trip reason={reason}, stopping the desktop', kmsg)
        return calls

    def test_quiet_sensors_do_nothing(self):
        rc, calls, colour, marker, kmsg = self.run_guard()
        self.assertEqual((rc, calls, colour, marker), (0, '', None, None))
        self.assertIn('M19: guard start battery_limit=420 zone_limit=80000', kmsg)
        self.assertIn('guard battery=341 zones=1 zone=45000 busy=0', kmsg)

    def test_a_hot_battery_trips_at_42_degrees(self):
        (self.root / 'battery-temp').write_text('419\n')
        self.assertEqual(self.run_guard()[1:4], ('', None, None))
        (self.root / 'battery-temp').write_text('420\n')
        self.assertTripped('battery')

    def test_a_hot_zone_trips(self):
        (self.root / 'thermal/thermal_zone0/temp').write_text('80000\n')
        self.assertTripped('zone')

    def test_implausible_zone_values_are_ignored(self):
        (self.root / 'thermal/thermal_zone0/temp').write_text('250000\n')
        rc, calls, colour, marker, kmsg = self.run_guard()
        self.assertEqual((calls, marker), ('', None))
        self.assertIn('zones=0 zone=-1', kmsg)

    def test_a_long_session_trips(self):
        self.assertTripped('time', session_ms=50)

    def test_a_busy_cpu_trips(self):
        self.assertTripped('cpu', busy_ms=50, run_ms=5000, busy=True)

    def test_missing_sensors_leave_time_in_charge(self):
        (self.root / 'battery-temp').unlink()
        shutil.rmtree(self.root / 'thermal')
        rc, calls, colour, marker, kmsg = self.run_guard()
        self.assertEqual((calls, marker), ('', None))
        self.assertIn('guard battery=-1 zones=0 zone=-1', kmsg)
        self.assertTripped('time', session_ms=50)

    def test_a_failed_stop_kills_the_units(self):
        (self.root / 'battery-temp').write_text('500\n')
        calls = self.assertTripped('battery', env={'M19_STOP_RC': '1'})
        self.assertIn('kill --signal=SIGKILL marble-xfce.service marble-xorg.service marble-xorg-fallback.service', calls)

    def test_a_clean_stop_kills_nothing(self):
        (self.root / 'battery-temp').write_text('500\n')
        self.assertNotIn('kill', self.assertTripped('battery'))


def main():
    global ARGS
    parser = argparse.ArgumentParser()
    parser.add_argument('--driver', required=True)
    parser.add_argument('tests', nargs='*', help='test classes to run; all when empty')
    ARGS = parser.parse_args()
    ARGS.driver = os.path.abspath(ARGS.driver)
    program = unittest.main(argv=['test', *ARGS.tests], exit=False, verbosity=1)
    sys.exit(not program.result.wasSuccessful())


if __name__ == '__main__':
    main()
