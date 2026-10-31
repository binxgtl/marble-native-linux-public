#!/usr/bin/env python3
"""The real r1.c and the real T scripts on synthetic trees, with a pty as the PC. No device."""
import argparse
import hashlib
import json
import os
import re
import select
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import plan  # noqa: E402
import rootfs  # noqa: E402

ARGS = None
GOOD = '#!/bin/sh\nexit 0\n'
BAD = '#!/bin/sh\nexit 3\n'
READY = '#!/bin/sh\necho CONNECTOR_READY\nexec cat >/dev/null\n'
DISPLAY = '#!/bin/sh\necho "$1 $2" >> "$(dirname "$0")/colours"\nexit 0\n'
STEPS = ('T0-extract', 'T1-services', 'T2-unlock', 'T5-mount', 'T6-read', 'T7-overlay', 'T8-writes')
FILES = ('t0', 't1', 't2', 't5', 't6', 't7', 't8')
BLUE, GREEN, YELLOW, RED = '000000ff', '0000ff00', '00ffff00', '00ff0000'
SCRIPTS = ('init', 'bootstrap', 'adsp', 't0-extract', 't1-start', 't2-unlock', 't5-mount', 't6-read', 't7-overlay', 't8-writes')


class Bench:
    def __init__(self, root):
        import pty
        import tty
        self.root = Path(root)
        self.test = self.root / 'test'
        self.test.mkdir()
        for name in ('bootstrap', 'adsp', *FILES):
            self.script(name, self.mark(name))
        self.script('connector', READY)
        self.script('display', DISPLAY)
        (self.test / 'kmsg').write_text('<6>kernel line\n')
        (self.test / 'boot.log').write_text('boot line\n')
        (self.test / 'logcat.txt').write_text('logcat line\n')
        self.master, self.slave = pty.openpty()
        tty.setraw(self.slave)
        self.path = os.ttyname(self.slave)

    def mark(self, name):
        return f'#!/bin/sh\necho {name} >> "$(dirname "$0")/order"\nexit 0\n'

    def script(self, name, text):
        path = self.test / name
        path.write_text(text)
        path.chmod(0o755)

    def order(self):
        path = self.test / 'order'
        return path.read_text().split() if path.exists() else []

    def colours(self):
        path = self.test / 'colours'
        return [line.split()[0] for line in path.read_text().splitlines()] if path.exists() else []

    def run(self, link_ms=3000, step_ms=2000, hello=True):
        lines, buffer, stop = [], bytearray(), threading.Event()

        def reader():
            sent = not hello
            while not stop.is_set():
                ready, _, _ = select.select([self.master], [], [], 0.02)
                if ready:
                    try:
                        buffer.extend(os.read(self.master, 65536))
                    except OSError:
                        return
                if not sent:
                    os.write(self.master, b'noise\n' + plan_hello())
                    sent = True

        thread = threading.Thread(target=reader)
        thread.start()
        env = dict(os.environ, ASAN_OPTIONS='detect_leaks=0')
        done = subprocess.run([ARGS.driver, str(self.root), self.path, str(link_ms), str(step_ms)], capture_output=True, text=True, timeout=60, env=env)
        time.sleep(0.1)
        stop.set()
        thread.join()
        self.wire = bytes(buffer)
        self.lines = lines
        return json.loads(done.stdout.strip().splitlines()[-1])

    def step_lines(self):
        return [line for line in self.wire.split(b'\n') if line.startswith((b'M19STEP', b'M19BEAT'))]

    def log(self):
        at = self.wire.index(b'M19LOG1 ')
        end = self.wire.index(b'\n', at)
        fields = self.wire[at:end].decode().split()
        size = int(fields[1])
        return fields, self.wire[end + 1:end + 1 + size]


def plan_hello():
    return b'M19HOST1\n'


class Run(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.bench = Bench(self.directory.name)

    def test_pass_order_and_colours(self):
        result = self.bench.run()
        self.assertEqual((result['end'], result['all_ok']), (0, 1))
        self.assertEqual(self.bench.order(), ['bootstrap', 'adsp', *FILES])
        self.assertEqual(self.bench.colours(), [BLUE, GREEN])
        self.assertEqual(result['ran'], [1] * 7)

    def test_link_comes_before_any_step(self):
        self.bench.run()
        self.assertLess(self.bench.order().index('adsp'), self.bench.order().index('t0'))

    def test_step_lines_on_the_wire(self):
        self.bench.run()
        lines = self.bench.step_lines()
        for name in STEPS:
            self.assertIn(f'M19STEP {name} START'.encode(), lines)
            self.assertIn(f'M19STEP {name} OK 0 0'.encode(), lines)

    def test_log_hash_and_sections(self):
        self.bench.run()
        fields, body = self.bench.log()
        self.assertEqual(fields[2], hashlib.sha256(body).hexdigest())
        self.assertEqual(fields[3:], ['1', '0'])
        for text in (b'M19 bootstrap.log', b'boot line', b'M19 kernel log', b'kernel line', b'M19 logcat', b'logcat line'):
            self.assertIn(text, body)

    def test_required_failure_stops_but_writes_still_run(self):
        self.bench.script('t2', BAD)
        result = self.bench.run()
        self.assertEqual((result['end'], result['all_ok']), (1, 0))
        self.assertEqual(result['ran'], [1, 1, 1, 0, 0, 0, 1])
        self.assertEqual(self.bench.colours()[-1], YELLOW)
        self.assertIn(b'M19STEP T2-unlock FAIL -1 768', self.bench.step_lines())

    def test_overlay_result_never_fails_the_run(self):
        self.bench.script('t7', BAD)
        result = self.bench.run()
        self.assertEqual((result['end'], result['all_ok']), (0, 1))
        self.assertEqual(self.bench.colours()[-1], GREEN)

    def test_write_counters_fail_the_run(self):
        self.bench.script('t8', BAD)
        result = self.bench.run()
        self.assertEqual((result['end'], result['all_ok']), (1, 0))
        self.assertEqual(self.bench.colours()[-1], YELLOW)

    def test_write_warning_in_kernel_log_fails_the_run(self):
        (self.bench.test / 'kmsg').write_text('Trying to write to read-only block-device dm-0 (partno 0)\n')
        result = self.bench.run()
        self.assertEqual((result['end'], result['all_ok'], result['write_warning']), (1, 0, 1))
        self.assertEqual(self.bench.log()[0][3:], ['0', '1'])

    def test_warning_text_in_logcat_is_not_a_kernel_finding(self):
        (self.bench.test / 'logcat.txt').write_text('Trying to write to read-only block-device\n')
        self.assertEqual(self.bench.run()['write_warning'], 0)

    def test_hung_step_is_left_alone_and_the_export_still_runs(self):
        self.bench.script('t1', '#!/bin/sh\nexec sleep 30\n')
        result = self.bench.run(step_ms=300)
        self.assertEqual((result['end'], result['all_ok']), (1, 0))
        self.assertEqual(result['ran'], [1, 1, 0, 0, 0, 0, 1])
        self.assertLess(result['results'][1], 0)
        self.assertIn(b'M19LOG1', self.bench.wire)

    def test_heartbeats_during_a_long_step(self):
        self.bench.script('t1', '#!/bin/sh\nsleep 0.3\nexit 0\n')
        self.bench.run()
        self.assertTrue(any(line.startswith(b'M19BEAT T1-services') for line in self.bench.step_lines()))

    def test_bootstrap_failure_starts_nothing(self):
        self.bench.script('bootstrap', BAD)
        result = self.bench.run()
        self.assertEqual(result['end'], 3)
        self.assertEqual(self.bench.order(), [])
        self.assertEqual(self.bench.colours(), [])

    def test_adsp_failure_never_reaches_the_tee(self):
        self.bench.script('adsp', BAD)
        result = self.bench.run()
        self.assertEqual(result['end'], 2)
        self.assertEqual(result['ran'], [0] * 7)
        self.assertEqual(self.bench.colours()[-1], RED)

    def test_wrong_connector_line_never_reaches_the_tee(self):
        self.bench.script('connector', '#!/bin/sh\necho NOT_READY\nexec cat >/dev/null\n')
        self.assertEqual(self.bench.run()['ran'], [0] * 7)

    def test_silent_host_never_reaches_the_tee(self):
        result = self.bench.run(link_ms=300, hello=False)
        self.assertEqual((result['end'], result['ran']), (2, [0] * 7))
        self.assertEqual(self.bench.colours()[-1], RED)


FAKE_BB = '''#!/bin/sh
echo "$*" >> "$M19_TEST/bb.log"
command=$1; shift
case "$command" in
 mount|umount|mknod|setsid|dd)
  case "${M19_FAIL:-}" in "$command") exit 1;; esac
  exit 0;;
 blockdev)
  case "$1" in --getro) echo "${M19_GETRO:-1}";; esac
  exit 0;;
 chroot) cat "$M19_TEST/unlock.out"; exit 0;;
 stat) echo 4096; exit 0;;
 sleep) exit 0;;
 *) exec "$command" "$@";;
esac
'''
BLOCKS = {'sda33': ('userdata', '8:33'), 'sda17': ('metadata', '8:17'), 'sde27': ('recovery_a', '8:91'), 'sda2': ('ssd', '8:2')}


class Scripts(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name) / 'root'
        self.test = Path(self.directory.name) / 'test'
        self.test.mkdir()
        (self.test / 'bb').write_text(FAKE_BB)
        (self.test / 'bb').chmod(0o755)
        for name in ('m19', 'sbin', 'dev', 'run/m19', 'tee/tmp/m19', 'sys/fs/selinux', 'sys/class/misc/device-mapper'):
            (self.root / name).mkdir(parents=True)
        shutil.copy(HERE / 'pins', self.root / 'm19/pins')
        (self.root / 'm19/init.rc').write_text('rc\n')
        (self.root / 'sys/fs/selinux/enforce').write_text('0')
        (self.root / 'sys/class/misc/device-mapper/dev').write_text('10:236\n')
        (self.root / 'tee/sepolicy').write_bytes(b'P' * 4096)
        rdx = self.root / 'sbin/m19-rdx'
        rdx.write_text('#!/bin/sh\necho "$@" > "$M19_TEST/rdx.args"\necho M19_RDX status=OK\nexit "${M19_RDX_RC:-0}"\n')
        rdx.chmod(0o755)
        for name, (part, number) in BLOCKS.items():
            entry = self.root / 'sys/class/block' / name
            entry.mkdir(parents=True)
            (entry / 'uevent').write_text(f'MAJOR=8\nDEVNAME={name}\nPARTNAME={part}\n')
            (entry / 'dev').write_text(number + '\n')
            (entry / 'stat').write_text(' '.join(['0'] * 17) + '\n')

    def run_script(self, name, **env):
        environment = dict(os.environ, M19_ROOT=str(self.root), M19_BB=str(self.test / 'bb'), M19_TEST=str(self.test), **env)
        return subprocess.run(['sh', str(HERE / name)], capture_output=True, text=True, env=environment, timeout=30)

    def bb_log(self):
        path = self.test / 'bb.log'
        return path.read_text() if path.exists() else ''

    def test_t0_makes_read_only_nodes_then_extracts(self):
        result = self.run_script('t0-extract')
        self.assertEqual(result.returncode, 0, result.stderr)
        log = self.bb_log()
        for name in ('recovery', 'metadata', 'userdata', 'ssd'):
            self.assertIn(f'blockdev --setro {self.root}/dev/m19-{name}', log)
        self.assertLess(log.rindex('--setro'), log.index('mount -t tmpfs'))
        args = (self.test / 'rdx.args').read_text().split()
        self.assertEqual(args[1], plan.RECOVERY_SHA256)
        self.assertEqual(args[4:], [f'ro.build.version.security_patch={plan.ANDROID_PATCH}', f'ro.vendor.build.security_patch={plan.ANDROID_PATCH}'])

    def test_t0_stops_when_read_only_did_not_take(self):
        self.assertEqual(self.run_script('t0-extract', M19_GETRO='0').returncode, 1)
        self.assertFalse((self.test / 'rdx.args').exists())

    def test_t0_stops_on_a_missing_partition(self):
        shutil.rmtree(self.root / 'sys/class/block/sda2')
        self.assertEqual(self.run_script('t0-extract').returncode, 1)
        self.assertFalse((self.test / 'rdx.args').exists())

    def test_t0_reports_a_failed_extraction(self):
        self.assertEqual(self.run_script('t0-extract', M19_RDX_RC='1').returncode, 1)

    def test_t1_goes_permissive_then_loads_in_one_write(self):
        (self.test / 'unlock.out').write_text('')
        (self.root / 'tee/tmp/m19/hwservicemanager').touch()
        (self.root / 'tee/tmp/m19/listeners').touch()
        (self.root / 'm19/m19-unlock').write_text('x')
        result = self.run_script('t1-start')
        self.assertEqual(result.returncode, 0, result.stderr)
        log = self.bb_log()
        self.assertIn(' bs=4096 count=1', log)
        self.assertIn('mount -t ext4 -o ro,noload', log)
        self.assertLess(log.index('of=' + str(self.root / 'sys/fs/selinux/load')), log.index('second_stage'))

    def test_t1_stops_if_permissive_did_not_take(self):
        (self.root / 'sys/fs/selinux/enforce').write_text('1')
        target = self.root / 'sys/fs/selinux/enforce'
        target.chmod(0o444)
        if os.access(target, os.W_OK):
            self.skipTest('running as root')
        self.assertNotEqual(self.run_script('t1-start').returncode, 0)
        self.assertNotIn('selinux/load', self.bb_log())

    def test_t1_fails_when_listeners_never_register(self):
        (self.root / 'tee/tmp/m19/hwservicemanager').touch()
        (self.root / 'm19/m19-unlock').write_text('x')
        result = self.run_script('t1-start')
        self.assertEqual(result.returncode, 1)
        self.assertIn('marker listeners', result.stderr)

    def test_t2_passes_the_pinned_arguments(self):
        (self.test / 'unlock.out').write_text('M19_UNLOCK status=OK detail=0 dev=253:0\n')
        result = self.run_script('t2-unlock')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f'/metadata/vold/metadata_encryption/key m19-userdata /dev/m19-userdata {plan.USERDATA_SECTORS}', self.bb_log())
        self.assertIn('M19_UNLOCK status=OK', (self.root / 'run/m19/unlock.line').read_text())

    def test_t2_fails_on_any_other_status(self):
        for line in ('M19_UNLOCK status=UPGRADE_REQUIRED detail=0 dev=0:0', 'M19_UNLOCK status=DECRYPT detail=-62 dev=0:0', ''):
            (self.test / 'unlock.out').write_text(line + '\n')
            with self.subTest(line=line):
                self.assertEqual(self.run_script('t2-unlock').returncode, 1)

    def test_t5_mounts_read_only_with_norecovery(self):
        (self.root / 'run/m19/unlock.line').write_text('M19_UNLOCK status=OK detail=0 dev=253:0\n')
        self.assertEqual(self.run_script('t5-mount').returncode, 0)
        log = self.bb_log()
        self.assertIn('mknod -m 400', log)
        self.assertIn(' b 253 0', log)
        self.assertIn('mount -t f2fs -o ro,noatime,norecovery,inlinecrypt', log)

    def test_t5_mount_options_match_the_plan(self):
        text = (HERE / 't5-mount').read_text()
        self.assertTrue(plan.data_mount()['read_only'])
        self.assertIn(plan.data_mount()['data'], text)

    def test_t5_refuses_a_bad_device_number(self):
        for line in ('dev=', 'dev=abc', 'dev=:1', 'dev=1:', 'no number'):
            (self.root / 'run/m19/unlock.line').write_text(f'M19_UNLOCK status=OK {line}\n')
            with self.subTest(line=line):
                self.assertEqual(self.run_script('t5-mount').returncode, 1)

    def test_t5_reports_a_failed_mount(self):
        (self.root / 'run/m19/unlock.line').write_text('M19_UNLOCK status=OK detail=0 dev=253:0\n')
        self.assertEqual(self.run_script('t5-mount', M19_FAIL='mount').returncode, 1)

    def fake_rootfs(self, version='24.04', probe=b'x'):
        root = self.root / 'm19-data/ubuntu'
        (root / 'usr/lib/systemd').mkdir(parents=True)
        (root / 'usr/lib/os-release').write_text(f'NAME="Ubuntu"\nVERSION_ID="{version}"\n')
        (root / 'usr/lib/systemd/systemd').write_bytes(probe)
        pins = self.root / 'm19/pins'
        pins.write_text(re.sub('ROOTFS_PROBE_SHA256=.*', 'ROOTFS_PROBE_SHA256=' + hashlib.sha256(b'x').hexdigest(), pins.read_text()))

    def test_t6_passes_on_the_right_bytes(self):
        self.fake_rootfs()
        self.assertEqual(self.run_script('t6-read').returncode, 0)

    def test_t6_fails_on_wrong_version_or_hash(self):
        self.fake_rootfs(version='22.04')
        self.assertEqual(self.run_script('t6-read').returncode, 1)
        shutil.rmtree(self.root / 'm19-data')
        self.fake_rootfs(probe=b'y')
        self.assertEqual(self.run_script('t6-read').returncode, 1)

    def test_t6_fails_when_nothing_is_mounted(self):
        self.assertEqual(self.run_script('t6-read').returncode, 1)

    def test_t7_records_either_outcome_and_exits_zero(self):
        for fail, text in (('mount', 'overlay refused'), ('', 'overlay mounted')):
            result = self.run_script('t7-overlay', M19_FAIL=fail)
            self.assertEqual(result.returncode, 0)
            self.assertIn(text, result.stderr)

    def test_t7_uses_tmpfs_for_upper_and_work(self):
        self.run_script('t7-overlay')
        self.assertRegex(self.bb_log(), r'upperdir=\S+/run/m19/overlay/upper,workdir=\S+/run/m19/overlay/work')

    def test_t8_passes_on_zero_counters(self):
        result = self.run_script('t8-writes')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr.count('writes=0 sectors=0 discards=0 discarded=0'), 4)

    def test_t8_fails_on_any_counter(self):
        for position, name in ((4, 'writes'), (6, 'sectors'), (11, 'discards'), (13, 'discarded')):
            fields = ['0'] * 17
            fields[position] = '1'
            (self.root / 'sys/class/block/sda33/stat').write_text(' '.join(fields) + '\n')
            with self.subTest(name=name):
                self.assertEqual(self.run_script('t8-writes').returncode, 1)

    def test_t8_ignores_reads(self):
        fields = ['0'] * 17
        fields[0], fields[2] = '500', '4096'
        (self.root / 'sys/class/block/sda33/stat').write_text(' '.join(fields) + '\n')
        self.assertEqual(self.run_script('t8-writes').returncode, 0)

    def test_t8_fails_on_a_missing_partition(self):
        shutil.rmtree(self.root / 'sys/class/block/sda17')
        self.assertEqual(self.run_script('t8-writes').returncode, 1)


class Static(unittest.TestCase):
    def test_pins_match_the_plan(self):
        pins = dict(line.split('=', 1) for line in (HERE / 'pins').read_text().splitlines() if '=' in line and not line.startswith('#'))
        self.assertEqual(pins['RECOVERY_SHA256'], plan.RECOVERY_SHA256)
        self.assertEqual(int(pins['USERDATA_SECTORS']), plan.USERDATA_SECTORS)
        self.assertEqual(pins['ANDROID_PATCH'], plan.ANDROID_PATCH)

    def test_scripts_hold_no_writing_command(self):
        forbidden = re.compile(r'\b(mkfs|fsck|mke2fs|tune2fs|blkdiscard|fstrim|remount|setrw|wipe|reboot|poweroff|flash|sgdisk|parted)\b|\bof=/dev|,rw\b|\brw,')
        for name in SCRIPTS:
            with self.subTest(name=name):
                self.assertIsNone(forbidden.search((HERE / name).read_text()))

    def test_every_block_mount_is_read_only(self):
        for name in ('t1-start', 't5-mount'):
            for line in (HERE / name).read_text().splitlines():
                if ' mount -t ext4' in line or ' mount -t f2fs' in line:
                    self.assertRegex(line, r'-o ro,')

    def test_no_script_reads_lock_screen_data(self):
        for name in SCRIPTS:
            text = (HERE / name).read_text()
            for word in ('locksettings', 'spblob', 'persistent.sqlite', 'gatekeeper', '/data/media'):
                self.assertNotIn(word, text)

    def test_steps_in_pid1_match_the_scripts(self):
        text = (HERE / 'pid1.c').read_text()
        for name in re.findall(r'"/m19/(t\d-[a-z]+)"', text):
            self.assertTrue((HERE / name).exists(), name)
        self.assertEqual(len(re.findall(r'"/m19/t\d-', text)), len(STEPS))

    def test_tmpfs_list_is_unrelated_to_this_run(self):
        self.assertNotIn('/m19-data', rootfs.TMPFS)

    def test_scripts_parse(self):
        for name in SCRIPTS:
            with self.subTest(name=name):
                self.assertEqual(subprocess.run(['sh', '-n', str(HERE / name)]).returncode, 0)


def main():
    global ARGS
    parser = argparse.ArgumentParser()
    parser.add_argument('--driver', required=True)
    ARGS = parser.parse_args()
    ARGS.driver = os.path.abspath(ARGS.driver)
    program = unittest.main(argv=['test'], exit=False, verbosity=1)
    sys.exit(not program.result.wasSuccessful())


if __name__ == '__main__':
    main()
