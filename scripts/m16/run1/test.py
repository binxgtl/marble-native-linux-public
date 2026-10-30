#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""The real run.c, machine and linux.c on a synthetic tree, with a pty as the PC. No device."""
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
sys.path.insert(0, str(HERE.parent / 's2'))
import host  # noqa: E402

ARGS = None
SCALE = 20
RTC_NOW = 80_076_948
TAG = 0x32
GOOD = '#!/bin/sh\nexit 0\n'
DISPLAY = '#!/bin/sh\necho "$1 $2" >> "$(dirname "$0")/colours"\nexit 0\n'
READY = '#!/bin/sh\necho CONNECTOR_READY\nexec cat >/dev/null\n'


class Bench:
    """Sysfs in the shape S1 and the M15 runs recorded, plus scripts for each child."""

    def __init__(self, root):
        import pty, tty  # POSIX only, and Scope must also run on the Windows host
        self.root = Path(root)
        self.test = self.root / 'test'
        self.test.mkdir(parents=True)
        files = {
            'sys/power/state': 'freeze mem\n', 'sys/power/mem_sleep': '[s2idle] deep\n', 'sys/power/wakeup_count': '41\n',
            'sys/power/suspend_stats/success': '0\n', 'sys/power/suspend_stats/fail': '0\n',
            'sys/power/suspend_stats/last_failed_errno': '0\n',
            'sys/class/rtc/rtc0/name': 'rtc-pm8xxx c42d000.qcom,spmi:qcom,pmk8350@0:rtc@6100\n',
            'sys/class/rtc/rtc0/wakealarm': '', 'sys/class/rtc/rtc0/since_epoch': f'{RTC_NOW}\n',
            'sys/devices/system/cpu/online': '0-7\n', 'sys/class/remoteproc/remoteproc0/state': 'offline\n',
            'sys/class/wakeup/wakeup0/active_time_ms': '0\n',
        }
        for name, text in files.items():
            self.write(name, text)
        (self.root / 'sys/class/udc/dummy_udc.0').mkdir(parents=True)  # as the carrier has it
        for cpu in range(8):
            self.write(f'sys/devices/system/cpu/cpu{cpu}/cpuidle/state1/s2idle/usage', '0\n')
        self.interrupts(0)
        for name, text in (('bootstrap', GOOD), ('adsp', GOOD), ('connector', READY), ('display', DISPLAY)):
            self.script(name, text)
        self.write('test/kmsg', '6,1,0,-;fixture kernel line\n')
        self.write('test/boot.log', 'fixture bootstrap\n')
        path = self.test / 'state_fifo'
        os.mkfifo(path)
        self.pipe = os.open(path, os.O_RDWR | os.O_NONBLOCK)
        try:
            while True:
                os.write(self.pipe, bytes(4096))
        except BlockingIOError:
            pass
        self.master, self.slave = pty.openpty()
        tty.setraw(self.slave)  # a default pty echoes the hello into the wire
        self.pending = bytearray()

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='ascii')

    def script(self, name, text):
        path = self.test / name
        path.write_text(text, encoding='ascii')
        path.chmod(path.stat().st_mode | stat.S_IXUSR)

    def interrupts(self, count):
        self.write('proc/interrupts', '           CPU0       CPU1\n'
                   f'260:  {count}  0  0  0  0  0  0  0  pmic_arb 25164545 Edge      pm8xxx_rtc_alarm\n')

    def resume(self, slept_ns):
        self.write('test/gap_ns', f'{slept_ns}\n')
        self.write('sys/power/suspend_stats/success', '1\n')
        for cpu in range(8):
            self.write(f'sys/devices/system/cpu/cpu{cpu}/cpuidle/state1/s2idle/usage', '1\n')
        self.interrupts(1)
        self.write('sys/class/rtc/rtc0/wakealarm', '')
        os.read(self.pipe, 65536)

    def wait(self, name, seconds=20):
        end = time.monotonic() + seconds
        while not (self.test / name).exists():
            if time.monotonic() > end:
                raise TimeoutError(name)
            time.sleep(0.002)

    def text(self, name):
        return (self.root / name).read_text(encoding='ascii')

    def start(self, channel_s=420):
        return subprocess.Popen([str(ARGS.driver), str(self.root), os.ttyname(self.slave), str(SCALE), str(channel_s)],
                                stdout=subprocess.PIPE, text=True)

    def hello(self):
        os.write(self.master, b'M16HOST1\n')

    def read_exact(self, size, seconds=20):
        end = time.monotonic() + seconds
        while len(self.pending) < size:
            if time.monotonic() > end:
                raise TimeoutError(f'{len(self.pending)} of {size}')
            if select.select([self.master], [], [], 0.05)[0]:
                self.pending += os.read(self.master, 65536)
        data = bytes(self.pending[:size])
        del self.pending[:size]
        return data

    def read_wire(self):
        head = self.read_exact(host.HEADER)
        count = int.from_bytes(head[12:16], 'little')
        return head + self.read_exact(count * host.RECORD)

    def read_line(self):
        line = bytearray()
        while not line.endswith(b'\n'):
            line += self.read_exact(1)
        return line.decode('ascii').strip()

    def ack(self, report):
        os.write(self.master, b'M16ACK1 ' + report['head'].encode('ascii') + b'\n')

    def read_log(self):
        fields = self.read_line().split()
        body = self.read_exact(int(fields[1]))
        return fields, body

    def close(self):
        os.close(self.pipe)
        os.close(self.master)
        os.close(self.slave)


class Run(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix='m16-run1-'))
        self.bench = Bench(self.dir / 'tree')

    def tearDown(self):
        self.bench.close()
        shutil.rmtree(self.dir, ignore_errors=True)

    def finish(self, process, seconds=30):
        timer = threading.Timer(seconds, process.kill)
        timer.start()
        try:
            line = process.stdout.readline()
            process.wait()
        finally:
            timer.cancel()
            process.stdout.close()
        return json.loads(line)

    def colours(self):
        path = self.bench.test / 'colours'
        return path.read_text(encoding='ascii').split('\n')[:-1] if path.exists() else []

    def cycle(self, process=None):
        process = process or self.bench.start()
        self.bench.wait('writer_started')
        self.assertEqual(self.bench.text('sys/class/rtc/rtc0/wakealarm'), '+45\n')
        self.bench.resume(40 * 10**9)
        return process

    def export(self):
        self.bench.hello()
        report = host.decode(self.bench.read_wire())
        return report

    def mark_read(self):
        return host.read_mark(int(self.bench.text('sys/class/rtc/rtc0/wakealarm')), RTC_NOW + 300, TAG)

    def test_complete_cycle(self):
        process = self.cycle()
        report = self.export()
        self.assertTrue(report['pass'], report)
        self.assertEqual(self.mark_read(), {'state': 'PRESENT', 'outcome': 'PASS'})
        self.bench.ack(report)
        fields, body = self.bench.read_log()
        result = self.finish(process)
        self.assertEqual(fields[0], 'M16LOG1')
        self.assertEqual(fields[2], hashlib.sha256(body).hexdigest())
        self.assertEqual((int(fields[3]), int(fields[4])), (0, result['mark_value']))
        self.assertIn(b'fixture bootstrap', body)
        self.assertIn(b'fixture kernel line', body)
        self.assertEqual(result['end'], 0)
        self.assertEqual((result['verdict'], result['failure']), ('PASS', 'NONE'))
        self.bench.wait('colours')
        time.sleep(0.2)
        self.assertEqual(self.colours(), ['000000ff 1', '0000ff00 1'], 'BLUE before, GREEN only after the ACK')

    def test_the_mark_is_written_before_adsp_starts(self):
        self.bench.script('adsp', '#!/bin/sh\ncp "$(dirname "$0")/../sys/class/rtc/rtc0/wakealarm" "$(dirname "$0")/seen"\nexit 0\n')
        process = self.cycle()
        report = self.export()
        self.bench.ack(report)
        self.bench.read_log()
        result = self.finish(process)
        self.assertEqual(int(self.bench.text('test/seen')), result['mark_value'])

    def test_the_export_waits_for_the_host(self):
        process = self.cycle()
        self.assertFalse(select.select([self.bench.master], [], [], 0.5)[0], 'nothing before the hello')
        report = self.export()
        self.bench.ack(report)
        self.bench.read_log()
        self.assertEqual(self.finish(process)['end'], 0)

    def test_a_held_source_settles_before_the_machine_reads_it(self):
        self.bench.write('sys/class/wakeup/wakeup0/active_time_ms', '12\n')
        process = self.bench.start()
        time.sleep(0.2)
        self.assertFalse((self.bench.test / 'writer_started').exists())
        self.bench.write('sys/class/wakeup/wakeup0/active_time_ms', '0\n')
        self.cycle(process)
        report = self.export()
        self.assertTrue(report['pass'], report)
        self.bench.ack(report)
        self.bench.read_log()
        self.finish(process)
        self.assertIn('settle rc=0 active=0', self.bench.text('test/kmsg'))

    def test_a_source_that_stays_held_refuses_suspend(self):
        self.bench.write('sys/class/wakeup/wakeup0/active_time_ms', '12\n')
        process = self.bench.start()
        report = self.export()
        self.assertEqual(report['failure']['reason'], 'WAKE_ACTIVE')
        self.bench.ack(report)
        self.bench.read_log()
        result = self.finish(process)
        self.assertEqual(result['end'], 1)
        self.assertFalse((self.bench.test / 'writer_started').exists())
        self.assertEqual(self.mark_read(), {'state': 'PRESENT', 'outcome': 'FAILED_BEFORE_SUSPEND'})
        self.bench.wait('colours')
        time.sleep(0.2)
        self.assertEqual(self.colours()[-1], '00ffff00 1', 'YELLOW: evidence is home, the cycle did not pass')

    def test_a_real_udc_refuses_suspend(self):
        (self.bench.root / 'sys/class/udc/a600000.dwc3').mkdir()
        process = self.bench.start()
        report = self.export()
        self.assertEqual(report['failure']['reason'], 'USB_PRESENT')
        self.bench.ack(report)
        self.bench.read_log()
        self.finish(process)
        self.assertFalse((self.bench.test / 'writer_started').exists())
        self.assertIn('dir /sys/class/udc: dummy_udc.0', self.bench.text('test/kmsg'))
        self.assertIn('dir /sys/class/udc: a600000.dwc3', self.bench.text('test/kmsg'))

    def test_a_failed_colour_never_suspends(self):
        self.bench.script('display', '#!/bin/sh\necho "$1 $2" >> "$(dirname "$0")/colours"\nexit 2\n')
        process = self.bench.start()
        report = self.export()
        self.assertEqual((report['failure']['reason'], report['failure']['error']), ('PREFLIGHT_READ', -19))
        self.bench.ack(report)
        self.bench.read_log()
        self.finish(process)
        self.assertFalse((self.bench.test / 'writer_started').exists())
        self.assertEqual(self.mark_read()['outcome'], 'FAILED_BEFORE_SUSPEND')

    def test_a_missing_rtc_is_exported_not_held(self):
        (self.bench.root / 'sys/class/rtc/rtc0/name').unlink()
        process = self.bench.start()
        report = self.export()
        self.assertEqual(report['failure']['reason'], 'RTC_IDENTITY')
        self.bench.ack(report)
        self.bench.read_log()
        self.finish(process)
        self.assertFalse((self.bench.test / 'writer_started').exists())

    def test_bootstrap_failure_holds_before_anything_is_shown(self):
        self.bench.script('bootstrap', '#!/bin/sh\nexit 1\n')
        process = self.bench.start()
        self.assertEqual(self.finish(process)['end'], 3)
        self.assertEqual(self.colours(), [])

    def test_adsp_failure_holds_with_the_mark_kept(self):
        self.bench.script('adsp', '#!/bin/sh\nexit 1\n')
        process = self.cycle()
        result = self.finish(process)
        self.assertEqual(result['end'], 2)
        self.assertEqual(self.mark_read(), {'state': 'PRESENT', 'outcome': 'PASS'})
        self.bench.wait('colours')
        time.sleep(0.2)
        self.assertEqual(self.colours()[-1], '00ff0000 1', 'RED: resumed, evidence not exported')

    def test_connector_failure_holds_with_the_mark_kept(self):
        # Stdout stays open, as on the real binary: it reports the failure, then pauses.
        self.bench.script('connector', '#!/bin/sh\necho CONNECTOR_FAILED\nexec cat\n')
        began = time.monotonic()
        result = self.finish(self.cycle())
        self.assertEqual(result['end'], 2)
        self.assertLess(time.monotonic() - began, 8, 'held at once, not by running out the channel deadline')
        self.assertEqual(self.mark_read()['state'], 'PRESENT')

    def test_no_host_runs_out_the_channel_deadline(self):
        result = self.finish(self.cycle(self.bench.start(channel_s=20)))
        self.assertEqual(result['end'], 2)
        self.assertEqual(self.mark_read()['state'], 'PRESENT')

    def test_a_stuck_writer_touches_nothing(self):
        process = self.bench.start()
        self.bench.wait('writer_started')
        result = self.finish(process)
        self.assertEqual((result['end'], result['failure'], result['writer_active']), (2, 'WRITER_TIMEOUT', 1))
        self.assertEqual(self.bench.text('sys/class/rtc/rtc0/wakealarm'), '+45\n', 'the RTC is left alone')
        time.sleep(0.5)  # a colour child, if any, gets time to record itself
        self.assertEqual(len(self.colours()), 1, 'no colour while the transition is unresolved')

    def test_a_wrong_ack_changes_nothing(self):
        process = self.cycle()
        report = self.export()
        os.write(self.bench.master, b'M16ACK1 ' + b'0' * 64 + b'\n')
        os.write(self.bench.master, b'garbage line\n')
        self.bench.ack(report)
        fields, _ = self.bench.read_log()
        self.assertEqual(fields[0], 'M16LOG1')
        self.assertEqual(self.finish(process)['end'], 0)

    def test_resend_gives_identical_bytes(self):
        process = self.cycle()
        self.bench.hello()
        first = self.bench.read_wire()
        os.write(self.bench.master, b'M16RESEND1\n')
        second = self.bench.read_wire()
        self.assertEqual(first, second)
        self.bench.ack(host.decode(second))
        self.bench.read_log()
        self.assertEqual(self.finish(process)['end'], 0)


class Scope(unittest.TestCase):
    """Run1 cannot grow a path the milestone forbids."""
    SOURCES = ('run.c', 'run.h', 'pid1.c', 'display.c', 'load-rtc.c', 'init', 'bootstrap', 'adsp')

    def code(self):
        text = '\n'.join((HERE / name).read_text(encoding='utf-8') for name in self.SOURCES)
        return re.sub(r'/\*.*?\*/', '', text, flags=re.S)

    def test_no_reboot_or_sysrq_path(self):
        for forbidden in ('reboot', 'sysrq', 'kexec', 'poweroff', 'switch_root'):
            self.assertNotIn(forbidden, self.code())

    def test_no_control_or_partition_path(self):
        for forbidden in ('charge_', 'thermal', 'data_role', 'power_role', 'usb_role', '/dev/block', 'mmcblk',
                          'BLKRO', 'regulator', 'mount -t ext', 'mem_sleep'):
            self.assertNotIn(forbidden, self.code())

    def test_only_the_named_kernel_writes(self):
        code = (HERE / 'run.c').read_text(encoding='utf-8')
        self.assertEqual(set(re.findall(r'"(/sys[^"]+)"', code)), {'/sys/class/rtc/rtc0/since_epoch', '/sys/class/rtc/rtc0/wakealarm',
                                                                  '/sys/class/udc', '/sys/devices/system/cpu/cpu0/cpuidle'})
        self.assertEqual(code.count('O_WRONLY'), 2, 'only kmsg and the alarm are written')

    def test_adsp_keeps_the_m15_order(self):
        old = (HERE.parent.parent / 'm15/runtime/bootstrap').read_text(encoding='utf-8')
        new = (HERE / 'adsp').read_text(encoding='utf-8')
        begin, end = old.index('adsp=\n'), old.index('link=\n')
        wanted = re.sub(r'#.*\n', '', old[begin:end]).replace('/run/m15', '/run/m16')
        self.assertIn(wanted, new)

    def test_adsp_is_never_started_before_the_cycle(self):
        boot = (HERE / 'bootstrap').read_text(encoding='utf-8')
        for forbidden in ('remoteproc', 'firmware_class', 'adsp2'):
            self.assertNotIn(forbidden, boot)


def main():
    global ARGS
    parser = argparse.ArgumentParser()
    parser.add_argument('--driver', type=Path)
    ARGS, rest = parser.parse_known_args()
    unittest.main(argv=[sys.argv[0]] + rest, verbosity=2)


if __name__ == '__main__':
    main()
