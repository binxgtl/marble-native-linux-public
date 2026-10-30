#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Host negative tests, the C/Python oracle comparison and real-fork fixture runs. No device."""
import argparse
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import host  # noqa: E402

ARGS = None
SCALE = 20


def rechain(data):
    """Recomputes every link, so a forged wire fails on meaning rather than on hashes."""
    data = bytearray(data)
    nonce = bytes(data[20:36])
    head = hashlib.sha256(nonce + bytes(16) + bytes(host.BODY)).digest()
    count = struct.unpack_from('<I', data, 12)[0]
    for i in range(count):
        at = host.HEADER + i * host.RECORD
        head = hashlib.sha256(bytes(head) + bytes(data[at:at + host.BODY])).digest()
        data[at + host.BODY:at + host.RECORD] = head
    data[36:68] = head
    return bytes(data)


def records(data):
    return [data[host.HEADER + i * host.RECORD:host.HEADER + (i + 1) * host.RECORD]
            for i in range((len(data) - host.HEADER) // host.RECORD)]


def assemble(data, items):
    head = bytearray(data[:host.HEADER])
    struct.pack_into('<I', head, 12, len(items))
    body = bytearray()
    for seq, item in enumerate(items):
        item = bytearray(item)
        struct.pack_into('<I', item, 0, seq)
        body += item
    return rechain(bytes(head) + bytes(body))


def type_of(record):
    return host.NAME[struct.unpack_from('<H', record, 4)[0]]


def index_of(items, name):
    return next(i for i, item in enumerate(items) if type_of(item) == name)


class Wire(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pass_wire = (ARGS.out / 'pass.wire').read_bytes()
        cls.refused_wire = (ARGS.out / 'refused.wire').read_bytes()

    def rejected(self, data, reason=None):
        with self.assertRaises((host.Rejected, struct.error)) as caught:
            host.decode(data)
        if reason:
            self.assertIn(reason, str(caught.exception))

    def test_pass_wire(self):
        report = host.decode(self.pass_wire)
        self.assertTrue(report['pass'])
        self.assertEqual((report['verdict'], report['slept_ns'], report['alarm_left_enabled']), ('PASS', 40 * 10**9, 0))

    def test_refused_wire_is_valid_and_not_a_pass(self):
        report = host.decode(self.refused_wire)
        self.assertEqual(report['verdict'], 'ABORTED')
        self.assertFalse(report['pass'])

    def test_every_byte_is_covered(self):
        """Any single flipped bit in the header or a record is caught, without exception."""
        data = bytearray(self.pass_wire)
        for offset in range(0, len(data)):
            data[offset] ^= 0x10
            self.rejected(bytes(data))
            data[offset] ^= 0x10

    def test_length(self):
        self.rejected(self.pass_wire[:-1], 'wire length')
        self.rejected(self.pass_wire + b'\0', 'wire length')
        self.rejected(self.pass_wire[:50], 'short header')
        self.rejected(b'')

    def test_dropping_or_moving_any_record_is_rejected_even_when_rechained(self):
        items = records(self.pass_wire)
        for i in range(len(items)):
            self.rejected(assemble(self.pass_wire, items[:i] + items[i + 1:]))
        for i in range(len(items) - 1):
            moved = list(items)
            moved[i], moved[i + 1] = moved[i + 1], moved[i]
            self.rejected(assemble(self.pass_wire, moved))

    def test_duplicate_record(self):
        items = records(self.pass_wire)
        at = index_of(items, 'WRITER')
        self.rejected(assemble(self.pass_wire, items[:at + 1] + [items[at]] + items[at + 1:]))

    def test_records_after_the_seal(self):
        items = records(self.pass_wire)
        forged = bytearray(assemble(self.pass_wire, items + [items[-1]]))
        self.rejected(bytes(forged))

    def forge(self, name, edit):
        items = [bytearray(item) for item in records(self.pass_wire)]
        edit(items[index_of(items, name)])
        return assemble(self.pass_wire, items)

    def test_claimed_pass_without_the_evidence(self):
        def no_rtc(item):
            struct.pack_into('<Q', item, 24 + 3 * 8, 0)
        self.rejected(self.forge('COUNTERS_POST', no_rtc), 'evidence says WRONG_WAKE')

    def test_claimed_sleep_without_a_gap(self):
        items = [bytearray(item) for item in records(self.pass_wire)]
        boot = struct.unpack_from('<Q', items[index_of(items, 'COUNTERS_PRE')], 8)[0]
        for item in items[index_of(items, 'WRITER'):]:
            mono = struct.unpack_from('<Q', item, 16)[0]
            struct.pack_into('<Q', item, 8, boot + mono - struct.unpack_from('<Q', items[0], 16)[0])
        self.rejected(assemble(self.pass_wire, items))

    def test_slept_figure_must_match(self):
        def more(item):
            struct.pack_into('<Q', item, 24 + 8, 41 * 10**9)
        self.rejected(self.forge('VERDICT', more), 'slept_ns disagrees')

    def test_upgrading_a_verdict(self):
        items = [bytearray(item) for item in records(self.refused_wire)]
        struct.pack_into('<I', items[index_of(items, 'VERDICT')], 24, 1)
        self.rejected(assemble(self.refused_wire, items), 'evidence says ABORTED')

    def test_failure_blocks_pass(self):
        items = [bytearray(item) for item in records(self.pass_wire)]
        failure = bytearray(items[index_of(items, 'CLEANUP')])
        struct.pack_into('<H', failure, 4, host.EV['FAIL'])
        failure[24:88] = struct.pack('<IiI', 1, 0, 3) + bytes(52)
        struct.pack_into('<I', items[-1], 24, len(items))
        forged = assemble(self.pass_wire, items[:-2] + [failure] + items[-2:])
        report = host.decode(forged)
        self.assertEqual(report['failure']['reason'], 'CLOCK')
        self.assertFalse(report['pass'])

    def test_clock_rules(self):
        items = [bytearray(item) for item in records(self.pass_wire)]
        struct.pack_into('<Q', items[3], 8, 1)
        self.rejected(assemble(self.pass_wire, items), 'clock')

    def test_non_zero_padding(self):
        def dirty(item):
            item[87] = 1
        self.rejected(self.forge('PHASE', dirty), 'payload padding')
        def reserved(item):
            item[90] = 1
        self.rejected(self.forge('PHASE', reserved), 'reserved bytes')

    def test_header_fields(self):
        bad = bytearray(self.pass_wire)
        bad[0] = 0x4e
        self.rejected(bytes(bad), 'bad magic')
        bad = bytearray(self.pass_wire)
        struct.pack_into('<I', bad, 8, 64)
        self.rejected(bytes(bad), 'record size')
        bad = bytearray(self.pass_wire)
        struct.pack_into('<I', bad, 16, 1)
        self.rejected(bytes(bad), 'count')
        bad = bytearray(self.pass_wire)
        bad[90] = 1
        self.rejected(bytes(bad), 'header padding')

    def test_records_cannot_move_between_runs(self):
        bad = bytearray(self.pass_wire)
        bad[20] ^= 1
        self.rejected(bytes(bad), 'chain break at 0')


class Oracle(unittest.TestCase):
    def test_vectors_agree_across_both_implementations(self):
        table = json.loads((HERE / 'vectors.json').read_text(encoding='utf-8'))
        lines, cases = [], []
        for vector in table['vectors']:
            case = json.loads(json.dumps(table['base']))
            for key, value in vector['set'].items():
                if '.' in key:
                    side, field = key.split('.')
                    case[side][field] = value
                else:
                    case[key] = value
            flat = case['clock_pre'] + case['clock_post'] + case['expect'] + [case['writer_rc'], case['writer_errno']]
            for side in ('pre', 'post'):
                flat += [case[side][field] for field in host.COUNTERS]
            flat += case['idle_pre'] + case['idle_post']
            flat += [0] * (44 - len(flat))
            lines.append(' '.join(str(v) for v in flat))
            cases.append((vector, case))
        output = subprocess.run([str(ARGS.driver), 'oracle'], input='\n'.join(lines) + '\n', capture_output=True,
                                text=True, check=True).stdout.splitlines()
        self.assertEqual(len(output), len(cases))
        for (vector, case), line in zip(cases, output):
            with self.subTest(vector['name']):
                cycle = dict(case)
                cycle['clock_pre'], cycle['clock_post'] = tuple(case['clock_pre']), tuple(case['clock_post'])
                for key in ('idle_pre', 'idle_post'):
                    cycle[key] = [case[key][0]] + [case[key][1]] * 7
                verdict, slept = host.judge(cycle, tuple(case['expect']))
                c_verdict, c_slept = line.split()
                self.assertEqual(verdict, vector['verdict'], 'python')
                self.assertEqual(c_verdict, vector['verdict'], 'c')
                self.assertEqual(int(c_slept), vector['slept_ns'], 'c slept')
                self.assertEqual(slept, vector['slept_ns'], 'python slept')

    def test_s1_shows_why_success_alone_is_not_enough(self):
        """S1: 27 entries, 25 counted success, many aborted at once. Duration is the proof."""
        table = json.loads((HERE / 'vectors.json').read_text(encoding='utf-8'))
        case = json.loads(json.dumps(table['base']))
        case['clock_post'] = (case['clock_pre'][0] + 10**8, case['clock_pre'][1] + 10**8)
        case['clock_pre'] = tuple(case['clock_pre'])
        case['idle_pre'], case['idle_post'] = [0] * 8, [1] * 8
        self.assertEqual(host.judge(case, tuple(case['expect']))[0], 'NO_SLEEP')


class Mark(unittest.TestCase):
    """The real C encoder against the separate Python reader."""
    NOW = 80_076_948

    def encode(self, now, tag, code):
        done = subprocess.run([str(ARGS.driver), 'mark', str(now), str(tag), str(code)], capture_output=True, text=True)
        return int(done.stdout) if done.returncode == 0 else None

    def test_every_outcome_round_trips(self):
        for code in range(1, len(host.MARKS)):
            alarm = self.encode(self.NOW, 0xa5, code)
            read = host.read_mark(alarm, self.NOW + 300, 0xa5)
            self.assertEqual(read, {'state': 'PRESENT', 'outcome': host.MARKS[code]})

    def test_reserved_values_are_not_encoded(self):
        self.assertIsNone(self.encode(self.NOW, 0xa5, 0))
        self.assertIsNone(self.encode(self.NOW, 0xa5, len(host.MARKS)))
        self.assertIsNone(self.encode(self.NOW, 0, 1))
        self.assertIsNone(self.encode(2**32 - 1, 0xa5, 1))

    def test_absence_is_never_a_verdict(self):
        self.assertEqual(host.read_mark(None, self.NOW, 0xa5), {'state': 'ABSENT', 'outcome': None})

    def test_another_runs_mark_is_foreign(self):
        alarm = self.encode(self.NOW, 0xa5, 1)
        self.assertEqual(host.read_mark(alarm, self.NOW, 0x5a)['state'], 'FOREIGN')

    def test_unrelated_alarm_values_are_foreign(self):
        alarm = self.encode(self.NOW, 0xa5, 1)
        cases = (self.NOW - 1, self.NOW, self.NOW + 7201, 2**32 + alarm, alarm & ~15, alarm | 15)
        for value in cases:
            with self.subTest(value):
                self.assertEqual(host.read_mark(value, self.NOW, 0xa5)['state'], 'FOREIGN')

    def test_tag_zero_never_matches(self):
        self.assertEqual(host.read_mark(self.NOW + 4097, self.NOW, 0)['state'], 'FOREIGN')

    def test_a_mark_read_too_late_cannot_be_read_as_present(self):
        alarm = self.encode(self.NOW, 0xa5, 1)
        self.assertEqual(host.read_mark(alarm, alarm, 0xa5)['state'], 'FOREIGN')

    def test_the_widest_lead_is_read_and_nothing_past_it(self):
        now = 0x10000000 - 7200
        alarm = self.encode(now, 0xff, 9)
        self.assertEqual(alarm - now, 7200 + 0xff9)
        self.assertEqual(host.read_mark(alarm, now, 0xff)['state'], 'PRESENT')
        self.assertEqual(host.read_mark(alarm + 4096, now, 0xff)['state'], 'FOREIGN')


class Fixture:
    """Synthetic sysfs in the shape S1 recorded. Writes to state go to a pipe kept full,
    so the real writer child blocks in write() until this test says the kernel returned."""

    def __init__(self, root):
        self.root = Path(root)
        self.pipe = None
        (self.root / 'test').mkdir(parents=True)
        files = {
            'sys/power/state': 'freeze mem\n', 'sys/power/mem_sleep': 's2idle [deep]\n',
            'sys/power/wakeup_count': '41\n',
            'sys/power/suspend_stats/success': '0\n', 'sys/power/suspend_stats/fail': '0\n',
            'sys/power/suspend_stats/last_failed_errno': '0\n',
            'sys/class/rtc/rtc0/name': 'rtc-pm8xxx c42d000.qcom,spmi:qcom,pmk8350@0:rtc@6100\n',
            'sys/class/rtc/rtc0/wakealarm': '', 'sys/devices/system/cpu/online': '0-7\n',
            'sys/class/remoteproc/remoteproc0/state': 'offline\n',
            'sys/class/wakeup/wakeup0/active_time_ms': '0\n',
        }
        for name, text in files.items():
            self.write(name, text)
        # Present on the carrier with no hardware behind it, as Run1 and M8 U1 run 3 recorded.
        (self.root / 'sys/class/udc/dummy_udc.0').mkdir(parents=True)
        for cpu in range(8):
            self.write(f'sys/devices/system/cpu/cpu{cpu}/cpuidle/state1/s2idle/usage', '0\n')
        self.interrupts(0)
        self.state()

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='ascii')

    def interrupts(self, count):
        self.write('proc/interrupts', '           CPU0       CPU1\n'
                   f'260:  {count}  0  0  0  0  0  0  0  pmic_arb 25164545 Edge      pm8xxx_rtc_alarm\n')

    def state(self):
        path = self.root / 'test/state_fifo'
        os.mkfifo(path)
        self.pipe = os.open(path, os.O_RDWR | os.O_NONBLOCK)
        try:
            while True:
                os.write(self.pipe, bytes(4096))
        except BlockingIOError:
            pass

    def resume(self, slept_ns, irq=1, success=1):
        self.write('test/gap_ns', f'{slept_ns}\n')
        self.write('sys/power/suspend_stats/success', f'{success}\n')
        for cpu in range(8):
            self.write(f'sys/devices/system/cpu/cpu{cpu}/cpuidle/state1/s2idle/usage', f'{success}\n')
        self.interrupts(irq)
        if irq:
            self.write('sys/class/rtc/rtc0/wakealarm', '')
        os.read(self.pipe, 65536) # room for the blocked write: the kernel "returned"

    def close(self):
        if self.pipe is not None:
            os.close(self.pipe)
            self.pipe = None

    def wait(self, name, seconds=20):
        end = time.monotonic() + seconds
        while not (self.root / 'test' / name).exists():
            if time.monotonic() > end:
                raise TimeoutError(name)
            time.sleep(0.002)


class Integration(unittest.TestCase):
    """Real linux.c, real fork and real blocking writes, against the fixture tree."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix='m16-s2-'))
        self.fixture = Fixture(self.dir / 'tree')
        self.wire = self.dir / 'out.wire'

    def tearDown(self):
        self.fixture.close()
        shutil.rmtree(self.dir, ignore_errors=True)

    def start(self, timeout_ms=200):
        return subprocess.Popen([str(ARGS.driver), 'run', str(self.fixture.root), str(self.wire), str(SCALE), str(timeout_ms)],
                                stdout=subprocess.PIPE, text=True)

    def finish(self, process, seconds=30):
        # A writer left blocked in the kernel still holds stdout, so never wait for EOF.
        timer = threading.Timer(seconds, process.kill)
        timer.start()
        try:
            line = process.stdout.readline()
            self.assertEqual(process.wait(), 0)
        finally:
            timer.cancel()
            process.stdout.close()
        return json.loads(line)

    def verify_and_ack(self):
        self.fixture.wait('wire_done')
        report = host.decode(self.wire.read_bytes())
        (self.fixture.root / 'test/ack').write_text(report['head'], encoding='ascii')
        return report

    def armed_text(self):
        return (self.fixture.root / 'sys/class/rtc/rtc0/wakealarm').read_text(encoding='ascii')

    def test_complete_cycle(self):
        process = self.start()
        self.fixture.wait('writer_started')
        self.assertEqual(self.armed_text(), '+45\n')
        self.assertEqual((self.fixture.root / 'sys/power/wakeup_count').read_text(encoding='ascii'), '41\n')
        self.fixture.resume(40 * 10**9)
        report = self.verify_and_ack()
        result = self.finish(process)
        self.assertTrue(report['pass'], report)
        self.assertEqual((result['outcome'], result['verdict'], result['failure']), (1, 'PASS', 'NONE'))

    def test_a_blocked_kernel_never_blocks_pid1(self):
        """The writer stays in write(). The machine must still decide, and hold."""
        process = self.start()
        self.fixture.wait('writer_started')
        result = self.finish(process)
        self.assertEqual((result['outcome'], result['failure']), (3, 'WRITER_TIMEOUT'))
        self.assertEqual(result['release_rc'], -16, 'evidence is not released')
        self.assertFalse(self.wire.stat().st_size, 'no export while the kernel is unresolved')
        self.assertEqual(self.armed_text(), '+45\n', 'the RTC is left alone')

    def fails_before_suspend(self, reason):
        process = self.start()
        report = self.verify_and_ack()
        result = self.finish(process)
        self.assertEqual((result['outcome'], result['failure']), (2, reason))
        self.assertEqual(report['failure']['reason'], reason)
        self.assertFalse(report['pass'])
        self.assertFalse((self.fixture.root / 'test/writer_started').exists(), 'must not reach suspend')
        return report

    def test_usb_present(self):
        (self.fixture.root / 'sys/class/udc/a600000.dwc3').mkdir()
        self.fails_before_suspend('USB_PRESENT')
        self.assertEqual(self.armed_text(), '', 'never armed')

    def test_adsp_running(self):
        self.fixture.write('sys/class/remoteproc/remoteproc0/state', 'running\n')
        self.fails_before_suspend('ADSP_RUNNING')

    def test_held_wakeup_source(self):
        self.fixture.write('sys/class/wakeup/wakeup0/active_time_ms', '7395000\n')
        self.fails_before_suspend('WAKE_ACTIVE')

    def test_wrong_rtc(self):
        self.fixture.write('sys/class/rtc/rtc0/name', 'rtc-pm8xxx c42d000.qcom,spmi:qcom,pm8350@1:rtc@6000\n')
        self.fails_before_suspend('RTC_IDENTITY')

    def test_missing_freeze_label(self):
        self.fixture.write('sys/power/state', 'mem\n')
        self.fails_before_suspend('NO_FREEZE')

    def test_stale_alarm(self):
        self.fixture.write('sys/class/rtc/rtc0/wakealarm', '80076948\n')
        self.fails_before_suspend('ALARM_STALE')
        self.assertEqual(self.armed_text(), '80076948\n', 'not ours to clear')

    def test_blocking_wakeup_count_is_bounded_and_disarms(self):
        """S1 saw this read block for hours while USB held a wakeup source."""
        path = self.fixture.root / 'sys/power/wakeup_count'
        path.unlink()
        os.mkfifo(path)
        began = time.monotonic()
        process = self.start(timeout_ms=150)
        report = self.verify_and_ack()
        result = self.finish(process)
        self.assertLess(time.monotonic() - began, 10)
        self.assertEqual(result['failure'], 'WAKE_COUNT_READ')
        self.assertEqual(report['failure']['error'], -110)
        self.assertEqual(self.armed_text(), '0\n', 'disarmed')
        self.assertFalse((self.fixture.root / 'test/writer_started').exists())

    def test_unreadable_counter(self):
        (self.fixture.root / 'sys/power/suspend_stats/success').unlink()
        self.fails_before_suspend('COUNTERS')

    def test_kernel_write_error(self):
        """The write fails with nothing counted, which is not a refusal the kernel reported."""
        self.fixture.close()
        path = self.fixture.root / 'test/state_fifo'
        path.unlink()
        path.mkdir()
        process = self.start()
        report = self.verify_and_ack()
        result = self.finish(process)
        self.assertEqual(result['verdict'], 'INVALID')
        self.assertFalse(report['pass'])


class Scope(unittest.TestCase):
    """The offline code cannot grow a path the milestone forbids."""
    SOURCES = ('journal', 'oracle', 'machine', 'linux', 'mark')

    def text(self):
        return '\n'.join((HERE / f'{name}.{ext}').read_text(encoding='utf-8')
                         for name in self.SOURCES for ext in ('c', 'h'))

    def test_no_reboot_or_sysrq_path(self):
        code = re.sub(r'/\*.*?\*/', '', self.text(), flags=re.S)
        for forbidden in ('reboot(', 'sysrq', 'LINUX_REBOOT', 'kexec', 'poweroff', 'init_module'):
            self.assertNotIn(forbidden, code)

    def test_no_charging_thermal_role_or_partition_path(self):
        code = re.sub(r'/\*.*?\*/', '', self.text(), flags=re.S)
        for forbidden in ('power_supply', 'charge_', 'thermal', 'data_role', 'power_role', 'usb_role',
                          '/dev/block', 'mmcblk', 'BLKRO', 'regulator'):
            self.assertNotIn(forbidden, code)

    def test_only_three_kernel_writes(self):
        code = (HERE / 'linux.c').read_text(encoding='utf-8')
        targets = set(re.findall(r'write_text\(\w+,"([^"]+)"', code))
        self.assertEqual(targets, {'/sys/class/rtc/rtc0/wakealarm', '/sys/power/wakeup_count'})
        self.assertEqual(code.count('"/sys/power/state"'), 2, 'one read, one writer child')
        self.assertNotIn('mem_sleep",', code.replace('read_text(l,"/sys/power/mem_sleep",b', ''))

    def test_journal_has_no_io(self):
        code = (HERE / 'journal.c').read_text(encoding='utf-8')
        for forbidden in ('open(', 'read(', 'fopen', 'printf', 'malloc'):
            self.assertNotIn(forbidden, code.replace('sha_', ''))

    def test_the_mark_stays_out_of_the_machine(self):
        """Marks are written by the run around it, after the seal, never by the cycle itself."""
        for name in ('machine.c', 'machine.h', 'linux.c', 'linux.h'):
            self.assertNotIn('mark', (HERE / name).read_text(encoding='utf-8'))


def main():
    global ARGS
    parser = argparse.ArgumentParser()
    parser.add_argument('--driver', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    ARGS, rest = parser.parse_known_args()
    unittest.main(argv=[sys.argv[0]] + rest, verbosity=2)


if __name__ == '__main__':
    main()
