#!/usr/bin/env python3
"""M18 R1 (docs/m18-performance-polish.md): the plan's changes on M17 G5's daily plan as committed (M19 R9's own plan
through scripts/m17/dailyplan.py), the copies' substitutions, and the scripts on synthetic trees. No device."""
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
M18 = ROOT / 'scripts/m18'
sys.path.insert(0, str(M18))
sys.path.insert(0, str(ROOT / 'scripts/m17'))
sys.path.insert(0, str(ROOT / 'scripts/m19/run2'))
import copies  # noqa: E402
import dailyplan  # noqa: E402
import r1plan  # noqa: E402
import r9plan  # noqa: E402


def sources():
    return {name: (M18 / name).read_bytes() for name in set(r1plan.SOURCES.values())}


class Plan(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.daily = dailyplan.plan(r9plan.render())
        cls.r1 = r1plan.plan(cls.daily, sources())

    def test_only_the_stated_changes(self):
        changed = sorted(k for k in self.r1 if k in self.daily and self.r1[k] != self.daily[k])
        added = sorted(k for k in self.r1 if k not in self.daily)
        control = r1plan.CONTROL
        self.assertEqual(changed, sorted([r1plan.PLAN + 'files', control + 'm17-session.service', control + 'm19-r9.target',
                                          control + 'marble-ce.service', control + 'marble-xfce.service']))
        self.assertEqual(added, sorted(r1plan.ROOT + name for name in list(r1plan.UNITS) + list(r1plan.SOURCES)))
        self.assertFalse(set(self.daily) - set(self.r1))

    def test_units(self):
        control = r1plan.CONTROL
        self.assertEqual(self.r1[control + 'marble-ce.service'].decode(), r1plan.CE)
        ce = r1plan.CE
        for script in ('m18-ce-ready', 'm18-ce-done'):
            self.assertIn(f'/bin/sh /run/m19/etc/{script}\n', ce)
            self.assertIn(r1plan.ETC + script, r1plan.SOURCES)
        self.assertNotIn('ConditionPathExists', ce)
        self.assertIn('ExecStart=/run/m19/m19-ce-prompt /run/m19/ce/ce.sock /run/m19/ce.result\n', ce)
        self.assertIn('ExecCondition=/bin/sh -c \'! grep -q "^M19_CE status=OK" /run/m19/ce.result 2>/dev/null\'\n', ce)
        xfce = self.r1[control + 'marble-xfce.service'].decode()
        self.assertIn(' XDG_DATA_DIRS=/run/m19/xdg-data:/usr/local/share:/usr/share\n', xfce)
        self.assertTrue(r1plan.ENTRY.startswith('run/m19/xdg-data/applications/'))
        target = self.r1[control + 'm19-r9.target'].decode()
        self.assertIn(' m18-perf.service m18-analyze.service\n', target)
        for name, text in r1plan.UNITS.items():
            self.assertEqual(self.r1[r1plan.ROOT + name].decode(), text)
            self.assertIn('Type=simple\n', text)  # never a oneshot the target's start would wait for
        self.assertIn('ExecStart=/bin/sh /run/m19/etc/m18-perf\n', r1plan.PERF)
        self.assertIn('ExecStart=/bin/sh /run/m19/etc/m18-analyze\n', r1plan.ANALYZE)
        files = self.r1[r1plan.PLAN + 'files'].decode().split()
        self.assertEqual(len(files), len(set(files)))

    def test_refuses_another_keypad_unit(self):
        other = dict(self.daily)
        other[r1plan.CONTROL + 'marble-ce.service'] = r1plan.R7_CE.replace('once', 'twice').encode()
        with self.assertRaises(AssertionError):
            r1plan.plan(other, sources())

    def test_entry(self):
        lines = (M18 / 'unlock-android.desktop').read_text(encoding='utf-8').splitlines()
        self.assertEqual(lines[0], '[Desktop Entry]')
        self.assertEqual([line for line in lines if line.startswith('Exec=')], ['Exec=systemctl start --no-block marble-ce.service'])
        self.assertEqual(lines.count('NoDisplay=false'), 1)  # ce-done hides the entry by this exact line
        self.assertIn('Type=Application', lines)


class Copies(unittest.TestCase):
    def test_check(self):
        for copy, (original, _) in copies.COPIES.items():
            self.assertTrue((ROOT / original).is_file(), original)
        subprocess.run([sys.executable, str(M18 / 'copies.py'), 'check'], check=True, capture_output=True)

    def test_the_daily_values(self):
        main = dict((old, new) for old, new, _ in copies.COPIES['scripts/m18/native-main.c'][1])
        self.assertEqual(main['.blue_ms = 3000,'], '.blue_ms = 0,')
        self.assertEqual(main['.ce_unit = "marble-ce.service",'], '.ce_unit = NULL,')
        boot = dict((old, (new, count)) for old, new, count in copies.COPIES['scripts/m18/native-bootstrap'][1])
        self.assertEqual(boot['/m19/payload.tar.xz'], ('/m19/payload.tar', 3))
        self.assertEqual(boot['$BB tar -xJpf '], ('$BB tar -xpf ', 1))


def sh(script, env, *args):
    return subprocess.run(['sh', str(M18 / script), *args], env={**os.environ, **env}, capture_output=True, text=True, timeout=60)


class CeReady(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.proc, self.run = self.dir / 'proc', self.dir / 'run'
        (self.run / 'ce').mkdir(parents=True)
        self.proc.mkdir()
        self.sock = self.run / 'ce/ce.sock'
        self.listener = None
        # a fake chroot: records its arguments and binds the socket, as the broker does
        self.chroot = self.dir / 'chroot'
        self.chroot.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >>"$M18_TEST_CALLS"\n'
                               'exec python3 -c "import socket,sys,time; s=socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET); '
                               's.bind(sys.argv[1]); time.sleep(3)" "$M18_TEST_SOCK"\n')
        self.chroot.chmod(0o755)
        self.calls = self.dir / 'calls'
        self.env = {'M18_PROC': str(self.proc), 'M18_RUN': str(self.run), 'M18_CHROOT': str(self.chroot), 'M18_WAIT': '50',
                    'M18_TEST_CALLS': str(self.calls), 'M18_TEST_SOCK': str(self.sock)}

    def tearDown(self):
        if self.listener:
            self.listener.close()

    def process(self, pid, cmdline=b'', island=False, binary=False):
        p = self.proc / str(pid)
        p.mkdir()
        (p / 'cmdline').write_bytes(cmdline)
        root = p / 'root'
        root.mkdir()
        if island or binary:
            (root / 'm19').mkdir()
            (root / 'm19/m19-ce').write_bytes(b'elf')
        if island:
            (root / 'm19-ce').mkdir()

    def listen(self):
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.listener.bind(str(self.sock))

    def test_reuses_the_boot_broker(self):
        self.process(10, b'/m19/m19-ce\0broker\0/m19-ce/ce.sock\0', island=True)
        self.listen()
        r = sh('ce-ready', self.env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('broker=boot pid=10', r.stderr)
        self.assertFalse(self.calls.exists())

    def test_starts_a_fresh_broker_in_the_island(self):
        self.process(5, b'/usr/bin/Xorg\0')
        self.process(6, b'/m19/m19-ce\0de\0', binary=True)  # the broker's binary, but no socket directory: not the island
        self.process(7, b'/vendor/bin/qseecomd\0', island=True)
        r = sh('ce-ready', self.env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('broker=fresh island=7', r.stderr)
        for _ in range(50):
            if self.calls.exists():
                break
            time.sleep(0.05)
        self.assertEqual(self.calls.read_text().split(), [str(self.proc / '7/root'), '/m19/m19-ce', 'broker', '/m19-ce/ce.sock'])

    def test_a_dead_brokers_socket_is_replaced(self):
        self.process(7, b'', island=True)
        self.sock.write_text('stale')
        r = sh('ce-ready', self.env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('broker=fresh', r.stderr)

    def test_only_a_broker_is_reused(self):
        self.process(9, b'/m19/m19-ce\0de\0')
        self.process(7, b'', island=True)
        self.listen()
        r = sh('ce-ready', self.env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('broker=fresh island=7', r.stderr)

    def test_a_broker_without_its_socket_is_not_reused(self):
        self.process(10, b'/m19/m19-ce\0broker\0/m19-ce/ce.sock\0')
        self.process(7, b'', island=True)
        r = sh('ce-ready', self.env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('broker=fresh island=7', r.stderr)

    def test_no_island(self):
        self.process(5, b'/usr/bin/Xorg\0')
        r = sh('ce-ready', self.env)
        self.assertEqual(r.returncode, 1)
        self.assertIn('broker=none why=no-island', r.stderr)

    def test_no_socket(self):
        self.process(7, b'', island=True)
        self.chroot.write_text('#!/bin/sh\nexit 0\n')
        r = sh('ce-ready', {**self.env, 'M18_WAIT': '5'})
        self.assertEqual(r.returncode, 1)
        self.assertIn('broker=none why=no-socket', r.stderr)

    def test_never_mentions_a_pin(self):
        text = (M18 / 'ce-ready').read_text()
        self.assertNotIn('PIN:', text)


class CeDone(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.run, self.lib = self.dir / 'run', self.dir / 'lib'
        (self.run / 'xdg-data/applications').mkdir(parents=True)
        self.lib.mkdir()
        self.entry = self.run / 'xdg-data/applications/m18-unlock-android.desktop'
        self.entry.write_bytes((M18 / 'unlock-android.desktop').read_bytes())
        self.env = {'M18_RUN': str(self.run), 'M18_LIB': str(self.lib)}

    def test_unlocked_hides_the_entry(self):
        (self.run / 'ce.result').write_text('M19_CE status=OK entries=3\n')
        self.assertEqual(sh('ce-done', self.env).returncode, 0)
        self.assertIn(' M18 ce M19_CE status=OK entries=3\n', (self.lib / 'm18-ce.log').read_text())
        self.assertIn('NoDisplay=true\n', self.entry.read_text())
        self.assertNotIn('NoDisplay=false', self.entry.read_text())

    def test_a_wrong_pin_keeps_the_entry(self):
        (self.run / 'ce.result').write_text('M19_CE status=GK_REJECTED\n')
        self.assertEqual(sh('ce-done', self.env).returncode, 0)
        self.assertIn('M18 ce M19_CE status=GK_REJECTED\n', (self.lib / 'm18-ce.log').read_text())
        self.assertIn('NoDisplay=false\n', self.entry.read_text())

    def test_no_result_and_odd_characters(self):
        self.assertEqual(sh('ce-done', self.env).returncode, 0)
        (self.run / 'ce.result').write_text('M19_CE status=CANCELLED;rm -rf /\n')
        self.assertEqual(sh('ce-done', self.env).returncode, 0)
        log = (self.lib / 'm18-ce.log').read_text().splitlines()
        self.assertTrue(log[0].endswith(' M18 ce none'))
        self.assertTrue(log[1].endswith(' M18 ce M19_CE status=CANCELLEDrm -rf '))
        self.assertIn('NoDisplay=false\n', self.entry.read_text())


class Recorder(unittest.TestCase):
    def tree(self):
        d = Path(tempfile.mkdtemp())
        sysfs, proc = d / 'sys', d / 'proc'
        for i, (cpus, freq, gov) in enumerate((('0 1 2', '1804800', 'walt'), ('3 4', '2419200', 'walt'))):
            p = sysfs / f'devices/system/cpu/cpufreq/policy{i * 3}'
            p.mkdir(parents=True)
            (p / 'related_cpus').write_text(cpus + '\n')
            (p / 'scaling_cur_freq').write_text(freq + '\n')
            (p / 'scaling_governor').write_text(gov + '\n')
        for i, (kind, temp) in enumerate((('cpu-0-0', '41000'), ('battery', '29500'))):
            z = sysfs / f'class/thermal/thermal_zone{i}'
            z.mkdir(parents=True)
            (z / 'type').write_text(kind + '\n')
            (z / 'temp').write_text(temp + '\n')
        b = sysfs / 'class/power_supply/battery'
        b.mkdir(parents=True)
        for name, v in (('voltage_now', '4100000'), ('current_now', '-350000'), ('capacity', '87'), ('temp', '295')):
            (b / name).write_text(v + '\n')
        (sysfs / 'class/kgsl/kgsl-3d0').mkdir(parents=True)
        (sysfs / 'class/kgsl/kgsl-3d0/gpuclk').write_text('220000000\n')
        proc.mkdir()
        (proc / 'uptime').write_text('123.45 400.00\n')
        (proc / 'loadavg').write_text('0.52 0.40 0.30 1/300 4000\n')
        (proc / 'meminfo').write_text('MemTotal: 11000000 kB\nMemFree:  1000 kB\nMemAvailable:    7654321 kB\n')
        return d, {'M18_SYS': str(sysfs), 'M18_PROC': str(proc), 'M18_LOG': str(d / 'perf.log'), 'M18_PERIOD': '0', 'M18_COUNT': '2'}

    def test_lines(self):
        d, env = self.tree()
        r = sh('perf-recorder', env)
        self.assertEqual(r.returncode, 0, r.stderr)
        lines = (d / 'perf.log').read_text().splitlines()
        self.assertEqual(lines[0], '123.45 M18 perf v1 period=0 policies=policy0(0.1.2),policy3(3.4), zones=cpu-0-0,battery,')
        self.assertEqual(lines[1], '123.45 cpu=1804800/walt,2419200/walt, gpu=220000000 tz=41000,29500, bat=4100000,-350000,87,295 '
                                   'load=0.52,0.40,0.30 mem=7654321')
        self.assertEqual(lines[2], lines[1])
        self.assertEqual(len(lines), 3)

    def test_absent_values_and_rotation(self):
        d, env = self.tree()
        (Path(env['M18_SYS']) / 'class/kgsl/kgsl-3d0/gpuclk').unlink()
        r = sh('perf-recorder', {**env, 'M18_LIMIT': '100', 'M18_COUNT': '3'})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(' gpu=- ', (d / 'perf.log').read_text())
        self.assertTrue((d / 'perf.log.1').exists())
        self.assertLess(len((d / 'perf.log').read_text()), 400)

    def test_reads_only(self):
        text = (M18 / 'perf-recorder').read_text()
        for word in ('echo ', '>"$SYS', '> "$SYS', 'tee ', 'scaling_setspeed', 'scaling_max_freq'):
            self.assertNotIn(word, text)
        self.assertEqual(text.count('>>"$LOG"'), 2)


class Analyze(unittest.TestCase):
    def test_log(self):
        d = Path(tempfile.mkdtemp())
        (d / 'systemctl').write_text('#!/bin/sh\necho running\n')
        (d / 'analyze').write_text('#!/bin/sh\necho "analyze $*"\n')
        for f in ('systemctl', 'analyze'):
            (d / f).chmod(0o755)
        (d / 'a.log').write_text('older\n')
        env = {'M18_LOG': str(d / 'a.log'), 'M18_ANALYZE': str(d / 'analyze'), 'M18_SYSTEMCTL': str(d / 'systemctl'), 'M18_LIMIT': '3'}
        self.assertEqual(sh('boot-analyze', env).returncode, 0)
        text = (d / 'a.log').read_text()
        self.assertRegex(text, r'^M18 analyze v1 boot=\S+ state=running waited=0\n== time\nanalyze time\n== blame\n'
                               r'analyze blame --no-pager\n== critical-chain\nanalyze critical-chain --no-pager\n$')
        self.assertEqual((d / 'a.log.1').read_text(), 'older\n')

    def test_gives_up_waiting(self):
        d = Path(tempfile.mkdtemp())
        (d / 'systemctl').write_text('#!/bin/sh\necho starting\n')
        (d / 'analyze').write_text('#!/bin/sh\nexit 1\n')
        for f in ('systemctl', 'analyze'):
            (d / f).chmod(0o755)
        env = {'M18_LOG': str(d / 'a.log'), 'M18_ANALYZE': str(d / 'analyze'), 'M18_SYSTEMCTL': str(d / 'systemctl'), 'M18_LIMIT': '2'}
        self.assertEqual(sh('boot-analyze', env).returncode, 0)
        self.assertIn('state=starting waited=2\n', (d / 'a.log').read_text())


if __name__ == '__main__':
    unittest.main(verbosity=1)
