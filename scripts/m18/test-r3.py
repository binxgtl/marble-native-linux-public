#!/usr/bin/env python3
"""M18 R3 (docs/m18-r3.md): plan_r3.py on R2's plan as committed (M19 R9's own plan through dailyplan.py, r1plan.py
and plan_r2.py), and the mark script on a synthetic tree. No device."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
M18 = ROOT / 'scripts/m18'
sys.path.insert(0, str(M18))
sys.path.insert(0, str(ROOT / 'scripts/m17'))
sys.path.insert(0, str(ROOT / 'scripts/m19/run2'))
import dailyplan  # noqa: E402
import plan_r2  # noqa: E402
import plan_r3  # noqa: E402
import r1plan  # noqa: E402
import r9plan  # noqa: E402

MODULE = b'\x7fELF' + b'\0' * 60 + b'name=qcom_tsens\0'
BYE = b'\x7fELF\x02\x01' + b'\0' * 58 + b'%lld.%02ld M18 bye %s\n'


def sources(names):
    return {name: (M18 / name).read_bytes() for name in names}


class Plan(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        r1 = r1plan.plan(dailyplan.plan(r9plan.render()), sources(set(r1plan.SOURCES.values())))
        cls.r2 = plan_r2.plan(r1, sources(set(plan_r2.SOURCES.values())), MODULE)
        cls.r3 = plan_r3.plan(cls.r2, sources(set(plan_r3.SOURCES.values())), BYE)

    def test_only_the_stated_changes(self):
        c = plan_r3.CONTROL
        changed = sorted(k for k in self.r3 if k in self.r2 and self.r3[k] != self.r2[k])
        added = sorted(k for k in self.r3 if k not in self.r2)
        self.assertEqual(changed, sorted([plan_r3.PLAN + 'files', c + 'marble-sink.service', c + 'poweroff.target',
                                          c + 'm18-perf.service', c + 'm19-r9.target']))
        self.assertEqual(added, sorted(plan_r3.ROOT + n for n in list(plan_r3.UNITS) + list(plan_r3.SOURCES) + [plan_r3.BINARY]))
        self.assertEqual(self.r3[plan_r3.ROOT + plan_r3.BINARY], BYE)

    def test_sink(self):
        sink = self.r3[plan_r3.CONTROL + 'marble-sink.service'].decode()
        self.assertIn('ExecStart=@/run/m19/m19-sink @m19-sink\nExecStop=/bin/kill -TERM $MAINPID\n', sink)
        for keep in ('KillMode=none\n', 'SendSIGKILL=no\n', 'TimeoutStopSec=infinity\n'):
            self.assertIn(keep, sink)
        before = self.r2[plan_r3.CONTROL + 'marble-sink.service'].decode()
        self.assertEqual(sink.replace('ExecStart=@/run/m19/m19-sink @m19-sink\nExecStop=/bin/kill -TERM $MAINPID\n',
                                      'ExecStart=/run/m19/m19-sink\n'), before)

    def test_shutdown_units(self):
        c, r = plan_r3.CONTROL, plan_r3.ROOT
        self.assertIn('Requires=systemd-reboot.service\nWants=m18-bye.service\n', self.r3[c + 'poweroff.target'].decode())
        self.assertEqual(self.r3[r + plan_r3.DROPIN].decode(), '[Unit]\nWants=m18-bye.service\n')
        bye = self.r3[c + 'm18-bye.service'].decode()
        self.assertIn('DefaultDependencies=no\n', bye)
        self.assertIn('After=marble-xorg.service', bye)
        self.assertIn('ExecStart=@/run/m19/m18-bye @m18-bye\n', bye)
        self.assertIn('ExecStartPre=/usr/bin/install -m 0755 /run/m19/etc/m18-bye /run/m19/m18-bye\n', bye)
        self.assertNotIn('Conflicts=', bye)
        self.assertEqual(self.r3[r + plan_r3.MANAGER].decode(), '[Manager]\nDefaultTimeoutStopSec=10s\n')
        self.assertIn('ExecStop=/bin/sh /run/m19/etc/m18-mark shutdown-begins\n', self.r3[c + 'm18-perf.service'].decode())

    def test_refuses_a_bad_binary(self):
        with self.assertRaises(AssertionError):
            plan_r3.plan(self.r2, sources(set(plan_r3.SOURCES.values())), b'#!/bin/sh\n')


class Mark(unittest.TestCase):
    def run_mark(self, lib, *args):
        return subprocess.run(['sh', str(M18 / 'mark'), *args], env={**os.environ, 'M18_LIB': str(lib)}, capture_output=True, timeout=30)

    def test_marks(self):
        lib = Path(tempfile.mkdtemp())
        self.assertEqual(self.run_mark(lib, 'shutdown-begins').returncode, 0)
        self.assertEqual(self.run_mark(lib, 'odd;rm -rf /').returncode, 0)
        self.assertEqual(self.run_mark(lib).returncode, 0)
        self.assertEqual(self.run_mark(lib, ';;').returncode, 0)
        lines = (lib / 'm18-shutdown.log').read_text().splitlines()
        self.assertTrue(lines[0].endswith(' M18 mark shutdown-begins'))
        self.assertTrue(lines[1].endswith(' M18 mark oddrm-rf'))
        self.assertTrue(lines[2].endswith(' M18 mark none'))
        self.assertTrue(lines[3].endswith(' M18 mark none'))  # nothing left after the filter
        self.assertEqual(len(lines), 4)

    def test_never_fails(self):
        self.assertEqual(self.run_mark(Path('/nonexistent-m18'), 'x').returncode, 0)


if __name__ == '__main__':
    unittest.main(verbosity=1)
