#!/usr/bin/env python3
"""M18 R2 (docs/m18-r2.md): plan_r2.py on R1's plan as committed (M19 R9's own plan through dailyplan.py and r1plan.py),
the startup signal's limits, and the governor and thermal scripts on synthetic trees. No device."""
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
import r1plan  # noqa: E402
import plan_r2 as r2plan  # noqa: E402  (scripts/m19/run2 has its own r2plan.py)
import r9plan  # noqa: E402

MODULE = b'\x7fELF' + b'\0' * 60 + b'name=qcom_tsens\0depends=qcom_ipc_logging\0'


def sources(names):
    return {name: (M18 / name).read_bytes() for name in names}


class Plan(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r1 = r1plan.plan(dailyplan.plan(r9plan.render()), sources(set(r1plan.SOURCES.values())))
        cls.r2 = r2plan.plan(cls.r1, sources(set(r2plan.SOURCES.values())), MODULE)

    def test_only_the_stated_changes(self):
        changed = sorted(k for k in self.r2 if k in self.r1 and self.r2[k] != self.r1[k])
        added = sorted(k for k in self.r2 if k not in self.r1)
        self.assertEqual(changed, sorted([r2plan.PLAN + 'files', r2plan.CONTROL + 'm19-r9.target']))
        self.assertEqual(added, sorted(r2plan.ROOT + n for n in list(r2plan.UNITS) + list(r2plan.SOURCES) + [r2plan.MODULE]))
        self.assertEqual(self.r2[r2plan.ROOT + r2plan.MODULE], MODULE)

    def test_units(self):
        target = self.r2[r2plan.CONTROL + 'm19-r9.target'].decode()
        self.assertIn(' m18-thermal.service m18-governor.service\n', target)
        for name, text in r2plan.UNITS.items():
            self.assertEqual(self.r2[r2plan.ROOT + name].decode(), text)
            self.assertIn('Type=exec\n', text)  # never holds the target's start
            self.assertNotIn('After=marble', text)
        self.assertIn('ExecStart=/bin/sh /run/m19/etc/m18-thermal\n', r2plan.UNITS['run/systemd/system.control/m18-thermal.service'])
        self.assertIn('ExecStart=/bin/sh /run/m19/etc/m18-governor\n', r2plan.UNITS['run/systemd/system.control/m18-governor.service'])

    def test_refuses_another_module(self):
        with self.assertRaises(AssertionError):
            r2plan.plan(self.r1, sources(set(r2plan.SOURCES.values())), MODULE.replace(b'qcom_tsens', b'qcom_other'))

    def test_signal_within_the_native_parser(self):
        s = r2plan.SIGNAL
        # the native plan parser's limits (M11's speaker plan parser, checked again by the local inspection):
        # 500 to 10000 ms, -40000 to -6000 mdBFS, at least one tone
        self.assertTrue(500 <= s['duration_ms'] <= 10000 and -40000 <= s['peak_mdbfs'] <= -6000 and s['tones_hz'])
        self.assertEqual(s['peak_mdbfs'], -40000)  # the quietest the parser allows
        self.assertEqual(s['tones_hz'], [50])
        self.assertEqual(s['duration_ms'], 500)
        # speaker_plan.synth_pcm's peak: int(32767 * 10 ** (peak_mdbfs / 20000)), 1 % of full scale
        self.assertEqual(int(32767 * 10 ** (s['peak_mdbfs'] / 1000 / 20)), 327)


def sh(script, env):
    return subprocess.run(['sh', str(M18 / script)], env={**os.environ, **env}, capture_output=True, text=True, timeout=60)


class Governor(unittest.TestCase):
    def tree(self, offered):
        d = Path(tempfile.mkdtemp())
        for i, gov in enumerate(offered):
            p = d / f'sys/devices/system/cpu/cpufreq/policy{i * 4}'
            p.mkdir(parents=True)
            (p / 'scaling_available_governors').write_text(gov + '\n')
            (p / 'scaling_governor').write_text('performance\n')
            (p / 'scaling_max_freq').write_text('2918400\n')
            if 'walt' in gov.split():
                (p / 'walt').mkdir()
                for f, v in (('hispeed_freq', '1651200'), ('hispeed_load', '90'), ('target_load_thresh', '1024'),
                             ('up_rate_limit_us', '0'), ('down_rate_limit_us', '0'), ('boost', '0')):
                    (p / 'walt' / f).write_text(v + '\n')
        (d / 'lib').mkdir()
        return d, {'M18_SYS': str(d / 'sys'), 'M18_LIB': str(d / 'lib')}

    def test_walt_where_offered(self):
        d, env = self.tree(['walt conservative powersave performance schedutil', 'conservative performance schedutil'])
        r = sh('governor', env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual((d / 'sys/devices/system/cpu/cpufreq/policy0/scaling_governor').read_text(), 'walt\n')
        self.assertEqual((d / 'sys/devices/system/cpu/cpufreq/policy4/scaling_governor').read_text(), 'schedutil\n')
        log = (d / 'lib/m18-tune.log').read_text()
        self.assertIn(' M18 governor policy0 before=performance offered=walt,conservative,powersave,performance,schedutil '
                      'set=walt now=walt max=2918400\n', log)
        self.assertIn(' M18 walt policy0 hispeed_freq=1651200 hispeed_load=90 target_load_thresh=1024 up_rate_limit_us=0 '
                      'down_rate_limit_us=0 boost=0\n', log)
        self.assertIn(' M18 governor policy4 before=performance offered=conservative,performance,schedutil set=schedutil now=schedutil', log)
        self.assertNotIn('M18 walt policy4', log)

    def test_never_performance(self):
        d, env = self.tree(['performance powersave'])
        r = sh('governor', env)
        self.assertEqual(r.returncode, 1)
        self.assertEqual((d / 'sys/devices/system/cpu/cpufreq/policy0/scaling_governor').read_text(), 'performance\n')
        self.assertIn(' set=none\n', (d / 'lib/m18-tune.log').read_text())

    def test_a_refused_write_fails(self):
        d, env = self.tree(['walt schedutil'])
        target = d / 'sys/devices/system/cpu/cpufreq/policy0/scaling_governor'
        target.chmod(0o444)
        if os.geteuid() == 0:
            self.skipTest('root writes anyway')
        r = sh('governor', env)
        self.assertEqual(r.returncode, 1)
        self.assertIn(' set=walt now=performance ', (d / 'lib/m18-tune.log').read_text())

    def test_no_policies_fails(self):
        d, env = self.tree([])
        r = sh('governor', env)
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn(' M18 governor policies=0 set=none\n', (d / 'lib/m18-tune.log').read_text())


class Thermal(unittest.TestCase):
    def tree(self, temps, loaded=False):
        d = Path(tempfile.mkdtemp())
        for i, t in enumerate(temps):
            z = d / f'sys/class/thermal/thermal_zone{i}'
            z.mkdir(parents=True)
            if t is not None:
                (z / 'temp').write_text(t + '\n')
        (d / 'proc').mkdir()
        (d / 'proc/modules').write_text('qcom_tsens 57344 0 - Live 0x0\n' if loaded else 'sched_walt 425984 9 - Live 0x0\n')
        (d / 'lib').mkdir()
        (d / 'insmod').write_text('#!/bin/sh\necho "$@" >>"$M18_TEST_CALLS"\nexit "${M18_TEST_RC:-0}"\n')
        (d / 'insmod').chmod(0o755)
        env = {'M18_SYS': str(d / 'sys'), 'M18_PROC': str(d / 'proc'), 'M18_LIB': str(d / 'lib'), 'M18_INSMOD': str(d / 'insmod'),
               'M18_MODULE': '/run/m19/etc/qcom_tsens.ko', 'M18_SETTLE': '0', 'M18_TEST_CALLS': str(d / 'calls')}
        return d, env

    def test_loads_and_counts(self):
        d, env = self.tree(['41000', '-273000', None, 'x', '32900'])
        r = sh('thermal', env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual((d / 'calls').read_text(), '/run/m19/etc/qcom_tsens.ko\n')
        self.assertIn(' M18 thermal qcom_tsens=now zones=5 readable=3\n', (d / 'lib/m18-tune.log').read_text())

    def test_already_loaded(self):
        d, env = self.tree(['41000'], loaded=True)
        self.assertEqual(sh('thermal', env).returncode, 0)
        self.assertFalse((d / 'calls').exists())
        self.assertIn(' qcom_tsens=already zones=1 readable=1\n', (d / 'lib/m18-tune.log').read_text())

    def test_a_failed_load(self):
        d, env = self.tree(['-', '-'])
        r = sh('thermal', {**env, 'M18_TEST_RC': '1'})
        self.assertEqual(r.returncode, 1)
        self.assertIn(' qcom_tsens=failed zones=2 readable=0\n', (d / 'lib/m18-tune.log').read_text())


if __name__ == '__main__':
    unittest.main(verbosity=1)
