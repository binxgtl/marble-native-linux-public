#!/usr/bin/env python3
"""M17 G5: the daily profile's changes (dailyplan.py): the plan checked on M19 R9's own plan as committed, and the count
shifts on texts holding the anchors they change. stage-g5.py applies the shifts to M19's committed scripts, each exactly
once, and inspect-g5.py checks the result line by line against what R9a staged. No device."""
import difflib
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/m17'))
sys.path.insert(0, str(ROOT / 'scripts/m19/run2'))
import dailyplan  # noqa: E402
import r9plan  # noqa: E402

CONTROL = 'm19/r8/root/run/systemd/system.control/'


def changed_lines(old, new):
    return [line for line in difflib.ndiff(old.splitlines(), new.splitlines()) if line[:2] in ('- ', '+ ')]


class Plan(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r9 = r9plan.render()
        cls.daily = dailyplan.plan(cls.r9)

    def test_only_the_daily_changes(self):
        changed = {name for name in set(self.r9) | set(self.daily) if self.r9.get(name) != self.daily.get(name)}
        self.assertEqual(changed, {'m19/r8/files', 'm19/r8/nodes', CONTROL + 'm19-r9.target', CONTROL + 'm19-r9-report.service',
                                   CONTROL + 'm17-session.service', CONTROL + 'm17-volkeys.service'})
        self.assertNotIn(CONTROL + 'm19-r9-report.service', self.daily)

    def test_target(self):
        text = self.daily[CONTROL + 'm19-r9.target'].decode()
        wants = re.search(r'^Wants=(.*)$', text, re.M).group(1).split()
        self.assertEqual(wants, ['multi-user.target', 'marble-wifi.service', 'm19-r3-guard.service', 'marble-xorg.service',
                                 'marble-xfce.service', 'marble-audio-log.service', 'm17-session.service', 'm17-volkeys.service'])
        self.assertEqual(changed_lines(self.r9[CONTROL + 'm19-r9.target'].decode(), text)[1::2][0][:14], '+ Description=')
        self.assertEqual(len(changed_lines(self.r9[CONTROL + 'm19-r9.target'].decode(), text)), 4)
        self.assertEqual(self.daily['m19/r8/default'], b'm19-r9.target\n')
        self.assertRegex(self.daily['m19/r8/default'].decode().strip(), r'^m19-r[0-9]\.target$')

    def test_units(self):
        session = self.daily[CONTROL + 'm17-session.service'].decode()
        volkeys = self.daily[CONTROL + 'm17-volkeys.service'].decode()
        self.assertIn('ExecStart=/run/m19/m19-report session\n', session)
        self.assertIn('Restart=no\n', session)
        self.assertIn('ExecStart=/run/m19/m19-report volkeys\n', volkeys)
        self.assertIn('Restart=always\nRestartSec=5\n', volkeys)
        guard = self.daily[CONTROL + 'm19-r3-guard.service'].decode()
        self.assertIn('ExecStart=/run/m19/m19-report guard\n', guard)
        # The units the session starts keep R9's text: their starts move, not their contents.
        for unit in ('marble-sink.service', 'marble-pulse.service', 'marble-ce.service'):
            self.assertEqual(self.daily[CONTROL + unit], self.r9[CONTROL + unit])

    def test_nodes_and_files(self):
        nodes = self.daily['m19/r8/nodes'].decode().splitlines()
        self.assertEqual(nodes, [line for line in self.r9['m19/r8/nodes'].decode().splitlines() if not line.startswith('ttyGS0 ')])
        self.assertEqual(len(nodes), 10)
        files = self.daily['m19/r8/files'].decode().split()
        old = self.r9['m19/r8/files'].decode().split()
        self.assertEqual(files, [f for f in old if f != 'run/systemd/system.control/m19-r9-report.service'] +
                         ['run/systemd/system.control/m17-session.service', 'run/systemd/system.control/m17-volkeys.service'])
        # run8's T9-root takes run/systemd/system.control/* and run/m19/* as they are, and nothing else here is new.
        for name in files:
            self.assertRegex(name, r'^[A-Za-z0-9@._/-]+$')
            self.assertIn('m19/r8/root/' + name, self.daily)

    def test_refuses_another_r9(self):
        other = dict(self.r9)
        other[CONTROL + 'm19-r9.target'] = other[CONTROL + 'm19-r9.target'].replace(b' m19-r9-report.service', b'')
        with self.assertRaises(AssertionError):
            dailyplan.plan(other)
        other = dict(self.r9)
        other['m19/r8/default'] = b'm19-r8.target\n'
        with self.assertRaises(AssertionError):
            dailyplan.plan(other)


class Counts(unittest.TestCase):
    """The shifts on texts holding exactly the anchors M19's audio stage and T9-gpu hold (stage-g5.py applies them to the
    scripts themselves; inspect-g5.py checks the result against R9a's)."""
    AUDIO = ('#!/bin/busybox sh\n# after the bootstrap has loaded its 102 modules\nloaded=102\n'
             '[ "$(count)" -eq 102 ] || hold "module count $(count)"\ncheck\n[ "$(count)" -eq 102 ] || hold "module count $(count)"\n'
             '  [ "$now" -ne 102 ] || skip "load $1 rc=$rc"\nphase audio 134\nphase machine 143\namps\nphase haptics 146\nphase transport 147\n')
    GPU = '#!/bin/busybox sh\n# on top of the 102 modules, or of 147\nbase=102\nif [ -e x ]; then\n base=147\nfi\n'

    def check(self, old, new, counts):
        self.assertTrue(new.startswith('#!/bin/busybox sh\n' + dailyplan.SHIFT_NOTE))
        lines = changed_lines(old, new)
        removed = [line[2:] for line in lines if line.startswith('- ')]
        added = [line[2:] for line in lines if line.startswith('+ ') and line[2:] + '\n' not in dailyplan.SHIFT_NOTE.splitlines(True)]
        self.assertEqual(len(removed), len(added))
        for before, after in zip(removed, added):
            numbers = re.findall(r'\b1[0-4][0-9]\b', before)
            self.assertEqual(len(numbers), 1, before)
            self.assertEqual(after, before.replace(numbers[0], str(int(numbers[0]) + dailyplan.KEY_ONLY)))
        self.assertEqual(sorted(int(n) for line in removed for n in re.findall(r'\b1[0-4][0-9]\b', line)), sorted(counts))

    def test_audio_stage(self):
        new = dailyplan.audio_stage(self.AUDIO)
        self.check(self.AUDIO, new, [102, 102, 102, 102, 134, 143, 146, 147])
        self.assertIn('# after the bootstrap has loaded its 102 modules\n', new)

    def test_t9_gpu(self):
        new = dailyplan.t9_gpu(self.GPU)
        self.check(self.GPU, new, [102, 147])
        self.assertIn('base=104\nif [ -e x ]; then\n base=149\n', new)

    def test_refuses_another_script(self):
        for text in ('#!/bin/busybox sh\nloaded=102\n', self.AUDIO.replace('phase machine 143\n', ''),
                     self.AUDIO.replace('#!/bin/busybox sh\n', '#!/bin/sh\n'), self.AUDIO + 'loaded=102\n'):
            with self.assertRaises(AssertionError):
                dailyplan.audio_stage(text)
        for text in ('#!/bin/sh\nbase=102\n base=147\n', self.GPU.replace(' base=147\n', ''), self.GPU + 'base=102\n'):
            with self.assertRaises(AssertionError):
                dailyplan.t9_gpu(text)


class SinkCopy(unittest.TestCase):
    """G5b: M17's sink stream and entry are M19 R6's byte for byte outside their marked probe blocks."""
    BEGIN, END = '/* M17 PROBE BEGIN */\n', '/* M17 PROBE END */\n'

    def unmarked(self, text):
        out, at = [], 0
        while True:
            begin = text.find(self.BEGIN, at)
            if begin < 0:
                return ''.join(out) + text[at:]
            end = text.find(self.END, begin)
            self.assertGreater(end, begin)
            self.assertNotIn(self.BEGIN, text[begin + len(self.BEGIN):end])
            out.append(text[at:begin])
            at = end + len(self.END)

    def test_copies(self):
        for mine, theirs, blocks in (('scripts/m17/sink-stream.c', 'scripts/m19/run6/stream.c', 5),
                                     ('scripts/m17/sink-main.c', 'scripts/m19/run6/sink-main.c', 3)):
            text = (ROOT / mine).read_text(encoding='utf-8')
            self.assertEqual(text.count(self.BEGIN), blocks, mine)
            self.assertEqual(text.count(self.END), blocks, mine)
            self.assertEqual(self.unmarked(text), (ROOT / theirs).read_text(encoding='utf-8'), mine)

    def test_probe_is_read_only(self):
        """The blocks send only the read command and the read, to the protection module, through the custodian."""
        text = (ROOT / 'scripts/m17/sink-stream.c').read_text(encoding='utf-8')
        blocks = ''.join(text[b:text.index(self.END, b)] for b in [i for i in range(len(text)) if text.startswith(self.BEGIN, i)])
        self.assertEqual(blocks.count('m11_custodian_cfg_observed('), 1)
        self.assertEqual(blocks.count('probe_round(s, '), 2)
        self.assertIn('probe_round(s, M11_APM_CMD_SET_CFG, cmd, m17_aw_status_cmd(cmd)', blocks)
        self.assertIn('probe_round(s, M11_APM_CMD_GET_CFG, req, m17_aw_status_req(req)', blocks)
        for word in ('m11_snd_ctl_set', 'gain_q15 =', 'peak_limit =', 'set_switches', 'amp_set(', 'm11_custodian_data_submit',
                     'm11_custodian_graph_cmd'):
            self.assertNotIn(word, blocks)


if __name__ == '__main__':
    unittest.main(verbosity=2)
