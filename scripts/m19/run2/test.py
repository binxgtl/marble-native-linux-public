#!/usr/bin/env python3
"""R2 on synthetic trees: the hand-off, the reporter, T9 and the plan. No device, no real mount."""
import argparse
import difflib
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
import r4plan  # noqa: E402
import r5plan  # noqa: E402
import r6plan  # noqa: E402
import r7plan  # noqa: E402
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

    def test_the_island_is_spared_when_kept(self):
        with tempfile.TemporaryDirectory() as directory:
            proc = fake_proc(directory, {300: ('init', 0), 301: ('keystore2', 0), 302: ('m16-display', 0), 303: ('sh', 0)})
            island, elsewhere = Path(directory) / 'tee', Path(directory) / 'other'
            island.mkdir()
            elsewhere.mkdir()
            os.symlink(island, proc / '300' / 'root')
            os.symlink(island, proc / '301' / 'root')
            os.symlink(elsewhere, proc / '302' / 'root')
            env = dict(os.environ, M19_KEEP_ROOT=str(island))
            done = subprocess.run([ARGS.driver, 'sweep', str(proc), '99999', '1'], capture_output=True, text=True, timeout=10, env=env)
            self.assertIn('count 2', done.stdout)
            self.assertEqual(sorted(re.findall(r'signal (\d+) 9', done.stdout)), ['302', '303'])
            # A kept root that cannot be read spares nothing: the island's two now count.
            env['M19_KEEP_ROOT'] = str(Path(directory) / 'missing')
            done = subprocess.run([ARGS.driver, 'sweep', str(proc), '99999', '0'], capture_output=True, text=True, timeout=10, env=env)
            self.assertIn('count 2', done.stdout)

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

    def test_a_kept_island_is_neither_killed_nor_detached(self):
        island = self.root / 'tee'
        island.mkdir()
        os.symlink(island, self.proc / '300' / 'root')
        wire = Wire()
        record = self.root / 'record'
        env = dict(os.environ, ASAN_OPTIONS='detect_leaks=0', M19_KEEP_ROOT=str(island))
        subprocess.run([ARGS.driver, 'handoff', str(self.proc), str(self.newroot), str(island), str(self.root / 'kmsg'), wire.path, str(record)],
                       capture_output=True, text=True, timeout=30, env=env)
        lines = [line for line in wire.close().decode().splitlines() if line.startswith('M19STEP')]
        calls = record.read_text().splitlines()
        self.assertEqual(lines, ['M19STEP T10-handoff START', 'M19STEP T10-handoff OK 0 0'])
        actions = [call.split()[0] for call in calls if not call.startswith(('argv', 'envp'))]
        self.assertEqual(actions, ['signal', 'chdir', 'mount', 'chroot', 'chdir', 'execve', 'exec-done'])
        self.assertIn('signal 301 9', calls)
        self.assertNotIn('signal 300 9', calls)

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
dir=$(dirname "$0")
case "$1" in
 is-system-running) cat "$dir/state"; exit 0;;
 is-active) echo active; echo active; exit "${M19_ACTIVE_RC:-0}";;
 start)
  echo "start $2" >> "$dir/started"
  # R6b: the session's PulseAudio comes up when its unit starts; the unit's rc is judged on its own.
  if [ "$2" = marble-pulse.service ]; then : > "$dir/pulse-up"; exit "${M19_PULSE_RC:-0}"; fi
  [ ! -e "$dir/speaker.report.staged" ] || cp "$dir/speaker.report.staged" "$dir/../speaker.report"
  [ ! -e "$dir/sink.report.staged" ] || cp "$dir/sink.report.staged" "$dir/../sink.report"
  [ ! -e "$dir/sink.status.staged" ] || cp "$dir/sink.status.staged" "$dir/../sink.status"
  exit "${M19_START_RC:-0}";;
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


class Audio(ReportBase):
    """R5a: the card M11 Run12 registered, as the session sees it, read-only, and no sound node in /dev."""
    CARDS = ' 0 [ukeemtpsndcard ]: ukee-mtp-snd-c - ukee-mtp-snd-card\n                      ukee-mtp-snd-card\n'
    PCM = '00-00: MultiMedia1 (*) :  : playback 1 : capture 1\n00-01: MultiMedia2 (*) :  : playback 1\n'

    def setUp(self):
        super().setUp()
        (self.root / 'asound').mkdir()
        (self.root / 'asound/cards').write_text(self.CARDS)
        (self.root / 'asound/pcm').write_text(self.PCM)
        (self.root / 'sound-class/controlC0').mkdir(parents=True)
        (self.root / 'sound-class/controlC0/dev').write_text('116:0\n')

    def audio(self, env=None):
        data, colour = self.run_report(env=dict({'M19_TEST_AUDIO': '1'}, **(env or {})))
        fields, log, _ = self.parse(data)
        line = re.search(r'M19 R5 audio (.*)\n', log)
        return fields, log, dict(item.split('=') for item in line.group(1).split()) if line else None, colour

    def test_the_registered_card_passes_and_is_recorded(self):
        fields, log, audio, colour = self.audio()
        self.assertEqual(audio, {'card': '0', 'control': '1', 'playback': '1', 'capture': '1', 'snd_nodes': '0', 'audio_ok': '1'})
        self.assertEqual((fields[3], colour), ('1', GREEN))
        self.assertIn('M19 asound cards\n' + self.CARDS, log)
        self.assertIn('M19 asound pcm\n' + self.PCM, log)

        # R5b: an empty /dev/snd or a dangling udev by-path symlink holds no sound node and passes.
        (self.root / 'snd/by-path').mkdir(parents=True)
        (self.root / 'snd/by-path/platform-sound').symlink_to('../controlC0')
        fields, log, audio, colour = self.audio()
        self.assertEqual((audio['snd_nodes'], audio['audio_ok'], fields[3], colour), ('0', '1', '1', GREEN))
        self.assertIn('M19 snd-entry ', log)

    def test_without_audio_nothing_is_read_or_judged(self):
        shutil.rmtree(self.root / 'asound')
        fields, log, _ = self.parse(self.run_report()[0])
        self.assertNotIn('M19 R5 audio', log)
        self.assertEqual(fields[3], '1')

    def test_each_missing_piece_fails(self):
        cases = (
            ('cards', lambda: (self.root / 'asound/cards').unlink(), {'card': '-1'}),
            ('other card', lambda: (self.root / 'asound/cards').write_text(' 0 [other ]: other - other\n'), {'card': '-1'}),
            ('name on the long line only', lambda: (self.root / 'asound/cards').write_text(' 0 [x ]: x - x\n  ukee-mtp-snd-card\n'), {'card': '-1'}),
            ('control', lambda: (self.root / 'sound-class/controlC0/dev').unlink(), {'control': '0'}),
            ('control major', lambda: (self.root / 'sound-class/controlC0/dev').write_text('0:5\n'), {'control': '0'}),
            ('control garbage', lambda: (self.root / 'sound-class/controlC0/dev').write_text('116\n'), {'control': '0'}),
            ('capture', lambda: (self.root / 'asound/pcm').write_text('00-00: MultiMedia1 (*) :  : playback 1\n'), {'capture': '0'}),
            ('playback', lambda: (self.root / 'asound/pcm').write_text('00-00: MultiMedia1 (*) :  : capture 1\n'), {'playback': '0'}),
            ("another card's pcm", lambda: (self.root / 'asound/pcm').write_text('01-00: x : : playback 1 : capture 1\n'), {'playback': '0'}),
            ('a sound node in snd', lambda: ((self.root / 'snd').mkdir(), (self.root / 'snd/pcmC0D0p').write_text('')), {'snd_nodes': '1'}),
            ('a live symlink in snd/by-path', lambda: ((self.root / 'snd/by-path').mkdir(parents=True),
                                                       (self.root / 'snd/by-path/live').symlink_to(self.root / 'mountinfo')), {'snd_nodes': '1'}),
            ('a top-level sound file', lambda: (self.root / 'snd').write_text(''), {'snd_nodes': '1'}),
            ('a sound link', lambda: (self.root / 'snd').symlink_to(self.root / 'nowhere'), {'snd_nodes': '1'}))
        for name, change, want in cases:
            with self.subTest(name=name):
                self.setUp()
                change()
                fields, _, audio, colour = self.audio()
                self.assertEqual({key: audio[key] for key in want}, want)
                self.assertEqual((audio['audio_ok'], fields[3], colour), ('0', '0', YELLOW))

    def test_the_card_index_comes_from_its_own_line(self):
        (self.root / 'asound/cards').write_text(' 0 [other ]: other - other\n 1 [ukeemtpsndcard ]: ukee-mtp-snd-c - ukee-mtp-snd-card\n')
        (self.root / 'sound-class/controlC1').mkdir()
        (self.root / 'sound-class/controlC1/dev').write_text('116:32\n')
        (self.root / 'asound/pcm').write_text('00-00: x : : playback 1 : capture 1\n01-00: y : : playback 1 : capture 1\n')
        fields, _, audio, _ = self.audio()
        self.assertEqual((audio['card'], audio['audio_ok'], fields[3]), ('1', '1', '1'))


class SpeakerReport(Audio):
    """R5b T12-audio: reporter starts marble-speaker.service once, parses speaker.report, and checks the retaining holder."""
    SHA = 'e1a810a314ce467e4b3f8e49d9759bda21526f6402a303e315a614750b8daa95'

    def valid_fields(self):
        return {
            'ok': '1', 'pid': '4242', 'entry_phase': '7', 'fail_step': '0', 'rc': '0', 'session_rc': '0',
            'spk_stage': '22', 'spk_fail_step': '0', 'regions_mapped': '2',
            're_verified': '1', 're0_q12': '26099', 're1_q12': '28684',
            'volume_level': '8', 'duration_ms': '4000', 'pcm_bytes': '768000',
            'buffers_sent': '100', 'buffers_done': '100', 'bytes_played': '768000',
            'amp_on': '1', 'amp_off_verified': '1', 'teardown_rc': '0', 'pdr_seen': '0',
            'census_rc': '0', 'census_why': '0', 'ctl_writes': '6', 'ctl_readbacks': '10',
            'resources_busy': '1', 'ack_deferred': '0', 'terminal_action': '3',
            'anchors_held': '2', 'anchor_fds_open': '4', 'pool_held': '1',
            'regions_in_pool': '2', 'unmap_attempted': '0', 'plan_sha256': self.SHA,
        }

    def write_staged_report(self, overrides=None, drop=()):
        items = self.valid_fields()
        if overrides:
            items.update(overrides)
        for key in drop:
            items.pop(key, None)
        (self.test / 'speaker.report.staged').write_text(''.join(f'{k}={v}\n' for k, v in items.items()))

    def make_holder(self, pid=4242, state='S', fds=9):
        pdir = self.root / f'proc/{pid}'
        (pdir / 'fd').mkdir(parents=True, exist_ok=True)
        (pdir / 'stat').write_text(f'{pid} (m19-speaker) {state} 1 4242 4242 0 -1 0\n')
        for i in range(fds):
            (pdir / 'fd' / str(i)).symlink_to(self.root / 'mountinfo')

    def setUp(self):
        super().setUp()
        (self.root / 'dev-clean').mkdir()
        self.write_staged_report()
        self.make_holder()

    def run_speaker_report(self, env=None):
        merged = {'M19_TEST_AUDIO': '1', 'M19_TEST_SPEAKER': '1'}
        if env:
            merged.update(env)
        data, colour = self.run_report(env=merged)
        fields, log, steps = self.parse(data)
        audio_line = re.search(r'M19 R5 audio (.*)\n', log)
        spk_line = re.search(r'M19 R5 speaker (unit_rc=.*)\n', log)
        audio = dict(item.split('=') for item in audio_line.group(1).split()) if audio_line else None
        spk = dict(item.split('=') for item in spk_line.group(1).split()) if spk_line else None
        return fields, log, steps, audio, spk, colour

    def test_valid_playback_and_retaining_holder_pass(self):
        fields, log, steps, audio, spk, colour = self.run_speaker_report()
        self.assertEqual((self.test / 'started').read_text(), 'start marble-speaker.service\n')
        self.assertIn('M19STEP T12-audio START', steps)
        self.assertIn('M19STEP T12-audio OK 1 22 768000 1 9', steps)
        self.assertEqual((spk['speaker_ok'], audio['audio_ok'], fields[3], colour), ('1', '1', '1', GREEN))
        self.assertIn('M19 speaker report\nok=1\n', log)

    def test_every_speaker_gate_failure_is_rejected(self):
        bad_overrides = (
            ('ok=0', {'ok': '0'}),
            ('pid=1', {'pid': '1'}),
            ('entry_phase=6', {'entry_phase': '6'}),
            ('fail_step=1', {'fail_step': '1'}),
            ('rc=-1', {'rc': '-1'}),
            ('session_rc=-5', {'session_rc': '-5'}),
            ('spk_stage=21', {'spk_stage': '21'}),
            ('spk_fail_step=1', {'spk_fail_step': '1'}),
            ('regions_mapped=1', {'regions_mapped': '1'}),
            ('re_verified=0', {'re_verified': '0'}),
            ('re0_q12=0', {'re0_q12': '0'}),
            ('re1_q12=0', {'re1_q12': '0'}),
            ('volume_level=0', {'volume_level': '0'}),
            ('volume_level=9', {'volume_level': '9'}),
            ('duration_ms=0', {'duration_ms': '0'}),
            ('duration_ms=5001', {'duration_ms': '5001'}),
            ('pcm_bytes=0', {'pcm_bytes': '0', 'bytes_played': '0'}),
            ('buffers_sent=0', {'buffers_sent': '0', 'buffers_done': '0'}),
            ('buffers_done!=sent', {'buffers_done': '99'}),
            ('bytes_played!=pcm', {'bytes_played': '767996'}),
            ('amp_on=0', {'amp_on': '0'}),
            ('amp_off_verified=0', {'amp_off_verified': '0'}),
            ('teardown_rc=-5', {'teardown_rc': '-5'}),
            ('pdr_seen=1', {'pdr_seen': '1'}),
            ('census_rc=-1', {'census_rc': '-1'}),
            ('census_why=1', {'census_why': '1'}),
            ('resources_busy=0', {'resources_busy': '0'}),
            ('terminal_action=1', {'terminal_action': '1'}),
            ('anchors_held=1', {'anchors_held': '1'}),
            ('anchor_fds_open=3', {'anchor_fds_open': '3'}),
            ('pool_held=0', {'pool_held': '0'}),
            ('regions_in_pool=1', {'regions_in_pool': '1'}),
            ('unmap_attempted=1', {'unmap_attempted': '1'}),
            ('bad_sha_upper', {'plan_sha256': self.SHA.upper()}),
            ('bad_sha_short', {'plan_sha256': self.SHA[:-1]}),
            ('non_int', {'bytes_played': '768000x'}),
        )
        for label, ov in bad_overrides:
            with self.subTest(label=label):
                self.setUp()
                self.write_staged_report(overrides=ov)
                fields, _, steps, audio, spk, colour = self.run_speaker_report()
                self.assertEqual((spk['speaker_ok'], audio['audio_ok'], fields[3], colour), ('0', '0', '0', YELLOW))
                self.assertTrue(any(s.startswith('M19STEP T12-audio FAIL ') for s in steps))

        # Missing required key (e.g. teardown_rc omitted -> stays LONG_MIN, never defaults to 0!)
        self.setUp()
        self.write_staged_report(drop=('teardown_rc',))
        fields, _, _, audio, spk, colour = self.run_speaker_report()
        self.assertEqual((spk['speaker_ok'], audio['audio_ok'], fields[3], colour), ('0', '0', '0', YELLOW))

        # Unit start failure, missing report, zombie holder, too few holder fds, dirty private node
        extra = (
            ('unit_rc', lambda: None, {'M19_START_RC': '1'}),
            ('missing_report', lambda: (self.test / 'speaker.report.staged').unlink(), {}),
            ('zombie_holder', lambda: (shutil.rmtree(self.root / 'proc/4242'), self.make_holder(state='Z')), {}),
            ('few_fds', lambda: (shutil.rmtree(self.root / 'proc/4242'), self.make_holder(fds=7)), {}),
            ('dirty_priv_node', lambda: (self.root / 'dev-clean/m11-snd').symlink_to('/missing'), {}),
        )
        for label, change, env in extra:
            with self.subTest(label=label):
                self.setUp()
                change()
                fields, log, steps, audio, spk, colour = self.run_speaker_report(env=env)
                self.assertEqual((spk['speaker_ok'], audio['audio_ok'], fields[3], colour), ('0', '0', '0', YELLOW))
                if label == 'missing_report':
                    self.assertTrue(any(s.startswith('M19BEAT T12-audio ') for s in steps))
                if label == 'dirty_priv_node':
                    self.assertEqual(spk['private_clean'], '0')
                    self.assertIn('M19 R5 speaker-dirty ', log)



# R6: the session's PulseAudio, faked. pactl answers from files; pacat plays the tone into the fake sink's counters as
# m19-sink would: loud bytes, the amplifier on, then, after the silence, off again.
PACTL = """#!/bin/sh
d=$(dirname "$0")
[ "${M19_TEST_PULSE:-}" = 1 ] || exit 9
[ -e "$d/pulse-up" ] || exit 1
case "$1 $2" in
 'list short') cat "$d/sinks" 2>/dev/null; exit 0;;
 'get-default-sink ') cat "$d/default-sink" 2>/dev/null; exit 0;;
esac
exit 1
"""
PACAT = """#!/bin/sh
d=$(dirname "$0")
[ "${M19_TEST_PULSE:-}" = 1 ] || exit 9
[ -e "$d/pulse-up" ] || exit 1
for last; do :; done
echo "$*" > "$d/pacat-args"
[ "$(wc -c < "$last")" -eq 192000 ] || exit 8
loud=${M19_TONE_LOUD:-192000}
peak_in=${M19_TONE_PEAK_IN:-32767}
peak_out=${M19_TONE_PEAK_OUT:-10361}
enables=${M19_TONE_ENABLES:-1}
printf 'streaming=1\\namp_on=1\\nstopped=0\\nbuffers=60\\nbytes_in=%s\\nbytes_loud=%s\\nunderruns=0\\namp_enables=%s\\namp_disables=1\\npeak_in=%s\\npeak_out=%s\\n' "$loud" "$loud" "$enables" "$peak_in" "$peak_out" > "$d/../sink.status"
if [ -z "${M19_TONE_STAYS_ON:-}" ]; then
 (sleep 0.3; printf 'streaming=1\\namp_on=0\\nstopped=0\\nbuffers=90\\nbytes_in=%s\\nbytes_loud=%s\\nunderruns=0\\namp_enables=%s\\namp_disables=2\\npeak_in=%s\\npeak_out=%s\\n' "$loud" "$loud" "$enables" "$peak_in" "$peak_out" > "$d/../sink.status.new" && mv "$d/../sink.status.new" "$d/../sink.status") &
fi
exit "${M19_PACAT_RC:-0}"
"""


class SinkReport(Audio):
    """R6 T12-audio: the sound server's chord, judged at the switch to the stream, then a tone through PulseAudio."""
    SHA = 'e1a810a314ce467e4b3f8e49d9759bda21526f6402a303e315a614750b8daa95'

    def setUp(self):
        super().setUp()
        for name, text in (('pactl', PACTL), ('pacat', PACAT)):
            (self.test / name).write_text(text)
            (self.test / name).chmod(0o755)
        (self.test / 'sinks').write_text('0\tmarble_speaker\tmodule-pipe-sink.c\ts16le 2ch 48000Hz\tIDLE\n')
        (self.test / 'default-sink').write_text('marble_speaker\n')
        (self.root / 'proc/4242/fd').mkdir(parents=True)
        (self.root / 'proc/4242/stat').write_text('4242 (m19-sink) S 1 4242 4242 0 -1\n')
        for i in range(10):
            os.symlink('/dev/null', self.root / 'proc/4242/fd' / str(i))
        self.write_report()
        self.write_status()

    def report_fields(self):
        return {'state': 'streaming', 'chord_ok': '1', 'ok': '0', 'pid': '4242', 'entry_phase': '6', 'regions_mapped': '2', 're_verified': '1',
                're0_q12': '26099', 're1_q12': '28684', 'volume_level': '8', 'pcm_bytes': '768000', 'bytes_played': '768000',
                'pdr_seen': '0', 'unmap_attempted': '0', 'plan_sha256': self.SHA, 'streaming': '1'}

    def write_report(self, overrides=None, drop=()):
        items = dict(self.report_fields(), **(overrides or {}))
        (self.test / 'sink.report.staged').write_text(''.join(f'{k}={v}\n' for k, v in items.items() if k not in drop))

    def write_status(self, amp_on='0'):
        (self.test / 'sink.status.staged').write_text(f'streaming=1\namp_on={amp_on}\nstopped=0\nbuffers=10\nbytes_in=0\nbytes_loud=0\n'
                                                      'underruns=0\namp_enables=0\namp_disables=1\npeak_in=0\npeak_out=0\n')

    def sink(self, env=None):
        data, colour = self.run_report(env=dict({'M19_TEST_AUDIO': '1', 'M19_TEST_SINK': '1'}, **(env or {})))
        fields, log, steps = self.parse(data)
        line = re.search(r'M19 R6 sink (.*)\n', log)
        return fields, log, dict(item.split('=', 1) for item in line.group(1).split()) if line else None, steps

    def test_the_chord_then_a_tone_through_pulseaudio_passes(self):
        fields, log, k, steps = self.sink()
        self.assertEqual(k['sink_ok'], '1', log)
        self.assertEqual((k['streaming'], k['chord_ok'], k['pulse_sink'], k['pulse_default'], k['tone_rc'], k['amp_off_before'], k['tone_loud'],
                          k['tone_peaks'], k['amp_on_seen'], k['amp_idle_off']), ('1', '1', '1', '1', '0', '1', '1', '1', '1', '1'))
        self.assertEqual((k['loud'], k['enables'], k['disables'], k['peak_in'], k['peak_out']), ('192000', '1', '1', '32767', '10361'))
        self.assertEqual(self.verdict(log)['all_ok'], '1')
        # R6b: PulseAudio only after the sink streams.
        self.assertEqual((self.test / 'started').read_text(), 'start marble-sink.service\nstart marble-pulse.service\n')
        self.assertEqual((k['pulse_unit_rc'], k['private_clean'], k['held_empty']), ('0', '1', '0'))
        self.assertIn('--playback --raw --format=s16le --rate=48000 --channels=2 --latency-msec=100 --device=marble_speaker ',
                      (self.test / 'pacat-args').read_text())
        self.assertEqual(len((self.root / 'sink-tone.raw').read_bytes()), 192000)
        self.assertIn('M19 sink report\n', log)
        self.assertIn('M19 sink status\n', log)
        self.assertTrue(any(step.startswith('M19STEP T12-audio OK') for step in steps), steps)

    def test_each_failure_fails(self):
        cases = (({'M19_START_RC': '1'}, None, None), ({}, {'state': 'failed'}, None), ({}, {'chord_ok': '0'}, None),
                 ({}, {'regions_mapped': '1'}, None), ({}, {'re_verified': '0'}, None), ({}, {'bytes_played': '767996'}, None),
                 ({}, {'pdr_seen': '1'}, None), ({}, {'unmap_attempted': '1'}, None), ({}, {'volume_level': '9'}, None),
                 ({}, {'plan_sha256': 'x'}, None), ({}, {'pid': '99'}, None), ({}, {'streaming': '0'}, None),
                 ({'M19_PACAT_RC': '1'}, None, None), ({'M19_TONE_LOUD': '100000'}, None, None), ({'M19_TONE_PEAK_IN': '20000'}, None, None),
                 ({'M19_TONE_PEAK_OUT': '10363'}, None, None), ({'M19_TONE_PEAK_OUT': '5000'}, None, None), ({'M19_TONE_ENABLES': '0'}, None, None),
                 ({'M19_TONE_STAYS_ON': '1'}, None, None), ({}, None, 'sinks'), ({}, None, 'default-sink'), ({}, None, 'amp-on'))
        for env, report, fixture in cases:
            with self.subTest(env=env, report=report, fixture=fixture):
                self.setUp()
                if report:
                    self.write_report(report)
                if fixture == 'sinks':
                    (self.test / 'sinks').write_text('0\tauto_null\tmodule-null-sink.c\n')
                elif fixture == 'default-sink':
                    (self.test / 'default-sink').write_text('auto_null\n')
                elif fixture == 'amp-on':
                    self.write_status(amp_on='1')
                fields, log, k, _ = self.sink(env)
                self.assertEqual(k['sink_ok'], '0', log)
                self.assertEqual(self.verdict(log)['all_ok'], '0')

    def test_a_dead_holder_or_another_default_sink_fails_on_its_own(self):
        (self.root / 'proc/4242/stat').write_text('4242 (m19-sink) Z 1 4242 4242 0 -1\n')
        fields, log, k, _ = self.sink()
        self.assertEqual((k['holder_alive'], k['holder_fds'], k['tone_loud'], k['sink_ok']), ('0', '10', '1', '0'))
        self.setUp()
        (self.test / 'default-sink').write_text('auto_null\n')
        fields, log, k, _ = self.sink()
        # The tone still reaches the sink by name; only the default fails.
        self.assertEqual((k['pulse_sink'], k['pulse_default'], k['tone_loud'], k['tone_peaks'], k['amp_idle_off'], k['sink_ok']),
                         ('1', '0', '1', '1', '1', '0'))

    def test_a_private_node_fails(self):
        (self.root / 'dev-clean').mkdir()
        (self.root / 'dev-clean/m11-snd').write_text('')
        fields, log, k, _ = self.sink()
        self.assertEqual((k['private_clean'], k['held_empty'], k['sink_ok']), ('0', '0', '0'))
        self.assertIn('M19 R6 sink-dirty ', log)

    def held(self, mode=0o700, entry=False):
        (self.root / 'dev-clean').mkdir(exist_ok=True)
        held = self.root / 'dev-clean/m11-snd'
        held.mkdir()
        if entry:
            (held / 'pcmC0D0p').write_text('')
        held.chmod(mode)
        self.addCleanup(lambda: held.chmod(0o700))
        return held

    def test_runs31_empty_private_directory_passes_while_streaming(self):
        # R6a: the stream holds Run31's private directory, its nodes unlinked as they were opened.
        self.held()
        fields, log, k, _ = self.sink()
        self.assertEqual((k['private_clean'], k['held_empty'], k['sink_ok']), ('1', '1', '1'), log)
        self.assertIn('M19 R6 sink-held ', log)
        self.assertNotIn('sink-dirty', log)

    def test_any_other_private_directory_fails(self):
        cases = (('mode', {'mode': 0o755}, {}, None), ('entry', {'entry': True}, {}, None), ('owner', {}, {'M19_TEST_HELD_UID': str(os.getuid() + 1)}, None),
                 ('not-streaming', {}, {}, {'state': 'failed'}), ('another-path', None, {}, None), ('link', 'link', {}, None))
        for label, shape, env, report in cases:
            with self.subTest(label=label):
                self.setUp()
                if shape == 'link':
                    (self.root / 'dev-clean').mkdir()
                    (self.root / 'elsewhere').mkdir(mode=0o700)
                    (self.root / 'dev-clean/m11-snd').symlink_to(self.root / 'elsewhere')
                elif shape is None:
                    (self.root / 'dev-clean').mkdir()
                    (self.root / 'dev-clean/m11-heap').mkdir(mode=0o700)
                else:
                    self.held(**shape)
                if report:
                    self.write_report(report)
                fields, log, k, _ = self.sink(env)
                self.assertEqual((k['private_clean'], k['held_empty'], k['sink_ok']), ('0', '0', '0'), log)
                self.assertIn('M19 R6 sink-dirty ', log)

    def test_pulseaudio_starts_only_once_the_sink_streams_and_its_unit_is_judged(self):
        fields, log, k, _ = self.sink({'M19_PULSE_RC': '1'})
        # The server came up, the tone played; the unit's failure alone fails the step (its wait status: exit 1 is 256).
        self.assertEqual((k['pulse_unit_rc'], k['pulse_sink'], k['tone_loud'], k['sink_ok']), ('256', '1', '1', '0'), log)
        for report in ({'state': 'failed'}, {'streaming': '0'}):
            with self.subTest(report=report):
                self.setUp()
                self.write_report(report)
                fields, log, k, _ = self.sink()
                self.assertEqual((self.test / 'started').read_text(), 'start marble-sink.service\n')
                self.assertEqual((k['pulse_unit_rc'], k['pulse_sink'], k['sink_ok']), ('-1', '0', '0'))


ROUTE_HEAD = 'Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n'
NMCLI = """#!/bin/sh
d=$(dirname "$0")
echo "$*" >> "$d/nmcli-args"
cat "$d/nm-devices"
"""
GETENT = '#!/bin/sh\nexit "${M19_DNS_RC:-0}"\n'


class CeReport(ReportBase):
    """R7 T12-ce: the keypad's recorded broker status and Android's own names in /data/media/0; no name printed."""

    def setUp(self):
        super().setUp()
        self.android = self.root / 'android0'
        self.android.mkdir()
        for name in ('Android', 'DCIM', 'Private holiday photos'):
            (self.android / name).mkdir()
        (self.root / 'ce.result').write_text('M19_CE status=OK detail=0 version=3 timeout=0\n')

    def ce(self, wait_ms='600'):
        data, colour = self.run_report(env={'M19_TEST_CE': wait_ms})
        fields, log, steps = self.parse(data)
        line = re.search(r'M19 R7 ce (.*)\n', log)
        return log, dict(item.split('=', 1) for item in line.group(1).split()) if line else None, steps

    def test_unlocked_storage_passes_without_names(self):
        log, e, steps = self.ce()
        self.assertEqual((e['status'], e['entry_seen'], e['entries'], e['ce_ok']), ('OK', '1', '3', '1'))
        self.assertEqual(self.verdict(log)['all_ok'], '1')
        self.assertIn('start marble-ce.service', (self.test / 'started').read_text())
        self.assertIn('M19STEP T12-ce OK OK 1 3', steps)
        self.assertNotIn('holiday', log)
        self.assertNotIn('DCIM', log)

    def test_each_missing_piece_fails(self):
        for change in ('rejected', 'cancelled', 'garbled', 'no-result', 'encrypted-names', 'no-storage'):
            with self.subTest(change=change):
                self.setUp()
                if change == 'rejected':
                    (self.root / 'ce.result').write_text('M19_CE status=GK_REJECTED detail=-1 version=3 timeout=0\n')
                elif change == 'cancelled':
                    (self.root / 'ce.result').write_text('M19_CE status=CANCELLED\n')
                elif change == 'garbled':
                    (self.root / 'ce.result').write_text('status=OK\n')
                elif change == 'no-result':
                    (self.root / 'ce.result').unlink()
                elif change == 'encrypted-names':
                    (self.android / 'Android').rmdir()
                    (self.android / 'AAAAAAAAAAAAAAAAAAAAAA').mkdir()
                else:
                    shutil.rmtree(self.android)
                log, e, steps = self.ce(wait_ms='300')
                self.assertEqual(e['ce_ok'], '0', change)
                self.assertEqual(self.verdict(log)['all_ok'], '0')
                if change in ('encrypted-names', 'no-storage'):
                    self.assertEqual(e['status'], 'OK')
                if change == 'no-storage':
                    self.assertEqual(e['entries'], '-1')

    def test_a_missing_result_is_waited_for(self):
        (self.root / 'ce.result').unlink()
        start = time.monotonic()
        log, e, steps = self.ce(wait_ms='800')
        self.assertGreaterEqual(time.monotonic() - start, 0.8)
        self.assertEqual((e['result_seen'], e['status'], e['ce_ok']), ('0', 'none', '0'))


class WifiReport(ReportBase):
    """R6 T12-wifi: m19-wifi's result, NetworkManager's state, the default route, its gateway's echo; nothing named."""

    def setUp(self):
        super().setUp()
        for name, text in (('nmcli', NMCLI), ('getent', GETENT)):
            (self.test / name).write_text(text)
            (self.test / name).chmod(0o755)
        (self.root / 'wifi.result').write_text('ready lo\n')
        (self.root / 'wifi.report').write_text('step=ready\nrc=0\nbdf=0000:01:00.0\niface=lo\n')
        (self.test / 'nm-devices').write_text('lo:wifi:connected\nusb0:ethernet:unmanaged\n')
        # The loopback address, little-endian as the kernel prints it.
        (self.root / 'route').write_text(ROUTE_HEAD + 'lo\t00000000\t0100007F\t0003\t0\t0\t600\t00000000\t0\t0\t0\n')
        # 'Hi Fi' as NetworkManager's keyfile byte list.
        (self.root / 'profile').write_text('[wifi]\nssid=72;105;32;70;105;\n[wifi-security]\nkey-mgmt=wpa-psk\n')

    def wifi(self, wait_ms='600', env=None):
        data, colour = self.run_report(env=dict({'M19_TEST_WIFI': wait_ms}, **(env or {})))
        fields, log, steps = self.parse(data)
        line = re.search(r'M19 R6 wifi (.*)\n', log)
        return fields, log, dict(item.split('=', 1) for item in line.group(1).split()) if line else None, steps

    def test_connected_with_a_route_is_recorded_without_names(self):
        fields, log, w, steps = self.wifi()
        self.assertEqual((w['ready'], w['iface'], w['connected'], w['route'], w['dns']), ('1', 'lo', '1', '1', '1'))
        # The gateway echo needs a raw socket: as root it answers on loopback, otherwise it fails closed.
        self.assertEqual(w['ping'], '1' if os.geteuid() == 0 else '0')
        self.assertEqual(w['wifi_ok'], w['ping'])
        self.assertEqual(self.verdict(log)['all_ok'], w['ping'])
        self.assertIn('-t -f DEVICE,TYPE,STATE device', (self.test / 'nmcli-args').read_text())
        self.assertIn('M19 wifi report\n', log)
        self.assertTrue(any(step.startswith('M19STEP T12-wifi') for step in steps), steps)

    def test_a_failed_bring_up_is_not_waited_for(self):
        (self.root / 'wifi.result').write_text('failed cbc -110\n')
        start = time.monotonic()
        fields, log, w, _ = self.wifi(wait_ms='5000')
        self.assertLess(time.monotonic() - start, 4.5)
        self.assertEqual((w['result'], w['ready'], w['connected'], w['wifi_ok']), ('failed_cbc_-110', '0', '0', '0'))
        self.assertEqual(self.verdict(log)['all_ok'], '0')
        self.assertFalse((self.test / 'nmcli-args').exists())

    def test_each_missing_piece_fails(self):
        for change in ('no-result', 'skipped', 'fault', 'disconnected', 'other-device', 'no-route', 'no-gateway-flag'):
            with self.subTest(change=change):
                self.setUp()
                if change == 'no-result':
                    (self.root / 'wifi.result').unlink()
                elif change == 'skipped':
                    (self.root / 'wifi.result').write_text('skipped stage\n')
                elif change == 'fault':
                    (self.root / 'wifi.result').write_text('fault owner\n')
                elif change == 'disconnected':
                    (self.test / 'nm-devices').write_text('lo:wifi:disconnected\n')
                elif change == 'other-device':
                    (self.test / 'nm-devices').write_text('wlan1:wifi:connected\n')
                elif change == 'no-route':
                    (self.root / 'route').write_text(ROUTE_HEAD)
                else:
                    (self.root / 'route').write_text(ROUTE_HEAD + 'lo\t00000000\t0100007F\t0001\t0\t0\t600\t00000000\t0\t0\t0\n')
                fields, log, w, _ = self.wifi(wait_ms='300')
                self.assertEqual(w['wifi_ok'], '0', log)
                self.assertEqual(self.verdict(log)['all_ok'], '0')
                # Each fails where it should, not only at the echo.
                if change in ('disconnected', 'other-device'):
                    self.assertEqual((w['ready'], w['connected'], w['route']), ('1', '0', '0'))
                elif change in ('no-route', 'no-gateway-flag'):
                    self.assertEqual((w['ready'], w['connected'], w['route'], w['ping']), ('1', '1', '0', '0'))
                else:
                    self.assertEqual((w['ready'], w['connected']), ('0', '0'))

    def test_dns_is_recorded_not_judged(self):
        fields, log, w, _ = self.wifi(env={'M19_DNS_RC': '2'})
        self.assertEqual(w['dns'], '0')
        self.assertEqual(w['wifi_ok'], w['ping'])

    # Built at run time, so the exported source holds no address-shaped text.
    MAC = ':'.join(('0a', '1B', '2c', '3D', '4e', '5F'))
    HOST = '.'.join(('192', '168', '1', '20'))
    GATEWAY = '.'.join(('192', '168', '1', '1'))

    def test_the_report_leaves_out_the_ssid_and_every_address(self):
        (self.test / 'kmsg').write_text(f'<6>wlan: connected to Hi Fi bssid {self.MAC} ip {self.HOST} via {self.GATEWAY}\n'
                                        '<6>kernel 5.10.236 Mesa 26.2.2 no address 1.2.3 and 1234.5.6.7\n')
        fields, log, w, _ = self.wifi()
        self.assertNotIn('Hi Fi', log)
        self.assertNotIn(self.MAC, log)
        self.assertNotIn(self.HOST, log)
        self.assertIn('connected to ***** bssid xx:xx:xx:xx:xx:xx ip xxx.xxx.x.xx via xxx.xxx.x.x', log)
        self.assertIn('kernel 5.10.236 Mesa 26.2.2 no address 1.2.3 and 1234.5.6.7', log)
        redacted = dict(item.split('=') for item in re.search(r'M19 R6 redacted (.*)\n', log).group(1).split())
        self.assertGreaterEqual(int(redacted['ssid']), 1)
        self.assertGreaterEqual(int(redacted['mac']), 1)
        self.assertGreaterEqual(int(redacted['ipv4']), 2)
        # The hash is the redacted log's.
        self.assertEqual(hashlib.sha256(log.encode()).hexdigest(), fields[2])

    def test_without_wifi_nothing_is_redacted(self):
        (self.test / 'kmsg').write_text(f'<6>addr {self.HOST}\n')
        data, colour = self.run_report()
        fields, log, _ = self.parse(data)
        self.assertIn(self.HOST, log)
        self.assertNotIn('M19 R6', log)

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
 cat)
  case "$1" in */card0-Virtual-1/status) if [ "$(cat "$1")" = off ] && [ -z "${M19_WB_STUCK:-}" ]; then echo disconnected; exit 0; fi;; esac
  exec cat "$@";;
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
        for name in ('handoff.c', 'report.c', 'wire.c', 'pid2.c', 't9-root', 'pid4.c', 'pid5.c', 'pid6.c', 'pid7.c', 't9-gpu', 'gpu-probe.c',
                     'present-probe.c'):
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
        for name in ('t9-root', 't9-desktop', 't9-gpu'):
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
        # The one write outside the new root: the writeback connector's sysfs status, set to off.
        sysfs = ' printf off >"$R/sys/class/drm/$writeback/status" || fail writeback-off'
        self.assertEqual([line for line in text.splitlines() if '/sys/' in line and '>"' in line], [sysfs])
        for line in text.splitlines():
            if line != sysfs and re.search(r'\$BB (cp|mkdir|mknod|chmod)\b|>"', line):
                self.assertRegex(line, r'"\$(new|home)[/"]', line)
        for word in ('.ssh', '.gnupg', '.gemini', 'shadow', 'spblob', '/data/media'):
            self.assertNotIn(word, text)


    def test_pid4_adds_t9_gpu_and_reports_the_gpu(self):
        text = (HERE / 'pid4.c').read_text()
        names = re.findall(r'\{"(T\d+-[a-z]+)", "/m19/(t\d-[a-z]+)"', text)
        self.assertEqual([name for name, _ in names],
                         ['T0-extract', 'T1-services', 'T2-unlock', 'T5-mount', 'T6-read', 'T9-root', 'T9-desktop', 'T9-gpu', 'T8-writes'])
        self.assertIn('{"T9-gpu", "/m19/t9-gpu", 90000, M19_STEP_REQUIRED}', text)
        self.assertIn('{"T8-writes", "/m19/t8-writes", 30000, M19_STEP_REQUIRED | M19_STEP_ALWAYS}', text)
        self.assertLessEqual(len(names), int(re.search(r'#define M19_STEPS_MAX (\d+)', (HERE.parent / 'run1/r1.h').read_text()).group(1)))
        for field in ('.desktop = 1', '.want_hz = 120.0', '.touch_ms = 60000', '.gpu = 1, ', '.gpu_ms = 30000, ', '.gears_ms = 11000, ',
                      '.cube_frames = 300, ', '.kgsl_node = "/dev/kgsl-3d0"', '.kgsl_model = "/sys/class/kgsl/kgsl-3d0/gpu_model"',
                      '.gpu_probe = "/run/m19/m19-gpu-probe"', '.vulkaninfo = "/usr/bin/vulkaninfo"', '.vkcube = "/usr/bin/vkcube"',
                      '.glxinfo = "/usr/bin/glxinfo"', '.glxgears = "/usr/bin/glxgears"', '.eglinfo = "/usr/bin/eglinfo"',
                      '.vk_env = dri3_env, .gl_env = dri3_env, .egl_env = dri3_env, .glamor = 1, .xorg_unit = "marble-xorg.service"',
                      '.gpu_profile = "/run/m19/gpu-profile", .glmark2 = "/usr/bin/glmark2", .copy_env = copy_env',
                      '.present_probe = "/run/m19/m19-present-probe", .present_frames = 120, .judge_copy = 1, .judge_dri3 = 1, .shell = "/bin/sh", .shows = shows,',
                      '.show_count = sizeof(shows) / sizeof(shows[0]), .show_seconds = 3,',
                      '.dmabuf_heap = "/dev/dma_heap/system", .dmabuf_env = dri3_env,',
                      '.xorg_logs = {"/var/log/Xorg.0.log", "/var/log/Xorg.cpu.log"}', '.battery_limit = 420, ', '.session_ms = 900000, ',
                      '.guard_unit = "m19-r3-guard.service"', '.units = {"marble-xfce.service", "marble-xorg.service", "marble-xorg-fallback.service"}'):
            self.assertIn(field, text)
        # R4h: no compositor views; R4d's compositor would black out the panel again.
        self.assertNotIn('.compositor_script', text)
        # R4i: six ways glxgears' frames can reach the X server, in this order.
        table = re.search(r'static const struct m19_show shows\[\] = \{(.*?)\};', text, re.S).group(1)
        self.assertEqual(re.findall(r'\{"(\w+)", (\w+)\}', table), [('dri3', 'dri3_env'), ('noubwc', 'noubwc_env'), ('linear', 'linear_env'),
                                                                     ('zink', 'zink_env'), ('copy', 'copy_env'), ('soft', 'soft_env'),
                                                                     ('finish', 'finish_env'), ('zinkfinish', 'zinkfinish_env')])
        # Every show fits the reporter's table.
        limit = int(re.search(r'#define M19_SHOWS_MAX (\d+)', (HERE / 'report.c').read_text()).group(1))
        self.assertLessEqual(len(re.findall(r'\{"\w+", \w+\}', table)), limit)
        dri3 = '"MESA_LOADER_DRIVER_OVERRIDE=kgsl", "FD_FORCE_KGSL=1", "FD_KGSL_ENABLE_DMABUF=1", M19_VK_ICD'
        self.assertIn(f'#define M19_DRI3 {dri3}\n', text)
        self.assertIn('#define M19_FINISH "LD_PRELOAD=/run/m19/m19-glfinish.so"\n', text)
        for name, items in (('noubwc', 'M19_DRI3, "FD_MESA_DEBUG=noubwc", NULL'), ('linear', 'M19_DRI3, "FD_MESA_DEBUG=noubwc,notile", NULL'),
                            ('zink', 'M19_VK_ICD, "MESA_LOADER_DRIVER_OVERRIDE=zink", NULL'), ('soft', '"LIBGL_ALWAYS_SOFTWARE=1", NULL'),
                            # R4k: dri3 and zink with glFinish before every swap.
                            ('finish', 'M19_DRI3, M19_FINISH, NULL'),
                            ('zinkfinish', 'M19_VK_ICD, "MESA_LOADER_DRIVER_OVERRIDE=zink", M19_FINISH, NULL')):
            self.assertIn(f'static const char *const {name}_env[] = {{{items}}};', text)
        # The reporter tests with exactly the variables the session's profiles carry.
        icd = re.search(r'#define M19_VK_ICD "([^"]+)"', text).group(1)
        for name, want in (('dri3_env', r4plan.DRI3_ENV), ('copy_env', r4plan.COPY_ENV)):
            body = re.search(rf'static const char \*const {name}\[\] = \{{(.*?)\}};', text).group(1)
            items = [icd if item.strip() == 'M19_VK_ICD' else item.strip().strip('"') for item in body.split(',')]
            self.assertEqual(items[-1], 'NULL')
            self.assertEqual(tuple(items[:-1]), want, name)
        self.assertNotRegex(text, r'\breboot\(|RB_AUTOBOOT|LINUX_REBOOT')

    def test_pid7_is_pid6_with_ce_and_the_kept_island_and_nothing_else(self):
        def body(name):
            text = (HERE / name).read_text()
            return text[text.index('*/\n') + 3:].splitlines()
        changes = [line[0] + ' ' + line[1:] for line in difflib.unified_diff(body('pid6.c'), body('pid7.c'), lineterm='', n=0)
                   if line[:1] in '+-' and line[:3] not in ('+++', '---')]
        self.assertEqual(changes, [
            '+     {"T7-de", "/m19/t7-de", 120000, M19_STEP_REQUIRED},',
            '+     {"T9-ce", "/m19/t9-ce", 30000, M19_STEP_REQUIRED},',
            "+     /* R7: the owner has five minutes for the PIN; the keypad records the broker's answer, Android's names judge it. */",
            '+     .ce = 1, .ce_ms = 300000, .ce_unit = "marble-ce.service", .ce_result = "/run/m19/ce.result", .ce_android = "/run/m19/android/0",',
            '+     .ce_entry = "Android",',
            '+         /* R7: the TEE island stays, for the CE broker and the services it calls. */',
            '-                                       .init = "/usr/lib/systemd/systemd", .self = getpid(), .settle_ms = 10000, .poll_ms = 20,',
            '-                                       .pace_ms = 20, .signal = kill};',
            '+                                       .init = "/usr/lib/systemd/systemd", .keep_root = "/tee", .self = getpid(), .settle_ms = 10000,',
            '+                                       .poll_ms = 20, .pace_ms = 20, .signal = kill};'])
        names = re.findall(r'\{"(T\d+-[a-z]+)", "/m19/(t\d-[a-z]+)"', (HERE / 'pid7.c').read_text())
        self.assertEqual([name for name, _ in names], ['T3-audio', 'T0-extract', 'T1-services', 'T2-unlock', 'T5-mount', 'T6-read', 'T7-de',
                                                       'T9-root', 'T9-desktop', 'T9-gpu', 'T9-sound', 'T9-wifi', 'T9-ce', 'T8-writes'])
        self.assertLessEqual(len(names), int(re.search(r'#define M19_STEPS_MAX (\d+)', (HERE.parent / 'run1/r1.h').read_text()).group(1)))

    def test_pid6_is_pid5_with_wifi_the_sink_and_landscape_and_nothing_else(self):
        def body(name):
            text = (HERE / name).read_text()
            return text[text.index('*/\n') + 3:].splitlines()
        changes = [line[0] + ' ' + line[1:] for line in difflib.unified_diff(body('pid5.c'), body('pid6.c'), lineterm='', n=0)
                   if line[:1] in '+-' and line[:3] not in ('+++', '---')]
        self.assertEqual(changes, [
            '-     {"T9-audio", "/m19/t9-audio", 30000, M19_STEP_REQUIRED},',
            '+     {"T9-sound", "/m19/t9-sound", 30000, M19_STEP_REQUIRED},',
            '+     {"T9-wifi", "/m19/t9-wifi", 240000, M19_STEP_REQUIRED},',
            "+ /* R6: the session's PulseAudio (R6b: marble-pulse.service, which the reporter starts), for root. */",
            '+ static const char *const pulse_env[] = {"HOME=/run/m19/session", "XDG_RUNTIME_DIR=/run/m19/xdg", "PULSE_SERVER=unix:/run/m19/xdg/pulse/native",',
            '+                                         NULL};',
            '+ ',
            '-     .present_probe = "/run/m19/m19-present-probe", .present_frames = 120, .judge_copy = 1, .judge_dri3 = 1, .shell = "/bin/sh", .shows = shows,',
            "+     /* R6: the turned screen adds a composite a frame; the windowed copy's rate is recorded, not judged. */",
            '+     .present_probe = "/run/m19/m19-present-probe", .present_frames = 120, .judge_copy = 0, .judge_dri3 = 1, .shell = "/bin/sh", .shows = shows,',
            '-     .speaker_unit = "marble-speaker.service", .speaker_report = "/run/m19/speaker.report",',
            '+     .sink_unit = "marble-sink.service", .sink_report = "/run/m19/sink.report", .sink_status = "/run/m19/sink.status",',
            '+     .pactl = "/usr/bin/pactl", .pacat = "/usr/bin/pacat", .sink_name = "marble_speaker", .tone_path = "/run/m19/sink-tone.raw",',
            '+     .pulse_env = pulse_env, .sink_ms = 60000, .tone_ms = 15000, .idle_wait_ms = 12000,',
            '+     .pulse_unit = "marble-pulse.service", .held_dir = "/dev/m11-snd", .held_uid = 0,',
            '+     .wifi = 1, .wifi_ms = 240000, .wifi_result = "/run/m19/wifi.result", .wifi_report = "/run/m19/wifi.report", .nmcli = "/usr/bin/nmcli",',
            '+     .getent = "/usr/bin/getent", .route = "/proc/net/route", .nm_profile = "/etc/NetworkManager/system-connections/m19-wifi.nmconnection",',
            '+     .dns_name = "connectivity-check.ubuntu.com",',
            '+     .rotation = "right",'])
        names = re.findall(r'\{"(T\d+-[a-z]+)", "/m19/(t\d-[a-z]+)"', (HERE / 'pid6.c').read_text())
        self.assertEqual(names[0], ('T3-audio', 't3-audio'))
        self.assertEqual(names[-3:], [('T9-sound', 't9-sound'), ('T9-wifi', 't9-wifi'), ('T8-writes', 't8-writes')])
        self.assertLessEqual(len(names), int(re.search(r'#define M19_STEPS_MAX (\d+)', (HERE.parent / 'run1/r1.h').read_text()).group(1)))

    def test_pid5_is_pid4_with_the_audio_stage_and_nothing_else(self):
        def body(name):
            text = (HERE / name).read_text()
            return text[text.index('*/\n') + 3:].splitlines()
        # Each change once, removals before additions, in file order.
        changes = [line[0] + ' ' + line[1:] for line in difflib.unified_diff(body('pid4.c'), body('pid5.c'), lineterm='', n=0)
                   if line[:1] in '+-' and line[:3] not in ('+++', '---')]
        self.assertEqual(changes, [
            '+     {"T3-audio", "/m19/t3-audio", 120000, M19_STEP_REQUIRED},',
            '+     {"T9-audio", "/m19/t9-audio", 30000, M19_STEP_REQUIRED},',
            '-     .bootstrap = "/m19/bootstrap", .adsp = "/m19/adsp", .connector = "/sbin/m15-connector", .display = "/sbin/m16-display",',
            '+     .bootstrap = "/m19/bootstrap-audio", .adsp = "/m19/adsp", .connector = "/sbin/m15-connector", .display = "/sbin/m16-display",',
            '-     .bootstrap_ms = 120000, .display_ms = 20000, .blue_ms = 3000, .final_ms = 600000, .poll_ms = 5, .pace_ms = 20,',
            '+     .bootstrap_ms = 180000, .display_ms = 20000, .blue_ms = 3000, .final_ms = 600000, .poll_ms = 5, .pace_ms = 20,',
            '+     .audio = 1, .speaker_ms = 30000, .asound_cards = "/proc/asound/cards", .asound_pcm = "/proc/asound/pcm",',
            '+     .sound_class = "/sys/class/sound", .snd_dev = "/dev/snd", .audio_card = "ukee-mtp-snd-card",',
            '+     .speaker_unit = "marble-speaker.service", .speaker_report = "/run/m19/speaker.report",',
            '+     .speaker_clean = {"/dev/m11-snd", "/dev/m11-heap", "/dev/aud_pasthru_adsp", "/dev/msm_audio_ion", "/dev/msm_audio_ion_cma"},',
            '-     if (m19_run_main(&run) == M19_END_PASS) {',
            '+     enum m19_run_end end = m19_run_main(&run);',
            '+     if (end == M19_END_BOOTSTRAP) {',
            '+         /* The bootstrap or the audio stage held, before the ADSP and the USB link. Nothing touched the TEE. */',
            '+         char *argv_red[] = {"/sbin/m16-display", "00ff0000", "600000", NULL};',
            '+         if (fork() == 0) {',
            '+             execv(argv_red[0], argv_red);',
            '+             _exit(127);',
            '+         }',
            '+     }',
            '+     if (end == M19_END_PASS) {'])
        names = re.findall(r'\{"(T\d+-[a-z]+)", "/m19/(t\d-[a-z]+)"', (HERE / 'pid5.c').read_text())
        self.assertEqual(names[0], ('T3-audio', 't3-audio'))
        self.assertIn(('T9-audio', 't9-audio'), names)
        self.assertLessEqual(len(names), int(re.search(r'#define M19_STEPS_MAX (\d+)', (HERE.parent / 'run1/r1.h').read_text()).group(1)))

    def test_t9_gpu_writes_only_ram_copies_and_the_firmware_path(self):
        text = (HERE / 't9-gpu').read_text()
        self.assertNotRegex(text, r'\b(reboot|poweroff|mkfs|fsck|blkdiscard|fstrim|remount|setrw|insmod|rmmod|modprobe)\b|\bof=/dev')
        self.assertIn('LOAD=${M19_LOAD:-/sbin/m19-load-heaps}\n', text)
        self.assertIn('param=$R/sys/module/firmware_class/parameters/path\n', text)
        # The one write outside RAM copies and nodes: the firmware loader's path, set to the RAM copy.
        self.assertEqual([line for line in text.splitlines() if '>"' in line], ["printf '%s' /run/m19/firmware >\"$param\" || fail firmware-path"])
        self.assertEqual([line.strip() for line in text.splitlines() if '/sys/' in line and not line.lstrip().startswith('#')],
                         ['param=$R/sys/module/firmware_class/parameters/path', 'while [ ! -r "$R/sys/class/$1/$2/dev" ]; do',
                          'number=$($BB cat "$R/sys/class/$1/$2/dev") || fail "$2 number"'])
        for line in text.splitlines():
            if re.search(r'\$BB (cp|mkdir|mknod|chmod)\b', line):
                self.assertRegex(line, r'"\$(new|directory|3)[/"]|"\$R/run/m19/firmware"', line)
        # Nothing opens the GPU before Ubuntu's Mesa does: its node is only made.
        code = '\n'.join(line for line in text.splitlines() if not line.lstrip().startswith('#'))
        self.assertEqual(re.findall(r'\S*kgsl-3d0\S*', code), ['kgsl-3d0', '"$new/dev/kgsl-3d0"'])


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
            self.assertIn('Section "Monitor"\n    Identifier "writeback"\n    Option "Ignore" "true"\nEndSection', text)
            self.assertNotIn('ZaphodHeads', text)
            for option in ('"Driver "modesetting"', '"kmsdev" "/dev/dri/card0"', '"AccelMethod" "none"', '"BlankTime" "0"', '"OffTime" "0"',
                           '"Monitor-DSI-1" "marble-panel"', '"Monitor-Virtual-1" "writeback"', '"NoTrapSignals" "true"'):
                self.assertIn(option.lstrip('"'), text)
        self.assertEqual(r3plan.MODE_120, '1080x2400x120vid')

    def test_units(self):
        self.assertIn('OnFailure=marble-xorg-fallback.service\n', r3plan.XORG)
        self.assertNotIn('OnFailure', r3plan.XORG_60)
        for text in (r3plan.XORG, r3plan.XORG_60):
            self.assertIn('LimitCORE=0\n', text)
            self.assertIn('Environment=LD_PRELOAD=/run/m19/m19-xorg-shim.so\n', text)
        self.assertNotIn('LD_PRELOAD', r3plan.XFCE + r3plan.REPORT + r3plan.GUARD)
        self.assertEqual(r3plan.FILES['sysctl.d/m19-r3.conf'], 'debug.exception-trace = 1\n')
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


class Plan4(unittest.TestCase):
    def test_render_is_r3_with_the_gpu(self):
        files, r3 = r4plan.render(), r3plan.render()
        self.assertEqual(files['m19/r2/default'], b'm19-r4.target\n')
        self.assertEqual(files['m19/r2/files'].decode().split(), list(r4plan.FILES))
        for name in ('m19/r3/xorg.conf', 'm19/r3/xorg-60.conf', 'm19/r3/modes', 'm19/r3/touch', 'm19/r3/hidden', 'm19/r3/writeback',
                     'm19/r2/masks', 'm19/r2/etc/systemd/system/m19-r3-guard.service', 'm19/r2/etc/sysctl.d/m19-r3.conf'):
            self.assertEqual(files[name], r3[name], name)
        self.assertFalse([name for name in files if re.search(r'm19-r3(-report\.service|\.target)$', name)])
        self.assertEqual(files['m19/r4/modules'].decode().split(), list(r4plan.GPU_MODULES))
        self.assertEqual(files['m19/r4/firmware'].decode().split(), list(r4plan.FIRMWARE))
        for name, env in r4plan.PROFILES.items():
            self.assertEqual(files[f'm19/r2/etc/m19/gpu-{name}.env'].decode().splitlines(), list(env))

    def test_glamor_configuration_is_r3c_with_glamor(self):
        glamor = r4plan.render()['m19/r4/xorg-glamor.conf'].decode()
        cpu = r3plan.xorg_conf(r3plan.MODE_120)
        self.assertIn('    Option "AccelMethod" "glamor"\n    Option "DRI" "3"\n', glamor)
        self.assertIn('    Option "PageFlip" "true"\n', glamor)
        self.assertIn('    Option "SWcursor" "false"\n', glamor)
        self.assertEqual(glamor.replace('    Option "AccelMethod" "glamor"\n    Option "DRI" "3"\n', '    Option "AccelMethod" "none"\n')
                         .replace('"PageFlip" "true"', '"PageFlip" "false"').replace('"SWcursor" "false"', '"SWcursor" "true"'), cpu)
        for line in ('Option "PreferredMode" "1080x2400x120vid"', 'Option "Monitor-Virtual-1" "writeback"', 'Option "Ignore" "true"'):
            self.assertIn(line, glamor)
        # The CPU fallback is R3c's, page flips off and the software cursor.
        self.assertIn('    Option "PageFlip" "false"\n', cpu)
        self.assertIn('    Option "SWcursor" "true"\n', cpu)

    def test_xorg_units(self):
        self.assertIn('-config /run/m19/xorg-glamor.conf -logfile /var/log/Xorg.0.log ', r4plan.XORG)
        self.assertIn('OnFailure=marble-xorg-fallback.service\n', r4plan.XORG)
        self.assertIn('Environment=LD_PRELOAD=/run/m19/m19-xorg-shim.so\n', r4plan.XORG)
        self.assertIn('Environment=M19_SHIM_GBM=1 M19_SHIM_NODIRTY=1 MESA_LOADER_DRIVER_OVERRIDE=kgsl FD_FORCE_KGSL=1 FD_KGSL_ENABLE_DMABUF=1\n',
                      r4plan.XORG)
        # The fallback is R3c's proven CPU Xorg at 120 Hz, with the shim but without the bridge.
        self.assertIn('-config /run/m19/xorg.conf -logfile /var/log/Xorg.cpu.log ', r4plan.XORG_FALLBACK)
        self.assertNotIn('OnFailure', r4plan.XORG_FALLBACK)
        self.assertNotIn('M19_SHIM_GBM', r4plan.XORG_FALLBACK)
        self.assertNotIn('M19_SHIM_NODIRTY', r4plan.XORG_FALLBACK)
        self.assertNotIn('MESA', r4plan.XORG_FALLBACK)
        self.assertEqual(r4plan.FILES['systemd/system/marble-xorg.service'], r4plan.XORG)
        self.assertEqual(r4plan.FILES['systemd/system/marble-xorg-fallback.service'], r4plan.XORG_FALLBACK)
        self.assertEqual(r4plan.GLAMOR_ENV, ('MESA_LOADER_DRIVER_OVERRIDE=kgsl', 'FD_FORCE_KGSL=1', 'FD_KGSL_ENABLE_DMABUF=1'))
        self.assertEqual(r4plan.DRI3_ENV, r4plan.GLAMOR_ENV + ('VK_DRIVER_FILES=/usr/share/vulkan/icd.d/freedreno_icd.aarch64.json',))
        self.assertEqual(r4plan.COPY_ENV, ('VK_DRIVER_FILES=/usr/share/vulkan/icd.d/freedreno_icd.aarch64.json', 'MESA_VK_WSI_DEBUG=sw',
                                           'MESA_LOADER_DRIVER_OVERRIDE=zink', 'LIBGL_KOPPER_DRI2=1'))

    def test_session_unit(self):
        self.assertIn('ExecStart=/bin/sh /etc/m19/gpu-session\n', r4plan.XFCE)
        self.assertIn('Restart=on-failure\nRestartSec=2\n', r4plan.XFCE)
        self.assertNotIn('MESA', r4plan.XFCE)
        self.assertIn('Environment=DISPLAY=:0 HOME=/run/m19/session XDG_RUNTIME_DIR=/run/m19/xdg', r4plan.XFCE)
        self.assertIn('Wants=multi-user.target m19-r4-report.service m19-r3-guard.service marble-xorg.service marble-xfce.service\n', r4plan.TARGET)
        self.assertIn('ExecStart=/run/m19/m19-report report\n', r4plan.REPORT)
        self.assertNotIn('MESA', r4plan.REPORT + r4plan.TARGET + r3plan.GUARD)
        self.assertEqual(r4plan.FILES['m19/gpu-session'], r4plan.SESSION)
        self.assertEqual(r4plan.FILES['m19/gpu-compositor'], r4plan.COMPOSITOR)
        for line in ('-p /general/vblank_mode -n -t string -s xpresent', '-p /general/unredirect_overlays -n -t bool -s true',
                     '-p /general/use_compositing -n -t bool -s true', '-p /general/use_compositing -n -t bool -s false'):
            self.assertEqual(r4plan.COMPOSITOR.count(f'/usr/bin/xfconf-query -c xfwm4 {line}'), 1, line)
        # R4e: nothing in the session touches xfwm4's settings; only the reporter runs the compositor script.
        self.assertNotIn('autostart', r4plan.SESSION)
        self.assertNotIn('gpu-compositor', r4plan.SESSION)


class Plan7(unittest.TestCase):
    """R7's plan: R6d's, with its own target and report, and the keypad unit the reporter starts once."""

    def setUp(self):
        self.files, self.r6 = r7plan.render(), r6plan.render()

    def test_everything_else_is_r6s(self):
        changed = {name for name in set(self.files) | set(self.r6) if self.files.get(name) != self.r6.get(name)}
        self.assertEqual(changed, {'m19/r2/default', 'm19/r2/files', 'm19/r2/etc/systemd/system/m19-r6.target',
                                   'm19/r2/etc/systemd/system/m19-r6-report.service', 'm19/r2/etc/systemd/system/m19-r7.target',
                                   'm19/r2/etc/systemd/system/m19-r7-report.service', 'm19/r2/etc/systemd/system/marble-ce.service'})
        self.assertEqual(self.files['m19/r2/default'], b'm19-r7.target\n')
        listed = self.files['m19/r2/files'].decode().split()
        self.assertEqual(sorted(listed), sorted(name[len('m19/r2/etc/'):] for name in self.files if name.startswith('m19/r2/etc/')))
        target = self.files['m19/r2/etc/systemd/system/m19-r7.target'].decode()
        old = self.r6['m19/r2/etc/systemd/system/m19-r6.target'].decode()
        self.assertEqual(target.replace('m19-r7-report.service', 'm19-r6-report.service').split('\n')[2:], old.split('\n')[2:])

    def test_the_keypad_runs_only_when_the_reporter_starts_it(self):
        unit = self.files['m19/r2/etc/systemd/system/marble-ce.service'].decode()
        self.assertNotIn('marble-ce', self.files['m19/r2/etc/systemd/system/m19-r7.target'].decode())
        self.assertNotIn('[Install]', unit)
        self.assertIn('ConditionPathExists=/run/m19/ce/ce.sock\n', unit)
        self.assertIn('ExecStart=/run/m19/m19-ce-prompt /run/m19/ce/ce.sock /run/m19/ce.result\n', unit)
        self.assertIn('Restart=no\n', unit)
        self.assertIn('LimitCORE=0\n', unit)
        self.assertIn('StandardOutput=null\n', unit)


class Plan6(unittest.TestCase):
    """R6's plan: R5's, with the landscape glamor configuration, Wi-Fi, NetworkManager, the sink and USB input."""

    def setUp(self):
        self.files, self.r5 = r6plan.render(), r5plan.render()

    def test_everything_else_is_r5s(self):
        changed = {name for name in set(self.files) | set(self.r5) if self.files.get(name) != self.r5.get(name)}
        etc = {name for name in changed if name.startswith('m19/r2/etc/')}
        self.assertEqual(changed - etc, {'m19/r2/default', 'm19/r2/masks', 'm19/r2/files', 'm19/r3/hidden', 'm19/r4/xorg-glamor.conf',
                                         'm19/r5/udev-masks', 'm19/r6/udev-masks'})
        self.assertEqual({name[len('m19/r2/etc/'):] for name in etc}, {
            'systemd/system/m19-r5.target', 'systemd/system/m19-r5-report.service', 'systemd/system/marble-speaker.service',
            'systemd/system/m19-r6.target', 'systemd/system/m19-r6-report.service', 'systemd/system/marble-sink.service',
            'systemd/system/marble-wifi.service', 'systemd/system/marble-pulse.service', 'systemd/system/NetworkManager.service.d/m19.conf',
            'systemd/system/wpa_supplicant.service.d/m19.conf', 'NetworkManager/conf.d/m19.conf', 'pulse/default.pa.d/m19-sink.pa',
            'udev/rules.d/70-m19-usb-input.rules', 'systemd/network/10-m19-wlan.link'})
        self.assertEqual(self.files['m19/r2/default'], b'm19-r6.target\n')
        self.assertEqual(self.files['m19/r6/udev-masks'], self.r5['m19/r5/udev-masks'])
        self.assertNotIn('m19/r5/udev-masks', self.files)
        listed = self.files['m19/r2/files'].decode().split()
        self.assertEqual(sorted(listed), sorted(name[len('m19/r2/etc/'):] for name in self.files if name.startswith('m19/r2/etc/')))

    def test_the_x_server_turns_right_and_the_touchscreen_with_it(self):
        conf = self.files['m19/r4/xorg-glamor.conf'].decode()
        old = self.r5['m19/r4/xorg-glamor.conf'].decode()
        self.assertEqual(conf.replace('    Option "Rotate" "right"\n', '', 1)[:len(old)], old)
        self.assertEqual(conf.count('Option "Rotate"'), 1)
        self.assertIn('    Option "PreferredMode" "1080x2400x120vid"\n    Option "Rotate" "right"\n', conf)
        self.assertTrue(conf.endswith('\nSection "InputClass"\n    Identifier "marble-touch-landscape"\n    MatchProduct "goodix_ts"\n'
                                      '    Option "TransformationMatrix" "0 1 0 -1 0 1 0 0 1"\nEndSection\n'), conf[-300:])
        # The matrix maps the panel's top right corner to the turned screen's top left, as a right turn does.
        m = [float(v) for v in r6plan.TOUCH_MATRIX.split()]
        self.assertEqual((m[0] * 1 + m[1] * 0 + m[2], m[3] * 1 + m[4] * 0 + m[5]), (0.0, 0.0))
        self.assertEqual((m[0] * 1 + m[1] * 1 + m[2], m[3] * 1 + m[4] * 1 + m[5]), (1.0, 0.0))
        # The CPU fallback stays R3c's portrait configuration.
        self.assertEqual(self.files['m19/r3/xorg.conf'], self.r5['m19/r3/xorg.conf'])
        self.assertNotIn(b'Rotate', self.files['m19/r3/xorg.conf'])

    def test_networkmanager_and_wpa_supplicant_run_and_wait_for_wifi(self):
        masks = self.files['m19/r2/masks'].decode().split()
        self.assertNotIn('NetworkManager.service', masks)
        self.assertNotIn('wpa_supplicant.service', masks)
        self.assertIn('NetworkManager-wait-online.service', masks)
        self.assertIn('ModemManager.service', masks)
        self.assertEqual(sorted(set(self.r5['m19/r2/masks'].decode().split()) - set(masks)), ['NetworkManager.service', 'wpa_supplicant.service'])
        etc = {name[len('m19/r2/etc/'):]: data.decode() for name, data in self.files.items() if name.startswith('m19/r2/etc/')}
        self.assertEqual(etc['systemd/system/NetworkManager.service.d/m19.conf'],
                         '[Unit]\nConditionPathExists=/run/m19/wifi.ready\n\n[Service]\nLogLevelMax=warning\n')
        self.assertEqual(etc['systemd/system/wpa_supplicant.service.d/m19.conf'], '[Service]\nLogLevelMax=warning\n')
        conf = etc['NetworkManager/conf.d/m19.conf']
        for line in ('plugins=keyfile', 'unmanaged-devices=except:interface-name:wlan0', 'level=WARN', 'enabled=false'):
            self.assertIn(line + '\n', conf)
        # R6d: the driver's names stay; udev's predictable names gave two of the three the same name (R6c).
        link = etc['systemd/network/10-m19-wlan.link']
        self.assertIn('[Match]\nOriginalName=wlan* p2p* wifi-aware*\n', link)
        self.assertIn('[Link]\nNamePolicy=\nMACAddressPolicy=none\n', link)
        self.assertNotRegex(link, r'(?m)^Name=')
        wifi = etc['systemd/system/marble-wifi.service']
        for line in ('ExecStart=/run/m19/wifi/m19-wifi', 'Restart=no', 'KillMode=none', 'SendSIGKILL=no', 'ConditionPathExists=/run/m19/wifi.stage'):
            self.assertIn(line + '\n', wifi)
        self.assertIn(' marble-wifi.service', etc['systemd/system/m19-r6.target'])
        self.assertNotIn('NetworkManager', etc['systemd/system/m19-r6.target'])

    def test_the_sink_is_the_reporters_alone_and_pulseaudio_writes_its_fifo(self):
        etc = {name[len('m19/r2/etc/'):]: data.decode() for name, data in self.files.items() if name.startswith('m19/r2/etc/')}
        sink = etc['systemd/system/marble-sink.service']
        for line in ('ExecStart=/run/m19/m19-sink', 'Restart=no', 'KillMode=none', 'SendSIGKILL=no', 'TimeoutStopSec=infinity'):
            self.assertIn(line + '\n', sink)
        self.assertNotIn('marble-sink', etc['systemd/system/m19-r6.target'])
        self.assertEqual(etc['pulse/default.pa.d/m19-sink.pa'],
                         'load-module module-pipe-sink file=/run/m19/sink/fifo sink_name=marble_speaker format=s16le rate=48000 channels=2 '
                         'sink_properties=device.description=Speaker\nset-default-sink marble_speaker\n')
        # R6b: the reporter starts PulseAudio once the sink streams; XFCE's autostart entry stays hidden, so a second
        # server never races it.
        hidden = self.files['m19/r3/hidden'].decode().split()
        self.assertIn('pulseaudio', hidden)
        self.assertNotIn('nm-applet', hidden)
        self.assertEqual(sorted(set(self.r5['m19/r3/hidden'].decode().split()) - set(hidden)), ['nm-applet'])
        pulse = etc['systemd/system/marble-pulse.service']
        for line in ('Environment=HOME=/run/m19/session XDG_RUNTIME_DIR=/run/m19/xdg',
                     'ExecStart=/usr/bin/pulseaudio --daemonize=no --exit-idle-time=-1 --realtime=no --high-priority=no --log-target=journal',
                     'Restart=no', 'ConditionPathExists=/run/m19/sink/fifo'):
            self.assertIn(line + '\n', pulse)
        self.assertNotIn('marble-pulse', etc['systemd/system/m19-r6.target'])
        for unit in ('alsa-restore.service', 'alsa-state.service'):
            self.assertIn(unit, self.files['m19/r2/masks'].decode().split())

    def test_usb_input_nodes_only(self):
        rule = self.files['m19/r2/etc/udev/rules.d/70-m19-usb-input.rules'].decode()
        lines = [line for line in rule.splitlines() if line and not line.startswith('#')]
        self.assertEqual(len(lines), 2)
        for line in lines:
            self.assertIn('SUBSYSTEM=="input", KERNEL=="event[0-9]*", DEVPATH=="*/usb[0-9]*"', line)
        self.assertIn('mknod -m 0660 /dev/input/%k c $major $minor', lines[0])
        self.assertIn('RUN+="/bin/rm -f /dev/input/%k"', lines[1])


class Plan5(unittest.TestCase):
    def test_render_is_r4_with_r5b_speaker_and_alsa_masks(self):
        files, r4 = r5plan.render(), r4plan.render()
        self.assertEqual(files['m19/r2/default'], b'm19-r5.target\n')
        self.assertEqual(files['m19/r2/files'].decode().split(), list(r5plan.FILES))
        for name in ('m19/r3/xorg.conf', 'm19/r3/xorg-60.conf', 'm19/r4/xorg-glamor.conf', 'm19/r4/modules', 'm19/r4/firmware'):
            self.assertEqual(files[name], r4[name], name)
        self.assertFalse([name for name in files if re.search(r'm19-r[34](-report\.service|\.target)$', name)])
        for unit in ('alsa-restore.service', 'alsa-state.service'):
            self.assertIn(unit, r5plan.MASKED)
            self.assertIn(f'{unit}\n'.encode(), files['m19/r2/masks'])
        self.assertEqual(files['m19/r5/udev-masks'], b'60-persistent-alsa.rules\n')

    def test_speaker_and_target_units(self):
        self.assertNotIn('marble-speaker.service', r5plan.TARGET)
        self.assertIn('Wants=multi-user.target m19-r5-report.service m19-r3-guard.service marble-xorg.service marble-xfce.service\n', r5plan.TARGET)
        self.assertIn('ExecStart=/run/m19/m19-report report\n', r5plan.REPORT)
        self.assertEqual(r5plan.FILES['systemd/system/marble-speaker.service'], r5plan.SPEAKER)
        for line in ('DefaultDependencies=no', 'IgnoreOnIsolate=yes', 'Type=simple', 'ExecStart=/run/m19/m19-speaker',
                     'Restart=no', 'KillMode=none', 'SendSIGKILL=no', 'TimeoutStopSec=infinity', 'LimitCORE=0'):
            self.assertIn(line + '\n', r5plan.SPEAKER)
        self.assertNotIn('WantedBy=', r5plan.SPEAKER)


SESSION_FAKES = (('xdpyinfo', '#!/bin/sh\n[ -e "$(dirname "$0")/x-up" ]\n'),
                 ('systemctl', '#!/bin/sh\n[ "$1 $2" = "is-active marble-xorg.service" ] || exit 9\ncat "$(dirname "$0")/xorg-state"\n'),
                 ('dbus-run-session', '#!/bin/sh\n[ "$1" = -- ] || exit 9\nshift\nDBUS_SESSION_BUS_ADDRESS=unix:path=/tmp/m19-test-bus,guid=1\n'
                                      'export DBUS_SESSION_BUS_ADDRESS\nexec "$@"\n'),
                 ('startxfce4', '#!/bin/sh\nenv | grep -E "^(MESA|FD_|VK_|LIBGL)" | sort\n'))


class SessionScript(unittest.TestCase):
    """r4plan.SESSION with its absolute paths pointed into a temporary tree."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        for name, text in SESSION_FAKES:
            (self.root / name).write_text(text)
            (self.root / name).chmod(0o755)
        (self.root / 'etc').mkdir()
        for name, env in r4plan.PROFILES.items():
            (self.root / 'etc' / f'gpu-{name}.env').write_text(''.join(f'{item}\n' for item in env))
        (self.root / 'x-up').write_text('')
        (self.root / 'xorg-state').write_text('active\n')
        (self.root / 'Xorg.0.log').write_text('(II) modeset(0): glamor X acceleration enabled on FD725\n(II) modeset(0): glamor initialized\n')
        script = r4plan.SESSION
        for old, new in (('/usr/bin/xdpyinfo', f'{self.root}/xdpyinfo'), ('/usr/bin/systemctl', f'{self.root}/systemctl'),
                         ('/usr/bin/grep', 'grep'), ('/var/log/Xorg.0.log', f'{self.root}/Xorg.0.log'), ('</etc/m19/gpu-$profile.env', f'<{self.root}/etc/gpu-$profile.env'),
                         ('/run/m19/gpu-profile', f'{self.root}/gpu-profile'), ('/run/m19/session-bus', f'{self.root}/session-bus'),
                         ('/usr/bin/dbus-run-session', f'{self.root}/dbus-run-session'), ('/usr/bin/startxfce4', f'{self.root}/startxfce4'),
                         ('sleep 0.2', 'sleep 0.01')):
            self.assertIn(old, script)
            script = script.replace(old, new)
        (self.root / 'session').write_text(script)
        (self.root / 'home/.config/autostart').mkdir(parents=True)

    def run_session(self):
        environment = {key: value for key, value in os.environ.items() if not key.startswith(('MESA', 'FD_', 'VK_', 'LIBGL', 'DBUS'))}
        environment['HOME'] = str(self.root / 'home')
        done = subprocess.run(['sh', str(self.root / 'session')], capture_output=True, text=True, env=environment, timeout=60)
        profile = (self.root / 'gpu-profile').read_text() if (self.root / 'gpu-profile').exists() else None
        bus = (self.root / 'session-bus').read_text() if (self.root / 'session-bus').exists() else None
        return done, profile, bus

    def test_glamor_gives_every_program_the_dri3_profile(self):
        done, profile, bus = self.run_session()
        self.assertEqual((done.returncode, profile), (0, 'dri3\n'), done.stderr)
        self.assertEqual(done.stdout.splitlines(), sorted(r4plan.DRI3_ENV))
        # The session's bus is left for the reporter; xfwm4's settings are left as the tree has them.
        self.assertEqual(bus, 'unix:path=/tmp/m19-test-bus,guid=1\n')
        self.assertEqual(list((self.root / 'home/.config/autostart').iterdir()), [])

    def test_without_glamor_the_session_takes_the_copy_profile(self):
        for change in ('log', 'inactive', 'missing-log'):
            with self.subTest(change=change):
                self.setUp()
                if change == 'log':
                    (self.root / 'Xorg.0.log').write_text('(II) modeset(0): glamor initialization failed\n')
                elif change == 'inactive':
                    (self.root / 'xorg-state').write_text('failed\n')
                else:
                    (self.root / 'Xorg.0.log').unlink()
                done, profile, bus = self.run_session()
                self.assertEqual((done.returncode, profile), (0, 'copy\n'), done.stderr)
                self.assertEqual(done.stdout.splitlines(), sorted(r4plan.COPY_ENV))
                self.assertEqual(bus, 'unix:path=/tmp/m19-test-bus,guid=1\n')

    def test_no_x_server_no_session(self):
        (self.root / 'x-up').unlink()
        done, profile, bus = self.run_session()
        self.assertNotEqual(done.returncode, 0)
        self.assertEqual((profile, bus, done.stdout), (None, None, ''))


XFCONF = '''#!/bin/sh
d=$(dirname "$0")
echo "$DBUS_SESSION_BUS_ADDRESS|$*" >> "$d/calls"
[ "$*" != "$(cat "$d/fail" 2>/dev/null)" ] || exit 1
case "$*" in
 "-c xfwm4 -p /general/use_compositing") echo true;;
 "-c xfwm4 -p /general/unredirect_overlays") echo false;;
 "-c xfwm4 -p /general/vblank_mode") exit 1;;
esac
'''


class CompositorScript(unittest.TestCase):
    """r4plan.COMPOSITOR with xfconf-query replaced by a fake that logs the bus and its arguments."""

    def run_compositor(self, *arguments, bus_file='unix:path=/tmp/m19-test-bus\n', bus=None, fail=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'xfconf-query').write_text(XFCONF)
            (root / 'xfconf-query').chmod(0o755)
            if bus_file is not None:
                (root / 'session-bus').write_text(bus_file)
            if fail:
                (root / 'fail').write_text(fail + '\n')
            script = r4plan.COMPOSITOR
            for old, new in (('/usr/bin/xfconf-query', f'{root}/xfconf-query'), ('/run/m19/session-bus', f'{root}/session-bus')):
                self.assertIn(old, script)
                script = script.replace(old, new)
            (root / 'compositor').write_text(script)
            environment = {key: value for key, value in os.environ.items() if not key.startswith('DBUS')}
            if bus:
                environment['DBUS_SESSION_BUS_ADDRESS'] = bus
            done = subprocess.run(['sh', str(root / 'compositor'), *arguments], capture_output=True, text=True, env=environment, timeout=30)
            calls = (root / 'calls').read_text().splitlines() if (root / 'calls').exists() else []
            return done.returncode, calls, done.stdout

    def test_on_sets_xpresent_and_unredirect_before_compositing(self):
        bus = 'unix:path=/tmp/m19-test-bus|-c xfwm4 '
        self.assertEqual(self.run_compositor('on'), (0, [bus + '-p /general/vblank_mode -n -t string -s xpresent',
                                                         bus + '-p /general/unredirect_overlays -n -t bool -s true',
                                                         bus + '-p /general/use_compositing -n -t bool -s true'], ''))

    def test_on_stops_at_the_first_setting_that_fails(self):
        rc, calls, _ = self.run_compositor('on', fail='-c xfwm4 -p /general/vblank_mode -n -t string -s xpresent')
        self.assertEqual((rc, len(calls)), (1, 1))

    def test_off_only_stops_compositing(self):
        self.assertEqual(self.run_compositor('off'), (0, ['unix:path=/tmp/m19-test-bus|-c xfwm4 -p /general/use_compositing -n -t bool -s false'], ''))

    def test_show_prints_each_setting_or_unset(self):
        rc, calls, out = self.run_compositor('show')
        self.assertEqual((rc, out), (0, 'use_compositing=true\nvblank_mode=unset\nunredirect_overlays=false\n'))
        self.assertEqual(len(calls), 3)

    def test_the_session_bus_comes_from_the_environment_or_the_file(self):
        rc, calls, _ = self.run_compositor('off', bus_file=None, bus='unix:path=/tmp/other')
        self.assertEqual((rc, calls), (0, ['unix:path=/tmp/other|-c xfwm4 -p /general/use_compositing -n -t bool -s false']))
        self.assertEqual(self.run_compositor('on', bus_file=None), (69, [], ''))

    def test_anything_else_does_nothing(self):
        for arguments in ((), ('yes',), ('ON',)):
            self.assertEqual(self.run_compositor(*arguments), (64, [], ''), arguments)


def start_xvfb(xvfb, geometry, *extra):
    """An Xvfb on a display it picks itself and names once it accepts clients, so mutants can run side by side."""
    read, write = os.pipe()
    server = subprocess.Popen([xvfb, '-displayfd', str(write), '-screen', '0', geometry, '-nolisten', 'tcp', *extra], pass_fds=(write,),
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    os.close(write)
    with os.fdopen(read) as pipe:
        number = pipe.readline().strip()
    return server, f':{number}'


class PresentProbe(unittest.TestCase):
    """present-probe.c against Xvfb, whose Present has a fake 60 Hz vblank and never flips. test.sh and mutate.py build it."""

    @classmethod
    def setUpClass(cls):
        cls.probe, cls.xvfb, cls.server = os.environ.get('M19_PRESENT_PROBE'), os.environ.get('M19_XVFB'), None
        if cls.probe and cls.xvfb:
            cls.server, cls.display = start_xvfb(cls.xvfb, '1080x2400x24')

    @classmethod
    def tearDownClass(cls):
        if cls.server:
            cls.server.kill()
            cls.server.wait()

    def setUp(self):
        if not self.server:
            self.skipTest('present probe or Xvfb not available in this run')

    def run_probe(self, *arguments, display=None):
        environment = {key: value for key, value in os.environ.items() if not key.startswith(('ASAN', 'UBSAN'))}
        environment['DISPLAY'] = display or self.display
        return subprocess.run([self.probe, *arguments], capture_output=True, text=True, env=environment, timeout=60)

    def summary(self, out, mode):
        line = re.search(rf'M19 PRESENT {mode} (frames=.*)\n', out).group(1)
        return {key: float(value) for key, value in (item.split('=') for item in line.split())}

    def test_copies_complete_one_vblank_apart(self):
        done = self.run_probe('copy', '30')
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        s = self.summary(done.stdout, 'copy')
        self.assertEqual((s['frames'], s['done'], s['copies'], s['flips'], s['skips'], s['others']), (30, 30, 30, 0, 0, 0))
        # Each request aims at the vblank after the last completion; a loaded runner may miss the odd one.
        self.assertTrue(0.9 <= s['msc_per_frame'] <= 1.5, s)
        # Xvfb's fake vblank is 1/60 s; each frame's UST time is its MSCs times that.
        self.assertAlmostEqual(s['us_per_frame'] / s['msc_per_frame'], 16667, delta=4000)
        self.assertIn('M19 PRESENT copy version=1.', done.stdout)
        self.assertTrue(done.stdout.endswith('M19 PRESENT copy ok\n'))

    def test_a_window_covering_the_screen_completes_without_flips_here(self):
        done = self.run_probe('flip', '20')
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        s = self.summary(done.stdout, 'flip')
        self.assertEqual((s['done'], s['flips'], s['copies'] + s['skips'] + s['others']), (20, 0, 20))

    def test_nothing_composites_on_bare_xvfb(self):
        done = self.run_probe('compositor')
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual(done.stdout, 'M19 PRESENT compositor owner=0x00000000\nM19 PRESENT compositor ok\n')

    def test_usage_and_no_server(self):
        for arguments in ((), ('copy',), ('copy', '1'), ('flip', 'x'), ('other', '10'), ('copy', '10', 'x'), ('compositor', 'x'), ('root', 'x'),
                          ('vblank', '10'), ('vblank', 'x', '/dev/null'), ('crtc', '1', '/dev/null'), ('crtc', '10', '/dev/null', 'x'),
                          ('vblank', '10001', '/dev/null'), ('xread',), ('xread', 'a', 'b'), ('gpuwrite', 'x'), ('chain', 'x'), ('xlate',),
                          ('xlate', 'a', 'b'), ('chainlate', 'x'), ('chainlater',), ('xagain',), ('xwait', 'a', 'b'), ('kgslsync', 'a'),
                          ('kgslsync', 'a', 'b', 'c'), ('xsync', 'a', 'b'), ('xsync', 'a', 'b', 'obj-wipe'), ('xsync', 'a', 'b', 'obj-clean', 'x'),
                          ('chainsync', 'a'), ('chainsync', 'a', 'flush'), ('chainagain', 'x'), ('xreimport',), ('glimport',),
                          ('glimport', 'a', 'b'), ('gbmimport', 'a'), ('gbmimport', 'a', 'b', 'c')):
            self.assertEqual(self.run_probe(*arguments).returncode, 64, arguments)
        done = self.run_probe('copy', '10', display=':119')
        self.assertEqual(done.returncode, 1)
        self.assertIn('M19 PRESENT copy FAIL connect', done.stdout)
        done = self.run_probe('compositor', display=':119')
        self.assertEqual((done.returncode, done.stdout), (1, 'M19 PRESENT compositor FAIL connect\n'))
        done = self.run_probe('root', display=':119')
        self.assertEqual((done.returncode, done.stdout), (1, 'M19 PRESENT root FAIL connect\n'))

    def test_xread_fills_its_buffer_then_needs_dri3(self):
        fake = os.environ.get('M19_FAKE_CARD')
        if not fake:
            self.skipTest('fake card not built in this run')
        with tempfile.TemporaryDirectory() as directory:
            heap = Path(directory) / 'heap'
            heap.write_text('')
            environment = {key: value for key, value in os.environ.items() if not key.startswith(('ASAN', 'UBSAN', 'M19_FAKE_'))}
            environment.update(DISPLAY=self.display, LD_PRELOAD=fake)
            done = subprocess.run([self.probe, 'xread', str(heap)], capture_output=True, text=True, env=environment, timeout=60)
        self.assertEqual((done.returncode, done.stdout), (1, 'M19 PRESENT xread cpu=1000\nM19 PRESENT xread FAIL no dri3\n'))

    def test_xlate_writes_only_once_the_server_has_the_buffer(self):
        fake = os.environ.get('M19_FAKE_CARD')
        if not fake:
            self.skipTest('fake card not built in this run')
        with tempfile.TemporaryDirectory() as directory:
            heap = Path(directory) / 'heap'
            heap.write_text('')
            environment = {key: value for key, value in os.environ.items() if not key.startswith(('ASAN', 'UBSAN', 'M19_FAKE_'))}
            environment.update(DISPLAY=self.display, LD_PRELOAD=fake)
            done = subprocess.run([self.probe, 'xlate', str(heap)], capture_output=True, text=True, env=environment, timeout=60)
            # Xvfb has no DRI3: no import, so nothing is written.
            self.assertEqual((done.returncode, done.stdout), (1, 'M19 PRESENT xlate FAIL no dri3\n'))
            # R4l: nor by the modes built on xlate, KGSL's operation included.
            for mode, extra in (('xsync', (str(heap), 'obj-clean')), ('xagain', ()), ('xwait', ()), ('xreimport', ())):
                done = subprocess.run([self.probe, mode, str(heap), *extra], capture_output=True, text=True, env=environment, timeout=60)
                self.assertEqual((done.returncode, done.stdout, done.stderr), (1, f'M19 PRESENT {mode} FAIL no dri3\n', ''), mode)

    def root(self, out):
        line = re.fullmatch(r'M19 PRESENT root (width=\S+ height=\S+ nonblack=\S+ mean=\S+)\nM19 PRESENT root ok\n', out).group(1)
        return {key: int(value) for key, value in (item.split('=') for item in line.split())}

    def test_a_bare_server_has_a_black_root(self):
        done = self.run_probe('root')
        self.assertEqual((done.returncode, self.root(done.stdout)), (0, {'width': 1080, 'height': 2400, 'nonblack': 0, 'mean': 0}))

    def test_the_retro_root_is_its_weave(self):
        server, display = start_xvfb(self.xvfb, '72x130x24', '-retro')
        try:
            done = self.run_probe('root', display=display)
        finally:
            server.kill()
            server.wait()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        r = self.root(done.stdout)
        # The classic root weave: some pixels white, the rest black.
        self.assertTrue(0 < r['nonblack'] < 1000, r)
        self.assertLessEqual(abs(r['mean'] - r['nonblack'] * 255 // 1000), 1, r)

    def test_black_and_white_roots_read_as_they_are(self):
        for option, want in (('-br', {'width': 72, 'height': 130, 'nonblack': 0, 'mean': 0}),
                             ('-wr', {'width': 72, 'height': 130, 'nonblack': 1000, 'mean': 255})):
            server, display = start_xvfb(self.xvfb, '72x130x24', option)
            try:
                done = self.run_probe('root', display=display)
            finally:
                server.kill()
                server.wait()
            self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
            self.assertEqual(self.root(done.stdout), want, option)


class CardProbe(unittest.TestCase):
    """present-probe.c's vblank and crtc modes on fake-card.c, a preloaded DRM card with a simulated 120 Hz clock."""

    @classmethod
    def setUpClass(cls):
        cls.probe, cls.fake = os.environ.get('M19_PRESENT_PROBE'), os.environ.get('M19_FAKE_CARD')

    def setUp(self):
        if not self.probe or not self.fake:
            self.skipTest('present probe or fake card not available in this run')
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.card = Path(directory.name) / 'card0'
        self.card.write_text('')

    def run_probe(self, *arguments, egl_lib=None, gles_lib=None, gbm_lib=None, **fake):
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith(('ASAN', 'UBSAN', 'M19_FAKE_', 'DISPLAY', 'M19_EGL', 'M19_GLES', 'M19_GBM'))}
        environment.update(LD_PRELOAD=self.fake, DISPLAY=':119', **{f'M19_FAKE_{key.upper()}': value for key, value in fake.items()})
        if egl_lib:
            environment['M19_EGL_LIB'] = egl_lib
        if gles_lib:
            environment['M19_GLES_LIB'] = gles_lib
        if gbm_lib:
            environment['M19_GBM_LIB'] = gbm_lib
        return subprocess.run([self.probe, *arguments], capture_output=True, text=True, env=environment, timeout=60)

    def vblank(self, out):
        line = re.fullmatch(r'M19 PRESENT vblank (frames=.*)\nM19 PRESENT vblank ok\n', out).group(1)
        return {key: float(value) for key, value in (item.split('=') for item in line.split())}

    def test_vblanks_one_frame_apart(self):
        done = self.run_probe('vblank', '20', str(self.card))
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        v = self.vblank(done.stdout)
        self.assertEqual(v['frames'], 20)
        # A loaded runner may oversleep the odd frame.
        for name in ('wait_seq', 'event_seq'):
            self.assertTrue(1.0 <= v[name] <= 1.3, v)
        self.assertLessEqual(v['late'], 2, v)
        self.assertAlmostEqual(v['wait_us'] / v['wait_seq'], 8333, delta=60)
        self.assertAlmostEqual(v['event_us'] / v['event_seq'], 8333, delta=60)
        self.assertTrue(4000 <= v['event_wall_us'] <= 12000, v)

    def test_late_vblanks_show_as_two_frames_and_late_events(self):
        done = self.run_probe('vblank', '20', str(self.card), lag='1')
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        v = self.vblank(done.stdout)
        for name in ('wait_seq', 'event_seq'):
            self.assertTrue(2.0 <= v[name] <= 2.3, v)
        self.assertEqual(v['late'], 20)
        self.assertAlmostEqual(v['event_us'] / v['event_seq'], 8333, delta=60)
        self.assertTrue(12000 <= v['event_wall_us'] <= 20000, v)

    def test_vblank_failures(self):
        for fail, want in (('wait', 'M19 PRESENT vblank FAIL wait errno=22\n'), ('event', 'M19 PRESENT vblank FAIL queue errno=22\n'),
                           ('deliver', 'M19 PRESENT vblank FAIL event after 0\n')):
            done = self.run_probe('vblank', '5', str(self.card), fail=fail)
            self.assertEqual((done.returncode, done.stdout), (1, want), fail)
        done = self.run_probe('vblank', '5', str(self.card) + '-missing')
        self.assertEqual((done.returncode, done.stdout), (1, 'M19 PRESENT vblank FAIL open errno=2\n'))

    def test_the_active_crtc_and_its_framebuffer(self):
        done = self.run_probe('crtc', '5', str(self.card))
        self.assertEqual((done.returncode, done.stdout), (0, 'M19 PRESENT crtc id=31 mode=1080x2400x120_vid refresh=120 fb=76 fbs=1 changes=0 '
                                                             'samples=5 pitch=4352 bpp=32\nM19 PRESENT crtc ok\n'))

    def test_an_unreadable_framebuffer_leaves_its_pitch_unknown(self):
        done = self.run_probe('crtc', '5', str(self.card), fail='fb')
        self.assertEqual((done.returncode, done.stdout), (0, 'M19 PRESENT crtc id=31 mode=1080x2400x120_vid refresh=120 fb=76 fbs=1 changes=0 '
                                                             'samples=5 pitch=-1 bpp=-1\nM19 PRESENT crtc ok\n'))

    def test_page_flips_change_the_framebuffer(self):
        done = self.run_probe('crtc', '5', str(self.card), flips='1')
        self.assertEqual((done.returncode, done.stdout), (0, 'M19 PRESENT crtc id=31 mode=1080x2400x120_vid refresh=120 fb=76 fbs=2 changes=5 '
                                                             'samples=5 pitch=4352 bpp=32\nM19 PRESENT crtc ok\n'))

    def test_xread_heap_failures_and_no_server(self):
        for env, path, want in (({}, str(self.card) + '-missing', 'M19 PRESENT xread FAIL heap open errno=2\n'),
                                ({'fail': 'heap'}, str(self.card), 'M19 PRESENT xread FAIL heap alloc errno=22\n'),
                                ({}, str(self.card), 'M19 PRESENT xread cpu=1000\nM19 PRESENT xread FAIL connect\n')):
            done = self.run_probe('xread', path, **env)
            self.assertEqual((done.returncode, done.stdout), (1, want), env)
        # R4k: xlate fails as xread does, but writes nothing before the X server has the buffer.
        for env, path, want in (({}, str(self.card) + '-missing', 'M19 PRESENT xlate FAIL heap open errno=2\n'),
                                ({'fail': 'heap'}, str(self.card), 'M19 PRESENT xlate FAIL heap alloc errno=22\n'),
                                ({}, str(self.card), 'M19 PRESENT xlate FAIL connect\n')):
            done = self.run_probe('xlate', path, **env)
            self.assertEqual((done.returncode, done.stdout), (1, want), env)
        # R4l: the modes built on xlate fail as it does.
        for mode, extra in (('xsync', (str(self.card), 'cache-flush')), ('xagain', ()), ('xwait', ()), ('xreimport', ())):
            done = self.run_probe(mode, str(self.card) + '-missing', *extra)
            self.assertEqual((done.returncode, done.stdout), (1, f'M19 PRESENT {mode} FAIL heap open errno=2\n'), mode)
            done = self.run_probe(mode, str(self.card), *extra)
            self.assertEqual((done.returncode, done.stdout, done.stderr), (1, f'M19 PRESENT {mode} FAIL connect\n', ''), mode)

    def test_kgslsync_runs_each_cache_operation_alone(self):
        done = self.run_probe('kgslsync', str(self.card), str(self.card))
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        lines = done.stdout.splitlines()
        self.assertEqual((lines[0], lines[5:]), ('M19 PRESENT kgslsync cpu=1000', ['M19 PRESENT kgslsync ok']))
        ops = [re.fullmatch(r'M19 PRESENT kgslsync kgsl op=(\S+) open=0 import=0 rc=0 us=\d+', line).group(1) for line in lines[1:5]]
        self.assertEqual(ops, ['obj-clean', 'obj-flush', 'cache-clean', 'cache-flush'])
        # Each over the whole buffer, from its start: CLEAN is 1, FLUSH 3; each import released once.
        size = str(256 * 256 * 4)
        self.assertEqual(re.findall(r'fake kgsl (\w+) op=(\d+) offset=(\d+) length=(\d+)\n', done.stderr),
                         [('obj', '1', '0', size), ('obj', '3', '0', size), ('cache', '1', '0', size), ('cache', '3', '0', size)])
        self.assertEqual(done.stderr.count('fake kgsl free id=42\n'), 4)

    def test_kgsl_failures_read_as_errnos_and_unreached_steps_as_minus_one(self):
        for env, node, want in (({'fail': 'kgsl-import'}, str(self.card), 'open=0 import=22 rc=-1 us=0'),
                                ({}, str(self.card) + '-missing', 'open=2 import=-1 rc=-1 us=0')):
            done = self.run_probe('kgslsync', str(self.card), node, **env)
            self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
            self.assertEqual(len(re.findall(rf'M19 PRESENT kgslsync kgsl op=\S+ {want}\n', done.stdout)), 4, env)
            self.assertNotIn('fake kgsl', done.stderr)
        for fail, want in (('kgsl-obj', [('obj-clean', '22'), ('obj-flush', '22'), ('cache-clean', '0'), ('cache-flush', '0')]),
                           ('kgsl-cache', [('obj-clean', '0'), ('obj-flush', '0'), ('cache-clean', '22'), ('cache-flush', '22')])):
            done = self.run_probe('kgslsync', str(self.card), str(self.card), fail=fail)
            self.assertEqual(re.findall(r'op=(\S+) open=0 import=0 rc=(\d+) us=\d+\n', done.stdout), want, fail)
            self.assertEqual(done.stderr.count('fake kgsl free id=42\n'), 4)

    def test_gpuwrite_and_chain_need_egl(self):
        for mode in ('gpuwrite', 'chain', 'chainlate'):
            done = self.run_probe(mode, egl_lib='/nonexistent/libEGL.so.1')
            self.assertEqual((done.returncode, done.stdout), (1, f'M19 PRESENT {mode} FAIL egl load\n'), mode)
        # R4m: the imports without X take the heap first, then GBM on the card, then EGL; and print nothing else.
        for arguments, want in ((('glimport', str(self.card) + '-missing'), 'FAIL heap open errno=2'),
                                (('glimport', str(self.card)), 'FAIL egl load'),
                                (('gbmimport', str(self.card) + '-missing', str(self.card)), 'FAIL heap open errno=2'),
                                (('gbmimport', str(self.card), str(self.card) + '-missing'), 'FAIL card open errno=2'),
                                (('gbmimport', str(self.card), str(self.card)), 'FAIL gbm')):
            done = self.run_probe(*arguments, egl_lib='/nonexistent/libEGL.so.1', gbm_lib='/nonexistent/libgbm.so.1')
            self.assertEqual((done.returncode, done.stdout), (1, f'M19 PRESENT {arguments[0]} {want}\n'), arguments)
        # R4l: and the late GPU modes, before any KGSL operation.
        for arguments in (('chainsync', str(self.card), 'obj-flush'), ('chainagain',)):
            done = self.run_probe(*arguments, egl_lib='/nonexistent/libEGL.so.1')
            self.assertEqual((done.returncode, done.stdout, done.stderr), (1, f'M19 PRESENT {arguments[0]} FAIL egl load\n', ''), arguments)
        # EGL alone missing is enough, whatever GLES does.
        done = self.run_probe('gpuwrite', egl_lib='/nonexistent/libEGL.so.1', gles_lib='libc.so.6')
        self.assertEqual((done.returncode, done.stdout), (1, 'M19 PRESENT gpuwrite FAIL egl load\n'))

    def test_crtc_failures(self):
        for fail, want in (('resources', 'M19 PRESENT crtc FAIL resources errno=22\n'), ('crtc', 'M19 PRESENT crtc FAIL no active crtc\n')):
            done = self.run_probe('crtc', '5', str(self.card), fail=fail)
            self.assertEqual((done.returncode, done.stdout), (1, want), fail)
        done = self.run_probe('crtc', '5', str(self.card) + '-missing')
        self.assertEqual((done.returncode, done.stdout), (1, 'M19 PRESENT crtc FAIL open errno=2\n'))


class DesktopScript(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name) / 'root'
        self.test = Path(self.directory.name) / 'test'
        self.test.mkdir()
        (self.test / 'bb').write_text(FAKE_BB)
        (self.test / 'bb').chmod(0o755)
        (self.root / 'm19').mkdir(parents=True, exist_ok=True)
        (self.root / 'm19/m19-xorg-shim.so').write_bytes(b'\x7fELF shim')
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
        writeback = self.root / 'sys/class/drm/card0-Virtual-1'
        writeback.mkdir(parents=True)
        (writeback / 'status').write_text('connected\n')
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
        self.assertEqual((self.new / 'run/m19/m19-xorg-shim.so').read_bytes(), b'\x7fELF shim')
        self.assertEqual(oct((self.new / 'run/m19/m19-xorg-shim.so').stat().st_mode & 0o777), '0o644')
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
        self.assertEqual((self.root / 'sys/class/drm/card0-Virtual-1/status').read_text(), 'off')
        self.assertIn(' writeback=off\n', result.stderr)

    def test_a_missing_mode_stops(self):
        (self.root / 'sys/class/drm/card0-DSI-1/modes').write_text('1080x2400x60vid\n1080x2400x90vid\n')
        self.assertFails('panel mode 1080x2400x120vid')

    def test_a_writeback_that_stays_connected_stops(self):
        result = self.run_script(M19_WB_STUCK='1')
        self.assertIn('M19 T9 desktop failed: writeback-still-connected\n', result.stderr)
        self.assertFalse((self.new / 'run/m19/xorg.conf').exists())

    def test_no_writeback_connector_is_recorded(self):
        shutil.rmtree(self.root / 'sys/class/drm/card0-Virtual-1')
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(' writeback=absent\n', result.stderr)

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

    def test_a_missing_shim_stops(self):
        (self.root / 'm19/m19-xorg-shim.so').unlink()
        self.assertFails('xorg-shim')

    def test_a_missing_tool_stops(self):
        (self.new / 'usr/bin/xinput').unlink()
        self.assertFails('missing usr/bin/xinput')

    def test_bad_plan_lines_stop(self):
        for name, text, reason in (('hidden', '../x\n', 'hidden name ../x'), ('touch', 'goodix ts\n', 'touch name goodix ts'),
                                   ('writeback', 'card0-DSI-1\n', 'writeback name card0-DSI-1'),
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


class DesktopFixture(ReportBase):
    """The desktop's fakes, shared by R3's desktop checks and R4's GPU checks."""

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

    def desktop(self, log):
        return dict(item.split('=') for item in re.search(r'M19 R3 desktop (.*)\n', log).group(1).split())


class Landscape(DesktopFixture):
    """R6: the desktop turned right, as xrandr reports it, wider than tall."""

    def run_turned(self, query, rotation='right'):
        (self.test / 'xrandr-query').write_text(query)
        wire = Wire()
        environment = dict(os.environ, ASAN_OPTIONS='detect_leaks=0', M19_VBLANK_HZ='120', M19_TEST_ROTATION=rotation)
        subprocess.run([ARGS.driver, 'report-desktop', str(self.root), wire.path, '300', '5000', '300'], capture_output=True, timeout=60,
                       env=environment)
        _, log, _ = self.parse(wire.close())
        line = re.search(r'M19 R6 landscape (.*)\n', log)
        return log, dict(item.split('=') for item in line.group(1).split())

    TURNED = ('DSI-1 connected primary 2400x1080+0+0 right (normal left inverted right x axis y axis) 69mm x 154mm\n'
              '   1080x2400x60vid  60.00 +\n   1080x2400x120vid 90.00   120.00*\n')

    def test_turned_right_passes(self):
        log, land = self.run_turned(self.TURNED)
        self.assertEqual(land, {'rotation': 'right', 'screen': '2400x1080', 'landscape_ok': '1'})
        self.assertEqual(self.desktop(log)['mode'], '1080x2400x120vid')
        self.assertEqual(self.verdict(log)['all_ok'], '1')

    def test_portrait_or_the_other_way_fails(self):
        for query, rotation in (('DSI-1 connected primary 1080x2400+0+0 (normal left inverted right x axis y axis) 69mm x 154mm\n'
                                 '   1080x2400x120vid 120.00*\n', 'normal'),
                                (self.TURNED.replace(' right (', ' left ('), 'left'),
                                ('DSI-1 connected primary 1080x2400+0+0 right (normal left inverted right x axis y axis)\n'
                                 '   1080x2400x120vid 120.00*\n', 'right'),
                                ('DSI-1 connected (normal left inverted right x axis y axis)\n   1080x2400x120vid 120.00*\n', 'none')):
            with self.subTest(rotation=rotation, query=query[:40]):
                log, land = self.run_turned(query)
                self.assertEqual((land['rotation'], land['landscape_ok']), (rotation, '0'))
                self.assertEqual(self.verdict(log)['all_ok'], '0')

    def test_without_a_rotation_nothing_is_judged(self):
        (self.test / 'xrandr-query').write_text('DSI-1 connected primary 1080x2400+0+0\n   1080x2400x120vid 120.00*\n')
        wire = Wire()
        subprocess.run([ARGS.driver, 'report-desktop', str(self.root), wire.path, '300', '5000', '300'], capture_output=True, timeout=60,
                       env=dict(os.environ, ASAN_OPTIONS='detect_leaks=0', M19_VBLANK_HZ='120'))
        _, log, _ = self.parse(wire.close())
        self.assertNotIn('M19 R6 landscape', log)


class Desktop(DesktopFixture):
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
                    (self.test / 'xi2').write_text('EVENT type 9 (FocusIn)\nEVENT type 7 (Enter)\n')
                fields, log, _ = self.parse(self.run_desktop()[0])
                self.assertEqual((fields[3], self.desktop(log)['touch_ok']), ('0', '0'))

    def test_a_swipe_already_under_way_counts_by_its_updates(self):
        (self.test / 'xi2').write_text('EVENT type 19 (TouchUpdate)\nEVENT type 23 (RawTouchUpdate)\nEVENT type 6 (Motion)\n'
                                       'EVENT type 17 (RawMotion)\nEVENT type 19 (TouchUpdate)\n')
        fields, log, steps = self.parse(self.run_desktop()[0])
        self.assertEqual((fields[3], self.desktop(log)['touch_events'], self.desktop(log)['touch_ok']), ('1', '5', '1'))
        self.assertIn('M19STEP T12-touch END 12 5', steps)

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

    def test_the_xorg_log_leaves_out_the_touch_flood(self):
        flood = 'source device 6: history size 6400 overflowing for touch 1\n'
        (self.root / 'xorg0.log').write_text('(II) first\n' + flood * 5000 + '(EE) after the flood\n' + 'x' * 20000 + '\n' + flood + 'tail')
        _, log, _ = self.parse(self.run_desktop()[0])
        section = log[log.index(f'M19 {self.root}/xorg0.log\n'):]
        self.assertNotIn('overflowing for touch 1', section)
        for text in ('(II) first\n(EE) after the flood\n', 'x' * 20000 + '\ntail', 'M19 left out 5001 lines holding "overflowing for touch"\n'):
            self.assertIn(text, section)

    def test_the_xorg_log_keeps_at_most_its_cap(self):
        line = 'y' * 99 + '\n'
        (self.root / 'xorg0.log').write_text(line * 3000 + 'source device 6: overflowing for touch 1\n' + '(EE) past the cap\n')
        _, log, _ = self.parse(self.run_desktop()[0])
        start = log.index(f'M19 {self.root}/xorg0.log\n') + len(f'M19 {self.root}/xorg0.log\n')
        end = log.index('M19 left out 1 lines holding "overflowing for touch", cut at the cap\n')
        self.assertEqual(log[start:end], line * (128 * 1024 // 100))
        self.assertNotIn('(EE) past the cap', log)

    def test_r2_failures_still_fail_the_desktop_run(self):
        self.counter('sda', 4)
        fields, log, _ = self.parse(self.run_desktop()[0])
        self.assertEqual((fields[3], self.verdict(log)['writes'], self.desktop(log)['touch_ok']), ('0', '0', '1'))


GPU_TOOLS = (('gpu-probe', '''#!/bin/sh
case "$*" in vulkan) ;; "dmabuf ${2:-}") [ "${2##*/}" = heap ] || exit 64;; *) exit 64;; esac
d=$(dirname "$0")
if [ "$VK_DRIVER_FILES" != /usr/share/vulkan/icd.d/freedreno_icd.aarch64.json ]; then echo "M19 GPU vulkan FAIL no device result=-9"; exit 1; fi
if [ "$1" = dmabuf ]; then echo "M19 GPU dmabuf cpu=1000 late=0 again=1000 first=0"; echo "M19 GPU dmabuf ok"; exit 0; fi
cat "$d/probe-out"; exit "$(cat "$d/probe-rc")"
'''), ('vulkaninfo', '''#!/bin/sh
d=$(dirname "$0")
[ "$1" = --summary ] || exit 2
if [ "$VK_DRIVER_FILES" = /usr/share/vulkan/icd.d/freedreno_icd.aarch64.json ]; then cat "$d/vulkaninfo-out"; else
 printf 'GPU0:\\n\\tdeviceName = llvmpipe (LLVM 20.1.0, 128 bits)\\n\\tdriverID = DRIVER_ID_MESA_LLVMPIPE\\n'; fi
'''), ('vkcube', '''#!/bin/sh
[ "$1 $2" = "--c 300" ] && [ -n "$VK_DRIVER_FILES" ] && [ "$MESA_LOADER_DRIVER_OVERRIDE" = kgsl ] || { echo "vulkan: no device"; exit 1; }
[ ! -e "$(dirname "$0")/vkcube-hang" ] || exec sleep 30
exit "$(cat "$(dirname "$0")/vkcube-rc")"
'''), ('glxinfo', '''#!/bin/sh
[ "$1" = -B ] || exit 2
if [ "$MESA_LOADER_DRIVER_OVERRIDE" = kgsl ] && [ "$FD_FORCE_KGSL" = 1 ] && [ "$FD_KGSL_ENABLE_DMABUF" = 1 ]; then cat "$(dirname "$0")/glxinfo-out"
elif [ "$MESA_LOADER_DRIVER_OVERRIDE" = zink ] && [ "$LIBGL_KOPPER_DRI2" = 1 ] && [ "$MESA_VK_WSI_DEBUG" = sw ]; then
 echo "OpenGL renderer string: zink Vulkan 1.4(Turnip Adreno (TM) 725 (MESA_TURNIP))"
else echo "OpenGL renderer string: llvmpipe (LLVM 20.1.0, 128 bits)"; fi
'''), ('glxgears', '''#!/bin/sh
d=$(dirname "$0")
[ "$MESA_LOADER_DRIVER_OVERRIDE" = kgsl ] || { echo "1 frames in 5.0 seconds = 0.2 FPS"; exit 1; }
cat "$d/gears-out"
# The X server worked meanwhile: 60 more ticks of CPU time.
echo "104 (Xorg) S 1 104 104 0 -1 4194560 100 0 0 0 310 30 0 0 20 0 2 0 5 0 0" > "$d/../proc/104/stat"
exec sleep 30
'''), ('glmark2', '''#!/bin/sh
[ "$*" = "-b build:duration=2.0 -b texture:duration=2.0 -b shading:duration=2.0" ] && [ "$MESA_LOADER_DRIVER_OVERRIDE" = kgsl ] || exit 2
cat "$(dirname "$0")/glmark2-out"; exit "$(cat "$(dirname "$0")/glmark2-rc")"
'''), ('present-probe', '''#!/bin/sh
d=$(dirname "$0")
state=$(cat "$d/compositor-state")
case "$1" in
 compositor) [ "$#" = 1 ] || exit 64; owner=$(cat "$d/owner-$state")
  # xfwm4 takes a moment to own the selection: from the second query after on.
  if [ "$state" = on ]; then n=$(($(cat "$d/on-queries") + 1)); echo "$n" >"$d/on-queries"; [ "$n" -gt 1 ] || owner=0x00000000; fi
  echo "M19 PRESENT compositor owner=$owner"; exit "$(cat "$d/present-compositor-rc")";;
 copy|flip) [ "$#" = 2 ] && [ "$2" = 120 ] || exit 64; mode=$1; [ "$state" != on ] || mode=$1-on; cat "$d/present-$mode-out"
  exit "$(cat "$d/present-$1-rc")";;
 vblank) [ "$#" = 3 ] && [ "$2" = 120 ] && [ "${3##*/}" = card ] || exit 64; cat "$d/vblank-out"; exit "$(cat "$d/vblank-rc")";;
 crtc) [ "$#" = 3 ] && [ "$2" = 50 ] && [ "${3##*/}" = card ] || exit 64; cat "$d/crtc-$state-out"; exit "$(cat "$d/crtc-rc")";;
 xread|xlate) [ "$#" = 2 ] && [ "${2##*/}" = heap ] || exit 64; cat "$d/$1-out";;
 xagain|xwait|xreimport) [ "$#" = 2 ] && [ "${2##*/}" = heap ] || exit 64; echo "M19 PRESENT $1 read";;
 glimport) [ "$#" = 2 ] && [ "${2##*/}" = heap ] || exit 64
  [ "${MESA_LOADER_DRIVER_OVERRIDE:-}" = kgsl ] || { echo "M19 PRESENT $1 FAIL egl init"; exit 1; }; echo "M19 PRESENT glimport read";;
 gbmimport) [ "$#" = 3 ] && [ "${2##*/}" = heap ] && [ "${3##*/}" = card ] || exit 64
  [ "${MESA_LOADER_DRIVER_OVERRIDE:-}" = kgsl ] || { echo "M19 PRESENT $1 FAIL egl init"; exit 1; }; echo "M19 PRESENT gbmimport read";;
 kgslsync) [ "$#" = 3 ] && [ "${2##*/}" = heap ] && [ "${3##*/}" = kgsl-node ] || exit 64; echo "M19 PRESENT kgslsync ok";;
 xsync) [ "$#" = 4 ] && [ "${2##*/}" = heap ] && [ "${3##*/}" = kgsl-node ] || exit 64; echo "M19 PRESENT xsync $4";;
 chainsync) [ "$#" = 3 ] && [ "${2##*/}" = kgsl-node ] || exit 64
  [ "${MESA_LOADER_DRIVER_OVERRIDE:-}" = kgsl ] || { echo "M19 PRESENT $1 FAIL egl init"; exit 1; }; echo "M19 PRESENT chainsync $3";;
 chainagain) [ "$#" = 1 ] || exit 64
  [ "${MESA_LOADER_DRIVER_OVERRIDE:-}" = kgsl ] || { echo "M19 PRESENT $1 FAIL egl init"; exit 1; }; echo "M19 PRESENT chainagain read";;
 gpuwrite|chain|chainlate) [ "$#" = 1 ] || exit 64
  [ "${MESA_LOADER_DRIVER_OVERRIDE:-}" = kgsl ] || { echo "M19 PRESENT $1 FAIL egl init"; exit 1; }; cat "$d/$1-out";;
 root) [ "$#" = 1 ] || exit 64
  if [ "${LIBGL_ALWAYS_SOFTWARE:-}" = 1 ]; then cat "$d/root-soft-out"
  elif [ "${MESA_VK_WSI_DEBUG:-}" = sw ]; then cat "$d/root-copy-out"
  elif [ "${MESA_LOADER_DRIVER_OVERRIDE:-}" = kgsl ]; then cat "$d/root-dri3-out"
  else cat "$d/root-$state-out"; fi;;
 *) exit 64;;
esac
'''), ('gpu-compositor', '''d=$(dirname "$0")
echo "$*" >> "$d/compositor-calls"
case "$*" in
 on) echo on >"$d/compositor-state"; echo 0 >"$d/on-queries"
  # Mesa's GLX library lands in xfwm4's maps, across the end of the reporter's first 64 KiB read.
  head -c 65530 /dev/zero | tr '\\0' x >"$d/../proc/101/maps"; printf 'libGLX_mesa.so.0\\n' >>"$d/../proc/101/maps"
  exit "$(cat "$d/compositor-on-rc")";;
 off) echo off >"$d/compositor-state"; : >"$d/../proc/101/maps"; exit "$(cat "$d/compositor-off-rc")";;
 show) echo use_compositing=true; echo "vblank_mode=$(cat "$d/compositor-state")";;
 *) exit 64;;
esac
'''), ('eglinfo', '''#!/bin/sh
[ "$*" = "-B -p surfaceless" ] && [ "$MESA_LOADER_DRIVER_OVERRIDE" = kgsl ] || { echo "OpenGL ES profile renderer: llvmpipe"; exit 0; }
cat "$(dirname "$0")/eglinfo-out"; exit "$(cat "$(dirname "$0")/eglinfo-rc")"
'''))
TURNIP = 'Turnip Adreno (TM) 725'
ZINK = 'zink Vulkan 1.4(Turnip Adreno (TM) 725 (MESA_TURNIP))'
PRESENT = ('M19 PRESENT {mode} version=1.2\nM19 PRESENT {mode} frames=120 done={done} copies={copies} flips={flips} skips=0 others=0 '
           'msc_per_frame={msc} us_per_frame={us} wall_us_per_frame={us}\n')
CRTC = ('M19 PRESENT crtc id=31 mode=1080x2400x120vid refresh=120 fb={fb} fbs={fbs} changes={changes} samples=50 pitch=4352 bpp=32\n'
        'M19 PRESENT crtc ok\n')
ROOT = 'M19 PRESENT root width=1080 height=2400 nonblack={nonblack} mean={mean}\nM19 PRESENT root ok\n'
VBLANK = ('M19 PRESENT vblank frames=120 wait_seq=1.00 wait_us=8355 event_seq=2.00 event_us=16710 event_wall_us=16702 late=120\n'
          'M19 PRESENT vblank ok\n')
GLAMOR_LOG = ('(II) modeset(0): glamor X acceleration enabled on FD725\n(II) modeset(0): glamor initialized\n'
              '(II) modeset(0): Output DSI-1 connected\n')
DRI3 = ('MESA_LOADER_DRIVER_OVERRIDE=kgsl FD_FORCE_KGSL=1 FD_KGSL_ENABLE_DMABUF=1 '
        'VK_DRIVER_FILES=/usr/share/vulkan/icd.d/freedreno_icd.aarch64.json')
COPY = ('VK_DRIVER_FILES=/usr/share/vulkan/icd.d/freedreno_icd.aarch64.json MESA_VK_WSI_DEBUG=sw MESA_LOADER_DRIVER_OVERRIDE=zink '
        'LIBGL_KOPPER_DRI2=1')


class Gpu(DesktopFixture):
    def setUp(self):
        super().setUp()
        for name, text in GPU_TOOLS:
            (self.test / name).write_text(text)
            (self.test / name).chmod(0o755)
        (self.test / 'journalctl').write_text('#!/bin/sh\necho "journal override=${MESA_LOADER_DRIVER_OVERRIDE:-none}"\n')
        os.symlink('/dev/null', self.root / 'kgsl-node')
        (self.root / 'gpu-model').write_text('Adreno725v1\n')
        (self.root / 'gpu-profile').write_text('dri3\n')
        (self.root / 'xorg0.log').write_text(GLAMOR_LOG)
        (self.root / 'proc/104/stat').write_text('104 (Xorg) S 1 104 104 0 -1 4194560 100 0 0 0 250 30 0 0 20 0 2 0 5 0 0\n')
        (self.test / 'probe-out').write_text(f'M19 GPU vulkan devices=1\nM19 GPU vulkan device={TURNIP}\nM19 GPU vulkan vendor=0x5143 type=1 '
                                             'driver=18 api=1.4.335 info=Mesa\nM19 GPU vulkan fill bytes=16777216 us=900 coherent=1 '
                                             'mismatches=0\nM19 GPU vulkan fill ok\n')
        (self.test / 'probe-rc').write_text('0\n')
        (self.test / 'vulkaninfo-out').write_text(f'Devices:\n========\nGPU0:\n\tvendorID = 0x5143\n\tdeviceName = {TURNIP}\n'
                                                  '\tdriverID = DRIVER_ID_MESA_TURNIP\n')
        (self.test / 'vkcube-rc').write_text('0\n')
        (self.test / 'glxinfo-out').write_text('name of display: :0\ndirect rendering: Yes\nOpenGL vendor string: freedreno\n'
                                               'OpenGL renderer string: FD725\n')
        (self.test / 'gears-out').write_text('600 frames in 5.0 seconds = 119.934 FPS\n')
        (self.test / 'glmark2-out').write_text('[build] use-vbo=false: FPS: 900\n=======\n                                  glmark2 Score: 812\n')
        (self.test / 'glmark2-rc').write_text('0\n')
        (self.test / 'eglinfo-out').write_text('Surfaceless platform:\nEGL vendor string: Mesa Project\nOpenGL ES profile renderer: FD725\n')
        (self.test / 'eglinfo-rc').write_text('0\n')
        (self.test / 'present-copy-out').write_text(PRESENT.format(mode='copy', done=120, copies=120, flips=0, msc='1.00', us=8333) + 'M19 PRESENT copy ok\n')
        (self.test / 'present-copy-rc').write_text('0\n')
        (self.test / 'present-flip-out').write_text(PRESENT.format(mode='flip', done=120, copies=2, flips=118, msc='1.00', us=8333) + 'M19 PRESENT flip ok\n')
        (self.test / 'present-flip-rc').write_text('0\n')
        (self.test / 'present-compositor-rc').write_text('0\n')
        # R4e: no compositor as the session leaves it, R4d's when it is on, none when it is off.
        for name, text in (('compositor-state', 'session\n'), ('owner-session', '0x00000000\n'), ('owner-on', '0x00c00003\n'),
                           ('owner-off', '0x00000000\n'), ('compositor-on-rc', '0\n'), ('compositor-off-rc', '0\n'), ('vblank-out', VBLANK),
                           ('vblank-rc', '0\n'), ('crtc-rc', '0\n'), ('crtc-session-out', CRTC.format(fb=76, fbs=1, changes=0)),
                           ('crtc-on-out', CRTC.format(fb=77, fbs=2, changes=50)), ('crtc-off-out', CRTC.format(fb=76, fbs=1, changes=0)),
                           ('root-session-out', ROOT.format(nonblack=912, mean=96)), ('root-on-out', ROOT.format(nonblack=0, mean=0)),
                           ('root-off-out', ROOT.format(nonblack=905, mean=95)),
                           # R4i: glxgears covering the screen, black through DRI3, drawn through the copy and software paths.
                           ('root-dri3-out', ROOT.format(nonblack=0, mean=0)), ('root-copy-out', ROOT.format(nonblack=140, mean=29)),
                           ('root-soft-out', ROOT.format(nonblack=152, mean=31)),
                           # R4j: the X server reads the CPU's dma-buf, the CPU reads the GPU's, the X server loses the GPU's.
                           ('xread-out', 'M19 PRESENT xread cpu=1000\nM19 PRESENT xread pixmap=1000 window=998\nM19 PRESENT xread ok\n'),
                           ('gpuwrite-out', 'M19 PRESENT gpuwrite renderer=FD725 fourcc=34324241 modifier=0 stride=1024 cpu=997\n'
                                            'M19 PRESENT gpuwrite ok\n'),
                           ('chain-out', 'M19 PRESENT chain renderer=FD725 fourcc=34324241 modifier=0 stride=1024 cpu=996\n'
                                         'M19 PRESENT chain pixmap=0 window=0\nM19 PRESENT chain ok\n'),
                           # R4k: written after the import, by the CPU, then by the GPU.
                           ('xlate-out', 'M19 PRESENT xlate cpu=1000\nM19 PRESENT xlate pixmap=993 window=992\nM19 PRESENT xlate ok\n'),
                           ('chainlate-out', 'M19 PRESENT chainlate renderer=FD725 fourcc=34324241 modifier=0 stride=1024 cpu=995\n'
                                             'M19 PRESENT chainlate pixmap=3 window=2\nM19 PRESENT chainlate ok\n'),
                           ('present-copy-on-out', PRESENT.format(mode='copy', done=120, copies=120, flips=0, msc='2.01', us=16750) +
                            'M19 PRESENT copy ok\n'),
                           ('present-flip-on-out', PRESENT.format(mode='flip', done=120, copies=120, flips=0, msc='2.01', us=16750) +
                            'M19 PRESENT flip ok\n')):
            (self.test / name).write_text(text)
        (self.root / 'proc/101/maps').write_text('')

    def run_gpu(self, gears_ms=600, **env):
        wire = Wire()
        environment = dict(os.environ, ASAN_OPTIONS='detect_leaks=0', M19_VBLANK_HZ='120', **env)
        for name in ('VK_DRIVER_FILES', 'MESA_VK_WSI_DEBUG', 'MESA_LOADER_DRIVER_OVERRIDE', 'LIBGL_KOPPER_DRI2', 'FD_FORCE_KGSL',
                     'FD_KGSL_ENABLE_DMABUF'):
            environment.pop(name, None)
        subprocess.run([ARGS.driver, 'report-gpu', str(self.root), wire.path, '300', '5000', '300', str(gears_ms)], capture_output=True,
                       timeout=90, env=environment)
        return self.parse(wire.close())

    def gpu(self, log):
        fields = {}
        for line in ('gpu', 'gpu-names', 'gpu-renderers', 'glamor', 'glamor-renderers', 'present', 'vblank', 'compositor', 'shows', 'dmabuf',
                     'late'):
            fields.update(item.split('=', 1) for item in re.search(rf'M19 R4 {line} (.*)\n', log).group(1).split())
        return fields

    def shows(self, log):
        return {name: dict(item.split('=', 1) for item in fields.split()) for name, fields in re.findall(r'M19 R4 show (\w+) (.*)\n', log)}

    def views(self, log):
        return {name: dict(item.split('=', 1) for item in fields.split()) for name, fields in re.findall(r'M19 R4 view (\w+) (.*)\n', log)}

    def test_gpu_pass(self):
        fields, log, steps = self.run_gpu()
        self.assertEqual(fields[3:], ['1', '0'])
        g = self.gpu(log)
        self.assertEqual((g['node'], g['model'], g['probe'], g['probe_device'], g['vk'], g['device'], g['cube'], g['gl'], g['gears'], g['egl']),
                         ('1', 'Adreno725v1', '1', 'Turnip_Adreno_(TM)_725', '1', 'Turnip_Adreno_(TM)_725', '1', '1', '1', '1'))
        self.assertEqual((g['renderer'], g['gears_fps'], g['egl_renderer'], g['gpu_ok']), ('FD725', '119.9', 'FD725', '1'))
        self.assertEqual((g['initialized'], g['enabled'], g['unit'], g['profile'], g['glmark2'], g['glamor_ok']), ('1', '1', '1', 'dri3', '812', '1'))
        self.assertEqual((g['glamor_renderer'], g['copy_renderer']), ('FD725', ZINK.replace(' ', '_')))
        self.assertGreater(float(g['xorg_cpu']), 0)
        self.assertGreater(float(g['cube_fps']), 0)
        self.assertEqual(self.desktop(log)['touch_ok'], '1')
        self.assertIn('M19STEP T12-gpu START', steps)
        self.assertIn('M19STEP T12-gpu END 1 1 1 1 1 1 1 1 1 1 1 1 1 1', steps)
        # R4i: glxgears covering the screen through each path, the screen read while it runs.
        self.assertEqual((g['ran'], g['of'], g['visible'], g['shows_ok']), ('3', '3', '2', '1'))
        self.assertEqual(self.shows(log), {'dri3': {'nonblack': '0', 'mean': '0'}, 'copy': {'nonblack': '140', 'mean': '29'},
                                           'soft': {'nonblack': '152', 'mean': '31'}})
        script = f'{self.test}/glxgears -fullscreen & gears=$!; sleep 0; {self.test}/present-probe root; kill $gears; wait $gears; exit 0'
        self.assertIn(f'M19 show dri3\nM19 $ {DRI3} /bin/sh -c {script}\n', log)
        self.assertIn(f'M19 show copy\nM19 $ {COPY} /bin/sh -c {script}\n', log)
        self.assertIn(f'M19 show soft\nM19 $ LIBGL_ALWAYS_SOFTWARE=1 /bin/sh -c {script}\n', log)
        # R4j: the three dma-buf readings, gpuwrite and chain with the dri3 profile.
        self.assertEqual((g['xread_cpu'], g['xread_pixmap'], g['xread_window'], g['gpu_cpu'], g['chain_cpu'], g['chain_pixmap'], g['chain_window'],
                          g['dmabuf_renderer']), ('1000', '1000', '998', '997', '996', '0', '0', 'FD725'))
        self.assertIn(f'M19 $ {self.test}/present-probe xread {self.root}/heap\n', log)
        self.assertIn(f'M19 $ {DRI3} {self.test}/present-probe gpuwrite\n', log)
        self.assertIn(f'M19 $ {DRI3} {self.test}/present-probe chain\n', log)
        # R4k: the late writes, the CPU's with no GPU profile, the GPU's with dri3.
        self.assertEqual((g['xlate_cpu'], g['xlate_pixmap'], g['xlate_window'], g['chainlate_cpu'], g['chainlate_pixmap'], g['chainlate_window']),
                         ('1000', '993', '992', '995', '3', '2'))
        self.assertIn(f'M19 $ {self.test}/present-probe xlate {self.root}/heap\n', log)
        self.assertIn(f'M19 $ {DRI3} {self.test}/present-probe chainlate\n', log)
        # R4l: nine runs in this order, each followed by what the probe printed; the GPU's with dri3.
        probe, heap, kgsl = f'{self.test}/present-probe', f'{self.root}/heap', f'{self.root}/kgsl-node'
        runs = [f'{probe} kgslsync {heap} {kgsl}\nM19 PRESENT kgslsync ok\n']
        runs += [f'{probe} xsync {heap} {kgsl} {op}\nM19 PRESENT xsync {op}\n' for op in ('obj-clean', 'cache-clean', 'obj-flush')]
        runs += [f'{probe} {mode} {heap}\nM19 PRESENT {mode} read\n' for mode in ('xagain', 'xwait')]
        runs += [f'{DRI3} {probe} chainsync {kgsl} {op}\nM19 PRESENT chainsync {op}\n' for op in ('obj-flush', 'cache-flush')]
        runs += [f'{DRI3} {probe} chainagain\nM19 PRESENT chainagain read\n']
        # R4m: four more, after them: Mesa's two with dri3, Turnip's with the Vulkan profile, the X server's bare.
        gpu, card = f'{self.test}/gpu-probe', f'{self.root}/card'
        runs += [f'{DRI3} {probe} glimport {heap}\nM19 PRESENT glimport read\n', f'{DRI3} {probe} gbmimport {heap} {card}\nM19 PRESENT gbmimport read\n',
                 f'{DRI3} {gpu} dmabuf {heap}\nM19 GPU dmabuf cpu=1000 late=0 again=1000 first=0\n', f'{probe} xreimport {heap}\nM19 PRESENT xreimport read\n']
        at = 0
        for run in runs:
            found = log.find('M19 $ ' + run, at)
            self.assertGreaterEqual(found, 0, run)
            at = found + len(run)
        # R4e: the kernel's vblanks, then three views of the screen around R4d's compositor, on then off.
        self.assertEqual((g['wait_seq'], g['wait_us'], g['event_seq'], g['event_us'], g['late'], g['vblank_ok']),
                         ('1.00', '8355', '2.00', '16710', '120', '1'))
        self.assertEqual((g['on_rc'], g['off_rc'], g['composited_done'], g['composited_copies'], g['composited_flips'], g['composited_msc'],
                          g['compositor_ok'], g['scanout_ok']), ('0', '0', '120', '120', '0', '2.01', '1', '1'))
        self.assertGreater(float(g['composited_cube_fps']), 0)
        self.assertEqual(self.views(log), {
            'session': {'owner': '0', 'gl': '0', 'fb': '76', 'fbs': '1', 'changes': '0', 'pitch': '4352', 'nonblack': '912', 'mean': '96'},
            'on': {'owner': str(0x00c00003), 'gl': '1', 'fb': '77', 'fbs': '2', 'changes': '50', 'pitch': '4352', 'nonblack': '0', 'mean': '0'},
            'off': {'owner': '0', 'gl': '0', 'fb': '76', 'fbs': '1', 'changes': '0', 'pitch': '4352', 'nonblack': '905', 'mean': '95'}})
        self.assertEqual((self.test / 'compositor-calls').read_text().split(), ['show', 'on', 'show', 'off', 'show'])
        self.assertIn(f'M19 $ {self.test}/present-probe vblank 120 {self.root}/card\n', log)
        self.assertEqual(log.count(f'M19 $ {self.test}/present-probe crtc 50 {self.root}/card\n'), 3)
        self.assertEqual(log.count(f'M19 $ {self.test}/present-probe root\n'), 3)
        self.assertEqual(log.count(f'M19 $ {self.test}/present-probe copy 120\n'), 2)
        self.assertEqual(log.count(f'M19 $ {DRI3} {self.test}/vkcube --c 300\n'), 2)
        order = [log.index(text) for text in ('M19 view session\n', f'M19 $ /bin/sh {self.test}/gpu-compositor on\n', 'M19 view on\n',
                                              f'M19 $ /bin/sh {self.test}/gpu-compositor off\n', 'M19 view off\n')]
        self.assertEqual(order, sorted(order))
        self.assertIn('use_compositing=true\nvblank_mode=on\n', log)
        self.assertLess(steps.index('M19STEP T12-touch END 12 2'), steps.index('M19STEP T12-gpu START'))
        # The copy run takes one vblank a frame (judged since R4h); the flip run is recorded; glxgears also ran fullscreen.
        self.assertEqual((g['copy_done'], g['copy_msc'], g['copy_us'], g['copy_ok'], g['flip_done'], g['flips'], g['flip_msc'], g['flip_us'],
                          g['gears_full_fps'], g['flip_ok']), ('120', '1.00', '8333', '1', '120', '118', '1.00', '8333', '119.9', '1'))
        self.assertIn(f'M19 $ {self.test}/present-probe copy 120\n', log)
        self.assertIn(f'M19 $ {self.test}/present-probe flip 120\n', log)
        self.assertIn(f'M19 $ {DRI3} {self.test}/glxgears -fullscreen\n', log)
        self.assertIn(f'M19 $ {DRI3} {self.test}/gpu-probe vulkan\n', log)
        self.assertIn(f'M19 $ {DRI3} {self.test}/vkcube --c 300\n', log)
        self.assertIn(f'M19 $ {DRI3} {self.test}/glxgears\n', log)
        self.assertIn(f'M19 $ {DRI3} {self.test}/glxinfo -B\n', log)
        self.assertIn(f'M19 $ {COPY} {self.test}/glxinfo -B\n', log)
        self.assertIn(f'M19 $ {DRI3} {self.test}/eglinfo -B -p surfaceless\n', log)
        # The variables reach each tool and nothing else.
        self.assertIn('journal override=none', log)

    def test_each_gpu_check_fails_the_run(self):
        root, test = self.root, self.test
        changes = {
            'node': (lambda: ((root / 'kgsl-node').unlink(), (root / 'kgsl-node').write_text('')), 'node', '0', {}),
            'probe': (lambda: (test / 'probe-rc').write_text('1\n'), 'probe', '0', {}),
            'probe_device': (lambda: (test / 'probe-out').write_text('M19 GPU vulkan device=llvmpipe (LLVM 20)\nM19 GPU vulkan fill ok\n'), 'probe', '0', {}),
            'probe_fill': (lambda: (test / 'probe-out').write_text(f'M19 GPU vulkan device={TURNIP}\nM19 GPU vulkan FAIL fill\n'), 'probe', '0', {}),
            'vk': (lambda: (test / 'vulkaninfo-out').write_text(f'\tdeviceName = {TURNIP}\n\tdriverID = DRIVER_ID_MESA_LLVMPIPE\n'), 'vk', '0', {}),
            'vk_name': (lambda: (test / 'vulkaninfo-out').write_text('\tdeviceName = lavapipe\n\tdriverID = DRIVER_ID_MESA_TURNIP\n'), 'vk', '0', {}),
            'cube': (lambda: (test / 'vkcube-rc').write_text('1\n'), 'cube', '0', {}),
            'gl': (lambda: (test / 'glxinfo-out').write_text('OpenGL renderer string: llvmpipe (LLVM 20.1.0, 128 bits)\n'), 'gl', '0', {}),
            'gl_zink': (lambda: (test / 'glxinfo-out').write_text(f'OpenGL renderer string: {ZINK}\n'), 'gl', '0', {}),
            'gears': (lambda: (test / 'gears-out').write_text('0 frames in 5.0 seconds = 0.000 FPS\n'), 'gears', '0', {}),
            'glamor_initialized': (lambda: (root / 'xorg0.log').write_text(GLAMOR_LOG.replace('glamor initialized', 'glamor initialization failed')),
                                   'initialized', '0', {}),
            'glamor_enabled': (lambda: (root / 'xorg0.log').write_text(GLAMOR_LOG.replace('glamor X acceleration enabled on FD725\n', '')),
                               'enabled', '0', {}),
            'glamor_cpu': (lambda: (root / 'xorg0.log').write_text(GLAMOR_LOG.replace('enabled on FD725', 'enabled on llvmpipe')), 'glamor_ok', '0', {}),
            'unit': (lambda: None, 'unit', '0', {'M19_ACTIVE_RC': '3'}),
            'profile': (lambda: (root / 'gpu-profile').write_text('copy\n'), 'profile', 'copy', {}),
            'no_profile': (lambda: (root / 'gpu-profile').unlink(), 'profile', 'none', {}),
            # R4e: the kernel's vblanks, the compositor coming and going, and every reading of the three views.
            'vblank_rc': (lambda: (test / 'vblank-rc').write_text('1\n'), 'vblank_ok', '0', {}),
            'vblank_line': (lambda: (test / 'vblank-out').write_text('M19 PRESENT vblank FAIL wait errno=22\n'), 'wait_seq', '-1.00', {}),
            'on_rc': (lambda: (test / 'compositor-on-rc').write_text('1\n'), 'compositor_ok', '0', {}),
            'off_rc': (lambda: (test / 'compositor-off-rc').write_text('1\n'), 'compositor_ok', '0', {}),
            'never_composites': (lambda: (test / 'owner-on').write_text('0x00000000\n'), 'compositor_ok', '0', {}),
            'still_composites': (lambda: (test / 'owner-off').write_text('0x00c00003\n'), 'compositor_ok', '0', {}),
            'owner_unreadable': (lambda: (test / 'present-compositor-rc').write_text('1\n'), 'compositor_ok', '0', {}),
            'session_owner_unreadable': (lambda: (test / 'owner-session').write_text('zz\n'), 'compositor_ok', '0', {}),
            'crtc_rc': (lambda: (test / 'crtc-rc').write_text('1\n'), 'scanout_ok', '0', {}),
            'crtc_line': (lambda: (test / 'crtc-on-out').write_text('M19 PRESENT crtc FAIL sample errno=22\n'), 'scanout_ok', '0', {}),
            'root_line': (lambda: (test / 'root-off-out').write_text('M19 PRESENT root FAIL connect\n'), 'scanout_ok', '0', {}),
            # R4h: a windowed copy must take one vblank a frame, every frame.
            'slow_copy': (lambda: (test / 'present-copy-out').write_text(PRESENT.format(mode='copy', done=120, copies=120, flips=0, msc='2.00',
                                                                                         us=16667)), 'copy_ok', '0', {}),
            'short_copy': (lambda: (test / 'present-copy-out').write_text(PRESENT.format(mode='copy', done=119, copies=119, flips=0, msc='1.00',
                                                                                          us=8333)), 'copy_ok', '0', {}),
            'failed_copy_run': (lambda: (test / 'present-copy-rc').write_text('1\n'), 'copy_ok', '0', {}),
            'no_copy_line': (lambda: (test / 'present-copy-out').write_text('M19 PRESENT copy FAIL connect\n'), 'copy_done', '-1', {}),
            # R4i: every path's screen must be read.
            'show_unread': (lambda: (test / 'root-copy-out').write_text('M19 PRESENT root FAIL connect\n'), 'shows_ok', '0', {}),
        }
        for change, (apply, flag, value, env) in changes.items():
            with self.subTest(change=change):
                self.setUp()
                root, test = self.root, self.test
                apply()
                fields, log, _ = self.run_gpu(**env)
                g = self.gpu(log)
                self.assertEqual((fields[3], g[flag], g['gpu_ok']), ('0', value, '0'))
                self.assertEqual(self.desktop(log)['touch_ok'], '1')

    def test_a_reading_that_fails_reads_minus_one(self):
        (self.test / 'crtc-on-out').write_text('M19 PRESENT crtc FAIL sample errno=22\n')
        (self.test / 'root-off-out').write_text('M19 PRESENT root FAIL connect\n')
        (self.test / 'owner-session').write_text('zz\n')
        _, log, _ = self.run_gpu()
        views = self.views(log)
        self.assertEqual(views['session'], {'owner': '-1', 'gl': '0', 'fb': '76', 'fbs': '1', 'changes': '0', 'pitch': '4352', 'nonblack': '912',
                                            'mean': '96'})
        self.assertEqual(views['on'], {'owner': str(0x00c00003), 'gl': '1', 'fb': '-1', 'fbs': '-1', 'changes': '-1', 'pitch': '-1', 'nonblack': '0',
                                       'mean': '0'})
        self.assertEqual(views['off'], {'owner': '0', 'gl': '0', 'fb': '76', 'fbs': '1', 'changes': '0', 'pitch': '4352', 'nonblack': '-1',
                                        'mean': '-1'})

    def test_failed_dma_buf_readings_read_minus_one_and_are_not_judged(self):
        (self.test / 'xread-out').write_text('M19 PRESENT xread FAIL heap open errno=2\n')
        # A line without its value: what a later line holds is not taken for it.
        (self.test / 'gpuwrite-out').write_text('M19 PRESENT gpuwrite renderer=FD725 fourcc=0 modifier=0 stride=1024\nM19 PRESENT later cpu=5\n')
        (self.test / 'chain-out').write_text('M19 PRESENT chain renderer=FD725 fourcc=0 modifier=0 stride=1024 cpu=x\nM19 PRESENT chain FAIL no dri3\n')
        (self.test / 'xlate-out').write_text('M19 PRESENT xlate FAIL heap alloc errno=22\n')
        (self.test / 'chainlate-out').write_text('M19 PRESENT chainlate renderer=FD725 fourcc=0 modifier=0 stride=1024 cpu=7\n'
                                                 'M19 PRESENT chainlate FAIL pixmap error=2\n')
        fields, log, _ = self.run_gpu()
        g = self.gpu(log)
        self.assertEqual((fields[3], g['gpu_ok']), ('1', '1'))
        self.assertEqual((g['xread_cpu'], g['xread_pixmap'], g['xread_window'], g['gpu_cpu'], g['chain_cpu'], g['chain_pixmap'], g['chain_window'],
                          g['dmabuf_renderer']), ('-1', '-1', '-1', '-1', '-1', '-1', '-1', 'FD725'))
        # R4k: the GPU drew, the X server refused the buffer.
        self.assertEqual((g['xlate_cpu'], g['xlate_pixmap'], g['xlate_window'], g['chainlate_cpu'], g['chainlate_pixmap'], g['chainlate_window']),
                         ('-1', '-1', '-1', '7', '-1', '-1'))

    def judged(self):
        """R4n's hardware: every path shows, and late writes reach the X server whole."""
        (self.test / 'root-dri3-out').write_text(ROOT.format(nonblack=128, mean=9))
        (self.test / 'xlate-out').write_text('M19 PRESENT xlate cpu=1000\nM19 PRESENT xlate pixmap=1000 window=990\nM19 PRESENT xlate ok\n')
        (self.test / 'chainlate-out').write_text('M19 PRESENT chainlate renderer=FD725 fourcc=34324241 modifier=0 stride=1024 cpu=1000\n'
                                                 'M19 PRESENT chainlate pixmap=990 window=1000\nM19 PRESENT chainlate ok\n')

    def test_r4o_judges_dri3_whole(self):
        self.judged()
        fields, log, steps = self.run_gpu(M19_TEST_JUDGE_DRI3='1')
        g = self.gpu(log)
        self.assertEqual((fields[3], g['gpu_ok'], g['late_ok'], g['visible'], g['shows_ok']), ('1', '1', '1', '3', '1'))
        self.assertIn('M19STEP T12-gpu END 1 1 1 1 1 1 1 1 1 1 1 1 1 1', steps)

    def test_r4o_fails_a_black_path_or_a_stale_late_read(self):
        for name, text, flag in (('root-dri3-out', ROOT.format(nonblack=4, mean=1), 'shows_ok'),
                                 ('xlate-out', 'M19 PRESENT xlate cpu=1000\nM19 PRESENT xlate pixmap=1000 window=989\n', 'late_ok'),
                                 ('chainlate-out', 'M19 PRESENT chainlate renderer=FD725 cpu=1000\nM19 PRESENT chainlate pixmap=989 window=1000\n', 'late_ok'),
                                 ('xlate-out', 'M19 PRESENT xlate cpu=1000\nM19 PRESENT xlate pixmap=989 window=1000\n', 'late_ok'),
                                 ('chainlate-out', 'M19 PRESENT chainlate renderer=FD725 cpu=1000\nM19 PRESENT chainlate pixmap=1000 window=989\n', 'late_ok'),
                                 ('xlate-out', 'M19 PRESENT xlate FAIL no dri3\n', 'late_ok')):
            with self.subTest(name=name, text=text):
                self.setUp()
                self.judged()
                (self.test / name).write_text(text)
                fields, log, _ = self.run_gpu(M19_TEST_JUDGE_DRI3='1')
                g = self.gpu(log)
                self.assertEqual((fields[3], g['gpu_ok'], g[flag]), ('0', '0', '0'))
        # Unjudged, as R4i to R4n ran: the same black path and stale read pass.
        self.setUp()
        self.judged()
        (self.test / 'root-dri3-out').write_text(ROOT.format(nonblack=0, mean=0))
        (self.test / 'xlate-out').write_text('M19 PRESENT xlate cpu=1000\nM19 PRESENT xlate pixmap=0 window=0\n')
        fields, log, _ = self.run_gpu()
        self.assertEqual((fields[3], self.gpu(log)['gpu_ok'], self.gpu(log)['late_ok']), ('1', '1', '0'))

    def test_an_unread_screen_reads_minus_one_and_black_is_not_visible(self):
        (self.test / 'root-copy-out').write_text('M19 PRESENT root FAIL connect\n')
        # A line cut short: what it did give is not kept.
        (self.test / 'root-soft-out').write_text('M19 PRESENT root width=1080 height=2400 nonblack=7\n')
        (self.test / 'root-dri3-out').write_text(ROOT.format(nonblack=4, mean=1))
        _, log, _ = self.run_gpu()
        g = self.gpu(log)
        self.assertEqual((g['ran'], g['visible'], g['shows_ok']), ('1', '0', '0'))
        self.assertEqual(self.shows(log), {'dri3': {'nonblack': '4', 'mean': '1'}, 'copy': {'nonblack': '-1', 'mean': '-1'},
                                           'soft': {'nonblack': '-1', 'mean': '-1'}})

    def test_page_flips_and_the_composited_runs_are_recorded_not_judged(self):
        test = self.test
        changes = {
            'no_flips': (lambda: (test / 'present-flip-out').write_text(PRESENT.format(mode='flip', done=120, copies=120, flips=0, msc='1.00', us=8333)),
                         'flip_ok', '0'),
            'few_flips': (lambda: (test / 'present-flip-out').write_text(PRESENT.format(mode='flip', done=120, copies=13, flips=107, msc='1.00', us=8333)),
                          'flip_ok', '0'),
            'slow_flips': (lambda: (test / 'present-flip-out').write_text(PRESENT.format(mode='flip', done=120, copies=0, flips=120, msc='1.11', us=9250)),
                           'flip_ok', '0'),
            'short_flips': (lambda: ((test / 'present-flip-out').write_text(PRESENT.format(mode='flip', done=119, copies=0, flips=119, msc='1.00', us=8333)),
                                     (test / 'present-flip-rc').write_text('1\n')), 'flip_ok', '0'),
            'failed_flip_run': (lambda: (test / 'present-flip-rc').write_text('1\n'), 'flip_ok', '0'),
            'short_flips_rc0': (lambda: (test / 'present-flip-out').write_text(PRESENT.format(mode='flip', done=119, copies=0, flips=119, msc='1.00',
                                                                                              us=8333)), 'flip_ok', '0'),
            'no_flip_line': (lambda: (test / 'present-flip-out').write_text('M19 PRESENT flip FAIL connect\n'), 'flip_done', '-1'),
            'no_composited_copy': (lambda: (test / 'present-copy-on-out').write_text('M19 PRESENT copy FAIL connect\n'), 'composited_done', '-1'),
            'composited_flips': (lambda: (test / 'present-flip-on-out').write_text(PRESENT.format(mode='flip', done=120, copies=0, flips=120, msc='1.00',
                                                                                                 us=8333)), 'composited_flips', '120'),
        }
        for change, (apply, flag, value) in changes.items():
            with self.subTest(change=change):
                self.setUp()
                test = self.test
                apply()
                fields, log, _ = self.run_gpu()
                g = self.gpu(log)
                self.assertEqual((fields[3], g[flag], g['gpu_ok']), ('1', value, '1'))

    def test_glmark2_and_freedreno_without_x_are_recorded_not_judged(self):
        (self.test / 'eglinfo-rc').write_text('1\n')
        (self.test / 'glmark2-rc').write_text('1\n')
        fields, log, _ = self.run_gpu()
        g = self.gpu(log)
        self.assertEqual((fields[3], g['egl'], g['glmark2'], g['gpu_ok']), ('1', '0', '-1', '1'))

    def test_without_views_the_compositor_is_never_touched(self):
        fields, log, steps = self.run_gpu(M19_TEST_NO_VIEWS='1')
        self.assertEqual(fields[3:], ['1', '0'])
        self.assertIn('M19STEP T12-gpu END 1 1 1 1 1 1 1 1 1 0 0 0 1 1', steps)
        for text in ('M19 R4 vblank', 'M19 R4 compositor', 'M19 R4 view', 'M19 view', 'present-probe vblank', 'present-probe crtc', 'gpu-compositor'):
            self.assertNotIn(text, log)
        self.assertFalse((self.test / 'compositor-calls').exists())
        self.assertRegex(log, r'M19 R4 present copy_done=120 copy_msc=1.00 .* copy_ok=1\n')
        self.assertRegex(log, r'M19 R4 gpu node=1 .* gpu_ok=1\n')

    def test_without_x_the_gpu_phase_does_not_run(self):
        (self.test / 'x-up').unlink()
        fields, log, steps = self.run_gpu()
        self.assertEqual((fields[3], self.gpu(log)['gpu_ok'], self.gpu(log)['probe'], self.gpu(log)['glamor_ok']), ('0', '0', '0', '0'))
        self.assertFalse([line for line in steps if 'T12-gpu' in line])

    def test_a_hung_gpu_tool_is_abandoned_and_the_report_still_goes(self):
        (self.test / 'vkcube-hang').write_text('')
        started = time.monotonic()
        fields, log, steps = self.run_gpu()
        self.assertLess(time.monotonic() - started, 25)
        g = self.gpu(log)
        self.assertEqual((fields[3], g['cube'], g['gl'], g['gears'], g['glamor_ok']), ('0', '0', '1', '1', '1'))
        self.assertIn('M19STEP T12-gpu END 1 1 1 0 1 1 1 1 1 1 1 1 1 1', steps)

LOADER = '''#!/bin/sh
echo "$*" >> "$M19_TEST/load.log"
[ "${M19_LOAD_RC:-0}" = 0 ] || exit "$M19_LOAD_RC"
n=0
for module in "$@"; do
 n=$((n+1))
 [ -z "${M19_LOAD_SHORT:-}" ] || [ "$n" -lt "$#" ] || break
 echo "${module%.ko} 4096 0 - Live 0x0" >> "$M19_ROOT/proc/modules"
done
'''


class GpuScript(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name) / 'root'
        self.test = Path(self.directory.name) / 'test'
        self.test.mkdir()
        for name, text in (('bb', FAKE_BB), ('load', LOADER)):
            (self.test / name).write_text(text)
            (self.test / name).chmod(0o755)
        for name, data in r4plan.render().items():
            if name.startswith('m19/r4/'):
                (self.root / name).parent.mkdir(parents=True, exist_ok=True)
                (self.root / name).write_bytes(data)
        self.firmware = {name: f'{name} blob\n'.encode() for name in r4plan.FIRMWARE}
        (self.root / 'm19/gpu-firmware').mkdir(parents=True)
        for name, data in self.firmware.items():
            (self.root / 'm19/gpu-firmware' / name).write_bytes(data)
        (self.root / 'm19/m19-gpu-probe').write_bytes(b'\x7fELF probe')
        (self.root / 'm19/m19-present-probe').write_bytes(b'\x7fELF present')
        (self.root / 'm19/m19-glfinish.so').write_bytes(b'\x7fELF finish')
        (self.root / 'run/m19').mkdir(parents=True)
        param = self.root / 'sys/module/firmware_class/parameters/path'
        param.parent.mkdir(parents=True)
        param.write_text('/m6/modem/image')
        (self.root / 'proc').mkdir()
        (self.root / 'proc/modules').write_text(''.join(f'm{i} 4096 0 - Live 0x0\n' for i in range(102)))
        for directory, number in (('sys/class/kgsl/kgsl-3d0', '504:0'), ('sys/class/dma_heap/system', '248:1')):
            (self.root / directory).mkdir(parents=True)
            (self.root / directory / 'dev').write_text(number + '\n')
        self.new = self.root / 'newroot'
        for name in ('run/m19', 'dev'):
            (self.new / name).mkdir(parents=True)
        for tool in ('usr/lib/aarch64-linux-gnu/libvulkan.so.1', 'usr/share/vulkan/icd.d/freedreno_icd.aarch64.json', 'usr/bin/vulkaninfo',
                     'usr/bin/vkcube', 'usr/bin/glxinfo', 'usr/bin/glxgears', 'usr/bin/eglinfo', 'usr/bin/glmark2',
                     'usr/lib/xorg/modules/libglamoregl.so', 'usr/lib/aarch64-linux-gnu/gbm/dri_gbm.so', 'usr/lib/aarch64-linux-gnu/dri/kgsl_dri.so',
                     'usr/bin/xfconf-query', 'usr/lib/aarch64-linux-gnu/libxcb-dri3.so.0', 'usr/lib/aarch64-linux-gnu/libEGL.so.1',
                     'usr/lib/aarch64-linux-gnu/libGLESv2.so.2'):
            (self.new / tool).parent.mkdir(parents=True, exist_ok=True)
            (self.new / tool).write_text('x\n')
        # R4n: the tree's Mesa, whose hash the step reports.
        (self.new / 'usr/lib/aarch64-linux-gnu/libgallium-26.3.0-devel.so').write_bytes(b'\x7fELF gallium')

    def run_script(self, **env):
        environment = dict(os.environ, M19_ROOT=str(self.root), M19_BB=str(self.test / 'bb'), M19_TEST=str(self.test),
                           M19_LOAD=str(self.test / 'load'), M19_GPU_WAIT='3', **env)
        return subprocess.run(['sh', str(HERE / 't9-gpu')], capture_output=True, text=True, env=environment, timeout=60)

    def log(self, name):
        path = self.test / name
        return path.read_text() if path.exists() else ''

    def assertFails(self, reason, **env):
        result = self.run_script(**env)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(f'M19 T9 gpu failed: {reason}\n', result.stderr)
        return result

    def test_prepares_the_gpu(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        for directory in (self.root / 'run/m19/firmware', self.new / 'run/m19/firmware'):
            self.assertEqual({path.name: path.read_bytes() for path in directory.iterdir()}, self.firmware)
            self.assertTrue(all(oct(path.stat().st_mode & 0o777) == '0o644' for path in directory.iterdir()))
        self.assertEqual((self.root / 'sys/module/firmware_class/parameters/path').read_text(), '/run/m19/firmware')
        self.assertEqual(self.log('load.log'), ' '.join(r4plan.GPU_MODULES) + '\n')
        self.assertEqual(len((self.root / 'proc/modules').read_text().splitlines()), 110)
        nodes = re.findall(r'mknod -m (\d+) (\S+) (\w) (\d+) (\d+)', self.log('bb.log'))
        self.assertEqual(nodes, [('600', f'{self.new}/dev/kgsl-3d0', 'c', '504', '0'), ('600', f'{self.new}/dev/dma_heap/system', 'c', '248', '1')])
        self.assertEqual((self.new / 'run/m19/m19-gpu-probe').read_bytes(), b'\x7fELF probe')
        self.assertEqual(oct((self.new / 'run/m19/m19-gpu-probe').stat().st_mode & 0o777), '0o755')
        self.assertEqual((self.new / 'run/m19/m19-present-probe').read_bytes(), b'\x7fELF present')
        self.assertEqual(oct((self.new / 'run/m19/m19-present-probe').stat().st_mode & 0o777), '0o755')
        self.assertEqual((self.new / 'run/m19/m19-glfinish.so').read_bytes(), b'\x7fELF finish')
        self.assertEqual(oct((self.new / 'run/m19/m19-glfinish.so').stat().st_mode & 0o777), '0o644')
        self.assertEqual((self.new / 'run/m19/xorg-glamor.conf').read_bytes(), r4plan.render()['m19/r4/xorg-glamor.conf'])
        self.assertIn('M19 T9 gpu: modules=110 firmware=7 kgsl=504:0 heap=248:1 path=/run/m19/firmware\n', result.stderr)
        gallium = hashlib.sha256(b'\x7fELF gallium').hexdigest()
        self.assertIn(f'M19 T9 gpu: libgallium sha256={gallium}\n', result.stderr)

    def test_missing_firmware_stops_before_any_module(self):
        (self.root / 'm19/gpu-firmware/a730_zap.b02').unlink()
        self.assertFails('firmware missing a730_zap.b02')
        self.assertEqual(self.log('load.log'), '')
        self.assertEqual((self.root / 'sys/module/firmware_class/parameters/path').read_text(), '/m6/modem/image')

    def test_the_module_count_must_be_102_then_110(self):
        (self.root / 'proc/modules').write_text('m 1 0 - Live 0x0\n' * 101)
        self.assertFails('module count 101')
        self.assertEqual(self.log('load.log'), '')
        self.setUp()
        self.assertFails('module count 109', M19_LOAD_SHORT='1')

    def modules(self, count):
        (self.root / 'proc/modules').write_text(''.join(f'm{i} 4096 0 - Live 0x0\n' for i in range(count)))

    def test_on_r5a_the_count_starts_at_the_audio_stage(self):
        (self.root / 'run/m19/audio.result').write_text('ready\n')
        self.modules(147)
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len((self.root / 'proc/modules').read_text().splitlines()), 155)
        self.assertIn('M19 T9 gpu: modules=155 ', result.stderr)
        self.setUp()
        (self.root / 'run/m19/audio.result').write_text('ready\n')
        self.assertFails('module count 102')
        self.assertEqual(self.log('load.log'), '')
        self.setUp()
        (self.root / 'run/m19/audio.result').write_text('ready\n')
        self.modules(147)
        self.assertFails('module count 154', M19_LOAD_SHORT='1')
        for stage in ('partial count audio 120', 'skipped super-missing', ''):
            with self.subTest(stage=stage):
                self.setUp()
                (self.root / 'run/m19/audio.result').write_text(stage + '\n')
                self.modules(147)
                self.assertFails('audio-stage')
                self.assertEqual(self.log('load.log'), '')

    def test_a_failed_load_stops(self):
        self.assertFails('module-load', M19_LOAD_RC='1')
        self.assertNotIn('mknod', self.log('bb.log'))

    def test_a_gpu_that_never_registers_stops(self):
        shutil.rmtree(self.root / 'sys/class/kgsl')
        self.assertFails('kgsl-3d0 missing')
        self.assertNotIn('mknod', self.log('bb.log'))
        self.setUp()
        (self.root / 'sys/class/kgsl/kgsl-3d0/dev').write_text('504\n')
        self.assertFails('kgsl-3d0 number')

    def test_a_missing_heap_stops(self):
        shutil.rmtree(self.root / 'sys/class/dma_heap')
        self.assertFails('system missing')

    def test_a_missing_probe_or_tool_stops(self):
        (self.root / 'm19/m19-gpu-probe').unlink()
        self.assertFails('gpu-probe')
        self.setUp()
        (self.root / 'm19/m19-present-probe').unlink()
        self.assertFails('present-probe')
        self.setUp()
        (self.root / 'm19/m19-glfinish.so').unlink()
        self.assertFails('glfinish')
        self.setUp()
        (self.new / 'usr/lib/aarch64-linux-gnu/libgallium-26.3.0-devel.so').unlink()
        self.assertFails('mesa-hash')
        self.setUp()
        (self.root / 'm19/m19-glfinish.so').unlink()
        (self.root / 'm19/m19-glfinish.so').symlink_to(self.root / 'm19/m19-present-probe')
        self.assertFails('glfinish')
        self.setUp()
        (self.new / 'usr/bin/vkcube').unlink()
        self.assertFails('missing usr/bin/vkcube')
        self.setUp()
        (self.new / 'usr/lib/xorg/modules/libglamoregl.so').unlink()
        self.assertFails('missing usr/lib/xorg/modules/libglamoregl.so')
        self.setUp()
        (self.new / 'usr/bin/xfconf-query').unlink()
        self.assertFails('missing usr/bin/xfconf-query')
        self.setUp()
        (self.new / 'usr/lib/aarch64-linux-gnu/libGLESv2.so.2').unlink()
        self.assertFails('missing usr/lib/aarch64-linux-gnu/libGLESv2.so.2')
        self.setUp()
        (self.root / 'm19/r4/xorg-glamor.conf').unlink()
        self.assertFails('xorg-glamor')

    def test_bad_plan_lines_stop(self):
        for name, text, reason in (('firmware', '../a730_sqe.fw\n', 'firmware name ../a730_sqe.fw'),
                                   ('firmware', 'a730_sqe.fw\n', 'firmware count 1'),
                                   ('modules', 'msm_kgsl\n', 'module name msm_kgsl'), ('modules', 'a b.ko\n', 'module name a b.ko'),
                                   ('modules', 'msm_kgsl.ko\n', 'module list 1')):
            with self.subTest(name=name, text=text):
                self.setUp()
                (self.root / 'm19/r4' / name).write_text(text)
                self.assertFails(reason)

    def test_without_the_new_root_nothing_happens(self):
        shutil.rmtree(self.new / 'run')
        self.assertFails('newroot')
        self.assertEqual((self.log('bb.log'), self.log('load.log')), ('', ''))


class GpuProbe(unittest.TestCase):
    """gpu-probe.c on lavapipe, the only Vulkan device a CI runner has. test.sh and mutate.py build it."""

    def setUp(self):
        self.probe, self.icd = os.environ.get('M19_GPU_PROBE'), os.environ.get('M19_LVP_ICD')
        if not self.probe or not self.icd:
            self.skipTest('probe or lavapipe not available in this run')

    def run_probe(self, *arguments, icd=None, **fake):
        environment = {key: value for key, value in os.environ.items() if not key.startswith(('ASAN', 'UBSAN', 'VK_', 'M19_FAKE_', 'LD_PRELOAD'))}
        environment['VK_DRIVER_FILES'] = icd or self.icd
        if fake:
            environment.update(LD_PRELOAD=os.environ['M19_FAKE_CARD'], **{f'M19_FAKE_{key.upper()}': value for key, value in fake.items()})
        return subprocess.run([self.probe, *arguments], capture_output=True, text=True, env=environment, timeout=120)

    def test_dmabuf_reads_a_write_made_after_the_import(self):
        if not os.environ.get('M19_FAKE_CARD'):
            self.skipTest('fake card not built in this run')
        with tempfile.TemporaryDirectory() as directory:
            heap = Path(directory) / 'heap'
            heap.write_text('')
            done = self.run_probe('dmabuf', str(heap), '--allow-cpu', lag='0')
            # Lavapipe imports by mapping the same memory: every read sees the write.
            self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
            self.assertTrue(done.stdout.endswith('M19 GPU dmabuf cpu=1000 late=1000 again=1000 first=1000\nM19 GPU dmabuf ok\n'), done.stdout)
            done = self.run_probe('dmabuf', str(heap) + '-missing', '--allow-cpu', lag='0')
            self.assertEqual(done.returncode, 1)
            self.assertTrue(done.stdout.endswith('M19 GPU dmabuf FAIL heap open errno=2\n'), done.stdout)
            done = self.run_probe('dmabuf', str(heap), '--allow-cpu', fail='heap')
            self.assertTrue(done.stdout.endswith('M19 GPU dmabuf FAIL heap alloc errno=22\n'), done.stdout)

    def test_fills_and_checks_every_word_on_an_allowed_cpu_device(self):
        done = self.run_probe('vulkan', '--allow-cpu')
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn('M19 GPU vulkan devices=1\n', done.stdout)
        self.assertRegex(done.stdout, r'M19 GPU vulkan device=llvmpipe')
        self.assertRegex(done.stdout, r'M19 GPU vulkan fill bytes=16777216 us=\d+ coherent=[01] mismatches=0\n')
        self.assertTrue(done.stdout.endswith('M19 GPU vulkan fill ok\n'))

    def test_a_cpu_device_is_refused_by_default(self):
        done = self.run_probe('vulkan')
        self.assertEqual(done.returncode, 1)
        self.assertIn('M19 GPU vulkan FAIL no device', done.stdout)
        self.assertNotIn('fill ok', done.stdout)

    def test_no_driver_fails(self):
        done = self.run_probe('vulkan', '--allow-cpu', icd='/nonexistent/none.json')
        self.assertEqual(done.returncode, 1)
        self.assertRegex(done.stdout, r'M19 GPU vulkan FAIL (instance|no device)')

    def test_usage(self):
        for arguments in ((), ('vulkan', '--other'), ('gl',), ('vulkan', '--allow-cpu', 'x'), ('dmabuf',), ('dmabuf', 'h', '--other'),
                          ('dmabuf', 'h', '--allow-cpu', 'x'), ('vulkan', 'h')):
            self.assertEqual(self.run_probe(*arguments).returncode, 64, arguments)



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



class Shim(unittest.TestCase):
    """xorg-shim.c preloaded into a driver linked against fake-drm.c. test.sh and mutate.py build them."""

    def setUp(self):
        self.lib, self.driver = os.environ.get('M19_SHIM_LIB'), os.environ.get('M19_SHIM_DRIVER')
        if not self.lib or not self.driver:
            self.skipTest('shim not built in this run')

    def run_driver(self, mode, preload=True, **env):
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith(('ASAN', 'UBSAN', 'LD_PRELOAD', 'M19_SHIM_GBM', 'M19_SHIM_NODIRTY'))}
        if preload:
            environment['LD_PRELOAD'] = self.lib
        environment.update(env)
        return subprocess.run([self.driver, mode], capture_output=True, text=True, env=environment, timeout=30)

    def test_the_gbm_bridge_hands_out_card0_handles(self):
        done = self.run_driver('gbm', M19_SHIM_GBM='1')
        self.assertEqual(done.returncode, 0, done.stderr)
        lines = done.stdout.splitlines()
        kms = re.search(r'kms (\d+)$', lines[-1]).group(1)
        # a: imported once, then cached; its second plane is the same dma-buf, so card0 gives the same handle;
        # b has no dma-buf and keeps GBM's handle; destroying a closes its one card0 handle once; c, perhaps
        # at a's old address, is a new import.
        self.assertEqual(lines, [f'prime kms={kms} handle 1281', 'a 1281', 'a again 1281', f'prime kms={kms} handle 1281 again', 'a plane1 1281',
                                 'b 4128', f'gem-close kms={kms} handle 1281', f'prime kms={kms} handle 1282', 'c 1282',
                                 f'gem-close kms={kms} handle 1282', f'imports 2 closes 2 destroyed 3 kms {kms}'])
        self.assertIn('M19 SHIM gbm plane 0 handle 4112 -> kms 1281\n', done.stderr)
        self.assertIn('M19 SHIM gbm plane 0 keeps handle 4128', done.stderr)
        self.assertIn('gbm bridge on', done.stderr)

    def test_the_gbm_bridge_is_off_unless_asked(self):
        for preload, env in ((True, {}), (True, {'M19_SHIM_GBM': '0'}), (False, {'M19_SHIM_GBM': '1'})):
            with self.subTest(preload=preload, env=env):
                done = self.run_driver('gbm', preload=preload, **env)
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertEqual(done.stdout.splitlines()[:5], ['a 4112', 'a again 4112', 'a plane1 4113', 'b 4128', 'c 4144'])
                self.assertRegex(done.stdout, r'imports 0 closes 0 destroyed 3 kms \d+\n')

    def test_a_failed_import_keeps_the_gbm_handle(self):
        done = self.run_driver('gbm', M19_SHIM_GBM='1', FAKE_PRIME_FAIL='1')
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout.splitlines()[:5], ['a 4112', 'a again 4112', 'a plane1 4113', 'b 4128', 'c 4144'])
        self.assertIn('M19 SHIM gbm plane 0 keeps handle 4112', done.stderr)
        self.assertRegex(done.stdout, r'imports 0 closes 0 destroyed 3 ')

    def test_kernel_dirty_updates_off_when_asked(self):
        done = self.run_driver('dirty', M19_SHIM_NODIRTY='1')
        self.assertEqual((done.returncode, done.stdout), (0, 'dirty -38 -38 calls 0\n'), done.stderr)
        self.assertEqual(done.stderr.count('M19 SHIM dirtyfb off: fb 175 answered -ENOSYS\n'), 1)
        self.assertIn('kernel dirty updates off\n', done.stderr)

    def test_kernel_dirty_updates_on_unless_asked(self):
        for preload, env in ((True, {}), (True, {'M19_SHIM_NODIRTY': '0'}), (False, {'M19_SHIM_NODIRTY': '1'})):
            with self.subTest(preload=preload, env=env):
                done = self.run_driver('dirty', preload=preload, **env)
                self.assertEqual((done.returncode, done.stdout), (0, 'dirty 0 0 calls 2\n'), done.stderr)
                self.assertNotIn('dirtyfb off', done.stderr)

    def test_glfinish_finishes_every_frame_before_its_swap(self):
        lib = os.environ.get('M19_GLFINISH_LIB')
        if not lib:
            self.skipTest('glfinish not built in this run')
        done = self.run_driver('swap', preload=False, LD_PRELOAD=lib)
        self.assertEqual((done.returncode, done.stdout), (0, 'finish\nswap 7\nfinish\nswap 8\n'), done.stderr)
        self.assertEqual(done.stderr, 'M19 GLFINISH first swap: glFinish found, glXSwapBuffers found\n')

    def test_without_glfinish_frames_swap_unfinished(self):
        done = self.run_driver('swap', preload=False)
        self.assertEqual((done.returncode, done.stdout, done.stderr), (0, 'swap 7\nswap 8\n', ''))

    def test_only_range_enum_and_blob_properties_remain(self):
        done = self.run_driver('filter')
        self.assertEqual(done.returncode, 0, done.stderr)
        for name in ('get', 'current'):
            self.assertIn(f'{name} count 4\n', done.stdout)
            self.assertEqual(re.findall(rf'{name} prop (\d+) (\d+)', done.stdout), [('1', '101'), ('2', '102'), ('3', '103'), ('8', '108')])
        for line in ('drops property 4 sde_bitmask flags=0x20', 'drops property 5 CRTC_ID flags=0x40',
                     'drops property 6 signed_range flags=0x80', 'drops property 7 (unreadable) flags=0'):
            self.assertEqual(done.stderr.count(line), 2, line)
        self.assertIn('M19 SHIM loaded', done.stderr)

    def test_nothing_changes_without_the_shim(self):
        done = self.run_driver('filter', preload=False)
        self.assertIn('get count 8\n', done.stdout)
        self.assertNotIn('M19 SHIM', done.stderr)

    def test_a_null_call_is_logged_and_ends_the_process(self):
        done = self.run_driver('null-call')
        self.assertEqual(done.returncode, -11, done.stdout + done.stderr)
        self.assertIn('installed 0', done.stdout)
        self.assertNotIn('own-handler', done.stdout)
        self.assertRegex(done.stderr, r'M19 SHIM fault signal=11 code=\d+ addr=\(nil\) pc=0 ')
        self.assertIn('M19 SHIM map ', done.stderr)

    def test_a_null_read_is_logged(self):
        done = self.run_driver('null-read')
        self.assertEqual(done.returncode, -11, done.stdout + done.stderr)
        self.assertNotIn('own-handler', done.stdout)
        self.assertRegex(done.stderr, r'M19 SHIM fault signal=11 code=\d+ addr=\(nil\) pc=0x[0-9a-f]+ ')


def main():
    global ARGS
    parser = argparse.ArgumentParser()
    parser.add_argument('--driver', required=True)
    parser.add_argument('--failfast', action='store_true', help='stop at the first failure, as mutants need')
    parser.add_argument('tests', nargs='*', help='test classes to run; all when empty')
    ARGS = parser.parse_args()
    ARGS.driver = os.path.abspath(ARGS.driver)
    program = unittest.main(argv=['test', *ARGS.tests], exit=False, verbosity=1, failfast=ARGS.failfast)
    sys.exit(not program.result.wasSuccessful())


if __name__ == '__main__':
    main()
