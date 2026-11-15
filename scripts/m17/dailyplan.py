#!/usr/bin/env python3
"""M17 G5: the native daily profile, as changes to M19 R9's own files (docs/m17-g5.md). Each change is asserted to land
exactly where it is meant to; everything else stays R9's byte for byte.

- The plan (r9plan.render(), under m19/r8, which run8's T9-root reads). R9's target and units, but:
  - no reporter: m19-r9-report.service is gone, and nothing listens on USB;
  - no USB serial node: the native path never starts the gadget, so ttyGS0 does not exist to be made;
  - m17-session.service starts the speaker's sink, PulseAudio and the CE keypad in R6 to R9's order (session.c) and
    records the session in /var/lib/m19/m17-session.log;
  - m17-volkeys.service: the volume keys (volkeys.c);
  - the target keeps R9's name: T9-root accepts only m19-r[0-9].target.
  The guard unit is unchanged; its binary's guard mode has the daily limits (native-main.c).
- R5a's audio stage and T9-gpu count the kernel's modules. On the native path the kernel holds the selector's two
  key-only modules as well, reboot-mode and qcom-pon, so each count is two more.
"""
import sys

KEY_ONLY = 2
PLAN = 'm19/r8/'
CONTROL = PLAN + 'root/run/systemd/system.control/'
REPORT = 'run/systemd/system.control/m19-r9-report.service'
SESSION_UNIT = 'run/systemd/system.control/m17-session.service'
VOLKEYS_UNIT = 'run/systemd/system.control/m17-volkeys.service'
SHIFT_NOTE = ('# M17 G5: every module count below is M19\'s plus 2, the selector\'s key-only modules reboot-mode and qcom-pon\n'
              '# (scripts/m17/dailyplan.py).\n')

SESSION = '''[Unit]
Description=M17 daily: the speaker's sink, PulseAudio and the CE keypad in R9's order, and the session's record
DefaultDependencies=no
IgnoreOnIsolate=yes
After=systemd-journald.socket

[Service]
Type=exec
ExecStart=/run/m19/m19-report session
Restart=no
LimitCORE=0
StandardInput=null
StandardOutput=journal
StandardError=journal
'''

VOLKEYS = '''[Unit]
Description=M17 daily: Volume Up and Down step the volume, both together take a screenshot
DefaultDependencies=no
IgnoreOnIsolate=yes
After=systemd-journald.socket

[Service]
Type=simple
ExecStart=/run/m19/m19-report volkeys
Restart=always
RestartSec=5
LimitCORE=0
StandardInput=null
StandardOutput=journal
StandardError=journal
'''


def swap(text, old, new, count=1):
    assert text.count(old) == count, (old, text.count(old))
    return text.replace(old, new)


def after_shebang(text):
    head, rest = text.split('\n', 1)
    assert head == '#!/bin/busybox sh'
    return head + '\n' + SHIFT_NOTE + rest


def audio_stage(text):
    """R5a's audio stage (scripts/m19/run5/audio-stage) on M19's 102 modules plus the two key-only ones."""
    for old, new, count in (('loaded=102\n', 'loaded=104\n', 1), ('[ "$(count)" -eq 102 ]', '[ "$(count)" -eq 104 ]', 2),
                            ('[ "$now" -ne 102 ]', '[ "$now" -ne 104 ]', 1), ('phase audio 134\n', 'phase audio 136\n', 1),
                            ('phase machine 143\n', 'phase machine 145\n', 1), ('phase haptics 146\n', 'phase haptics 148\n', 1),
                            ('phase transport 147\n', 'phase transport 149\n', 1)):
        text = swap(text, old, new, count)
    return after_shebang(text)


def t9_gpu(text):
    """T9-gpu (scripts/m19/run2/t9-gpu): its base count, with or without the audio stage's 45."""
    text = swap(swap(text, 'base=102\n', 'base=104\n'), ' base=147\n', ' base=149\n')
    return after_shebang(text)


def plan(r9):
    """R9's rendered plan (r9plan.render()) as the daily profile's."""
    out = dict(r9)
    assert out[PLAN + 'default'] == b'm19-r9.target\n'
    target = out[CONTROL + 'm19-r9.target'].decode()
    target = swap(target, "Description=M19 R9: R8d's session with the desktop's sound held to whole buffers\n",
                  "Description=M17 daily: R9's session without the PC, its reporter or its limits\n")
    target = swap(target, ' m19-r9-report.service', '')
    target = swap(target, ' marble-audio-log.service\n', ' marble-audio-log.service m17-session.service m17-volkeys.service\n')
    out[CONTROL + 'm19-r9.target'] = target.encode()
    del out[PLAN + 'root/' + REPORT]
    files = out[PLAN + 'files'].decode()
    files = swap(files, REPORT + '\n', '') + SESSION_UNIT + '\n' + VOLKEYS_UNIT + '\n'
    out[PLAN + 'files'] = files.encode()
    out[PLAN + 'root/' + SESSION_UNIT] = SESSION.encode()
    out[PLAN + 'root/' + VOLKEYS_UNIT] = VOLKEYS.encode()
    out[PLAN + 'nodes'] = swap(out[PLAN + 'nodes'].decode(), 'ttyGS0 tty/ttyGS0 600\n', '').encode()
    listed = set(out[PLAN + 'files'].decode().split())
    assert listed == {name[len(PLAN + 'root/'):] for name in out if name.startswith(PLAN + 'root/')}, 'files list and root agree'
    # The getty mask on ttyGS0 stays: it masks a unit that never comes.
    assert not any(b'm19-report report' in data for name, data in out.items() if name.startswith(PLAN))
    assert b'ttyGS0' not in out[PLAN + 'nodes'] and b'serial-getty' + b'@ttyGS0.service\n' in out[PLAN + 'masks']
    return out


if __name__ == '__main__':
    sys.path.insert(0, sys.argv[1])
    import r9plan  # noqa: E402
    for name, data in sorted(plan(r9plan.render()).items()):
        print(f'{len(data):6d} {name}')
