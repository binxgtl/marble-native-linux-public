#!/usr/bin/env python3
"""M18 R1 (docs/m18-performance-polish.md): changes to M17 G5's daily plan (scripts/m17/dailyplan.py's output), each
asserted to land exactly where it is meant to; everything else stays G5's byte for byte.

- marble-ce.service, R7's keypad unit: opened from the menu, not by the session. Before the keypad, ce-ready makes sure
  a broker listens (the boot's while it waits, otherwise a fresh one in the TEE island); after it, ce-done records the
  status line and hides the menu's entry once unlocked; nothing runs once unlocked.
- marble-xfce.service: XDG_DATA_DIRS with the RAM-only /run/m19/xdg-data first, where the entry lives.
- m18-perf.service and m18-analyze.service: the read-only record (perf-recorder, boot-analyze), wanted by the target.
- m17-session.service: its description, since the session no longer starts the keypad (scripts/m18/session.c).
"""
import sys

PLAN = 'm19/r8/'
ROOT = PLAN + 'root/'
CONTROL = ROOT + 'run/systemd/system.control/'
ETC = 'run/m19/etc/'
ENTRY = 'run/m19/xdg-data/applications/m18-unlock-android.desktop'
# plan path -> the scripts/m18 source it carries
SOURCES = {ETC + 'm18-ce-ready': 'ce-ready', ETC + 'm18-ce-done': 'ce-done', ETC + 'm18-perf': 'perf-recorder',
           ETC + 'm18-analyze': 'boot-analyze', ENTRY: 'unlock-android.desktop'}

R7_CE = '''[Unit]
Description=M19 R7 CE keypad: the owner's PIN, once, to the broker in the TEE island
DefaultDependencies=no
IgnoreOnIsolate=yes
ConditionPathExists=/run/m19/ce/ce.sock

[Service]
Type=simple
Environment=DISPLAY=:0 HOME=/run/m19/session
ExecStart=/run/m19/m19-ce-prompt /run/m19/ce/ce.sock /run/m19/ce.result
Restart=no
LimitCORE=0
StandardInput=null
StandardOutput=null
StandardError=journal
'''

CE = '''[Unit]
Description=M18 R1 Android storage unlock: R7's keypad, opened from the menu, to a broker in the TEE island
DefaultDependencies=no
IgnoreOnIsolate=yes

[Service]
Type=simple
Environment=DISPLAY=:0 HOME=/run/m19/session
ExecCondition=/bin/sh -c '! grep -q "^M19_CE status=OK" /run/m19/ce.result 2>/dev/null'
ExecStartPre=/bin/sh /run/m19/etc/m18-ce-ready
ExecStart=/run/m19/m19-ce-prompt /run/m19/ce/ce.sock /run/m19/ce.result
ExecStopPost=/bin/sh /run/m19/etc/m18-ce-done
Restart=no
LimitCORE=0
StandardInput=null
StandardOutput=null
StandardError=journal
'''

PERF = '''[Unit]
Description=M18 R1: the session's performance and power record, read-only (/var/lib/m19/m18-perf.log)
DefaultDependencies=no
IgnoreOnIsolate=yes
After=systemd-journald.socket

[Service]
Type=simple
ExecStart=/bin/sh /run/m19/etc/m18-perf
Nice=10
Restart=no
LimitCORE=0
StandardInput=null
StandardOutput=null
StandardError=journal
'''

ANALYZE = '''[Unit]
Description=M18 R1: systemd's account of the boot once it has started (/var/lib/m19/m18-analyze.log)
DefaultDependencies=no
IgnoreOnIsolate=yes
After=systemd-journald.socket

[Service]
Type=simple
ExecStart=/bin/sh /run/m19/etc/m18-analyze
Nice=10
Restart=no
LimitCORE=0
StandardInput=null
StandardOutput=null
StandardError=journal
'''

UNITS = {'run/systemd/system.control/m18-perf.service': PERF, 'run/systemd/system.control/m18-analyze.service': ANALYZE}
XFCE_ENV = 'Environment=DISPLAY=:0 HOME=/root XDG_RUNTIME_DIR=/run/m19/xdg XDG_SESSION_TYPE=x11 XDG_CONFIG_DIRS=/run/m19/xdg-config:/etc/xdg\n'


def swap(text, old, new, count=1):
    assert text.count(old) == count, (old, text.count(old))
    return text.replace(old, new)


def plan(daily, sources):
    """G5's daily plan as R1's. sources: scripts/m18 file name -> bytes."""
    out = dict(daily)
    assert out[CONTROL + 'marble-ce.service'] == R7_CE.encode(), 'R7\'s keypad unit'
    out[CONTROL + 'marble-ce.service'] = CE.encode()
    xfce = out[CONTROL + 'marble-xfce.service'].decode()
    xfce = swap(xfce, XFCE_ENV, XFCE_ENV[:-1] + ' XDG_DATA_DIRS=/run/m19/xdg-data:/usr/local/share:/usr/share\n')
    out[CONTROL + 'marble-xfce.service'] = xfce.encode()
    target = out[CONTROL + 'm19-r9.target'].decode()
    target = swap(target, ' m17-session.service m17-volkeys.service\n', ' m17-session.service m17-volkeys.service m18-perf.service m18-analyze.service\n')
    target = swap(target, "Description=M17 daily: R9's session without the PC, its reporter or its limits\n",
                  "Description=M18 R1 daily: M17 G5's session, the unlock from the menu, and a read-only record\n")
    out[CONTROL + 'm19-r9.target'] = target.encode()
    session = out[CONTROL + 'm17-session.service'].decode()
    session = swap(session, "Description=M17 daily: the speaker's sink, PulseAudio and the CE keypad in R9's order, and the session's record\n",
                   "Description=M18 R1 daily: the speaker's sink and PulseAudio in R9's order, and the session's record (the CE keypad from the menu)\n")
    out[CONTROL + 'm17-session.service'] = session.encode()
    added = []
    for name, text in UNITS.items():
        assert ROOT + name not in out, name
        out[ROOT + name] = text.encode()
        added.append(name)
    for name, source in SOURCES.items():
        assert ROOT + name not in out, name
        out[ROOT + name] = sources[source]
        added.append(name)
    files = out[PLAN + 'files'].decode()
    out[PLAN + 'files'] = (files + ''.join(f'{name}\n' for name in added)).encode()
    listed = set(out[PLAN + 'files'].decode().split())
    assert listed == {name[len(ROOT):] for name in out if name.startswith(ROOT)}, 'files list and root agree'
    return out


if __name__ == '__main__':
    sys.exit(__doc__)
