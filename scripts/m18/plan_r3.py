#!/usr/bin/env python3
"""M18 R3 (docs/m18-r3.md): changes to R2's plan (plan_r2.py's output), each asserted to land exactly where it is
meant to; everything else stays R2's byte for byte.

- The shutdown's spinner: m18-bye.service, wanted by poweroff.target (M19's, a reboot) and reboot.target, starts once
  the X server has stopped (systemd orders a stop before a start whatever the ordering's direction), copies the binary
  into place and runs it as "@m18-bye", so systemd's final killing spares it until the reset. It writes the
  shutdown's timeline to /var/lib/m19/m18-shutdown.log.
- A shorter shutdown:
  - marble-sink.service: ExecStop sends SIGTERM when the shutdown begins (the sink ends its stream, amplifiers off
    first, then holds, as M11 designed), and argv[0] "@m19-sink", so systemd's final killing spares the holding sink
    instead of waiting for it and then killing it: the hold lasts until the reset, which is M11's own rule;
  - DefaultTimeoutStopSec=10s for every other unit and for that final wait (systemd's default is 90 s).
- m18-perf.service: when it stops, a "shutdown-begins" mark in the same log.
"""
import sys

PLAN = 'm19/r8/'
ROOT = PLAN + 'root/'
CONTROL = ROOT + 'run/systemd/system.control/'
ETC = 'run/m19/etc/'
SOURCES = {ETC + 'm18-mark': 'mark'}
BINARY = ETC + 'm18-bye'
DROPIN = 'run/systemd/system.control/reboot.target.d/m18.conf'
MANAGER = 'run/systemd/system.conf.d/m18.conf'

BYE = '''[Unit]
Description=M18 R3: a spinner on the panel from the X server's stop to the reset, and the shutdown's timeline
DefaultDependencies=no
After=marble-xorg.service marble-xorg-fallback.service marble-xfce.service

[Service]
Type=simple
ExecStartPre=/usr/bin/install -m 0755 /run/m19/etc/m18-bye /run/m19/m18-bye
ExecStart=@/run/m19/m18-bye @m18-bye
LimitCORE=0
StandardInput=null
StandardOutput=null
StandardError=journal
'''
UNITS = {'run/systemd/system.control/m18-bye.service': BYE,
         DROPIN: '[Unit]\nWants=m18-bye.service\n',
         MANAGER: '[Manager]\nDefaultTimeoutStopSec=10s\n'}


def swap(text, old, new, count=1):
    assert text.count(old) == count, (old, text.count(old))
    return text.replace(old, new)


def plan(r2, sources, bye):
    """R2's plan as R3's. sources: scripts/m18 file name -> bytes; bye: the m18-bye binary (this candidate's CI)."""
    out = dict(r2)
    sink = out[CONTROL + 'marble-sink.service'].decode()
    sink = swap(sink, 'ExecStart=/run/m19/m19-sink\n', 'ExecStart=@/run/m19/m19-sink @m19-sink\nExecStop=/bin/kill -TERM $MAINPID\n')
    assert 'KillMode=none\n' in sink and 'SendSIGKILL=no\n' in sink
    out[CONTROL + 'marble-sink.service'] = sink.encode()
    poweroff = out[CONTROL + 'poweroff.target'].decode()
    poweroff = swap(poweroff, 'Requires=systemd-reboot.service\n', 'Requires=systemd-reboot.service\nWants=m18-bye.service\n')
    out[CONTROL + 'poweroff.target'] = poweroff.encode()
    perf = out[CONTROL + 'm18-perf.service'].decode()
    perf = swap(perf, 'ExecStart=/bin/sh /run/m19/etc/m18-perf\n',
                'ExecStart=/bin/sh /run/m19/etc/m18-perf\nExecStop=/bin/sh /run/m19/etc/m18-mark shutdown-begins\n')
    out[CONTROL + 'm18-perf.service'] = perf.encode()
    target = out[CONTROL + 'm19-r9.target'].decode()
    target = swap(target, "Description=M18 R2 daily: R1, the temperature sensors back, stock's CPU governor, no audible startup chord\n",
                  "Description=M18 R3 daily: R2 with G5c's sink, the shutdown's spinner and a shorter shutdown\n")
    out[CONTROL + 'm19-r9.target'] = target.encode()
    added = []
    for name, text in UNITS.items():
        assert ROOT + name not in out, name
        out[ROOT + name] = text.encode()
        added.append(name)
    for name, source in SOURCES.items():
        assert ROOT + name not in out, name
        out[ROOT + name] = sources[source]
        added.append(name)
    assert ROOT + BINARY not in out and bye[:6] == b'\x7fELF\x02\x01' and b'M18 bye' in bye
    out[ROOT + BINARY] = bye
    added.append(BINARY)
    out[PLAN + 'files'] = (out[PLAN + 'files'].decode() + ''.join(f'{name}\n' for name in added)).encode()
    listed = set(out[PLAN + 'files'].decode().split())
    assert listed == {name[len(ROOT):] for name in out if name.startswith(ROOT)}, 'files list and root agree'
    return out


if __name__ == '__main__':
    sys.exit(__doc__)
