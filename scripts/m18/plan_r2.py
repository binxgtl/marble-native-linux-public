#!/usr/bin/env python3
"""M18 R2 (docs/m18-r2.md), named plan_r2 because scripts/m19/run2 has an r2plan: changes to R1's plan (r1plan.py's output), each asserted to land exactly where it is meant
to; everything else stays R1's byte for byte.

- m18-thermal.service: loads the stock qcom_tsens.ko (carried at /run/m19/etc/qcom_tsens.ko) and records the thermal
  zones it makes readable.
- m18-governor.service: every CPU policy to walt, stock's governor (schedutil if walt is not offered).
- both wanted by the target, before the desktop, with no ordering on anything else.
The startup chord's replacement is not in the plan: it is the speaker plan's signal (SIGNAL below), which the local staging builds in.
"""
import sys

PLAN = 'm19/r8/'
ROOT = PLAN + 'root/'
CONTROL = ROOT + 'run/systemd/system.control/'
ETC = 'run/m19/etc/'
SOURCES = {ETC + 'm18-governor': 'governor', ETC + 'm18-thermal': 'thermal'}
MODULE = ETC + 'qcom_tsens.ko'
# The startup check's signal: one 50 Hz tone, 0.5 s, -40 dBFS, faded in and out over 100 ms. With the stream volume
# at level 8 (-24 dB) that is -64 dB at a band the phone's speakers barely reproduce. The native plan parser allows
# 500 ms to 10 s and -40 to -6 dBFS (scripts/m11/anchor-native/speaker_plan_native.c); the sink's gates stay.
SIGNAL = {'duration_ms': 500, 'fade_ms': 100, 'peak_mdbfs': -40000, 'tones_hz': [50]}

UNIT = '''[Unit]
Description=M18 R2: {what}
DefaultDependencies=no
IgnoreOnIsolate=yes
After=systemd-journald.socket

[Service]
Type=exec
ExecStart=/bin/sh /run/m19/etc/{script}
LimitCORE=0
StandardInput=null
StandardOutput=null
StandardError=journal
'''
UNITS = {'run/systemd/system.control/m18-thermal.service':
         UNIT.format(what='the SoC temperature sensors (stock qcom_tsens.ko), recorded in /var/lib/m19/m18-tune.log', script='m18-thermal'),
         'run/systemd/system.control/m18-governor.service':
         UNIT.format(what='every CPU policy to walt, stock\'s governor, recorded in /var/lib/m19/m18-tune.log', script='m18-governor')}


def swap(text, old, new, count=1):
    assert text.count(old) == count, (old, text.count(old))
    return text.replace(old, new)


def plan(r1, sources, module):
    """R1's plan as R2's. sources: scripts/m18 file name -> bytes; module: the stock qcom_tsens.ko."""
    out = dict(r1)
    target = out[CONTROL + 'm19-r9.target'].decode()
    target = swap(target, ' m18-perf.service m18-analyze.service\n', ' m18-perf.service m18-analyze.service m18-thermal.service m18-governor.service\n')
    target = swap(target, "Description=M18 R1 daily: M17 G5's session, the unlock from the menu, and a read-only record\n",
                  "Description=M18 R2 daily: R1, the temperature sensors back, stock's CPU governor, no audible startup chord\n")
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
    assert ROOT + MODULE not in out and module[:4] == b'\x7fELF' and b'name=qcom_tsens\x00' in module
    out[ROOT + MODULE] = module
    added.append(MODULE)
    out[PLAN + 'files'] = (out[PLAN + 'files'].decode() + ''.join(f'{name}\n' for name in added)).encode()
    listed = set(out[PLAN + 'files'].decode().split())
    assert listed == {name[len(ROOT):] for name in out if name.startswith(ROOT)}, 'files list and root agree'
    return out


if __name__ == '__main__':
    sys.exit(__doc__)
