#!/usr/bin/env python3
"""M18 R3b adds shutdown diagnostics to the frozen R3a plan."""
from plan_r3 import BINARY, CONTROL, ROOT, swap

PERF = CONTROL + 'm18-perf.service'
BYE = CONTROL + 'm18-bye.service'
SPINNER = ROOT + BINARY


def plan(r3a, spinner):
    assert spinner[:6] == b'\x7fELF\x02\x01' and b'M18 procs count=' in spinner
    out = dict(r3a)
    perf = out[PERF].decode()
    assert 'ExecStop=/bin/sh /run/m19/etc/m18-mark shutdown-begins\n' in perf
    out[PERF] = swap(perf, 'After=systemd-journald.socket\n',
                     'After=systemd-journald.socket\nBefore=shutdown.target\nConflicts=shutdown.target\n').encode()
    bye = out[BYE].decode()
    out[BYE] = swap(bye, 'marble-xorg-fallback.service marble-xfce.service\n',
                    'marble-xorg-fallback.service marble-xfce.service m18-perf.service\n').encode()
    assert SPINNER in out
    out[SPINNER] = spinner
    return out
