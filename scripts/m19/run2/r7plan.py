#!/usr/bin/env python3
"""R7 on top of R6d: CE unlock with the owner's PIN inside the session (docs/m19-r7.md).

- marble-ce.service runs the keypad (m19-ce-prompt) on the session's display, once, when the reporter starts it in
  T12-ce; nothing else starts it. The keypad hands the PIN to the CE broker in the TEE island through
  /run/m19/ce/ce.sock and records the broker's one status line in /run/m19/ce.result.
- Android's /data/media is at /run/m19/android, read-only and root only (T9-ce); /data/media/0's names read once
  the CE key is in.
Everything else is R6d's.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import r4plan  # noqa: E402
import r6plan  # noqa: E402

CE = '''[Unit]
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

TARGET = r4plan._swap(r4plan._swap(r6plan.TARGET, 'Description=M19 R6: XFCE landscape, the GPU, Wi-Fi and the desktop speaker on the read-only Ubuntu root',
                                   'Description=M19 R7: R6d\'s session and CE unlock with the owner\'s PIN on the read-only Ubuntu root'),
                      'm19-r6-report.service', 'm19-r7-report.service')
REPORT = r4plan._swap(r6plan.REPORT, 'M19 R6 evidence over USB', 'M19 R7 evidence over USB')

FILES = {name: text for name, text in r6plan.FILES.items()
         if name not in ('systemd/system/m19-r6.target', 'systemd/system/m19-r6-report.service')}
FILES.update({'systemd/system/m19-r7.target': TARGET,
              'systemd/system/m19-r7-report.service': REPORT,
              'systemd/system/marble-ce.service': CE})


def render():
    """R6d's files with R7's target, report and keypad unit."""
    assert 'marble-ce.service' not in TARGET
    out = {name: data for name, data in r6plan.render().items() if not name.startswith('m19/r2/etc/')}
    out['m19/r2/default'] = b'm19-r7.target\n'
    out['m19/r2/files'] = ''.join(f'{name}\n' for name in FILES).encode()
    out.update({f'm19/r2/etc/{name}': text.encode() for name, text in FILES.items()})
    return out


if __name__ == '__main__':
    for name, data in render().items():
        print(f'{len(data):6d} {name}')
