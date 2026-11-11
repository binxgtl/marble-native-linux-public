#!/usr/bin/env python3
"""R5 on top of R4: Run12's registered card stays node-free in /dev, udev's persistent ALSA symlink rule and
Ubuntu's ALSA state units are masked in the RAM /etc, and marble-speaker.service stands ready for the reporter's
one-shot Run31 speaker playback gate after T12-gpu.

marble-speaker.service is never pulled in by m19-r5.target: the reporter starts it once in T12-audio, and after
any DSP MAP intent the service holds its sealed endpoint, ION and dma-buf fds open until the power-button reset.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import r3plan  # noqa: E402
import r4plan  # noqa: E402

AUDIO_MASKED = ('alsa-restore.service', 'alsa-state.service')
MASKED = r3plan.MASKED + AUDIO_MASKED
UDEV_MASKED = ('60-persistent-alsa.rules',)

# Started once by the reporter in T12-audio, never by the target. KillMode=none and SendSIGKILL=no keep systemd
# from closing the retaining holder if anything stops units before the operator's long-press reset.
SPEAKER = '''[Unit]
Description=M19 R5b one-shot bounded speaker clip under M11 Run31 gates
DefaultDependencies=no
IgnoreOnIsolate=yes

[Service]
Type=simple
ExecStart=/run/m19/m19-speaker
Restart=no
KillMode=none
SendSIGKILL=no
TimeoutStopSec=infinity
OOMScoreAdjust=-900
LimitCORE=0
StandardInput=null
StandardOutput=journal
StandardError=journal
'''

TARGET = r4plan._swap(
    r4plan._swap(r4plan.TARGET,
                 'Description=M19 R4: XFCE and the GPU on the read-only Ubuntu root',
                 'Description=M19 R5: XFCE, the GPU and the Run31 speaker gate on the read-only Ubuntu root'),
    'm19-r4-report.service', 'm19-r5-report.service')
REPORT = r4plan._swap(r4plan.REPORT, 'M19 R4 evidence over USB', 'M19 R5 evidence over USB')

FILES = {name: text for name, text in r4plan.FILES.items()
         if name not in ('systemd/system/m19-r4.target', 'systemd/system/m19-r4-report.service')}
FILES.update({'systemd/system/m19-r5.target': TARGET,
              'systemd/system/m19-r5-report.service': REPORT,
              'systemd/system/marble-speaker.service': SPEAKER})


def render():
    """R4's files with R5's target, report and speaker units, ALSA unit masks, and udev rule masks."""
    assert len(set(MASKED)) == len(MASKED) and len(set(UDEV_MASKED)) == len(UDEV_MASKED)
    assert 'marble-speaker.service' not in TARGET
    out = {name: data for name, data in r4plan.render().items() if not name.startswith('m19/r2/etc/')}
    out['m19/r2/default'] = b'm19-r5.target\n'
    out['m19/r2/masks'] = ''.join(f'{unit}\n' for unit in MASKED).encode()
    out['m19/r2/files'] = ''.join(f'{name}\n' for name in FILES).encode()
    out.update({f'm19/r2/etc/{name}': text.encode() for name, text in FILES.items()})
    out['m19/r5/udev-masks'] = ''.join(f'{name}\n' for name in UDEV_MASKED).encode()
    return out


if __name__ == '__main__':
    for name, data in render().items():
        print(f'{len(data):6d} {name}')
