#!/usr/bin/env python3
"""R6 on top of R5: Wi-Fi, the desktop sound server and a landscape desktop, in the RAM /etc (docs/m19-r6.md).

- Landscape: glamor's X server turns the panel's 1080x2400 scan-out to a 2400x1080 screen, rotated right (the
  phone held with its top to the left, Android's own landscape), and the touchscreen's coordinates turn with it.
  The CPU fallback stays R3c's portrait configuration, as proven.
- Wi-Fi: marble-wifi.service runs m19-wifi (M12 Run9 to Run11's bring-up, run6/wifi.c) at boot. NetworkManager
  starts only once m19-wifi reports the interface ready (wifi.ready), manages Wi-Fi devices only, and connects with
  the operator's one profile, which T9-wifi puts in the RAM /etc. NetworkManager and wpa_supplicant log warnings only:
  network names stay out of the journal.
- Sound: PulseAudio gets one sink, marble_speaker, a pipe into /run/m19/sink/fifo; marble-sink (run6/sink.c) plays
  Run31's chord, then streams that FIFO to the speaker, never louder than the chord. The reporter starts it once in
  T12-audio, as R5b started its clip; nothing else does. R6b: the reporter then starts PulseAudio too
  (marble-pulse.service): the tree's autostart entry is for systemd user sessions, and this root session has none, so
  in R6a nothing started it. XFCE's entry stays hidden, so no second server races it.
- USB input: a keyboard or mouse plugged into a hub once the PC's cable is out gets its /dev/input node from udev
  (the kernel has no devtmpfs), so the X server picks it up.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import r3plan  # noqa: E402
import r4plan  # noqa: E402
import r5plan  # noqa: E402

# Android's landscape: the phone's top to the left, the screen turned right. The touchscreen reports the panel's own
# axes; this matrix maps them onto the turned screen (x' = y, y' = 1 - x).
ROTATE = 'right'
TOUCH_MATRIX = '0 1 0 -1 0 1 0 0 1'

NETWORK_UNMASKED = ('NetworkManager.service', 'wpa_supplicant.service')
NETWORK_MASKED = ('NetworkManager-wait-online.service',)
MASKED = tuple(unit for unit in r5plan.MASKED if unit not in NETWORK_UNMASKED) + NETWORK_MASKED
# The tray's network applet now has something to run against. PulseAudio's autostart stays hidden (R6b): the
# reporter starts the server.
HIDDEN = tuple(name for name in r3plan.HIDDEN if name != 'nm-applet')
UDEV_MASKED = r5plan.UDEV_MASKED

SINK_NAME = 'marble_speaker'
SINK_FIFO = '/run/m19/sink/fifo'
# Run31's plan format, which m19-sink requires of its FIFO.
PULSE_SINK = (f'load-module module-pipe-sink file={SINK_FIFO} sink_name={SINK_NAME} format=s16le rate=48000 channels=2 '
              'sink_properties=device.description=Speaker\n'
              f'set-default-sink {SINK_NAME}\n')


def xorg_landscape_conf():
    """R4o's glamor configuration with the panel turned right and the touchscreen's coordinates turned with it."""
    conf = r4plan.xorg_glamor_conf()
    conf = r4plan._swap(conf, f'    Option "PreferredMode" "{r3plan.MODE_120}"\n',
                        f'    Option "PreferredMode" "{r3plan.MODE_120}"\n    Option "Rotate" "{ROTATE}"\n')
    return conf + '\n'.join(('', 'Section "InputClass"', '    Identifier "marble-touch-landscape"', f'    MatchProduct "{r3plan.TOUCH}"',
                             f'    Option "TransformationMatrix" "{TOUCH_MATRIX}"', 'EndSection', ''))


# Started once by the reporter in T12-audio, never by the target; KillMode=none and SendSIGKILL=no keep systemd from
# closing the retaining holder (R5b's marble-speaker.service).
SINK = '''[Unit]
Description=M19 R6 desktop sound server: Run31's speaker session streaming PulseAudio's pipe sink
DefaultDependencies=no
IgnoreOnIsolate=yes

[Service]
Type=simple
ExecStart=/run/m19/m19-sink
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

# R6b: the session's sound server, the tree's PulseAudio for root, with the session's home and runtime directory
# (where the desktop's clients find it), never daemonised and never exiting when idle. Started by the reporter once
# the sink streams, never by the target.
PULSE = '''[Unit]
Description=M19 R6 PulseAudio for the session, into marble-sink's FIFO
DefaultDependencies=no
IgnoreOnIsolate=yes
ConditionPathExists=/run/m19/sink/fifo

[Service]
Type=simple
Environment=HOME=/run/m19/session XDG_RUNTIME_DIR=/run/m19/xdg
ExecStart=/usr/bin/pulseaudio --daemonize=no --exit-idle-time=-1 --realtime=no --high-priority=no --log-target=journal
Restart=no
LimitCORE=0
StandardInput=null
StandardOutput=journal
StandardError=journal
'''

# Started by the target at boot. It holds the CNSS daemon for good, so nothing may stop or kill it.
WIFI = '''[Unit]
Description=M19 R6 Wi-Fi: M12's native CNSS bring-up, then NetworkManager
DefaultDependencies=no
IgnoreOnIsolate=yes
ConditionPathExists=/run/m19/wifi.stage
After=systemd-udevd.service

[Service]
Type=simple
ExecStart=/run/m19/wifi/m19-wifi
Restart=no
KillMode=none
SendSIGKILL=no
TimeoutStopSec=infinity
LimitCORE=0
StandardInput=null
StandardOutput=journal
StandardError=journal
'''

# NetworkManager waits for m19-wifi: at boot the condition fails quietly; m19-wifi starts it once the interface is ready.
NM_DROPIN = '''[Unit]
ConditionPathExists=/run/m19/wifi.ready

[Service]
LogLevelMax=warning
'''
WPA_DROPIN = '''[Service]
LogLevelMax=warning
'''
NM_CONF = '''# M19 R6: Wi-Fi only, from the RAM /etc; nothing written to the tree.
[main]
plugins=keyfile

[keyfile]
unmanaged-devices=except:type:wifi

[logging]
level=WARN

[connectivity]
enabled=false
'''

# The kernel has no devtmpfs, so a device plugged in during the session has no node unless udev makes one. Only input
# event devices below a USB port get one; they go when the device goes.
USB_INPUT = ('# M19 R6: /dev/input nodes for USB keyboards and mice plugged into a hub during the session.\n'
             'ACTION=="add", SUBSYSTEM=="input", KERNEL=="event[0-9]*", DEVPATH=="*/usb[0-9]*", '
             'RUN+="/bin/sh -c \'mkdir -p /dev/input && mknod -m 0660 /dev/input/%k c $major $minor\'"\n'
             'ACTION=="remove", SUBSYSTEM=="input", KERNEL=="event[0-9]*", DEVPATH=="*/usb[0-9]*", RUN+="/bin/rm -f /dev/input/%k"\n')

TARGET = r4plan._swap(r4plan._swap(r5plan.TARGET, 'Description=M19 R5: XFCE, the GPU and the Run31 speaker gate on the read-only Ubuntu root',
                                   'Description=M19 R6: XFCE landscape, the GPU, Wi-Fi and the desktop speaker on the read-only Ubuntu root'),
                      'm19-r5-report.service', 'm19-r6-report.service marble-wifi.service')
REPORT = r4plan._swap(r5plan.REPORT, 'M19 R5 evidence over USB', 'M19 R6 evidence over USB')

FILES = {name: text for name, text in r5plan.FILES.items()
         if name not in ('systemd/system/m19-r5.target', 'systemd/system/m19-r5-report.service', 'systemd/system/marble-speaker.service')}
FILES.update({'systemd/system/m19-r6.target': TARGET,
              'systemd/system/m19-r6-report.service': REPORT,
              'systemd/system/marble-sink.service': SINK,
              'systemd/system/marble-wifi.service': WIFI,
              'systemd/system/marble-pulse.service': PULSE,
              'systemd/system/NetworkManager.service.d/m19.conf': NM_DROPIN,
              'systemd/system/wpa_supplicant.service.d/m19.conf': WPA_DROPIN,
              'NetworkManager/conf.d/m19.conf': NM_CONF,
              'pulse/default.pa.d/m19-sink.pa': PULSE_SINK,
              'udev/rules.d/70-m19-usb-input.rules': USB_INPUT})


def render():
    """R5's files with R6's target, report, sink, Wi-Fi, NetworkManager, PulseAudio and udev files, the network units
    unmasked, the tray's network and sound shown, and the landscape glamor configuration."""
    assert len(set(MASKED)) == len(MASKED) and len(set(HIDDEN)) == len(HIDDEN)
    assert not set(NETWORK_UNMASKED) & set(MASKED) and set(NETWORK_UNMASKED) <= set(r5plan.MASKED)
    assert 'marble-sink.service' not in TARGET and 'marble-pulse.service' not in TARGET and 'marble-speaker.service' not in FILES
    out = {name: data for name, data in r5plan.render().items() if not name.startswith('m19/r2/etc/') and name != 'm19/r5/udev-masks'}
    out['m19/r2/default'] = b'm19-r6.target\n'
    out['m19/r2/masks'] = ''.join(f'{unit}\n' for unit in MASKED).encode()
    out['m19/r2/files'] = ''.join(f'{name}\n' for name in FILES).encode()
    out.update({f'm19/r2/etc/{name}': text.encode() for name, text in FILES.items()})
    out['m19/r3/hidden'] = ''.join(f'{name}\n' for name in HIDDEN).encode()
    out['m19/r4/xorg-glamor.conf'] = xorg_landscape_conf().encode()
    out['m19/r6/udev-masks'] = ''.join(f'{name}\n' for name in UDEV_MASKED).encode()
    return out


if __name__ == '__main__':
    for name, data in render().items():
        print(f'{len(data):6d} {name}')
