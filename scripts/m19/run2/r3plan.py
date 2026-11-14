#!/usr/bin/env python3
"""R3 on top of R2: Xorg at 120 Hz on DSI-1 with a 60 Hz fallback, XFCE as root, touch, and no
software path to power off or reboot. Everything lands in RAM: the RAM /etc, /run/m19 and the
session home. The tree is never written.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import r2plan  # noqa: E402
import rootfs  # noqa: E402

TOUCH = 'goodix_ts'
MODE_120, MODE_60 = rootfs.REFRESH_MODES[120], rootfs.REFRESH_MODES[60]
# Observed on this panel: 1080x2400x60vid, x120vid, x90vid and x30vid.
MODES = (MODE_120, MODE_60)

# Lockers would lock a phone that has no keyboard; the power manager owns the power key and DPMS.
# The rest need hardware, a network or audio this run does not bring up.
HIDDEN = ('light-locker', 'xscreensaver', 'xfce4-power-manager', 'nm-applet', 'pulseaudio', 'print-applet',
          'polkit-gnome-authentication-agent-1', 'xiccd', 'org.gnome.Evolution-alarm-notify', 'unity-fallback-mount-helper',
          'unity-settings-daemon', 'indicator-application', 'indicator-messages', 'gnome-keyring-pkcs11', 'gnome-keyring-secrets',
          'gnome-keyring-ssh', 'im-launch')

# A desktop has Shut Down and Restart buttons. With these masked, long-press stays the only exit.
POWER_MASKED = ('poweroff.target', 'reboot.target', 'halt.target', 'kexec.target', 'ctrl-alt-del.target', 'systemd-poweroff.service',
                'systemd-reboot.service', 'systemd-halt.service', 'systemd-kexec.service')
MASKED = r2plan.MASKED + POWER_MASKED


def xorg_conf(mode):
    assert mode in MODES
    return '\n'.join((
        # NoTrapSignals: a crash reaches the kernel, which logs the faulting address and library (R3a had no backtrace).
        'Section "ServerFlags"', '    Option "AutoAddGPU" "false"', '    Option "DontVTSwitch" "true"', '    Option "BlankTime" "0"',
        '    Option "StandbyTime" "0"', '    Option "SuspendTime" "0"', '    Option "OffTime" "0"', '    Option "NoTrapSignals" "true"',
        'EndSection', '',
        'Section "Device"', '    Identifier "marble-kms"', '    Driver "modesetting"', '    Option "kmsdev" "/dev/dri/card0"',
        '    Option "AccelMethod" "none"', '    Option "PageFlip" "false"', '    Option "SWcursor" "true"',
        # R3a crashed with SDE's writeback connector Virtual-1 enabled as a second output. T9-desktop
        # forces it off; Xorg also ignores it. ZaphodHeads would not do: modesetting reads it only for
        # a shared, multi-screen entity.
        '    Option "Monitor-DSI-1" "marble-panel"', '    Option "Monitor-Virtual-1" "writeback"', 'EndSection', '',
        'Section "Monitor"', '    Identifier "marble-panel"', f'    Option "PreferredMode" "{mode}"', 'EndSection', '',
        'Section "Monitor"', '    Identifier "writeback"', '    Option "Ignore" "true"', 'EndSection', ''))


SHIM = '/run/m19/m19-xorg-shim.so'


def xorg_unit(description, config, log, fallback):
    lines = ['[Unit]', f'Description={description}', 'After=systemd-udev-trigger.service systemd-udevd.service']
    if fallback:
        lines.append('OnFailure=marble-xorg-fallback.service')
    # R3b: modesetting reads NULL atoms for SDE connector properties; the shim drops those properties.
    lines += ['', '[Service]', 'Type=simple', f'Environment=LD_PRELOAD={SHIM}',
              f'ExecStart=/usr/lib/xorg/Xorg :0 -config {config} -logfile {log} -nolisten tcp -noreset -novtswitch -s 0 -dpms',
              'LimitCORE=0', 'Restart=no', '']
    return '\n'.join(lines)


XORG = xorg_unit('M19 R3 Xorg on DSI-1 at 120 Hz', '/run/m19/xorg.conf', '/var/log/Xorg.0.log', True)
XORG_60 = xorg_unit('M19 R3 Xorg on DSI-1 at 60 Hz, after 120 Hz failed', '/run/m19/xorg-60.conf', '/var/log/Xorg.60.log', False)

XFCE = '''[Unit]
Description=M19 R3 XFCE session as root
After=marble-xorg.service marble-xorg-fallback.service dbus.socket

[Service]
Type=simple
Environment=DISPLAY=:0 HOME=/run/m19/session XDG_RUNTIME_DIR=/run/m19/xdg XDG_SESSION_TYPE=x11
ExecStartPre=/bin/sh -c 'i=0; while [ ! -S /tmp/.X11-unix/X0 ]; do i=$$((i+1)); [ "$$i" -lt 600 ] || exit 1; sleep 0.2; done'
ExecStart=/usr/bin/dbus-run-session -- /usr/bin/startxfce4
TimeoutStartSec=150
Restart=no
'''

TARGET = '''[Unit]
Description=M19 R3: XFCE on the read-only Ubuntu root
Requires=basic.target
Wants=multi-user.target m19-r3-report.service m19-r3-guard.service marble-xorg.service marble-xfce.service
After=basic.target multi-user.target
AllowIsolate=yes
'''

REPORT = r2plan.REPORT.replace('M19 R2 evidence over USB', 'M19 R3 evidence over USB')

# Its own service, started with the first units and restarted if it dies. It stops the desktop
# units and paints YELLOW on a hot battery or zone, a busy CPU or a long session.
GUARD = '''[Unit]
Description=M19 R3 thermal, load and time guard for the desktop
DefaultDependencies=no
IgnoreOnIsolate=yes

[Service]
Type=exec
ExecStart=/run/m19/m19-report guard
Restart=on-failure
RestartSec=1
StandardInput=null
StandardOutput=journal
StandardError=journal
'''

FILES = {name: text for name, text in r2plan.FILES.items() if not name.startswith('systemd/system/m19-r2')}
# arm64 logs an unhandled fault with its address and library only when exception tracing is on.
SYSCTL = 'debug.exception-trace = 1\n'

FILES.update({'systemd/system/m19-r3.target': TARGET, 'systemd/system/m19-r3-report.service': REPORT,
              'sysctl.d/m19-r3.conf': SYSCTL,
              'systemd/system/m19-r3-guard.service': GUARD,
              'systemd/system/marble-xorg.service': XORG, 'systemd/system/marble-xorg-fallback.service': XORG_60,
              'systemd/system/marble-xfce.service': XFCE})


# SDE's writeback connector, forced off by T9-desktop through its sysfs status.
WRITEBACK = 'card0-Virtual-1'


def render():
    """The files staged in the ramdisk: R2's root plan under m19/r2, the desktop under m19/r3."""
    assert len(set(MASKED)) == len(MASKED) and len(set(HIDDEN)) == len(HIDDEN)
    out = {name: data for name, data in r2plan.render().items() if not name.startswith('m19/r2/etc/')}
    out['m19/r2/default'] = b'm19-r3.target\n'
    out['m19/r2/masks'] = ''.join(f'{unit}\n' for unit in MASKED).encode()
    out['m19/r2/files'] = ''.join(f'{name}\n' for name in FILES).encode()
    out.update({f'm19/r2/etc/{name}': text.encode() for name, text in FILES.items()})
    out.update({'m19/r3/xorg.conf': xorg_conf(MODE_120).encode(), 'm19/r3/xorg-60.conf': xorg_conf(MODE_60).encode(),
                'm19/r3/modes': ''.join(f'{mode}\n' for mode in MODES).encode(), 'm19/r3/touch': f'{TOUCH}\n'.encode(),
                'm19/r3/hidden': ''.join(f'{name}\n' for name in HIDDEN).encode(), 'm19/r3/writeback': f'{WRITEBACK}\n'.encode()})
    return out


if __name__ == '__main__':
    for name, data in render().items():
        print(f'{len(data):6d} {name}')
