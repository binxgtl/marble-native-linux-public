#!/usr/bin/env python3
"""Runtime plan for booting /data/ubuntu natively without changing it.

overlayfs cannot use a casefold f2fs as a lower layer on this kernel, so the root stays
read-only and every write goes to tmpfs. Configuration is generated under /run, which
systemd reads before /etc. Nothing here touches the rootfs.
"""
from fbe import Stop

ROOT = '/data/ubuntu'
TMPFS = ('/run', '/tmp', '/var/tmp', '/var/log', '/var/cache', '/var/spool', '/var/lib/systemd',
         '/var/lib/NetworkManager', '/var/lib/upower')
# Disabled for now: each needs a device, a VT or a daemon this boot does not provide.
MASKED = ('apport.service', 'cups.service', 'cups.path', 'cups-browsed.service', 'display-manager.service',
          'e2scrub_reap.service', 'getty@tty1.service', 'lightdm.service', 'lm-sensors.service',
          'ModemManager.service', 'NetworkManager.service', 'networkd-dispatcher.service', 'ssl-cert.service',
          'systemd-fsck-root.service', 'systemd-remount-fs.service', 'unattended-upgrades.service',
          'whoopsie.path', 'wpa_supplicant.service', 'sleep.target', 'suspend.target', 'hibernate.target',
          'hybrid-sleep.target', 'suspend-then-hibernate.target')
HOME_ALLOWED = ('.config/xfce4',)
HOME_REFUSED = ('.gemini', '.ssh', '.gnupg', '.config/gh', '.aws', '.npm', '.bash_history', '.cache')
SESSION_HOME = '/run/m19/session'
REFRESH_MODES = {30: '1080x2400x30vid', 60: '1080x2400x60vid', 90: '1080x2400x90vid', 120: '1080x2400x120vid'}

# What the existing tree provides, with what native boot does to each part.
REUSE = {
    'Userspace packages (1581)': 'keep',
    'systemd 255, udev, dbus': 'keep',
    'Xorg, modesetting driver, libinput driver': 'keep',
    'XFCE 4.18': 'keep',
    'Mesa and Turnip KGSL build': 'keep, later stage',
    'XFCE settings under /root': 'copy allowlisted paths to tmpfs',
    '/var runtime state': 'tmpfs per directory',
    'Enabled units for absent hardware': 'mask from /run',
    'lightdm': 'not used, needs a VT',
    'Termux bind mounts and environment': 'not used',
    'Android apps data, credentials under /root': 'not read, not copied',
}


def xorg_conf(refresh=60):
    if refresh not in REFRESH_MODES:
        raise Stop('REFRESH_MODE')
    return '\n'.join((
        'Section "ServerFlags"', '    Option "AutoAddGPU" "false"', '    Option "DontVTSwitch" "true"', 'EndSection', '',
        'Section "Device"', '    Identifier "marble-kms"', '    Driver "modesetting"',
        '    Option "kmsdev" "/dev/dri/card0"', '    Option "AccelMethod" "none"', '    Option "PageFlip" "false"',
        '    Option "SWcursor" "true"', '    Option "Monitor-DSI-1" "marble-panel"', 'EndSection', '',
        'Section "Monitor"', '    Identifier "marble-panel"', f'    Option "PreferredMode" "{REFRESH_MODES[refresh]}"', 'EndSection', ''))


def _unit(description, after, body, install):
    return '\n'.join(('[Unit]', f'Description={description}', f'After={after}', '', '[Service]', *body, '', '[Install]',
                      f'WantedBy={install}', ''))


def units():
    xorg = _unit('Native Xorg on DSI-1', 'systemd-udevd.service dbus.service',
                 ('Type=simple', 'ExecStart=/usr/lib/xorg/Xorg :0 -config /run/m19/xorg.conf -nolisten tcp -noreset',
                  'Restart=no'), 'marble-desktop.target')
    session = _unit('XFCE session', 'marble-xorg.service',
                    ('Type=simple', 'Environment=DISPLAY=:0', f'Environment=HOME={SESSION_HOME}',
                     'Environment=XDG_RUNTIME_DIR=/run/m19/xdg', 'ExecStartPre=/usr/bin/test -S /tmp/.X11-unix/X0',
                     'ExecStart=/usr/bin/dbus-run-session -- /usr/bin/startxfce4', 'Restart=no'), 'marble-desktop.target')
    target = '\n'.join(('[Unit]', 'Description=Native XFCE desktop', 'Requires=basic.target',
                        'Wants=marble-xorg.service marble-xfce.service', 'After=basic.target', ''))
    return {'marble-xorg.service': xorg, 'marble-xfce.service': session, 'marble-desktop.target': target}


def home_copies(paths=HOME_ALLOWED):
    for path in paths:
        if path not in HOME_ALLOWED or any(path == bad or path.startswith(bad + '/') for bad in HOME_REFUSED):
            raise Stop('HOME_PATH')
    return [(f'/root/{path}', f'{SESSION_HOME}/{path}') for path in paths]


def plan(refresh=60):
    tree = {f'/run/systemd/system/{name}': text for name, text in units().items()}
    tree['/run/m19/xorg.conf'] = xorg_conf(refresh)
    links = {f'/run/systemd/system/{name}': '/dev/null' for name in MASKED}
    links['/run/systemd/system/default.target'] = 'marble-desktop.target'
    for path in (*tree, *links):
        if not path.startswith('/run/'):
            raise Stop('WRITE_OUTSIDE_RUN')
    return {'root': ROOT, 'root_read_only': True, 'tmpfs': list(TMPFS), 'files': tree, 'links': links,
            'home_copies': home_copies()}


def check_mountpoints(plan_value, existing):
    """A read-only root cannot grow a mount point, so each must already exist."""
    absent = [path for path in plan_value['tmpfs'] if path != '/run' and path not in existing]
    if absent:
        raise Stop('TMPFS_MOUNTPOINT ' + ','.join(absent))
    return True
