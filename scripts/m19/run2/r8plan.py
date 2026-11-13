#!/usr/bin/env python3
"""R8 on top of R7a: the Ubuntu tree read-write, and the battery on the panel (docs/m19-r8.md).

- / is /data/ubuntu itself, read-write (scripts/m19/run8/t9-root). M19's own files never go into the tree. They are
  laid out here as paths under the new root: in /run, which is RAM, or in the three /etc directories that T9-root
  makes RAM for the boot. systemd's /run/systemd/system.control comes before /etc/systemd/system, so R7a's masks and
  the default target hold whatever the tree's /etc holds; T9-root refuses any other file the tree's /etc would
  outrank.
- /var/cache and /var/spool are the tree's now. Logs, systemd's state, NetworkManager's and upower's stay RAM, and
  NetworkManager's connections too: the Wi-Fi profile never reaches the disk.
- upower runs: its unit asks for PrivateUsers=, and this kernel has no user namespaces (R7a: upowerd exited 217/USER,
  and the panel's battery and xfce4-power-manager waited on it).
- xfce4-power-manager is no longer hidden. Xorg still runs with -dpms, so it cannot blank the panel.
- XFCE's home is /root, kept. PulseAudio and the keypad keep R7a's RAM home.
Everything else is R7a's.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import r4plan  # noqa: E402
import r6plan  # noqa: E402
import r7plan  # noqa: E402

# Point, mode, size and kind of each RAM mount, in order: /run first, since M19's files go there. "copy" puts the
# tree's files back on top; "empty" starts empty.
TMPFS = (('/run', '0755', '256m', ''), ('/tmp', '1777', '512m', ''), ('/var/tmp', '1777', '256m', ''), ('/var/log', '0755', '256m', ''),
         ('/var/lib/systemd', '0755', '64m', ''), ('/var/lib/NetworkManager', '0755', '16m', ''), ('/var/lib/upower', '0755', '16m', ''),
         ('/media', '0755', '1m', ''), ('/etc/NetworkManager/system-connections', '0700', '1m', 'empty'),
         ('/etc/udev/rules.d', '0755', '16m', 'copy'), ('/etc/pulse/default.pa.d', '0755', '1m', 'copy'))

UPOWER = '''[Service]
# M19 R8: this kernel has no user namespaces. With PrivateUsers=yes upowerd exited 217/USER (R7a).
PrivateUsers=no
'''

# R7a's session. XFCE's home is /root, and M19's hidden autostart entries come first among the system's.
XFCE_ENV = ('Environment=DISPLAY=:0 HOME=/run/m19/session XDG_RUNTIME_DIR=/run/m19/xdg XDG_SESSION_TYPE=x11\n',
            'Environment=DISPLAY=:0 HOME=/root XDG_RUNTIME_DIR=/run/m19/xdg XDG_SESSION_TYPE=x11 XDG_CONFIG_DIRS=/run/m19/xdg-config:/etc/xdg\n')
HIDDEN = tuple(name for name in r6plan.HIDDEN if name != 'xfce4-power-manager')

TARGET = r4plan._swap(r4plan._swap(r7plan.TARGET, "Description=M19 R7: R6d's session and CE unlock with the owner's PIN on the read-only Ubuntu root",
                                   "Description=M19 R8: R7a's session on the read-write Ubuntu root, with the battery on the panel"),
                      'm19-r7-report.service', 'm19-r8-report.service')
REPORT = r4plan._swap(r7plan.REPORT, 'M19 R7 evidence over USB', 'M19 R8 evidence over USB')


def place(name):
    """Where an R7a file goes under R8's new root, or None for R2's empty fstab: the tree's own has no line, and its
    generator stays masked."""
    if name == 'fstab':
        return None
    if name.startswith('systemd/system/'):
        return 'run/systemd/system.control/' + name[len('systemd/system/'):]
    if name.startswith(('systemd/', 'sysctl.d/', 'NetworkManager/conf.d/')):
        return 'run/' + name
    if name.startswith('m19/'):
        return 'run/m19/etc/' + name[len('m19/'):]
    if name.startswith(('pulse/default.pa.d/', 'udev/rules.d/')):
        return 'etc/' + name
    raise ValueError(name)


def files():
    """R7a's files at their R8 places, /etc/m19 read from /run/m19/etc, with R8's target, report, session and upower."""
    out = {}
    for name, text in r7plan.FILES.items():
        if name in ('systemd/system/m19-r7.target', 'systemd/system/m19-r7-report.service'):
            continue
        where = place(name)
        if where is None:
            continue
        if name == 'systemd/system/marble-xfce.service':
            text = r4plan._swap(text, *XFCE_ENV)
        out[where] = text.replace('/etc/m19/', '/run/m19/etc/')
    out['run/systemd/system.control/m19-r8.target'] = TARGET
    out['run/systemd/system.control/m19-r8-report.service'] = REPORT
    out['run/systemd/system.control/upower.service.d/m19.conf'] = UPOWER
    return out


def render():
    """R7a's plan without R2's /etc layout, with R8's under m19/r8 and the power manager shown."""
    r7 = r7plan.render()
    placed = files()
    assert not any('/etc/m19/' in text for text in placed.values())
    assert len(set(HIDDEN)) == len(HIDDEN) and len(HIDDEN) == len(r6plan.HIDDEN) - 1
    assert {point for point, _, _, kind in TMPFS if kind} <= {'/' + where.rsplit('/', 1)[0] for where in placed if where.startswith('etc/')} | {
        '/etc/NetworkManager/system-connections'}
    out = {name: data for name, data in r7.items() if not name.startswith('m19/r2/')}
    out['m19/r8/masks'] = r7['m19/r2/masks']
    out['m19/r8/generators'] = r7['m19/r2/generators']
    out['m19/r8/nodes'] = r7['m19/r2/nodes']
    out['m19/r8/tmpfs'] = ''.join(f'{point} {mode} {size}{" " + kind if kind else ""}\n' for point, mode, size, kind in TMPFS).encode()
    out['m19/r8/default'] = b'm19-r8.target\n'
    out['m19/r8/files'] = ''.join(f'{where}\n' for where in placed).encode()
    out.update({f'm19/r8/root/{where}': text.encode() for where, text in placed.items()})
    out['m19/r3/hidden'] = ''.join(f'{name}\n' for name in HIDDEN).encode()
    return out


if __name__ == '__main__':
    for name, data in render().items():
        print(f'{len(data):6d} {name}')
