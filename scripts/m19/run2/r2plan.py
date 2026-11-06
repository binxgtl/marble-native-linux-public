#!/usr/bin/env python3
"""What T9 lays over the RAM copy of /etc for R2, and the tmpfs and /dev lists it mounts.

The Ubuntu tree is never written. systemd reads M19's units, masks and drop-ins from the RAM
copy of /etc, where they outrank anything the tree ships. Every mask is either hardware this
boot does not have, or a unit that could write storage, firmware or the serial line.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import rootfs  # noqa: E402

TMPFS = (('/run', '0755', '256m'), ('/tmp', '1777', '512m'), ('/var/tmp', '1777', '256m'), ('/var/log', '0755', '256m'),
         ('/var/cache', '0755', '256m'), ('/var/spool', '0755', '64m'), ('/var/lib/systemd', '0755', '64m'),
         ('/var/lib/NetworkManager', '0755', '16m'), ('/var/lib/upower', '0755', '16m'))

# Character nodes only. No block device, no TEE, no raw SCSI, no device-mapper control, no input
# (the power key would reach logind), no watchdog.
NODES = (('null', 'mem/null', '666'), ('zero', 'mem/zero', '666'), ('full', 'mem/full', '666'), ('random', 'mem/random', '666'),
         ('urandom', 'mem/urandom', '666'), ('kmsg', 'mem/kmsg', '644'), ('tty', 'tty/tty', '666'), ('console', 'tty/console', '600'),
         ('ptmx', 'tty/ptmx', '666'), ('ttyGS0', 'tty/ttyGS0', '600'), ('dri/card0', 'drm/card0', '600'))

# Units that could write a disk, firmware, EFI or boot state, or attach storage.
STORAGE_MASKED = ('fwupd.service', 'fwupd-refresh.service', 'fwupd-refresh.timer', 'udisks2.service', 'fstrim.service', 'fstrim.timer',
                  'e2scrub_all.service', 'e2scrub_all.timer', 'systemd-pstore.service', 'systemd-repart.service', 'systemd-growfs-root.service',
                  'systemd-sysext.service', 'systemd-confext.service', 'systemd-tmpfiles-setup-dev.service',
                  'systemd-tmpfiles-setup-dev-early.service', 'kmod-static-nodes.service', 'lvm2-monitor.service', 'lvm2-lvmpolld.socket',
                  'lvm2-lvmpolld.service', 'blk-availability.service', 'dm-event.socket', 'dm-event.service', 'mdmonitor.service',
                  'mdmonitor-oneshot.timer', 'mdcheck_start.timer', 'mdcheck_continue.timer', 'multipathd.service', 'multipathd.socket',
                  'iscsid.socket', 'iscsid.service', 'open-iscsi.service', 'zfs-import-cache.service', 'zfs-import-scan.service',
                  'zfs-mount.service', 'zfs-zed.service', 'zfs-share.service', 'zfs-volume-wait.service', 'snapd.service', 'snapd.socket',
                  'snapd.seeded.service', 'snapd.apparmor.service', 'snapd.autoimport.service', 'snapd.core-fixup.service',
                  'snapd.recovery-chooser-trigger.service', 'cloud-init-local.service', 'cloud-init.service', 'cloud-config.service',
                  'cloud-final.service', 'grub-common.service', 'grub-initrd-fallback.service', 'secureboot-db.service',
                  'systemd-boot-update.service', 'apt-daily.timer', 'apt-daily-upgrade.timer', 'systemd-firstboot.service')
# The panel belongs to the reporter's verdict, and the serial line to the PC.
DEVICE_MASKED = ('plymouth-start.service', 'plymouth-read-write.service', 'plymouth-quit.service', 'plymouth-quit-wait.service',
                 'serial-getty@ttyGS0.service')
# Nothing runs on a clock during the hold. The clock starts near systemd's build time, and the
# tmpfs job state reads as never run, so anacron would start every daily job a few minutes in.
SCHEDULE_MASKED = ('cron.service', 'anacron.service', 'anacron.timer', 'logrotate.timer', 'man-db.timer', 'dpkg-db-backup.timer',
                   'motd-news.timer', 'update-notifier-download.timer', 'update-notifier-motd.timer')
MASKED = rootfs.MASKED + STORAGE_MASKED + DEVICE_MASKED + SCHEDULE_MASKED

# Generators that turn fstab, crypttab, GPT entries or the kernel command line into mounts, swap,
# devices or gettys.
GENERATORS = ('systemd-gpt-auto-generator', 'systemd-fstab-generator', 'systemd-cryptsetup-generator', 'systemd-veritysetup-generator',
              'systemd-integritysetup-generator', 'systemd-hibernate-resume-generator', 'systemd-getty-generator',
              'systemd-system-update-generator', 'systemd-bless-boot-generator', 'snapd-generator', 'zfs-mount-generator',
              'cloud-init-generator', 'lvm2-activation-generator')

TARGET = '''[Unit]
Description=M19 R2: Ubuntu under systemd on the read-only root
Requires=basic.target
Wants=multi-user.target m19-r2-report.service
After=basic.target multi-user.target
AllowIsolate=yes
'''

# Early and outside the boot ordering, so it reports even if the boot stalls or isolates.
REPORT = '''[Unit]
Description=M19 R2 evidence over USB
DefaultDependencies=no
IgnoreOnIsolate=yes
After=systemd-journald.socket

[Service]
Type=exec
ExecStart=/run/m19/m19-report report
StandardInput=null
StandardOutput=journal
StandardError=journal
'''

MANAGER = '''[Manager]
ShowStatus=no
DefaultTimeoutStartSec=45s
DefaultDeviceTimeoutSec=45s
RuntimeWatchdogSec=off
RebootWatchdogSec=off
CrashReboot=no
'''

JOURNAL = '''[Journal]
Storage=volatile
RuntimeMaxUse=64M
ForwardToConsole=no
ForwardToWall=no
'''

LOGIN = '''[Login]
NAutoVTs=0
ReserveVT=0
HandlePowerKey=ignore
HandlePowerKeyLongPress=ignore
HandleRebootKey=ignore
HandleSuspendKey=ignore
HandleHibernateKey=ignore
HandleLidSwitch=ignore
HandleLidSwitchExternalPower=ignore
HandleLidSwitchDocked=ignore
IdleAction=ignore
'''

SLEEP = '''[Sleep]
AllowSuspend=no
AllowHibernation=no
AllowSuspendThenHibernate=no
AllowHybridSleep=no
'''

FSTAB = '# M19 R2: nothing mounts from fstab. / is a read-only bind made before systemd starts.\n'

FILES = {'fstab': FSTAB, 'systemd/system/m19-r2.target': TARGET, 'systemd/system/m19-r2-report.service': REPORT,
         'systemd/system.conf.d/m19-r2.conf': MANAGER, 'systemd/journald.conf.d/m19-r2.conf': JOURNAL,
         'systemd/logind.conf.d/m19-r2.conf': LOGIN, 'systemd/sleep.conf.d/m19-r2.conf': SLEEP}


def render():
    """The files staged under m19/r2 in the ramdisk, by path."""
    assert tuple(point for point, _, _ in TMPFS) == rootfs.TMPFS
    assert len(set(MASKED)) == len(MASKED) and len(set(GENERATORS)) == len(GENERATORS)
    out = {'m19/r2/masks': ''.join(f'{unit}\n' for unit in MASKED),
           'm19/r2/generators': ''.join(f'{name}\n' for name in GENERATORS),
           'm19/r2/tmpfs': ''.join(f'{point} {mode} {size}\n' for point, mode, size in TMPFS),
           'm19/r2/nodes': ''.join(f'{name} {kind} {mode}\n' for name, kind, mode in NODES),
           'm19/r2/files': ''.join(f'{name}\n' for name in FILES)}
    out.update({f'm19/r2/etc/{name}': text for name, text in FILES.items()})
    return {name: text.encode() for name, text in out.items()}


if __name__ == '__main__':
    for name, data in render().items():
        print(f'{len(data):6d} {name}')
