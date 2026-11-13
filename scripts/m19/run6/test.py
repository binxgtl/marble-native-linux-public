#!/usr/bin/env python3
"""R6 tests (docs/m19-r6.md): m19-wifi on a fake kernel and a stand-in CNSS daemon, T9-wifi and T9-sound on synthetic
trees, and m19-sink over R5b's Run31 fixtures. No phone, no module, no firmware and no network."""
import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

try:
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None

HERE = Path(__file__).resolve().parent
ARGS = None
CMDLINE = 'console=null hwid.hwid_value=589833 hwid.project=15 hwid.build_adc=10093 hwid.project_adc=57421 androidboot.x=1\n'
HWID = {'hwid_value': '589833', 'project': '15', 'build_adc': '10093', 'project_adc': '57421'}

# m19-audio's stand-in for m19-wifi: each phase leaves the kernel state the real modules would.
WIFI_HELPER = r'''#!/bin/sh
R=$M19_WIFI_ROOT
echo "$*" >> "$M19_TEST/helper.log"
[ "$1" = load ] || exit 2
phase=$3
case "${M19_FAKE_LOAD_FAIL:-}" in "$phase") exit 1;; esac
dev=$R/sys/devices/pci0000/0000:01:00.0
case "$phase" in
 wifi)
  for m in pci_msm_drv mhi qrtr_mhi cnss_plat_ipc_qmi_svc memory_dump_v2 wlan_firmware_service cnss2; do
   echo "$m 4096 0 - Live 0x0" >> "$R/proc/modules"
  done
  mkdir -p "$R/sys/bus/pci/devices" "$R/sys/bus/pci/drivers/cnss_pci" "$R/sys/bus/platform/drivers/cnss2" "$R/sys/bus/mhi/devices/mhi0"
  mkdir -p "$R/sys/bus/platform/devices/b0000000.qcom,cnss-qca6490"
  [ "${M19_FAKE_PLATFORM:-bound}" = unbound ] || ln -s "$R/sys/bus/platform/drivers/cnss2" "$R/sys/bus/platform/devices/b0000000.qcom,cnss-qca6490/driver"
  if [ "${M19_FAKE_PCI:-one}" != none ]; then
   mkdir -p "$dev"
   echo 0x17cb > "$dev/vendor"; echo 0x1103 > "$dev/device"
   [ "${M19_FAKE_PCI:-one}" = unbound ] || ln -s "$R/sys/bus/pci/drivers/cnss_pci" "$dev/driver"
   ln -s "$dev" "$R/sys/bus/pci/devices/0000:01:00.0"
  fi
  if [ "${M19_FAKE_PCI:-one}" = two ]; then
   other=$R/sys/devices/pci0001/0001:01:00.0
   mkdir -p "$other"; echo 0x17cb > "$other/vendor"; echo 0x1103 > "$other/device"
   ln -s "$R/sys/bus/pci/drivers/cnss_pci" "$other/driver"; ln -s "$other" "$R/sys/bus/pci/devices/0001:01:00.0"
  fi;;
 wlan)
  for m in cfg80211 cnss_nl cnss_prealloc cnss_utils mi_cnss_statistic qca6490; do
   [ "$m" = qca6490 ] && [ "${M19_FAKE_MODULES:-}" = noqca ] && continue
   echo "$m 4096 0 - Live 0x0" >> "$R/proc/modules"
  done
  case "${M19_FAKE_FW:-good}" in
   good) echo "6,500,1,-;cnss: FW name is qca6490/amss20.bin, FW fallback name is amss20.bin" >> "$R/dev/kmsg";;
   wrong) echo "6,500,1,-;cnss: FW name is qca6490/amss.bin, FW fallback name is amss.bin" >> "$R/dev/kmsg";;
  esac
  echo "6,501,2,-;cnss: Target capability: chip_id: 0x12, chip_family: 0xb, board_id: 0xff, soc_id: 0x400c1211, otp_version: 0x440102" >> "$R/dev/kmsg"
  if [ "${M19_FAKE_NET:-one}" != none ]; then
   mkdir -p "$dev/net/wlan0" "$dev/ieee80211/phy0" "$R/sys/class/net/wlan0"
   ln -s "$dev" "$dev/ieee80211/phy0/device"
   ln -s "$dev" "$R/sys/class/net/wlan0/device"
   ln -s "$dev/ieee80211/phy0" "$R/sys/class/net/wlan0/phy80211"
  fi;;
esac
exit 0
'''
SYSTEMCTL = '#!/bin/sh\necho "$*" >> "$M19_TEST/systemctl.log"\nexit "${M19_SYSTEMCTL_RC:-0}"\n'


class Daemon(unittest.TestCase):
    """m19-cnssd's admission: M12's daemon for an owner that is its parent, never init (R6a, R6b)."""

    def test_the_owner_is_the_parent_that_made_the_pair(self):
        result = subprocess.run([ARGS.admit], capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, 'm19-cnssd admission: 16 cases PASS\n')

    def test_the_entry_keeps_m12s_daemon_and_main(self):
        text = (HERE / 'cnssd-main.c').read_text()
        self.assertIn('#define M12_CNSSD_NO_MAIN\n#include "../../m12/next/cnssd-linux.c"\n', text)
        # After admission, M12's main line for line.
        m12 = (HERE.parents[1] / 'm12/next/cnssd-linux.c').read_text()
        tail = m12[m12.index('    (void)signal(SIGTERM,SIG_IGN);'):m12.index('#endif', m12.index('int main('))]
        self.assertIn(tail, text)
        self.assertIn('if (m19_cnssd_admit(argc, argv, getppid(), geteuid(), 0, &l))\n        return 2;', text)


class WifiRunner(unittest.TestCase):
    """m19-wifi: M12's order, its fail-closed stops, NetworkManager only after readiness, the daemon kept."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.test = Path(self.directory.name)
        self.root = self.test / 'root'
        r = self.root
        for d in ('run/m19/wifi/modules', 'proc', 'sys/module/firmware_class/parameters', 'sys/kernel/cnss', 'sys/class/net', 'dev', 'usr/bin'):
            (r / d).mkdir(parents=True, exist_ok=True)
        (r / 'run/m19/wifi.stage').write_text('staged\n')
        (r / 'run/m19/wifi/modules.list').write_text('')
        (r / 'run/m19/wifi/m19-audio').write_text(WIFI_HELPER)
        (r / 'run/m19/wifi/m19-audio').chmod(0o755)
        shutil.copy(ARGS.cnssd, r / 'run/m19/wifi/m19-cnssd')
        (r / 'usr/bin/systemctl').write_text(SYSTEMCTL)
        (r / 'usr/bin/systemctl').chmod(0o755)
        (r / 'proc/cmdline').write_text(CMDLINE)
        (r / 'proc/modules').write_text('msm_qmp 4096 0 - Live 0x0\nhwid 4096 0 - Live 0x0\n')
        (r / 'sys/module/hwid/parameters').mkdir(parents=True)
        for key, value in HWID.items():
            (r / 'sys/module/hwid/parameters' / key).write_text(value + '\n')
        (r / 'sys/module/firmware_class/parameters/path').write_text('/run/m19/firmware\n')
        (r / 'sys/kernel/cnss/fs_ready').write_text('')
        (r / 'dev/kmsg').write_text('6,1,1,-;before the cursor: cnss: FW name is qca6490/amss.bin, FW fallback name is amss.bin\n')

    def run_wifi(self, **env):
        environment = {**os.environ, 'ASAN_OPTIONS': 'detect_leaks=0', 'M19_WIFI_ROOT': str(self.root), 'M19_TEST': str(self.test),
                       'M19_FAKE_KMSG': str(self.root / 'dev/kmsg'), 'M19_FAKE_FS_READY': str(self.root / 'sys/kernel/cnss/fs_ready'),
                       'M19_WIFI_RETURN_MS': '200', 'M19_WIFI_OWNER_MS': '1500', 'M19_WIFI_CBC_MS': '1500', **env}
        result = subprocess.run([ARGS.wifi], capture_output=True, text=True, env=environment, timeout=60, start_new_session=True)
        return result.returncode, result.stdout + result.stderr

    def result(self):
        return (self.root / 'run/m19/wifi.result').read_text() if (self.root / 'run/m19/wifi.result').exists() else None

    def report(self):
        return dict(line.split('=', 1) for line in (self.root / 'run/m19/wifi.report').read_text().splitlines())

    def log(self, name):
        path = self.test / name
        return path.read_text() if path.exists() else ''

    def test_the_bring_up_in_m12s_order(self):
        rc, out = self.run_wifi()
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.result(), 'ready wlan0\n')
        rep = self.report()
        self.assertEqual({k: rep[k] for k in ('step', 'rc', 'hwid', 'wifi_rc', 'pci', 'bdf', 'wlan_rc', 'owner', 'firmware', 'fs_ready', 'cbc',
                                              'cbc_bdf', 'cbc_capability', 'cbc_mission', 'cbc_requirement', 'cbc_fault', 'iface', 'nm',
                                              'owner_poisoned')},
                         {'step': 'ready', 'rc': '0', 'hwid': '1', 'wifi_rc': '0', 'pci': '1', 'bdf': '0000:01:00.0', 'wlan_rc': '0', 'owner': '1',
                          'firmware': '1', 'fs_ready': '1', 'cbc': '1', 'cbc_bdf': '1', 'cbc_capability': '1', 'cbc_mission': '1',
                          'cbc_requirement': '2', 'cbc_fault': '0', 'iface': 'wlan0', 'nm': '0', 'owner_poisoned': '0'})
        modules = self.root / 'run/m19/wifi/modules'
        self.assertEqual(self.log('helper.log').splitlines(), [f'load {self.root}/run/m19/wifi/modules.list wifi {modules} {modules}',
                                                                f'load {self.root}/run/m19/wifi/modules.list wlan {modules} {modules}'])
        self.assertEqual(self.log('systemctl.log'), 'start --no-block NetworkManager.service\n')
        self.assertTrue((self.root / 'run/m19/wifi.ready').exists() and (self.root / 'run/m19/wifi.started').exists())
        self.assertEqual((self.root / 'sys/kernel/cnss/fs_ready').read_text(), '1')
        # The kernel log before the cursor is never read: its wrong firmware name did not count.
        self.assertIn('M19 wifi: kernel cnss: FW name is qca6490/amss20.bin', out)
        self.assertIn('M19 wifi: hwid project expected=15 observed=15', out)

    def test_the_daemon_is_admitted_by_its_own_check(self):
        # The stand-in runs m19-cnssd's admission: this runner, its parent, made the pair. A daemon that refuses its
        # owner (as M12's did, R6a and R6b) is the end of the socket at once.
        rc, out = self.run_wifi()
        self.assertEqual((rc, self.result()), (0, 'ready wlan0\n'), out)
        self.assertRegex(out, r'daemon pid=\d+ ready=1 idle=1 rc=0')
        rc, out = self.run_wifi(M19_FAKE_CNSSD='exit')
        self.assertEqual((rc, self.result()), (1, 'failed owner -71\n'), out)
        self.assertIn('daemon receipt rc=-32', out)

    def test_one_run_a_boot(self):
        (self.root / 'run/m19/wifi.started').write_text('')
        rc, out = self.run_wifi()
        self.assertEqual(rc, 2)
        self.assertIsNone(self.result())
        self.assertEqual(self.log('helper.log'), '')

    def test_refusals_before_anything_loads(self):
        cases = (('not-staged', 'skipped stage\n', 2), ('firmware-path', 'failed firmware-path -18\n', 1), ('hwid-value', 'failed hwid -18\n', 1),
                 ('hwid-missing', 'failed hwid -71\n', 1), ('cmdline', 'failed hwid -22\n', 1))
        for change, want, code in cases:
            with self.subTest(change=change):
                self.setUp()
                if change == 'not-staged':
                    (self.root / 'run/m19/wifi.stage').write_text('skipped modem-mount\n')
                elif change == 'firmware-path':
                    (self.root / 'sys/module/firmware_class/parameters/path').write_text('/m6/modem/image\n')
                elif change == 'hwid-value':
                    (self.root / 'sys/module/hwid/parameters/project').write_text('0\n')
                elif change == 'hwid-missing':
                    (self.root / 'sys/module/hwid/parameters/build_adc').unlink()
                else:
                    (self.root / 'proc/cmdline').write_text('console=null hwid.project=15\n')
                rc, out = self.run_wifi()
                self.assertEqual((rc, self.result()), (code, want), out)
                self.assertEqual(self.log('helper.log'), '')
                self.assertEqual(self.log('systemctl.log'), '')
                self.assertFalse((self.root / 'run/m19/wifi.ready').exists())

    def test_each_failure_stops_at_its_step(self):
        cases = (({'M19_FAKE_LOAD_FAIL': 'wifi'}, 'failed load-wifi 1\n', 1), ({'M19_FAKE_PCI': 'none'}, 'failed pci -19\n', 1),
                 ({'M19_FAKE_PCI': 'two'}, 'failed pci -17\n', 1), ({'M19_FAKE_PCI': 'unbound'}, 'failed pci -19\n', 1), ({'M19_FAKE_LOAD_FAIL': 'wlan'}, 'failed load-wlan 1\n', 2),
                 ({'M19_FAKE_CNSSD': 'silent'}, 'failed owner -110\n', 2), ({'M19_FAKE_CNSSD': 'poison'}, 'failed owner -71\n', 2),
                 ({'M19_FAKE_CNSSD': 'bad'}, 'failed owner -71\n', 2), ({'M19_FAKE_CNSSD': 'exit'}, 'failed owner -71\n', 2),
                 ({'M19_FAKE_FW': 'wrong'}, 'failed firmware -18\n', 2), ({'M19_FAKE_FW': 'none'}, 'failed firmware -2\n', 2),
                 ({'M19_FAKE_CBC': 'wrong-bdf'}, 'failed cbc -18\n', 2), ({'M19_FAKE_CBC': 'caldb'}, 'failed cbc -61\n', 2),
                 ({'M19_FAKE_CBC': 'none', 'M19_WIFI_CBC_MS': '400'}, 'failed cbc -110\n', 2),
                 ({'M19_FAKE_CNSSD': 'late-poison'}, 'failed cbc -71\n', 2), ({'M19_FAKE_NET': 'none'}, 'failed iface -19\n', 2),
                 ({'M19_FAKE_PLATFORM': 'unbound'}, 'failed iface -19\n', 2), ({'M19_FAKE_MODULES': 'noqca'}, 'failed iface -19\n', 2))
        for env, want, loads in cases:
            with self.subTest(env=env):
                self.setUp()
                rc, out = self.run_wifi(**env)
                self.assertEqual((rc, self.result()), (1, want), out)
                self.assertEqual(len(self.log('helper.log').splitlines()), loads)
                # Nothing is ever unloaded, retried or handed to NetworkManager.
                self.assertEqual(self.log('systemctl.log'), '')
                self.assertFalse((self.root / 'run/m19/wifi.ready').exists())
                self.assertNotIn('rmmod', self.log('helper.log'))
                fs_ready = (self.root / 'sys/kernel/cnss/fs_ready').read_text()
                self.assertEqual(fs_ready, '1' if want.startswith(('failed cbc', 'failed iface')) else '')

    def test_a_daemon_fault_after_readiness_is_recorded(self):
        rc, out = self.run_wifi(M19_FAKE_POISON_ON=str(self.root / 'run/m19/wifi.ready'), M19_WIFI_RETURN_MS='800')
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.result(), 'fault owner\n')
        self.assertEqual(self.report()['owner_poisoned'], '1')
        self.assertIn('daemon fault after readiness', out)
        self.assertEqual(self.log('systemctl.log'), 'start --no-block NetworkManager.service\n')

    def test_a_networkmanager_start_failure_is_recorded_not_fatal(self):
        rc, out = self.run_wifi(M19_SYSTEMCTL_RC='1')
        self.assertEqual((rc, self.result()), (0, 'ready wlan0\n'))
        self.assertEqual(self.report()['nm'], '1')

    def test_the_runner_never_kills_unloads_or_writes_elsewhere(self):
        text = (HERE / 'wifi.c').read_text()
        self.assertNotRegex(text, r'\b(kill|delete_module|rmmod|reboot|SIGKILL|unlink|O_TRUNC[^\n]*fs_ready)\b')
        self.assertEqual(re.findall(r'write\(fd, "1", 1\)', text), ['write(fd, "1", 1)'])
        # The daemon is m19-cnssd, this process's own child.
        self.assertIn('.cnssd = "/run/m19/wifi/m19-cnssd",', text)
        self.assertEqual(re.findall(r'execl\(C->cnssd, "([^"]+)"', text), ['m19-cnssd'])


FAKE_BB = r'''#!/bin/sh
echo "$*" >> "$M19_TEST/bb.log"
command=$1; shift
case "$command" in
 mount) case "${M19_FAIL:-}" in mount|"mount-$2") exit 1;; esac; exit 0;;
 umount) case "${M19_FAIL:-}" in umount) exit 1;; esac; exit 0;;
 mknod) case "${M19_FAIL:-}" in mknod) exit 1;; esac; : > "$3"; exit 0;;
 blockdev) case "$1" in --getro) echo "${M19_GETRO:-1}";; esac; exit 0;;
 sha256sum) if [ "$1" = -c ] && [ "$2" = -s ]; then shift 2; exec sha256sum -c --status "$@"; fi; exec sha256sum "$@";;
 *) exec "$command" "$@";;
esac
'''
STAGE_HELPER = r'''#!/bin/sh
echo "$*" >> "$M19_TEST/helper.log"
case "$1" in
 map) echo "${M19_MAP_OUT:-253:9}"; exit "${M19_MAP_RC:-0}";;
 unmap) exit "${M19_UNMAP_RC:-0}";;
 check) exit "${M19_CHECK_RC:-0}";;
esac
exit 2
'''


def sha(data):
    return hashlib.sha256(data).hexdigest()


class WifiStage(unittest.TestCase):
    """T9-wifi: the firmware read-only from modem, the modules from vendor_dlkm and the ramdisk, every hash checked."""
    BOOT = ('pci-msm-drv.ko', 'mhi.ko', 'qrtr-mhi.ko', 'cnss_plat_ipc_qmi_svc.ko', 'memory_dump_v2.ko', 'wlan_firmware_service.ko', 'cnss2.ko',
            'cfg80211.ko', 'cnss_nl.ko', 'cnss_prealloc.ko', 'cnss_utils.ko', 'mi_cnss_statistic.ko')

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.test = Path(self.directory.name)
        r = self.root = self.test / 'root'
        new = r / 'newroot'
        for d in ('run/m19/firmware', 'etc', 'dev'):
            (new / d).mkdir(parents=True)
        (r / 'run/m19').mkdir(parents=True)
        (r / 'run/m19/audio.result').write_text('ready\n')
        (r / 'sys/module/firmware_class/parameters').mkdir(parents=True)
        (r / 'sys/module/firmware_class/parameters/path').write_text('/run/m19/firmware\n')
        (r / 'proc').mkdir()
        (r / 'proc/bootconfig').write_text('androidboot.slot_suffix = "_a"\nandroidboot.other = "x"\n')
        for name, part, dev in (('sda12', 'modem_a', '8:12'), ('sda13', 'modem_b', '8:13'), ('sda20', 'super', '8:20')):
            (r / 'sys/class/block' / name).mkdir(parents=True)
            (r / 'sys/class/block' / name / 'uevent').write_text(f'MAJOR=8\nPARTNAME={part}\n')
            (r / 'sys/class/block' / name / 'dev').write_text(dev + '\n')
        (r / 'sys/class/misc/device-mapper').mkdir(parents=True)
        (r / 'sys/class/misc/device-mapper/dev').write_text('10:236\n')
        (r / 'dev').mkdir()
        plan = r / 'm19/wifi'
        plan.mkdir(parents=True)
        # 222 firmware files on the "mounted" modem, and M12's inventory of them.
        modem = r / 'run/m19/wifi-stage/modem/image/qca6490'
        modem.mkdir(parents=True)
        lines = []
        for i in range(222):
            data = f'firmware {i}\n'.encode()
            (modem / f'fw{i:03d}.bin').write_bytes(data)
            lines.append(f'{sha(data)}  qca6490/fw{i:03d}.bin\n')
        (plan / 'firmware.sha256').write_text(''.join(lines))
        (r / 'lib/modules').mkdir(parents=True)
        dlkm = r / 'run/m19/wifi-stage/dlkm/lib/modules'
        dlkm.mkdir(parents=True)
        rows = []
        for name in self.BOOT:
            (r / 'lib/modules' / name).write_bytes(name.encode())
            rows.append(f"{'wlan' if self.BOOT.index(name) >= 7 else 'wifi'} vendor_boot {name} {len(name)} {sha(name.encode())}\n")
        (dlkm / 'qca_cld3_qca6490.ko').write_bytes(b'wlan driver')
        rows.append(f'wlan vendor_dlkm qca_cld3_qca6490.ko 11 {sha(b"wlan driver")}\n')
        (plan / 'modules.list').write_text(''.join(rows))
        (plan / 'WCNSS_qcom_cfg.ini').write_text('gEnableIdleScan=0\n')
        (plan / 'WCNSS_qcom_cfg.ini.sha256').write_text(sha(b'gEnableIdleScan=0\n') + '  WCNSS_qcom_cfg.ini\n')
        (plan / 'm19-cnssd').write_bytes(b'cnssd')
        (plan / 'm19-cnssd.sha256').write_text(sha(b'cnssd') + '  m19-cnssd\n')
        (plan / 'm19-wifi').write_bytes(b'runner')
        (plan / 'private.nmconnection').write_text('[wifi]\nssid=1;2;\n')
        (plan / 'private.nmconnection').chmod(0o644)  # whatever its mode, the copy is root's alone
        (r / 'sbin').mkdir()
        (r / 'sbin/m19-audio').write_text(STAGE_HELPER)
        (r / 'sbin/m19-audio').chmod(0o755)
        (self.test / 'bb').write_text(FAKE_BB)
        (self.test / 'bb').chmod(0o755)

    def run_stage(self, **env):
        environment = {**os.environ, 'M19_ROOT': str(self.root), 'M19_BB': str(self.test / 'bb'), 'M19_AUDIO': str(self.root / 'sbin/m19-audio'),
                       'M19_TEST': str(self.test), **env}
        result = subprocess.run(['sh', str(HERE / 't9-wifi')], capture_output=True, text=True, env=environment, timeout=60)
        return result.returncode, result.stderr

    def stage(self):
        path = self.root / 'newroot/run/m19/wifi.stage'
        return path.read_text() if path.exists() else None

    def log(self, name):
        path = self.test / name
        return path.read_text() if path.exists() else ''

    def test_everything_staged_read_only(self):
        rc, err = self.run_stage()
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.stage(), 'staged\n')
        new = self.root / 'newroot'
        firmware = sorted(p.name for p in (new / 'run/m19/firmware/qca6490').iterdir())
        self.assertEqual(len(firmware), 222)
        self.assertEqual((new / 'run/m19/firmware/wlan/qca_cld/qca6490/WCNSS_qcom_cfg.ini').read_text(), 'gEnableIdleScan=0\n')
        modules = sorted(p.name for p in (new / 'run/m19/wifi/modules').iterdir())
        self.assertEqual(modules, sorted(self.BOOT + ('qca_cld3_qca6490.ko',)))
        for name in ('m19-audio', 'm19-cnssd', 'm19-wifi'):
            self.assertEqual((new / 'run/m19/wifi' / name).stat().st_mode & 0o777, 0o755)
        profile = new / 'etc/NetworkManager/system-connections/m19-wifi.nmconnection'
        self.assertEqual((profile.read_text(), profile.stat().st_mode & 0o777), ('[wifi]\nssid=1;2;\n', 0o600))
        bb = self.log('bb.log')
        self.assertIn(f'mknod -m 400 {self.root}/dev/m19-wifi-modem b 8 12\n', bb)
        self.assertIn(f'blockdev --setro {self.root}/dev/m19-wifi-modem\n', bb)
        self.assertIn(f'mount -t vfat -o ro,nosuid,nodev,noexec {self.root}/dev/m19-wifi-modem {self.root}/run/m19/wifi-stage/modem\n', bb)
        self.assertIn(f'mount -t erofs -o ro,nosuid,nodev,noexec {self.root}/dev/m19-wifi-dlkm {self.root}/run/m19/wifi-stage/dlkm\n', bb)
        self.assertEqual(bb.count('umount '), 2)
        self.assertNotRegex(bb, r'(?<!u)mount (?!-t (vfat|erofs) -o ro,)')
        helper = self.log('helper.log').splitlines()
        self.assertEqual(helper[0], f'map {self.root}/dev/m19-wifi-control {self.root}/dev/m19-wifi-super 8:20 vendor_dlkm_a 0 m19-wifi-dlkm')
        self.assertEqual(helper[1:], [f'unmap {self.root}/dev/m19-wifi-control m19-wifi-dlkm',
                                      f'check {new}/run/m19/wifi/modules.list {new}/run/m19/wifi/modules {new}/run/m19/wifi/modules'])
        # Nothing this step made stays outside the new root.
        for node in ('m19-wifi-modem', 'm19-wifi-control', 'm19-wifi-super', 'm19-wifi-dlkm'):
            self.assertFalse((self.root / 'dev' / node).exists(), node)
        self.assertFalse((self.root / 'run/m19/wifi-stage').exists())

    def test_the_other_slot(self):
        (self.root / 'proc/bootconfig').write_text('androidboot.slot_suffix = "_b"\n')
        rc, err = self.run_stage()
        self.assertEqual((rc, self.stage()), (0, 'staged\n'), err)
        self.assertIn(f'mknod -m 400 {self.root}/dev/m19-wifi-modem b 8 13\n', self.log('bb.log'))
        self.assertIn(' vendor_dlkm_b 1 m19-wifi-dlkm', self.log('helper.log'))

    def test_every_fault_skips_and_cleans_up(self):
        cases = (('audio', 'skipped audio-stage\n'), ('path', 'skipped firmware-path\n'), ('input', 'skipped input m19-cnssd\n'),
                 ('slot', 'skipped slot []\n'), ('modem', 'skipped modem-missing\n'), ('writable', 'skipped modem-writable\n'),
                 ('mount', 'skipped modem-mount\n'), ('missing-fw', 'skipped firmware missing fw007.bin\n'),
                 ('count', 'skipped firmware count 221\n'), ('hash', 'skipped firmware-hash\n'), ('ini', 'skipped ini-hash\n'),
                 ('map', 'skipped map rc=2\n'), ('module', 'skipped module missing cnss2.ko\n'), ('rows', 'skipped list rows 12 1\n'),
                 ('check', 'skipped module-check\n'), ('cnssd', 'skipped cnssd hash ' + sha(b'other') + '\n'))
        for change, want in cases:
            with self.subTest(change=change):
                self.setUp()
                env = {}
                plan = self.root / 'm19/wifi'
                if change == 'audio':
                    (self.root / 'run/m19/audio.result').write_text('partial load audio rc=1\n')
                elif change == 'path':
                    (self.root / 'sys/module/firmware_class/parameters/path').write_text('/m6/modem/image\n')
                elif change == 'input':
                    (plan / 'm19-cnssd').unlink()
                elif change == 'slot':
                    (self.root / 'proc/bootconfig').write_text('androidboot.other = "x"\n')
                elif change == 'modem':
                    shutil.rmtree(self.root / 'sys/class/block/sda12')
                elif change == 'writable':
                    env['M19_GETRO'] = '0'
                elif change == 'mount':
                    env['M19_FAIL'] = 'mount'
                elif change == 'missing-fw':
                    (self.root / 'run/m19/wifi-stage/modem/image/qca6490/fw007.bin').unlink()
                elif change == 'count':
                    lines = (plan / 'firmware.sha256').read_text().splitlines(True)
                    (plan / 'firmware.sha256').write_text(''.join(lines[:-1]))
                elif change == 'hash':
                    (self.root / 'run/m19/wifi-stage/modem/image/qca6490/fw100.bin').write_text('changed\n')
                elif change == 'ini':
                    (plan / 'WCNSS_qcom_cfg.ini').write_text('changed\n')
                elif change == 'map':
                    env['M19_MAP_RC'] = '2'
                elif change == 'module':
                    (self.root / 'lib/modules/cnss2.ko').unlink()
                elif change == 'rows':
                    lines = (plan / 'modules.list').read_text().splitlines(True)
                    (plan / 'modules.list').write_text(''.join(lines[1:]))
                elif change == 'check':
                    env['M19_CHECK_RC'] = '2'
                else:
                    (plan / 'm19-cnssd').write_bytes(b'other')
                rc, err = self.run_stage(**env)
                self.assertEqual((rc, self.stage()), (0, want), err)
                new = self.root / 'newroot'
                for path in ('run/m19/wifi', 'run/m19/firmware/qca6490', 'run/m19/firmware/wlan', 'etc/NetworkManager/system-connections/m19-wifi.nmconnection'):
                    self.assertFalse((new / path).exists(), path)
                for node in ('m19-wifi-modem', 'm19-wifi-control', 'm19-wifi-super', 'm19-wifi-dlkm'):
                    self.assertFalse((self.root / 'dev' / node).exists(), node)
                bb = self.log('bb.log')
                self.assertEqual(bb.count('mount -t vfat'), bb.count('umount ' + str(self.root / 'run/m19/wifi-stage/modem')) + (change == 'mount'))
                helper = self.log('helper.log')
                if 'map ' in helper and change != 'map':
                    self.assertIn('unmap ', helper)

    def test_a_cleanup_that_cannot_finish_stops_the_run(self):
        rc, err = self.run_stage(M19_FAIL='umount', M19_CHECK_RC='2')
        self.assertEqual(rc, 1, err)
        self.assertIn('M19 T9 wifi: FAILED ', err)
        self.assertIsNone(self.stage())

    def test_an_existing_stage_is_never_overwritten(self):
        (self.root / 'newroot/run/m19/wifi.stage').write_text('staged\n')
        rc, err = self.run_stage()
        self.assertEqual(rc, 1)
        self.assertEqual(self.log('bb.log'), '')

    def test_the_step_mounts_read_only_and_writes_only_ram(self):
        text = (HERE / 't9-wifi').read_text()
        self.assertNotRegex(text, r'\b(reboot|poweroff|mkfs|fsck|blkdiscard|fstrim|setrw|insmod|rmmod|modprobe|dd|losetup|remount)\b|/data|--setrw')
        self.assertEqual(re.findall(r'mount -t (\S+) -o (\S+)', text), [('vfat', 'ro,nosuid,nodev,noexec'), ('erofs', 'ro,nosuid,nodev,noexec')])
        self.assertEqual(re.findall(r'mknod -m (\d+)', text), ['400', '400', '600', '400'])


class SoundPrep(unittest.TestCase):
    """T9-sound: R5b's ALSA mask, the sink and its verified plan in RAM, and PulseAudio's FIFO, made once."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.test = Path(self.directory.name)
        r = self.root = self.test / 'root'
        for d in ('newroot/run/m19', 'newroot/etc', 'newroot/dev', 'run/m19', 'm19/r6', 'm19/speaker'):
            (r / d).mkdir(parents=True)
        (r / 'run/m19/audio.result').write_text('ready\n')
        (r / 'm19/r6/udev-masks').write_text('60-persistent-alsa.rules\n')
        (r / 'm19/m19-sink').write_bytes(b'sink')
        self.plan = b'M11SPK01 plan'
        (r / 'm19/speaker/plan.bin').write_bytes(self.plan)
        (r / 'm19/speaker/plan.sha256').write_text(sha(self.plan) + '  plan.bin\n')
        (self.test / 'bb').write_text(FAKE_BB)
        (self.test / 'bb').chmod(0o755)

    def run_prep(self, **env):
        environment = {**os.environ, 'M19_ROOT': str(self.root), 'M19_BB': str(self.test / 'bb'), 'M19_TEST': str(self.test), **env}
        result = subprocess.run(['sh', str(HERE / 't9-sound')], capture_output=True, text=True, env=environment, timeout=60)
        return result.returncode, result.stderr

    def test_masks_copies_and_makes_the_fifo(self):
        rc, err = self.run_prep()
        self.assertEqual(rc, 0, err)
        new = self.root / 'newroot'
        rule = new / 'etc/udev/rules.d/60-persistent-alsa.rules'
        self.assertTrue(rule.is_symlink() and os.readlink(rule) == '/dev/null')
        self.assertEqual((new / 'run/m19/m19-sink').stat().st_mode & 0o777, 0o755)
        self.assertEqual((new / 'run/m19/sink').stat().st_mode & 0o777, 0o700)
        self.assertEqual((new / 'run/m19/sink/plan.bin').read_bytes(), self.plan)
        self.assertEqual((new / 'run/m19/sink/plan.bin').stat().st_mode & 0o777, 0o600)
        fifo = new / 'run/m19/sink/fifo'
        self.assertTrue(fifo.is_fifo())
        self.assertEqual(fifo.stat().st_mode & 0o777, 0o600)
        self.assertIn(f'M19 T9 sound: udev_masks=1 plan_sha256={sha(self.plan)} fifo=1\n', err)

    def test_every_precondition_fails(self):
        for change in ('stage', 'snd', 'm11-snd', 'plan', 'sha', 'binary', 'masks', 'exists'):
            with self.subTest(change=change):
                self.setUp()
                r = self.root
                if change == 'stage':
                    (r / 'run/m19/audio.result').write_text('skipped list\n')
                elif change in ('snd', 'm11-snd'):
                    (r / 'newroot/dev' / change).mkdir()
                elif change == 'plan':
                    (r / 'm19/speaker/plan.bin').write_bytes(self.plan + b'x')
                elif change == 'sha':
                    (r / 'm19/speaker/plan.sha256').write_text('XYZ  plan.bin\n')
                elif change == 'binary':
                    (r / 'm19/m19-sink').unlink()
                elif change == 'masks':
                    (r / 'm19/r6/udev-masks').write_text('')
                else:
                    (r / 'newroot/run/m19/sink').mkdir()
                rc, err = self.run_prep()
                self.assertEqual(rc, 1, change)
                self.assertIn('M19 T9 sound failed: ', err)

    def test_the_step_touches_only_ram_etc_and_run(self):
        text = (HERE / 't9-sound').read_text()
        self.assertNotRegex(text, r'\b(reboot|poweroff|mkfs|fsck|mount|umount|mknod|insmod|rmmod|modprobe|dd)\b|/data')
        self.assertEqual(re.findall(r'mkfifo -m (\d+) "([^"]+)"', text), [('600', '$new/run/m19/sink/fifo')])


class Sink(unittest.TestCase):
    """m19-sink (test-sink.c): the scanner, the prechecks and qualifications, and Run31's session with the stream."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def run_sink(self, *args, as_root=False):
        env = {**os.environ, 'ASAN_OPTIONS': 'detect_leaks=0'}
        cmd = [ARGS.sink, *map(str, args)]
        if as_root and os.geteuid() != 0:
            check = subprocess.run(['sudo', '-n', 'true'], stdin=subprocess.DEVNULL, capture_output=True)
            if check.returncode != 0:
                if os.environ.get('CI'):
                    self.fail('sudo -n required on CI for the sink root session')
                self.skipTest('sudo -n unavailable')
            cmd = ['sudo', '-n', 'timeout', '--kill-after=5', '120', *cmd]
            root = str(self.root)
            self.addCleanup(lambda: subprocess.run(['sudo', '-n', 'rm', '-rf', root], stdin=subprocess.DEVNULL, capture_output=True))
        if as_root and fcntl is not None:
            lock_fd = os.open('/tmp/m19-speaker-root.lock', os.O_CREAT | os.O_RDWR, 0o666)
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX)
                return subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True, env=env, timeout=240, start_new_session=True)
            finally:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
                os.close(lock_fd)
        return subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True, env=env, timeout=240, start_new_session=True)

    def test_1_scan_snd(self):
        snd = self.root / 'snd'
        snd.mkdir()
        self.assertEqual(self.run_sink('scan-snd', snd).stdout.strip(), '0')
        (snd / 'controlC0').write_text('')
        self.assertEqual(self.run_sink('scan-snd', snd).stdout.strip(), '1')

    def test_2_prechecks(self):
        res = self.run_sink('prechecks', self.root)
        self.assertEqual(res.returncode, 0, res.stderr + res.stdout)
        self.assertIn('PASS m19-sink prechecks\n', res.stdout)

    def test_3_root_session(self):
        if ARGS.no_root_sink:
            return
        res = self.run_sink('session', self.root, as_root=True)
        self.assertEqual(res.returncode, 0, res.stderr + res.stdout)
        self.assertIn('PASS m19-sink root session\n', res.stdout)


def main():
    global ARGS
    parser = argparse.ArgumentParser()
    parser.add_argument('--wifi', help='test-wifi, the runner built with M19_WIFI_TEST')
    parser.add_argument('--cnssd', help='test-cnssd, the stand-in daemon')
    parser.add_argument('--admit', help='test-cnssd-main, m19-cnssd\'s admission tests')
    parser.add_argument('--sink', help='test-sink')
    parser.add_argument('--no-root-sink', action='store_true')
    ARGS, rest = parser.parse_known_args()
    unittest.main(argv=[sys.argv[0], *rest])


if __name__ == '__main__':
    main()
