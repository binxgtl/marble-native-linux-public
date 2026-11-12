#!/usr/bin/env python3
"""R5a on synthetic inputs: the audio helper on a fake kernel and synthetic super images, the audio stage and
T3-audio on synthetic trees. No device, no module, no image from the phone."""
import argparse
import hashlib
import os
import re
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
try:
    import fcntl
except ImportError:
    fcntl = None

HERE = Path(__file__).resolve().parent
ARGS = None
SLOT_BYTES = 65536


def sha(data):
    return hashlib.sha256(data).digest()


def super_image(partitions, minor=2, slots=3, first=2048, device_bytes=None, device_name=b'super', slot_overrides=None, entry_sizes=None):
    """An LP image as AOSP lays it out: 4096 reserved bytes, two geometry copies, then each slot's metadata.
    partitions: {name: [(sectors, type, target, source), ...]}; slot_overrides: {slot: partitions}."""
    geometry = bytearray(struct.pack('<II32sIII', 0x616c4467, 52, bytes(32), SLOT_BYTES, slots, 4096))
    geometry[8:40] = sha(bytes(geometry))
    image = bytearray(4096) + geometry.ljust(4096, b'\0') * 2
    sizes = entry_sizes or (52, 24, 48, 64)
    for slot in range(slots):
        table_partitions, table_extents = b'', b''
        count = 0
        for name, extents in (slot_overrides or {}).get(slot, partitions).items():
            table_partitions += struct.pack('<36sIIII', name.encode(), 1, count, len(extents), 0).ljust(sizes[0], b'\0')[:sizes[0]]
            for sectors, kind, target, source in extents:
                table_extents += struct.pack('<QIQI', sectors, kind, target, source).ljust(sizes[1], b'\0')[:sizes[1]]
                count += 1
        groups = struct.pack('<36sIQ', b'default', 0, 0).ljust(sizes[2], b'\0')[:sizes[2]]
        size = device_bytes if device_bytes is not None else 8 * 1024 * 1024 * 1024
        devices = struct.pack('<QIIQ36sI', first, 0, 0, size, device_name, 0).ljust(sizes[3], b'\0')[:sizes[3]]
        tables = table_partitions + table_extents + groups + devices
        header_size = 256 if minor == 2 else 128
        offsets = [0, len(table_partitions), len(table_partitions) + len(table_extents), len(table_partitions) + len(table_extents) + len(groups)]
        counts = [len(table_partitions) // sizes[0], len(table_extents) // sizes[1], 1, 1]
        header = bytearray(struct.pack('<IHHI32sI32s', 0x414c5030, 10, minor, header_size, bytes(32), len(tables), sha(tables)))
        for offset, number, entry in zip(offsets, counts, sizes):
            header += struct.pack('<III', offset, number, entry)
        header = header.ljust(header_size, b'\0')
        header[12:44] = sha(bytes(header))
        image += (bytes(header) + tables).ljust(SLOT_BYTES, b'\0')
    return bytes(image)


DLKM = {'vendor_dlkm_a': [(57744, 0, 15460352, 0)], 'vendor_dlkm_b': [], 'system_a': [(1000, 0, 4096, 0)]}


class Helper(unittest.TestCase):
    """m19-audio on the fake kernel (test-audio.c)."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def run_helper(self, *args, **env):
        environment = {**os.environ, 'ASAN_OPTIONS': 'detect_leaks=0', **env}
        result = subprocess.run([ARGS.driver, *map(str, args)], capture_output=True, text=True, env=environment, timeout=60)
        return result.returncode, result.stdout, result.stderr

    def map(self, image, partition='vendor_dlkm_a', slot=0, **env):
        path = self.root / 'super'
        path.write_bytes(image)
        return self.run_helper('map', '/dev/control', path, '259:32', partition, slot, 'm19-vendor-dlkm', **env)

    def test_maps_the_partition_read_only(self):
        rc, out, err = self.map(super_image(DLKM), M19_FAKE_SECTORS=str(16 * 1024 * 1024 * 2))
        self.assertEqual((rc, out), (0, '253:4615\n'), err)
        self.assertIn('FAKE block 259:32\n', err)
        self.assertIn('M19 audio map: vendor_dlkm_a extent 0 sectors=57744 at=15460352\n', err)
        calls = [line for line in err.splitlines() if line.startswith('FAKE dm')]
        self.assertEqual(calls, ['FAKE dm /dev/control create m19-vendor-dlkm version=4 flags=0',
                                 'FAKE dm /dev/control table m19-vendor-dlkm version=4 flags=1 targets=1 size=368 [0+57744 linear 259:32 15460352]',
                                 'FAKE dm /dev/control resume m19-vendor-dlkm version=4 flags=0'])
        self.assertIn('M19 audio map: vendor_dlkm_a sectors=57744 read-only as m19-vendor-dlkm 253:4615\n', err)

    def test_extents_map_end_to_end_in_order(self):
        image = super_image({'vendor_dlkm_a': [(100, 0, 4096, 0), (50, 0, 9000, 0), (8, 0, 2048, 0)]})
        rc, out, err = self.map(image)
        self.assertEqual(rc, 0, err)
        table = next(line for line in err.splitlines() if ' table ' in line)
        self.assertTrue(table.endswith('targets=3 size=480 [0+100 linear 259:32 4096] [100+50 linear 259:32 9000] [150+8 linear 259:32 2048]'), table)
        self.assertNotIn('SIZE-MISMATCH', err)

    def test_the_slot_and_the_header_version_are_read_as_written(self):
        image = super_image(DLKM, slot_overrides={1: {'vendor_dlkm_a': [(7, 0, 3000, 0)]}})
        rc, _, err = self.map(image, slot=1)
        self.assertEqual(rc, 0, err)
        self.assertIn('[0+7 linear 259:32 3000]', err)
        for minor in (0, 1):
            with self.subTest(minor=minor):
                rc, _, err = self.map(super_image(DLKM, minor=minor))
                self.assertEqual(rc, 0, err)
        rc, _, err = self.map(super_image(DLKM, slots=2), slot=2)
        self.assertEqual(rc, 2)
        self.assertIn('M19 audio lp: geometry bounds\n', err)

    def corrupt(self, image, offset, value=b'\xff'):
        return image[:offset] + value + image[offset + len(value):]

    def assertRefused(self, image, why, partition='vendor_dlkm_a', **env):
        rc, out, err = self.map(image, partition=partition, **env)
        self.assertEqual((rc, out), (2, ''), err)
        self.assertIn(f'M19 audio lp: {why}\n', err)
        self.assertNotIn('FAKE dm', err)

    def test_every_metadata_fault_refuses_before_any_device(self):
        good = super_image(DLKM)
        metadata = 12288
        self.assertRefused(self.corrupt(good, 4096), 'geometry magic')
        self.assertRefused(self.corrupt(good, 4096 + 50), 'geometry checksum')
        self.assertRefused(self.corrupt(good, metadata), 'header magic')
        self.assertRefused(self.corrupt(good, metadata + 4, b'\x0b'), 'header magic')
        self.assertRefused(self.corrupt(good, metadata + 200), 'header checksum')
        self.assertRefused(self.corrupt(good, metadata + 256 + 3), 'tables checksum')
        self.assertRefused(good[:9000], 'geometry read' if len(good[:9000]) < 4096 + 52 else 'metadata read')
        self.assertRefused(super_image(DLKM, entry_sizes=(56, 24, 48, 64)), 'table bounds')
        self.assertRefused(super_image(DLKM, device_name=b'userdata'), 'block device')
        self.assertRefused(super_image({'vendor_dlkm_ab': [(8, 0, 4096, 0)]}), 'partition missing')
        self.assertRefused(super_image({'vendor_dlkm_a ': [(8, 0, 4096, 0)], 'vendor_dlkm': [(8, 0, 4096, 0)]}), 'partition missing')
        self.assertRefused(super_image({'vendor_dlkm_a': [(8, 0, 4096, 0)], 'x': [], 'vendor_dlkm_a\0': []}), 'duplicate partition')
        self.assertRefused(super_image({'vendor_dlkm_a': []}), 'extent bounds')
        self.assertRefused(super_image({'vendor_dlkm_a': [(1, 0, 4096 + i, 0) for i in range(9)]}), 'extent bounds')
        self.assertRefused(super_image({'vendor_dlkm_a': [(8, 1, 0, 0)]}), 'extent type')
        self.assertRefused(super_image({'vendor_dlkm_a': [(8, 0, 4096, 1)]}), 'extent type')
        self.assertRefused(super_image({'vendor_dlkm_a': [(0, 0, 4096, 0)]}), 'extent range')
        self.assertRefused(super_image({'vendor_dlkm_a': [(8, 0, 2047, 0)]}), 'extent range')
        self.assertRefused(super_image({'vendor_dlkm_a': [(9, 0, 4096, 0)]}, device_bytes=(4096 + 8) * 512), 'extent range')
        self.assertRefused(super_image({'vendor_dlkm_a': [(2 ** 64 - 1, 0, 4096, 0)]}), 'extent range')
        # super itself is smaller than its metadata claims.
        self.assertRefused(super_image(DLKM), 'extent range', M19_FAKE_SECTORS='15460352')
        rc, _, err = self.map(super_image({'vendor_dlkm_a': [(9, 0, 4096, 0)]}, device_bytes=(4096 + 9) * 512))
        self.assertEqual(rc, 0, err)

    def test_the_super_node_and_the_arguments_are_checked(self):
        rc, out, err = self.map(super_image(DLKM), M19_FAKE_FAIL='block')
        self.assertEqual((rc, out), (2, ''))
        self.assertIn('M19 audio map: super is not 259:32\n', err)
        self.assertNotIn('FAKE dm', err)
        path = self.root / 'super'
        for args in (('/dev/control', path, '259', 'vendor_dlkm_a', '0', 'n'), ('/dev/control', path, '259:32', 'vendor_dlkm_a', 'x', 'n'),
                     ('/dev/control', path, '259:32', '', '0', 'n'), ('/dev/control', path, '259:32', 'vendor_dlkm_a', '0', ''),
                     ('/dev/control', path, '259:32', 'p' * 36, '0', 'n'), ('/dev/control', path, '259:32x', 'vendor_dlkm_a', '0', 'n'),
                     ('/dev/control', path, '259:32', 'vendor_dlkm_a', '0', 'n' * 128)):
            with self.subTest(args=args):
                rc, out, err = self.run_helper('map', *args)
                self.assertEqual((rc, out), (2, ''))
                self.assertNotIn('FAKE', err)
        rc, _, err = self.run_helper('map', '/dev/control', self.root / 'absent', '259:32', 'vendor_dlkm_a', '0', 'n')
        self.assertEqual(rc, 2)
        self.assertNotIn('FAKE dm', err)
        for args in ((), ('map',), ('unmap', 'c'), ('load', 'l', 'p', 'd'), ('check', 'l', 'd'), ('other', 'a', 'b')):
            with self.subTest(args=args):
                rc, _, err = self.run_helper(*args)
                self.assertEqual(rc, 2)
                self.assertIn('M19 audio: usage\n', err)

    def test_a_failed_table_removes_the_device(self):
        image = super_image(DLKM)
        rc, out, err = self.map(image, M19_FAKE_FAIL='create')
        self.assertEqual((rc, out), (2, ''))
        self.assertNotIn(' remove ', err)
        for fail in ('table', 'resume'):
            with self.subTest(fail=fail):
                rc, out, err = self.map(image, M19_FAKE_FAIL=fail)
                self.assertEqual((rc, out), (2, ''))
                self.assertIn('FAKE dm /dev/control remove m19-vendor-dlkm', err)
                rc, out, err = self.map(image, M19_FAKE_FAIL=fail + ',remove')
                self.assertEqual((rc, out), (1, ''))
                self.assertIn('M19 audio map: remove errno=6\n', err)

    def test_unmap(self):
        rc, _, err = self.run_helper('unmap', '/dev/control', 'm19-vendor-dlkm')
        self.assertEqual(rc, 0)
        self.assertIn('FAKE dm /dev/control remove m19-vendor-dlkm version=4 flags=0\n', err)
        rc, _, err = self.run_helper('unmap', '/dev/control', 'm19-vendor-dlkm', M19_FAKE_FAIL='remove')
        self.assertEqual(rc, 1)
        self.assertIn('M19 audio unmap: m19-vendor-dlkm errno=6\n', err)


class Loader(unittest.TestCase):
    """m19-audio check and load: every byte loaded is a byte hashed."""
    ROWS = (('first', 'vendor_boot', 'btpower.ko'), ('first', 'vendor_dlkm', 'bam_dma.ko'), ('second', 'vendor_dlkm', 'machine_dlkm.ko'),
            ('second', 'vendor_boot', 'hwid.ko'), ('second', 'vendor_dlkm', 'aw882xx_dlkm.ko'))

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.dlkm, self.boot = self.root / 'dlkm', self.root / 'boot'
        self.dlkm.mkdir()
        self.boot.mkdir()
        self.lines = []
        for phase, source, name in self.ROWS:
            data = f'{name}\n'.encode() + bytes(range(256)) * (len(name) + 3)
            (self.dlkm if source == 'vendor_dlkm' else self.boot).joinpath(name).write_bytes(data)
            self.lines.append(f'{phase} {source} {name} {len(data)} {hashlib.sha256(data).hexdigest()}\n')
        self.write_list()

    def write_list(self, lines=None):
        self.list = self.root / 'modules.list'
        self.list.write_text(''.join(self.lines if lines is None else lines))

    def run_helper(self, *args, **env):
        environment = {**os.environ, 'ASAN_OPTIONS': 'detect_leaks=0', **env}
        result = subprocess.run([ARGS.driver, *map(str, args)], capture_output=True, text=True, env=environment, timeout=60)
        return result.returncode, result.stderr

    def load(self, phase, **env):
        return self.run_helper('load', self.list, phase, self.dlkm, self.boot, **env)

    def loaded(self, err):
        return re.findall(r'FAKE init_module (\S+) size=', err)

    def test_check_reads_every_module_and_loads_nothing(self):
        rc, err = self.run_helper('check', self.list, self.dlkm, self.boot)
        self.assertEqual(rc, 0, err)
        self.assertIn('M19 audio check: 5 of 5 modules checked\n', err)
        self.assertNotIn('FAKE init_module', err)

    def test_each_phase_loads_in_list_order_from_its_source(self):
        rc, err = self.load('first')
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.loaded(err), ['btpower.ko', 'bam_dma.ko'])
        self.assertIn('M19 audio load: first btpower.ko rc=0 errno=0\n', err)
        self.assertIn('M19 audio load: phase first loaded=2 of 2\n', err)
        rc, err = self.load('second')
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.loaded(err), ['machine_dlkm.ko', 'hwid.ko', 'aw882xx_dlkm.ko'])
        rc, err = self.load('third')
        self.assertEqual(rc, 2)
        self.assertIn('M19 audio load: phase third is empty\n', err)

    def test_any_bad_module_in_the_phase_stops_before_the_first_load(self):
        for change in ('hash', 'size', 'missing', 'link', 'directory'):
            with self.subTest(change=change):
                self.setUp()
                path = self.dlkm / 'aw882xx_dlkm.ko'
                data = path.read_bytes()
                if change == 'hash':
                    path.write_bytes(data[:-1] + b'\0')
                elif change == 'size':
                    path.write_bytes(data + b'\0')
                elif change == 'missing':
                    path.unlink()
                elif change == 'link':
                    (self.root / 'elsewhere').write_bytes(data)
                    path.unlink()
                    path.symlink_to(self.root / 'elsewhere')
                else:
                    path.unlink()
                    path.mkdir()
                rc, err = self.load('second')
                self.assertEqual(rc, 2, err)
                self.assertEqual(self.loaded(err), [])
                rc, err = self.run_helper('check', self.list, self.dlkm, self.boot)
                self.assertEqual(rc, 2, err)
                # The other phase is untouched by it.
                rc, err = self.load('first')
                self.assertEqual(rc, 0, err)

    def test_the_source_decides_the_directory(self):
        (self.dlkm / 'hwid.ko').write_bytes((self.boot / 'hwid.ko').read_bytes())
        (self.boot / 'hwid.ko').unlink()
        rc, err = self.load('second')
        self.assertEqual(rc, 2)
        self.assertIn('M19 audio: hwid.ko unreadable or not', err)

    def test_a_failed_load_stops_and_says_whether_anything_loaded(self):
        rc, err = self.load('second', M19_FAKE_FAIL='load:machine_dlkm.ko')
        self.assertEqual(rc, 2)
        self.assertEqual(self.loaded(err), ['machine_dlkm.ko'])
        self.assertIn('M19 audio load: second machine_dlkm.ko rc=-1 errno=17\n', err)
        rc, err = self.load('second', M19_FAKE_FAIL='load:hwid.ko')
        self.assertEqual(rc, 1)
        self.assertEqual(self.loaded(err), ['machine_dlkm.ko', 'hwid.ko'])
        self.assertIn('M19 audio load: phase second loaded=1 of 3\n', err)

    def test_bad_lists_are_refused(self):
        line = self.lines[0]
        phase, source, name, size, digest = line.split()
        bad = (f'{phase} vendor_xxx {name} {size} {digest}\n', f'{phase} {source} ../{name} {size} {digest}\n',
               f'{phase} {source} {name[:-3]} {size} {digest}\n', f'{phase} {source} .{name} {size} {digest}\n',
               f'{phase} {source} {name} 0 {digest}\n', f'{phase} {source} {name} {2 ** 23} {digest}\n', f'{phase} {source} {name} -1 {digest}\n',
               f'{phase} {source} {name} {size} {digest.upper()}\n', f'{phase} {source} {name} {size} {digest[:-1]}\n',
               f'{phase} {source} {name} {size} {digest}0\n', f'{phase} {source} {name} {size} {digest} extra\n',
               f'{phase} {source} {name} {size}\n', f'{phase} {source} {name} {size} {digest[:-1]}g\n', line.rstrip('\n'))
        for text in bad:
            with self.subTest(text=text):
                self.write_list(self.lines[1:] + [text])
                for args in (('check', self.list, self.dlkm, self.boot), ('load', self.list, 'first', self.dlkm, self.boot)):
                    rc, err = self.run_helper(*args)
                    self.assertEqual(rc, 2, err)
                    self.assertIn('M19 audio: bad list\n', err)
                    self.assertNotIn('FAKE init_module', err)
        self.write_list(self.lines + [self.lines[0]])
        rc, err = self.run_helper('check', self.list, self.dlkm, self.boot)
        self.assertEqual(rc, 2)
        self.write_list([])
        rc, err = self.run_helper('check', self.list, self.dlkm, self.boot)
        self.assertEqual(rc, 2)
        self.write_list(self.lines * 13)
        rc, err = self.run_helper('check', self.list, self.dlkm, self.boot)
        self.assertEqual(rc, 2)


FAKE_BB = '''#!/bin/sh
echo "$*" >> "$M19_TEST/bb.log"
command=$1; shift
case "$command" in
 mount)
  case "${M19_FAIL:-}" in mount) exit 1;; esac
  exit 0;;
 umount)
  case "${M19_FAIL:-}" in umount) exit 1;; esac
  exit 0;;
 mknod)
  case "${M19_FAIL:-}" in mknod) exit 1;; esac
  : > "$3"; exit 0;;
 blockdev)
  case "$1" in --getro) echo "${M19_GETRO:-1}";; esac
  exit 0;;
 cp)
  case "${M19_FAIL:-}" in
   cp) exit 1;;
   corrupt-plan-cp)
    cp "$@" || exit 1
    case "$2" in */plan.bin) printf x >> "$2";; esac
    exit 0;;
  esac
  exec cp "$@";;
 *) exec "$command" "$@";;
esac
'''

# The helper: logs each call, and loads by appending the phase's rows to the fake /proc/modules.
FAKE_HELPER = '''#!/bin/sh
echo "$*" >> "$M19_TEST/helper.log"
case "$1" in
 map) [ -n "${M19_MAP_OUT+x}" ] && echo "$M19_MAP_OUT" || echo 253:7; exit "${M19_MAP_RC:-0}";;
 unmap) exit "${M19_UNMAP_RC:-0}";;
 check) exit "${M19_CHECK_RC:-0}";;
 load)
  list=$2; phase=$3
  rows=$(awk -v p="$phase" '$1 == p' "$list" | wc -l)
  rc=0
  case "${M19_LOAD_FAIL:-}" in "$phase":*) rest=${M19_LOAD_FAIL#*:}; rc=${rest%%:*}; rows=${rest#*:};; esac
  case "${M19_LOAD_SHORT:-}" in "$phase") rows=$((rows-1));; esac
  i=0
  while [ "$i" -lt "$rows" ]; do echo "$phase$i 4096 0 - Live 0x0" >> "$M19_ROOT/proc/modules"; i=$((i+1)); done
  case "${M19_ADSP_AFTER:-}" in "$phase") echo running > "$M19_ROOT/sys/class/remoteproc/remoteproc0/state";; esac
  case "${M19_SOUND_AFTER:-}" in "$phase") mkdir -p "$M19_ROOT/sys/bus/platform/devices/soc:spf_core_platform:sound";; esac
  exit "$rc";;
esac
exit 2
'''

FAKE_MAPPER = '''#!/bin/sh
echo "$*" >> "$M19_TEST/mapper.log"
case "$1" in
 --check-maps) exit "${M19_MAPS_RC:-0}";;
 --serve)
  [ -n "${M19_NO_ENDPOINT:-}" ] || echo "1 7" > "$M19_ROOT/run/m11/pd.endpoint"
  [ -z "${M19_SERVE_EXIT:-}" ] || exit 0
  while [ -d "$M19_TEST" ] && [ ! -e "$M19_TEST/stop" ] && [ ! -e "$M19_ROOT/run/m11/pd.stop" ]; do sleep 0.05; done
  exit 0;;
 --probe) exit "${M19_PROBE_RC:-0}";;
esac
exit 2
'''

PHASES = (('audio', 32), ('machine', 9), ('haptics', 3), ('transport', 1))


def tree(root, test):
    """A root as the audio stage finds it after R1's bootstrap: 102 modules, the ADSP offline, both amplifiers on
    one adapter, super by PARTNAME, the device-mapper control, the list and the amplifier sample."""
    adsp = root / 'sys/devices/platform/soc/3000000.remoteproc-adsp'
    adsp.mkdir(parents=True)
    node = root / 'sys/class/remoteproc/remoteproc0'
    node.mkdir(parents=True)
    (node / 'device').symlink_to(adsp)
    (node / 'state').write_text('offline\n')
    other = root / 'sys/devices/platform/soc/8300000.remoteproc-cdsp'
    other.mkdir(parents=True)
    (root / 'sys/class/remoteproc/remoteproc1').mkdir()
    (root / 'sys/class/remoteproc/remoteproc1/device').symlink_to(other)
    (root / 'sys/bus/platform/devices/soc:qcom,pmic_glink').mkdir(parents=True)
    (root / 'proc').mkdir()
    (root / 'proc/modules').write_text(''.join(f'm{i} 4096 0 - Live 0x0\n' for i in range(102)))
    (root / 'proc/bootconfig').write_text('androidboot.mode = "normal"\nandroidboot.slot_suffix = "_a"\n')
    for name, partname, number in (('sda1', 'ssd', '8:1'), ('sda32', 'super', '259:32'), ('sde', None, '8:64')):
        block = root / 'sys/class/block' / name
        block.mkdir(parents=True)
        (block / 'uevent').write_text(f'MAJOR={number.split(":")[0]}\n' + (f'PARTNAME={partname}\n' if partname else ''))
        (block / 'dev').write_text(number + '\n')
    (root / 'sys/class/misc/device-mapper').mkdir(parents=True)
    (root / 'sys/class/misc/device-mapper/dev').write_text('10:236\n')
    driver = root / 'sys/bus/i2c/drivers/aw882xx_smartpa'
    driver.mkdir(parents=True)
    for address in ('0034', '0035'):
        client = root / f'sys/bus/i2c/devices/3-{address}'
        client.mkdir(parents=True)
        (client / 'driver').symlink_to(driver)
    (root / 'sys/bus/i2c/devices/0-004f').mkdir()
    (root / 'dev').mkdir()
    (root / 'run/m19').mkdir(parents=True)
    (root / 'm19/audio').mkdir(parents=True)
    shutil.copy(HERE / 'amps', root / 'm19/audio/amps')
    rows, dlkm = [], root / 'run/m19/audio/dlkm/lib/modules'
    dlkm.mkdir(parents=True)
    for phase, count in PHASES:
        for i in range(count):
            source = 'vendor_boot' if (phase == 'haptics' or i % 5 == 0) and len([r for r in rows if r[1] == 'vendor_boot']) < 8 else 'vendor_dlkm'
            rows.append((phase, source, f'{phase}{i}.ko'))
    while len([r for r in rows if r[1] == 'vendor_dlkm']) > 37:
        index = next(i for i, r in enumerate(rows) if r[1] == 'vendor_dlkm')
        rows[index] = (rows[index][0], 'vendor_boot', rows[index][2])
    lines = []
    for phase, source, name in rows:
        data = f'{name}\n'.encode()
        if source == 'vendor_dlkm':
            (dlkm / name).write_bytes(data)
        lines.append(f'{phase} {source} {name} {len(data)} {hashlib.sha256(data).hexdigest()}\n')
    (root / 'm19/audio/modules.list').write_text(''.join(lines))
    return rows


class Stage(unittest.TestCase):
    def setUp(self):
        prev_test = getattr(self, 'test', None)
        if prev_test is not None and prev_test.exists():
            (prev_test / 'stop').write_text('')
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name) / 'root'
        self.test = Path(self.directory.name) / 'test'
        self.test.mkdir()
        test = self.test
        self.addCleanup(lambda: (test / 'stop').write_text('') if test.exists() else None)
        for name, text in (('bb', FAKE_BB), ('helper', FAKE_HELPER), ('mapper', FAKE_MAPPER)):
            (self.test / name).write_text(text)
            (self.test / name).chmod(0o755)
        self.rows = tree(self.root, self.test)

    def run_stage(self, **env):
        environment = {**os.environ, 'M19_ROOT': str(self.root), 'M19_BB': str(self.test / 'bb'), 'M19_TEST': str(self.test),
                       'M19_AUDIO': str(self.test / 'helper'), 'M19_MAPPER': str(self.test / 'mapper'), 'M19_AUDIO_WAIT': '20', **env}
        return subprocess.run(['sh', str(HERE / 'audio-stage')], stdin=subprocess.DEVNULL, capture_output=True, text=True, env=environment, timeout=120)

    def log(self, name):
        path = self.test / name
        return path.read_text() if path.exists() else ''

    def result(self):
        path = self.root / 'run/m19/audio.result'
        return path.read_text() if path.exists() else None

    def count(self):
        return len((self.root / 'proc/modules').read_text().splitlines())

    def calls(self):
        return [line.split()[0] + (' ' + line.split()[2] if line.startswith('load') else '') for line in self.log('helper.log').splitlines()]

    def assertClean(self):
        for name in ('m19-audio-control', 'm19-audio-super', 'm19-audio-dlkm'):
            self.assertFalse((self.root / 'dev' / name).exists(), name)

    def assertSkipped(self, reason, loads=(), **env):
        result = self.run_stage(**env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.result(), f'skipped {reason}\n', result.stderr)
        self.assertEqual(self.count(), 102)
        self.assertEqual([call for call in self.calls() if call.startswith('load')], list(loads))
        self.assertNotIn('--serve', self.log('mapper.log'))
        self.assertClean()
        self.assertFalse((self.root / 'run/m19/audio/modules').exists() and any((self.root / 'run/m19/audio/modules').iterdir()))
        return result

    def assertPartial(self, reason, calls, **env):
        result = self.run_stage(**env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.result(), f'partial {reason}\n', result.stderr)
        self.assertEqual([call for call in self.calls() if call.startswith('load')], calls)
        self.assertClean()
        return result

    def assertHeld(self, reason, **env):
        result = self.run_stage(**env)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(f'M19 audio: HOLD {reason}\n', result.stderr)
        self.assertIsNone(self.result())
        self.assertNotIn('--serve', self.log('mapper.log'))
        return result

    def test_ready_keeps_run12s_order(self):
        result = self.run_stage()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.result(), 'ready\n')
        self.assertEqual(self.count(), 147)
        self.assertEqual(self.calls(), ['map', 'unmap', 'check', 'load audio', 'load machine', 'load haptics', 'load transport'])
        helper = self.log('helper.log').splitlines()
        self.assertEqual(helper[0], f'map {self.root}/dev/m19-audio-control {self.root}/dev/m19-audio-super 259:32 vendor_dlkm_a 0 m19-vendor-dlkm')
        self.assertEqual(helper[1], f'unmap {self.root}/dev/m19-audio-control m19-vendor-dlkm')
        work = f'{self.root}/run/m19/audio'
        self.assertEqual(helper[2], f'check {self.root}/m19/audio/modules.list {work}/modules {self.root}/lib/modules')
        self.assertEqual(helper[3], f'load {self.root}/m19/audio/modules.list audio {work}/modules {self.root}/lib/modules')
        bb = self.log('bb.log')
        self.assertEqual(re.findall(r'^mknod -m (\d+) (\S+) (\w) (\d+) (\d+)$', bb, re.M),
                         [('400', f'{self.root}/dev/m19-audio-super', 'b', '259', '32'), ('600', f'{self.root}/dev/m19-audio-control', 'c', '10', '236'),
                          ('400', f'{self.root}/dev/m19-audio-dlkm', 'b', '253', '7')])
        self.assertEqual(re.findall(r'^(?:mount|umount) .*$', bb, re.M),
                         [f'mount -t erofs -o ro,nosuid,nodev,noexec {self.root}/dev/m19-audio-dlkm {work}/dlkm', f'umount {work}/dlkm'])
        self.assertIn(f'blockdev --getro {self.root}/dev/m19-audio-dlkm', bb)
        # The mapping is gone before the check, and the check before the first load.
        self.assertLess(bb.index('umount'), bb.index('rm -f'))
        self.assertClean()
        self.assertFalse((self.root / f'run/m19/audio/modules').exists())
        self.assertEqual(self.log('mapper.log').splitlines(), ['--check-maps', '--check-maps', '--serve', '--probe'])
        pid = int((self.root / 'run/m11/pd.pid').read_text())
        os.kill(pid, 0)
        for text in ('M19 audio: vendor_dlkm_a read-only: 37 modules copied, unmapped\n', 'M19 audio: phase audio count=134\n',
                     'M19 audio: phase machine count=143\n', 'M19 audio: amps state=both clients=1:1 bound=1:1 adapters=3:3 stable=5\n',
                     'M19 audio: phase haptics count=146\n', 'M19 audio: phase transport count=147\n', f'M19 audio: mapper pid={pid} serving; count=147\n',
                     'M19 audio: result ready\n'):
            self.assertIn(text, result.stderr)

    def test_the_other_slot(self):
        (self.root / 'proc/bootconfig').write_text('androidboot.slot_suffix = "_b"\n')
        result = self.run_stage()
        self.assertEqual(self.result(), 'ready\n', result.stderr)
        self.assertIn(' vendor_dlkm_b 1 m19-vendor-dlkm', self.log('helper.log'))

    def test_before_any_load_a_fault_skips_and_cleans_up(self):
        cases = (
            ('list', lambda: (self.root / 'm19/audio/modules.list').unlink(), {}),
            ('list rows 44 37', lambda: (self.root / 'm19/audio/modules.list').write_text(
                ''.join((self.root / 'm19/audio/modules.list').read_text().splitlines(True)[1:])), {}),
            ('list source audio1.ko', lambda: (self.root / 'm19/audio/modules.list').write_text(
                (self.root / 'm19/audio/modules.list').read_text().replace('audio1.ko', 'audio1.ko').replace(' vendor_dlkm audio1.ko', ' vendor audio1.ko')), {}),
            ('list name ../x.ko', lambda: (self.root / 'm19/audio/modules.list').write_text(
                (self.root / 'm19/audio/modules.list').read_text().replace(' audio1.ko ', ' ../x.ko ')), {}),
            ('amps-missing', lambda: (self.root / 'm19/audio/amps').unlink(), {}),
            ('mapper-maps', lambda: None, {'M19_MAPS_RC': '3'}),
            ('slot []', lambda: (self.root / 'proc/bootconfig').write_text('androidboot.mode = "normal"\n'), {}),
            ('slot []', lambda: (self.root / 'proc/bootconfig').write_text('androidboot.slot_suffix = "_c"\n'), {}),
            ('super-missing', lambda: (self.root / 'sys/class/block/sda32/uevent').write_text('PARTNAME=superx\n'), {}),
            ('duplicate-super', lambda: (self.root / 'sys/class/block/sda1/uevent').write_text('PARTNAME=super\n'), {}),
            ('super-number', lambda: (self.root / 'sys/class/block/sda32/dev').write_text('259\n'), {}),
            ('control-number', lambda: shutil.rmtree(self.root / 'sys/class/misc'), {}),
            ('nodes-exist', lambda: (self.root / 'dev/m19-audio-dlkm').write_text(''), {}),
            ('map rc=2', lambda: None, {'M19_MAP_RC': '2'}),
            ('map rc=1', lambda: None, {'M19_MAP_RC': '1'}),
            ('map device [253]', lambda: None, {'M19_MAP_OUT': '253'}),
            ('map device []', lambda: None, {'M19_MAP_OUT': ''}),
            ('dlkm-writable', lambda: None, {'M19_GETRO': '0'}),
            ('dlkm-mount', lambda: None, {'M19_FAIL': 'mount'}),
            ('missing audio1.ko', lambda: (self.root / 'run/m19/audio/dlkm/lib/modules/audio1.ko').unlink(), {}),
            ('copy audio1.ko', lambda: None, {'M19_FAIL': 'cp'}),
            ('check', lambda: None, {'M19_CHECK_RC': '2'}),
            ('load audio rc=2', lambda: None, {'M19_LOAD_FAIL': 'audio:2:0'}))
        for reason, change, env in cases:
            with self.subTest(reason=reason, env=env):
                self.setUp()
                change()
                self.assertSkipped(reason, ['load audio'] if reason.startswith('load') else [], **env)
                calls = self.calls()
                if reason in ('map rc=1', 'map device [253]', 'map device []', 'dlkm-writable', 'dlkm-mount', 'missing audio1.ko', 'copy audio1.ko'):
                    self.assertEqual(calls[-1], 'unmap', reason)
                if reason == 'map rc=2':
                    self.assertNotIn('unmap', calls)
                if reason in ('dlkm-mount',):
                    self.assertNotIn('umount', self.log('bb.log'))
                if reason in ('missing audio1.ko', 'copy audio1.ko'):
                    self.assertIn('umount', self.log('bb.log'))

    def test_a_cleanup_that_fails_still_skips(self):
        result = self.run_stage(M19_FAIL='umount')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.result(), 'skipped cleanup cleanup\n')
        self.assertEqual(self.count(), 102)
        self.assertNotIn('check', self.calls())
        self.setUp()
        result = self.run_stage(M19_UNMAP_RC='1')
        self.assertEqual(self.result(), 'skipped cleanup cleanup\n', result.stderr)

    def test_after_loading_begins_a_fault_stops_without_the_mapper(self):
        self.assertPartial('load audio rc=1 count=112', ['load audio'], M19_LOAD_FAIL='audio:1:10')
        self.setUp()
        self.assertPartial('load machine rc=1 count=134', ['load audio', 'load machine'], M19_LOAD_FAIL='machine:1:0')
        self.setUp()
        self.assertPartial('count audio 133', ['load audio'], M19_LOAD_SHORT='audio')
        self.setUp()
        self.assertPartial('count transport 146', ['load audio', 'load machine', 'load haptics', 'load transport'], M19_LOAD_SHORT='transport')
        self.assertNotIn('--serve', self.log('mapper.log'))

    def test_the_amplifier_gate(self):
        for state, change in (('neither', lambda: [(self.root / f'sys/bus/i2c/devices/3-{a}/driver').unlink() for a in ('0034', '0035')]),
                              ('only34', lambda: (self.root / 'sys/bus/i2c/devices/3-0035/driver').unlink()),
                              ('only35', lambda: (self.root / 'sys/bus/i2c/devices/3-0034/driver').unlink()),
                              ('unknown', lambda: (self.root / 'sys/bus/i2c/devices/4-0035').mkdir()),
                              ('unknown', lambda: os.rename(self.root / 'sys/bus/i2c/devices/3-0035', self.root / 'sys/bus/i2c/devices/4-0035')),
                              ('unknown', lambda: ((self.root / 'sys/bus/i2c/devices/3-0035/driver').unlink(),
                                                   (self.root / 'sys/bus/i2c/drivers/other').mkdir(),
                                                   (self.root / 'sys/bus/i2c/devices/3-0035/driver').symlink_to(self.root / 'sys/bus/i2c/drivers/other')))):
            with self.subTest(state=state):
                self.setUp()
                change()
                self.assertPartial(f'amps {state} stable=0', ['load audio', 'load machine'])
                self.assertEqual(self.count(), 143)
                self.assertNotIn('--serve', self.log('mapper.log'))

    def test_the_mapper(self):
        self.assertPartial('mapper probe rc=3', ['load audio', 'load machine', 'load haptics', 'load transport'], M19_PROBE_RC='3')
        # No mapper is left serving: Run12's stop request ended it.
        self.assertEqual((self.root / 'run/m11/pd.stop').read_text(), '1\n')
        self.assertFalse((self.root / 'run/m11/pd.pid').exists())
        self.setUp()
        self.assertPartial('mapper-endpoint', ['load audio', 'load machine', 'load haptics', 'load transport'], M19_NO_ENDPOINT='1')
        self.assertTrue((self.root / 'run/m11/pd.stop').exists())
        self.setUp()
        self.assertPartial('mapper-exited', ['load audio', 'load machine', 'load haptics', 'load transport'], M19_NO_ENDPOINT='1', M19_SERVE_EXIT='1')
        self.setUp()
        (self.root / 'run/m11').mkdir()
        (self.root / 'run/m11/pd.done').write_text('1\n')
        self.assertPartial('mapper-state', ['load audio', 'load machine', 'load haptics', 'load transport'])
        self.assertNotIn('--serve', self.log('mapper.log'))

    def test_the_invariants_hold(self):
        self.setUp()
        (self.root / 'sys/class/remoteproc/remoteproc0/state').write_text('running\n')
        self.assertHeld('ADSP not offline: start')
        self.assertEqual(self.calls(), [])
        self.setUp()
        (self.root / 'sys/bus/platform/devices/soc:spf_core_platform:sound').mkdir()
        self.assertHeld('sound exists: start')
        self.setUp()
        (self.root / 'proc/modules').write_text('m 1 0 - Live 0x0\n' * 101)
        self.assertHeld('module count 101')
        self.setUp()
        (self.root / 'run/m19/audio.result').write_text('ready\n')
        result = self.run_stage()
        self.assertEqual(result.returncode, 1)
        self.assertIn('M19 audio: HOLD result-exists\n', result.stderr)
        self.setUp()
        shutil.rmtree(self.root / 'sys/class/remoteproc')
        self.assertHeld('missing-adsp')
        self.setUp()
        self.assertHeld('ADSP not offline: audio', M19_ADSP_AFTER='audio')
        self.assertEqual(self.calls()[-1], 'load audio')
        self.setUp()
        self.assertHeld('sound exists: machine', M19_SOUND_AFTER='machine')
        self.assertEqual(self.calls()[-1], 'load machine')
        self.setUp()
        self.assertHeld('ADSP not offline: transport', M19_ADSP_AFTER='transport')
        self.setUp()
        result = self.run_stage(M19_ROOT='relative')
        self.assertEqual(result.returncode, 1)

    def test_scripts_parse_and_write_nothing_but_ram(self):
        for name in ('audio-stage', 't3-audio', 't9-audio', 'amps', 'bootstrap-audio'):
            self.assertEqual(subprocess.run(['sh', '-n', str(HERE / name)]).returncode, 0, name)
        text = (HERE / 'audio-stage').read_text()
        code = '\n'.join(line for line in text.splitlines() if not line.lstrip().startswith('#'))
        self.assertNotRegex(code, r'\b(reboot|poweroff|mkfs|fsck|blkdiscard|fstrim|setrw|insmod|rmmod|modprobe|dd|losetup)\b|\bof=/dev|--setrw')
        # Every redirect into a file goes to RAM: the result, the mapper's log and pid, or the kernel log.
        targets = sorted(set(re.findall(r'>>?"([^"]+)"', code)))
        self.assertEqual(targets, ['$R/dev/kmsg', '$R/run/m11/pd.log', '$R/run/m11/pd.pid', '$R/run/m11/pd.stop', '$R/run/m19/audio.result'])
        self.assertEqual(re.findall(r'\$BB mount [^\n|]*', code), ['$BB mount -t erofs -o ro,nosuid,nodev,noexec "$dlkm_node" "$work/dlkm" '])
        self.assertNotIn('/sys/module/firmware_class', code)
        self.assertEqual((HERE / 'bootstrap-audio').read_text().splitlines()[-2:], ['/m19/bootstrap || exit 1', 'exec /m19/audio-stage'])


class Observer(unittest.TestCase):
    """T3-audio: Run12's registration criteria, read-only, before anything touches the TEE."""
    CARDS = ' 0 [ukeemtpsndcard ]: ukee-mtp-snd-c - ukee-mtp-snd-card\n                      ukee-mtp-snd-card\n'
    PCM = '00-00: MultiMedia1 (*) :  : playback 1 : capture 1\n00-01: MultiMedia2 (*) :  : playback 1\n'

    def setUp(self):
        prev_mapper = getattr(self, 'mapper', None)
        if prev_mapper is not None:
            self.reap(prev_mapper)
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name) / 'root'
        self.test = Path(self.directory.name) / 'test'
        self.test.mkdir()
        (self.test / 'bb').write_text(FAKE_BB)
        (self.test / 'bb').chmod(0o755)
        tree(self.root, self.test)
        (self.root / 'sys/class/remoteproc/remoteproc0/state').write_text('running\n')
        (self.root / 'run/m19/audio.result').write_text('ready\n')
        (self.root / 'run/m19/adsp.owner').write_text('/sys/class/remoteproc/remoteproc0\n')
        self.mapper = subprocess.Popen(['sleep', '60'], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(self.reap, self.mapper)
        (self.root / 'run/m11').mkdir(parents=True)
        (self.root / 'run/m11/pd.pid').write_text(f'{self.mapper.pid}\n')
        (self.root / 'proc/asound').mkdir()
        (self.root / 'proc/asound/cards').write_text(self.CARDS)
        (self.root / 'proc/asound/pcm').write_text(self.PCM)
        (self.root / 'sys/class/sound/controlC0').mkdir(parents=True)
        (self.root / 'sys/class/sound/controlC0/dev').write_text('116:0\n')

    @staticmethod
    def reap(process):
        if process.poll() is None:
            process.kill()
            process.wait()

    def run_step(self, **env):
        environment = {**os.environ, 'M19_ROOT': str(self.root), 'M19_BB': str(self.test / 'bb'), 'M19_TEST': str(self.test), 'M19_AUDIO_WAIT': '20', **env}
        return subprocess.run(['sh', str(HERE / 't3-audio')], stdin=subprocess.DEVNULL, capture_output=True, text=True, env=environment, timeout=60)

    def assertFails(self, reason):
        result = self.run_step()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(f'M19 T3 audio failed: {reason}\n', result.stderr)
        return result

    def test_the_registered_card_passes(self):
        result = self.run_step()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('M19 T3 audio: stage ready\n', result.stderr)
        self.assertIn('stable=5\n', result.stderr)
        self.assertIn(f'M19 T3 audio: card=0 control=116:0 amps=both adsp=running mapper={self.mapper.pid} registered\n', result.stderr)
        self.assertIn('M19 T3 audio: cards\n' + self.CARDS, result.stderr)
        self.assertIn('M19 T3 audio: pcm\n' + self.PCM, result.stderr)
        # Read-only: the fake busybox saw no write of any kind.
        self.assertNotRegex(self.log(), r'(?m)^(mknod|mount|umount|cp|rm|mkdir|chmod|blockdev) ')

    def log(self):
        path = self.test / 'bb.log'
        return path.read_text() if path.exists() else ''

    def test_the_stage_must_be_ready(self):
        (self.root / 'run/m19/audio.result').write_text('partial amps neither stable=0\n')
        self.assertFails('stage partial amps neither stable=0')
        (self.root / 'run/m19/audio.result').unlink()
        self.assertFails('no-stage-result')

    def test_each_criterion_fails(self):
        cases = (
            ('adsp owner /sys/class/remoteproc/x', lambda: (self.root / 'run/m19/adsp.owner').write_text('/sys/class/remoteproc/x\n')),
            ('adsp-owner', lambda: (self.root / 'run/m19/adsp.owner').unlink()),
            ('mapper-pid', lambda: (self.root / 'run/m11/pd.pid').write_text('x\n')),
            ('mapper-exited', lambda: self.reap(self.mapper)),
            ('not stable: card=[] valid=0 amps=both adsp=running', lambda: (self.root / 'proc/asound/cards').write_text('--- no soundcards ---\n')),
            ('not stable: card=[0] valid=0 amps=both adsp=running', lambda: (self.root / 'proc/asound/pcm').write_text('00-00: x : : playback 1\n')),
            ('not stable: card=[0] valid=0 amps=both adsp=running', lambda: (self.root / 'sys/class/sound/controlC0/dev').write_text('0:1\n')),
            ('not stable: card=[0] valid=0 amps=both adsp=running', lambda: (self.root / 'sys/class/sound/controlC0/dev').write_text('116\n')),
            ('not stable: card=[0] valid=1 amps=only34 adsp=running', lambda: (self.root / 'sys/bus/i2c/devices/3-0035/driver').unlink()),
            ('not stable: card=[0] valid=1 amps=both adsp=offline', lambda: (self.root / 'sys/class/remoteproc/remoteproc0/state').write_text('offline\n')),
            ('amps-missing', lambda: (self.root / 'm19/audio/amps').unlink()))
        for reason, change in cases:
            with self.subTest(reason=reason):
                self.setUp()
                change()
                self.assertFails(reason)

    def test_the_step_writes_nothing(self):
        text = (HERE / 't3-audio').read_text()
        code = '\n'.join(line for line in text.splitlines() if not line.lstrip().startswith('#'))
        self.assertNotRegex(code, r'\$BB (mknod|mount|umount|cp|rm|mkdir|chmod|blockdev)\b|>"|>>"|\btee\b|/dev/snd')


class AudioPrep(unittest.TestCase):
    """T9-audio: udev ALSA persistent rule mask in RAM /etc, /dev cleanliness, and verified Run31 plan staging."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name) / 'root'
        self.test = Path(self.directory.name) / 'test'
        self.test.mkdir()
        (self.test / 'bb').write_text(FAKE_BB)
        (self.test / 'bb').chmod(0o755)
        (self.root / 'run/m19').mkdir(parents=True)
        (self.root / 'run/m19/audio.result').write_text('ready\n')
        (self.root / 'newroot/run/m19').mkdir(parents=True)
        (self.root / 'newroot/etc/udev/rules.d').mkdir(parents=True)
        (self.root / 'newroot/dev').mkdir(parents=True)
        (self.root / 'm19/r5').mkdir(parents=True)
        (self.root / 'm19/r5/udev-masks').write_text('# persistent ALSA symlinks\n\n60-persistent-alsa.rules\n')
        (self.root / 'm19/m19-speaker').write_bytes(b'\x7fELF-m19-speaker')
        (self.root / 'm19/speaker').mkdir(parents=True)
        self.plan_bytes = b'M11SPK01' + bytes(range(128))
        self.plan_sha = hashlib.sha256(self.plan_bytes).hexdigest()
        (self.root / 'm19/speaker/plan.bin').write_bytes(self.plan_bytes)
        (self.root / 'm19/speaker/plan.sha256').write_text(f'{self.plan_sha}  plan.bin\n')

    def run_step(self, **env):
        environment = {**os.environ, 'M19_ROOT': str(self.root), 'M19_BB': str(self.test / 'bb'), 'M19_TEST': str(self.test), **env}
        return subprocess.run(['sh', str(HERE / 't9-audio')], stdin=subprocess.DEVNULL, capture_output=True, text=True, env=environment, timeout=60)

    def assertFails(self, reason, **env):
        result = self.run_step(**env)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(f'M19 T9 audio failed: {reason}\n', result.stderr)
        return result

    def test_masks_udev_rule_and_copies_verified_speaker_bundle(self):
        existing = self.root / 'newroot/etc/udev/rules.d/60-persistent-alsa.rules'
        existing.write_text('ACTION=="add", SUBSYSTEM=="sound"\n')
        result = self.run_step()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f'M19 T9 audio: udev_masks=1 plan_sha256={self.plan_sha}\n', result.stderr)
        self.assertTrue(existing.is_symlink())
        self.assertEqual(os.readlink(existing), '/dev/null')
        spk = self.root / 'newroot/run/m19/m19-speaker'
        spk_dir = self.root / 'newroot/run/m19/speaker'
        plan = spk_dir / 'plan.bin'
        sha_file = spk_dir / 'plan.sha256'
        self.assertEqual(spk.read_bytes(), b'\x7fELF-m19-speaker')
        self.assertEqual(spk.stat().st_mode & 0o777, 0o755)
        self.assertEqual(spk_dir.stat().st_mode & 0o777, 0o700)
        self.assertEqual(plan.read_bytes(), self.plan_bytes)
        self.assertEqual(plan.stat().st_mode & 0o777, 0o600)
        self.assertEqual(sha_file.stat().st_mode & 0o777, 0o600)

    def test_every_precondition_and_integrity_fault_fails(self):
        self.assertFails('root', M19_ROOT='relative')
        self.assertFails('plan-rehash', M19_FAIL='corrupt-plan-cp')
        cases = (
            ('no-stage-result', lambda: (self.root / 'run/m19/audio.result').unlink()),
            ('audio-stage', lambda: (self.root / 'run/m19/audio.result').write_text('partial amps\n')),
            ('newroot', lambda: shutil.rmtree(self.root / 'newroot/dev')),
            ('dev dirty snd', lambda: (self.root / 'newroot/dev/snd').symlink_to('/missing')),
            ('dev dirty m11-snd', lambda: (self.root / 'newroot/dev/m11-snd').mkdir()),
            ('dev dirty m11-heap', lambda: (self.root / 'newroot/dev/m11-heap').mkdir()),
            ('dev dirty aud_pasthru_adsp', lambda: (self.root / 'newroot/dev/aud_pasthru_adsp').write_text('')),
            ('dev dirty msm_audio_ion', lambda: (self.root / 'newroot/dev/msm_audio_ion').write_text('')),
            ('dev dirty msm_audio_ion_cma', lambda: (self.root / 'newroot/dev/msm_audio_ion_cma').write_text('')),
            ('udev-link', lambda: (shutil.rmtree(self.root / 'newroot/etc/udev'),
                                   (self.root / 'newroot/etc/udev').symlink_to('/tmp'))),
            ('udev-masks', lambda: (self.root / 'm19/r5/udev-masks').unlink()),
            ('udev mask count 0', lambda: (self.root / 'm19/r5/udev-masks').write_text('# none\n')),
            ('udev rule ../60.rules', lambda: (self.root / 'm19/r5/udev-masks').write_text('../60.rules\n')),
            ('udev rule .hidden.rules', lambda: (self.root / 'm19/r5/udev-masks').write_text('.hidden.rules\n')),
            ('udev rule badname', lambda: (self.root / 'm19/r5/udev-masks').write_text('badname\n')),
            ('udev rule directory 60-persistent-alsa.rules',
             lambda: (self.root / 'newroot/etc/udev/rules.d/60-persistent-alsa.rules').mkdir()),
            ('speaker-binary', lambda: (self.root / 'm19/m19-speaker').unlink()),
            ('speaker-plan', lambda: (self.root / 'm19/speaker/plan.bin').write_bytes(b'')),
            ('speaker-sha', lambda: (self.root / 'm19/speaker/plan.sha256').write_text(self.plan_sha.upper() + '\n')),
            (f'speaker plan hash {self.plan_sha} != ' + '0' * 64,
             lambda: (self.root / 'm19/speaker/plan.sha256').write_text('0' * 64 + '  plan.bin\n')),
            ('speaker-exists', lambda: (self.root / 'newroot/run/m19/m19-speaker').write_text('')),
            ('speaker-dir-exists', lambda: (self.root / 'newroot/run/m19/speaker').mkdir()),
        )
        for reason, change in cases:
            with self.subTest(reason=reason):
                self.setUp()
                change()
                self.assertFails(reason)

    def test_the_step_touches_only_ram_etc_and_run(self):
        text = (HERE / 't9-audio').read_text()
        code = '\n'.join(line for line in text.splitlines() if not line.lstrip().startswith('#'))
        self.assertNotRegex(code, r'\b(reboot|poweroff|mkfs|fsck|blkdiscard|fstrim|setrw|insmod|rmmod|modprobe|dd|losetup|mount|umount|mknod)\b|/data')
        self.assertEqual(re.findall(r'>>?"([^"]+)"', code), [])


class Speaker(unittest.TestCase):
    """m19-speaker (test-speaker.c): recursive /dev/snd scanner, prechecks, and Run31 speaker session."""

    def setUp(self):
        self.assertIsNotNone(ARGS.speaker_driver, '--speaker-driver required for Speaker tests')
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def run_speaker(self, *args, as_root=False):
        env = {**os.environ, 'ASAN_OPTIONS': 'detect_leaks=0'}
        cmd = [ARGS.speaker_driver, *map(str, args)]
        if as_root and os.geteuid() != 0:
            check = subprocess.run(['sudo', '-n', 'true'], stdin=subprocess.DEVNULL, capture_output=True)
            if check.returncode != 0:
                if os.environ.get('CI'):
                    self.fail('sudo -n required on CI for Speaker root session tests')
                self.skipTest('sudo -n unavailable')
            cmd = ['sudo', '-n', 'timeout', '--kill-after=5', '90', *cmd]
            root = str(self.root)
            self.addCleanup(lambda: subprocess.run(['sudo', '-n', 'rm', '-rf', root], stdin=subprocess.DEVNULL, capture_output=True))
        if as_root and fcntl is not None:
            lock_fd = os.open('/tmp/m19-speaker-root.lock', os.O_CREAT | os.O_RDWR, 0o666)
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX)
                return subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True, env=env, timeout=180)
            finally:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                finally:
                    os.close(lock_fd)
        return subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True, env=env, timeout=180)

    def scan(self, path):
        res = self.run_speaker('scan-snd', path)
        self.assertEqual(res.returncode, 0, res.stderr)
        return int(res.stdout.strip())

    def test_1_scan_snd(self):
        self.assertEqual(self.scan(self.root / 'absent'), 0)
        snd = self.root / 'snd'
        snd.mkdir()
        self.assertEqual(self.scan(snd), 0)
        bypath = snd / 'by-path'
        bypath.mkdir()
        (bypath / 'platform-sound').symlink_to('../controlC0')
        self.assertEqual(self.scan(snd), 0)

        live_target = self.root / 'target'
        live_target.write_text('x')
        (bypath / 'live').symlink_to(live_target)
        self.assertEqual(self.scan(snd), 1)
        (bypath / 'live').unlink()
        self.assertEqual(self.scan(snd), 0)

        (snd / 'pcmC0D32p').write_text('')
        self.assertEqual(self.scan(snd), 1)
        (snd / 'controlC0').write_text('')
        self.assertEqual(self.scan(snd), 3)
        (snd / 'controlC0').unlink()
        self.assertEqual(self.scan(snd), 1)

        top_file = self.root / 'top-file'
        top_file.write_text('')
        self.assertEqual(self.scan(top_file), 1)

        top_dangling = self.root / 'top-dangling'
        top_dangling.symlink_to(self.root / 'nowhere')
        self.assertEqual(self.scan(top_dangling), 1)

        deep = self.root / 'deep'
        cur = deep
        for i in range(10):
            cur = cur / f'd{i}'
        cur.mkdir(parents=True)
        self.assertGreaterEqual(self.scan(deep), 1)

    def test_2_prechecks(self):
        res = self.run_speaker('prechecks', self.root)
        self.assertEqual(res.returncode, 0, res.stderr + res.stdout)
        self.assertIn('PASS m19-speaker prechecks\n', res.stdout)

    def test_3_root_session(self):
        if ARGS.no_root_speaker:
            return
        res = self.run_speaker('session', self.root, as_root=True)
        self.assertEqual(res.returncode, 0, res.stderr + res.stdout)
        self.assertIn('PASS m19-speaker root session\n', res.stdout)


def main():
    global ARGS
    parser = argparse.ArgumentParser()
    parser.add_argument('--driver', required=True)
    parser.add_argument('--speaker-driver')
    parser.add_argument('--no-root-speaker', action='store_true')
    ARGS, rest = parser.parse_known_args()
    ARGS.driver = str(Path(ARGS.driver).resolve())
    if ARGS.speaker_driver:
        ARGS.speaker_driver = str(Path(ARGS.speaker_driver).resolve())
    unittest.main(argv=[sys.argv[0], *rest], verbosity=2)


if __name__ == '__main__':
    main()
