#!/usr/bin/env python3
"""m19-ce-prompt in a real X server (Xvfb), tapped through XTEST, against a fake broker socket. No PIN of the
owner's: the fake broker accepts one synthetic code."""
import argparse
import re
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path

ARGS = None


class FakeBroker(threading.Thread):
    def __init__(self, path, reply):
        super().__init__(daemon=True)
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.server.bind(str(path))
        self.server.listen(1)
        self.server.settimeout(30)
        self.reply = reply
        self.messages = []

    def run(self):
        try:
            client, _ = self.server.accept()
            self.messages.append(client.recv(128))
            client.send(self.reply)
            client.close()
        except OSError:
            pass


HOLDER = r"""
import ctypes, sys, time
x = ctypes.CDLL('libX11.so.6')
x.XOpenDisplay.restype = ctypes.c_void_p
x.XDefaultRootWindow.argtypes = [ctypes.c_void_p]
x.XDefaultRootWindow.restype = ctypes.c_ulong
x.XGrabPointer.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_int, ctypes.c_uint, ctypes.c_int, ctypes.c_int, ctypes.c_ulong,
                           ctypes.c_ulong, ctypes.c_ulong]
x.XSync.argtypes = [ctypes.c_void_p, ctypes.c_int]
x.XCloseDisplay.argtypes = [ctypes.c_void_p]
display = x.XOpenDisplay(None)
print(x.XGrabPointer(display, x.XDefaultRootWindow(display), 1, 0, 1, 1, 0, 0, 0), flush=True)
x.XSync(display, 0)
time.sleep(float(sys.argv[1]))
x.XCloseDisplay(display)
"""


class Prompt(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.xvfb = subprocess.Popen(['Xvfb', ':57', '-screen', '0', '2400x1080x24', '-nolisten', 'tcp'], stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL)
        os.environ['DISPLAY'] = ':57'
        time.sleep(2)

    @classmethod
    def tearDownClass(cls):
        cls.xvfb.terminate()
        cls.xvfb.wait(timeout=10)

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.socket = self.root / 'ce.sock'
        self.result = self.root / 'ce.result'

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def session(self, keys, reply=b'M19_CE status=OK detail=0 version=3 timeout=0', broker=True, wait=0):
        fake = FakeBroker(self.socket, reply) if broker else None
        if fake:
            fake.start()
        prompt = subprocess.Popen([ARGS.prompt, str(self.socket), str(self.result)])
        time.sleep(wait)
        subprocess.run([ARGS.xclick, keys], check=True, timeout=60)
        code = prompt.wait(timeout=60)
        if fake:
            fake.join(timeout=10)
        return code, fake.messages if fake else [], self.result.read_text() if self.result.exists() else None

    def test_taps_send_one_pin_and_record_the_reply(self):
        code, messages, result = self.session('48291BU')
        self.assertEqual(messages, [b'PIN:4829'])
        self.assertEqual(result, 'M19_CE status=OK detail=0 version=3 timeout=0\n')
        self.assertEqual(code, 0)
        self.assertEqual(self.result.stat().st_mode & 0o777, 0o600)

    def test_a_refusal_is_recorded(self):
        code, messages, result = self.session('123456U', reply=b'M19_CE status=GK_REJECTED detail=-1 version=3 timeout=0')
        self.assertEqual(messages, [b'PIN:123456'])
        self.assertTrue(result.startswith('M19_CE status=GK_REJECTED'))
        self.assertEqual(code, 1)

    def test_cancel_sends_nothing(self):
        code, messages, result = self.session('12C')
        self.assertEqual(messages, [])
        self.assertEqual(result, 'M19_CE status=CANCELLED\n')

    def test_short_pins_are_not_sent(self):
        code, messages, result = self.session('123UC')
        self.assertEqual(messages, [])
        self.assertEqual(result, 'M19_CE status=CANCELLED\n')

    def test_a_pointer_held_longer_than_r7s_five_seconds_only_delays_the_keypad(self):
        # R8c: another client held the pointer when the keypad came up; R7's keypad gave up after five seconds.
        holder = subprocess.Popen(['python3', '-c', HOLDER, '7'], stdout=subprocess.PIPE, text=True)
        self.assertEqual(holder.stdout.readline().strip(), '0')
        code, messages, result = self.session('48291BU', wait=8)
        holder.wait(timeout=30)
        self.assertEqual(messages, [b'PIN:4829'])
        self.assertEqual(result, 'M19_CE status=OK detail=0 version=3 timeout=0\n')
        self.assertEqual(code, 0)

    def test_no_broker(self):
        code, messages, result = self.session('4829U', broker=False)
        self.assertEqual(result, 'M19_CE status=NO_BROKER\n')
        self.assertEqual(code, 1)


HERE = Path(__file__).resolve().parent


class Steps(unittest.TestCase):
    """T7-de and T9-ce as text: they need root and the phone, so their shape is what CI can hold them to."""

    def test_every_mount_is_a_read_only_bind(self):
        for name in ('t7-de', 't9-ce'):
            text = (HERE / name).read_text()
            self.assertTrue(text.startswith('#!/bin/busybox sh\nset -eu\n') or text.startswith('#!/bin/busybox sh\n#'), name)
            mounts = [line.strip() for line in text.splitlines() if ' mount ' in f' {line.strip()} ' and not line.strip().startswith('#')]
            self.assertTrue(mounts, name)
            for line in mounts:
                self.assertRegex(line, r'^\$BB mount -o (bind|remount,bind,ro) ', name)
            self.assertNotRegex(text, r'\brw\b|mknod|blockdev|dd |of=|rm -|umount|reboot|/data/misc/vold/user_keys/ce|setprop', name)
            self.assertIn('ro|ro,*) ;;', text, name)

    def test_t7_runs_the_de_step_only(self):
        text = (HERE / 't7-de').read_text()
        self.assertEqual(re.findall(r'/m19/m19-ce \w+', text), ['/m19/m19-ce de'])
        self.assertIn('"M19_CE_DE status=OK keys=2 "*" db=OK") exit 0;;', text)

    def test_t9_starts_the_broker_in_the_island_and_shows_media_read_only(self):
        text = (HERE / 't9-ce').read_text()
        self.assertEqual(re.findall(r'/m19/m19-ce \w+[^\n\\]*', text), ['/m19/m19-ce broker /m19-ce/ce.sock '])
        self.assertIn('$BB setsid $BB chroot "$R/tee" /m19/m19-ce broker', text)
        self.assertIn('$BB mount -o bind "$R/m19-data/media" "$new/run/m19/android"', text)
        self.assertIn('$BB mount -o remount,bind,ro "$new/run/m19/android"', text)
        self.assertIn('$BB mkdir -m 0700 "$dir"', text)
        self.assertNotIn('/data/media/0', text)


def main():
    global ARGS
    parser = argparse.ArgumentParser()
    parser.add_argument('--prompt', required=True)
    parser.add_argument('--xclick', required=True)
    ARGS, rest = parser.parse_known_args()
    unittest.main(argv=['test.py', *rest], verbosity=1)


if __name__ == '__main__':
    main()
