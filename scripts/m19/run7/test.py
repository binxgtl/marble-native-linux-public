#!/usr/bin/env python3
"""m19-ce-prompt in a real X server (Xvfb), tapped through XTEST, against a fake broker socket. No PIN of the
owner's: the fake broker accepts one synthetic code."""
import argparse
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

    def session(self, keys, reply=b'M19_CE status=OK detail=0 version=3 timeout=0', broker=True):
        fake = FakeBroker(self.socket, reply) if broker else None
        if fake:
            fake.start()
        prompt = subprocess.Popen([ARGS.prompt, str(self.socket), str(self.result)])
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

    def test_no_broker(self):
        code, messages, result = self.session('4829U', broker=False)
        self.assertEqual(result, 'M19_CE status=NO_BROKER\n')
        self.assertEqual(code, 1)


def main():
    global ARGS
    parser = argparse.ArgumentParser()
    parser.add_argument('--prompt', required=True)
    parser.add_argument('--xclick', required=True)
    ARGS, rest = parser.parse_known_args()
    unittest.main(argv=['test.py', *rest], verbosity=1)


if __name__ == '__main__':
    main()
