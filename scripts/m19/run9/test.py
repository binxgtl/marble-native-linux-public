#!/usr/bin/env python3
"""R9's kernel release patch on synthetic Images: every copy of the release but vermagic loses -dirty, nothing else
moves, and anything unexpected refuses (docs/m19-r9.md). No device, and never the carrier Image."""
import importlib.util
import io
import random
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('kernel_release', HERE / 'kernel-release.py')
kr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kr)

RELEASE = b'5.10.236-gb97c62c4e7d1-dirty'
BANNER = (b'Linux version 5.10.236-gb97c62c4e7d1-dirty (marble-ci@github-actions) (Android (7284624, based on r416183b) clang '
          b'version 12.0.5, LLD 12.0.5) #1 SMP PREEMPT 1970-01-01 00:00:00 UTC\n')
VERMAGIC = b'5.10.236-gb97c62c4e7d1-dirty SMP preempt mod_unload modversions aarch64'
STRINGS = (b'/lib/firmware/' + RELEASE, b'/lib/firmware/updates/' + RELEASE, RELEASE, BANNER, VERMAGIC, RELEASE)


def image(strings=STRINGS, seed=9, tail=b'\0'):
    """Filler without the release, each string NUL-terminated between, as in the carrier's .rodata and .data."""
    rng = random.Random(seed)
    out = bytearray()
    for text in strings:
        out += bytes(rng.randrange(1, 256) for _ in range(rng.randrange(40, 400))) + b'\0'
        out += text + tail + b'\0' * rng.randrange(0, 40)
    out += bytes(rng.randrange(1, 256) for _ in range(300))
    return bytes(out)


class Patch(unittest.TestCase):
    def test_every_copy_but_vermagic_is_clean_and_nothing_else_moves(self):
        data = image()
        out, changed = kr.patch(data)
        self.assertEqual(len(out), len(data))
        self.assertEqual([kind for kind, _, _ in changed], ['firmware', 'firmware', 'release', 'banner', 'release'])
        self.assertEqual(out.count(RELEASE), 1)
        self.assertEqual(out.count(VERMAGIC + b'\0'), 1)
        self.assertEqual(out.count(b'-dirty'), 1)
        for text in (b'/lib/firmware/5.10.236-gb97c62c4e7d1\0\0\0\0\0\0\0', b'/lib/firmware/updates/5.10.236-gb97c62c4e7d1\0\0\0\0\0\0\0'):
            self.assertEqual(out.count(text), 1, text)
        self.assertEqual(out.count(b'\x005.10.236-gb97c62c4e7d1\0\0\0\0\0\0\0'), 2)
        banner = BANNER.replace(b'-dirty', b'')
        self.assertEqual(out.count(b'\0' + banner + b'\0' * 7), 1)
        # The banner keeps its place: it starts where it did, and its array ends where it did.
        start = data.index(BANNER)
        self.assertEqual(out[start:start + len(BANNER) + 1], banner + b'\0' * 7)
        differ = [i for i in range(len(data)) if out[i] != data[i]]
        self.assertTrue(differ)
        self.assertTrue(all(any(start <= i < end for _, start, end in changed) for i in differ))
        # Each string's own bytes before the release are untouched.
        for kind, start, end in changed:
            self.assertEqual(out[start:end].rstrip(b'\0'), data[start:end].replace(b'-dirty', b''), kind)

    def test_twice_is_refused(self):
        out, _ = kr.patch(image())
        with self.assertRaisesRegex(ValueError, 'release strings'):
            kr.patch(out)

    def test_anything_unexpected_refuses(self):
        cases = {
            'a copy missing': (STRINGS[:5], 'release strings'),
            'a third bare copy': (STRINGS + (RELEASE,), 'release strings'),
            'a second banner': (STRINGS + (BANNER,), 'release strings'),
            'an unknown string': (STRINGS + (b'version ' + RELEASE,), 'unknown string'),
            'another firmware path': (STRINGS[1:] + (b'/vendor/firmware/' + RELEASE,), 'unknown string'),
            'a banner without its newline': (STRINGS[:3] + (BANNER[:-1],) + STRINGS[4:], 'unknown string'),
            'a banner with the release twice': (STRINGS[:3] + (BANNER + RELEASE + b'\n',) + STRINGS[4:], 'unknown string'),
            'vermagic of another kind': (STRINGS[:4] + (RELEASE + b' SMP preempt mod_unload aarch64',) + STRINGS[5:], 'unknown string'),
            'a release run on': (STRINGS[:2] + (RELEASE + b'x',) + STRINGS[3:], 'unknown string'),
        }
        for name, (strings, message) in cases.items():
            with self.subTest(case=name):
                with self.assertRaisesRegex(ValueError, message):
                    kr.patch(image(strings))
        with self.assertRaisesRegex(ValueError, 'has no NUL'):
            kr.patch(image() + RELEASE)


class Main(unittest.TestCase):
    def test_only_the_pinned_carrier_is_patched(self):
        self.assertEqual(kr.PINNED_IN, '17ca7970f2cccccc537fc6ea2bfb1cbd5a5e05d2512e7f8315343b66f89febc1')
        self.assertEqual(kr.IN_BYTES, 38604684)
        self.assertEqual(kr.PINNED_OUT, '9dc5e431d1fbe7efc5c7f1dedef60fe7ee664e6819b3a2887fc17c2f59a07c32')
        with tempfile.TemporaryDirectory() as directory:
            source, out = Path(directory, 'Image'), Path(directory, 'Image-r9')
            source.write_bytes(image())
            with self.assertRaisesRegex(SystemExit, 'not the pinned carrier'):
                kr.main([str(source), str(out)])
            self.assertFalse(out.exists())
            # The pins checked, the synthetic Image goes through as the carrier would, and the output pin refuses it.
            saved = kr.PINNED_IN, kr.IN_BYTES
            try:
                kr.PINNED_IN, kr.IN_BYTES = kr.sha(source.read_bytes()), len(source.read_bytes())
                with self.assertRaisesRegex(SystemExit, 'not the pinned R9 Image'):
                    kr.main([str(source), str(out)])
                self.assertFalse(out.exists())
                with self.assertRaisesRegex(SystemExit, 'must not be the input'):
                    kr.main([str(source), str(source)])
                pinned_out, kr.PINNED_OUT = kr.PINNED_OUT, kr.sha(kr.patch(source.read_bytes())[0])
                try:
                    with redirect_stdout(io.StringIO()) as printed:
                        self.assertEqual(kr.main([str(source), str(out)]), 0)
                finally:
                    kr.PINNED_OUT = pinned_out
                self.assertEqual(out.read_bytes(), kr.patch(source.read_bytes())[0])
                self.assertIn(f'bytes={len(source.read_bytes())} sha256={kr.sha(out.read_bytes())}\n', printed.getvalue())
                self.assertIn('banner ', printed.getvalue())
                self.assertNotIn('-dirty', printed.getvalue())
            finally:
                kr.PINNED_IN, kr.IN_BYTES = saved


if __name__ == '__main__':
    sys.exit(0 if unittest.main(argv=[sys.argv[0], '-v'], exit=False).result.wasSuccessful() else 1)
