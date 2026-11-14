#!/usr/bin/env python3
"""R9: the carrier kernel's release without the build's "-dirty" (docs/m19-r9.md). No phone command.

The carrier Image (M4's artifacts/m4/Image) was built from a tree with uncommitted changes, so its release reads
5.10.236-gb97c62c4e7d1-dirty in uname -r, /proc/version and the boot banner. Rebuilding the kernel would change far
more than the name, so this rewrites the name in the pinned Image's bytes, in place, and moves nothing else:
- the release in init_uts_ns, which uname -r, /proc/version and /proc/sys/kernel/osrelease read, and the standalone
  copy of the release: "-dirty" becomes NULs;
- the firmware loader's two versioned search paths, /lib/firmware/<release> and /lib/firmware/updates/<release>: the
  same. Nothing is staged in either;
- the boot banner, linux_banner ("Linux version ..."): the text after "-dirty" moves 6 bytes left, and NULs fill the
  array's end.
The sixth copy, the vermagic string modules are checked against, stays as built. With modversions only the part after
the release is compared, and none of the phone's modules was built with this release.
Each copy must be a whole NUL-terminated string of the kind listed, six in all; anything else refuses.
No other string starts inside a "-dirty" this zeroes: the linker merged identical strings in this Image but not tails
(it holds "%s\\n" once on its own, beside hundreds of strings ending in it, and "dirty" once on its own).
The SUSFS kernel in boot_a reports the same clean release; the carrier is told apart by its Image's hash.
"""
import argparse
import collections
import hashlib
import sys
from pathlib import Path

DIRTY = b'-dirty'
CLEAN = b'5.10.236-gb97c62c4e7d1'
RELEASE = CLEAN + DIRTY
FIRMWARE = (b'/lib/firmware/', b'/lib/firmware/updates/')
BANNER = b'Linux version '
VERMAGIC = b' SMP preempt mod_unload modversions aarch64'
KINDS = {'release': 2, 'firmware': 2, 'banner': 1, 'vermagic': 1}
# The carrier Image as M4 built it, and this script's output from it.
PINNED_IN = '17ca7970f2cccccc537fc6ea2bfb1cbd5a5e05d2512e7f8315343b66f89febc1'
PINNED_OUT = '9dc5e431d1fbe7efc5c7f1dedef60fe7ee664e6819b3a2887fc17c2f59a07c32'
IN_BYTES = 38604684


def sha(data):
    return hashlib.sha256(data).hexdigest()


def kind_of(text):
    """What a NUL-terminated string holding the release is, or None."""
    if text == RELEASE:
        return 'release'
    if any(text == path + RELEASE for path in FIRMWARE):
        return 'firmware'
    if text == RELEASE + VERMAGIC:
        return 'vermagic'
    if text.startswith(BANNER + RELEASE + b' (') and text.endswith(b'\n') and text.count(RELEASE) == 1:
        return 'banner'
    return None


def find(data):
    """Every string holding the release: (kind, start of the string, where the release is, its NUL)."""
    found, at = [], data.find(RELEASE)
    while at >= 0:
        start = data.rfind(b'\0', 0, at) + 1
        end = data.find(b'\0', at)
        if end < 0:
            raise ValueError(f'release at {at:#x} has no NUL')
        kind = kind_of(data[start:end])
        if kind is None:
            raise ValueError(f'release at {at:#x} in an unknown string of {end - start} bytes')
        found.append((kind, start, at, end))
        at = data.find(RELEASE, at + 1)
    counts = collections.Counter(kind for kind, _, _, _ in found)
    if counts != collections.Counter(KINDS):
        raise ValueError(f'release strings {dict(sorted(counts.items()))}, want {KINDS}')
    return found


def patch(data):
    """The Image with -dirty gone from every copy but vermagic; the same length, and only those strings' bytes changed."""
    out = bytearray(data)
    changed = []
    for kind, start, at, end in find(data):
        cut = at + len(CLEAN)
        if kind == 'vermagic':
            continue
        if kind == 'banner':
            out[cut:end] = data[cut + len(DIRTY):end] + b'\0' * len(DIRTY)
        else:
            out[cut:cut + len(DIRTY)] = b'\0' * len(DIRTY)
            assert cut + len(DIRTY) == end
        changed.append((kind, start, end))
    out = bytes(out)
    assert len(out) == len(data)
    assert out.count(RELEASE) == 1 and out.count(DIRTY) == data.count(DIRTY) - 5
    assert out.count(CLEAN + b'\0') == data.count(CLEAN + b'\0') + 4
    differ = [i for i in range(len(data)) if out[i] != data[i]] if len(data) < (1 << 20) else None
    if differ is not None:
        assert all(any(start <= i < end for _, start, end in changed) for i in differ)
    return out, changed


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    ap.add_argument('image', type=Path, help="M4's carrier Image")
    ap.add_argument('out', type=Path, help='where the patched Image goes; never the input')
    args = ap.parse_args(argv)
    data = args.image.read_bytes()
    if len(data) != IN_BYTES or sha(data) != PINNED_IN:
        raise SystemExit('the input is not the pinned carrier Image')
    if args.out.resolve() == args.image.resolve():
        raise SystemExit('the output must not be the input')
    out, changed = patch(data)
    # Outside the five strings, no byte changed: compare in blocks.
    lo = min(start for _, start, _ in changed)
    hi = max(end for _, _, end in changed)
    assert out[:lo] == data[:lo] and out[hi:] == data[hi:]
    for (_, _, end), (_, start, _) in zip(changed, changed[1:]):
        assert out[end:start] == data[end:start]
    if PINNED_OUT is not None and sha(out) != PINNED_OUT:
        raise SystemExit(f'the output is not the pinned R9 Image: {sha(out)}')
    args.out.write_bytes(out)
    for kind, start, end in changed:
        print(f'{kind} {start:#x} {out[start:end].rstrip(bytes(1))[:60].decode()}')
    print(f'bytes={len(out)} sha256={sha(out)}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
