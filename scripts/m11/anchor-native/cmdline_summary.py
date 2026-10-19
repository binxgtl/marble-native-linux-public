"""B3 (docs/m11-argon-hw-readiness-review.md): the B6 cmdline record body, computed off-device.

  cmdline_summary.py <file|->     one line: allowed=%d len=%d strict=%s passthrough=%s crc32=%08x

Byte-faithful to m11_entry_cmdline_summary() in custodian_entry_native.c, whose gate is
m11_custodian_cmdline_allowed() (pinned ACK lib/cmdline.c next_arg() and kernel/params.c
parameqn() semantics); test-cmdline-summary.py checks the two agree on a fixed and a random corpus.

Operator use (B3 option A, read-only): capture the stock Android /proc/cmdline into a local,
gitignored file and summarise it here. The text holds device identifiers, so never commit or export the
capture, and treat the crc32 field as local evidence too (it is invertible over one short unknown
field). Only the verdict and the two token values may go into docs."""
import sys
import zlib

MAX = 4096
SPACES = (32, 9, 10)


def kspace(c):
    return 9 <= c <= 13 or c == 32 or c == 160


def cstr(buf, i):
    j = buf.index(0, i)
    return bytes(buf[i:j])


def skip(buf, k):
    while kspace(buf[k]):
        k += 1
    return k


def next_arg(buf, a):
    equals, in_quote, quoted = 0, False, False
    if buf[a] == 0x22:
        a += 1
        in_quote = quoted = True
    i = 0
    while buf[a + i]:
        c = buf[a + i]
        if kspace(c) and not in_quote:
            break
        if equals == 0 and c == 0x3D:
            equals = i
        if c == 0x22:
            in_quote = not in_quote
        i += 1
    param, val = a, None
    if equals:
        buf[a + equals] = 0
        val = a + equals + 1
        if buf[val] == 0x22:
            val += 1
            if buf[a + i - 1] == 0x22:
                buf[a + i - 1] = 0
    if quoted and i > 0 and buf[a + i - 1] == 0x22:
        buf[a + i - 1] = 0
    if buf[a + i]:
        buf[a + i] = 0
        nxt = a + i + 1
    else:
        nxt = a + i
    return skip(buf, nxt), param, val


def parameq(buf, a, name):
    dash = lambda c: 0x5F if c == 0x2D else c
    want = name + b'\0'
    for k, w in enumerate(want):
        if dash(buf[a + k]) != dash(w):
            return False
    return True


def gate(text):
    if len(text) >= MAX:
        return False
    buf = bytearray(text) + b'\0\0'
    a = skip(buf, 0)
    while buf[a]:
        if buf[a] == 0x22 and buf[a + 1] == 0:
            return False
        a, param, val = next_arg(buf, a)
        if parameq(buf, param, b'iommu.strict'):
            if val is None or cstr(buf, val) != b'1':
                return False
        elif parameq(buf, param, b'iommu.passthrough'):
            if val is None or cstr(buf, val) != b'0':
                return False
    return True


def token_value(text, key):
    out, p, n = 'absent', 0, len(text)
    while p < n:
        while p < n and text[p] in SPACES:
            p += 1
        s = p
        while p < n and text[p] not in SPACES:
            p += 1
        if p - s >= len(key) and text[s:s + len(key)] == key:
            v = text[s + len(key):p][:15]
            ok = lambda c: 48 <= c <= 57 or 97 <= c <= 122 or 65 <= c <= 90 or c in b'.-_'
            out = ''.join(chr(c) if ok(c) else '?' for c in v) or 'empty'
    return out


def summary(raw):
    text = raw.split(b'\0', 1)[0]
    return (f'allowed={int(gate(text))} len={len(text)} strict={token_value(text, b"iommu.strict=")} '
            f'passthrough={token_value(text, b"iommu.passthrough=")} crc32={zlib.crc32(text) & 0xffffffff:08x}')


def main(argv):
    if len(argv) != 1:
        print(__doc__)
        return 2
    raw = sys.stdin.buffer.read() if argv[0] == '-' else open(argv[0], 'rb').read()
    print(summary(raw[:MAX - 1]))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
