"""B3: cmdline_summary.py (off-device) must produce exactly the B6 record body that the entry writes
(m11_entry_cmdline_summary in C) over a fixed corpus of gate edge cases and a seeded random corpus.
Usage: test-cmdline-summary.py <driver binary>. Synthetic data only."""
import random
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cmdline_summary as cs  # noqa: E402

FIXED = [
    b'', b' ', b'console=ttyMSM0 iommu.strict=1 rdinit=/init\n', b'iommu.strict=0', b'iommu.strict=1',
    b'iommu.strict', b'iommu.strict=', b'"iommu.strict=0"', b'iommu.strict="0"', b'iommu.strict="1"',
    b'a iommu.strict=1 iommu.strict=0', b'iommu.passthrough=1', b'iommu.passthrough=0', b'iommu.passthrough',
    b'iommu-strict=0', b'iommu.strict=1\tiommu.passthrough=0', b'iommu.strict=1\xa0iommu.strict=0',
    b'x "', b'"', b'x="a b" iommu.strict=0', b'"x=a iommu.strict=0', b'=iommu.strict=0', b'iommu.strict==1',
    b'-- iommu.strict=0', b'iommu.strict=1 -- iommu.passthrough=1', b'iommu.strict=1\x0biommu.strict=0',
    b'iommu.strict=\xc3\xa91', b'iommu.strict=1234567890123456789', b'androidboot.hardware=qcom iommu.strict=1',
    b'a' * 4095, b'iommu.strict=1 ' * 200,
]
ALPHABET = b'iommu.strict=passthrough01"\t\n\xa0 -_xa'


def corpus():
    rnd = random.Random(20261019)
    out = list(FIXED)
    for _ in range(4000):
        n = rnd.randrange(0, 60)
        parts = [rnd.choice([b'iommu.strict', b'iommu.passthrough', b'iommu-passthrough', b'=', b'"', b' ', b'\t',
                             b'0', b'1', b'\xa0', b'x']) if rnd.random() < 0.5 else bytes([rnd.choice(ALPHABET)])
                 for _ in range(n)]
        out.append(b''.join(parts)[:4095])
    return out


def main(argv):
    cases = corpus()
    feed = ''.join(c.hex() + '\n' for c in cases).encode()
    got = subprocess.run([argv[0]], input=feed, stdout=subprocess.PIPE, check=True).stdout.decode().splitlines()
    assert len(got) == len(cases), (len(got), len(cases))
    bad = [(c, g, cs.summary(c)) for c, g in zip(cases, got) if g != cs.summary(c)]
    for c, g, w in bad[:5]:
        print(f'MISMATCH {c!r}\n  C:      {g}\n  Python: {w}')
    assert not bad, f'{len(bad)} mismatches'
    allowed = sum(1 for g in got if g.startswith('allowed=1'))
    print(f'PASS B3 cmdline summary: Python == C (m11_entry_cmdline_summary) on {len(cases)} inputs '
          f'({len(FIXED)} fixed gate edge cases, {allowed} allowed)')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
