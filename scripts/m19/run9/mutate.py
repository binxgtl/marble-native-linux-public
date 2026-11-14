#!/usr/bin/env python3
"""Mutation check for R9's kernel release patch: every mutant of scripts/m19/run9/kernel-release.py must fail run9/test.py."""
import concurrent.futures
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent

MUTANTS = (
    # The kinds: each copy recognised whole, and only those.
    ('kernel-release.py', "KINDS = {'release': 2, 'firmware': 2, 'banner': 1, 'vermagic': 1}", "KINDS = {'release': 3, 'firmware': 2, 'banner': 1}"),
    ('kernel-release.py', "    if any(text == path + RELEASE for path in FIRMWARE):", "    if any(text.endswith(RELEASE) for path in FIRMWARE):"),
    ('kernel-release.py', "and text.endswith(b'\\n') and text.count(RELEASE) == 1:", "and text.count(RELEASE) == 1:"),
    ('kernel-release.py', "and text.endswith(b'\\n') and text.count(RELEASE) == 1:", "and text.endswith(b'\\n'):"),
    ('kernel-release.py', "    if text == RELEASE + VERMAGIC:", "    if text.startswith(RELEASE + b' '):"),
    ('kernel-release.py', "            raise ValueError(f'release at {at:#x} has no NUL')", "            end = len(data)"),
    ('kernel-release.py', "    if counts != collections.Counter(KINDS):", "    if not counts:"),
    # The patch: vermagic kept, the banner moved, the others cut, nothing else touched.
    ('kernel-release.py', "        if kind == 'vermagic':\n            continue\n", ''),
    ('kernel-release.py', "            out[cut:end] = data[cut + len(DIRTY):end] + b'\\0' * len(DIRTY)", "            out[cut:cut + len(DIRTY)] = b'\\0' * len(DIRTY)"),
    ('kernel-release.py', "            out[cut:cut + len(DIRTY)] = b'\\0' * len(DIRTY)\n            assert", "            out[cut:cut + len(DIRTY)] = b' ' * len(DIRTY)\n            assert"),
    # The pins and the refusals around them.
    ('kernel-release.py', "    if len(data) != IN_BYTES or sha(data) != PINNED_IN:", "    if sha(data) == '':"),
    ('kernel-release.py', "    if PINNED_OUT is not None and sha(out) != PINNED_OUT:", "    if False:"),
    ('kernel-release.py', "    if args.out.resolve() == args.image.resolve():", "    if False:"),
    ('kernel-release.py', "PINNED_OUT = '9dc5e431d1fbe7efc5c7f1dedef60fe7ee664e6819b3a2887fc17c2f59a07c32'", "PINNED_OUT = None"),
    ('kernel-release.py', "    args.out.write_bytes(out)\n", "    args.out.write_bytes(data)\n"),
)


def run(number, name, old, new):
    with tempfile.TemporaryDirectory() as directory:
        target = Path(directory) / 'run9'
        shutil.copytree(HERE, target, ignore=shutil.ignore_patterns('__pycache__'))
        path = target / name
        text = path.read_text(encoding='utf-8')
        assert text.count(old) == 1, f'mutant {number} does not apply exactly once to {name}: {old!r}'
        path.write_text(text.replace(old, new), encoding='utf-8', newline='\n')
        try:
            result = subprocess.run([sys.executable, str(target / 'test.py')], stdin=subprocess.DEVNULL, capture_output=True, timeout=300,
                                    start_new_session=True)
            return result.returncode != 0
        except subprocess.TimeoutExpired:
            return True


def main():
    check = subprocess.run([sys.executable, str(HERE / 'test.py')], stdin=subprocess.DEVNULL, capture_output=True, timeout=300)
    if check.returncode:
        print(check.stdout.decode('utf-8', 'replace') + check.stderr.decode('utf-8', 'replace'))
        raise SystemExit('the unmutated tests fail')
    survivors = []
    with concurrent.futures.ThreadPoolExecutor(max(1, min(4, os.cpu_count() or 1))) as pool:
        futures = {pool.submit(run, number, name, old, new): (number, name, old) for number, (name, old, new) in enumerate(MUTANTS, 1)}
        for future in concurrent.futures.as_completed(futures):
            number, name, old = futures[future]
            if not future.result():
                survivors.append((number, name, old))
    for number, name, old in sorted(survivors):
        print(f'SURVIVED {number} {name}: {old!r}')
    print(f'R9 mutants killed: {len(MUTANTS) - len(survivors)} of {len(MUTANTS)}')
    return 1 if survivors else 0


if __name__ == '__main__':
    sys.exit(main())
