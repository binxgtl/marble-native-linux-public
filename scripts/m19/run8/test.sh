#!/usr/bin/env bash
# R8's read-write steps (T2-unlock, T5-mount, T8-writes, T9-root, T9-desktop, T9-ce) on synthetic trees with a fake busybox,
# then, unless M19_MUTANTS=0, their mutants. No device, no real mount.
set -euo pipefail
out=${1:?output}; mkdir -p "$out"
python3 scripts/m19/run8/test.py 2>&1 | tee "$out/run8-tests.txt"
if [[ ${M19_MUTANTS:-1} == 1 ]]; then
  python3 scripts/m19/run8/mutate.py | tee "$out/run8-mutants.txt"
fi
