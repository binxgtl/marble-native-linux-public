#!/usr/bin/env bash
set -euo pipefail
out=${1:?out}; mkdir -p "$out"
[[ $(gcc -dumpmachine) == aarch64* ]]
for v in a b; do
 gcc -std=c11 -O2 -ffunction-sections -fdata-sections -Wall -Wextra -Werror -static -no-pie -Wl,--build-id=none,--gc-sections -DM12_RUN5_EMBEDDED scripts/m12/run11/runner.c scripts/m12/run5/fs-ready.c scripts/m12/run5/readiness.c scripts/m12/run5/cbc-evidence.c scripts/m12/next/caldb.c scripts/m12/run10/owner-supervisor.c -o "$out/m12-run11-$v"
 gcc -std=c11 -O2 -Wall -Wextra -Werror -static -no-pie -Wl,--build-id=none scripts/m12/run11/network.c -o "$out/m12-network-$v"
done
for n in m12-run11 m12-network; do cmp "$out/$n-a" "$out/$n-b"; readelf -h -l "$out/$n-a" > "$out/$n-elf.txt"; ! grep -q INTERP "$out/$n-elf.txt"; done
gcc --version > "$out/compiler.txt"
