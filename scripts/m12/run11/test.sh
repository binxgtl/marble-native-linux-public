#!/usr/bin/env bash
set -euo pipefail
out=${1:?out};mkdir -p "$out"
python3 scripts/m12/run11/test-evidence.py | tee "$out/evidence.txt"
for variant in normal sanitize; do
 flags=(-std=c11 -O2 -Wall -Wextra -Werror)
 if [[ $variant == sanitize ]]; then flags+=(-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer); fi
 gcc "${flags[@]}" scripts/m12/run11/test-network-main.c -o "$out/main-$variant"
 timeout 30s "$out/main-$variant" | tee "$out/main-$variant.txt"
 gcc "${flags[@]}" '-DWDIR="m12/wpa"' scripts/m12/run11/test-disconnect.c -o "$out/disconnect-$variant"
 timeout 15s "$out/disconnect-$variant" | tee "$out/disconnect-$variant.txt"
 gcc "${flags[@]}" -ffunction-sections -fdata-sections -Wl,--gc-sections -DM12_RUN5_EMBEDDED scripts/m12/run11/test-result-parser.c scripts/m12/run5/fs-ready.c scripts/m12/run5/readiness.c scripts/m12/run5/cbc-evidence.c scripts/m12/next/caldb.c scripts/m12/run10/owner-supervisor.c -o "$out/parser-$variant"
 "$out/parser-$variant" | tee "$out/parser-$variant.txt"
 # Frozen Run9 network, parser, supplicant and control regressions remain exact.
 for test in network network-main supplicant config frozen-control control; do
  gcc "${flags[@]}" "scripts/m12/run9/test-$test.c" -o "$out/historical-$test-$variant"
  if [[ $test == config ]]; then python3 scripts/m12/run9/test-contract.py "$out/historical-$test-$variant" | tee "$out/config-$variant.txt"; else timeout 90s "$out/historical-$test-$variant" | tee "$out/historical-$test-$variant.txt"; fi
 done
 gcc "${flags[@]}" scripts/m12/run10/test-owner.c scripts/m12/run10/owner-supervisor.c -o "$out/owner-$variant"
 timeout 30s "$out/owner-$variant" | tee "$out/owner-$variant.txt"
done
