#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail
out=${1:?output}
# Explicit capability gate. Failure is BLOCKED, never a skipped PID1 PASS.
sudo unshare --mount --pid --fork --mount-proc true
for variant in normal sanitize; do
 flags=(-std=c11 -O2 -Wall -Wextra -Werror)
 if [[ $variant == sanitize ]]; then flags+=(-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -fno-pie -no-pie); fi
 gcc "${flags[@]}" scripts/m15/native4/pid1.c -o "$out/pid1-$variant"
 gcc "${flags[@]}" scripts/m15/native1/escrow.c scripts/m15/native1/supervise.c scripts/m15/native4/custodian.c -o "$out/native4-custodian-$variant"
 for mode in 0 1 2 3 4 5 6 7; do
  # Namespace teardown may prevent LSan from tracing PID1; ASan/UBSan remain on.
  sudo env ASAN_OPTIONS=detect_leaks=0 timeout 15s unshare --mount --pid --fork --mount-proc "$out/pid1-$variant" --namespace-fixture "$mode"
 done | tee "$out/native4-pid1-$variant.txt"
 sudo env ASAN_OPTIONS=detect_leaks=0 timeout 30s unshare --mount --pid --fork --mount-proc python3 scripts/m15/native4/test-pid1-integration.py "$out/native4-custodian-$variant" "$out/m15-observe-o3-a" "$out/native1-normal/native1-synthetic.wire" | tee "$out/native4-integration-$variant.txt"
done
