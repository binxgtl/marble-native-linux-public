#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail
out=${1:?output directory};mkdir -p "$out"
python3 scripts/m15/o3/verify-legacy.py | tee "$out/o3-legacy.txt"
for variant in normal sanitize; do
 flags=(-std=c11 -O2 -Wall -Wextra -Werror)
 if [[ $variant == sanitize ]]; then flags+=(-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -fno-pie -no-pie); fi
 gcc "${flags[@]}" scripts/m15/o3/observe.c -o "$out/observe-o3-$variant"
 gcc "${flags[@]}" scripts/m15/o3/observe.c scripts/m15/phaseb/test-faults.c -Wl,--wrap=open -Wl,--wrap=read -Wl,--wrap=__read_chk -o "$out/fault-o3-$variant"
 python3 scripts/m15/o3/test.py "$out/observe-o3-$variant" "$out/fault-o3-$variant" -v 2>&1 | tee "$out/o3-$variant.txt"
done
