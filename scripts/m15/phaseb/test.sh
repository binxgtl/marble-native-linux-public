#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail
out=${1:?output directory}; mkdir -p "$out"
python3 scripts/m15/phaseb/verify-compatibility.py | tee "$out/compatibility.txt"
for variant in normal sanitize; do
 flags=(-std=c11 -O2 -Wall -Wextra -Werror)
 if [[ $variant == sanitize ]]; then flags+=(-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -fno-pie -no-pie); fi
 gcc "${flags[@]}" scripts/m15/phaseb/observe.c -o "$out/observe-o2-$variant"
 gcc "${flags[@]}" scripts/m15/phaseb/observe.c scripts/m15/phaseb/test-faults.c -Wl,--wrap=open -Wl,--wrap=read -Wl,--wrap=__read_chk -o "$out/fault-o2-$variant"
 python3 scripts/m15/phaseb/test.py "$out/observe-o2-$variant" "$out/fault-o2-$variant" -v 2>&1 | tee "$out/phaseb-$variant.txt"
done
