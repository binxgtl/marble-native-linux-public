#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail
out=${1:?output directory}; mkdir -p "$out"
for variant in normal sanitize; do
 flags=(-std=c11 -O2 -Wall -Wextra -Werror)
 if [[ $variant == sanitize ]]; then flags+=(-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -fno-pie -no-pie); fi
 gcc "${flags[@]}" scripts/m15/observe.c -o "$out/observe-$variant"
 gcc "${flags[@]}" scripts/m15/observe.c scripts/m15/test-faults.c -Wl,--wrap=read -Wl,--wrap=write -o "$out/fault-$variant"
 python3 scripts/m15/test.py "$out/observe-$variant" --fault-binary "$out/fault-$variant" -v 2>&1 | tee "$out/tests-$variant.txt"
done
