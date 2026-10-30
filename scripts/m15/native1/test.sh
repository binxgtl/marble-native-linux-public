#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail
out=${1:?output}; mkdir -p "$out"
for variant in normal sanitize; do
  flags=(-std=c11 -O2 -Wall -Wextra -Werror)
  observer="$out/m15-observe-o3-a"
  if [[ $variant == sanitize ]]; then
    flags+=(-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -fno-pie -no-pie)
    observer="$out/observe-o3-sanitize"
  fi
  gcc "${flags[@]}" scripts/m15/native1/escrow.c scripts/m15/native1/supervise.c scripts/m15/native1/test-driver.c -o "$out/native1-test-$variant"
  gcc "${flags[@]}" scripts/m15/native1/escrow.c scripts/m15/native1/test-census.c -o "$out/native1-census-$variant"
  "$out/native1-census-$variant" | tee "$out/native1-census-$variant.txt"
  python3 scripts/m15/native1/test.py --driver "$out/native1-test-$variant" --observer "$observer" --out "$out/native1-$variant" -v 2>&1 | tee "$out/native1-$variant.txt"
done
cmp "$out/native1-normal/native1-synthetic.wire" "$out/native1-sanitize/native1-synthetic.wire"
sha256sum "$out/native1-normal/native1-synthetic.wire" > "$out/native1-wire-sha256.txt"
