#!/usr/bin/env bash
set -euo pipefail
out=${1:?output}
for variant in normal sanitize; do
  flags=(-std=c11 -O2 -Wall -Wextra -Werror)
  if [[ $variant == sanitize ]]; then flags+=(-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -fno-pie -no-pie); fi
  gcc "${flags[@]}" scripts/m15/native1/escrow.c scripts/m15/native1/supervise.c scripts/m15/native3/custodian.c -o "$out/native3-$variant"
  python3 scripts/m15/native3/test.py --custodian "$out/native3-$variant" --observer "$out/m15-observe-o3-a" --wire "$out/native1-normal/native1-synthetic.wire" -v 2>&1 | tee "$out/native3-$variant.txt"
done
