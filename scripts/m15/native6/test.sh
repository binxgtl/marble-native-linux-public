#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail
out=$1
mkdir -p "$out/native6"
python3 scripts/m15/native6/derive.py "$out/native6"
chmod +x scripts/m15/native6/fake-display.py
for variant in normal sanitize; do
 flags=(-std=c11 -O2 -Wall -Wextra -Werror)
 if [ "$variant" = sanitize ]; then flags+=(-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -fno-pie -no-pie); fi
 cc "${flags[@]}" scripts/m15/native6/pid1.c scripts/m15/native5/ownership.c -o "$out/native6/pid1-$variant"
 cc "${flags[@]}" -DM15_SMOKE_DEADLINE=10000 scripts/m15/native6/pid1.c scripts/m15/native5/ownership.c -o "$out/native6/pid1-fixture-$variant"
 cc "${flags[@]}" -I scripts/m15/native1 "$out/native6/custodian.c" scripts/m15/native1/escrow.c scripts/m15/native1/supervise.c -o "$out/native6/custodian-$variant"
 cc "${flags[@]}" -I scripts -I scripts/m15/native6 "$out/native6/display-kms.c" scripts/m15/native6/display-main.c scripts/m15/native6/display-loop.c -o "$out/native6/display-$variant"
 cc "${flags[@]}" scripts/m15/native6/test-display.c scripts/m15/native6/display-loop.c -o "$out/native6/test-display-$variant"
 "$out/native6/test-display-$variant" | tee "$out/native6/display-$variant.txt"
 sudo env ASAN_OPTIONS=detect_leaks=0 python3 scripts/m15/native6/test-integration.py "$out/native6/pid1-fixture-$variant" "$out/native6/custodian-$variant" "$out/m15-observe-o3-a" "$out/native1-normal/native1-synthetic.wire" "$out/native6/$variant" | tee "$out/native6/integration-$variant.txt"
done
