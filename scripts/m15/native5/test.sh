#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail
out=$1
mkdir -p "$out/native5"
python3 scripts/m15/native5/test-provenance.py -v 2>&1 | tee "$out/native5-provenance.txt"
for variant in normal sanitize; do
  flags=(-std=c11 -Wall -Wextra -Werror -O1 -g)
  if [ "$variant" = sanitize ]; then flags+=(-fsanitize=address,undefined -fno-omit-frame-pointer -fno-pie -no-pie); fi
  cc "${flags[@]}" scripts/m15/native5/coordinator.c scripts/m15/native5/ownership.c scripts/m15/native5/test-coordinator.c -o "$out/native5/coordinator-$variant"
  "$out/native5/coordinator-$variant" | tee "$out/native5-coordinator-$variant.txt"
  cc "${flags[@]}" scripts/m15/native5/io.c scripts/m15/native5/test-io.c -o "$out/native5/io-$variant"
  "$out/native5/io-$variant" | tee "$out/native5-io-$variant.txt"
  cc "${flags[@]}" scripts/m15/native5/coordinator.c scripts/m15/native5/ownership.c scripts/m15/native5/pid1.c -o "$out/native5/pid1-$variant"
done
# External namespace termination is TEST cleanup, not native recovery policy.
set +e
sudo timeout --signal=KILL 1s unshare --mount --pid --fork --mount-proc "$out/native5/pid1-normal" --namespace-hold-test > "$out/native5-hold.txt" 2>&1
rc=$?
set -e
test "$rc" = 137
grep -q 'PERSISTENT_HOLD no_release no_reboot' "$out/native5-hold.txt"
