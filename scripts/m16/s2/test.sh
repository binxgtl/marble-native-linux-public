#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail
out=${1:?output}; mkdir -p "$out"
src=scripts/m16/s2
core=("$src/journal.c" "$src/oracle.c" "$src/machine.c" "$src/mark.c")
for variant in normal sanitize; do
  flags=(-std=c11 -O2 -Wall -Wextra -Werror)
  if [[ $variant == sanitize ]]; then
    flags+=(-O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer)
  fi
  dir="$out/$variant"; mkdir -p "$dir"
  gcc "${flags[@]}" "${core[@]}" "$src/test-journal.c" -o "$dir/test-journal"
  gcc "${flags[@]}" "$src/linux.c" "$src/test-linux.c" -o "$dir/test-linux"
  gcc "${flags[@]}" "$src/mark.c" "$src/test-mark.c" -o "$dir/test-mark"
  gcc "${flags[@]}" "${core[@]}" "$src/test-machine.c" -o "$dir/test-machine"
  gcc "${flags[@]}" "${core[@]}" "$src/linux.c" "$src/driver.c" -o "$dir/driver"
  "$dir/test-journal" | tee "$dir/journal.txt"
  "$dir/test-linux" | tee "$dir/linux.txt"
  "$dir/test-mark" | tee "$dir/mark.txt"
  "$dir/test-machine" "$dir" | tee "$dir/machine.txt"
  python3 "$src/test.py" --driver "$dir/driver" --out "$dir" 2>&1 | tee "$dir/host.txt"
done
# Same synthetic cycle, same bytes, with and without sanitizers.
cmp "$out/normal/pass.wire" "$out/sanitize/pass.wire"
cmp "$out/normal/refused.wire" "$out/sanitize/refused.wire"
sha256sum "$out/normal/pass.wire" "$out/normal/refused.wire" > "$out/wire-sha256.txt"
python3 "$src/host.py" "$out/normal/pass.wire" > "$out/pass-report.json"
python3 "$src/verify-delta.py" > "$out/closure-delta.txt"
python3 "$src/mutate.py" --out "$out/mutants.json" | tee "$out/mutants.txt"
