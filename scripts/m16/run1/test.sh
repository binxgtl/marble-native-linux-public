#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail
out=${1:?output}; mkdir -p "$out"
src=scripts/m16/run1
s2=scripts/m16/s2
core=("$s2/journal.c" "$s2/oracle.c" "$s2/machine.c" "$s2/mark.c" "$s2/linux.c")
sh -n "$src/init"
sh -n "$src/bootstrap"
sh -n "$src/adsp"
for variant in normal sanitize; do
  flags=(-std=c11 -O2 -Wall -Wextra -Werror)
  if [[ $variant == sanitize ]]; then
    flags+=(-O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer)
  fi
  gcc "${flags[@]}" "${core[@]}" "$src/run.c" "$src/test-run.c" -o "$out/test-run-$variant"
  ASAN_OPTIONS=detect_leaks=0 python3 "$src/test.py" --driver "$out/test-run-$variant" 2>&1 | tee "$out/run-$variant.txt"
done
python3 "$src/mutate.py" --out "$out/mutants.json" | tee "$out/mutants.txt"
# Reviewable binaries only, never a boot image. Independent output names must match.
for copy in a b; do
  flags=(-std=c11 -O2 -Wall -Wextra -Werror -static -Wl,--build-id=none)
  gcc "${flags[@]}" "${core[@]}" "$src/run.c" "$src/pid1.c" -o "$out/pid1-$copy"
  gcc "${flags[@]}" -I scripts "$src/display.c" scripts/m9-kms.c -o "$out/display-$copy"
  gcc "${flags[@]}" "$src/load-rtc.c" -o "$out/load-rtc-$copy"
done
for name in pid1 display load-rtc; do
  cmp "$out/$name-a" "$out/$name-b"
  sha256sum "$out/$name-a"
done | tee "$out/static-binaries.txt"
