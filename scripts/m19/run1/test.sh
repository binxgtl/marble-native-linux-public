#!/usr/bin/env bash
set -euo pipefail
out=${1:?output}; mkdir -p "$out"
src=scripts/m19/run1
hash=scripts/m19/unlock/hash.c
for variant in normal sanitize; do
  flags=(-std=c11 -O2 -Wall -Wextra -Werror)
  if [[ $variant == sanitize ]]; then
    flags+=(-O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer)
  fi
  gcc "${flags[@]}" "$hash" "$src/r1.c" "$src/test-r1.c" -o "$out/test-r1-$variant"
  python3 "$src/test.py" --driver "$out/test-r1-$variant" 2>&1 | tee "$out/run-$variant.txt"
done
python3 "$src/mutate.py" | tee "$out/mutants.txt"
# Reviewable binaries only, never a boot image. Independent outputs must match.
for copy in a b; do
  flags=(-std=c11 -Os -Wall -Wextra -Werror -static -Wl,--build-id=none)
  gcc "${flags[@]}" "$hash" "$src/r1.c" "$src/pid1.c" -o "$out/pid1-$copy"
  gcc "${flags[@]}" "$src/load-heaps.c" -o "$out/load-heaps-$copy"
done
for name in pid1 load-heaps; do
  cmp "$out/$name-a" "$out/$name-b"
  sha256sum "$out/$name-a"
done | tee "$out/run1-binaries.txt"
