#!/usr/bin/env bash
set -euo pipefail
out=${1:?output}; mkdir -p "$out"
src=scripts/m19/run2
hash=scripts/m19/unlock/hash.c
wraps=-Wl,--wrap=umount2,--wrap=mount,--wrap=chroot,--wrap=chdir,--wrap=execve,--wrap=stat
for variant in normal sanitize; do
  flags=(-std=c11 -O2 -Wall -Wextra -Werror)
  if [[ $variant == sanitize ]]; then
    flags+=(-O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer)
  fi
  gcc "${flags[@]}" "$hash" "$src/wire.c" "$src/handoff.c" "$src/report.c" "$src/test-r2.c" "$wraps" -o "$out/test-r2-$variant"
  python3 "$src/test.py" --driver "$out/test-r2-$variant" 2>&1 | tee "$out/run-$variant.txt"
done
python3 "$src/mutate.py" | tee "$out/mutants.txt"
# Reviewable binaries only, never a boot image. Independent outputs must match.
for copy in a b; do
  flags=(-std=c11 -Os -Wall -Wextra -Werror -static -Wl,--build-id=none)
  gcc "${flags[@]}" "$hash" scripts/m19/run1/r1.c "$src/wire.c" "$src/handoff.c" "$src/report.c" "$src/pid2.c" -o "$out/pid2-$copy"
done
cmp "$out/pid2-a" "$out/pid2-b"
sha256sum "$out/pid2-a" | tee "$out/run2-binaries.txt"
