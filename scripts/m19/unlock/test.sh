#!/usr/bin/env bash
set -euo pipefail
out=${1:?output}; mkdir -p "$out"
src=scripts/m19/unlock
python3 -m pip install --quiet --break-system-packages lz4 >/dev/null 2>&1 || true
for variant in normal sanitize; do
  flags=(-std=c11 -O2 -Wall -Wextra -Werror)
  if [[ $variant == sanitize ]]; then
    flags+=(-O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer)
  fi
  gcc "${flags[@]}" "$src/core.c" "$src/hash.c" "$src/test-core.c" -o "$out/test-core-$variant"
  gcc "${flags[@]}" "$src/hash.c" "$src/rdx.c" -o "$out/rdx-$variant"
  gcc "${flags[@]}" -c "$src/dm.c" -o "$out/dm-$variant.o"
  "$out/test-core-$variant"
  python3 "$src/test-native.py" --rdx "$out/rdx-$variant" --core "$out/test-core-$variant"
done
python3 "$src/mutate.py" | tee "$out/mutants.txt"
# Reviewable binary only, never a boot image. Independent outputs must match.
for copy in a b; do
  gcc -std=c11 -O2 -Wall -Wextra -Werror -static -Wl,--build-id=none "$src/hash.c" "$src/rdx.c" -o "$out/m19-rdx-$copy"
done
cmp "$out/m19-rdx-a" "$out/m19-rdx-b"
sha256sum "$out/m19-rdx-a" | tee "$out/static-binaries.txt"
