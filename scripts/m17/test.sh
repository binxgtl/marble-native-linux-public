#!/usr/bin/env bash
# M17: the selector core (G1) and K1-keys (G3), normal and ASan/UBSan, on synthetic trees (no device); then, unless
# M17_STATIC=0, the phone's static binaries twice, which must match. Usage: test.sh OUTDIR [normal]
set -euo pipefail
out=${1:?output}; mkdir -p "$out"
only=${2:-}
src=$(cd "$(dirname "$0")" && pwd)
variants=(normal sanitize)
[[ -n $only ]] && variants=("$only")
for variant in "${variants[@]}"; do
  flags=(-std=c11 -O2 -Wall -Wextra -Werror)
  if [[ $variant == sanitize ]]; then
    flags+=(-O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer)
  fi
  gcc "${flags[@]}" "$src/select.c" "$src/test-select.c" -o "$out/test-select-$variant" &
  first=$!
  gcc "${flags[@]}" "$src/select.c" "$src/g3.c" "$src/test-g3.c" -o "$out/test-g3-$variant" &
  second=$!
  wait "$first"
  wait "$second"
done
pids=()
for variant in "${variants[@]}"; do
  for name in select g3; do
    TMPDIR=$(mktemp -d) "$out/test-$name-$variant" >"$out/test-$name-$variant.txt" 2>&1 &
    pids+=("$!")
  done
done
rc=0
for pid in "${pids[@]}"; do
  wait "$pid" || rc=1
done
cat "$out"/test-*-*.txt
[[ $rc -eq 0 ]] || { echo "M17 tests failed" >&2; exit 1; }
echo "M17 selector core and K1-keys PASS (${variants[*]})"

[[ ${M17_STATIC:-1} == 1 ]] || exit 0
# The phone's binaries: M19 R1's runtime as PID 1 with K1, and K1 itself. Reviewable binaries only, never a boot image.
m19=$src/../m19
for copy in a b; do
  flags=(-std=c11 -Os -Wall -Wextra -Werror -static -Wl,--build-id=none)
  gcc "${flags[@]}" "$m19/unlock/hash.c" "$m19/run1/r1.c" "$src/pid-g3.c" -o "$out/m17-pid-g3-$copy"
  gcc "${flags[@]}" "$src/select.c" "$src/g3.c" "$src/keys-main.c" -o "$out/m17-keys-$copy"
done
for name in m17-pid-g3 m17-keys; do
  cmp "$out/$name-a" "$out/$name-b"
  sha256sum "$out/$name-a"
done | tee "$out/m17-binaries.txt"
