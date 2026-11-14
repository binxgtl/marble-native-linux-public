#!/usr/bin/env bash
# M17: the selector core (G1), K1-keys (G3), the selector (G4) and the native path's runtime, loader, session and volume keys (G5),
# normal and ASan/UBSan, on synthetic trees (no device); then, unless M17_STATIC=0, the phone's static binaries twice, which must
# match. Usage: test.sh OUTDIR [normal]
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
  gcc "${flags[@]}" "$src/select.c" "$src/selector.c" "$src/menu.c" "$src/modules.c" "$src/test-g4.c" -o "$out/test-g4-$variant" &
  third=$!
  gcc "${flags[@]}" "$src/select.c" "$src/load.c" "$src/native.c" "$src/cmd.c" "$src/session.c" "$src/volkeys.c" "$src/test-g5.c" \
    -o "$out/test-g5-$variant" &
  fourth=$!
  wait "$first"
  wait "$second"
  wait "$third"
  wait "$fourth"
done
pids=()
for variant in "${variants[@]}"; do
  for name in select g3 g4 g5; do
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
echo "M17 selector core, K1-keys, the selector and the native path PASS (${variants[*]})"

[[ ${M17_STATIC:-1} == 1 ]] || exit 0
# The phone's binaries: M19 R1's runtime as PID 1 with K1, and K1 itself (G3); the selector without a native path (G4) and
# with one (G5); the native path's PID 1 with M19 R2's hand-off and R3's guard (G5). Reviewable binaries only, never a boot
# image.
m19=$src/../m19
for copy in a b; do
  flags=(-std=c11 -Os -Wall -Wextra -Werror -static -Wl,--build-id=none)
  gcc "${flags[@]}" "$m19/unlock/hash.c" "$m19/run1/r1.c" "$src/pid-g3.c" -o "$out/m17-pid-g3-$copy"
  gcc "${flags[@]}" "$src/select.c" "$src/g3.c" "$src/keys-main.c" -o "$out/m17-keys-$copy"
  gcc "${flags[@]}" "$src/select.c" "$src/selector.c" "$src/menu.c" "$src/modules.c" "$src/kms.c" "$src/selector-main.c" -o "$out/m17-selector-$copy"
  gcc "${flags[@]}" -DM17_NATIVE_BUILD=1 "$src/select.c" "$src/selector.c" "$src/menu.c" "$src/modules.c" "$src/kms.c" "$src/selector-main.c" \
    -o "$out/m17-selector-native-$copy"
  gcc "${flags[@]}" "$m19/unlock/hash.c" "$m19/run2/wire.c" "$m19/run2/handoff.c" "$m19/run2/report.c" "$src/select.c" "$src/load.c" \
    "$src/native.c" "$src/cmd.c" "$src/session.c" "$src/volkeys.c" "$src/native-main.c" -o "$out/m17-native-$copy"
done
for name in m17-pid-g3 m17-keys m17-selector m17-selector-native m17-native; do
  cmp "$out/$name-a" "$out/$name-b"
  sha256sum "$out/$name-a"
done | tee "$out/m17-binaries.txt"
