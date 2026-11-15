#!/usr/bin/env bash
# M18 R1 (docs/m18-performance-polish.md): the copies against M17 (copies.py), M17's native-path and session tests on
# M18's copies, normal and ASan/UBSan, the plan and the scripts on synthetic trees (test-r1.py); then, unless
# M18_STATIC=0, the phone's static binaries twice, which must match. No device. Usage: test.sh OUTDIR [normal]
# M18_COPIES=0 skips the copies check (the mutants change the copies on purpose).
set -euo pipefail
out=${1:?output}; mkdir -p "$out"
only=${2:-}
src=$(cd "$(dirname "$0")" && pwd)
m17=$src/../m17
m19=$src/../m19
if [[ ${M18_COPIES:-1} == 1 ]]; then
  python3 "$src/copies.py" check
fi
variants=(normal sanitize)
[[ -n $only ]] && variants=("$only")
for variant in "${variants[@]}"; do
  flags=(-std=c11 -O2 -Wall -Wextra -Werror -I"$m17")
  if [[ $variant == sanitize ]]; then
    flags+=(-O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer)
  fi
  gcc "${flags[@]}" "$m17/select.c" "$m17/load.c" "$src/native.c" "$m17/cmd.c" "$src/session.c" "$m17/volkeys.c" "$src/test-r1.c" \
    -o "$out/test-r1-$variant"
done
rc=0
for variant in "${variants[@]}"; do
  TMPDIR=$(mktemp -d) "$out/test-r1-$variant" >"$out/test-r1-$variant.txt" 2>&1 || rc=1
  cat "$out/test-r1-$variant.txt"
done
python3 "$src/test-r1.py" || rc=1
python3 "$src/test-r2.py" || rc=1
[[ $rc -eq 0 ]] || { echo "M18 tests failed" >&2; exit 1; }
echo "M18 R1 and R2 copies, native path, session, plans and scripts PASS (${variants[*]})"

[[ ${M18_STATIC:-1} == 1 ]] || exit 0
# The phone's binaries: M18's native path (its copies of native.c, session.c and native-main.c), M17's native path and
# selector unchanged (the staging reads them before R1's changes). Reviewable binaries only, never a boot image.
for copy in a b; do
  flags=(-std=c11 -Os -Wall -Wextra -Werror -static -Wl,--build-id=none)
  gcc "${flags[@]}" -I"$m17" "$m19/unlock/hash.c" "$m19/run2/wire.c" "$m19/run2/handoff.c" "$m19/run2/report.c" "$m17/select.c" \
    "$m17/load.c" "$src/native.c" "$m17/cmd.c" "$src/session.c" "$m17/volkeys.c" "$src/native-main.c" -o "$out/m18-native-$copy"
  gcc "${flags[@]}" "$m19/unlock/hash.c" "$m19/run2/wire.c" "$m19/run2/handoff.c" "$m19/run2/report.c" "$m17/select.c" "$m17/load.c" \
    "$m17/native.c" "$m17/cmd.c" "$m17/session.c" "$m17/volkeys.c" "$m17/native-main.c" -o "$out/m17-native-$copy"
  gcc "${flags[@]}" -DM17_NATIVE_BUILD=1 "$m17/select.c" "$m17/selector.c" "$m17/menu.c" "$m17/modules.c" "$m17/kms.c" \
    "$m17/selector-main.c" -o "$out/m17-selector-native-$copy"
done
for name in m18-native m17-native m17-selector-native; do
  cmp "$out/$name-a" "$out/$name-b"
  sha256sum "$out/$name-a"
done | tee "$out/m18-binaries.txt"
