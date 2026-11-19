#!/usr/bin/env bash
# M18 R1 (docs/m18-performance-polish.md): the copies against M17 (copies.py), M17's native-path and session tests on
# M18's copies, normal and ASan/UBSan, the plan and the scripts on synthetic trees (test-r1.py); then, unless
# M18_STATIC=0, the phone's static binaries twice, which must match. No device. Usage: test.sh OUTDIR [normal]
# Mutation tests can select one C suite with OUTDIR normal native|spinner|shutdown-trace.
set -euo pipefail
out=${1:?output}; mkdir -p "$out"
src=$(cd "$(dirname "$0")" && pwd)
m17=$src/../m17
m19=$src/../m19

run_c_test() (
  local suite=$1 variant=$2 binary="$out/test-$1-$2" scratch
  local flags=(-std=c11 -O2 -Wall -Wextra -Werror -I"$m17")
  if [[ $variant == sanitize ]]; then
    flags+=(-O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer)
  fi
  case $suite in
    native)
      gcc "${flags[@]}" "$m17/select.c" "$m17/load.c" "$src/native.c" "$m17/cmd.c" "$src/session.c" \
        "$m17/volkeys.c" "$src/test-r1.c" -o "$binary" || return
      ;;
    spinner) gcc "${flags[@]}" "$src/bye.c" "$src/test-r3.c" -lm -o "$binary" || return ;;
    shutdown-trace) gcc "${flags[@]}" "$src/shutdown-trace.c" "$src/test-r3b.c" -o "$binary" || return ;;
    *) echo "Unknown M18 test suite: $suite" >&2; return 2 ;;
  esac
  scratch=$(mktemp -d) || return
  trap 'rm -r -- "$scratch"' EXIT
  if [[ $suite == shutdown-trace ]]; then
    "$binary" "$scratch"
  else
    TMPDIR="$scratch" "$binary"
  fi
)

if [[ -n ${3:-} ]]; then
  [[ ${2:-} == normal ]] || exit 2
  run_c_test "$3" normal
  exit
fi
if [[ ${M18_COPIES:-1} == 1 ]]; then
  python3 "$src/copies.py" check
fi
variants=(normal sanitize)
[[ -n ${2:-} ]] && variants=("$2")
rc=0
for variant in "${variants[@]}"; do
  for suite in native spinner shutdown-trace; do
    run_c_test "$suite" "$variant" || rc=1
  done
done
python3 "$src/test-r1.py" || rc=1
python3 "$src/test-r2.py" || rc=1
python3 "$src/test-r3.py" || rc=1
[[ $rc -eq 0 ]] || { echo "M18 tests failed" >&2; exit 1; }
echo "M18 R1 to R3 copies, native path, session, spinner, plans and scripts PASS (${variants[*]})"

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
  # R3: the shutdown's spinner, with the selector's KMS code
  gcc "${flags[@]}" -I"$m17" "$src/bye.c" "$src/bye-main.c" "$m17/kms.c" -lm -o "$out/m18-bye-$copy"
  gcc "${flags[@]}" -DM18_R3B -I"$m17" "$src/bye.c" "$src/bye-main.c" "$src/shutdown-trace.c" "$m17/kms.c" -lm -o "$out/m18-bye-r3b-$copy"
done
for name in m18-native m17-native m17-selector-native m18-bye m18-bye-r3b; do
  cmp "$out/$name-a" "$out/$name-b"
  sha256sum "$out/$name-a"
done | tee "$out/m18-binaries.txt"
