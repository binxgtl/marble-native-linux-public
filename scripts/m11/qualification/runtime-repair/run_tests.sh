#!/usr/bin/env bash
# Offline runtime-repair qualification, self-contained (no Argon checkout, no repository history),
# for the public CI: the repaired suite, the P1-P6 hardening regression suite with the post-MAP
# hold, the fixed-seed fuzz, the Python wire/source oracle, the review witnesses before/after, the
# hardening baseline reproduction and the mutation check (gcc, clang, ASan+UBSan).
# Mocks only; nothing here talks to hardware.
#   usage: run_tests.sh <out-dir>
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
out="$(mkdir -p "$1" && cd "$1" && pwd)"
units=(m11_gpr_engine m11_shmem m11_apm_protocol m11_aw_protection m11_offline_sim m11_strict_mock)
srcs=(); for u in "${units[@]}"; do srcs+=("$here/$u.c"); done
for mode in gcc clang sanitize; do
  cc=gcc; flags=(-std=c11 -O1 -g -Wall -Wextra -Werror -I "$here")
  [[ "$mode" == clang ]] && cc=clang
  [[ "$mode" == sanitize ]] && flags+=(-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer)
  "$cc" "${flags[@]}" "${srcs[@]}" "$here/test_runtime_repair.c" -o "$out/runtime-repair-$mode"
  "$out/runtime-repair-$mode" | tee "$out/runtime-repair-$mode.log"
  "$cc" "${flags[@]}" "${srcs[@]}" "$here/test_runtime_hardening.c" -o "$out/runtime-hardening-$mode"
  "$out/runtime-hardening-$mode" | tee "$out/runtime-hardening-$mode.log"
  grep -q 'HARDENING RESULT: PASS' "$out/runtime-hardening-$mode.log"
  "$cc" "${flags[@]}" "${srcs[@]}" "$here/fuzz_runtime_invariants.c" -o "$out/runtime-fuzz-$mode"
  "$out/runtime-fuzz-$mode" 20000 | tee "$out/runtime-fuzz-$mode.log"
  grep -q 'FUZZ RESULT: PASS' "$out/runtime-fuzz-$mode.log"
  # The amplifier-enable switch must stay a compile-time error.
  if "$cc" "${flags[@]}" -DM11_ALLOW_AMP_ENABLE=1 -c "$here/m11_aw_protection.c" -o "$out/forbidden-amp-$mode.o" 2>/dev/null; then
    echo "ERROR: M11_ALLOW_AMP_ENABLE did not trigger the compile-time #error" >&2; exit 1
  fi
done
echo 'PASS repaired suite, hardening regression suite (post-MAP hold) and fixed-seed fuzz (gcc, clang, ASan+UBSan)'
M11_REQUIRE_NATIVE_ORACLE=1 python3 -I "$here/test_runtime_repair_py.py" -v 2>&1 | tee "$out/python-oracle.log"
test "${PIPESTATUS[0]}" -eq 0
bash "$here/run_review_regression.sh" "$out/review"
grep -q 'REVIEW BASELINE DEFECTS REPRODUCED' "$out/review/baseline-gcc.log"
grep -q 'RUNTIME REVIEW REGRESSION PASS' "$out/review/repaired-gcc.log"
echo 'PASS review witnesses: the review baseline reproduces the review defects, the repaired tree does not'
bash "$here/run_baseline_repro.sh" "$out/baseline" | tee "$out/baseline-repro.log"
test "${PIPESTATUS[0]}" -eq 0
for m in "gcc" "clang" "gcc --sanitize"; do
  tag="${m// /-}"
  # shellcheck disable=SC2086
  python3 -I "$here/run_mutation_check.py" "$out/mutation-$tag" --cc $m 2>&1 | tee "$out/mutation-$tag.log"
  test "${PIPESTATUS[0]}" -eq 0
done
echo 'PASS runtime-repair qualification (mocks only; no firmware or hardware claim)'
