#!/usr/bin/env bash
# M17 G1: the selector core, normal and ASan/UBSan, on synthetic trees (no device). Usage: test.sh OUTDIR [normal]
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
  gcc "${flags[@]}" "$src/select.c" "$src/test-select.c" -o "$out/test-select-$variant"
done
rc=0
for variant in "${variants[@]}"; do
  TMPDIR=$(mktemp -d) "$out/test-select-$variant" || rc=$?
  [[ $rc -eq 0 ]] || { echo "test-select-$variant failed rc=$rc" >&2; exit 1; }
done
echo "M17 selector core PASS (${variants[*]})"
