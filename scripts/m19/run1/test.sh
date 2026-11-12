#!/usr/bin/env bash
set -euo pipefail
out=${1:?output}; mkdir -p "$out"
src=scripts/m19/run1
hash=scripts/m19/unlock/hash.c
build_pids=()
for variant in normal sanitize; do
  flags=(-std=c11 -O2 -Wall -Wextra -Werror)
  if [[ $variant == sanitize ]]; then
    flags+=(-O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer)
  fi
  gcc "${flags[@]}" "$hash" "$src/r1.c" "$src/test-r1.c" -Wl,--wrap=waitpid -o "$out/test-r1-$variant" &
  build_pids+=("$!")
done
for pid in "${build_pids[@]}"; do
  wait "$pid"
done

python3 "$src/test.py" --driver "$out/test-r1-normal" >"$out/run-normal.txt" 2>&1 &
pid_normal=$!
python3 "$src/test.py" --driver "$out/test-r1-sanitize" >"$out/run-sanitize.txt" 2>&1 &
pid_sanitize=$!
rc_normal=0
wait "$pid_normal" || rc_normal=$?
rc_sanitize=0
wait "$pid_sanitize" || rc_sanitize=$?
cat "$out/run-normal.txt" "$out/run-sanitize.txt"
# Not "test A && test B": under set -e a false A in an AND list does not stop the script.
if [ "$rc_normal" -ne 0 ] || [ "$rc_sanitize" -ne 0 ]; then
  echo "tests failed: normal=$rc_normal sanitize=$rc_sanitize" >&2
  exit 1
fi

# Mutants depend on the tests, not on the CPU: CI runs them once, in a job of their own.
if [[ ${M19_MUTANTS:-1} == 1 ]]; then
  python3 "$src/mutate.py" | tee "$out/mutants.txt"
fi
# Reviewable binaries only, never a boot image. Independent outputs must match.
static_pids=()
for copy in a b; do
  flags=(-std=c11 -Os -Wall -Wextra -Werror -static -Wl,--build-id=none)
  gcc "${flags[@]}" "$hash" "$src/r1.c" "$src/pid1.c" -o "$out/pid1-$copy" &
  static_pids+=("$!")
  gcc "${flags[@]}" "$src/load-heaps.c" -o "$out/load-heaps-$copy" &
  static_pids+=("$!")
done
for pid in "${static_pids[@]}"; do
  wait "$pid"
done
for name in pid1 load-heaps; do
  cmp "$out/$name-a" "$out/$name-b"
  sha256sum "$out/$name-a"
done | tee "$out/run1-binaries.txt"
