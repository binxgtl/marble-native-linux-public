#!/usr/bin/env bash
# Actual binding/main/supervisor logic; typed fakes only, no Binder/TEE/device.
set -euo pipefail
out=${1:?output}; mkdir -p "$out"
src=scripts/m19/unlock
for variant in normal sanitize; do
  flags=(-O2 -Wall -Wextra -Werror)
  if [[ $variant == sanitize ]]; then
    flags+=(-O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer)
  fi
  gcc "${flags[@]}" -std=c11 -c "$src/core.c" -o "$out/core-$variant.o"
  gcc "${flags[@]}" -std=c11 -c "$src/hash.c" -o "$out/hash-$variant.o"
  gcc "${flags[@]}" -std=c11 -DM19_PROBE_STEP_MS=300 -DM19_PROBE_TOTAL_MS=2800 -DM19_PROBE_REAP_MS=300 -c "$src/probe-supervisor.c" -o "$out/supervisor-$variant.o"
  g++ "${flags[@]}" -std=c++17 -DM19_BINDING_TEST "$src/binding.cpp" "$src/test-binding.cpp" -o "$out/binding-$variant"
  g++ "${flags[@]}" -std=c++17 -DM19_BINDING_TEST "$src/binding.cpp" "$src/probe.cpp" \
    "$out/core-$variant.o" "$out/hash-$variant.o" "$out/supervisor-$variant.o" -o "$out/probe-$variant"
  gcc "${flags[@]}" -std=c11 -DM19_PROBE_STEP_MS=300 -DM19_PROBE_TOTAL_MS=2800 -DM19_PROBE_REAP_MS=300 "$src/test-probe-supervisor.c" -o "$out/hostile-$variant"
  # Forked, killed workers are intentional. No namespace/worker leak-free claim.
  sudo -E env ASAN_OPTIONS=detect_leaks=0 python3 "$src/test-probe.py" --binding "$out/binding-$variant" \
    --probe "$out/probe-$variant" --supervisor "$out/hostile-$variant" 2>&1 | tee "$out/probe-$variant.txt"
done
