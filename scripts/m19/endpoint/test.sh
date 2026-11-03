#!/usr/bin/env bash
# Endpoint-only C/DSO/supervisor tests. No device or actual Binder is contacted.
set -euo pipefail
out=${1:?output}; mkdir -p "$out"; out=$(cd "$out" && pwd)
src=scripts/m19/endpoint
symbols=(AParcel_markSensitive AServiceManager_checkService AIBinder_Class_define
         AIBinder_associateClass AIBinder_getClass AIBinder_Class_getDescriptor AIBinder_decStrong)
for variant in normal sanitize; do
  flags=(-std=c11 -O2 -Wall -Wextra -Werror)
  if [[ $variant == sanitize ]]; then
    flags+=(-O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer)
  fi
  gcc "${flags[@]}" -fPIC -shared "$src/fake-binder.c" -o "$out/fake-$variant.so"
  for suffix in '' "${symbols[@]}"; do
    if [[ -n $suffix ]]; then
      lib="$out/omit-$suffix-$variant.so"; name="-omit-$suffix"
      gcc "${flags[@]}" -fPIC -shared -D"M19_FAKE_OMIT_$suffix" "$src/fake-binder.c" -o "$lib"
    else
      lib="$out/fake-$variant.so"; name=''
    fi
    gcc "${flags[@]}" -DM19_ENDPOINT_LIBRARY="\"$lib\"" "$src/endpoint.c" "$src/test-core.c" -ldl -o "$out/core$name-$variant"
    gcc "${flags[@]}" -DM19_ENDPOINT_LIBRARY="\"$lib\"" -DM19_ENDPOINT_WORK_MS=500 -DM19_ENDPOINT_REAP_MS=300 \
      "$src/endpoint.c" "$src/supervisor.c" -ldl -o "$out/endpoint$name-$variant"
  done
  gcc "${flags[@]}" -DM19_ENDPOINT_LIBRARY="\"$out/nonexistent-library.so\"" -DM19_ENDPOINT_WORK_MS=500 -DM19_ENDPOINT_REAP_MS=300 \
    "$src/endpoint.c" "$src/supervisor.c" -ldl -o "$out/endpoint-missing-$variant"
  gcc "${flags[@]}" -DM19_ENDPOINT_WORK_MS=500 -DM19_ENDPOINT_REAP_MS=300 \
    "$src/test-supervisor.c" -o "$out/hostile-$variant"
  ASAN_OPTIONS=detect_leaks=0 python3 "$src/test.py" --out "$out" --variant "$variant" 2>&1 | tee "$out/tests-$variant.txt"
done
python3 "$src/mutate.py" --out "$out" | tee "$out/mutants.txt"
