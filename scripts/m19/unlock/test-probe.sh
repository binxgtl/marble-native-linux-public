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
  if [[ $variant == normal ]]; then
    # Independently restore each reviewed defect: focused regressions MUST fail.
    # Linux CI is the build interface; these are never built/run on the phone.
    for regression in parent-death upgrade-facts sticky-upgrade; do
      bad="$out/red-$regression"; mkdir -p "$bad"
      cp "$src/"*.c "$src/"*.cpp "$src/"*.h "$bad/"
      python3 - "$bad" "$regression" <<'PY'
import sys
from pathlib import Path
root,case=Path(sys.argv[1]),sys.argv[2]
if case=='parent-death':
    name='probe-supervisor.c'
    old='if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) || getppid() != parent) _exit(125);'
    new='(void)parent; /* Historical missing parent-death protection. */'
elif case=='upgrade-facts':
    name='probe-supervisor.c'
    old='!consistent(&e, fact, observed, key_rpc_started)'
    new='(consistent(&e, fact, observed, key_rpc_started), 0)'
else:
    name='binding.cpp'
    old='''    c->observed = 1;
    c->upgrade = M19_U_OBSERVED;
    if (blob->empty() || blob->size() > M19_KEY_MAX) return false;'''
    new='''    if (blob->empty() || blob->size() > M19_KEY_MAX) return false;
    c->observed = 1;
    c->upgrade = M19_U_OBSERVED;'''
path=root/name;source=path.read_text();assert source.count(old)==1,(case,'mutation does not apply')
path.write_text(source.replace(old,new))
PY
      binding="$out/binding-normal"; hostile="$out/hostile-normal"
      if [[ $regression == sticky-upgrade ]]; then
        g++ "${flags[@]}" -std=c++17 -DM19_BINDING_TEST "$bad/binding.cpp" "$bad/test-binding.cpp" -o "$bad/binding"
        binding="$bad/binding"
      else
        gcc "${flags[@]}" -std=c11 -DM19_PROBE_STEP_MS=300 -DM19_PROBE_TOTAL_MS=2800 -DM19_PROBE_REAP_MS=300 \
          "$bad/test-probe-supervisor.c" -o "$bad/hostile"
        hostile="$bad/hostile"
      fi
      if sudo -E python3 "$src/test-probe.py" --binding "$binding" --probe "$out/probe-normal" \
           --supervisor "$hostile" --case "$regression" > "$out/red-$regression.txt" 2>&1; then
        echo "Historical defect survived: $regression" >&2; exit 1
      else
        rc=$?; test "$rc" -eq 1
        grep -q '^FAIL:' "$out/red-$regression.txt"
        if grep -q '^ERROR:' "$out/red-$regression.txt"; then cat "$out/red-$regression.txt"; exit 1; fi
      fi
      echo "Reviewed $regression defect rejected by focused regression"
    done
  fi
done
