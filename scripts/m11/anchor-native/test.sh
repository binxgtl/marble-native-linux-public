#!/usr/bin/env bash
# Integrated native anchor suite (R1, P1-P5), offline: gcc, clang and gcc ASan+UBSan. Stand-ins
# only; the integrated runner binary is linked but refuses to act outside PID1. No hardware.
#  - static structure checks of the integrated sources and the flow's shell inputs;
#  - terminal enum identical in the offline and native build modes;
#  - the integrated runner links and returns 2 outside PID1;
#  - the actual runner control flow with every boundary replaced (15 scenarios);
#  - the PID1 endpoint census rule;
#  - an end-to-end GET_SPF_STATE through the integrated worker on a /dev/ptmx stand-in held by a
#    sealed owner, as non-root and (sudo) as root, with the live worker's confinement and fd
#    table inspected;
#  - one-line mutants of the integration that must fail for a named reason.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../../.." && pwd)"
rt="$root/scripts/m11/runtime"
own="$root/scripts/m11/qualification/ownership"
repair="$root/scripts/m11/qualification/runtime-repair"
out="$(mkdir -p "$1" && cd "$1" && pwd)"
anchor=("$own/m11_pid1_anchor.c" "$own/m11_anchor_linux.c" "$own/m11_anchor_owner.c")
sudo_ok=0
if sudo -n true 2>/dev/null; then sudo_ok=1; fi
sha256sum "$here"/*.c "$here"/*.h "$here"/*.py "$here"/*.sh "${anchor[@]}" > "$out/inputs.sha256"

python3 "$here/test-static.py" | tee "$out/static.log"
gcc -std=c11 -Wall -Wextra -Werror -DM11_OWNERSHIP_OFFLINE -I "$own" -I "$repair" "$here/test-terminal-enum.c" -o "$out/enum-offline"
gcc -std=c11 -Wall -Wextra -Werror -DM11_ANCHOR_NATIVE -I "$own" "$here/test-terminal-enum.c" -o "$out/enum-native"
"$out/enum-offline" > "$out/enum-offline.txt"; "$out/enum-native" > "$out/enum-native.txt"
cmp "$out/enum-offline.txt" "$out/enum-native.txt"
echo 'PASS terminal enum identical in the offline and native build modes'

# Unit -> sources it is built from, for the mutants below.
build() { # name output [file-to-replace replacement-path]
  local name="$1" output="$2" from="${3:-}" to="${4:-}" srcs=()
  case "$name" in
    runner) srcs=("$here/runner.c" "$here/gpr_linux.c" "$here/audio_runtime.c" "$rt/gpr_native.c"
                  "$rt/gpr_encode.c" "$rt/audio_pd.c" "$rt/audio_encode.c" "${anchor[@]}");;
    test-runner) srcs=("$here/test-runner.c" "$rt/gpr_encode.c" "$rt/audio_encode.c");;
    test-census) srcs=("$here/test-census.c" "$here/audio_runtime.c" "$rt/audio_pd.c" "${anchor[@]}");;
    test-query) srcs=("$here/test-query-standin.c" "$here/gpr_linux.c" "$rt/gpr_native.c" "${anchor[@]}");;
  esac
  local extra=() inc=(-I "$here")
  if [[ -n "$from" ]]; then
    for i in "${!srcs[@]}"; do [[ "${srcs[$i]}" == "$here/$from" ]] && srcs[$i]="$to"; done
    inc=(-I "$(dirname "$to")" -I "$here") # test-runner.c includes runner.c: a mutated copy wins
  fi
  if [[ "$name" == test-runner ]]; then
    for w in getpid umask fork waitpid poll clock_gettime open read write close lstat fstat mknod fopen pipe2 reboot; do
      extra+=("-Wl,--wrap=$w")
    done
  fi
  "$cc" "${flags[@]}" "${inc[@]}" -I "$rt" -I "$own" "${srcs[@]}" "${extra[@]}" -o "$output"
}
mutate() { # file old new dir: copy file with exactly one line deleted (new='') or replaced
  local file="$1" old="$2" new="$3" dir="$4"
  mkdir -p "$dir"
  awk -v old="$old" -v new="$new" -v del="${new:+0}" '
    index($0, old) { n++; if (del == "0") print new; next } { print }
    END { if (n != 1) exit 3 }' "$here/$file" > "$dir/$file"
  if cmp -s "$here/$file" "$dir/$file"; then echo "ERROR: mutant of $file changed nothing" >&2; exit 1; fi
}
nmutant() { # name test file old new expect [root]
  local name="$1" test="$2" file="$3" old="$4" new="$5" expect="$6" asroot="${7:-0}" dir="$out/mutant-$1-$mode"
  if [[ "$asroot" == 1 && "$sudo_ok" != 1 ]]; then echo "SKIP mutant $name ($mode): no sudo"; return; fi
  mutate "$file" "$old" "$new" "$dir"
  if [[ "$test" == test-runner && "$file" == runner.c ]]; then
    cp "$here/test-runner.c" "$dir/test-runner.c"
    build test-runner "$out/mutant-$name-$mode.bin" test-runner.c "$dir/test-runner.c"
  else
    build "$test" "$out/mutant-$name-$mode.bin" "$file" "$dir/$file"
  fi
  local run=("$out/mutant-$name-$mode.bin")
  [[ "$asroot" == 1 ]] && run=(sudo -n "${run[@]}")
  if "${run[@]}" > "$out/mutant-$name-$mode.log" 2>&1; then
    echo "ERROR: integration suite did not detect mutant $name" >&2; exit 1
  fi
  grep -m1 -F -- "$expect" "$out/mutant-$name-$mode.log"
  echo "PASS integration suite detects mutant $name ($mode)"
}

for mode in gcc clang sanitize; do
  cc=gcc
  flags=(-std=c11 -O1 -g -Wall -Wextra -Werror -DM11_ANCHOR_NATIVE)
  if [[ "$mode" == clang ]]; then cc=clang; fi
  if [[ "$mode" == sanitize ]]; then flags+=(-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer); fi
  build runner "$out/runner-$mode"
  set +e; "$out/runner-$mode"; rc=$?; set -e
  if [[ "$rc" != 2 ]]; then echo "ERROR: integrated runner did not refuse to act outside PID1 (rc=$rc)" >&2; exit 1; fi
  echo "PASS integrated runner links ($mode) and returns 2 outside PID1"
  # The control-flow test longjmps out of wrapped syscalls; it runs without sanitizers, like
  # the historical next/test.sh runner test.
  if [[ "$mode" != sanitize ]]; then
    build test-runner "$out/test-runner-$mode"
    "$out/test-runner-$mode" | tee "$out/test-runner-$mode.log"
  fi
  build test-census "$out/test-census-$mode"
  "$out/test-census-$mode" | tee "$out/test-census-$mode.log"
  build test-query "$out/test-query-$mode"
  "$out/test-query-$mode" | tee "$out/test-query-$mode.log"
  if [[ "$sudo_ok" == 1 ]]; then
    sudo -n "$out/test-query-$mode" | tee "$out/test-query-root-$mode.log"
  else
    echo "SKIP root stand-in query ($mode): passwordless sudo unavailable" | tee "$out/test-query-root-$mode.log"
  fi
  if [[ "$mode" != sanitize ]]; then
    nmutant no-seal test-runner runner.c 'm11_anchor_owner_seal(&anchor,"/dev/aud_pasthru_adsp")' '' 'a==&anchor && sealed'
    nmutant no-final-close test-runner runner.c 'if (m11_anchor_final_close(&anchor))' '' 'fin>=0 && fin<stop'
    nmutant direct-job test-runner runner.c 'if (spawned(JOB_CONTROL,"stop_adsp",40000)) hold("ADSP stop/restore failed");' \
      '    if (job("/m11/control","stop_adsp",40000)) hold("ADSP stop/restore failed");' '!forks_after_seal'
  fi
  nmutant no-census-rule test-census audio_runtime.c 'else return -1; /* any other endpoint fd in PID1' '' \
    'm11_census_pid1_endpoint(fds,rdevs,2,ep,-1,-1)==-1'
  nmutant no-worker-confine test-query gpr_linux.c 'if (m11_anchor_linux_confine()) _exit(M11_WORKER_EXIT_CONFINE);' '' \
    'worker seccomp filters'
  nmutant no-worker-hygiene test-query gpr_linux.c '/* worker fd hygiene */' '' 'worker fd hygiene' 1
done
echo 'PASS integrated native anchor suite (offline, stand-ins; not a candidate, not hardware-qualified)'
