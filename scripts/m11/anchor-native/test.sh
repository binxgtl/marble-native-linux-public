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
#  - R2 (docs/m11-r2-ion-ownership.md): path admission per build mode, the two-pair owner seal,
#    and the stand-in query with a sealed ION anchor that the worker drops before its hygiene;
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
# R2 path admission: native build (endpoint only) and R2 build (endpoint + /dev/msm_audio_ion).
gcc -std=c11 -Wall -Wextra -Werror -DM11_ANCHOR_NATIVE -I "$own" "$here/test-ion-path.c" "${anchor[@]}" -o "$out/ion-path-native"
gcc -std=c11 -Wall -Wextra -Werror -DM11_ANCHOR_NATIVE -DM11_ANCHOR_NATIVE_ION -I "$own" "$here/test-ion-path.c" "${anchor[@]}" -o "$out/ion-path-r2"
"$out/ion-path-native" | tee "$out/ion-path-native.log"; "$out/ion-path-r2" | tee "$out/ion-path-r2.log"
if gcc -std=c11 -DM11_OWNERSHIP_OFFLINE -DM11_ANCHOR_NATIVE_ION -I "$own" -I "$repair" -c "$own/m11_anchor_linux.c" -o "$out/ion-offline.o" 2>/dev/null; then
  echo "ERROR: M11_ANCHOR_NATIVE_ION compiled outside the native build" >&2; exit 1
fi
echo 'PASS M11_ANCHOR_NATIVE_ION refused outside the native integration build'

# Terminal core (docs/m11-run24.md): the boot-ledger + terminal-decision subset of the
# offline custodian, linkable into native PID1 with NO custodian/shmem/apm/gpr-engine dep.
gcc -std=c11 -Wall -Wextra -Werror -DM11_ANCHOR_NATIVE -I "$own" -c "$here/terminal_core.c" -o "$out/terminal_core-native.o"
echo 'PASS terminal_core compiles under M11_ANCHOR_NATIVE (no custodian/shmem/apm/gpr-engine)'
# It must not compile without an explicit build mode (device integration stays gated).
if gcc -std=c11 -I "$own" -I "$repair" -c "$here/terminal_core.c" -o "$out/terminal_core-nomode.o" 2>/dev/null; then
  echo "ERROR: terminal_core compiled with no build mode" >&2; exit 1
fi
echo 'PASS terminal_core refuses to build without M11_ANCHOR_NATIVE or M11_OWNERSHIP_OFFLINE'
# Cross-check: the native terminal core decides a boot's end IDENTICALLY to the frozen,
# CI-qualified offline custodian over the never-mapped state space (terminal decisions and
# the cmdline gate). Offline mode links both in one program; the custodian is unchanged.
tc_units=(m11_gpr_engine m11_shmem m11_apm_protocol m11_aw_protection m11_strict_mock)
for tc_mode in gcc clang sanitize; do
  tc_cc=gcc
  tc_flags=(-std=c11 -O1 -g -Wall -Wextra -Werror -DM11_OWNERSHIP_OFFLINE -I "$own" -I "$repair" -I "$here")
  [[ "$tc_mode" == clang ]] && tc_cc=clang
  [[ "$tc_mode" == sanitize ]] && tc_flags+=(-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer)
  tc_srcs=(); for u in "${tc_units[@]}"; do tc_srcs+=("$repair/$u.c"); done
  "$tc_cc" "${tc_flags[@]}" "${tc_srcs[@]}" "$own/m11_custodian.c" "$here/terminal_core.c" "$here/test-terminal-core.c" -o "$out/terminal-core-$tc_mode"
  "$out/terminal-core-$tc_mode" | tee "$out/terminal-core-$tc_mode.log"
done
echo 'PASS terminal core matches the frozen custodian (terminal decisions + cmdline gate)'
# Detection power: a terminal core that diverges from the custodian must fail the cross-check.
tc_mut="$out/terminal-core-mutant"; mkdir -p "$tc_mut"
awk 'index($0,"return M11_TERMINAL_ORDERLY_SHUTDOWN;"){n++; if(n==1){print "    return M11_TERMINAL_HOLD;"; next}} {print}
     END{if(n<1) exit 3}' "$here/terminal_core.c" > "$tc_mut/terminal_core.c"
cmp -s "$here/terminal_core.c" "$tc_mut/terminal_core.c" && { echo "ERROR: terminal_core mutant changed nothing" >&2; exit 1; }
tc_srcs=(); for u in "${tc_units[@]}"; do tc_srcs+=("$repair/$u.c"); done
gcc -std=c11 -O1 -Wall -Wextra -Werror -DM11_OWNERSHIP_OFFLINE -I "$own" -I "$repair" -I "$here" \
  "${tc_srcs[@]}" "$own/m11_custodian.c" "$tc_mut/terminal_core.c" "$here/test-terminal-core.c" -o "$tc_mut/bin"
if "$tc_mut/bin" > "$tc_mut/log" 2>&1; then
  echo "ERROR: cross-check did not detect a diverging terminal core" >&2; exit 1
fi
echo 'PASS cross-check detects a diverging terminal core'

# Unit -> sources it is built from, for the mutants below.
build() { # name output [file-to-replace replacement-path]
  local name="$1" output="$2" from="${3:-}" to="${4:-}" srcs=()
  case "$name" in
    runner) srcs=("$here/runner.c" "$here/gpr_linux.c" "$here/audio_runtime.c" "$rt/gpr_native.c"
                  "$rt/gpr_encode.c" "$rt/audio_pd.c" "$rt/audio_encode.c" "${anchor[@]}");;
    test-runner) srcs=("$here/test-runner.c" "$rt/gpr_encode.c" "$rt/audio_encode.c");;
    test-census) srcs=("$here/test-census.c" "$here/audio_runtime.c" "$rt/audio_pd.c" "${anchor[@]}");;
    test-query) srcs=("$here/test-query-standin.c" "$here/gpr_linux.c" "$rt/gpr_native.c" "${anchor[@]}");;
    test-pdr) srcs=("$here/test-pdr.c" "$rt/audio_pd.c" "${anchor[@]}");;
    test-pdr-e2e) srcs=("$here/test-pdr-e2e.c" "$rt/audio_pd.c" "${anchor[@]}");;
    test-ion-seal) srcs=("$here/test-ion-seal.c" "${anchor[@]}");;
  esac
  local extra=() inc=(-I "$here")
  if [[ -n "$from" ]]; then
    for i in "${!srcs[@]}"; do [[ "${srcs[$i]}" == "$here/$from" ]] && srcs[$i]="$to"; done
    inc=(-I "$(dirname "$to")" -I "$here") # test-runner.c includes runner.c: a mutated copy wins
  fi
  if [[ "$name" == test-pdr || "$name" == test-pdr-e2e ]]; then
    # Wrapped syscalls only: Ubuntu gcc's default _FORTIFY_SOURCE turns some calls into *_chk
    # symbols (e.g. __recvfrom_chk under ASan) that --wrap does not intercept.
    extra+=(-U_FORTIFY_SOURCE)
    for w in getpid geteuid open openat close read statfs fstatfs fstat flock fcntl opendir readdir closedir stat lstat pipe2 recvfrom sendto socket bind getsockname; do
      extra+=("-Wl,--wrap=$w")
    done
  fi
  if [[ "$name" == test-runner ]]; then
    for w in getpid umask fork waitpid poll clock_gettime open read write close lstat fstat mknod fopen pipe2 unlink reboot; do
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
  elif [[ "$test" == test-pdr* && "$file" == audio_runtime.c ]]; then
    # the test #includes "audio_runtime.c": a copy next to the mutant makes the mutant win
    cp "$here/$test.c" "$dir/$test.c"
    build "$test" "$out/mutant-$name-$mode.bin" "$test.c" "$dir/$test.c"
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
  flags=(-std=c11 -O1 -g -Wall -Wextra -Werror -DM11_ANCHOR_NATIVE -DM11_ANCHOR_NATIVE_ION)
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
  # Run22 strict-evidence defect: C journal stamps at /proc/uptime's clock and granularity.
  "$cc" "${flags[@]}" -I "$here" "$here/test-journal-time.c" -o "$out/test-journal-time-$mode"
  "$out/test-journal-time-$mode" | tee "$out/test-journal-time-$mode.log"
  if [[ "$mode" == gcc ]]; then
    command -v busybox >/dev/null || { echo "ERROR: busybox required for the journal.sh end-to-end check" >&2; exit 1; }
    python3 "$here/test-journal-time.py" "$out/test-journal-time-$mode" | tee "$out/test-journal-e2e.log"
  fi
  # Run21 hardware failure, offline: the frozen runtime binds QRTR node 0 (refused, :816),
  # fails before m11_pd_begin, and retire then calls the NULL send hook (PID1 SIGSEGV at 0).
  pdr_wrap=()
  for w in getpid geteuid open openat close read statfs fstatfs fstat flock fcntl opendir readdir closedir stat lstat pipe2 recvfrom sendto socket bind getsockname; do
    pdr_wrap+=("-Wl,--wrap=$w")
  done
  "$cc" "${flags[@]}" -U_FORTIFY_SOURCE -DRUNTIME_ORIGINAL -I "$rt" "$here/test-pdr.c" "$rt/audio_pd.c" "${pdr_wrap[@]}" -o "$out/test-pdr-original-$mode"
  set +e; "$out/test-pdr-original-$mode" > "$out/test-pdr-original-$mode.log" 2>&1; rc=$?; set -e
  if [[ "$rc" == 0 ]] || ! grep -q '^REPRO Run21' "$out/test-pdr-original-$mode.log" || grep -q UNEXPECTED "$out/test-pdr-original-$mode.log"; then
    echo "ERROR: the frozen runtime did not reproduce the Run21 PDR crash (rc=$rc)" >&2; cat "$out/test-pdr-original-$mode.log" >&2; exit 1
  fi
  echo "PASS frozen runtime reproduces Run21 offline ($mode): bind(node 0) refused, retire faults (rc=$rc)"
  build test-pdr "$out/test-pdr-$mode"
  "$out/test-pdr-$mode" | tee "$out/test-pdr-$mode.log"
  build test-pdr-e2e "$out/test-pdr-e2e-$mode"
  timeout 120 "$out/test-pdr-e2e-$mode" | tee "$out/test-pdr-e2e-$mode.log"
  build test-census "$out/test-census-$mode"
  "$out/test-census-$mode" | tee "$out/test-census-$mode.log"
  build test-ion-seal "$out/test-ion-seal-$mode"
  "$out/test-ion-seal-$mode" | tee "$out/test-ion-seal-$mode.log"
  build test-query "$out/test-query-$mode"
  "$out/test-query-$mode" | tee "$out/test-query-$mode.log"
  if [[ "$sudo_ok" == 1 ]]; then
    sudo -n "$out/test-query-$mode" | tee "$out/test-query-root-$mode.log"
  else
    echo "SKIP root stand-in query ($mode): passwordless sudo unavailable" | tee "$out/test-query-root-$mode.log"
  fi
  if [[ "$mode" != sanitize ]]; then
    nmutant no-seal test-runner runner.c 'm11_anchor_owner_seal(&anchor,"/dev/aud_pasthru_adsp")' '' 'a==&anchor && sealed'
    nmutant no-final-close test-runner runner.c 'if (!pdrc && m11_anchor_final_close(&anchor))' '' 'fin>=0 && fin<stop'
    nmutant open-without-pdr-up test-runner runner.c 'if (!pdrc) { /* PDR qualified UP' '        if (1) {' 'pd_up'
    nmutant direct-job test-runner runner.c 'if (spawned(JOB_CONTROL,"stop_adsp",40000)) hold("ADSP stop/restore failed");' \
      '    if (job("/m11/control","stop_adsp",40000)) hold("ADSP stop/restore failed");' '!forks_after_seal'
  fi
  # Pre-hardware audit F1: qrtr_sendmsg refuses MSG_NOSIGNAL (af_qrtr.c:893); F2: a reaped
  # borrower is quiescent under the anchor; F3: retire with nothing sent closes only.
  nmutant qrtr-nosignal test-pdr audio_runtime.c 'ssize_t sent=sendto(r->qrtr,b,n,MSG_DONTWAIT,'     '    ssize_t sent=sendto(r->qrtr,b,n,MSG_DONTWAIT|MSG_NOSIGNAL,(struct sockaddr *)&a,sizeof(a));' 'first_cmd==10'
  nmutant no-anchored-finish test-pdr-e2e audio_runtime.c 'if (!anchored && (!out->worker_exit_ok'     '    if ((void)anchored, (!out->worker_exit_ok || !out->close_returned || !out->close_ok || !out->ipc_complete)) {' 'worker timeout'
  nmutant no-census-rule test-census audio_runtime.c 'else return -1; /* any other endpoint fd in PID1' '' \
    'm11_census_pid1_endpoint(fds,rdevs,2,ep,-1,-1)==-1'
  nmutant no-worker-confine test-query gpr_linux.c 'if (m11_anchor_linux_confine()) _exit(M11_WORKER_EXIT_CONFINE);' '' \
    'worker seccomp filters'
  nmutant no-worker-hygiene test-query gpr_linux.c '/* worker fd hygiene */' '' 'worker fd hygiene' 1
  nmutant no-ion-drop test-query gpr_linux.c 'if (ion && syscall(SYS_close_range' '' 'query rc=-1'
done
echo 'PASS integrated native anchor suite (offline, stand-ins; not a candidate, not hardware-qualified)'
