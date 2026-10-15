#!/usr/bin/env bash
# PID1 endpoint-anchor adapter (R1) offline suite, under gcc, clang and gcc ASan+UBSan:
#  - directed cases on the synthetic pinned-ACK file-lifetime model, including a before/after
#    witness of the current native path and the custodian ledger integration;
#  - real fork/exec/SIGKILL cases on a STAND-IN character device (/dev/ptmx), never the endpoint,
#    including negative controls (CLONE_FILES, close_range, dup3, self-exec, SCM_RIGHTS in flight)
#    and the confined worker (fd hygiene, seccomp denylist, kcmp census);
#  - the sealed owner (P1-P4 seccomp, pre-bind spawner) without root, and P5 with real root
#    semantics (sudo on the hosted runner): private stand-in node, capability-reduced jobs,
#    full-capability negative controls;
#  - seeded fuzz with coverage gates; detection power against three one-line fuzz mutants,
#    six one-line process-test mutants and three one-line root-test mutants;
#  - the offline compile gate. Mock/model/stand-in evidence only: no device or DSP claim.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repair="$here/../runtime-repair"
out="$(mkdir -p "$1" && cd "$1" && pwd)"
units=(m11_gpr_engine m11_shmem m11_apm_protocol m11_aw_protection m11_strict_mock)
sha256sum "$here/m11_pid1_anchor.c" "$here/m11_pid1_anchor.h" "$here/m11_anchor_linux.c" \
  "$here/m11_anchor_linux.h" "$here/m11_anchor_owner.c" "$here/m11_anchor_owner.h" \
  "$here/anchor_kernel_model.c" "$here/anchor_kernel_model.h" "$here/test_anchor_model.c" \
  "$here/test_anchor_process.c" "$here/test_anchor_root.c" "$here/fuzz_anchor.c" > "$out/anchor-inputs.sha256"
root=0
if sudo -n true 2>/dev/null; then root=1; fi
# Detection power: change exactly ONE line of a copy of the adapter; the same fuzz MUST report
# the matching invariant violation. The copy sits alone in its directory, so its quoted
# includes resolve through -I "$here" to the unchanged headers.
mutate() { # unit old new dir: copy unit.c with exactly one line deleted (new='') or replaced
  local unit="$1" old="$2" new="$3" dir="$4"
  mkdir -p "$dir"
  awk -v old="$old" -v new="$new" -v del="${new:+0}" '
    index($0, old) { n++; if (del == "0") print new; next } { print }
    END { if (n != 1) exit 3 }' "$here/$unit.c" > "$dir/$unit.c"
  if cmp -s "$here/$unit.c" "$dir/$unit.c"; then
    echo "ERROR: mutant of $unit changed nothing" >&2; exit 1
  fi
}
mutant() {
  local name="$1" old="$2" new="$3" expect="$4" dir="$out/mutant-anchor-$1-$mode"
  mutate m11_pid1_anchor "$old" "$new" "$dir"
  "$cc" "${flags[@]}" -I "$here" "$dir/m11_pid1_anchor.c" "$here/anchor_kernel_model.c" \
    "$here/fuzz_anchor.c" -o "$out/fuzz-anchor-mutant-$name-$mode"
  if "$out/fuzz-anchor-mutant-$name-$mode" 1 3000 60 > "$out/fuzz-anchor-mutant-$name-$mode.log" 2>&1; then
    echo "ERROR: anchor fuzz did not detect mutant $name" >&2; exit 1
  fi
  grep -m1 -E "$expect" "$out/fuzz-anchor-mutant-$name-$mode.log"
  echo "PASS anchor fuzz detects mutant $name ($mode)"
}
# Process-test mutants: one line deleted from the adapter or the backend; the real-process suite
# MUST fail on the named assertion.
# Real-process mutants: one line deleted from the adapter, the backend or the owner unit; the
# process suite (or, for rmutant, the root suite under sudo) MUST fail on an assertion.
xmutant() {
  local suite="$1" name="$2" unit="$3" old="$4" expect="$5" dir="$out/$1-mutant-anchor-$2-$mode"
  local srcs_=("$here/m11_pid1_anchor.c" "$here/m11_anchor_linux.c" "$here/m11_anchor_owner.c")
  mutate "$unit" "$old" '' "$dir"
  for i in "${!srcs_[@]}"; do [[ "${srcs_[$i]}" == "$here/$unit.c" ]] && srcs_[$i]="$dir/$unit.c"; done
  "$cc" "${flags[@]}" -I "$here" "${srcs_[@]}" "$here/test_anchor_$suite.c" -o "$out/anchor-$suite-mutant-$name-$mode"
  local run=("$out/anchor-$suite-mutant-$name-$mode")
  [[ "$suite" == root ]] && run=(sudo -n "${run[@]}")
  if "${run[@]}" > "$out/anchor-$suite-mutant-$name-$mode.log" 2>&1; then
    echo "ERROR: $suite suite did not detect mutant $name" >&2; exit 1
  fi
  grep -m1 -F 'Assertion' "$out/anchor-$suite-mutant-$name-$mode.log"
  grep -m1 -F -- "$expect" "$out/anchor-$suite-mutant-$name-$mode.log" # the intended reason
  echo "PASS $suite suite detects mutant $name ($mode)"
}
pmutant() { xmutant process "$1" "$2" "$3" "$4"; }
rmutant() {
  if [[ "$root" == 1 ]]; then xmutant root "$1" "$2" "$3" "$4"; else echo "SKIP root mutant $1 ($mode): no sudo"; fi
}
for mode in gcc clang sanitize; do
  cc=gcc
  flags=(-std=c11 -O1 -g -Wall -Wextra -Werror -DM11_OWNERSHIP_OFFLINE -I "$repair")
  if [[ "$mode" == clang ]]; then cc=clang; fi
  if [[ "$mode" == sanitize ]]; then flags+=(-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer); fi
  srcs=(); for unit in "${units[@]}"; do srcs+=("$repair/$unit.c"); done
  "$cc" "${flags[@]}" "${srcs[@]}" "$here/m11_custodian.c" "$here/m11_pid1_anchor.c" \
    "$here/anchor_kernel_model.c" "$here/test_anchor_model.c" -o "$out/anchor-model-$mode"
  "$out/anchor-model-$mode" | tee "$out/anchor-model-$mode.log"
  owner=("$here/m11_pid1_anchor.c" "$here/m11_anchor_linux.c" "$here/m11_anchor_owner.c")
  "$cc" "${flags[@]}" "${owner[@]}" "$here/test_anchor_process.c" -o "$out/anchor-process-$mode"
  "$out/anchor-process-$mode" | tee "$out/anchor-process-$mode.log"
  "$cc" "${flags[@]}" "${owner[@]}" "$here/test_anchor_root.c" -o "$out/anchor-root-$mode"
  if [[ "$root" == 1 ]]; then
    sudo -n "$out/anchor-root-$mode" | tee "$out/anchor-root-$mode.log"
  else
    echo "SKIP root P5 suite ($mode): passwordless sudo unavailable" | tee "$out/anchor-root-$mode.log"
  fi
  "$cc" "${flags[@]}" "$here/m11_pid1_anchor.c" "$here/anchor_kernel_model.c" "$here/fuzz_anchor.c" \
    -o "$out/fuzz-anchor-$mode"
  scen=3000; [[ "$mode" == sanitize ]] && scen=1500
  : > "$out/fuzz-anchor-$mode.log"
  for seed in 1 7 3735928559 11400714819323198485; do
    "$out/fuzz-anchor-$mode" "$seed" "$scen" 60 | tee -a "$out/fuzz-anchor-$mode.log"
  done
  mutant guard-alias 'a->guard_fd=a->anchor_fd<0 ? -1 : a->ops.dup_min(a->ops.ctx,fd,a->anchor_fd+1);' \
    '    a->guard_fd=a->anchor_fd;' \
    "anchor OFD released outside the adapter's final close"
  mutant final-census '/* sole holder: the second close is the last fput */' '' \
    'final close returned success but was not the last fput|final close granted while a second endpoint OFD existed'
  mutant lend-census '/* no other holder may share the loan */' '' \
    'loan granted while another process held the endpoint OFD|loan granted while a second endpoint OFD existed'
  pmutant no-seccomp m11_anchor_linux '/* worker seccomp confinement */' 'lend(&a,confined,'
  pmutant no-hygiene m11_anchor_linux '/* worker fd hygiene */' 'lend(&a,hygiene,'
  pmutant no-kcmp-census m11_pid1_anchor 'latch(a,M11_ANCHOR_LATCH_SECOND_OFD); foreign=true; continue;' \
    'a.latches & M11_ANCHOR_LATCH_SECOND_OFD'
  pmutant no-hidden-latch m11_pid1_anchor 'if (a->release==M11_RELEASE_NOT_OBSERVED) latch(' \
    'M11_ANCHOR_LATCH_HIDDEN_REFERENCE'
  pmutant shared-table m11_pid1_anchor 'if (a->ops.fd_table_shared) shared=' 'm11_anchor_lend_abort(&a) || !kcmp'
  pmutant no-owner-seal m11_anchor_owner '/* owner seal filter */' 'seal battery step 21'
  rmutant no-cap-drop m11_anchor_owner '/* P5: job capabilities */' 'job caps rc=0 status=10'
  rmutant no-unlink m11_anchor_owner '/* P5: no path left to a second OFD */' 'node path still present'
  rmutant inode-census m11_anchor_linux '/* census by device number */' 'control owner B exit 63'
done
# Same seed, same operation sequence under gcc and clang.
cmp "$out/fuzz-anchor-gcc.log" "$out/fuzz-anchor-clang.log"
echo 'PASS anchor fuzz logs identical under gcc and clang'
# Neither the adapter nor its Linux backend may compile outside offline qualification.
for unit in m11_pid1_anchor m11_anchor_linux m11_anchor_owner; do
  if gcc -std=c11 -I "$repair" -c "$here/$unit.c" -o "$out/forbidden-$unit.o" 2> "$out/physical-build-rejection-$unit.txt"; then
    echo "ERROR: offline compile gate bypassed for $unit" >&2; exit 1
  fi
  grep -F 'device integration is BLOCKED' "$out/physical-build-rejection-$unit.txt"
done
echo 'PASS offline compile boundary; anchor adapter not wired to the native runner or the real endpoint'
