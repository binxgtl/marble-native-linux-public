#!/usr/bin/env bash
# Run24 runner suite, offline: static structure checks; shell syntax of the Run24 shell inputs;
# the Run24 runner links (gcc, clang, gcc ASan+UBSan) and refuses to act outside PID1; the actual
# runner control flow with every boundary replaced and the REAL terminal core linked (gcc, clang);
# one-line mutants that must fail
# for a named reason. The anchor-native suite (stand-in GET_SPF_STATE, census, worker
# confinement) runs separately (scripts/m11/anchor-native/test.sh). No hardware.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../../.." && pwd)"
rt="$root/scripts/m11/runtime"
own="$root/scripts/m11/qualification/ownership"
native="$root/scripts/m11/anchor-native"
out="$(mkdir -p "$1" && cd "$1" && pwd)"
anchor=("$own/m11_pid1_anchor.c" "$own/m11_anchor_linux.c" "$own/m11_anchor_owner.c")
sha256sum "$here"/runner.c "$here"/test-runner.c "$here"/test-static.py "$here"/test.sh \
  "$here"/control "$here"/usb "$here"/init "$here"/amp-gate "$native"/gpr_linux.c "$native"/audio_runtime.c "$native"/journal_time.h "$native"/terminal_core.c "$native"/terminal_core.h \
  "${anchor[@]}" > "$out/inputs.sha256"

python3 "$here/test-static.py" | tee "$out/static.log"
for f in init control usb amp-gate; do bash -n "$here/$f"; done
bash -n "$root/scripts/m11/run19/amp-switch"; bash -n "$root/scripts/m11/run16/prepare"
echo 'PASS Run24 shell inputs parse (init, control, usb, amp-gate; amp-switch and prepare unchanged)'

build() { # name output [file-to-replace replacement-path]
  local name="$1" output="$2" from="${3:-}" to="${4:-}" srcs=()
  case "$name" in
    runner) srcs=("$here/runner.c" "$native/gpr_linux.c" "$native/audio_runtime.c" "$rt/gpr_native.c"
                  "$rt/gpr_encode.c" "$rt/audio_pd.c" "$rt/audio_encode.c" "$native/terminal_core.c" "${anchor[@]}");;
    test-runner) srcs=("$here/test-runner.c" "$native/terminal_core.c" "$rt/gpr_encode.c" "$rt/audio_encode.c");;
  esac
  local extra=() inc=(-I "$here")
  if [[ -n "$from" ]]; then
    for i in "${!srcs[@]}"; do [[ "${srcs[$i]}" == "$here/$from" ]] && srcs[$i]="$to"; done
    inc=(-I "$(dirname "$to")" -I "$here")
  fi
  if [[ "$name" == test-runner ]]; then
    for w in getpid umask fork waitpid poll clock_gettime open read write close lstat fstat mknod fopen pipe2 unlink reboot _exit; do
      extra+=("-Wl,--wrap=$w")
    done
  fi
  "$cc" "${flags[@]}" "${inc[@]}" -I "$native" -I "$rt" -I "$own" "${srcs[@]}" "${extra[@]}" -o "$output"
}
mutate() { # file old new dir: copy file with exactly one line deleted (new='') or replaced
  local file="$1" old="$2" new="$3" dir="$4"
  mkdir -p "$dir"
  awk -v old="$old" -v new="$new" -v del="${new:+0}" '
    index($0, old) { n++; if (del == "0") print new; next } { print }
    END { if (n != 1) exit 3 }' "$here/$file" > "$dir/$file"
  if cmp -s "$here/$file" "$dir/$file"; then echo "ERROR: mutant of $file changed nothing" >&2; exit 1; fi
}
nmutant() { # name old new expect: a runner.c mutant must fail the control-flow test
  local name="$1" old="$2" new="$3" expect="$4" dir="$out/mutant-$1-$mode"
  mutate runner.c "$old" "$new" "$dir"
  cp "$here/test-runner.c" "$dir/test-runner.c"
  build test-runner "$out/mutant-$name-$mode.bin" test-runner.c "$dir/test-runner.c"
  if timeout 120 "$out/mutant-$name-$mode.bin" > "$out/mutant-$name-$mode.log" 2>&1; then
    echo "ERROR: Run24 suite did not detect mutant $name" >&2; exit 1
  fi
  grep -m1 -F -- "$expect" "$out/mutant-$name-$mode.log"
  echo "PASS Run24 suite detects mutant $name ($mode)"
}

for mode in gcc clang sanitize; do
  cc=gcc
  flags=(-std=c11 -O1 -g -Wall -Wextra -Werror -DM11_ANCHOR_NATIVE -DM11_ANCHOR_NATIVE_ION)
  if [[ "$mode" == clang ]]; then cc=clang; fi
  if [[ "$mode" == sanitize ]]; then flags+=(-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer); fi
  build runner "$out/runner-$mode"
  set +e; "$out/runner-$mode"; rc=$?; set -e
  if [[ "$rc" != 2 ]]; then echo "ERROR: Run24 runner did not refuse to act outside PID1 (rc=$rc)" >&2; exit 1; fi
  echo "PASS Run24 runner links ($mode) and returns 2 outside PID1"
  # The control-flow test longjmps out of wrapped syscalls and a signal handler; no sanitizers.
  [[ "$mode" == sanitize ]] && continue
  build test-runner "$out/test-runner-$mode"
  timeout 300 "$out/test-runner-$mode" | tee "$out/test-runner-$mode.log"
  # (awk -v expands backslash escapes: patterns avoid them; the gate stays referenced so
  # -Werror=unused-function cannot mask the mutant.)
  nmutant no-amp-gate 'if (amp_gate()) hold(' '    if (0 && amp_gate()) hold("mutant");' 'gate>=0 && gate<spawn'
  nmutant amp-gate-ignored 'return strcmp(result,"switches-disabled' '    return 0;' 'spawn<0 && bind<0'
  nmutant no-fatal-record 'kmsg_line(b,strlen(b));' '    (void)b;' 'fatal_logged'
  nmutant no-anchor-crumb 'crumb("anchor_bind");' '' 'last_crumb(),"anchor_bind"'
  nmutant no-seal 'if (m11_anchor_owner_seal_pairs(pairs,nodes,2))' '            (void)pairs; (void)nodes;' 'ion==&ion_anchor && sealed'
  # Run24 terminal observation: the owned path must exit holding both anchors, never reboot or
  # final-close; captures read their sources; the IOMMU helper never forks from sealed PID1.
  nmutant reboot-instead-of-exit '_exit(0); /* PID1 dies holding BOTH anchors' '        (void)reboot(RB_AUTOBOOT);' 'last_crumb(),"reboot"'
  nmutant final-close-on-owned 'held=1; color=qrc?"red":"green";' '            (void)m11_anchor_final_close(&anchor); held=1; color=qrc?"red":"green";' 'at("final_close")<0'
  nmutant iommu-via-fork 'int rc=spawned(JOB_CONTROL,"iommu_capture",15000);' '    int rc=job("/m11/control","iommu_capture",15000);' 'forks_after_seal'
  nmutant no-cmdline-capture 'if (capture_cmdline()) hold(' '        if (0 && capture_cmdline()) hold("mutant");' 'open_cmdline'
  nmutant no-terminal-enroll 'crumb("terminal_enroll");' '' 'crumb_at("terminal_enroll")'
  nmutant no-exit-usb-grace 'hold("USB teardown before the forced exit failed")' '' 'usb>at("spawn:seal")'
  nmutant no-ion-unlink 'if (unlink("/dev/msm_audio_ion"))' '' 'unlinked_ion>=0'
  nmutant no-ion-worker-drop 'if (m11_gpr_anchor_attach(&anchor,&diagnostic.fd,1) || m11_gpr_anchor_attach_ion' \
    '            if (m11_gpr_anchor_attach(&anchor,&diagnostic.fd,1))' 'at("loan_setup_ion")>at("loan_setup")'
  nmutant no-ion-crumb 'crumb("ion_bind");' '' 'last_crumb(),"ion_bind"'
  nmutant open-without-pdr-up 'if (!pdrc) { /* PDR qualified UP' '        if (1) {' 'pd_up'
done
echo 'PASS Run24 runner suite (offline; not a candidate; not hardware-qualified)'
