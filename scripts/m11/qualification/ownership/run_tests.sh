#!/usr/bin/env bash
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repair="$here/../runtime-repair"
out="$(mkdir -p "$1" && cd "$1" && pwd)"
units=(m11_gpr_engine m11_shmem m11_apm_protocol m11_aw_protection m11_strict_mock)
# Baseline custodian bytes are committed fixtures pinned here by sha256, so the witnesses
# need no repository history (baselines/README.md names the source commits and
# verify_baselines.py proves the bytes equal them wherever that history exists).
#   round2         custodian reviewed in round 2
#   round3-pre-w1b custodian before the W1b fix (latched foreign traffic refused only
#                  the first retire)
(cd "$here/baselines" && sha256sum -c --strict --quiet - <<'EOF'
9a9b17f0b7e91a2e7521de9ae8443d87fab3773a5de861cb2a87e151b7af811f  round2/m11_custodian.c
ccdb77a60882ab1ce20ce8be548c3373e5f0d5e4f62fbd0acc011fcb7b09c49d  round2/m11_custodian.h
41f2ea525a9fc8a68326fdaf97671c74da676140a2afa304194e0db2c007635d  round3-pre-w1b/m11_custodian.c
3773b007e856c2caaa342f840dd918a2498bf5e86aade1754ec5469273edfa71  round3-pre-w1b/m11_custodian.h
EOF
)
# Each baseline is placed beside a copy of its witness so quoted includes resolve to the
# BASELINE header (quoted includes search the source directory first).
base="$out/baseline/ownership"; mkdir -p "$base"
cp "$here/baselines/round2/m11_custodian.c" "$here/baselines/round2/m11_custodian.h" "$base/"
cp "$here/witness_regressions.c" "$base/witness_regressions.c"
base2="$out/baseline-w1b/ownership"; mkdir -p "$base2"
cp "$here/baselines/round3-pre-w1b/m11_custodian.c" "$here/baselines/round3-pre-w1b/m11_custodian.h" "$base2/"
cp "$here/witness_w1b.c" "$here/fuzz_custodian.c" "$base2/"
sha256sum "$base/m11_custodian.c" "$base/m11_custodian.h" "$here/witness_regressions.c" \
  "$base2/m11_custodian.c" "$base2/m11_custodian.h" "$here/witness_w1b.c" "$here/fuzz_custodian.c" > "$out/witness-inputs.sha256"
# Optional W3: differential against VERBATIM pinned-ACK next_arg/parameq. Kernel sources are
# never committed; point M11_ACK_SRC at the SHA-pinned extracts to run it.
w3=0
if [[ -n "${M11_ACK_SRC:-}" ]]; then
  mkdir -p "$out/w3"; python3 -I "$here/gen_ack_ref.py" "$M11_ACK_SRC" "$out/w3/ack_ref.inc"; w3=1
else
  echo 'SKIP W3 cmdline differential: M11_ACK_SRC not set (pinned ACK sources are not in Git)'
fi
# Detection power for the rev-4/rev-5 rules: delete exactly one rule line from a copy of the
# current custodian; the same fuzz MUST report the matching violation (extended regex).
mutant() {
  local name="$1" line="$2" expect="$3" mut="$out/mutant-$1-$mode/ownership"
  mkdir -p "$mut"; cp "$here/m11_custodian.h" "$here/fuzz_custodian.c" "$mut/"
  grep -vF -- "$line" "$here/m11_custodian.c" > "$mut/m11_custodian.c" || true
  if [[ $(wc -l < "$here/m11_custodian.c") -ne $(( $(wc -l < "$mut/m11_custodian.c") + 1 )) ]]; then
    echo "ERROR: mutant $name did not remove exactly one line" >&2; exit 1
  fi
  "$cc" "${flags[@]}" "${srcs[@]}" "$mut/m11_custodian.c" "$mut/fuzz_custodian.c" -o "$out/fuzz-mutant-$name-$mode"
  if "$out/fuzz-mutant-$name-$mode" 1 3000 60 > "$out/fuzz-mutant-$name-$mode.log" 2>&1; then
    echo "ERROR: fuzz did not detect mutant $name" >&2; exit 1
  fi
  grep -E "$expect" "$out/fuzz-mutant-$name-$mode.log"
  echo "PASS fuzz detects mutant $name ($mode)"
}
for mode in gcc clang sanitize; do
  cc=gcc
  flags=(-std=c11 -O1 -g -Wall -Wextra -Werror -DM11_OWNERSHIP_OFFLINE -I "$repair")
  if [[ "$mode" == clang ]]; then cc=clang; fi
  if [[ "$mode" == sanitize ]]; then flags+=(-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer); fi
  srcs=(); for unit in "${units[@]}"; do srcs+=("$repair/$unit.c"); done
  "$cc" "${flags[@]}" "${srcs[@]}" "$here/m11_custodian.c" "$here/test_custodian.c" -o "$out/custodian-$mode"
  "$out/custodian-$mode" | tee "$out/custodian-$mode.log"
  "$cc" "${flags[@]}" "${srcs[@]}" "$here/m11_custodian.c" "$here/test_process_lifetime.c" -o "$out/process-$mode"
  "$out/process-$mode" | tee "$out/process-$mode.log"
  # Before/after witness: identical witness bytes, baseline vs current custodian.
  "$cc" "${flags[@]}" "${srcs[@]}" "$base/m11_custodian.c" "$base/witness_regressions.c" -o "$out/witness-baseline-$mode"
  "$out/witness-baseline-$mode" baseline | tee "$out/witness-baseline-$mode.log"
  "$cc" "${flags[@]}" "${srcs[@]}" "$here/m11_custodian.c" "$here/witness_regressions.c" -o "$out/witness-fixed-$mode"
  "$out/witness-fixed-$mode" fixed | tee "$out/witness-fixed-$mode.log"
  "$cc" "${flags[@]}" "${srcs[@]}" "$base2/m11_custodian.c" "$base2/witness_w1b.c" -o "$out/witness-w1b-baseline-$mode"
  "$out/witness-w1b-baseline-$mode" baseline | tee "$out/witness-w1b-baseline-$mode.log"
  "$cc" "${flags[@]}" "${srcs[@]}" "$here/m11_custodian.c" "$here/witness_w1b.c" -o "$out/witness-w1b-fixed-$mode"
  "$out/witness-w1b-fixed-$mode" fixed | tee "$out/witness-w1b-fixed-$mode.log"
  # Adversarial matrices: W1 UNMAP-at-transmit probe x graph setup x event; W2 clock sweep.
  "$cc" "${flags[@]}" "${srcs[@]}" "$here/m11_custodian.c" "$here/adv_w1.c" -o "$out/adv-w1-$mode"
  "$out/adv-w1-$mode" > "$out/adv-w1-$mode.log"; grep -E '^(SUMMARY|MINIMAL|PASS)' "$out/adv-w1-$mode.log"
  "$cc" "${flags[@]}" "${srcs[@]}" "$here/m11_custodian.c" "$here/adv_w2.c" -o "$out/adv-w2-$mode"
  "$out/adv-w2-$mode" > "$out/adv-w2-$mode.log"; grep -E '^(SUMMARY|PASS)' "$out/adv-w2-$mode.log"
  if [[ "$w3" == 1 ]]; then
    "$cc" "${flags[@]}" -I "$out/w3" "${srcs[@]}" "$here/m11_custodian.c" "$here/w3_cmdline_diff.c" -o "$out/w3-$mode"
    n=2000000; [[ "$mode" == sanitize ]] && n=300000
    "$out/w3-$mode" "$n" 12345 > "$out/w3-$mode.log"; grep -E '^(FIXED|DIFF|KERNEL-UB|PASS)' "$out/w3-$mode.log"
  fi
  # Detection power: the same fuzz against the pre-W1b custodian MUST report the violation.
  "$cc" "${flags[@]}" "${srcs[@]}" "$base2/m11_custodian.c" "$base2/fuzz_custodian.c" -o "$out/fuzz-w1b-baseline-$mode"
  if "$out/fuzz-w1b-baseline-$mode" 1 3000 60 > "$out/fuzz-w1b-baseline-$mode.log" 2>&1; then
    echo 'ERROR: fuzz did not detect the pre-W1b UNMAP-after-latch defect' >&2; exit 1
  fi
  # W1b shows as either form: the retire after the latch transmits UNMAP (DSP-mapped
  # region) or succeeds without one (region never DSP-mapped). Both are the defect.
  grep -E 'UNMAP transmitted after FOREIGN_TRAFFIC/GRAPH_UNKNOWN was latched|retire succeeded after the FOREIGN/GRAPH_UNKNOWN latch' \
    "$out/fuzz-w1b-baseline-$mode.log"
  echo "PASS fuzz detects the pre-W1b defect ($mode)"
  # Rev 5 (post-MAP hold, docs/m11-argon-cp2-c5-hold-design.md). The rev-4 one-shot rule (no MAP
  # after an UNMAP) stays in the custodian but is unreachable: no UNMAP is ever sent after a MAP
  # intent, so its mutant can no longer be told apart and is not run. The rev-4 reboot rule
  # became the unconditional retaining rule below.
  mutant reboot 'if (b->dsp_map_attempted) return M11_TERMINAL_RESET_RETAINING_ANCHORS;' \
    'post-MAP hold: terminal not retaining after a MAP intent'
  mutant retire-guard 'if (!c->boot || c->boot->dsp_map_attempted) return -EPERM;' \
    'post-MAP hold: (UNMAP transmitted|retire not refused) after a MAP intent'
  mutant close-guard 'if (c->boot->dsp_map_attempted) return -EPERM;' \
    'post-MAP hold: close not refused after a MAP intent'
  # Bounded seeded state-machine fuzz against mock ground truth.
  "$cc" "${flags[@]}" "${srcs[@]}" "$here/m11_custodian.c" "$here/fuzz_custodian.c" -o "$out/fuzz-$mode"
  scen=3000; [[ "$mode" == sanitize ]] && scen=1500
  for seed in 1 7 3735928559 11400714819323198485; do
    "$out/fuzz-$mode" "$seed" "$scen" 60 | tee -a "$out/fuzz-$mode.log"
  done
done
# Same seed, same operation sequence under gcc and clang (every draw is its own statement).
cmp "$out/fuzz-gcc.log" "$out/fuzz-clang.log"
echo 'PASS fuzz logs identical under gcc and clang'
# Prove this library cannot silently compile as a physical adapter.
if gcc -std=c11 -I "$repair" -c "$here/m11_custodian.c" -o "$out/forbidden.o" 2> "$out/physical-build-rejection.txt"; then
  echo 'ERROR: qualification-only compile gate was bypassed' >&2; exit 1
fi
grep -F 'device integration is BLOCKED' "$out/physical-build-rejection.txt"
echo 'PASS offline compile boundary; no hardware integration or recovery adapter'
