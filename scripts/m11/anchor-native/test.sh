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
# Cross-check: over the never-mapped state space (terminal decisions and the cmdline gate) the
# native terminal core decides a boot's end IDENTICALLY to the CI-qualified offline custodian,
# both linked into one program in offline mode. The custodian's post-MAP hold (rev 5) lies
# outside that space (a mapped boot always ends retaining; Run24 never maps).
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
# CP2 criterion 5, post-MAP hold (docs/m11-argon-cp2-c5-hold-design.md): the REAL custodian (L1) and
# region manager (L3) against the strict mock, offline only. One mutant per layer guard below.
for pmh_mode in gcc clang sanitize; do
  pmh_cc=gcc
  pmh_flags=(-std=c11 -O1 -g -Wall -Wextra -Werror -DM11_OWNERSHIP_OFFLINE -I "$own" -I "$repair" -I "$here")
  [[ "$pmh_mode" == clang ]] && pmh_cc=clang
  [[ "$pmh_mode" == sanitize ]] && pmh_flags+=(-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer)
  pmh_srcs=(); for u in "${tc_units[@]}"; do pmh_srcs+=("$repair/$u.c"); done
  "$pmh_cc" "${pmh_flags[@]}" "${pmh_srcs[@]}" "$own/m11_custodian.c" "$here/test-post-map-hold.c" -o "$out/post-map-hold-$pmh_mode"
  "$out/post-map-hold-$pmh_mode" | tee "$out/post-map-hold-$pmh_mode.log"
done
echo 'PASS post-MAP hold layers (gcc, clang, ASan+UBSan)'
pmh_mutant() { # name custodian|shmem pattern replacement assertion last-pass (same detection rule as gtn_mutant)
  local name="$1" which="$2" pat="$3" rep="$4" want="$5" last="$6" dir="$out/pmh-mutant-$1" rc=0 got src file
  case "$which" in
    custodian) src="$own/m11_custodian.c" ;;
    shmem) src="$repair/m11_shmem.c" ;;
    *) echo "ERROR: post-MAP hold mutant $name: unknown file $which" >&2; exit 1 ;;
  esac
  file="$(basename "$src")"
  mkdir -p "$dir"
  awk -v pat="$pat" -v rep="$rep" 'index($0,pat){n++; print rep; next} {print} END{if(n!=1) exit 3}' "$src" > "$dir/$file"
  local srcs=() u
  for u in "${tc_units[@]}"; do [[ "$u.c" == "$file" ]] && srcs+=("$dir/$file") || srcs+=("$repair/$u.c"); done
  [[ "$file" == m11_custodian.c ]] && srcs+=("$dir/$file") || srcs+=("$own/m11_custodian.c")
  gcc -std=c11 -O1 -g -Wall -Wextra -Werror -DM11_OWNERSHIP_OFFLINE -I "$own" -I "$repair" -I "$here" \
    "${srcs[@]}" "$here/test-post-map-hold.c" -o "$dir/bin"
  timeout 120 "$dir/bin" > "$dir/log" 2>&1 || rc=$?
  got="$(grep '^PASS ' "$dir/log" | tail -n1 || true)"
  if [[ "$rc" != 134 ]] || ! grep -qF -- "Assertion \`$want' failed" "$dir/log" || [[ "$got" != "$last" ]]; then
    echo "ERROR: post-MAP hold mutant $name not detected for the expected reason (rc=$rc, last PASS: '${got}')" >&2
    cat "$dir/log" >&2; exit 1
  fi
  echo "PASS post-MAP hold test detects mutant $name: Assertion \`$want'"
}
# M1 (L1): retire reaches the legacy UNMAP body. The L3 choke point still refuses the release
# (so retire even returns -EPERM), but the UNMAP went on the wire.
pmh_mutant retire-guard-removed custodian 'if (!c->boot || c->boot->dsp_map_attempted) return -EPERM;' '    (void)0;' \
  'mock.unmap_cmd_count == 0 && mock.tx_pkt_count == tx0' \
  'PASS P1 never-mapped boot unchanged: retire -EINVAL, HOLD while open, one close, then ORDERLY_SHUTDOWN'
# M2 (L1): close after a MAP intent falls to the legacy checks (-EBUSY with a region open).
pmh_mutant close-guard-removed custodian 'if (c->boot->dsp_map_attempted) return -EPERM;' '    (void)0;' \
  'm11_custodian_close(&c) == -EPERM' \
  'PASS T1 retire after a MAP ACK is refused at the custodian: no UNMAP on the wire, nothing released, no taint'
# M3 (L1): a clean mapped boot is HOLD again (waits for a teardown that can never come).
pmh_mutant terminal-rule-removed custodian 'if (b->dsp_map_attempted) return M11_TERMINAL_RESET_RETAINING_ANCHORS;' '    (void)0;' \
  'final_action(a)' \
  'PASS T2 close after a MAP intent is refused: the endpoint last-close never runs'
# M5 (L3): an in-flight MAP NACK is not held as OWNERSHIP_UNRESOLVED (it tries the release).
pmh_mutant nack-releases shmem 'mark_unresolved(mgr, out_region, M11_SHMEM_CAUSE_MAP_NACK, rc, M11_SHMEM_ORPHAN_NONE, 0u, B_MAP_NACK);' \
  '            out_region->remote_inactive = true; (void)release_local_handles(mgr, out_region);' \
  'r->state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED && r->cause != M11_SHMEM_CAUSE_NONE' \
  'PASS T3 every mapped state (clean, worker exit, PD down, global cleanup, owner exit, supervisor exit, deadline) ends retaining; retire and close refused'
# M6 (L3): a late MAP NACK through reconcile tries the release.
pmh_mutant late-nack-releases shmem 'return -EREMOTEIO; /* late MAP NACK: held */' \
  '            region->remote_inactive = true; return release_local_handles(mgr, region);' \
  'lrc == -EREMOTEIO' \
  'PASS T5 post-TX MAP failures (NACK, write error, delivered then error, short write, lost response, no handle, PDR) keep backing and ownership'
# M7 (L3): the single release choke point removed: the UNMAP research path releases after its ACK.
pmh_mutant choke-point-removed shmem 'if (region->map_tx_started && !region->map_tx_unsent_proof) return -EPERM;' '    (void)0;' \
  'urc == -EPERM && r->state == M11_SHMEM_STATE_DSP_UNMAP_ACKNOWLEDGED && held(r) && mock_held()' \
  'PASS T6 a late MAP NACK through reconcile is held (OWNERSHIP_UNRESOLVED, cause MAP_NACK)'
# M8 (L3): MAP_TX_STARTED never set (the choke point would see an untransmitted region).
pmh_mutant tx-started-not-set shmem 'out_region->map_tx_started = true;' '    (void)0;' \
  'c.regions[i].state == M11_SHMEM_STATE_DSP_MAP_ACKNOWLEDGED && c.regions[i].map_tx_started && !c.regions[i].map_tx_unsent_proof' \
  'PASS P1 never-mapped boot unchanged: retire -EINVAL, HOLD while open, one close, then ORDERLY_SHUTDOWN'
# M9 (L3): the unsent proof forged on a write error (write_fn was entered).
pmh_mutant proof-forged shmem 'm11_shmem_cause_t cause = M11_SHMEM_CAUSE_MAP_WRITE_ERROR;' \
  '        out_region->map_tx_unsent_proof = true; m11_shmem_cause_t cause = M11_SHMEM_CAUSE_MAP_WRITE_ERROR;' \
  'r->map_tx_started && !r->map_tx_unsent_proof' \
  'PASS T3 every mapped state (clean, worker exit, PD down, global cleanup, owner exit, supervisor exit, deadline) ends retaining; retire and close refused'
# M10 (L3): the unsent proof never set: a proven pre-TX failure would leak the backing (C1).
pmh_mutant proof-never-set shmem 'out_region->map_tx_unsent_proof = true;' '            (void)0;' \
  'pre.map_tx_started && pre.map_tx_unsent_proof && pre.state == M11_SHMEM_STATE_RELEASED' \
  'PASS T7 UNMAP research path (driven directly): ACK, late ACK and LOCAL_RELEASE_PENDING never release a transmitted region'
# G1 (docs/m11-custodian-native-integration.md): the reviewed M11_CUSTODIAN_NATIVE build mode. It
# selects the build only (no native backend yet); custodian, anchor and terminal core share one
# terminal enum and one boot ledger.
cm_flags=(-std=c11 -O1 -Wall -Wextra -Werror -DM11_ANCHOR_NATIVE -DM11_CUSTODIAN_NATIVE -I "$own" -I "$repair" -I "$here")
tc_srcs=(); for u in "${tc_units[@]}"; do tc_srcs+=("$repair/$u.c"); done
for cm_cc in gcc clang; do
  "$cm_cc" "${cm_flags[@]}" "${tc_srcs[@]}" "$own/m11_custodian.c" "$here/terminal_core.c" "$here/test-custodian-mode.c" -o "$out/custodian-mode-$cm_cc"
  "$out/custodian-mode-$cm_cc" | tee "$out/custodian-mode-$cm_cc.log"
  head -n 1 "$out/custodian-mode-$cm_cc.log" | cmp - "$out/enum-offline.txt"
done
echo 'PASS M11_CUSTODIAN_NATIVE builds and links (one enum and ledger; enum identical to the offline build)'
custodian_refused() { # label flags...: compiling m11_custodian.c with these flags must fail
  local label="$1"; shift
  if gcc -std=c11 "$@" -I "$own" -I "$repair" -c "$own/m11_custodian.c" -o "$out/custodian-refused.o" 2> "$out/custodian-refused-$label.txt"; then
    echo "ERROR: custodian compiled with $label" >&2; exit 1
  fi
}
custodian_refused no-mode
grep -qF 'device integration is BLOCKED' "$out/custodian-refused-no-mode.txt"
custodian_refused native-without-anchor -DM11_CUSTODIAN_NATIVE
custodian_refused offline-and-native -DM11_OWNERSHIP_OFFLINE -DM11_CUSTODIAN_NATIVE -DM11_ANCHOR_NATIVE
custodian_refused anchor-native-alone -DM11_ANCHOR_NATIVE
echo 'PASS custodian refused with no mode, native without anchor-native, both modes, or anchor-native alone'
# No never-mapped candidate build may select the native custodian.
for f in "$root"/scripts/m11/run2[0-4]/build.sh "$root"/scripts/m11/run2[0-4]/stage.py "$here/runner.c"; do
  if [[ -f "$f" ]] && grep -qF M11_CUSTODIAN_NATIVE "$f"; then
    echo "ERROR: candidate input $f selects M11_CUSTODIAN_NATIVE" >&2; exit 1
  fi
done
echo 'PASS no candidate build input (run20-run24 build.sh/stage.py, anchor-native runner) selects M11_CUSTODIAN_NATIVE'
# G2: the native GPR transport over the endpoint anchor, driven by the REAL engine against a
# SOCK_SEQPACKET stand-in peer (no device).
gtn_srcs=("${tc_srcs[@]}" "$here/gpr_transport_native.c" "$here/test-gpr-transport-native.c")
for cm_cc in gcc clang; do
  "$cm_cc" "${cm_flags[@]}" "${gtn_srcs[@]}" -o "$out/gpr-transport-native-$cm_cc"
  timeout 120 "$out/gpr-transport-native-$cm_cc" | tee "$out/gpr-transport-native-$cm_cc.log"
done
gcc "${cm_flags[@]}" -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer \
  "${gtn_srcs[@]}" -o "$out/gpr-transport-native-sanitize"
timeout 120 "$out/gpr-transport-native-sanitize" | tee "$out/gpr-transport-native-sanitize.log"
if gcc -std=c11 -DM11_ANCHOR_NATIVE -I "$own" -I "$repair" -c "$here/gpr_transport_native.c" -o "$out/gtn-refused.o" 2>/dev/null; then
  echo "ERROR: gpr_transport_native compiled outside M11_CUSTODIAN_NATIVE" >&2; exit 1
fi
echo 'PASS G2 transport (gcc, clang, ASan+UBSan) and refused outside M11_CUSTODIAN_NATIVE'
gtn_mutant() { # name pattern replacement assertion last-pass
  # A transport mutant counts as detected only if the stand-in test aborts (SIGABRT from assert,
  # status 134; never a timeout, crash or build error) on the named assertion, after exactly the
  # expected sections passed ("" = it must fail in the first section).
  local name="$1" pat="$2" rep="$3" want="$4" last="$5" dir="$out/gtn-mutant-$1" rc=0 got
  mkdir -p "$dir"
  awk -v pat="$pat" -v rep="$rep" 'index($0,pat){n++; print rep; next} {print} END{if(n!=1) exit 3}' \
    "$here/gpr_transport_native.c" > "$dir/gpr_transport_native.c"
  cp "$here/gpr_transport_native.h" "$dir/"
  gcc "${cm_flags[@]}" -I "$dir" "${tc_srcs[@]}" "$dir/gpr_transport_native.c" "$here/test-gpr-transport-native.c" -o "$dir/bin"
  timeout 120 "$dir/bin" > "$dir/log" 2>&1 || rc=$?
  got="$(grep '^PASS ' "$dir/log" | tail -n1 || true)"
  if [[ "$rc" != 134 ]] || ! grep -qF -- "Assertion \`$want' failed" "$dir/log" || [[ "$got" != "$last" ]]; then
    echo "ERROR: G2 mutant $name not detected for the expected reason (rc=$rc, last PASS: '${got}')" >&2
    cat "$dir/log" >&2; exit 1
  fi
  echo "PASS G2 test detects mutant $name: Assertion \`$want'"
}
gtn_mutant close-in-detach 'never closed here' '    (void)close(fd);' \
  'fcntl(r.sv[0], F_GETFD) != -1' ''
gtn_mutant no-held-check 'a->state != M11_ANCHOR_HELD' '    if (!a || a->anchor_fd < 0) {' \
  'm11_gpr_engine_open(&r.eng) == -EBADF' \
  'PASS peer EOF and a write after hangup are transport errors (-EPIPE), not timeouts'
# G3: the native shmem backend against fixture syscalls (memfd dma-bufs, a recorded ION fd list),
# then the REAL region manager and engine over the G2 transport with a SEQPACKET peer answering
# MAP/UNMAP (no device, no driver; the ION ioctl numbers reach only the fixture).
g3_srcs=("${tc_srcs[@]}" "$here/gpr_transport_native.c" "$here/shmem_backend_native.c" "$here/test-shmem-backend-native.c")
for cm_cc in gcc clang; do
  "$cm_cc" "${cm_flags[@]}" "${g3_srcs[@]}" -o "$out/shmem-backend-native-$cm_cc"
  timeout 120 "$out/shmem-backend-native-$cm_cc" | tee "$out/shmem-backend-native-$cm_cc.log"
done
gcc "${cm_flags[@]}" -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer \
  "${g3_srcs[@]}" -o "$out/shmem-backend-native-sanitize"
timeout 120 "$out/shmem-backend-native-sanitize" | tee "$out/shmem-backend-native-sanitize.log"
if gcc -std=c11 -DM11_ANCHOR_NATIVE -I "$own" -I "$repair" -c "$here/shmem_backend_native.c" -o "$out/sbn-refused.o" 2>/dev/null; then
  echo "ERROR: shmem_backend_native compiled outside M11_CUSTODIAN_NATIVE" >&2; exit 1
fi
echo 'PASS G3 shmem backend (gcc, clang, ASan+UBSan) and refused outside M11_CUSTODIAN_NATIVE'
g3_mutant() { # name pattern replacement assertion last-pass (same detection rule as gtn_mutant)
  local name="$1" pat="$2" rep="$3" want="$4" last="$5" dir="$out/sbn-mutant-$1" rc=0 got
  mkdir -p "$dir"
  awk -v pat="$pat" -v rep="$rep" 'index($0,pat){n++; print rep; next} {print} END{if(n!=1) exit 3}' \
    "$here/shmem_backend_native.c" > "$dir/shmem_backend_native.c"
  cp "$here/shmem_backend_native.h" "$dir/"
  gcc "${cm_flags[@]}" -I "$dir" "${tc_srcs[@]}" "$here/gpr_transport_native.c" "$dir/shmem_backend_native.c" \
    "$here/test-shmem-backend-native.c" -o "$dir/bin"
  timeout 120 "$dir/bin" > "$dir/log" 2>&1 || rc=$?
  got="$(grep '^PASS ' "$dir/log" | tail -n1 || true)"
  if [[ "$rc" != 134 ]] || ! grep -qF -- "Assertion \`$want' failed" "$dir/log" || [[ "$got" != "$last" ]]; then
    echo "ERROR: G3 mutant $name not detected for the expected reason (rc=$rc, last PASS: '${got}')" >&2
    cat "$dir/log" >&2; exit 1
  fi
  echo "PASS G3 test detects mutant $name: Assertion \`$want'"
}
g3_mutant hyp-allowed 'never issues 0x4004616D' '    (void)hyp_assign;' \
  'b.ion_import_fd_fn(b.user, fd, true) == -EPERM' \
  'PASS alloc/mmap/sync/import/unimport/munmap/close round trip on a memfd-backed fixture'
g3_mutant close-while-busy 'if (b->vaddr || b->imported) { l->refused++; return -EBUSY; }' '    (void)0;' \
  'b.close_fd_fn(b.user, fd) == -EBUSY && fd_open(fd)' \
  'PASS foreign fd numbers refused before any syscall'
g3_mutant no-ion-anchor-check 'a->state != M11_ANCHOR_HELD' '    if (!a || a->anchor_fd < 0) {' \
  'b.ion_unmap_fd_fn(b.user, fd, false) == -EBADF' \
  'PASS close refused while mmapped or imported'
g3_mutant close-error-surfaced 'l->close_errors++; l->last_close_errno = errno;' '    if (l->sys->close_fn(fd) < 0) return -errno;' \
  'b.close_fd_fn(b.user, fd) == 0' \
  'PASS ION I/O refused unless the ION anchor is HELD by this process'
# G4: PID1's /dev/dma_heap/system node over a fake sysfs/procfs tree and a scratch /dev directory
# (no dma-heap driver). Unprivileged it covers metadata, census and every refusal; as root (sudo)
# it makes a real character node carrying /dev/full's number as the heap stand-in.
g4_srcs=("$here/heap_node_native.c" "$here/test-heap-node-native.c")
for cm_cc in gcc clang; do
  "$cm_cc" "${cm_flags[@]}" "${g4_srcs[@]}" -o "$out/heap-node-native-$cm_cc"
  timeout 120 "$out/heap-node-native-$cm_cc" "$out" | tee "$out/heap-node-native-$cm_cc.log"
done
gcc "${cm_flags[@]}" -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer \
  "${g4_srcs[@]}" -o "$out/heap-node-native-sanitize"
timeout 120 "$out/heap-node-native-sanitize" "$out" | tee "$out/heap-node-native-sanitize.log"
if [[ "$sudo_ok" == 1 ]]; then
  timeout 120 sudo -n "$out/heap-node-native-gcc" "$out" | tee "$out/heap-node-native-root.log"
  grep -qF 'PASS G4 heap node (root sections)' "$out/heap-node-native-root.log"
else
  # CI must exercise the root sections; only a local run without sudo may skip them.
  if [[ -n "${CI:-}" ]]; then echo "ERROR: G4 root sections need sudo in CI" >&2; exit 1; fi
  echo "SKIP G4 root sections: no sudo"
fi
if gcc -std=c11 -DM11_ANCHOR_NATIVE -I "$own" -I "$repair" -c "$here/heap_node_native.c" -o "$out/hnn-refused.o" 2>/dev/null; then
  echo "ERROR: heap_node_native compiled outside M11_CUSTODIAN_NATIVE" >&2; exit 1
fi
echo 'PASS G4 heap node (gcc, clang, ASan+UBSan, root when sudo) and refused outside M11_CUSTODIAN_NATIVE'
g4_mutant() { # name asroot pattern replacement assertion last-pass (same detection rule as gtn_mutant)
  local name="$1" asroot="$2" pat="$3" rep="$4" want="$5" last="$6" dir="$out/hnn-mutant-$1" rc=0 got
  if [[ "$asroot" == 1 && "$sudo_ok" != 1 ]]; then echo "SKIP G4 mutant $name: no sudo"; return; fi
  mkdir -p "$dir"
  awk -v pat="$pat" -v rep="$rep" 'index($0,pat){n++; print rep; next} {print} END{if(n!=1) exit 3}' \
    "$here/heap_node_native.c" > "$dir/heap_node_native.c"
  cp "$here/heap_node_native.h" "$dir/"
  gcc "${cm_flags[@]}" -I "$dir" "$dir/heap_node_native.c" "$here/test-heap-node-native.c" -o "$dir/bin"
  if [[ "$asroot" == 1 ]]; then
    timeout 120 sudo -n "$dir/bin" "$dir" > "$dir/log" 2>&1 || rc=$?
    sudo -n rm -rf "$dir"/m11-heap-* # an aborted root run leaves its root-owned scratch tree
  else
    timeout 120 "$dir/bin" "$dir" > "$dir/log" 2>&1 || rc=$?
    rm -rf "$dir"/m11-heap-*
  fi
  got="$(grep '^PASS ' "$dir/log" | tail -n1 || true)"
  if [[ "$rc" != 134 ]] || ! grep -qF -- "Assertion \`$want' failed" "$dir/log" || [[ "$got" != "$last" ]]; then
    echo "ERROR: G4 mutant $name not detected for the expected reason (rc=$rc, last PASS: '${got}')" >&2
    cat "$dir/log" >&2; exit 1
  fi
  echo "PASS G4 test detects mutant $name: Assertion \`$want'"
}
g4_mutant devname-substring 0 'if (strncmp(b, HEAP_DEVNAME' '    if (!strstr(b, HEAP_DEVNAME))' \
  'meta_with_uevent(XDEV) == -ENODEV' \
  'PASS metadata: exact MAJ:MIN, DEVNAME=dma_heap/system by number, one dma_heap character major'
g4_mutant census-allows-dup 0 'fds[i] == heap_fd && !seen' '        if (heap_fd >= 0 && fds[i] == heap_fd) seen = 1;' \
  'm11_census_pid1_heap(f3, r2, 2, H, 5) == -1' \
  'PASS metadata refused: zero major, padded or unterminated number, wrong or prefixed DEVNAME, duplicate/mismatched/block-only major, missing file, non-kernel filesystems'
g4_mutant no-one-shot 0 'if (heap_attempted) return -EALREADY;' '    (void)0;' \
  'second == -EALREADY && h.fd == -1 && absent(p_node)' \
  'PASS open refused: existing node, symlinked or world-writable directory, bad arguments; nothing made'
g4_mutant world-writable-dir 1 '(dir.st_mode & 022) ||' '    if (p->require_root && (dir.st_uid || dir.st_gid)) { rc = -EPERM; goto fail; }' \
  'm11_heap_node_open(&P, full_rdev(), &h) == -EPERM' \
  'PASS census scan of /proc/<pid>/fd: self and a child holder'
g4_mutant no-unlink 1 'if (unlink(p->node)) { rc = -errno; goto fail; }' '    (void)0;' \
  'rc == 0 && h.fd >= 0' \
  'PASS open is one-shot: a second attempt is refused after a failure'
# G5: dma-buf pool anchors (memfd buffers from a fixture heap ioctl), the real seccomp pool seal,
# the dma-buf census and the G3 backend in pooled mode (unprivileged; no dma-heap or ION driver).
g5_srcs=("$here/shmem_backend_native.c" "$here/dmabuf_pool_native.c" "$here/test-dmabuf-pool-native.c")
for cm_cc in gcc clang; do
  "$cm_cc" "${cm_flags[@]}" "${g5_srcs[@]}" -o "$out/dmabuf-pool-native-$cm_cc"
  timeout 120 "$out/dmabuf-pool-native-$cm_cc" | tee "$out/dmabuf-pool-native-$cm_cc.log"
done
gcc "${cm_flags[@]}" -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer \
  "${g5_srcs[@]}" -o "$out/dmabuf-pool-native-sanitize"
timeout 120 "$out/dmabuf-pool-native-sanitize" | tee "$out/dmabuf-pool-native-sanitize.log"
if gcc -std=c11 -DM11_ANCHOR_NATIVE -I "$own" -I "$repair" -I "$here" -c "$here/dmabuf_pool_native.c" -o "$out/dpn-refused.o" 2>/dev/null; then
  echo "ERROR: dmabuf_pool_native compiled outside M11_CUSTODIAN_NATIVE" >&2; exit 1
fi
echo 'PASS G5 dma-buf pool (gcc, clang, ASan+UBSan) and refused outside M11_CUSTODIAN_NATIVE'
g5_mutant() { # name file pattern replacement assertion last-pass (same detection rule as gtn_mutant)
  local name="$1" file="$2" pat="$3" rep="$4" want="$5" last="$6" dir="$out/dpn-mutant-$1" rc=0 got
  mkdir -p "$dir"
  awk -v pat="$pat" -v rep="$rep" 'index($0,pat){n++; print rep; next} {print} END{if(n!=1) exit 3}' \
    "$here/$file" > "$dir/$file"
  local srcs=() s
  for s in "${g5_srcs[@]}"; do [[ "$(basename "$s")" == "$file" ]] && srcs+=("$dir/$file") || srcs+=("$s"); done
  gcc "${cm_flags[@]}" "${srcs[@]}" -o "$dir/bin"
  timeout 120 "$dir/bin" > "$dir/log" 2>&1 || rc=$?
  got="$(grep '^PASS ' "$dir/log" | tail -n1 || true)"
  if [[ "$rc" != 134 ]] || ! grep -qF -- "Assertion \`$want' failed" "$dir/log" || [[ "$got" != "$last" ]]; then
    echo "ERROR: G5 mutant $name not detected for the expected reason (rc=$rc, last PASS: '${got}')" >&2
    cat "$dir/log" >&2; exit 1
  fi
  echo "PASS G5 test detects mutant $name: Assertion \`$want'"
}
g5_mutant census-ignores-inode dmabuf_pool_native.c \
  'if (seen[off] || e[i].ino != (unsigned long long)pool->ino[off / 2]) return -1;' '        if (seen[off]) return -1;' \
  'm11_census_dmabuf(&p, wrong, 4, 1) == -1' ''
g5_mutant census-allows-others dmabuf_pool_native.c 'if (!pid1) return -1;' '        (void)0;' \
  'm11_census_dmabuf(&p, full, 5, 0) == -1' ''
g5_mutant bind-unsealed shmem_backend_native.c 'if (!pool->sealed || pool->owner_pid != getpid() || !pool->count ||' \
  '    if (pool->owner_pid != getpid() || !pool->count ||' \
  'm11_shmem_native_backend_pool(&l, &ion, &p, &fx_sys, &b) == -EPERM' \
  'PASS pool: 4 buffers pinned at anchor/guard pairs from 200 (one inode per pair, one device, CLOEXEC); census holds'
g5_mutant pool-close-allowed dmabuf_pool_native.c 'reserved(p, __NR_close, 0, r, k);' '    (void)0;' \
  'denied(close(BASE))' \
  'PASS pooled backend refuses an unsealed pool; the pool seal rejects overlap and installs once'
g5_mutant pool-close-range-allowed dmabuf_pool_native.c '/* every other close_range: refused */' \
  '    STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);' \
  'denied(syscall(SYS_close_range, BASE, BASE + 1, 0))' \
  'PASS pooled backend refuses an unsealed pool; the pool seal rejects overlap and installs once'
g5_mutant pooled-close-closes shmem_backend_native.c 'if (l->pool) { /* G5: back to the pool' '    if (0) {' \
  'l.pool_returns == 1 && l.closes == 0 && fx_closes == closes && l.close_errors == 0' \
  'PASS census: a post-seal fork holds pool buffers (refused) and cannot drop them'
# G5 follow-up: the pool seal stacked on the REAL owner seal (m11_anchor_owner_seal_pairs over two
# real adapters on stand-ins) in one process, in both orders, plus the intersection check.
g5s_srcs=("$here/dmabuf_pool_native.c" "$here/shmem_backend_native.c" "$here/test-pool-stacked-native.c" "${anchor[@]}")
g5s_flags=("${cm_flags[@]}" -DM11_ANCHOR_NATIVE_ION)
for cm_cc in gcc clang; do
  "$cm_cc" "${g5s_flags[@]}" "${g5s_srcs[@]}" -o "$out/pool-stacked-native-$cm_cc"
  timeout 120 "$out/pool-stacked-native-$cm_cc" | tee "$out/pool-stacked-native-$cm_cc.log"
done
gcc "${g5s_flags[@]}" -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer \
  "${g5s_srcs[@]}" -o "$out/pool-stacked-native-sanitize"
timeout 120 "$out/pool-stacked-native-sanitize" | tee "$out/pool-stacked-native-sanitize.log"
echo 'PASS G5 pool seal stacked on the real owner seal (gcc, clang, ASan+UBSan)'
# Detection power: a pool seal that stops permitting the base pairs' exact close_range must break
# the owner's final close in the stacked case (same detection rule as gtn_mutant).
g5s_mut="$out/pool-stacked-mutant"; mkdir -p "$g5s_mut"
awk 'index($0,"        STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);"){n++; print "        STMT(BPF_RET | BPF_K, RET_DENY);"; next} {print} END{if(n!=1) exit 3}' \
  "$here/dmabuf_pool_native.c" > "$g5s_mut/dmabuf_pool_native.c"
gcc "${g5s_flags[@]}" "$g5s_mut/dmabuf_pool_native.c" "$here/shmem_backend_native.c" "$here/test-pool-stacked-native.c" \
  "${anchor[@]}" -o "$g5s_mut/bin"
g5s_rc=0; timeout 120 "$g5s_mut/bin" > "$g5s_mut/log" 2>&1 || g5s_rc=$?
g5s_want='m11_anchor_final_close(&io) == 0 && io.state == M11_ANCHOR_OWNER_FDS_DROPPED'
if [[ "$g5s_rc" != 134 ]] || ! grep -qF -- "Assertion \`$g5s_want' failed" "$g5s_mut/log" || grep -q '^PASS ' "$g5s_mut/log"; then
  echo "ERROR: stacked test did not detect a pool seal that refuses the base pairs (rc=$g5s_rc)" >&2
  cat "$g5s_mut/log" >&2; exit 1
fi
echo "PASS stacked test detects mutant pool-denies-base-pairs: Assertion \`$g5s_want'"
# G6: the PDR event loop. The REAL custodian, region manager and engine over the G6 transport
# (SEQPACKET endpoint stand-in, pipe PD-monitor stand-in) and the G3 backend over fixture syscalls;
# a forked peer plays the ADSP and the PD notifier (no QRTR, no driver).
g6_srcs=("${tc_srcs[@]}" "$own/m11_custodian.c" "$here/gpr_transport_native.c" "$here/shmem_backend_native.c"
         "$here/pdr_loop_native.c" "$here/test-pdr-loop-native.c")
for cm_cc in gcc clang; do
  "$cm_cc" "${cm_flags[@]}" "${g6_srcs[@]}" -o "$out/pdr-loop-native-$cm_cc"
  timeout 120 "$out/pdr-loop-native-$cm_cc" | tee "$out/pdr-loop-native-$cm_cc.log"
done
gcc "${cm_flags[@]}" -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer \
  "${g6_srcs[@]}" -o "$out/pdr-loop-native-sanitize"
timeout 120 "$out/pdr-loop-native-sanitize" | tee "$out/pdr-loop-native-sanitize.log"
if gcc -std=c11 -DM11_ANCHOR_NATIVE -I "$own" -I "$repair" -I "$here" -c "$here/pdr_loop_native.c" -o "$out/pln-refused.o" 2>/dev/null; then
  echo "ERROR: pdr_loop_native compiled outside M11_CUSTODIAN_NATIVE" >&2; exit 1
fi
echo 'PASS G6 PDR event loop (gcc, clang, ASan+UBSan) and refused outside M11_CUSTODIAN_NATIVE'
g6_mutant() { # name file pattern replacement assertion last-pass (same detection rule as gtn_mutant)
  local name="$1" file="$2" pat="$3" rep="$4" want="$5" last="$6" dir="$out/pln-mutant-$1" rc=0 got
  mkdir -p "$dir"
  awk -v pat="$pat" -v rep="$rep" 'index($0,pat){n++; print rep; next} {print} END{if(n!=1) exit 3}' \
    "$here/$file" > "$dir/$file"
  local srcs=() s
  for s in "${g6_srcs[@]}"; do [[ "$(basename "$s")" == "$file" ]] && srcs+=("$dir/$file") || srcs+=("$s"); done
  gcc "${cm_flags[@]}" "${srcs[@]}" -o "$dir/bin"
  timeout 120 "$dir/bin" > "$dir/log" 2>&1 || rc=$?
  got="$(grep '^PASS ' "$dir/log" | tail -n1 || true)"
  if [[ "$rc" != 134 ]] || ! grep -qF -- "Assertion \`$want' failed" "$dir/log" || [[ "$got" != "$last" ]]; then
    echo "ERROR: G6 mutant $name not detected for the expected reason (rc=$rc, last PASS: '${got}')" >&2
    cat "$dir/log" >&2; exit 1
  fi
  echo "PASS G6 test detects mutant $name: Assertion \`$want'"
}
g6_mutant wait-ignores-monitor gpr_transport_native.c 'nfds_t nfds = l->pd ? 2 : 1;' '        nfds_t nfds = 1;' \
  'rc == -ENETRESET && el < 250' \
  'PASS UP throughout: PD traffic during the MAP changes nothing; idle wait pumps the monitor; retire refused, backing held'
g6_mutant tx-after-down gpr_transport_native.c '/* no TX once DOWN */' '    rc = 0; (void)rc;' \
  'rc == -ENETRESET && r.glink.writes == 0' \
  'PASS DOWN before the ACK: the DOWN wins, the late ACK is not adopted'
g6_mutant settle-silent pdr_loop_native.c 'm11_custodian_pd_down(l->c, now_ms);' '        (void)now_ms;' \
  'term == M11_TERMINAL_RESET_RETAINING_ANCHORS && (r.boot.reasons & M11_TAINT_PD_DOWN) && r.cust.kernel_imports_lost' \
  'PASS UP throughout: PD traffic during the MAP changes nothing; idle wait pumps the monitor; retire refused, backing held'
g6_mutant idle-ignores-hangup pdr_loop_native.c 'if (!rc && (p.revents & (POLLHUP | POLLERR | POLLNVAL))) {' '        if (0) {' \
  'rc == -ENETRESET && r.glink.pd_down && r.loop.down_reported' \
  'PASS DOWN while idle: the idle wait reports it, MAP refused, no packet ever transmitted'
# G7: the intent journal around the G2 transport, under the REAL custodian, manager and engine; the
# forked ADSP stand-in reads the journal pipe and requires each packet's record to precede it.
g7_srcs=("${tc_srcs[@]}" "$own/m11_custodian.c" "$here/gpr_transport_native.c" "$here/shmem_backend_native.c"
         "$here/intent_journal_native.c" "$here/test-intent-journal-native.c")
for cm_cc in gcc clang; do
  "$cm_cc" "${cm_flags[@]}" "${g7_srcs[@]}" -o "$out/intent-journal-native-$cm_cc"
  timeout 120 "$out/intent-journal-native-$cm_cc" | tee "$out/intent-journal-native-$cm_cc.log"
done
gcc "${cm_flags[@]}" -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer \
  "${g7_srcs[@]}" -o "$out/intent-journal-native-sanitize"
timeout 120 "$out/intent-journal-native-sanitize" | tee "$out/intent-journal-native-sanitize.log"
if gcc -std=c11 -DM11_ANCHOR_NATIVE -I "$own" -I "$repair" -I "$here" -c "$here/intent_journal_native.c" -o "$out/ijn-refused.o" 2>/dev/null; then
  echo "ERROR: intent_journal_native compiled outside M11_CUSTODIAN_NATIVE" >&2; exit 1
fi
echo 'PASS G7 intent journal (gcc, clang, ASan+UBSan) and refused outside M11_CUSTODIAN_NATIVE'
g7_mutant() { # name pattern replacement assertion last-pass (same detection rule as gtn_mutant)
  local name="$1" pat="$2" rep="$3" want="$4" last="$5" dir="$out/ijn-mutant-$1" rc=0 got file=intent_journal_native.c
  mkdir -p "$dir"
  awk -v pat="$pat" -v rep="$rep" 'index($0,pat){n++; print rep; next} {print} END{if(n!=1) exit 3}' \
    "$here/$file" > "$dir/$file"
  local srcs=() s
  for s in "${g7_srcs[@]}"; do [[ "$(basename "$s")" == "$file" ]] && srcs+=("$dir/$file") || srcs+=("$s"); done
  gcc "${cm_flags[@]}" "${srcs[@]}" -o "$dir/bin"
  timeout 120 "$dir/bin" > "$dir/log" 2>&1 || rc=$?
  got="$(grep '^PASS ' "$dir/log" | tail -n1 || true)"
  if [[ "$rc" != 134 ]] || ! grep -qF -- "Assertion \`$want' failed" "$dir/log" || [[ "$got" != "$last" ]]; then
    echo "ERROR: G7 mutant $name not detected for the expected reason (rc=$rc, last PASS: '${got}')" >&2
    cat "$dir/log" >&2; exit 1
  fi
  echo "PASS G7 test detects mutant $name: Assertion \`$want'"
}
g7_mutant no-journal-append 'int arc = l->sink->append_fn(l->sink->user, rec, (size_t)n);' '    int arc = 0;' \
  'm11_custodian_map(&r.cust, 4096, ms(), &slot) == 0' \
  'PASS rotating sink: a fresh file every per_fd (<= 9) records, the old one closed; a failed reopen is -EIO with no write'
g7_mutant tx-despite-sink-failure '/* no TX without its journal record */' '    (void)arc;' \
  'rc < 0 && r.glink.writes == 0 && r.ilink.sink_failures == 1' \
  'PASS MAP journaled before TX (the peer saw its record before the packet), with fd and size; retire refused after the MAP: no UNMAP record, no TX, region held, retaining end'
g7_mutant no-ledger-check 'if ((h.opcode == M11_APM_CMD_SHARED_MEM_MAP_REGIONS && !l->boot->dsp_map_attempted) ||' '    if ((0) ||' \
  'rc < 0 && r.glink.writes == 0 && r.ilink.refused == 1' \
  'PASS sink failure: no TX; the region stays unresolved (unknown TX, fail closed)'
g7_mutant close-all-allowed "return -EPERM; /* outside the custodian's set" '        break;' \
  'm11_intent_format(rec, sizeof rec, 7, 3, pkt, pl) == -EPERM' ''
# Post-MAP hold L2: an UNMAP is never journaled, so never transmitted (design M4).
g7_mutant journal-allows-unmap 'return -EPERM; /* CP2 post-MAP hold L2: no UNMAP is journaled' '        break;' \
  'un == -EPERM' ''
# P5: a data command before any MAP intent; a sink that never rotates past the kmsg burst.
g7_mutant data-before-map '(data && !l->boot->dsp_map_attempted)) { /* a data command names mapped memory */' '        ((void)data, 0)) {' \
  'rc == -EPERM && r.glink.writes == 0 && jcount == 0 && r.ilink.refused == 1' \
  'PASS opcode set: GET_SPF_STATE journaled and sent; CLOSE_ALL and an unknown opcode refused'
g7_mutant never-rotates 'if (s->on_fd >= s->per_fd) {' '    if (0) {' \
  'rs.writes == 7 && rs.reopens == 2 && rs.fd == rp[2][1] && rs.on_fd == 1' \
  'PASS fd sink: one write(2) per record; a failed write is -EIO'
# G8: the native end of a custodian boot over real adapters (stand-ins), the real owner seal and the
# real custodian, manager and engine; test exit/reboot hooks report the fds at the moment of the end.
g8_srcs=("${tc_srcs[@]}" "$own/m11_custodian.c" "$here/gpr_transport_native.c" "$here/shmem_backend_native.c"
         "$here/dmabuf_pool_native.c" "$here/intent_journal_native.c" "$here/terminal_native.c"
         "$here/test-terminal-native.c" "${anchor[@]}")
g8_flags=("${cm_flags[@]}" -DM11_ANCHOR_NATIVE_ION)
for cm_cc in gcc clang; do
  "$cm_cc" "${g8_flags[@]}" "${g8_srcs[@]}" -o "$out/terminal-native-$cm_cc"
  timeout 120 "$out/terminal-native-$cm_cc" | tee "$out/terminal-native-$cm_cc.log"
done
gcc "${g8_flags[@]}" -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer \
  "${g8_srcs[@]}" -o "$out/terminal-native-sanitize"
timeout 120 "$out/terminal-native-sanitize" | tee "$out/terminal-native-sanitize.log"
if gcc -std=c11 -DM11_ANCHOR_NATIVE -I "$own" -I "$repair" -I "$here" -c "$here/terminal_native.c" -o "$out/tn-refused.o" 2>/dev/null; then
  echo "ERROR: terminal_native compiled outside M11_CUSTODIAN_NATIVE" >&2; exit 1
fi
echo 'PASS G8 native terminal (gcc, clang, ASan+UBSan) and refused outside M11_CUSTODIAN_NATIVE'
g8_mutant() { # name pattern replacement assertion last-pass (same detection rule as gtn_mutant)
  local name="$1" pat="$2" rep="$3" want="$4" last="$5" dir="$out/tn-mutant-$1" rc=0 got file=terminal_native.c
  mkdir -p "$dir"
  awk -v pat="$pat" -v rep="$rep" 'index($0,pat){n++; print rep; next} {print} END{if(n!=1) exit 3}' \
    "$here/$file" > "$dir/$file"
  local srcs=() s
  for s in "${g8_srcs[@]}"; do [[ "$(basename "$s")" == "$file" ]] && srcs+=("$dir/$file") || srcs+=("$s"); done
  gcc "${g8_flags[@]}" "${srcs[@]}" -o "$dir/bin"
  timeout 120 "$dir/bin" > "$dir/log" 2>&1 || rc=$?
  got="$(grep '^PASS ' "$dir/log" | tail -n1 || true)"
  if [[ "$rc" != 134 ]] || ! grep -qF -- "Assertion \`$want' failed" "$dir/log" || [[ "$got" != "$last" ]]; then
    echo "ERROR: G8 mutant $name not detected for the expected reason (rc=$rc, last PASS: '${got}')" >&2
    cat "$dir/log" >&2; exit 1
  fi
  echo "PASS G8 test detects mutant $name: Assertion \`$want'"
}
g8_mutant reset-taken-as-orderly 'if (t->action == M11_TERMINAL_ORDERLY_SHUTDOWN && m11_custodian_reboot_permitted(t->c) &&' \
  '    if ((1) ||' \
  'st == 42 && strstr(rep, "EXIT fds_open=4/4 pool_open=4/4") && strstr(rep, "end=pid1_exit anchors_held=2/2 anchor_fds_open=4/4 pool=held")' \
  'PASS never-mapped boot: both anchors final-closed, the record journaled, then reboot'
g8_mutant no-final-close 'if (m11_anchor_final_close(a) != 0) {' '            if (0) {' \
  'st == 43 && strstr(rep, "REBOOT fds_open=0/4") && strstr(rep, "action=ORDERLY_SHUTDOWN end=reboot anchors_held=0/2 anchor_fds_open=0/4")' ''
g8_mutant in-pool-always 'if (in_pool(t->pool, t->c->regions[i].dma_buf_fd)) t->regions_in_pool++;' '        t->regions_in_pool += 1u + 0u * (unsigned)in_pool(t->pool, 0);' \
  'st == 42 && !region_in_pool(rep) && strstr(rep, "regions=1 in_pool=0 note=mapped_boot")' \
  'PASS mapped boot, region still mapped at the end: the region is a pool buffer and the pool is held at PID1 exit'
g8_mutant hold-not-refused 'if (t->action == M11_TERMINAL_HOLD || t->action == M11_TERMINAL_HOLD_RECONCILE) return -EBUSY;' '    (void)0;' \
  'st == 0 && strstr(rep, "RET=-16 fds_open=4/4") && strstr(rep, "sink_writes=0")' \
  'PASS a mapped dma-buf outside the pool is reported (regions=1 in_pool=0)'
g8_mutant no-precheck 'if (!anchors_ready(t)) { t->orderly_failed = 1; return end_retaining(t, "anchor_not_held"); }' '        (void)anchors_ready;' \
  'st == 42 && strstr(rep, "EXIT fds_open=4/4") && strstr(rep, "note=anchor_not_held")' \
  'PASS PD DOWN on a never-mapped boot: reset end holding the anchors; panic=0 recorded as a hang'
g8_mutant fds-from-adapter 'int a = t->saved ? t->saved_fd[i][0] : t->anchors[i]->anchor_fd;' '        int a = t->anchors[i]->anchor_fd;' \
  'st == 42 && strstr(rep, "EXIT fds_open=2/4") && strstr(rep, "anchor_fds_open=2/4") && strstr(rep, "note=partial_final_close")' \
  'PASS orderly end with an anchor no longer HELD (lent): nothing closed, PID1 exit, no reboot'
g8_mutant latch-not-prechecked 'if ((a->latches & M11_ANCHOR_LATCH_REFUSE) || m11_anchor_check(a) != 0) return 0;' \
  '            if (m11_anchor_check(a) != 0) return 0;' \
  'st == 42 && strstr(rep, "EXIT fds_open=4/4") && strstr(rep, "note=anchor_not_held")' \
  'PASS partial final close (the second close refused): PID1 exit, the record states the two fds still open'
g8_mutant reboot-failure-returns 'if (t->ops.reboot_fn(t->ops.user) != 0) { t->reboot_failed = 1;' \
  '            if (t->ops.reboot_fn(t->ops.user) != 0) return -EIO;' \
  'st == 42 && strstr(rep, "EXIT fds_open=0/4") && strstr(rep, "note=reboot_failed")' \
  'PASS a refusing latch on the second anchor is caught before the first close: nothing closed'
g8_mutant sink-failure-blocks 'record(t, "pid1_exit", note);' '    record(t, "pid1_exit", note); if (t->sink_failed) return -EIO;' \
  'st == 42 && strstr(rep, "EXIT fds_open=4/4 pool_open=4/4") && strstr(rep, "sink_writes=0 sink_failed=1")' \
  'PASS reboot(2) failing after the orderly closes: PID1 exit, never a retry'
g8_mutant teardown-failure-reboots 'if ((t->teardown_rc = t->ops.teardown_fn(t->ops.user)) != 0) { t->ops.hold_fn(t->ops.user); return -ECANCELED; }' \
  '            t->teardown_rc = t->ops.teardown_fn(t->ops.user);' \
  'st == 44 && strstr(rep, "TEARDOWN fds_open=0/4") && strstr(rep, "HOLD fds_open=0/4") && !strstr(rep, "REBOOT") && !strstr(rep, "EXIT")' \
  'PASS B5 teardown: after both final closes and the journaled record, before the reboot'
# Criterion 7 composition: G1-G8 in the composed runner core under one stand-in harness (real
# adapters, owner + pool seals, GPR over a raw pty to the ADSP stand-in, PD pipe, journal pipe).
cr_srcs=("${tc_srcs[@]}" "$own/m11_custodian.c" "$here/gpr_transport_native.c" "$here/shmem_backend_native.c"
         "$here/dmabuf_pool_native.c" "$here/heap_node_native.c" "$here/intent_journal_native.c"
         "$here/pdr_loop_native.c" "$here/terminal_native.c" "$here/custodian_runner_native.c"
         "$here/test-crunner-native.c" "${anchor[@]}")
cr_flags=("${cm_flags[@]}" -DM11_ANCHOR_NATIVE_ION)
for cm_cc in gcc clang; do
  "$cm_cc" "${cr_flags[@]}" "${cr_srcs[@]}" -o "$out/crunner-native-$cm_cc"
  timeout 180 "$out/crunner-native-$cm_cc" | tee "$out/crunner-native-$cm_cc.log"
done
gcc "${cr_flags[@]}" -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer \
  "${cr_srcs[@]}" -o "$out/crunner-native-sanitize"
timeout 180 "$out/crunner-native-sanitize" | tee "$out/crunner-native-sanitize.log"
if gcc -std=c11 -DM11_ANCHOR_NATIVE -I "$own" -I "$repair" -I "$here" -c "$here/custodian_runner_native.c" -o "$out/crn-refused.o" 2>/dev/null; then
  echo "ERROR: custodian_runner_native compiled outside M11_CUSTODIAN_NATIVE" >&2; exit 1
fi
echo 'PASS composed runner core (gcc, clang, ASan+UBSan) and refused outside M11_CUSTODIAN_NATIVE'
cr_mutant() { # name pattern replacement assertion last-pass (same detection rule as gtn_mutant)
  local name="$1" pat="$2" rep="$3" want="$4" last="$5" dir="$out/crn-mutant-$1" rc=0 got file=custodian_runner_native.c
  mkdir -p "$dir"
  awk -v pat="$pat" -v rep="$rep" 'index($0,pat){n++; print rep; next} {print} END{if(n!=1) exit 3}' \
    "$here/$file" > "$dir/$file"
  local srcs=() s
  for s in "${cr_srcs[@]}"; do [[ "$(basename "$s")" == "$file" ]] && srcs+=("$dir/$file") || srcs+=("$s"); done
  gcc "${cr_flags[@]}" "${srcs[@]}" -o "$dir/bin"
  timeout 180 "$dir/bin" > "$dir/log" 2>&1 || rc=$?
  got="$(grep '^PASS ' "$dir/log" | tail -n1 || true)"
  if [[ "$rc" != 134 ]] || ! grep -qF -- "Assertion \`$want' failed" "$dir/log" || [[ "$got" != "$last" ]]; then
    echo "ERROR: composed-runner mutant $name not detected for the expected reason (rc=$rc, last PASS: '${got}')" >&2
    cat "$dir/log" >&2; exit 1
  fi
  echo "PASS composed-runner test detects mutant $name: Assertion \`$want'"
}
cr_mutant heap-left-open 'int crc = sys->close_fn(cfg->heap_fd);' '    int crc = 0; (void)sys;' \
  'rc == 0 && step == 0' ''
cr_mutant pool-unsealed 'if ((rc = m11_dmabuf_pool_seal(&r->pool, base, 2))) FAIL(3, rc);' '    (void)base;' \
  'rc == 0 && step == 0' ''
cr_mutant journal-bypassed 'if ((rc = m11_gpr_engine_init(&r->eng, &r->transport,' \
  '    if ((rc = m11_gpr_engine_init(&r->eng, &r->inner, cfg->src_port ? cfg->src_port : 0x0100u)) ||' \
  'm11_crunner_map(&R, 4096, ms(), &s) == 0' ''
cr_mutant no-settle-after-map '/* settle after MAP */' '    (void)0;' \
  'strstr(rep, "MAP rc=-102 unresolved=1 imports_lost=1")' \
  'PASS composed never-mapped boot: both anchors final-closed, terminal journaled, reboot; nothing sent'
cr_mutant census-no-force 'r->term.force_retain_note = r->force_note;' '        (void)0;' \
  'st == 42 && strstr(rep, "EXIT anchors=4/4") && strstr(rep, "action=HOLD end=pid1_exit") && strstr(rep, "note=foreign_holder_why=19")' \
  'PASS composed PD DOWN during MAP: -ENETRESET, region unresolved, custodian told at once, PID1 exit holding everything'
cr_mutant close-without-census '/* census before close */' '    (void)0;' \
  'strstr(rep, "CLOSE rc=-130 closed=0 census_failed=1 imports_lost=0 MAP rc=-130 why=19") && peer_count(rep) == 0' \
  'PASS composed PD DOWN during MAP: -ENETRESET, region unresolved, custodian told at once, PID1 exit holding everything'
cr_mutant no-census-before-map '/* census before MAP */' '    (void)0;' \
  'strstr(rep, "CLOSE rc=-130 closed=0 census_failed=1 imports_lost=0 MAP rc=-130 why=19") && peer_count(rep) == 0' \
  'PASS composed PD DOWN during MAP: -ENETRESET, region unresolved, custodian told at once, PID1 exit holding everything'
cr_mutant no-tree-census 'if (desc[i] && holds_forbidden(r, pids[i]) != 0) return -1;' \
  '        if (desc[i] && holds_forbidden(r, pids[i]) < -1) return -1;' \
  'strstr(rep, "CLOSE rc=-130 closed=0 census_failed=1 imports_lost=0 MAP rc=-130 why=19") && peer_count(rep) == 0' \
  'PASS composed PD DOWN during MAP: -ENETRESET, region unresolved, custodian told at once, PID1 exit holding everything'
cr_mutant idle-without-census '/* census after idle */' '    (void)0;' \
  'strstr(rep, "IDLE rc=-130 census_failed=1 imports_lost=0 why=19") && st == 42 && strstr(rep, "note=foreign_holder_why=19")' \
  'PASS composed tree census: a descendant holding only pool buffers (anchors dropped) fails the census before any TX'
cr_mutant end-without-census '/* a foreign holder now still turns the end' '    (void)0;' \
  'st == 42 && strstr(rep, "EXIT anchors=4/4") && strstr(rep, "why=19") && strstr(rep, "action=ORDERLY_SHUTDOWN end=pid1_exit") && strstr(rep, "note=foreign_holder_why=19")' \
  'PASS composed census after idle: a foreign holder found while idle forces the retaining end'
cr_mutant no-cmdline-gate 'if (!ct.strict_iommu) FAIL(1, -EPERM);' '    (void)0;' \
  'strstr(rep, "START rc=-1 step=1 started=0 heap_open=1") && peer_count(rep) == 0 && !strstr(rep, "END returned")' \
  'PASS composed census in end: a descendant holding only pool buffers after a clean close prevents the orderly reboot the custodian alone would choose'
cr_mutant no-partial-end 'if (!r->started) return end_partial(r);' '    if (!r->started) { (void)end_partial; return -EINVAL; }' \
  'strstr(rep, "START rc=-1 step=1 started=0 heap_open=1") && peer_count(rep) == 0 && !strstr(rep, "END returned")' \
  'PASS composed census in end: a descendant holding only pool buffers after a clean close prevents the orderly reboot the custodian alone would choose'
cr_mutant heap-fd-stale 'if (crc) FAIL(3, -EIO); /* nothing allocates after the pool */' \
  '    if (crc) { r->cfg.heap_fd = cfg->heap_fd; FAIL(3, -EIO); }' \
  'strstr(rep, "START rc=-5 step=3 started=0 heap_open=0 heapfd=-1 pool_fd=1")' \
  'PASS composed pool build failure: START_FAILED step=3 with the heap fd untouched'
cr_mutant read-ppid-skip 'if (rc) { closedir(d); return -1; }       /* exists but unreadable' '        if (rc) continue;' \
  'strstr(rep, "START rc=-130 step=6 started=1 why=16") && st == 42 && strstr(rep, "note=foreign_holder_why=16")' \
  'PASS composed start failing after the sealed pool (engine open at PD DOWN): START_FAILED step=4, PID1 exit holding anchors and pool'
cr_mutant not-one-shot 'if (crunner_started_once) return -EALREADY;' '    (void)0;' \
  'st == 0 && strstr(rep, "SECOND rc=-114 pool_count=2 started=1 stage=6")' \
  'PASS composed tree census: a process gone between readdir and read is not counted'
cr_mutant map-intent-not-required 'if (!r->cfg.map_intent_fn) return -EPERM;' '    (void)0;' \
  'strstr(rep, "MAP rc=-1 slot=-1 intents=0 attempted=0") && peer_count(rep) == 0' \
  'PASS composed journal failure: no TX, region unresolved and held, the end is the retaining reset (post-MAP hold)'
cr_mutant map-intent-not-called 'r->cfg.map_intent_fn(r->cfg.map_intent_user);' '    (void)0;' \
  'intents == 1 && R.map_intents == 1' ''
cr_mutant map-intent-orderly 'else if (r->map_intents && m11_custodian_terminal_action(&r->cust) == M11_TERMINAL_ORDERLY_SHUTDOWN) {' '    } else if (0) {' \
  'st == 42 && strstr(rep, "EXIT anchors=4/4") && strstr(rep, "action=ORDERLY_SHUTDOWN end=pid1_exit") && strstr(rep, "note=map_intent=1")' \
  'PASS composed MAP without the MAP-intent hook: refused before any import or TX; the boot stays never-mapped'
# Production P1: the long-session SERVREG listener and its QRTR adapter (the G6 PD monitor) over a
# fixture QRTR; the frozen one-query codec (runtime/audio_pd.c) is not used and stays unchanged.
p1_srcs=("$here/pd_session_native.c" "$here/gpr_transport_native.c" "$here/test-pd-session-native.c")
for cm_cc in gcc clang; do
  "$cm_cc" "${cm_flags[@]}" "${p1_srcs[@]}" -o "$out/pd-session-native-$cm_cc"
  timeout 120 "$out/pd-session-native-$cm_cc" | tee "$out/pd-session-native-$cm_cc.log"
done
gcc "${cm_flags[@]}" -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer \
  "${p1_srcs[@]}" -o "$out/pd-session-native-sanitize"
timeout 120 "$out/pd-session-native-sanitize" | tee "$out/pd-session-native-sanitize.log"
if gcc -std=c11 -DM11_ANCHOR_NATIVE -I "$own" -I "$repair" -I "$here" -c "$here/pd_session_native.c" -o "$out/pds-refused.o" 2>/dev/null; then
  echo "ERROR: pd_session_native compiled outside M11_CUSTODIAN_NATIVE" >&2; exit 1
fi
echo 'PASS production P1 PD session (gcc, clang, ASan+UBSan) and refused outside M11_CUSTODIAN_NATIVE'
p1_mutant() { # name pattern replacement assertion last-pass (same detection rule as gtn_mutant)
  local name="$1" pat="$2" rep="$3" want="$4" last="$5" dir="$out/pds-mutant-$1" rc=0 got file=pd_session_native.c
  mkdir -p "$dir"
  awk -v pat="$pat" -v rep="$rep" 'index($0,pat){n++; print rep; next} {print} END{if(n!=1) exit 3}' \
    "$here/$file" > "$dir/$file"
  local srcs=() s
  for s in "${p1_srcs[@]}"; do [[ "$(basename "$s")" == "$file" ]] && srcs+=("$dir/$file") || srcs+=("$s"); done
  gcc "${cm_flags[@]}" "${srcs[@]}" -o "$dir/bin"
  timeout 120 "$dir/bin" > "$dir/log" 2>&1 || rc=$?
  got="$(grep '^PASS ' "$dir/log" | tail -n1 || true)"
  if [[ "$rc" != 134 ]] || ! grep -qF -- "Assertion \`$want' failed" "$dir/log" || [[ "$got" != "$last" ]]; then
    echo "ERROR: P1 mutant $name not detected for the expected reason (rc=$rc, last PASS: '${got}')" >&2
    cat "$dir/log" >&2; exit 1
  fi
  echo "PASS P1 test detects mutant $name: Assertion \`$want'"
}
p1_mutant deadline-after-ready 'if (!s->ever_ready && now >= s->ready_deadline) return end(s, M11_PDS_DEADLINE);' \
  '    if (now >= s->ready_deadline) return end(s, M11_PDS_DEADLINE);' \
  'm11_pdmon_pump(&M, 1003 + 600000) == 1 && m11_pdmon_pump(&M, 1003 + 3600000) == 1' \
  'PASS bring-up: NEW_LOOKUP (service 0x42, instance 74), registration to the announced peer, READY on an UP snapshot'
p1_mutant reindication-drops-ready 'if (s->phase != M11_PDS_READY) settle(s); /* READY persists' '        s->phase = M11_PDS_WAIT_UP;' \
  'm11_pdmon_pump(&M, 3601010) == 1' \
  'PASS long session: still UP an hour after READY (the frozen codec ends at 10 s)'
p1_mutant busy-acks-down 'if (s->resources_busy) { s->ack_deferred = 1; return -1; }' '            (void)0;' \
  'm11_pdmon_pump(&M, 20010) == 0 && ntx == before && M.pds.ack_deferred' \
  'PASS DOWN after READY: terminal, acknowledged, never UP again'
p1_mutant del-client-any 'return s->peer && a == s->node && c == s->port ? end(s, M11_PDS_PEER_LOST) : 0;' \
  '        return end(s, M11_PDS_PEER_LOST);' \
  'm11_pdmon_pump(&M, 30011) == 1' \
  'PASS DOWN while resources are busy: not UP at once, the ACK deferred until release'
p1_mutant unknown-ctrl-ignored 'default: /* anything else cannot be read as UP */' '    default: return 0;' \
  'hello == 0' \
  'PASS DOWN while resources are busy: not UP at once, the ACK deferred until release'
p1_mutant stop-while-busy 'if (s->resources_busy || s->phase != M11_PDS_READY || s->ack_txn || s->ack_deferred || s->register_txn) return -1;' \
  '    if (s->phase != M11_PDS_READY || s->ack_txn || s->ack_deferred || s->register_txn) return -1;' \
  'busy_stop == -1 && M.pds.phase == M11_PDS_READY && ntx == b0' \
  'PASS monitor in the G6 transport: the DOWN pumped before the write refuses the TX (-ENETRESET)'
# Production P2: the PID1 boot sequence over a fake sysfs/procfs tree and a scratch /dev. Metadata
# unprivileged; the refusals and a full boot handed to the composed runner as root (sudo).
p2_srcs=("${tc_srcs[@]}" "$own/m11_custodian.c" "$here/gpr_transport_native.c" "$here/shmem_backend_native.c"
         "$here/dmabuf_pool_native.c" "$here/heap_node_native.c" "$here/intent_journal_native.c"
         "$here/pdr_loop_native.c" "$here/terminal_native.c" "$here/custodian_runner_native.c"
         "$here/custodian_boot_native.c" "$here/test-boot-native.c" "${anchor[@]}")
p2_flags=("${cm_flags[@]}" -DM11_ANCHOR_NATIVE_ION)
for cm_cc in gcc clang; do
  "$cm_cc" "${p2_flags[@]}" "${p2_srcs[@]}" -o "$out/boot-native-$cm_cc"
  timeout 180 "$out/boot-native-$cm_cc" "$out" | tee "$out/boot-native-$cm_cc.log"
done
gcc "${p2_flags[@]}" -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer \
  "${p2_srcs[@]}" -o "$out/boot-native-sanitize"
timeout 180 "$out/boot-native-sanitize" "$out" | tee "$out/boot-native-sanitize.log"
if [[ "$sudo_ok" == 1 ]]; then
  timeout 180 sudo -n "$out/boot-native-gcc" "$out" | tee "$out/boot-native-root.log"
  grep -qF 'PASS production P2 boot sequence (root sections)' "$out/boot-native-root.log"
else
  if [[ -n "${CI:-}" ]]; then echo "ERROR: P2 root sections need sudo in CI" >&2; exit 1; fi
  echo "SKIP P2 root sections: no sudo"
fi
if gcc -std=c11 -DM11_ANCHOR_NATIVE -I "$own" -I "$repair" -I "$here" -c "$here/custodian_boot_native.c" -o "$out/cbn-refused.o" 2>/dev/null; then
  echo "ERROR: custodian_boot_native compiled outside M11_CUSTODIAN_NATIVE" >&2; exit 1
fi
echo 'PASS production P2 boot sequence (gcc, clang, ASan+UBSan, root when sudo) and refused outside M11_CUSTODIAN_NATIVE'
p2_mutant() { # name asroot pattern replacement assertion last-pass (same detection rule as gtn_mutant)
  local name="$1" asroot="$2" pat="$3" rep="$4" want="$5" last="$6" dir="$out/cbn-mutant-$1" rc=0 got file=custodian_boot_native.c
  if [[ "$asroot" == 1 && "$sudo_ok" != 1 ]]; then echo "SKIP P2 mutant $name: no sudo"; return; fi
  mkdir -p "$dir"
  awk -v pat="$pat" -v rep="$rep" 'index($0,pat){n++; print rep; next} {print} END{if(n!=1) exit 3}' \
    "$here/$file" > "$dir/$file"
  local srcs=() s
  for s in "${p2_srcs[@]}"; do [[ "$(basename "$s")" == "$file" ]] && srcs+=("$dir/$file") || srcs+=("$s"); done
  gcc "${p2_flags[@]}" "${srcs[@]}" -o "$dir/bin"
  if [[ "$asroot" == 1 ]]; then
    timeout 180 sudo -n "$dir/bin" "$dir" > "$dir/log" 2>&1 || rc=$?
    sudo -n rm -rf "$dir"/m11-boot-*
  else
    timeout 180 "$dir/bin" "$dir" > "$dir/log" 2>&1 || rc=$?
    rm -rf "$dir"/m11-boot-*
  fi
  got="$(grep '^PASS ' "$dir/log" | tail -n1 || true)"
  if [[ "$rc" != 134 ]] || ! grep -qF -- "Assertion \`$want' failed" "$dir/log" || [[ "$got" != "$last" ]]; then
    echo "ERROR: P2 mutant $name not detected for the expected reason (rc=$rc, last PASS: '${got}')" >&2
    cat "$dir/log" >&2; exit 1
  fi
  echo "PASS P2 test detects mutant $name: Assertion \`$want'"
}
p2_mutant devname-unchecked 0 'if (strncmp(b, line, strlen(line)) && !strstr(b, nl)) return -ENODEV;' '    (void)nl;' \
  'devname_rc == -ENODEV' \
  'PASS default config: the real node paths, minor 0, root nodes, the whole-system census, a capability-dropped spawner'
p2_mutant pd-not-required 1 'if (pd->pump_fn(pd->user, now_ms) != 1) FAIL(2, -ENETRESET);' '    (void)now_ms;' \
  'st == 0 && strstr(rep, "BOOT rc=-102 step=2 stage=1") && strstr(rep, "SECOND rc=-114 step=0 same=1 open=1")' \
  'PASS boot metadata: exact MAJ:MIN (minor 0 in production), DEVNAME by number, exactly one matching character major'
p2_mutant no-one-shot 0 'if (boot_started_once) return -EALREADY;' '    (void)0;' \
  'st == 0 && strstr(rep, "BOOT rc=-102 step=2 stage=1") && strstr(rep, "SECOND rc=-114 step=0 same=1 open=1")' \
  'PASS boot metadata: exact MAJ:MIN (minor 0 in production), DEVNAME by number, exactly one matching character major'
p2_mutant cma-node-allowed 1 '(rc = !lstat(c->ion_cma.node, &st) ? -EEXIST : errno == ENOENT ? 0 : -errno)) {' '        (rc = 0)) {' \
  'st == 0 && strstr(rep, "BOOT rc=-17 step=4 stage=3 ep=HELD ion=UNBOUND ep_node=0 ion_node=0 cma_node=1")' \
  "PASS boot refused when the number's DEVNAME is not the endpoint: no node made"
p2_mutant nodes-left-on-heap-failure 1 '(void)unlink(c->ion.node); (void)unlink(c->endpoint.node); /* nodes go; the anchors stay held */' '        (void)0;' \
  'st == 0 && strstr(rep, "BOOT rc=-19 step=5 stage=4 ep=HELD ion=HELD ep_node=0 ion_node=0 cma_node=0 heap_fd=0 heap_dir=0 sealed=0")' \
  'PASS boot refused when the ION CMA twin has a node: the endpoint stays held, its node removed, no ION node; a retry is refused and leaves the held endpoint intact'
# Production P3: the PID1 entry (P1 monitor + P2 boot + composed runner + G8 terminal) over a fake
# sysfs/procfs tree, a scratch /dev and a fixture QRTR crossing processes. Unprivileged refusals; the
# full boots (never-mapped orderly, mapped HOLD then DOWN, DOWN during MAP, DOWN before MAP) as root.
p3_srcs=(); p3_main=()
for s in "${p2_srcs[@]}"; do
  if [[ "$s" == "$here/test-boot-native.c" ]]; then p3_srcs+=("$here/test-entry-native.c"); p3_main+=("$here/custodian_entry_main.c")
  else p3_srcs+=("$s"); p3_main+=("$s"); fi
done
p3_srcs+=("$here/pd_session_native.c" "$here/custodian_entry_native.c")
p3_main+=("$here/pd_session_native.c" "$here/custodian_entry_native.c" "$here/p4_env_native.c")
for cm_cc in gcc clang; do
  "$cm_cc" "${p2_flags[@]}" "${p3_srcs[@]}" -o "$out/entry-native-$cm_cc"
  timeout 180 "$out/entry-native-$cm_cc" "$out" | tee "$out/entry-native-$cm_cc.log"
done
gcc "${p2_flags[@]}" -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer \
  "${p3_srcs[@]}" -o "$out/entry-native-sanitize"
timeout 180 "$out/entry-native-sanitize" "$out" | tee "$out/entry-native-sanitize.log"
if [[ "$sudo_ok" == 1 ]]; then
  timeout 180 sudo -n "$out/entry-native-gcc" "$out" | tee "$out/entry-native-root.log"
  grep -qF 'PASS production P3 PID1 entry (root sections)' "$out/entry-native-root.log"
else
  if [[ -n "${CI:-}" ]]; then echo "ERROR: P3 root sections need sudo in CI" >&2; exit 1; fi
  echo "SKIP P3 root sections: no sudo"
fi
# The PID1 binary links (production defaults, libc QRTR and syscalls) and refuses to act outside PID1.
for cm_cc in gcc clang; do
  "$cm_cc" "${p2_flags[@]}" "${p3_main[@]}" -o "$out/custodian-entry-$cm_cc"
  rc=0; "$out/custodian-entry-$cm_cc" || rc=$?
  if [[ "$rc" != 2 ]]; then echo "ERROR: custodian entry binary ($cm_cc) did not refuse outside PID1 (rc=$rc)" >&2; exit 1; fi
done
for f in custodian_entry_native.c custodian_entry_main.c p4_env_native.c; do
  if gcc -std=c11 -DM11_ANCHOR_NATIVE -I "$own" -I "$repair" -I "$here" -c "$here/$f" -o "$out/cen-refused.o" 2>/dev/null; then
    echo "ERROR: $f compiled outside M11_CUSTODIAN_NATIVE" >&2; exit 1
  fi
done
echo 'PASS production P3 PID1 entry (gcc, clang, ASan+UBSan, root when sudo); the PID1 binary links and returns 2 outside PID1; refused outside M11_CUSTODIAN_NATIVE'
# T10 (R4 rule; docs/m11-argon-cp2-c5-hold-design.md): nothing the P4 PID1 runs names the SysRq trigger
# (a 'b'/'c' write would end the boot outside the custodian's terminal decision).
#  - source layer: every production anchor-native file; every unit p4/build.sh compiles into the PID1
#    (read from build.sh itself and required to equal the PID1 linked above) with every header they
#    include, transitively; the relay; every repository script the P4 payload ships (public-payload.py
#    REPO_SOURCES) and the Run14 journal.sh it reuses;
#  - binary layer: the strings of the PID1 linked above on this runner (x64 or ARM64; gcc, clang),
#    which also show literals the compiler joins ("/proc/sys" "rq-trigger");
#  - a self-test per layer. A name assembled at run time evades both layers (review residual).
t10_scan() { LC_ALL=C grep -Il -i sysrq "$@" || true; }
t10_bin() { LC_ALL=C grep -a -c -i sysrq "$1" || true; }
sysrq_hits="$(grep -rIl -i --exclude='test*' --exclude='*.md' sysrq "$here" || true)"
if [[ -n "$sysrq_hits" ]]; then echo "ERROR: SysRq named in production anchor-native sources: $sysrq_hits" >&2; exit 1; fi
t10_block="$(sed -n '/^ pid1)/,/^  for variant/p' "$here/p4/build.sh")"
t10_units=()
for tok in $(printf '%s\n' "$t10_block" | grep -oE '[A-Za-z0-9_]+' | sort -u); do
  for d in "$repair" "$own" "$here"; do [[ -f "$d/$tok.c" ]] && t10_units+=("$d/$tok.c"); done
done
t10_a="$(for f in "${t10_units[@]}"; do basename "$f"; done | sort)"
t10_b="$(for f in "${p3_main[@]}"; do basename "$f"; done | sort)"
if [[ "${#t10_units[@]}" -lt 20 || "$t10_a" != "$t10_b" ]]; then
  echo "ERROR: T10: the p4/build.sh PID1 units differ from the PID1 linked above" >&2
  diff <(printf '%s\n' "$t10_a") <(printf '%s\n' "$t10_b") >&2 || true; exit 1
fi
t10_files=("${t10_units[@]}" "$here/p4/kmsg-relay.c"); t10_queue=("${t10_files[@]}"); t10_seen=" "
while ((${#t10_queue[@]})); do
  f="${t10_queue[0]}"; t10_queue=("${t10_queue[@]:1}")
  for h in $(sed -n 's/^#include "\([^"]*\)".*/\1/p' "$f"); do
    p=""; for d in "$(dirname "$f")" "$repair" "$own" "$here"; do [[ -f "$d/$h" ]] && { p="$d/$h"; break; }; done
    if [[ -z "$p" ]]; then echo "ERROR: T10: $(basename "$f") includes $h, not found" >&2; exit 1; fi
    p="$(cd "$(dirname "$p")" && pwd)/$(basename "$p")" # one path per file ("../" includes)
    [[ "$t10_seen" == *" $p "* ]] && continue
    t10_seen+="$p "; t10_files+=("$p"); t10_queue+=("$p")
  done
done
t10_headers=$(( ${#t10_files[@]} - ${#t10_units[@]} - 1 ))
# The repository scripts the P4 payload ships (p4/public-payload.py REPO_SOURCES; that file is not in the
# public export, so the list is declared here and compared with it wherever it exists) and the Run14
# journal.sh it reuses. run16/haptics-suppliers is never exported: frozen and scope-guard locked, it is
# scanned in the private tree and is the only input allowed to be absent.
t10_shipped=(scripts/m11/anchor-native/p4/init scripts/m11/anchor-native/p4/prepare scripts/m11/anchor-native/p4/usb
             scripts/m11/run16/haptics-suppliers scripts/m11/run19/amp-switch scripts/m11/run23/amp-gate
             scripts/m11/run23/control)
t10_private_only=scripts/m11/run16/haptics-suppliers
if [[ -f "$here/p4/public-payload.py" ]]; then
  t10_declared="$(python3 -I - "$here/p4/public-payload.py" <<'PY'
import ast, sys
tree = ast.parse(open(sys.argv[1], encoding="utf-8").read())
maps = [ast.literal_eval(n.value) for n in tree.body
        if isinstance(n, ast.Assign) and any(getattr(t, "id", None) == "REPO_SOURCES" for t in n.targets)]
if len(maps) == 1:
    print("\n".join(sorted(set(maps[0].values()))))
PY
)"
  if [[ "$t10_declared" != "$(printf '%s\n' "${t10_shipped[@]}" | LC_ALL=C sort)" ]]; then
    echo "ERROR: T10: the shipped-script list differs from p4/public-payload.py REPO_SOURCES" >&2; exit 1
  fi
  t10_drift='checked against REPO_SOURCES'
else
  t10_drift='REPO_SOURCES not in this tree'
fi
t10_absent=()
for s in "${t10_shipped[@]}" scripts/m11/instrumentation/journal.sh; do
  if [[ -f "$root/$s" ]]; then t10_files+=("$root/$s")
  elif [[ "$s" == "$t10_private_only" ]]; then t10_absent+=("$s")
  else echo "ERROR: T10: shipped script $s missing" >&2; exit 1; fi
done
t10_hits="$(t10_scan "${t10_files[@]}")"
if [[ -n "$t10_hits" ]]; then echo "ERROR: T10: SysRq named in P4 PID1 inputs: $t10_hits" >&2; exit 1; fi
echo "PASS T10 source layer: no P4 PID1 input names the SysRq trigger (${#t10_units[@]} build.sh units, $t10_headers headers, the relay, $(( ${#t10_shipped[@]} - ${#t10_absent[@]} ))/${#t10_shipped[@]} shipped scripts ($t10_drift; not in this tree: ${t10_absent[*]:-none}) and journal.sh; every production anchor-native file)"
for cm_cc in gcc clang; do
  if [[ "$(t10_bin "$out/custodian-entry-$cm_cc")" != 0 ]]; then
    echo "ERROR: T10: the linked PID1 ($cm_cc) carries a SysRq string" >&2; exit 1
  fi
done
echo 'PASS T10 binary layer: the PID1 linked on this runner (gcc, clang) carries no SysRq string'
# Self-test: the source layer flags a P4 unit outside anchor-native and a shipped script; the binary
# layer flags a split literal that the source layer cannot see.
t10_mut="$out/t10-mutant"; mkdir -p "$t10_mut/src" "$t10_mut/bin"
t10_source_mutant() { # original-path line
  local orig="$1" copy="$t10_mut/src/$(basename "$1")" sub=() f got
  { cat "$orig"; printf '%s\n' "$2"; } > "$copy"
  for f in "${t10_files[@]}"; do [[ "$f" == "$orig" ]] && sub+=("$copy") || sub+=("$f"); done
  got="$(t10_scan "${sub[@]}")"
  if [[ "$got" != "$copy" ]]; then echo "ERROR: T10 source layer missed a SysRq name in $orig (got '$got')" >&2; exit 1; fi
}
t10_source_mutant "$own/m11_pid1_anchor.c" '/* T10 self-test: writes /proc/sysrq-trigger */'
t10_source_mutant "$root/scripts/m11/run23/control" '# T10 self-test: echo b > /proc/sysrq-trigger'
{ cat "$own/m11_pid1_anchor.c"; printf '%s\n' 'const char m11_t10_probe[] = "/proc/sys" "rq-trigger";'; } > "$t10_mut/bin/m11_pid1_anchor.c"
t10_main=(); for f in "${p3_main[@]}"; do [[ "$f" == "$own/m11_pid1_anchor.c" ]] && t10_main+=("$t10_mut/bin/m11_pid1_anchor.c") || t10_main+=("$f"); done
gcc "${p2_flags[@]}" "${t10_main[@]}" -o "$t10_mut/bin/pid1"
if [[ -n "$(t10_scan "$t10_mut/bin/m11_pid1_anchor.c")" || "$(t10_bin "$t10_mut/bin/pid1")" == 0 ]]; then
  echo "ERROR: T10 binary layer self-test: a split SysRq literal was not caught by the binary layer alone" >&2; exit 1
fi
echo 'PASS T10 self-test: the source layer flags an ownership unit and a shipped script; the binary layer flags a split literal the source layer cannot see'
# P4 item 1: the environment phase (Run23's pre-owned path) over shell stand-ins and an ELF helper
# stand-in; as root (sudo) the helpers drop to uid 65534 with no capabilities.
gcc -std=c11 -O1 -Wall -Wextra -Werror "$here/test-p4-helper.c" -o "$out/p4-helper"
p4e_srcs=()
for s in "${p2_srcs[@]}"; do [[ "$s" == "$here/test-boot-native.c" ]] && p4e_srcs+=("$here/test-p4-env-native.c") || p4e_srcs+=("$s"); done
p4e_srcs+=("$here/p4_env_native.c")
for cm_cc in gcc clang; do
  "$cm_cc" "${p2_flags[@]}" "${p4e_srcs[@]}" -o "$out/p4-env-$cm_cc"
  timeout 180 "$out/p4-env-$cm_cc" "$out" "$out/p4-helper" | tee "$out/p4-env-$cm_cc.log"
done
gcc "${p2_flags[@]}" -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer \
  "${p4e_srcs[@]}" -o "$out/p4-env-sanitize"
timeout 180 "$out/p4-env-sanitize" "$out" "$out/p4-helper" | tee "$out/p4-env-sanitize.log"
if [[ "$sudo_ok" == 1 ]]; then
  timeout 180 sudo -n "$out/p4-env-gcc" "$out" "$out/p4-helper" | tee "$out/p4-env-root.log"
  grep -qF 'PASS P4 environment phase (root)' "$out/p4-env-root.log"
else
  if [[ -n "${CI:-}" ]]; then echo "ERROR: P4 environment root sections need sudo in CI" >&2; exit 1; fi
  echo "SKIP P4 environment root sections: no sudo"
fi
echo 'PASS P4 environment phase (gcc, clang, ASan+UBSan, root when sudo)'
# P5 W3 (docs/m11-argon-speaker-run-design.md): the speaker back ends and amplifier controls through
# PID1-private ALSA nodes, against fixture syscalls (no ALSA device).
w3_srcs=("$here/snd_backend_native.c" "$here/test-snd-backend-native.c")
for cm_cc in gcc clang; do
  "$cm_cc" "${cm_flags[@]}" "${w3_srcs[@]}" -o "$out/snd-backend-native-$cm_cc"
  timeout 120 "$out/snd-backend-native-$cm_cc" | tee "$out/snd-backend-native-$cm_cc.log"
done
gcc "${cm_flags[@]}" -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer \
  "${w3_srcs[@]}" -o "$out/snd-backend-native-sanitize"
timeout 120 "$out/snd-backend-native-sanitize" | tee "$out/snd-backend-native-sanitize.log"
if gcc -std=c11 -DM11_ANCHOR_NATIVE -I "$own" -I "$repair" -I "$here" -c "$here/snd_backend_native.c" -o "$out/sbe-refused.o" 2>/dev/null; then
  echo "ERROR: snd_backend_native compiled outside M11_CUSTODIAN_NATIVE" >&2; exit 1
fi
echo 'PASS W3 snd backend (gcc, clang, ASan+UBSan) and refused outside M11_CUSTODIAN_NATIVE'
w3_mutant() { # name pattern replacement assertion last-pass (same detection rule as gtn_mutant)
  local name="$1" pat="$2" rep="$3" want="$4" last="$5" dir="$out/sbe-mutant-$1" rc=0 got
  mkdir -p "$dir"
  awk -v pat="$pat" -v rep="$rep" 'index($0,pat){n++; print rep; next} {print} END{if(n!=1) exit 3}' \
    "$here/snd_backend_native.c" > "$dir/snd_backend_native.c"
  cp "$here/snd_backend_native.h" "$dir/"
  gcc "${cm_flags[@]}" -I "$dir" "$dir/snd_backend_native.c" "$here/test-snd-backend-native.c" -o "$dir/bin"
  timeout 120 "$dir/bin" > "$dir/log" 2>&1 || rc=$?
  got="$(grep '^PASS ' "$dir/log" | tail -n1 || true)"
  if [[ "$rc" != 134 ]] || ! grep -qF -- "Assertion \`$want' failed" "$dir/log" || [[ "$got" != "$last" ]]; then
    echo "ERROR: W3 mutant $name not detected for the expected reason (rc=$rc, last PASS: '${got}')" >&2
    cat "$dir/log" >&2; exit 1
  fi
  echo "PASS W3 test detects mutant $name: Assertion \`$want'"
}
w3_mutant node-kept-at-open 'int urc = b->sys->unlink_fn(path); /* the entry goes whatever the open did */' \
  '    int urc = 0; (void)path;' 'dir_live && live_nodes() == 2 && open_fds() == 1' ''
w3_mutant no-readback 'for (unsigned c = 0; c < count; c++) if (got[c] != want) return -EIO;' '    (void)got;' \
  'm11_snd_ctl_set(&b, "aw_dev_1_switch", "Enable") == -EIO' \
  'PASS prepare: exact names, playback/capture, MAJ:MIN; private 0700 directory; control opened and its node removed'
w3_mutant mmap-access 'hw_set_mask(&hw, SNDRV_PCM_HW_PARAM_ACCESS, SNDRV_PCM_ACCESS_RW_INTERLEAVED);' \
  '    hw_set_mask(&hw, SNDRV_PCM_HW_PARAM_ACCESS, SNDRV_PCM_ACCESS_MMAP_INTERLEAVED);' \
  'h->masks[SNDRV_PCM_HW_PARAM_ACCESS - SNDRV_PCM_HW_PARAM_FIRST_MASK].bits[0] == 1u << SNDRV_PCM_ACCESS_RW_INTERLEAVED' \
  'PASS controls: enumerated item by name, written then read back; unknown item or control, a read-back that differs, a non-enumerated or duplicated control refused'
w3_mutant no-direction-check 'if (!strstr(buf + used, want)) return -ENODEV;' '                (void)want;' \
  'prep(&b) == want[i] && !dir_live && live_nodes() == 0 && open_fds() == 0' \
  'PASS prepare is separate and once-open; close is DROP then close; release leaves no fd, node or directory'
w3_mutant period-check-removed 'if (ps->min != period || ps->max != period || pc->min != periods || pc->max != periods ||' \
  '    if (period == 0 ||' \
  'm11_snd_pcm_open(&b, M11_SND_RX, 96000, 3, SNDRV_PCM_FORMAT_S32_LE, 682, 2, 170, INT_MAX) == -EPROTO' \
  'PASS prepare refused: missing, wrong-direction, duplicated or prefix-only name, malformed or mixed majors, existing directory, a node that opens another device; nothing left behind'
# P5 W5 (docs/m11-argon-speaker-run-design.md, sections 3 and 4): the speaker session under the REAL custodian,
# region manager, engine and intent journal; a forked ADSP stand-in; memfd and ALSA fixtures. No device.
w5_srcs=("${tc_srcs[@]}" "$own/m11_custodian.c" "$here/gpr_transport_native.c" "$here/shmem_backend_native.c"
         "$here/intent_journal_native.c" "$here/snd_backend_native.c" "$here/speaker_plan_native.c"
         "$here/speaker_session_native.c" "$here/test-speaker-session-native.c")
for cm_cc in gcc clang; do
  "$cm_cc" "${cm_flags[@]}" "${w5_srcs[@]}" -o "$out/speaker-session-native-$cm_cc"
  timeout 180 "$out/speaker-session-native-$cm_cc" | tee "$out/speaker-session-native-$cm_cc.log"
done
gcc "${cm_flags[@]}" -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer \
  "${w5_srcs[@]}" -o "$out/speaker-session-native-sanitize"
timeout 180 "$out/speaker-session-native-sanitize" | tee "$out/speaker-session-native-sanitize.log"
for f in speaker_plan_native.c speaker_session_native.c; do
  if gcc -std=c11 -DM11_ANCHOR_NATIVE -I "$own" -I "$repair" -I "$here" -c "$here/$f" -o "$out/spk-refused.o" 2>/dev/null; then
    echo "ERROR: $f compiled outside M11_CUSTODIAN_NATIVE" >&2; exit 1
  fi
done
echo 'PASS W5 speaker session (gcc, clang, ASan+UBSan) and refused outside M11_CUSTODIAN_NATIVE'
w5_mutant() { # name file pattern replacement assertion last-pass (same detection rule as gtn_mutant)
  local name="$1" file="$2" pat="$3" rep="$4" want="$5" last="$6" dir="$out/spk-mutant-$1" rc=0 got
  mkdir -p "$dir"
  awk -v pat="$pat" -v rep="$rep" 'index($0,pat){n++; print rep; next} {print} END{if(n!=1) exit 3}' \
    "$here/$file" > "$dir/$file"
  local srcs=() s
  for s in "${w5_srcs[@]}"; do [[ "$(basename "$s")" == "$file" ]] && srcs+=("$dir/$file") || srcs+=("$s"); done
  gcc "${cm_flags[@]}" "${srcs[@]}" -o "$dir/bin"
  timeout 180 "$dir/bin" > "$dir/log" 2>&1 || rc=$?
  got="$(grep '^PASS ' "$dir/log" | tail -n1 || true)"
  if [[ "$rc" != 134 ]] || ! grep -qF -- "Assertion \`$want' failed" "$dir/log" || [[ "$got" != "$last" ]]; then
    echo "ERROR: W5 mutant $name not detected for the expected reason (rc=$rc, last PASS: '${got}')" >&2
    cat "$dir/log" >&2; exit 1
  fi
  echo "PASS W5 test detects mutant $name: Assertion \`$want'"
}
w5_spk_plan='PASS plan: generator format parsed (graphs, IDs, back ends, controls, Re, PCM); truncation, magic and section order refused'
w5_spk_happy='PASS happy path: back ends before graphs, VI before RX, Re read back, gate, amplifier on, RX prepare, 13 buffers, EOS; amplifier off first, then stop, back-end close and close in order; regions held, no UNMAP'
w5_spk_before='PASS before the gate: a refused RX START or a Re read-back that differs never writes Enable; started graphs stopped, back ends closed, graphs closed'
# the amplifier switched on before the RX graph started: the gate's re-read catches it
w5_mutant amp-before-start speaker_session_native.c 'done(s, M11_SPK_RX_PREPARE, "rx_prepare");' \
  '    done(s, M11_SPK_RX_PREPARE, "rx_prepare"); (void)set_switches(s, "Enable"); /* MUTANT */' \
  'rc == 0 && rep.stage == M11_SPK_EOS && rep.amp_off_verified && !rep.teardown_rc' "$w5_spk_plan"
# a failed Re read-back does not stop the session
w5_mutant re-unverified speaker_session_native.c 'if (rc || !r->re.pair_re_readback_verified) return fail(s, M11_SPK_RX_RE, "rx_re", rc ? rc : -EIO);' \
  '    (void)rc;' \
  'rc < 0 && rep.fail_step == M11_SPK_RX_RE && !rep.amp_touched && at("sw0=Enable") < 0' "$w5_spk_happy"
# the teardown never drives the switches Disable
w5_mutant amp-off-skipped speaker_session_native.c 'if (r->amp_touched) {' '    if (0) {' \
  'rc == 0 && rep.stage == M11_SPK_EOS && rep.amp_off_verified && !rep.teardown_rc' "$w5_spk_plan"
# a single-parameter config sent to APM instead of its module (the stock routing rule)
w5_mutant cfg-to-apm speaker_session_native.c 'const uint32_t dst = (((first[2] + 7u) & ~7u) + 16u == b->len) ? first[0] : M11_APM_MODULE_IID;' \
  '    const uint32_t dst = M11_APM_MODULE_IID; (void)first;' \
  'count(op(M11_APM_CMD_SET_CFG, 1)) == 2 && count(op(M11_APM_CMD_SET_CFG, 0x428F)) == 3 + 6' "$w5_spk_plan"
# the gate does not re-read the switches
w5_mutant no-gate speaker_session_native.c 'if ((rc = switches_read(s, "Disable"))) { r->amp_touched = 1; return fail(s, M11_SPK_GATE, "gate", rc); }' \
  '    (void)0;' \
  'rc == -EIO && rep.fail_step == M11_SPK_GATE && !rep.amp_on && at("sw0=Enable") < 0 && last("sw0=Disable") > at("rx_hw") && rep.amp_off_verified' \
  "$w5_spk_before"
# the teardown leaves the RX back end open
w5_mutant rx-be-left-open speaker_session_native.c 'rc = m11_snd_pcm_close(io->snd, M11_SND_RX);' '        rc = 0;' \
  'amp_off < rx_stop && rx_stop < at("rx_drop") && at("rx_drop") < last(op(M11_APM_CMD_GRAPH_STOP, 1))' "$w5_spk_plan"
# W5b: a graph command sent around the custodian (the engine directly): the custodian's foreign-traffic latch
# refuses the next session call
w5_mutant bypass-custodian speaker_session_native.c 'int rc = m11_custodian_graph_cmd(s->io->cust, g, opcode, now(s));' \
  '    uint32_t st_ = 0; int rc = m11_apm_transact_graph_mgmt(eng(s), opcode, s->io->cust->graphs[g].sgs, s->io->cust->graphs[g].num_sgs, 300, &st_); /* MUTANT */' \
  'rc == 0 && rep.stage == M11_SPK_EOS && rep.amp_off_verified && !rep.teardown_rc' "$w5_spk_plan"
# W5b: every out-of-band payload written at the same offset (a payload whose reply never came may still be read)
w5_mutant oob-reused speaker_session_native.c 's->oob_next = (uint32_t)(((size_t)s->oob_next + len + OOB_ALIGN - 1u) / OOB_ALIGN * OOB_ALIGN);' \
  '    (void)0; /* MUTANT */' \
  '!memcmp(cmdr, plan.vi.open.data, plan.vi.open.len) && !memcmp(cmdr + 4096, plan.vi.cal.data, plan.vi.cal.len) && !memcmp(cmdr + 8192, plan.rx.open.data, plan.rx.open.len) && !memcmp(cmdr + 12288, plan.rx.cal.data, plan.rx.cal.len)' \
  "$w5_spk_plan"
# P5 (W6, docs/m11-argon-speaker-run-design.md): the speaker PID1 binary (speaker_entry_main: the P4 composition,
# the plan check, the rotating journal, P2's pre-seal ALSA hook and the speaker session) links with production
# defaults and refuses to act outside PID1; p5/build.sh compiles exactly these units; T10 for P5: no input it
# compiles and neither linked binary names the SysRq trigger.
p5_main=()
for s in "${p3_main[@]}"; do [[ "$s" == "$here/custodian_entry_main.c" ]] || p5_main+=("$s"); done
p5_main+=("$here/snd_backend_native.c" "$here/speaker_plan_native.c" "$here/speaker_session_native.c" "$here/speaker_entry_main.c")
for cm_cc in gcc clang; do
  "$cm_cc" "${p2_flags[@]}" "${p5_main[@]}" -o "$out/speaker-entry-$cm_cc"
  rc=0; "$out/speaker-entry-$cm_cc" || rc=$?
  if [[ "$rc" != 2 ]]; then echo "ERROR: speaker entry binary ($cm_cc) did not refuse outside PID1 (rc=$rc)" >&2; exit 1; fi
  if [[ "$(t10_bin "$out/speaker-entry-$cm_cc")" != 0 ]]; then echo "ERROR: T10: the P5 PID1 ($cm_cc) carries a SysRq string" >&2; exit 1; fi
done
if gcc -std=c11 -DM11_ANCHOR_NATIVE -I "$own" -I "$repair" -I "$here" -c "$here/speaker_entry_main.c" -o "$out/p5-refused.o" 2>/dev/null; then
  echo "ERROR: speaker_entry_main.c compiled outside M11_CUSTODIAN_NATIVE" >&2; exit 1
fi
p5_block="$(sed -n '/^ pid1)/,/^  for variant/p' "$here/p5/build.sh")"
p5_units=()
for tok in $(printf '%s\n' "$p5_block" | grep -oE '[A-Za-z0-9_]+' | sort -u); do
  for d in "$repair" "$own" "$here"; do [[ -f "$d/$tok.c" ]] && p5_units+=("$d/$tok.c"); done
done
p5_a="$(for f in "${p5_units[@]}"; do basename "$f"; done | sort)"
p5_b="$(for f in "${p5_main[@]}"; do basename "$f"; done | sort)"
if [[ "$p5_a" != "$p5_b" ]]; then
  echo "ERROR: the p5/build.sh PID1 units differ from the P5 PID1 linked here" >&2
  diff <(printf '%s\n' "$p5_a") <(printf '%s\n' "$p5_b") >&2 || true; exit 1
fi
p5_hits="$(t10_scan "${p5_main[@]}" "$here"/snd_backend_native.h "$here"/speaker_plan_native.h "$here"/speaker_session_native.h \
  "$here/p4/sha256.h" "$here/p5/kmsg-relay.c" "$here/p5/init" "$here/p5/usb")"
if [[ -n "$p5_hits" ]]; then echo "ERROR: T10: SysRq named in P5 PID1 inputs: $p5_hits" >&2; exit 1; fi
echo "PASS P5 speaker PID1 (gcc, clang) links with production defaults and returns 2 outside PID1; refused outside M11_CUSTODIAN_NATIVE; p5/build.sh compiles exactly its ${#p5_main[@]} units; T10: no SysRq in its inputs or binaries"
p4e_mutant() { # name asroot pattern replacement assertion last-pass (same detection rule as gtn_mutant)
  local name="$1" asroot="$2" pat="$3" rep="$4" want="$5" last="$6" dir="$out/p4e-mutant-$1" rc=0 got file=p4_env_native.c
  if [[ "$asroot" == 1 && "$sudo_ok" != 1 ]]; then echo "SKIP P4 environment mutant $name: no sudo"; return; fi
  mkdir -p "$dir"
  awk -v pat="$pat" -v rep="$rep" 'index($0,pat){n++; print rep; next} {print} END{if(n!=1) exit 3}' \
    "$here/$file" > "$dir/$file"
  local srcs=() s
  for s in "${p4e_srcs[@]}"; do [[ "$(basename "$s")" == "$file" ]] && srcs+=("$dir/$file") || srcs+=("$s"); done
  gcc "${p2_flags[@]}" "${srcs[@]}" -o "$dir/bin"
  if [[ "$asroot" == 1 ]]; then
    timeout 180 sudo -n "$dir/bin" "$dir" "$out/p4-helper" > "$dir/log" 2>&1 || rc=$?
    sudo -n rm -rf "$dir"/m11-p4env-*
  else
    timeout 180 "$dir/bin" "$dir" "$out/p4-helper" > "$dir/log" 2>&1 || rc=$?
    rm -rf "$dir"/m11-p4env-*
  fi
  got="$(grep '^PASS ' "$dir/log" | tail -n1 || true)"
  if [[ "$rc" != 134 ]] || ! grep -qF -- "Assertion \`$want' failed" "$dir/log" || [[ "$got" != "$last" ]]; then
    echo "ERROR: P4 environment mutant $name not detected for the expected reason (rc=$rc, last PASS: '${got}')" >&2
    cat "$dir/log" >&2; exit 1
  fi
  echo "PASS P4 environment test detects mutant $name: Assertion \`$want'"
}
p4e_mutant amp-result-unchecked 0 'FAIL(7, -EPERM);' '    (void)result;' \
  'st == 0 && strstr(rep, "ENV rc=-1 step=7 estep=6") && strstr(rep, "jobs=prepare,journal,probe,start,usb_start,amp_gate ")' \
  'PASS P4 environment: a locator that never reports ready stops the phase (it is left running, never killed)'
p4e_mutant helper-fds-kept 0 'if (!failed && keep_lo > 3) failed = syscall(SYS_close_range, 3u, (unsigned)keep_lo - 1u, 0u) != 0;' '        (void)0;' \
  'strstr(rep, " fds=0]") && strstr(rep, "M11P4 v=1 env step=8 metadata rc=0")' \
  'PASS P4 environment defaults: Run23'"'"'s scripts, helpers, markers and deadlines; checked root images, tmpfs log, dropped helpers'
p4e_mutant drop-skipped 1 'if (!failed && c->drop_helpers) failed = drop_privileges();' '        (void)drop_privileges;' \
  'strstr(rep, "loc=[uid=65534 caps=0000000000000000 fds=0]") && strstr(rep, "rel=[uid=65534 caps=0000000000000000 fds=0]")' \
  'PASS P4 environment: a helper log off tmpfs (production rule) is refused'
# B3: the off-device cmdline summary (cmdline_summary.py) equals the entry's B6 record body.
b3_srcs=()
for s in "${p3_srcs[@]}"; do [[ "$s" == "$here/test-entry-native.c" ]] && b3_srcs+=("$here/test-cmdline-summary.c") || b3_srcs+=("$s"); done
gcc "${p2_flags[@]}" -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer \
  "${b3_srcs[@]}" -o "$out/cmdline-summary-driver"
python3 "$here/test-cmdline-summary.py" "$out/cmdline-summary-driver" | tee "$out/cmdline-summary.log"
# P4 item 3 (docs/m11-argon-p4-assembly.md): the host evidence check over synthetic captures and over
# the record lines the C writers produced in the P3 root sections (p4-journal-*.txt, required whenever
# those ran), plus four one-line mutants of the check. The staging rules are tested on the operator PC
# with the local staging (never exported); the binaries are built by the m11-r2 P4 jobs.
find "$here/p4" -maxdepth 1 -type f -exec sha256sum {} + | sort -k2 > "$out/p4-inputs.sha256"
p4a_req=(); [[ "$sudo_ok" == 1 ]] && p4a_req=(--require-c)
python3 "$here/p4/test-p4-check.py" "$out" "${p4a_req[@]}" | tee "$out/p4-check.log"
grep -qF 'PASS P4 host-check tests' "$out/p4-check.log"
if [[ "$sudo_ok" == 1 ]]; then grep -qF 'PASS P4 check over the C writers (helpers-ok' "$out/p4-check.log"; fi
p4c_mutant() { # name pattern replacement expected-case: the suite must fail on that case's assertion
  local name="$1" pat="$2" rep="$3" want="$4" dir="$out/p4c-mutant-$1" rc=0
  mkdir -p "$dir"
  awk -v pat="$pat" -v rep="$rep" 'index($0,pat){n++; print rep; next} {print} END{if(n!=1) exit 3}' \
    "$here/p4/check-capture.py" > "$dir/check-capture.py"
  M11_P4_CHECK_MUTANT="$dir/check-capture.py" python3 "$here/p4/test-p4-check.py" > "$dir/log" 2>&1 || rc=$?
  if [[ "$rc" != 1 ]] || ! grep -q '^AssertionError' "$dir/log" || ! grep -qF -- "$want" "$dir/log"; then
    echo "ERROR: P4 check mutant $name not detected for the expected reason (rc=$rc)" >&2
    cat "$dir/log" >&2; exit 1
  fi
  echo "PASS P4 host-check test detects mutant $name: $want"
}
p4c_mutant caller-unchecked "        if caller != 'T1':" '        if False:' "('record not from PID1', 'record-not-from-pid1'"
p4c_mutant intents-ignored "         'intents': sum(1 for r in entry if r['kind'] == 'intent')," \
  "         'intents': 0, 'records': len(records), 'b3': 'not-compared'}" "('MAP intent recorded', 'orderly-shape-invalid'"
p4c_mutant b3-unchecked "            d['b3'] = 'match' if" "            d['b3'] = 'match'" "('b3 strict differs', 'b3-cmdline-differs'"
p4c_mutant teardown-steps-unchecked "    if n['steps'] != TEARDOWN_STEPS:" '    if False:' "('teardown list not Run23', 'teardown-steps-differ'"
p4c_mutant seal-unchecked "        if td is not None or seal is None:" '        if td is not None:' "('retaining end without the seal', 'retaining-end-unsealed'"
p3_mutant() { # name asroot pattern replacement assertion last-pass (same detection rule as gtn_mutant)
  local name="$1" asroot="$2" pat="$3" rep="$4" want="$5" last="$6" dir="$out/cen-mutant-$1" rc=0 got file=custodian_entry_native.c
  if [[ "$asroot" == 1 && "$sudo_ok" != 1 ]]; then echo "SKIP P3 mutant $name: no sudo"; return; fi
  mkdir -p "$dir"
  awk -v pat="$pat" -v rep="$rep" 'index($0,pat){n++; print rep; next} {print} END{if(n!=1) exit 3}' \
    "$here/$file" > "$dir/$file"
  local srcs=() s
  for s in "${p3_srcs[@]}"; do [[ "$(basename "$s")" == "$file" ]] && srcs+=("$dir/$file") || srcs+=("$s"); done
  gcc "${p2_flags[@]}" "${srcs[@]}" -o "$dir/bin"
  if [[ "$asroot" == 1 ]]; then
    timeout 180 sudo -n "$dir/bin" "$dir" > "$dir/log" 2>&1 || rc=$?
    sudo -n rm -rf "$dir"/m11-entry-*
  else
    timeout 180 "$dir/bin" "$dir" > "$dir/log" 2>&1 || rc=$?
    rm -rf "$dir"/m11-entry-*
  fi
  got="$(grep '^PASS ' "$dir/log" | tail -n1 || true)"
  if [[ "$rc" != 134 ]] || ! grep -qF -- "Assertion \`$want' failed" "$dir/log" || [[ "$got" != "$last" ]]; then
    echo "ERROR: P3 mutant $name not detected for the expected reason (rc=$rc, last PASS: '${got}')" >&2
    cat "$dir/log" >&2; exit 1
  fi
  echo "PASS P3 test detects mutant $name: Assertion \`$want'"
}
p3_mutant cmdline-gate-late 0 'if (!allowed) return entry_fail(e, "cmdline", 3, -EPERM);' '    (void)allowed;' \
  'st == 0 && strstr(rep, "CALLS perm=-1 inval=-22 first=-14 second=-114 phase=1/1 fail_step=3/3")' \
  'PASS default entry: PID1 only, /dev/kmsg (1:11) journal, /proc/cmdline, the AF_QIPCRTR monitor (10 s bring-up), the real nodes, no session (never maps), production terminal ops'
p3_mutant kmsg-identity-unchecked 0 'if (cfg->journal_require_kmsg && (!S_ISCHR(st.st_mode) || st.st_rdev != makedev(1, 11))) {' '    if (0) {' \
  'st == 43 && strstr(rep, "REBOOT phase=0 fail_step=2 fail_rc=-19 ") && strstr(rep, "sockets=0 spawner=1") && strstr(rep, "phases=- lines=0 ")' \
  'PASS entry calls: not PID1 and a bad configuration touch nothing and do not count; the first real call does, a second is refused and changes nothing'
p3_mutant pd-not-awaited 0 'rc = m11_pdmon_wait_up(&e->pdmon, cfg->pd_ready_budget_ms);' '        (void)0;' \
  'st == 43 && strstr(rep, "REBOOT phase=2 fail_step=4 fail_rc=-102 ") && strstr(rep, "regs=1 sockets=1 spawner=1 anchors_open=0/4 ep_node=0")' \
  'PASS entry refused by the effective cmdline before anything is opened: no PD socket, no node; the verdict, gate tokens, length and CRC journaled (never the text); START_FAILED, the sealed teardown (CYAN; the spawner forked for it), reboot'
# B4: a failure before any bind reboots, a failure after one never does; B6: the cmdline record.
p3_mutant prebind-exits 0 'const int reboot = nothing_opened(e);' '    const int reboot = 0; (void)nothing_opened;' \
  'st == 43 && strstr(rep, "REBOOT phase=0 fail_step=2 fail_rc=-19 ") && strstr(rep, "sockets=0 spawner=1") && strstr(rep, "phases=- lines=0 ")' \
  'PASS entry calls: not PID1 and a bad configuration touch nothing and do not count; the first real call does, a second is refused and changes nothing'
p3_mutant reboot-after-bind 1 'const int reboot = nothing_opened(e);' '    const int reboot = 1; (void)nothing_opened;' \
  'st == 42 && strstr(rep, "EXIT phase=3 fail_step=4 fail_rc=-17 ") && strstr(rep, "spawner=1 anchors_open=2/4") && !strstr(rep, "REBOOT")' \
  'PASS entry with the PD DOWN before any MAP: acknowledged at once (nothing mapped), retaining end (a PD DOWN loses the kernel imports)'
# B5: the PD listener withdrawn before any control job, job status and the evidence marker checked.
p3_mutant retire-skipped 1 'int rc = m11_pdmon_retire(&e->pdmon, c->pd_retire_budget_ms);' '    int rc = 0;' \
  'st == 43 && strstr(rep, "REBOOT phase=7 fail_step=0 fail_rc=0 hold=0 busy=0 deferred=0 acks_sent=0 regs=2 sockets=1 spawner=1 anchors_open=0/4 ep_node=0 ion_node=0")' \
  'PASS entry whose reboot returns: journaled (reboot_failed) and ended through the retaining PID1 exit'
# (the job status is now first checked by R1's pre-bind failure teardown, unprivileged)
p3_mutant job-status-ignored 0 'return rc ? rc : status ? -ECHILD : 0;' '        (void)status; return rc;' \
  'st == 44 && strstr(rep, "HOLD phase=1 fail_step=3 fail_rc=-1 ") && strstr(rep, "jobs=seal,usb_stop ") && !strstr(rep, "REBOOT")' \
  'PASS entry with a refused boot before any bind (an endpoint node already exists): the P2 step journaled, nothing opened or closed; reboot'
p3_mutant evidence-unchecked 1 'return -ENODATA;' '        (void)b; (void)st;' \
  'st == 44 && strstr(rep, "HOLD phase=7 ") && strstr(rep, "td=1/-61 step=2 pds=6 jobs=seal ") && !strstr(rep, "REBOOT")' \
  'PASS B5 PD listener not withdrawn (no answer within the budget): hold before any control job (USB and ADSP untouched)'
p3_mutant reap-status-ignored 1 'if (got == pid) return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -ECHILD;' '            if (got == pid) return 0;' \
  'st == 44 && strstr(rep, "HOLD phase=7 ") && strstr(rep, "td=1/-10 step=7 pds=6 jobs=seal,usb_stop,stop_adsp ") && !strstr(rep, "REBOOT")' \
  "PASS P4 teardown, Run23's whole sequence: seal, relay reaped, logger.done, usb_stop, stop_adsp, pd.stop, locator reaped, pd.done, common, checkpoint, unmount, then the reboot"
p3_mutant no-cmdline-record 0 'phase_record(e, "phase=cmdline %s", summary);' '    (void)summary;' \
  'strstr(rep, "action=START_FAILED end=reboot phase=cmdline step=3 rc=-1 anchors_held=0/2 boot_stage=0") && strstr(rep, "phases=journal,cmdline,teardown lines=4 ")' \
  "PASS entry refused when the journal is not the kernel log: nothing written to it, no socket; nothing audio opened, so Run23's sealed teardown (CYAN), then reboot"
p3_mutant map-intent-not-busy 1 'm11_pds_resources_busy(&e->pdmon.pds);' '    (void)e;' \
  'strstr(rep, "MAP rc=0 busy=1 intents=1") && strstr(rep, "PEER n=1") && !strstr(rep, "PEER down_sent") && !strstr(rep, "PEER_VIOLATION")' \
  'PASS entry, production shape (no session): P1 UP, P2 boot (nodes made, bound, sealed, removed), runner start, close, G8 orderly end: both anchors final-closed, reboot; nothing sent'
# Post-MAP hold: a mapped boot never holds (its end is the retaining reset at once), so the HOLD
# wait is driven by the never-mapped foreign-traffic case (HOLD_RECONCILE until the deadline).
p3_mutant hold-not-waited 1 'if (rc != -EBUSY) return rc;' '        return rc;' \
  'st == 42 && strstr(rep, "EXIT phase=7 ") && hold_of(rep) >= 2 && strstr(rep, "intents=0") && strstr(rep, "anchors_open=4/4")' \
  'PASS entry with a mapped region left (PD UP throughout): the MAP intent latched resources busy before the TX; close refused, no HOLD wait: the retaining end at once, holding every anchor and the mapped region (post-MAP hold)'
# Run25 readiness R1/D2: the pre-bind failure end tears down sealed (CYAN) before the reboot; every
# retaining exit seals first.
p3_mutant fail-teardown-skipped 0 'if (e->cfg.teardown_count && fail_teardown(e)) { /* R1' '        if (0 && fail_teardown(e)) {' \
  'st == 43 && strstr(rep, "REBOOT phase=0 fail_step=2 fail_rc=-19 ") && strstr(rep, "sockets=0 spawner=1") && strstr(rep, "phases=- lines=0 ")' \
  'PASS entry calls: not PID1 and a bad configuration touch nothing and do not count; the first real call does, a second is refused and changes nothing'
p3_mutant failure-colour-green 0 'e->result = "cyan";' '    e->result = "green";' \
  'strstr(rep, "jobs=seal,usb_stop,stop_adsp,common,checkpoint-cyan,unmount ") && strstr(rep, "td=0/0 step=8 ")' \
  'PASS entry calls: not PID1 and a bad configuration touch nothing and do not count; the first real call does, a second is refused and changes nothing'
p3_mutant seal-before-exit-skipped 1 'if (!c->teardown_count || e->steps_started || e->boot.spawner.pid <= 0) return;' '    if (c) return;' \
  'strstr(rep, "phases=journal,cmdline,pd_up,boot,runner,session,seal lines=9 ")' \
  'PASS entry, production shape (no session): P1 UP, P2 boot (nodes made, bound, sealed, removed), runner start, close, G8 orderly end: both anchors final-closed, reboot; nothing sent'
# E-1: the last record gets seal_settle_ms of relay rounds before the seal's logger.stop.
p3_mutant seal-settle-skipped 0 'while (m11_entry_now_ms() < settle_until) sleep_until(settle_until);' '    (void)settle_until; (void)sleep_until;' \
  'settle_of(rep) >= 100 && strstr(rep, "checkpoint-cyan")' \
  "PASS entry refused when the journal is not the kernel log: nothing written to it, no socket; nothing audio opened, so Run23's sealed teardown (CYAN), then reboot"

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
