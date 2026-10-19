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
  'PASS UP throughout: PD traffic during MAP and UNMAP changes nothing; idle wait pumps the monitor'
g6_mutant tx-after-down gpr_transport_native.c '/* no TX once DOWN */' '    rc = 0; (void)rc;' \
  'rc == -ENETRESET && r.glink.writes == 0' \
  'PASS DOWN before the ACK: the DOWN wins, the late ACK is not adopted'
g6_mutant settle-silent pdr_loop_native.c 'm11_custodian_pd_down(l->c, now_ms);' '        (void)now_ms;' \
  'term == M11_TERMINAL_RESET_RETAINING_ANCHORS && (r.boot.reasons & M11_TAINT_PD_DOWN) && r.cust.kernel_imports_lost' \
  'PASS UP throughout: PD traffic during MAP and UNMAP changes nothing; idle wait pumps the monitor'
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
  'PASS fd sink: one write(2) per record; a failed write is -EIO'
g7_mutant tx-despite-sink-failure '/* no TX without its journal record */' '    (void)arc;' \
  'rc < 0 && r.glink.writes == 0 && r.ilink.sink_failures == 1' \
  'PASS MAP and UNMAP journaled before TX (the peer saw each record before its packet), with fd, size and handle'
g7_mutant no-ledger-check 'if ((h.opcode == M11_APM_CMD_SHARED_MEM_MAP_REGIONS && !l->boot->dsp_map_attempted) ||' '    if ((0) ||' \
  'rc < 0 && r.glink.writes == 0 && r.ilink.refused == 1' \
  'PASS sink failure: no TX; the region stays unresolved (unknown TX, fail closed)'
g7_mutant close-all-allowed "return -EPERM; /* outside the custodian's set" '        break;' \
  'm11_intent_format(rec, sizeof rec, 7, 3, pkt, pl) == -EPERM' ''
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
  'PASS composed journal failure: no TX, region unresolved, the end is held (HOLD_RECONCILE)'
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
p3_main+=("$here/pd_session_native.c" "$here/custodian_entry_native.c")
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
for f in custodian_entry_native.c custodian_entry_main.c; do
  if gcc -std=c11 -DM11_ANCHOR_NATIVE -I "$own" -I "$repair" -I "$here" -c "$here/$f" -o "$out/cen-refused.o" 2>/dev/null; then
    echo "ERROR: $f compiled outside M11_CUSTODIAN_NATIVE" >&2; exit 1
  fi
done
echo 'PASS production P3 PID1 entry (gcc, clang, ASan+UBSan, root when sudo); the PID1 binary links and returns 2 outside PID1; refused outside M11_CUSTODIAN_NATIVE'
# B3: the off-device cmdline summary (cmdline_summary.py) equals the entry's B6 record body.
b3_srcs=()
for s in "${p3_srcs[@]}"; do [[ "$s" == "$here/test-entry-native.c" ]] && b3_srcs+=("$here/test-cmdline-summary.c") || b3_srcs+=("$s"); done
gcc "${p2_flags[@]}" -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer \
  "${b3_srcs[@]}" -o "$out/cmdline-summary-driver"
python3 "$here/test-cmdline-summary.py" "$out/cmdline-summary-driver" | tee "$out/cmdline-summary.log"
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
  'st == 43 && strstr(rep, "REBOOT phase=0 fail_step=2 fail_rc=-19 ") && strstr(rep, "sockets=0 spawner=0") && strstr(rep, "phases=- lines=0 ")' \
  'PASS entry calls: not PID1 and a bad configuration touch nothing and do not count; the first real call does, a second is refused and changes nothing'
p3_mutant pd-not-awaited 0 'rc = m11_pdmon_wait_up(&e->pdmon, cfg->pd_ready_budget_ms);' '        (void)0;' \
  'st == 43 && strstr(rep, "REBOOT phase=2 fail_step=4 fail_rc=-102 ") && strstr(rep, "regs=1 sockets=1 spawner=0 anchors_open=0/4 ep_node=0")' \
  'PASS entry refused by the effective cmdline before anything is opened: no PD socket, no spawner, no node; the verdict, gate tokens, length and CRC journaled (never the text); START_FAILED, reboot'
# B4: a failure before any bind reboots, a failure after one never does; B6: the cmdline record.
p3_mutant prebind-exits 0 'const int reboot = nothing_opened(e);' '    const int reboot = 0; (void)nothing_opened;' \
  'st == 43 && strstr(rep, "REBOOT phase=0 fail_step=2 fail_rc=-19 ") && strstr(rep, "sockets=0 spawner=0") && strstr(rep, "phases=- lines=0 ")' \
  'PASS entry calls: not PID1 and a bad configuration touch nothing and do not count; the first real call does, a second is refused and changes nothing'
p3_mutant reboot-after-bind 1 'const int reboot = nothing_opened(e);' '    const int reboot = 1; (void)nothing_opened;' \
  'st == 42 && strstr(rep, "EXIT phase=3 fail_step=4 fail_rc=-17 ") && strstr(rep, "spawner=1 anchors_open=2/4") && !strstr(rep, "REBOOT")' \
  'PASS entry with the PD DOWN before any MAP: acknowledged at once (nothing mapped), retaining end (a PD DOWN loses the kernel imports)'
# B5: the PD listener withdrawn before any control job, job status and the evidence marker checked.
p3_mutant retire-skipped 1 'int rc = m11_pdmon_retire(&e->pdmon, c->pd_retire_budget_ms);' '    int rc = 0;' \
  'st == 43 && strstr(rep, "REBOOT phase=7 fail_step=0 fail_rc=0 hold=0 busy=0 deferred=0 acks_sent=0 regs=2 sockets=1 spawner=1 anchors_open=0/4 ep_node=0 ion_node=0")' \
  'PASS entry whose reboot returns: journaled (reboot_failed) and ended through the retaining PID1 exit'
p3_mutant job-status-ignored 1 'if (rc || status) return e->teardown_rc = rc ? rc : -ECHILD;' '        (void)status;' \
  'st == 44 && strstr(rep, "HOLD phase=7 ") && strstr(rep, "td=1/-10 step=3 pds=6 jobs=seal,usb_stop,stop_adsp ") && strstr(rep, "anchors_open=0/4")' \
  'PASS entry with a boot refused after a bind (ION CMA twin has a node, endpoint HELD): never reboots, retaining PID1 exit holding the endpoint'
p3_mutant evidence-unchecked 1 'if (i == 0 && c->evidence_marker) {' '        if (0) {' \
  'st == 44 && strstr(rep, "HOLD phase=7 ") && strstr(rep, "td=1/-61 step=1 pds=6 jobs=seal ") && !strstr(rep, "REBOOT")' \
  'PASS B5 PD listener not withdrawn (no answer within the budget): hold before any control job (USB and ADSP untouched)'
p3_mutant no-cmdline-record 0 'phase_record(e, "phase=cmdline %s", summary);' '    (void)summary;' \
  'strstr(rep, "action=START_FAILED end=reboot phase=cmdline step=3 rc=-1 anchors_held=0/2 boot_stage=0") && strstr(rep, "phases=journal,cmdline lines=3 ")' \
  'PASS entry refused when the journal is not the kernel log: nothing written to it, no socket, no spawner; nothing audio opened, so reboot'
p3_mutant map-intent-not-busy 1 'm11_pds_resources_busy(&e->pdmon.pds);' '    (void)e;' \
  'strstr(rep, "MAP rc=0 busy=1 intents=1") && strstr(rep, "PEER n=1") && strstr(rep, "PEER down_sent") && !strstr(rep, "PEER_VIOLATION")' \
  'PASS entry, production shape (no session): P1 UP, P2 boot (nodes made, bound, sealed, removed), runner start, close, G8 orderly end: both anchors final-closed, reboot; nothing sent'
p3_mutant hold-not-waited 1 'if (rc != -EBUSY) return rc;' '        return rc;' \
  'st == 42 && strstr(rep, "EXIT phase=7 ") && strstr(rep, "busy=1 deferred=1 acks_sent=0") && strstr(rep, "anchors_open=4/4")' \
  'PASS entry, production shape (no session): P1 UP, P2 boot (nodes made, bound, sealed, removed), runner start, close, G8 orderly end: both anchors final-closed, reboot; nothing sent'

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
