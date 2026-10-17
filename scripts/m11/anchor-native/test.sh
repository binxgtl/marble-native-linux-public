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
