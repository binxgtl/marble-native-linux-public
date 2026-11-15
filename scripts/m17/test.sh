#!/usr/bin/env bash
# M17: the selector core (G1), K1-keys (G3), the selector (G4) and the native path's runtime, loader, session and volume keys (G5),
# normal and ASan/UBSan, on synthetic trees (no device); then, unless M17_STATIC=0, the phone's static binaries twice, which must
# match. Usage: test.sh OUTDIR [normal]
set -euo pipefail
out=${1:?output}; mkdir -p "$out"
only=${2:-}
src=$(cd "$(dirname "$0")" && pwd)
variants=(normal sanitize)
[[ -n $only ]] && variants=("$only")
for variant in "${variants[@]}"; do
  flags=(-std=c11 -O2 -Wall -Wextra -Werror)
  if [[ $variant == sanitize ]]; then
    flags+=(-O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer)
  fi
  gcc "${flags[@]}" "$src/select.c" "$src/test-select.c" -o "$out/test-select-$variant" &
  first=$!
  gcc "${flags[@]}" "$src/select.c" "$src/g3.c" "$src/test-g3.c" -o "$out/test-g3-$variant" &
  second=$!
  gcc "${flags[@]}" "$src/select.c" "$src/selector.c" "$src/menu.c" "$src/modules.c" "$src/test-g4.c" -o "$out/test-g4-$variant" &
  third=$!
  gcc "${flags[@]}" "$src/select.c" "$src/load.c" "$src/native.c" "$src/cmd.c" "$src/session.c" "$src/volkeys.c" "$src/test-g5.c" \
    -o "$out/test-g5-$variant" &
  fourth=$!
  gcc "${flags[@]}" "$src/awprobe.c" "$src/test-g5b.c" -o "$out/test-g5b-$variant" &
  fifth=$!
  wait "$first"
  wait "$second"
  wait "$third"
  wait "$fourth"
  wait "$fifth"
done
pids=()
for variant in "${variants[@]}"; do
  for name in select g3 g4 g5 g5b; do
    TMPDIR=$(mktemp -d) "$out/test-$name-$variant" >"$out/test-$name-$variant.txt" 2>&1 &
    pids+=("$!")
  done
done
rc=0
for pid in "${pids[@]}"; do
  wait "$pid" || rc=1
done
cat "$out"/test-*-*.txt
[[ $rc -eq 0 ]] || { echo "M17 tests failed" >&2; exit 1; }
echo "M17 selector core, K1-keys, the selector and the native path PASS (${variants[*]})"

[[ ${M17_STATIC:-1} == 1 ]] || exit 0
# The phone's binaries: M19 R1's runtime as PID 1 with K1, and K1 itself (G3); the selector without a native path (G4) and
# with one (G5); the native path's PID 1 with M19 R2's hand-off and R3's guard (G5). Reviewable binaries only, never a boot
# image.
m19=$src/../m19
for copy in a b; do
  flags=(-std=c11 -Os -Wall -Wextra -Werror -static -Wl,--build-id=none)
  gcc "${flags[@]}" "$m19/unlock/hash.c" "$m19/run1/r1.c" "$src/pid-g3.c" -o "$out/m17-pid-g3-$copy"
  gcc "${flags[@]}" "$src/select.c" "$src/g3.c" "$src/keys-main.c" -o "$out/m17-keys-$copy"
  gcc "${flags[@]}" "$src/select.c" "$src/selector.c" "$src/menu.c" "$src/modules.c" "$src/kms.c" "$src/selector-main.c" -o "$out/m17-selector-$copy"
  gcc "${flags[@]}" -DM17_NATIVE_BUILD=1 "$src/select.c" "$src/selector.c" "$src/menu.c" "$src/modules.c" "$src/kms.c" "$src/selector-main.c" \
    -o "$out/m17-selector-native-$copy"
  gcc "${flags[@]}" "$m19/unlock/hash.c" "$m19/run2/wire.c" "$m19/run2/handoff.c" "$m19/run2/report.c" "$src/select.c" "$src/load.c" \
    "$src/native.c" "$src/cmd.c" "$src/session.c" "$src/volkeys.c" "$src/native-main.c" -o "$out/m17-native-$copy"
done
# G5b: M19 R6's m19-sink, built as M19 builds it (scripts/m19/run6/test.sh: the same units, flags and options), but for
# its stream and entry, which are M19's with the protection probe added in marked blocks (test-g5.py checks the rest is
# M19's byte for byte), and the probe itself.
repair=$m19/../m11/qualification/runtime-repair
own=$m19/../m11/qualification/ownership
native=$m19/../m11/anchor-native
sink_srcs=("$m19/unlock/hash.c")
for u in m11_gpr_engine m11_shmem m11_apm_protocol m11_aw_protection m11_strict_mock; do
  sink_srcs+=("$repair/$u.c")
done
for u in m11_custodian m11_pid1_anchor m11_anchor_linux m11_anchor_owner; do
  sink_srcs+=("$own/$u.c")
done
for u in gpr_transport_native shmem_backend_native dmabuf_pool_native heap_node_native intent_journal_native \
         pdr_loop_native terminal_native custodian_runner_native custodian_boot_native pd_session_native \
         custodian_entry_native snd_backend_native speaker_plan_native; do
  sink_srcs+=("$native/$u.c")
done
sink_srcs+=("$src/sink-stream.c" "$m19/run6/sink.c" "$src/awprobe.c")
m11_flags=(-DM11_ANCHOR_NATIVE -DM11_CUSTODIAN_NATIVE -DM11_ANCHOR_NATIVE_ION -I"$own" -I"$repair" -I"$native" -I"$m19/run6")
for copy in a b; do
  gcc -std=c11 -O2 -Wall -Wextra -Werror -static -no-pie -Wl,--build-id=none "${m11_flags[@]}" "${sink_srcs[@]}" "$src/sink-main.c" \
    -o "$out/m17-sink-$copy"
done
for name in m17-pid-g3 m17-keys m17-selector m17-selector-native m17-native m17-sink; do
  cmp "$out/$name-a" "$out/$name-b"
  sha256sum "$out/$name-a"
done | tee "$out/m17-binaries.txt"
