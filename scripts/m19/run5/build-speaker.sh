#!/usr/bin/env bash
# Build the M19 R5b session speaker holder (m19-speaker) twice from M11 Run31's frozen native sources and
# M19's session wrapper, compare byte for byte, verify static linkage (no INTERP, no DYNAMIC), and verify safe
# non-root / extra-arg refusal without touching any device.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
out=${1:?output directory}
mkdir -p "$out"

repair="$root/scripts/m11/qualification/runtime-repair"
own="$root/scripts/m11/qualification/ownership"
native="$root/scripts/m11/anchor-native"
r5="$root/scripts/m19/run5"
hash="$root/scripts/m19/unlock/hash.c"

srcs=("$hash")
for u in m11_gpr_engine m11_shmem m11_apm_protocol m11_aw_protection m11_strict_mock; do
  srcs+=("$repair/$u.c")
done
for u in m11_custodian m11_pid1_anchor m11_anchor_linux m11_anchor_owner; do
  srcs+=("$own/$u.c")
done
for u in gpr_transport_native shmem_backend_native dmabuf_pool_native heap_node_native intent_journal_native \
         pdr_loop_native terminal_native custodian_runner_native custodian_boot_native pd_session_native \
         custodian_entry_native snd_backend_native speaker_plan_native speaker_session_native; do
  srcs+=("$native/$u.c")
done
srcs+=("$r5/speaker.c" "$r5/speaker-main.c")

spk_pids=()
for copy in a b; do
  gcc -std=c11 -O2 -Wall -Wextra -Werror -static -no-pie -Wl,--build-id=none \
    -DM11_ANCHOR_NATIVE -DM11_CUSTODIAN_NATIVE -DM11_ANCHOR_NATIVE_ION \
    -I"$own" -I"$repair" -I"$native" -I"$r5" \
    "${srcs[@]}" -o "$out/m19-speaker-$copy" &
  spk_pids+=("$!")
done
for pid in "${spk_pids[@]}"; do
  wait "$pid"
done

cmp "$out/m19-speaker-a" "$out/m19-speaker-b"
readelf -h -l "$out/m19-speaker-a" > "$out/speaker-elf.txt"
grep -q 'EXEC (Executable file)' "$out/speaker-elf.txt"
if [[ $(gcc -dumpmachine) == aarch64* ]]; then
  grep -q 'AArch64' "$out/speaker-elf.txt"
fi
if grep -q INTERP "$out/speaker-elf.txt" || grep -q DYNAMIC "$out/speaker-elf.txt"; then
  echo 'm19-speaker not static' >&2
  exit 1
fi

set +e
"$out/m19-speaker-a" extra
rc_extra=$?
if [[ $(id -u) -ne 0 ]]; then
  "$out/m19-speaker-a"
  rc_nonroot=$?
else
  rc_nonroot=2
fi
set -e
test "$rc_extra" = 2 && test "$rc_nonroot" = 2
sha256sum "$out/m19-speaker-a" >> "$out/run5-binaries.txt"
