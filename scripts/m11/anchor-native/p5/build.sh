#!/usr/bin/env bash
# P5 (Run26 speaker candidate) on-device binaries (docs/m11-argon-speaker-run-design.md, W6), built only in
# CI (no local compiler installation), on the P4 build pattern (p4/build.sh):
#   build.sh pid1 <out>    the speaker PID1 (speaker_entry_main: the plan check, the P4 environment phase,
#                          then the P3 entry with the rotating journal, P2's pre-seal ALSA hook and the
#                          speaker session) static ARM64 with native gcc on ubuntu-24.04-arm; built twice
#                          and compared byte for byte; static (no INTERP, no DYNAMIC); must refuse to act
#                          outside PID1 (rc 2).
#   build.sh relay <out>   the M11R26 relay, freestanding ARM64 with the pinned clang-r416183b (x64 host);
#                          built twice and compared.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../../.." && pwd)
what=${1:?pid1|relay}; out=${2:?output directory}
mkdir -p "$out"
native="$root/scripts/m11/anchor-native"; here="$native/p5"
own="$root/scripts/m11/qualification/ownership"; repair="$root/scripts/m11/qualification/runtime-repair"
case "$what" in
 pid1)
  [[ $(gcc -dumpmachine) == aarch64* ]]
  srcs=()
  for u in m11_gpr_engine m11_shmem m11_apm_protocol m11_aw_protection m11_strict_mock; do srcs+=("$repair/$u.c"); done
  srcs+=("$own/m11_custodian.c" "$own/m11_pid1_anchor.c" "$own/m11_anchor_linux.c" "$own/m11_anchor_owner.c")
  for u in gpr_transport_native shmem_backend_native dmabuf_pool_native heap_node_native intent_journal_native \
           pdr_loop_native terminal_native custodian_runner_native custodian_boot_native pd_session_native \
           custodian_entry_native p4_env_native snd_backend_native speaker_plan_native speaker_session_native \
           speaker_entry_main; do srcs+=("$native/$u.c"); done
  for variant in a b; do
   gcc -std=c11 -O2 -Wall -Wextra -Werror -static -no-pie -Wl,--build-id=none \
    -DM11_ANCHOR_NATIVE -DM11_CUSTODIAN_NATIVE -DM11_ANCHOR_NATIVE_ION \
    -I"$own" -I"$repair" -I"$native" "${srcs[@]}" -o "$out/m11-p5-$variant"
  done
  cmp "$out/m11-p5-a" "$out/m11-p5-b"
  cp "$out/m11-p5-a" "$out/m11-p5"
  readelf -h -l "$out/m11-p5" > "$out/pid1-elf.txt"
  grep -q 'AArch64' "$out/pid1-elf.txt"
  grep -q 'EXEC (Executable file)' "$out/pid1-elf.txt"
  # explicit failures: set -e ignores a command negated with "!" (p4/build.sh's "! grep" lines never fail)
  if grep -q INTERP "$out/pid1-elf.txt" || grep -q DYNAMIC "$out/pid1-elf.txt"; then echo 'PID1 not static' >&2; exit 1; fi
  set +e; "$out/m11-p5"; rc=$?; "$out/m11-p5" extra; rc2=$?; set -e
  test "$rc" = 2 && test "$rc2" = 2 # never acts outside initial PID1
  gcc --version | head -1 > "$out/pid1-compiler.txt"
  (cd "$out" && sha256sum m11-p5 pid1-elf.txt pid1-compiler.txt > SHA256SUMS-pid1)
  ;;
 relay)
  LOCK_FILE="$root/manifests/sources.lock" bash "$root/scripts/setup-toolchain.sh" "$root/artifacts/m11/toolchain"
  cc="$root/artifacts/m11/toolchain/clang-r416183b/bin/clang"
  for side in a b; do
   "$cc" --target=aarch64-linux-gnu -static -nostdlib -nostdinc -ffreestanding \
    -fno-stack-protector -fno-builtin -fno-PIC -fno-asynchronous-unwind-tables \
    -fuse-ld=lld -Wl,-e,_start,--build-id=none -O2 -Wall -Wextra -Werror \
    -o "$out/m11-kmsg-relay-$side" "$here/kmsg-relay.c"
  done
  cmp "$out/m11-kmsg-relay-a" "$out/m11-kmsg-relay-b"
  cp "$out/m11-kmsg-relay-a" "$out/m11-kmsg-relay"
  "$cc" --version | head -1 > "$out/relay-compiler.txt"
  git -C "$root/artifacts/m11/toolchain/clang-r416183b" rev-parse HEAD > "$out/relay-toolchain-commit.txt"
  (cd "$out" && sha256sum m11-kmsg-relay relay-compiler.txt relay-toolchain-commit.txt > SHA256SUMS-relay)
  ;;
 *) echo "usage: build.sh pid1|relay <out>" >&2; exit 2;;
esac
