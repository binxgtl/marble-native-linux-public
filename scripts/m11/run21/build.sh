#!/usr/bin/env bash
# Run21 on-device binaries, built only in CI (no local compiler installation):
#   build.sh runner <out>   static ARM64 PID1 runner with native gcc on ubuntu-24.04-arm
#                           (run16/build.sh pattern); built twice and compared byte for byte;
#                           must refuse to act outside PID1 (rc 2).
#   build.sh relay <out>    freestanding ARM64 relay with the pinned clang-r416183b
#                           (run20/build.sh pattern, x64 host); built twice and compared.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
what=${1:?runner|relay}; out=${2:?output directory}
mkdir -p "$out"
case "$what" in
 runner)
  [[ $(gcc -dumpmachine) == aarch64* ]]
  rt="$root/scripts/m11/runtime"; own="$root/scripts/m11/qualification/ownership"
  native="$root/scripts/m11/anchor-native"; here="$root/scripts/m11/run21"
  for variant in a b; do
   gcc -std=c11 -O2 -Wall -Wextra -Werror -static -no-pie -Wl,--build-id=none -DM11_ANCHOR_NATIVE \
    -I"$here" -I"$native" -I"$rt" -I"$own" \
    "$here/runner.c" "$native/gpr_linux.c" "$native/audio_runtime.c" \
    "$rt/"{gpr_native,gpr_encode,audio_pd,audio_encode}.c \
    "$own/"{m11_pid1_anchor,m11_anchor_linux,m11_anchor_owner}.c \
    -o "$out/m11-run21-$variant"
  done
  cmp "$out/m11-run21-a" "$out/m11-run21-b"
  cp "$out/m11-run21-a" "$out/m11-run21"
  readelf -h -l "$out/m11-run21" > "$out/runner-elf.txt"
  grep -q 'AArch64' "$out/runner-elf.txt"
  ! grep -q INTERP "$out/runner-elf.txt"
  ! grep -q DYNAMIC "$out/runner-elf.txt"
  set +e; "$out/m11-run21"; rc=$?; set -e
  test "$rc" = 2 # never acts outside initial PID1
  gcc --version | head -1 > "$out/runner-compiler.txt"
  (cd "$out" && sha256sum m11-run21 runner-elf.txt runner-compiler.txt > SHA256SUMS-runner)
  ;;
 relay)
  LOCK_FILE="$root/manifests/sources.lock" bash "$root/scripts/setup-toolchain.sh" "$root/artifacts/m11/toolchain"
  cc="$root/artifacts/m11/toolchain/clang-r416183b/bin/clang"
  for side in a b; do
   "$cc" --target=aarch64-linux-gnu -static -nostdlib -nostdinc -ffreestanding \
    -fno-stack-protector -fno-builtin -fno-PIC -fno-asynchronous-unwind-tables \
    -fuse-ld=lld -Wl,-e,_start,--build-id=none -O2 -Wall -Wextra -Werror \
    -o "$out/m11-kmsg-relay-$side" "$root/scripts/m11/run21/kmsg-relay.c"
  done
  cmp "$out/m11-kmsg-relay-a" "$out/m11-kmsg-relay-b"
  cp "$out/m11-kmsg-relay-a" "$out/m11-kmsg-relay"
  "$cc" --version | head -1 > "$out/relay-compiler.txt"
  git -C "$root/artifacts/m11/toolchain/clang-r416183b" rev-parse HEAD > "$out/relay-toolchain-commit.txt"
  (cd "$out" && sha256sum m11-kmsg-relay relay-compiler.txt relay-toolchain-commit.txt > SHA256SUMS-relay)
  ;;
 *) echo "usage: build.sh runner|relay <out>" >&2; exit 2;;
esac
