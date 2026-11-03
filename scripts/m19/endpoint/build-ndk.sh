#!/usr/bin/env bash
# Build the standalone m19-endpoint Android client. This target links no M19 core,
# generated AIDL, or C++ binding objects; Binder NDK is loaded at runtime.
set -euo pipefail

out_arg=${1:?output directory required}
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd -P)
artifacts_root=$repo_root/artifacts/m19/endpoint
mkdir -p "$artifacts_root"
artifacts_root=$(cd "$artifacts_root" && pwd -P)
if [[ "$out_arg" = /* ]]; then
  out=$out_arg
else
  out=$repo_root/$out_arg
fi
out=$(realpath -m "$out")
case "$out" in
  "$artifacts_root"/*) ;;
  *) printf 'output must be below %s\n' "$artifacts_root" >&2; exit 2 ;;
esac
mkdir -p "$out"
out=$(cd "$out" && pwd -P)

if [[ $(uname -m) != x86_64 ]]; then
  printf 'Android NDK cross-build requires an x86_64 Linux host\n' >&2
  exit 2
fi

ndk=${ANDROID_NDK_LATEST_HOME:?ANDROID_NDK_LATEST_HOME is required}
bin=$ndk/toolchains/llvm/prebuilt/linux-x86_64/bin
src=$repo_root/scripts/m19/endpoint
build=$out/ndk-build
mkdir -p "$build/obj-a" "$build/obj-b"

cp "$ndk/source.properties" "$out/ndk-version.txt"
"$bin/clang" --version > "$out/clang-version.txt"
sha256sum "$bin/clang" "$bin/llvm-strip" "$bin/llvm-readelf" > "$out/build-tools.txt"

common=(--target=aarch64-linux-android31 -std=c11 -O2 -fPIE -fno-ident
  -ffile-prefix-map="$repo_root"=. -ffunction-sections -fdata-sections
  -Wall -Wextra -Werror -I"$src")

for copy in a b; do
  obj=$build/obj-$copy
  "$bin/clang" "${common[@]}" -c "$src/endpoint.c" -o "$obj/endpoint.o"
  "$bin/clang" "${common[@]}" -c "$src/supervisor.c" -o "$obj/supervisor.o"
  "$bin/clang" --target=aarch64-linux-android31 -pie \
    -Wl,--build-id=none -Wl,--gc-sections \
    "$obj/endpoint.o" "$obj/supervisor.o" -ldl \
    -o "$build/m19-endpoint-$copy.unstripped"
done

cmp "$build/m19-endpoint-a.unstripped" "$build/m19-endpoint-b.unstripped"
cp "$build/m19-endpoint-a.unstripped" "$out/m19-endpoint-a"
cp "$build/m19-endpoint-b.unstripped" "$out/m19-endpoint-b"
"$bin/llvm-strip" -s "$out/m19-endpoint-a"
"$bin/llvm-strip" -s "$out/m19-endpoint-b"
cmp "$out/m19-endpoint-a" "$out/m19-endpoint-b"

"$bin/llvm-readelf" -d "$out/m19-endpoint-a" | grep 'NEEDED' > "$out/needed.txt"
sha256sum \
  "$build/m19-endpoint-a.unstripped" \
  "$build/m19-endpoint-b.unstripped" \
  "$out/m19-endpoint-a" \
  "$out/m19-endpoint-b" > "$out/binary.txt"
python3 "$src/verify-binary.py" \
  --readelf "$bin/llvm-readelf" \
  --binary "$out/m19-endpoint-a" \
  --report "$out/elf.json"
