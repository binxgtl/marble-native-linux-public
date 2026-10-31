#!/usr/bin/env bash
# Build m19-unlock for bionic. It needs libbinder_ndk at run time and links nothing proprietary.
set -euo pipefail
out=${1:?output}; rm -rf "$out"; mkdir -p "$out"
out=$(cd "$out" && pwd)
src=scripts/m19/unlock
python3 "$src/fetch-aidl.py" --out "$out/aidl"
aidl=$(ls -d "${ANDROID_HOME:?}"/build-tools/* | sort -V | tail -n 1)/aidl
bin=${ANDROID_NDK_LATEST_HOME:?}/toolchains/llvm/prebuilt/linux-x86_64/bin
"$bin/clang" --version | head -n 1
mapfile -t interfaces < <(find "$out/aidl" -name '*.aidl' | LC_ALL=C sort)
for file in "${interfaces[@]}"; do
  "$aidl" --lang=ndk --structured --stability=vintf --min_sdk_version=31 \
    -I"$out/aidl/keymint" -I"$out/aidl/secureclock" -I"$out/aidl/keystore2" \
    -h "$out/gen/include" -o "$out/gen" "$file"
done
for copy in a b; do
  objects=()
  mkdir -p "$out/obj-$copy"
  common=(--target=aarch64-linux-android31 -O2 -fPIE -fno-ident -ffile-prefix-map="$out"=. -I"$src" -isystem "$out/aidl/binder_cpp")
  while IFS= read -r file; do
    object=$out/obj-$copy/$(echo "$file" | sha256sum | cut -c1-16).o
    "$bin/clang++" "${common[@]}" -std=c++17 -I"$out/gen/include" -c "$file" -o "$object"
    objects+=("$object")
  done < <(find "$out/gen" -name '*.cpp' | LC_ALL=C sort)
  for file in binding main; do
    "$bin/clang++" "${common[@]}" -std=c++17 -Wall -Wextra -Werror -I"$out/gen/include" -c "$src/$file.cpp" -o "$out/obj-$copy/$file.o"
    objects+=("$out/obj-$copy/$file.o")
  done
  for file in core hash dm; do
    "$bin/clang" "${common[@]}" -std=c11 -Wall -Wextra -Werror -c "$src/$file.c" -o "$out/obj-$copy/$file.o"
    objects+=("$out/obj-$copy/$file.o")
  done
  "$bin/clang++" --target=aarch64-linux-android31 -pie -static-libstdc++ -Wl,--build-id=none -Wl,--gc-sections \
    "${objects[@]}" -lbinder_ndk -ldl -o "$out/m19-unlock-$copy"
done
cmp "$out/m19-unlock-a" "$out/m19-unlock-b"
"$bin/llvm-strip" -s "$out/m19-unlock-a"
"$bin/llvm-readelf" -d "$out/m19-unlock-a" | grep NEEDED | tee "$out/needed.txt"
python3 "$src/check-needed.py" "$out/needed.txt"
sha256sum "$out/m19-unlock-a" | tee "$out/unlock-binary.txt"
