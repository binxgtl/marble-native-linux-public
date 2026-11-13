#!/usr/bin/env bash
# Build m19-ce for bionic, twice. It needs libbinder_ndk at run time; the island's BoringSSL and
# android.hardware.gatekeeper@1.0.so are opened at run time, and nothing proprietary is linked.
set -euo pipefail
out=${1:?output}; rm -rf "$out"; mkdir -p "$out"
out=$(cd "$out" && pwd)
src=scripts/m19/ce
unlock=scripts/m19/unlock
python3 "$unlock/fetch-aidl.py" --out "$out/aidl"
python3 "$src/fetch-aidl.py" --out "$out/aidl"
aidl=$(ls -d "${ANDROID_HOME:?}"/build-tools/* | sort -V | tail -n 1)/aidl
bin=${ANDROID_NDK_LATEST_HOME:?}/toolchains/llvm/prebuilt/linux-x86_64/bin
cat "$ANDROID_NDK_LATEST_HOME/source.properties" | tee "$out/ndk-version.txt"
sha256sum "$aidl" "$bin/clang" "$bin/llvm-strip" "$bin/llvm-readelf" | tee "$out/build-tools.txt"
includes=(-I"$out/aidl/keymint" -I"$out/aidl/secureclock" -I"$out/aidl/keystore2" -I"$out/aidl/authorization")
while IFS= read -r file; do
  "$aidl" --lang=ndk --structured --stability=vintf --min_sdk_version=31 "${includes[@]}" -h "$out/gen/include" -o "$out/gen" "$file"
done < <(find "$out/aidl/keymint" "$out/aidl/secureclock" "$out/aidl/keystore2" -name '*.aidl' | LC_ALL=C sort)
# IKeystoreAuthorization is a system interface, not a VINTF one.
while IFS= read -r file; do
  "$aidl" --lang=ndk --structured --min_sdk_version=31 "${includes[@]}" -h "$out/gen/include" -o "$out/gen" "$file"
done < <(find "$out/aidl/authorization" -name '*.aidl' | LC_ALL=C sort)
for copy in a b; do
  objects=()
  mkdir -p "$out/obj-$copy"
  common=(--target=aarch64-linux-android31 -O2 -fPIE -fno-ident -ffile-prefix-map="$out"=. -ffunction-sections -fdata-sections
          -isystem "$out/aidl/binder_cpp" -isystem "$out/aidl/binder_platform")
  while IFS= read -r file; do
    object=$out/obj-$copy/$(echo "$file" | sha256sum | cut -c1-16).o
    "$bin/clang++" "${common[@]}" -std=c++17 -I"$out/gen/include" -c "$file" -o "$object"
    objects+=("$object")
  done < <(find "$out/gen" -name '*.cpp' | LC_ALL=C sort)
  for file in "$unlock/binding.cpp" "$src/ks.cpp" "$src/gk.cpp" "$src/main.cpp"; do
    object=$out/obj-$copy/$(basename "$file" .cpp)-cpp.o
    "$bin/clang++" "${common[@]}" -std=c++17 -Wall -Wextra -Werror -I"$out/gen/include" -c "$file" -o "$object"
    objects+=("$object")
  done
  for file in "$unlock/core.c" "$unlock/hash.c" "$src/ce.c" "$src/crypto.c" "$src/fscrypt.c" "$src/broker.c"; do
    object=$out/obj-$copy/$(basename "$file" .c)-c.o
    "$bin/clang" "${common[@]}" -std=c11 -Wall -Wextra -Werror -c "$file" -o "$object"
    objects+=("$object")
  done
  "$bin/clang++" --target=aarch64-linux-android31 -pie -static-libstdc++ -Wl,--build-id=none -Wl,--gc-sections \
    "${objects[@]}" -lbinder_ndk -ldl -o "$out/m19-ce-$copy"
done
cmp "$out/m19-ce-a" "$out/m19-ce-b"
"$bin/llvm-strip" -s "$out/m19-ce-a" "$out/m19-ce-b"
cmp "$out/m19-ce-a" "$out/m19-ce-b"
"$bin/llvm-readelf" -d "$out/m19-ce-a" | grep NEEDED | tee "$out/needed.txt"
python3 "$unlock/check-needed.py" "$out/needed.txt"
# Only verify is reachable in the Gatekeeper interface; no enroll or delete entry point is linked by name.
if "$bin/llvm-readelf" --dyn-syms "$out/m19-ce-a" | grep -E 'enroll|deleteUser|deleteAllUsers'; then
  echo 'm19-ce names a Gatekeeper method other than verify' >&2
  exit 1
fi
sha256sum "$out/m19-ce-a" | tee "$out/ce-binary.txt"
