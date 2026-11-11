#!/usr/bin/env bash
# Run on an ARM64 build worker with a static libc and liblzma development files.
# Does not install a toolchain. CI provisioning/validation is a separate task.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
: "${CC:?Set CC to the ARM64 Linux C compiler (for example gcc on an ARM64 worker)}"
work="$root/artifacts/m11/run12-pdr-build"
mkdir -p "$work"
fetch() {
 local name=$1 url=$2 commit=$3
 if [[ ! -d "$work/$name/.git" ]]; then
  git init "$work/$name"
  git -C "$work/$name" remote add origin "$url"
 fi
 [[ $(git -C "$work/$name" remote get-url origin) == "$url" ]]
 git -C "$work/$name" fetch --depth=1 origin "$commit"
 git -C "$work/$name" checkout --detach "$commit"
 [[ $(git -C "$work/$name" rev-parse HEAD) == "$commit" ]]
 [[ -z $(git -C "$work/$name" status --porcelain) ]]
}
fetch pd-mapper https://github.com/linux-msm/pd-mapper.git 5ecd2fe926aca7abfe40724177f63b942cff3947
fetch qrtr https://github.com/linux-msm/qrtr.git 29e36ae164389580a0f8ea7a7fdb728140ae978d
pd="$work/pd-mapper"; qr="$work/qrtr"
# Compile our code under Werror; upstream warnings are recorded independently.
"$CC" -std=gnu11 -O2 -fno-pie -Wall -Wextra -Werror -I"$pd" -I"$qr/include" \
 -c "$root/scripts/m11/run12/pd-mapper.c" -o "$work/mapper.o"
for suffix in a b; do
 "$CC" -std=gnu11 -O2 -fno-pie -no-pie -Wall -Wextra -static -Wl,--build-id=none \
  -I"$pd" -I"$qr/include" "$work/mapper.o" \
  "$pd/json.c" "$pd/lzma_decomp.c" "$pd/servreg_loc.c" \
  "$qr/lib/qrtr.c" "$qr/lib/qmi.c" "$qr/lib/logging.c" -llzma \
  -o "$work/m11-pd-mapper-$suffix"
done
cmp "$work/m11-pd-mapper-a" "$work/m11-pd-mapper-b"
cp "$work/m11-pd-mapper-a" "$work/m11-pd-mapper"
"$CC" --version > "$work/compiler.txt"
"$CC" -dumpmachine >> "$work/compiler.txt"
[[ $("$CC" -dumpmachine) == aarch64* ]]
cp "$pd/LICENSE" "$work/pd-mapper-LICENSE"
cp "$qr/LICENSE" "$work/qrtr-LICENSE"
sha256sum "$work/m11-pd-mapper" "$work/compiler.txt" > "$work/SHA256SUMS"
