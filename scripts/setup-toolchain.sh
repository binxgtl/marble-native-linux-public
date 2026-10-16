#!/usr/bin/env bash
set -euo pipefail

root=${1:-work}
lock_file=${LOCK_FILE:-manifests/sources.lock}
toolchain_dir="$root/clang-r416183b"

field() {
  local name=$1 column=$2
  awk -F '|' -v name="$name" -v column="$column" '$1 == name { print $column; exit }' "$lock_file"
}

url=$(field clang-r416183b 3)
commit=$(field clang-r416183b 5)

if [[ -z "$url" || ! "$commit" =~ ^[0-9a-f]{40}$ ]]; then
  echo "invalid toolchain entry in $lock_file" >&2
  exit 2
fi

mkdir -p "$root"
if [[ ! -d "$toolchain_dir/.git" ]]; then
  git init "$toolchain_dir"
  git -C "$toolchain_dir" remote add origin "$url"
fi

git -C "$toolchain_dir" fetch --depth=1 --no-tags origin "$commit"
git -C "$toolchain_dir" checkout --detach "$commit"
test "$(git -C "$toolchain_dir" rev-parse HEAD)" = "$commit"
test -x "$toolchain_dir/bin/clang"
"$toolchain_dir/bin/clang" --version | tee "$root/toolchain-version.txt"
