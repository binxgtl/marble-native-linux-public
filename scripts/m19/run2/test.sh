#!/usr/bin/env bash
set -euo pipefail
out=${1:?output}; mkdir -p "$out"
src=scripts/m19/run2
hash=scripts/m19/unlock/hash.c
wraps=-Wl,--wrap=umount2,--wrap=mount,--wrap=chroot,--wrap=chdir,--wrap=execve,--wrap=stat,--wrap=ioctl
# The Xorg preload library on a fake libdrm. Never sanitized: ASan must come first in a process, a preload cannot.
gcc -std=c11 -O2 -Wall -Wextra -Werror -shared -fPIC "$src/fake-drm.c" -o "$out/libfakedrm.so"
gcc -std=c11 -O2 -Wall -Wextra -Werror -shared -fPIC "$src/xorg-shim.c" -ldl -o "$out/xorg-shim-test.so"
gcc -std=c11 -O0 -Wall -Wextra -Werror "$src/test-shim.c" -L"$out" -lfakedrm -Wl,-rpath,"$(cd "$out" && pwd)" -o "$out/test-shim"
export M19_SHIM_LIB="$(cd "$out" && pwd)/xorg-shim-test.so" M19_SHIM_DRIVER="$(cd "$out" && pwd)/test-shim"
for variant in normal sanitize; do
  flags=(-std=c11 -O2 -Wall -Wextra -Werror)
  if [[ $variant == sanitize ]]; then
    flags+=(-O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer)
  fi
  gcc "${flags[@]}" "$hash" "$src/wire.c" "$src/handoff.c" "$src/report.c" "$src/test-r2.c" "$wraps" -o "$out/test-r2-$variant"
  python3 "$src/test.py" --driver "$out/test-r2-$variant" 2>&1 | tee "$out/run-$variant.txt"
done
# Mutants depend on the tests, not on the CPU: CI runs them once, in a job of their own.
if [[ ${M19_MUTANTS:-1} == 1 ]]; then
  python3 "$src/mutate.py" | tee "$out/mutants.txt"
fi
# Reviewable binaries only, never a boot image. Independent outputs must match.
for copy in a b; do
  flags=(-std=c11 -Os -Wall -Wextra -Werror -static -Wl,--build-id=none)
  for pid in pid2 pid3; do
    gcc "${flags[@]}" "$hash" scripts/m19/run1/r1.c "$src/wire.c" "$src/handoff.c" "$src/report.c" "$src/$pid.c" -o "$out/$pid-$copy"
  done
done
for pid in pid2 pid3; do
  cmp "$out/$pid-a" "$out/$pid-b"
  sha256sum "$out/$pid-a"
done | tee "$out/run2-binaries.txt"
for copy in a b; do
  gcc -std=c11 -Os -Wall -Wextra -Werror -shared -fPIC -Wl,--build-id=none "$src/xorg-shim.c" -ldl -o "$out/xorg-shim-$copy.so"
done
cmp "$out/xorg-shim-a.so" "$out/xorg-shim-b.so"
sha256sum "$out/xorg-shim-a.so" | tee -a "$out/run2-binaries.txt"
