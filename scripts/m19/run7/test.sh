#!/usr/bin/env bash
# R7's keypad (m19-ce-prompt): its logic, normal and ASan/UBSan, then the binary in Xvfb tapped through XTEST against
# a fake broker. The ARM64 build is the one staged. No device, PIN or key.
set -euo pipefail
out=${1:?output}; mkdir -p "$out"
src=scripts/m19/run7
for variant in normal sanitize; do
  flags=(-std=c11 -O2 -Wall -Wextra -Werror)
  if [[ $variant == sanitize ]]; then
    flags+=(-O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer)
  fi
  gcc "${flags[@]}" "$src/prompt.c" "$src/test-prompt.c" -o "$out/test-prompt-$variant"
  "$out/test-prompt-$variant"
  gcc "${flags[@]}" "$src/prompt.c" "$src/ce-prompt.c" -lX11 -o "$out/ce-prompt-$variant"
done
gcc -std=c11 -O2 -Wall -Wextra -Werror "$src/prompt.c" "$src/xclick.c" -lX11 -lXtst -o "$out/xclick"
python3 "$src/test.py" --prompt "$out/ce-prompt-normal" --xclick "$out/xclick"
ASAN_OPTIONS=detect_leaks=0 python3 "$src/test.py" --prompt "$out/ce-prompt-sanitize" --xclick "$out/xclick"
# The staged binary, built twice; it needs the tree's libX11 and libc only.
for copy in a b; do
  gcc -std=c11 -O2 -Wall -Wextra -Werror -Wl,--build-id=none "$src/prompt.c" "$src/ce-prompt.c" -lX11 -o "$out/m19-ce-prompt-$copy"
done
cmp "$out/m19-ce-prompt-a" "$out/m19-ce-prompt-b"
strip "$out/m19-ce-prompt-a" "$out/m19-ce-prompt-b"
cmp "$out/m19-ce-prompt-a" "$out/m19-ce-prompt-b"
needed=$(readelf -d "$out/m19-ce-prompt-a" | awk '/NEEDED/ { print $NF }' | tr -d '[]' | LC_ALL=C sort | tr '\n' ' ')
# On aarch64 glibc also names its own loader, which the tree has as every program's interpreter.
case "$needed" in
 'libX11.so.6 libc.so.6 '|'ld-linux-aarch64.so.1 libX11.so.6 libc.so.6 ') ;;
 *) echo "m19-ce-prompt needs: $needed" >&2; exit 1;;
esac
sha256sum "$out/m19-ce-prompt-a" | tee "$out/prompt-binary.txt"
