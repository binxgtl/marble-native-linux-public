#!/usr/bin/env bash
# R5a: the audio helper on a fake kernel, normal and ASan/UBSan, the stage and T3-audio on synthetic trees, the
# mutants, and the reviewable static helper twice. No device, no module and no image from the phone.
set -euo pipefail
out=${1:?output}; mkdir -p "$out"
src=scripts/m19/run5
hash=scripts/m19/unlock/hash.c
for variant in normal sanitize; do
  flags=(-std=c11 -O2 -Wall -Wextra -Werror)
  if [[ $variant == sanitize ]]; then
    flags+=(-O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer)
  fi
  gcc "${flags[@]}" -DM19_AUDIO_TEST "$hash" "$src/audio.c" "$src/test-audio.c" -o "$out/test-audio-$variant"
  python3 "$src/test.py" --driver "$out/test-audio-$variant" 2>&1 | tee "$out/run-$variant.txt"
done
# Mutants depend on the tests, not on the CPU: CI runs them once, in a job of their own.
if [[ ${M19_MUTANTS:-1} == 1 ]]; then
  python3 "$src/mutate.py" | tee "$out/mutants.txt"
fi
# Reviewable binaries only, never a boot image. Independent outputs must match.
for copy in a b; do
  gcc -std=c11 -Os -Wall -Wextra -Werror -static -Wl,--build-id=none "$hash" "$src/audio.c" -o "$out/m19-audio-$copy"
done
cmp "$out/m19-audio-a" "$out/m19-audio-b"
sha256sum "$out/m19-audio-a" | tee "$out/run5-binaries.txt"
