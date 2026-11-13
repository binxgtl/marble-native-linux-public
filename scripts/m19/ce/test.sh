#!/usr/bin/env bash
# R7 CE core on synthetic fixtures from model.py, normal and ASan/UBSan, then its mutants. No device, PIN or key.
set -euo pipefail
out=${1:?output}; mkdir -p "$out"
src=scripts/m19/ce
crypto=$(ldconfig -p | awk '$1 == "libcrypto.so.3" { print $NF; exit }')
[ -n "$crypto" ] || { echo 'libcrypto.so.3 not found' >&2; exit 1; }
python3 "$src/model.py"
for variant in normal sanitize; do
  flags=(-std=c11 -O2 -Wall -Wextra -Werror -DM19_CE_TEST)
  if [[ $variant == sanitize ]]; then
    flags+=(-O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer)
  fi
  gcc "${flags[@]}" "$src/ce.c" "$src/crypto.c" "$src/fscrypt.c" "$src/test-ce.c" scripts/m19/unlock/core.c scripts/m19/unlock/hash.c \
    -ldl -o "$out/test-ce-$variant"
  ASAN_OPTIONS=detect_leaks=0 python3 "$src/test.py" --binary "$out/test-ce-$variant" --libcrypto "$crypto"
done
if [ "${M19_MUTANTS:-1}" != 0 ]; then
  python3 "$src/mutate.py" --libcrypto "$crypto" | tee "$out/mutants.txt"
fi
