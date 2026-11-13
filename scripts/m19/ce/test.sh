#!/usr/bin/env bash
# R7 CE core, Gatekeeper ABI, Keystore2 contract and broker on synthetic inputs, normal and ASan/UBSan, then the
# core's mutants. No device, PIN or key.
set -euo pipefail
out=${1:?output}; mkdir -p "$out"
src=scripts/m19/ce
unlock=scripts/m19/unlock
crypto=$(ldconfig -p | awk '$1 == "libcrypto.so.3" { print $NF; exit }')
[ -n "$crypto" ] || { echo 'libcrypto.so.3 not found' >&2; exit 1; }
python3 "$src/model.py"
# The Gatekeeper fake is built with clang and real libc++ (std::__1), the platform's C++ runtime.
clang++ -std=c++17 -stdlib=libc++ -fPIC -shared -O1 -Wall -Wextra -Werror "$src/fake-gk.cpp" -o "$out/fake-gk.so"
for variant in normal sanitize; do
  flags=(-O2 -Wall -Wextra -Werror)
  if [[ $variant == sanitize ]]; then
    flags+=(-O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer)
  fi
  gcc -std=c11 "${flags[@]}" -DM19_CE_TEST "$src/ce.c" "$src/crypto.c" "$src/fscrypt.c" "$src/test-ce.c" "$unlock/core.c" "$unlock/hash.c" \
    -ldl -o "$out/test-ce-$variant"
  g++ -std=c++17 "${flags[@]}" "$src/gk.cpp" "$src/test-gk.cpp" -ldl -o "$out/test-gk-$variant"
  gcc -std=c11 "${flags[@]}" -c "$unlock/core.c" -o "$out/core-$variant.o"
  gcc -std=c11 "${flags[@]}" -c "$unlock/hash.c" -o "$out/hash-$variant.o"
  g++ -std=c++17 "${flags[@]}" -DM19_KS_TEST -I"$src" "$src/ks.cpp" "$src/test-ks.cpp" "$out/core-$variant.o" "$out/hash-$variant.o" \
    -ldl -o "$out/test-ks-$variant"
  gcc -std=c11 "${flags[@]}" "$src/broker.c" "$src/test-broker.c" "$src/ce.c" "$unlock/core.c" "$unlock/hash.c" -o "$out/test-broker-$variant"
  ASAN_OPTIONS=detect_leaks=0 M19_CE_GK=1 M19_CE_KS=1 M19_CE_BROKER=1 python3 "$src/test.py" --binary "$out/test-ce-$variant" \
    --libcrypto "$crypto" --gk-binary "$out/test-gk-$variant" --gk-library "$out/fake-gk.so" --ks-binary "$out/test-ks-$variant" \
    --broker-binary "$out/test-broker-$variant"
done
if [ "${M19_MUTANTS:-1}" != 0 ]; then
  python3 "$src/mutate.py" --libcrypto "$crypto" | tee "$out/mutants.txt"
fi
