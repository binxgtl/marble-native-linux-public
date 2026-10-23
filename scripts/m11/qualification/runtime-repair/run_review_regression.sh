#!/usr/bin/env bash
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
out="$(mkdir -p "$1" && cd "$1" && pwd)"
# The reviewed baseline (the six units as the independent takeover found them) is a committed
# fixture pinned here by sha256, so the witness needs no repository history.
(cd "$here/baselines" && sha256sum -c --strict --quiet - <<'EOF'
ef7112650562502d5e11b34e8db6dc1eda74b438c0bfa6980a48b71459d0be28  review/m11_apm_protocol.c
22aa84d342a4cfa993e86b51c6524d65f2852fba09639cb1a30ec0715ca2d7eb  review/m11_apm_protocol.h
90ed456085d8bf8b45443a691458740f088072ff07064345cfc79a1715fd1309  review/m11_aw_protection.c
0420dfbc9061da0dc205452c3948422a20b5cbe16fd264dfa0cd3f6bd1cee821  review/m11_aw_protection.h
cde3cad99b283aa319875f621279f71658db188d17d22ff8dd133977c38be1fc  review/m11_gpr_engine.c
d6c9a6d61bc55e2f8a8f722649b866cb38262596f0a8df063e235e7a4f7cd98c  review/m11_gpr_engine.h
342b8d54cf23b8b30783b41b876f1f9e94a523c377409219c6e26e1809d10154  review/m11_offline_sim.c
2e62d3b93c885e7931b7b16b5fb6d5f388ec4dc60ef41684e676ed313daad0f1  review/m11_offline_sim.h
9f70b634fc30174b6d9dbf9fc6123b5609f5300f3fa0b0a7b39af58466fe2193  review/m11_shmem.c
104e5cf8b6c6959859f96f4911056fc1a3b31cbf7c40698890a08fb153111949  review/m11_shmem.h
c4919d710c87da9c3da386deebdcc8164d5d5c9eb85444381de1572198e38782  review/m11_strict_mock.c
bd792e9b6131fdb2bfd9f672a4069fb09d244d86488f01a4242b2867f5b04eef  review/m11_strict_mock.h
EOF
)
old="$out/sonnet-baseline"
mkdir -p "$old"
units=(m11_gpr_engine m11_shmem m11_apm_protocol m11_aw_protection m11_offline_sim m11_strict_mock)
for unit in "${units[@]}"; do
  for ext in c h; do cp "$here/baselines/review/$unit.$ext" "$old/$unit.$ext"; done
done
cp "$here/test_runtime_review.c" "$old/test_runtime_review.c"
for mode in gcc clang sanitize; do
  cc=gcc; flags=(-std=c11 -O1 -g -Wall -Wextra -Werror)
  if [[ "$mode" == clang ]]; then cc=clang; fi
  if [[ "$mode" == sanitize ]]; then flags+=(-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer); fi
  for tree in "$old" "$here"; do
    srcs=(); for unit in "${units[@]}"; do srcs+=("$tree/$unit.c"); done
    label=repaired; args=()
    if [[ "$tree" == "$old" ]]; then label=baseline; args=(--legacy-witness); fi
    # Quoted includes resolve relative to the test source before -I. Copy the
    # identical witness into the old tree so baseline code uses baseline headers.
    "$cc" "${flags[@]}" -I "$tree" "${srcs[@]}" "$tree/test_runtime_review.c" -o "$out/$label-$mode"
    "$out/$label-$mode" "${args[@]}" | tee "$out/$label-$mode.log"
  done
done
