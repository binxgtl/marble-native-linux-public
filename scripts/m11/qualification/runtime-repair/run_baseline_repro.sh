#!/usr/bin/env bash
# Reproduces the pre-hardening defects: builds the runtime exactly as it was before the P1-P6
# hardening (the committed fixture baselines/pre-hardening, pinned below by sha256) and runs the
# CURRENT regression file against it. Every case that targets a reproduced defect must FAIL there,
# and the same file must PASS on the hardened tree.
#
#   usage: run_baseline_repro.sh <out-dir>
#
# The mock (m11_strict_mock.*) and the test are taken from the working tree on purpose: they are
# test scaffolding. The five production units come from the fixture unchanged; no repository
# history is read.
set -euo pipefail

out="$(mkdir -p "$1" && cd "$1" && pwd)"
here="$(cd "$(dirname "$0")" && pwd)"
units=(m11_gpr_engine.c m11_gpr_engine.h m11_shmem.c m11_shmem.h
       m11_apm_protocol.c m11_apm_protocol.h m11_aw_protection.c m11_aw_protection.h
       m11_offline_sim.c m11_offline_sim.h)

(cd "$here/baselines" && sha256sum -c --strict --quiet - <<'EOF'
465611ede75de18195160f950d606022e55b8b1cb1494b57e32e325aa3e8d532  pre-hardening/m11_apm_protocol.c
22aa84d342a4cfa993e86b51c6524d65f2852fba09639cb1a30ec0715ca2d7eb  pre-hardening/m11_apm_protocol.h
6568dce81a1398839e8e1371e6de69befb180fb35e8c420c96f5bfcc90dfd88a  pre-hardening/m11_aw_protection.c
0d08752f3dd8de842d5a334f1e28caf19983f133068244a81db15ef75bf8cfda  pre-hardening/m11_aw_protection.h
50f0e90e0210fdd1017680fa4e8ac41c59d760329dedf66c984e8ece395a5923  pre-hardening/m11_gpr_engine.c
efa3149c54c06bce0be168ba070b4dfedcfb207b9fe1c148abcd7e2a72311443  pre-hardening/m11_gpr_engine.h
4652ba1bd70d51b113c32701642bd2852f4629b38c2eb41a0ddf6e003a13f65e  pre-hardening/m11_offline_sim.c
f2f9da1af44a2abcb31b058456a24eaecbb027ec18b69c42104c8686869d07de  pre-hardening/m11_offline_sim.h
8a0a3e90dee9d3e2e4d0c66ef207a3b188324af6045ab0c19cf510a5f5ce0f5e  pre-hardening/m11_shmem.c
f25c309a27b76521237a5ae3bb02f44985d08157a1d331c2d10f7c39bbb03b3a  pre-hardening/m11_shmem.h
EOF
)
work="$out/baseline-tree"
rm -rf "$work"
mkdir -p "$work"
for f in "${units[@]}"; do cp "$here/baselines/pre-hardening/$f" "$work/$f"; done
cp "$here/m11_strict_mock.c" "$here/m11_strict_mock.h" "$here/test_runtime_hardening.c" "$work/"

echo "baseline sources  : $(cd "$work" && sha256sum m11_gpr_engine.c m11_shmem.c m11_apm_protocol.c m11_aw_protection.c m11_offline_sim.c | awk '{print substr($1,1,12)}' | tr '\n' ' ')"
if grep -q M11_RUNTIME_HARDENING_API_VERSION "$work/m11_gpr_engine.h"; then
  echo "refusing: the baseline already contains the hardening API" >&2
  exit 2
fi

cc="${CC:-gcc}"
flags=(-std=c11 -O1 -g -Wall -Wextra -Werror -I"$work")
"$cc" "${flags[@]}" "$work"/m11_gpr_engine.c "$work"/m11_shmem.c "$work"/m11_apm_protocol.c \
      "$work"/m11_aw_protection.c "$work"/m11_offline_sim.c "$work"/m11_strict_mock.c \
      "$work"/test_runtime_hardening.c -o "$out/hardening-baseline"

set +e
"$out/hardening-baseline" > "$out/hardening-baseline.log" 2>&1
status=$?
set -e
cat "$out/hardening-baseline.log"

failed="$(grep -c '^\[FAIL\]' "$out/hardening-baseline.log" || true)"
echo "baseline exit status: $status, failing cases: $failed"
if [[ "$status" -eq 0 || "$failed" -eq 0 ]]; then
  echo "UNEXPECTED: the baseline passed; the regression does not reproduce the defects" >&2
  exit 1
fi
exp="$here/expected-baseline-failures.txt"
grep '^\[FAIL\]' "$out/hardening-baseline.log" | sed 's/^\[FAIL\] //' | sort > "$out/actual-baseline-failures.txt"
if ! diff -u "$exp" "$out/actual-baseline-failures.txt"; then
  echo "UNEXPECTED: the set of failing cases differs from expected-baseline-failures.txt" >&2
  exit 1
fi
echo "failing set matches expected-baseline-failures.txt exactly"
echo "BASELINE REPRODUCTION OK: $failed case(s) fail on the pre-hardening baseline"
