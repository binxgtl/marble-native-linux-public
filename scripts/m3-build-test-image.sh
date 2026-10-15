#!/usr/bin/env bash
set -euo pipefail

stock_boot=${1:?usage: m3-build-test-image.sh STOCK_BOOT IMAGE [OUTPUT_DIRECTORY]}
kernel=${2:?usage: m3-build-test-image.sh STOCK_BOOT IMAGE [OUTPUT_DIRECTORY]}
output_dir=${3:-artifacts/m3-local}

. scripts/m3-python.sh
m3_resolve_python

mkdir -p "$output_dir"
exec "$PYTHON" scripts/m3-repack-boot.py \
  --stock-boot "$stock_boot" \
  --kernel "$kernel" \
  --output "$output_dir/marble-m3-test-boot.img" \
  --report "$output_dir/marble-m3-test-boot.json"
