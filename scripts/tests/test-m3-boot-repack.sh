#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

. "$root/scripts/m3-python.sh"
m3_resolve_python

"$PYTHON" - "$tmp" <<'PY'
import pathlib
import struct
import sys

root = pathlib.Path(sys.argv[1])
page = 4096

def align(value):
    return (value + page - 1) & ~(page - 1)

def arm64_image(size, fill):
    data = bytearray(bytes([fill]) * size)
    data[56:60] = b"ARMd"
    return bytes(data)

old_kernel = arm64_image(6000, 0x31)
new_kernel = arm64_image(7000, 0x32)
ramdisk = b"synthetic-ramdisk" * 73
signature = b"S" * 4096
os_version = ((12 << 14) << 11) | ((25 << 4) | 9)
header = bytearray(page)
struct.pack_into("<8s4I4II", header, 0, b"ANDROID!", len(old_kernel),
                 len(ramdisk), os_version, 1584, 0, 0, 0, 0, 4)
struct.pack_into("<I", header, 1580, len(signature))
boot = bytes(header)
boot += old_kernel + bytes(align(len(old_kernel)) - len(old_kernel))
boot += ramdisk + bytes(align(len(ramdisk)) - len(ramdisk))
boot += signature
boot += bytes(32768 - len(boot))
(root / "stock.img").write_bytes(boot)
(root / "new-Image").write_bytes(new_kernel)
(root / "bad-Image").write_bytes(b"not-an-arm64-image")
(root / "ramdisk").write_bytes(ramdisk)

bad_magic = bytearray(boot)
bad_magic[:8] = b"NOTBOOT!"
(root / "bad-magic.img").write_bytes(bad_magic)
bad_version = bytearray(boot)
struct.pack_into("<I", bad_version, 40, 3)
(root / "bad-version.img").write_bytes(bad_version)
bad_signature = bytearray(boot)
struct.pack_into("<I", bad_signature, 1580, 512)
(root / "bad-signature.img").write_bytes(bad_signature)
(root / "huge-Image").write_bytes(arm64_image(40000, 0x33))
PY

"$PYTHON" "$root/scripts/m3-repack-boot.py" \
  --stock-boot "$tmp/stock.img" \
  --kernel "$tmp/new-Image" \
  --output "$tmp/test-boot.img" \
  --report "$tmp/report.json"

"$PYTHON" - "$tmp" <<'PY'
import hashlib
import json
import pathlib
import struct
import sys

root = pathlib.Path(sys.argv[1])
page = 4096
image = (root / "test-boot.img").read_bytes()
kernel = (root / "new-Image").read_bytes()
ramdisk = (root / "ramdisk").read_bytes()
report = json.loads((root / "report.json").read_text())

def align(value):
    return (value + page - 1) & ~(page - 1)

assert image[:8] == b"ANDROID!"
assert struct.unpack_from("<I", image, 8)[0] == len(kernel)
assert struct.unpack_from("<I", image, 12)[0] == len(ramdisk)
assert struct.unpack_from("<I", image, 20)[0] == 1584
assert struct.unpack_from("<I", image, 40)[0] == 4
assert struct.unpack_from("<I", image, 1580)[0] == 0
assert image[page:page + len(kernel)] == kernel
ramdisk_offset = page + align(len(kernel))
assert image[ramdisk_offset:ramdisk_offset + len(ramdisk)] == ramdisk
assert len(image) <= (root / "stock.img").stat().st_size
assert report["status"] == "HARDWARE TEST PENDING"
assert report["warning"] == "UNSIGNED TEST IMAGE — NOT BOOT-PROVEN — DO NOT FLASH"
assert report["stock_signature_size"] == 4096
assert report["output_signature_size"] == 0
assert report["ramdisk_sha256"] == hashlib.sha256(ramdisk).hexdigest()
assert report["output_sha256"] == hashlib.sha256(image).hexdigest()
PY

expect_failure() {
  local stock=$1 kernel=$2 label=$3
  if "$PYTHON" "$root/scripts/m3-repack-boot.py" \
    --stock-boot "$tmp/$stock" --kernel "$tmp/$kernel" \
    --output "$tmp/out-$label.img" --report "$tmp/$label.json"; then
    echo "expected $label fixture to fail" >&2
    exit 1
  fi
}

expect_failure bad-magic.img new-Image bad-magic
expect_failure bad-version.img new-Image bad-version
expect_failure bad-signature.img new-Image bad-signature
expect_failure stock.img bad-Image bad-kernel
expect_failure stock.img huge-Image oversized

stock_hash=$(sha256sum "$tmp/stock.img" | cut -d' ' -f1)
expect_path_collision() {
  local output=$1 report=$2 label=$3
  if "$PYTHON" "$root/scripts/m3-repack-boot.py" \
    --stock-boot "$tmp/stock.img" --kernel "$tmp/new-Image" \
    --output "$output" --report "$report"; then
    echo "expected $label path collision to fail" >&2
    exit 1
  fi
  test "$(sha256sum "$tmp/stock.img" | cut -d' ' -f1)" = "$stock_hash"
}

expect_path_collision "$tmp/collision-output.img" "$tmp/stock.img" report-input
ln -s "$tmp/stock.img" "$tmp/stock-symlink.img"
expect_path_collision "$tmp/collision-output.img" "$tmp/stock-symlink.img" report-symlink
ln "$tmp/stock.img" "$tmp/stock-hardlink.img"
expect_path_collision "$tmp/collision-output.img" "$tmp/stock-hardlink.img" report-hardlink
expect_path_collision "$tmp/shared-output-report" "$tmp/shared-output-report" output-report

mkdir "$tmp/real-output-dir"
ln -s "$tmp/real-output-dir" "$tmp/output-dir-symlink"
expect_path_collision \
  "$tmp/real-output-dir/shared" "$tmp/output-dir-symlink/shared" \
  output-report-parent-symlink

# The documented entry point must work end to end, not just the Python tool it
# wraps. It resolves its own paths relative to the repository root.
(
  cd "$root"
  ./scripts/m3-build-test-image.sh "$tmp/stock.img" "$tmp/new-Image" "$tmp/wrapper"
)
test -s "$tmp/wrapper/marble-m3-test-boot.img"
test -s "$tmp/wrapper/marble-m3-test-boot.json"
cmp "$tmp/wrapper/marble-m3-test-boot.img" "$tmp/test-boot.img"

# Interpreter resolution must auto-detect Python 3, honour an explicit PYTHON
# override, and fail closed rather than silently falling back to Python 2 or to
# no interpreter at all.
resolve_with() {
  env "$@" "$BASH" -c '
    set -euo pipefail
    . "$1/scripts/m3-python.sh"
    m3_resolve_python
    printf "%s\n" "$PYTHON"
  ' resolver "$root"
}

autodetected=$(resolve_with PYTHON=)
test -n "$autodetected"
"$autodetected" -c 'import sys; sys.exit(0 if sys.version_info[0] == 3 else 1)'
test "$(resolve_with PYTHON="$PYTHON")" = "$PYTHON"

if resolve_with PYTHON="$root/scripts/m3-python.sh" >/dev/null 2>&1; then
  echo 'expected a non-Python PYTHON override to fail closed' >&2
  exit 1
fi
if resolve_with PYTHON= PATH=/nonexistent >/dev/null 2>&1; then
  echo 'expected resolution with no interpreter on PATH to fail closed' >&2
  exit 1
fi
