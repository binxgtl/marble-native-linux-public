#!/usr/bin/env bash
# Fetch the five pinned-ACK source files the W3 differential reference is extracted from.
# They are public GPL-2.0 kernel sources and are never committed; gen_ack_ref.py rejects
# any file whose sha256 differs from its pin.
# Usage: fetch_ack_ref_sources.sh <out_dir>
set -euo pipefail
out="$(mkdir -p "$1" && cd "$1" && pwd)"
base=https://android.googlesource.com/kernel/common/+/b97c62c4e7d1e80fb6a2cb0cb381f03bbcd26a4e
while read -r name path; do
  curl -sfL --retry 3 "$base/$path?format=TEXT" | base64 -d > "$out/$name"
done <<'EOF'
include_linux_ctype.h include/linux/ctype.h
lib_ctype.c lib/ctype.c
lib_string.c lib/string.c
lib_cmdline.c lib/cmdline.c
kernel_params.c kernel/params.c
EOF
echo "fetched pinned ACK reference sources into $out"
