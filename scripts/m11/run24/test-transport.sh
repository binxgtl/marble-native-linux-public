#!/usr/bin/env bash
# Run24 Linux-side transport tests (M11I3 relay, independent checker, runner-journal terminal rule).
# Mirrors the Run20 workflow step "Actual sender C normal and ASan/UBSan; independent hashlib integration",
# for gcc AND clang. No device, no hardware, no network. Usage: test-transport.sh OUTPUT_DIR
set -euo pipefail
out=${1:?usage: test-transport.sh OUTPUT_DIR}
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
run12="$here/../run12"
mkdir -p "$out"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

python3 "$here/test-protocol.py"

for cc in gcc clang; do
  command -v "$cc" >/dev/null || { echo "missing compiler: $cc" >&2; exit 1; }
  for mode in normal sanitize; do
    flags=''
    if [ "$mode" = sanitize ]; then
      flags='-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer'
    fi
    d="$out/$cc-$mode"
    mkdir -p "$d"
    echo "== $cc $mode =="
    # shellcheck disable=SC2086
    "$cc" -std=c11 -O1 -g -Wall -Wextra -Werror $flags "$here/test-producer.c" -o "$tmp/sender"
    "$tmp/sender" "$d/capture.bin"
    python3 "$here/test-protocol.py" "$d/capture.bin"
    "$tmp/sender" "$d/loss-capture.bin" loss
    python3 "$here/test-protocol.py" "$d/loss-capture.bin" loss
    # shellcheck disable=SC2086
    "$cc" -std=c11 -O1 -g -Wall -Wextra -Werror $flags "$here/test-lifecycle.c" -o "$tmp/lifecycle"
    "$tmp/lifecycle" 0 "$d/lifecycle.bin"
    python3 "$here/test-protocol.py" "$d/lifecycle.bin"
    # 1-5: Run20 fault modes; 6-7: stop boundary 135168 and EVENT_RESERVE accepted;
    # 8-9: stop boundary EVENT_RESERVE+1 and event overshoot rejected.
    for fault in 1 2 3 4 5 6 7 8 9; do "$tmp/lifecycle" "$fault"; done
    if [ "$cc" = gcc ]; then
      # Frozen Run12 relay regression, exactly as in the Run20 workflow (gcc only, as validated there).
      # shellcheck disable=SC2086
      "$cc" -std=c11 -O1 -g -Wall -Wextra -Werror $flags "$run12/test-relay.c" -o "$tmp/frozen-relay"
      "$tmp/frozen-relay"
    fi
  done
done

# Stable names for downstream jobs (Windows receiver fixture): first configuration is canonical.
cp "$out/gcc-normal/capture.bin" "$out/capture.bin"
cp "$out/gcc-normal/loss-capture.bin" "$out/loss-capture.bin"
cp "$out/gcc-normal/lifecycle.bin" "$out/lifecycle.bin"
echo "PASS Run24 Linux transport tests (gcc+clang, normal+ASan/UBSan); no hardware"
