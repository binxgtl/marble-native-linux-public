#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail
out=$1
mkdir -p "$out/runtime"
sh -n scripts/m15/runtime/init
sh -n scripts/m15/runtime/bootstrap
python3 scripts/m15/runtime/test.py -v 2>&1 | tee "$out/runtime/python-tests.txt"
chmod +x scripts/m15/runtime/fake-connector.py scripts/m15/native6/fake-display.py
for variant in normal sanitize; do
 flags=(-std=c11 -O2 -Wall -Wextra -Werror)
 if [ "$variant" = sanitize ]; then flags+=(-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -fno-pie -no-pie); fi
 cc "${flags[@]}" scripts/m15/runtime/connector.c scripts/m15/runtime/test-connector.c -o "$out/runtime/test-connector-$variant"
 "$out/runtime/test-connector-$variant" | tee "$out/runtime/connector-$variant.txt"
 cc "${flags[@]}" scripts/m15/runtime/connector.c scripts/m15/runtime/connector-worker.c -o "$out/runtime/connector-$variant"
 cc "${flags[@]}" -DM15_RUNTIME_TEST -DM15_STAGE_BUDGET=8000 scripts/m15/runtime/pid1.c scripts/m15/native5/ownership.c scripts/m15/native5/io.c -o "$out/runtime/pid1-fixture-$variant"
 cc "${flags[@]}" -DM15_RUNTIME_TEST scripts/m15/runtime/custodian.c scripts/m15/native1/escrow.c scripts/m15/native1/supervise.c -o "$out/runtime/custodian-fixture-$variant"
 cc "${flags[@]}" -DM15_RUNTIME_TEST scripts/m15/runtime/bootstrap-supervisor.c -o "$out/runtime/bootstrap-fixture-$variant"
 sudo env ASAN_OPTIONS=detect_leaks=0 python3 scripts/m15/runtime/test-bootstrap.py "$out/runtime/bootstrap-fixture-$variant" | tee "$out/runtime/bootstrap-$variant.txt"
 sudo env ASAN_OPTIONS=detect_leaks=0 python3 scripts/m15/runtime/test-integration.py "$out/runtime/pid1-fixture-$variant" "$out/runtime/custodian-fixture-$variant" "$out/m15-observe-o3-a" "$out/native1-normal/native1-synthetic.wire" "$out/runtime/$variant" | tee "$out/runtime/integration-$variant.txt"
done
for copy in a b; do
 flags=(-std=c11 -O2 -Wall -Wextra -Werror -static -Wl,--build-id=none)
 cc "${flags[@]}" scripts/m15/runtime/pid1.c scripts/m15/native5/ownership.c scripts/m15/native5/io.c -o "$out/runtime/pid1-$copy"
 cc "${flags[@]}" scripts/m15/runtime/custodian.c scripts/m15/native1/escrow.c scripts/m15/native1/supervise.c -o "$out/runtime/custodian-$copy"
 cc "${flags[@]}" scripts/m15/runtime/connector.c scripts/m15/runtime/connector-worker.c -o "$out/runtime/connector-$copy"
 cc "${flags[@]}" scripts/m15/runtime/bootstrap-supervisor.c -o "$out/runtime/bootstrap-$copy"
 cc "${flags[@]}" scripts/m15/runtime/load-m8-tail.c -o "$out/runtime/tail-$copy"
done
for name in pid1 custodian connector bootstrap tail; do cmp "$out/runtime/$name-a" "$out/runtime/$name-b";sha256sum "$out/runtime/$name-a";done | tee "$out/runtime/static-binaries.txt"
