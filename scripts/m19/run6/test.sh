#!/usr/bin/env bash
# R6: m19-wifi on a fake kernel with a stand-in CNSS daemon, T9-wifi and T9-sound on synthetic trees, m19-sink over
# R5b's Run31 fixtures (stand-in nodes, QRTR SERVREG, raw-PTY ADSP responder), m19-cnssd's admission, normal and
# ASan/UBSan, the mutants, and the reviewable static binaries built twice. No device, no module, no firmware and no
# network; m19-cnssd never opens QRTR here.
set -euo pipefail
out=${1:?output}; mkdir -p "$out"
src=scripts/m19/run6
hash=scripts/m19/unlock/hash.c
repair=scripts/m11/qualification/runtime-repair
own=scripts/m11/qualification/ownership
native=scripts/m11/anchor-native

# M12 Run10's owner supervisor and Run5's CBC parser, unchanged; caldb.c for the admission predicate they link.
wifi_srcs=("$src/wifi.c" scripts/m12/run10/owner-supervisor.c scripts/m12/run5/cbc-evidence.c scripts/m12/next/caldb.c)
sink_srcs=("$hash")
for u in m11_gpr_engine m11_shmem m11_apm_protocol m11_aw_protection m11_strict_mock; do
  sink_srcs+=("$repair/$u.c")
done
for u in m11_custodian m11_pid1_anchor m11_anchor_linux m11_anchor_owner; do
  sink_srcs+=("$own/$u.c")
done
# Run31's units, less its speaker session: stream.c is that session with the stream after its step 7.
for u in gpr_transport_native shmem_backend_native dmabuf_pool_native heap_node_native intent_journal_native \
         pdr_loop_native terminal_native custodian_runner_native custodian_boot_native pd_session_native \
         custodian_entry_native snd_backend_native speaker_plan_native; do
  sink_srcs+=("$native/$u.c")
done
sink_srcs+=("$src/stream.c" "$src/sink.c")
# R6c: m19-cnssd is M12's daemon (protocol core, CalDB admission, Linux adapter: unchanged) with its own entry.
cnssd_srcs=(scripts/m12/next/caldb.c scripts/m12/next/cnssd.c "$src/cnssd-main.c")
# The stand-in daemon and the admission tests include cnssd-main.c without its main: M12's adapter functions that only
# main uses go unused there.
admit_flags=(-Wno-unused-function)
m11_flags=(-DM11_ANCHOR_NATIVE -DM11_CUSTODIAN_NATIVE -DM11_ANCHOR_NATIVE_ION -I"$own" -I"$repair" -I"$native" -I"$src")

build_pids=()
gcc -std=c11 -O2 -Wall -Wextra -Werror "${admit_flags[@]}" "$src/test-cnssd.c" -lcrypto -o "$out/test-cnssd" &
build_pids+=("$!")
for variant in normal sanitize; do
  flags=(-std=c11 -O2 -Wall -Wextra -Werror)
  if [[ $variant == sanitize ]]; then
    flags+=(-O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer)
  fi
  gcc "${flags[@]}" -DM19_WIFI_TEST "${wifi_srcs[@]}" "$src/wifi-main.c" -o "$out/test-wifi-$variant" &
  build_pids+=("$!")
  gcc "${flags[@]}" "${m11_flags[@]}" "${sink_srcs[@]}" "$src/test-sink.c" -o "$out/test-sink-$variant" &
  build_pids+=("$!")
  gcc "${flags[@]}" "${admit_flags[@]}" "$src/test-cnssd-main.c" -lcrypto -o "$out/test-cnssd-main-$variant" &
  build_pids+=("$!")
done
for pid in "${build_pids[@]}"; do
  wait "$pid"
done

python3 "$src/test.py" --wifi "$out/test-wifi-normal" --cnssd "$out/test-cnssd" --sink "$out/test-sink-normal" \
  --admit "$out/test-cnssd-main-normal" >"$out/run-normal.txt" 2>&1 &
pid_normal=$!
python3 "$src/test.py" --wifi "$out/test-wifi-sanitize" --cnssd "$out/test-cnssd" --sink "$out/test-sink-sanitize" \
  --admit "$out/test-cnssd-main-sanitize" --no-root-sink >"$out/run-sanitize.txt" 2>&1 &
pid_sanitize=$!
rc_normal=0
wait "$pid_normal" || rc_normal=$?
rc_sanitize=0
wait "$pid_sanitize" || rc_sanitize=$?
cat "$out/run-normal.txt" "$out/run-sanitize.txt"
# Not "test A && test B": under set -e a false A in an AND list does not stop the script.
if [ "$rc_normal" -ne 0 ] || [ "$rc_sanitize" -ne 0 ]; then
  echo "tests failed: normal=$rc_normal sanitize=$rc_sanitize" >&2
  exit 1
fi

# Mutants depend on the tests, not on the CPU: CI runs them once, in a job of their own.
if [[ ${M19_MUTANTS:-1} == 1 ]]; then
  python3 "$src/mutate.py" | tee "$out/mutants.txt"
fi

# Reviewable binaries only, never a boot image. Independent outputs must match; both are static.
static_pids=()
for copy in a b; do
  gcc -std=c11 -O2 -Wall -Wextra -Werror -static -no-pie -Wl,--build-id=none "${wifi_srcs[@]}" "$src/wifi-main.c" -o "$out/m19-wifi-$copy" &
  static_pids+=("$!")
  gcc -std=c11 -O2 -Wall -Wextra -Werror -static -no-pie -Wl,--build-id=none "${m11_flags[@]}" "${sink_srcs[@]}" "$src/sink-main.c" \
    -o "$out/m19-sink-$copy" &
  static_pids+=("$!")
  # The flags and libraries M12 built m12-cnssd with: static OpenSSL needs -ldl and -pthread.
  gcc -std=c11 -O2 -Wall -Wextra -Werror -static -no-pie -Wl,--build-id=none "${cnssd_srcs[@]}" -lcrypto -ldl -pthread \
    -o "$out/m19-cnssd-$copy" &
  static_pids+=("$!")
done
for pid in "${static_pids[@]}"; do
  wait "$pid"
done
for name in m19-wifi m19-sink m19-cnssd; do
  cmp "$out/$name-a" "$out/$name-b"
  readelf -h -l "$out/$name-a" > "$out/$name-elf.txt"
  grep -q 'EXEC (Executable file)' "$out/$name-elf.txt"
  if grep -q INTERP "$out/$name-elf.txt" || grep -q DYNAMIC "$out/$name-elf.txt"; then
    echo "$name not static" >&2
    exit 1
  fi
done
# Each refuses before touching anything: an argument, a non-root caller; m19-cnssd its missing or unowned socket,
# before it opens QRTR.
exec 7<>/dev/null
set +e
"$out/m19-wifi-a" extra; rc_wifi=$?
"$out/m19-sink-a" extra; rc_sink=$?
"$out/m19-cnssd-a"; rc_cnssd=$?
"$out/m19-cnssd-a" 7; rc_cnssd_fd=$?
set -e
exec 7>&-
# Not "test A && test B": under set -e a false A in an AND list does not stop the script.
if [ "$rc_wifi" != 2 ] || [ "$rc_sink" != 2 ] || [ "$rc_cnssd" != 2 ] || [ "$rc_cnssd_fd" != 2 ]; then
  echo "refusals: wifi=$rc_wifi sink=$rc_sink cnssd=$rc_cnssd cnssd_fd=$rc_cnssd_fd" >&2
  exit 1
fi
sha256sum "$out/m19-wifi-a" "$out/m19-sink-a" "$out/m19-cnssd-a" | tee "$out/run6-binaries.txt"
