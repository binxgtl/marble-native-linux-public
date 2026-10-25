#!/system/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# RAM-only wrapper for the unchanged O3 observer. Never invokes su or adb itself.
PATH=/system/bin:/system/xbin
export PATH
set -u
fail() { printf '%s\n' 'M15 Termux workflow BLOCKED; retain RAM evidence' >&2; exit 70; }
[ "$#" -eq 4 ] || fail
phase=$1; session=$2; expected_binary=$3; expected_topology=$4
case "$phase" in qualify|acquire) ;; *) fail;; esac
case "$session" in /dev/m15-o3-*) ;; *) fail;; esac
leaf=${session#/dev/}
case "$leaf" in *[!A-Za-z0-9-]*) fail;; esac
[ "${#leaf}" -le 80 ] || fail
for digest in "$expected_binary" "$expected_topology"; do
 [ "${#digest}" -eq 64 ] || fail
 case "$digest" in *[!0-9a-f]*) fail;; esac
done
[ "$(id -u)" = 0 ] || fail
[ -d "$session" ] && [ ! -L "$session" ] || fail
[ "$(stat -f -c %T "$session")" = tmpfs ] || fail
[ "$(stat -c %u:%a "$session")" = 0:700 ] || fail
cd -P "$session" || fail
[ "$PWD" = "$session" ] || fail
for name in observer topology.json capture.sh; do
 [ -f "$name" ] && [ ! -L "$name" ] || fail
 [ "$(stat -c %u "$name")" = 0 ] || fail
done
file_hash() {
 value=$(sha256sum "$1") || fail
 printf '%s' "${value%% *}"
}
binary=$(file_hash observer); topology=$(file_hash topology.json); runner=$(file_hash capture.sh)
[ "$binary" = "$expected_binary" ] && [ "$topology" = "$expected_topology" ] || fail
binding=$(printf '%s\n' "$binary" "$topology" "$runner")
if [ "$phase" = acquire ]; then
 for name in qualification.ok qualify/SHA256SUMS qualify/input-binding.txt; do
  [ -f "$name" ] && [ ! -L "$name" ] || fail
 done
 [ "$(cat qualification.ok)" = "$(file_hash qualify/SHA256SUMS)" ] || fail
 [ "$(cat qualify/input-binding.txt)" = "$binding" ] || fail
 (cd qualify && sha256sum -c SHA256SUMS) || fail
 # The host verifier writes qualification.ok only after strict qualification replay.
 # This is an input-bound local admission marker, NOT an authenticated sender seal.
fi
umask 077
mkdir "$phase" || fail
out=$session/$phase
printf '%s\n' "$binding" > "$out/input-binding.txt" || fail
ulimit -c 0 || fail
trap 'exit 130' HUP INT TERM
if [ "$phase" = qualify ]; then
 ./observer > "$out/noargs.raw" 2> "$out/noargs.stderr"
 noargs_rc=$?
 printf '%s\n' "$noargs_rc" > "$out/noargs.exit" || fail
 [ "$noargs_rc" -eq 64 ] && [ ! -s "$out/noargs.raw" ] || fail
 mkdir "$out/empty" || fail
 ./observer --fixture-root "$out/empty" --samples 1 --deadline-ms 10000 > "$out/capture.raw" 2> "$out/capture.stderr"
 rc=$?
else
 ./observer --sysfs --samples 3 --interval-ms 1000 --deadline-ms 90000 > "$out/capture.raw" 2> "$out/capture.stderr"
 rc=$?
fi
printf '%s\n' "$rc" > "$out/capture.exit" || fail
printf '{"schema":"M15-Termux-capture-v1","phase":"%s","process_rc":%s,"sealed_baseline":false,"control_permitted":false,"freshness":"UNKNOWN","negotiated_contract":"UNKNOWN","protection_active":"UNKNOWN"}\n' "$phase" "$rc" > "$out/record.json" || fail
cd "$out" || fail
if [ "$phase" = qualify ]; then
 sha256sum input-binding.txt record.json capture.raw capture.stderr capture.exit noargs.raw noargs.stderr noargs.exit > SHA256SUMS || fail
else
 sha256sum input-binding.txt record.json capture.raw capture.stderr capture.exit > SHA256SUMS || fail
fi
# A nonzero child result is preserved after writing the receipt. Missing final
# framing, unfinished shell or output/hash failure will be rejected on the PC.
printf '%s\n' 'M15 RAM capture returned; host verification required; no sender seal'
exit "$rc"
