#!/system/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# RAM-only 10-sample run of the unchanged O3 observer: the same window as the native capture.
# Never invokes su or adb itself. Separate from capture.sh, which the Android reference used.
PATH=/system/bin:/system/xbin
export PATH
set -u
fail() { printf '%s\n' 'M15 Termux workflow BLOCKED; retain RAM evidence' >&2; exit 70; }
[ "$#" -eq 3 ] || fail
session=$1; expected_binary=$2; expected_topology=$3
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
for name in observer topology.json long.sh; do
 [ -f "$name" ] && [ ! -L "$name" ] || fail
 [ "$(stat -c %u "$name")" = 0 ] || fail
done
file_hash() {
 value=$(sha256sum "$1") || fail
 printf '%s' "${value%% *}"
}
binary=$(file_hash observer); topology=$(file_hash topology.json); runner=$(file_hash long.sh)
[ "$binary" = "$expected_binary" ] && [ "$topology" = "$expected_topology" ] || fail
binding=$(printf '%s\n' "$binary" "$topology" "$runner")
umask 077
mkdir long || fail
out=$session/long
printf '%s\n' "$binding" > "$out/input-binding.txt" || fail
ulimit -c 0 || fail
trap 'exit 130' HUP INT TERM
./observer --sysfs --samples 10 --interval-ms 10000 --deadline-ms 120000 > "$out/capture.raw" 2> "$out/capture.stderr"
rc=$?
printf '%s\n' "$rc" > "$out/capture.exit" || fail
printf '{"schema":"M15-Termux-capture-v1","phase":"long","process_rc":%s,"sealed_baseline":false,"control_permitted":false,"freshness":"UNKNOWN","negotiated_contract":"UNKNOWN","protection_active":"UNKNOWN"}\n' "$rc" > "$out/record.json" || fail
cd "$out" || fail
sha256sum input-binding.txt record.json capture.raw capture.stderr capture.exit > SHA256SUMS || fail
# A nonzero child result is preserved after writing the receipt.
printf '%s\n' 'M15 RAM capture returned; host verification required; no sender seal'
exit "$rc"
