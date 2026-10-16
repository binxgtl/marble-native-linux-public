# Source from an owned diagnostic shell. Single writer; RAM journal only.
# This is not integrated into a candidate. No writes to audio/device controls.
journal_init() {
    [ "$#" -eq 2 ] || return 1
    # BusyBox command substitution/helpers must not inherit closed stdio.
    # Preserve already-open fds; only repair missing ones before any external call.
    [ -e /proc/self/fd/0 ] || exec 0</dev/null || return 1
    [ -e /proc/self/fd/1 ] || exec 1>/dev/null || return 1
    [ -e /proc/self/fd/2 ] || exec 2>/dev/null || return 1
    case "$1$2" in *[!0-9a-f]*) return 1;; esac
    [ "${#1}" -eq 32 ] && [ "${#2}" -eq 64 ] || return 1
    [ "$("$BB" stat -f -c %T /run)" = tmpfs ] || return 1
    [ ! -e /run/m11-instrumentation ] && [ ! -L /run/m11-instrumentation ] || return 1
    "$BB" mkdir -m 700 /run/m11-instrumentation || return 1
    J=/run/m11-instrumentation/journal
    : > "$J" || return 1
    J_SEQ=0 J_CLOSED=0
    journal_record session identity metadata 0 "$1 $2" || return 1
}
journal_record() {
    [ "$#" -eq 5 ] && [ "$J_CLOSED" -eq 0 ] || return 1
    case "$1$2$3" in *[!a-z_0-9]*) return 1;; esac
    case "$4" in -*) v=${4#-};; *) v=$4;; esac
    case "$v" in ''|*[!0-9]*) return 1;; esac
    [ "${#5}" -le 32768 ] || return 1
    t=$("$BB" cut -d ' ' -f 1 /proc/uptime) || return 1
    "$BB" printf '%s' "$5" > /run/m11-instrumentation/payload || return 1
    "$BB" od -An -v -tx1 /run/m11-instrumentation/payload > /run/m11-instrumentation/hex || return 1
    h=$("$BB" tr -d ' \n' < /run/m11-instrumentation/hex) || return 1
    [ -n "$h" ] || h=-
    "$BB" printf 'M11I1 %s %s %s %s %s %s %s\n' "$J_SEQ" "$t" "$1" "$2" "$3" "$4" "$h" >> "$J" || return 1
    J_SEQ=$((J_SEQ + 1))
    n=$("$BB" wc -c < "$J") || return 1
    [ "$n" -le 1048576 ] || return 1
}
journal_file() {
    # Files below are a fixed procfs allowlist, never arbitrary sysfs attributes.
    case "$3" in /proc/asound/cards|/proc/asound/pcm|/proc/asound/modules|/proc/modules|/proc/devices|/proc/mounts|/proc/version|/proc/cmdline|/proc/uptime) ;; *) return 1;; esac
    if "$BB" head -c 32769 "$3" > /run/m11-instrumentation/sample; then r=0; else r=$?; fi
    n=$("$BB" wc -c < /run/m11-instrumentation/sample) || return 1
    [ "$n" -le 32768 ] || r=75
    data=$("$BB" head -c 32768 /run/m11-instrumentation/sample) || return 1
    journal_record "$1" "$2" filesystem_read "$r" "$data" || return 1
}
journal_finish() {
    [ "$J_CLOSED" -eq 0 ] || return 1
    journal_record session final_state metadata 0 'amp_enable_permitted=0 actuator_implemented=0' || return 1
    sum=$("$BB" sha256sum "$J") || return 1
    sum=${sum%% *}
    "$BB" printf 'M11I1 END %s %s\n' "$J_SEQ" "$sum" >> "$J" || return 1
    J_CLOSED=1
    n=$("$BB" wc -c < "$J") || return 1
    "$BB" printf '%s\n' "$n" > /run/m11-instrumentation/logger.stop.tmp || return 1
    "$BB" mv /run/m11-instrumentation/logger.stop.tmp /run/m11-instrumentation/logger.stop || return 1
}
