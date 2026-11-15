/* M17 G5: the daily session's starter and its record (docs/m17-g5.md).
 *
 * M19's reporter started three units of the session itself, in an order R6 to R9 proved, and judged everything over
 * USB. The daily profile has no reporter and no PC; this keeps the starts and their order and records, on disk, what
 * a later read from Android needs:
 *   the desktop up (the X socket, the panel and the desktop running);
 *   the speaker's sink started once, then PulseAudio once the sink streams, then the CE keypad, last, as in R7 to R9;
 *   the record written; then the keypad's one status line, when the owner has answered or the wait ran out.
 * Counts and states only: no name, address or PIN ever reaches the record. */
#ifndef M17_SESSION_H
#define M17_SESSION_H

struct m17_session {
    const char *systemctl, *pactl, *nmcli, *proc, *x_socket, *sink_report, *ce_result, *boot_id, *osrelease, *guard_marker;
    const char *sink_unit, *pulse_unit, *ce_unit, *keys_unit, *guard_unit, *sink_name;
    const char *panel_comm, *desktop_comm;
    const char *log; /* "/var/lib/m19/m17-session.log": appended, under 256 KiB, one older kept */
    const char *const *pulse_env;
    unsigned desktop_ms, sink_ms, pulse_ms, ce_ms, command_ms, poll_ms;
};

struct m17_session_result {
    int x_ok, desktop_ok, sink_rc, streaming, pulse_rc, pulse_sink, ce_rc, ce_seen;
    char sink_state[16], ce_status[32];
};

/* Runs once at every boot of the session. 0 when the desktop came up and the sound is there; 1 otherwise. The record is
 * written either way. */
int m17_session_main(const struct m17_session *s, struct m17_session_result *r);

#endif
