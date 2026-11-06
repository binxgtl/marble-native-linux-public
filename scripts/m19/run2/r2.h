/* M19 R2: R1's proven steps, then PID 1 hands the phone to systemd on the read-only Ubuntu root.
 * The same binary, copied into the new root's /run, is the evidence reporter that systemd starts. */
#ifndef M19_R2_H
#define M19_R2_H

#include <stddef.h>
#include <sys/types.h>

#include "../run1/r1.h"

/* Paced writes on the USB serial line, as R1 sends them. */
unsigned long long m19_now_ms(void);
int m19_wire_open(const char *tty);
int m19_wire_put(int fd, const void *data, size_t size, unsigned pace_ms, unsigned long long end_ms);
int m19_wire_line(int fd, unsigned pace_ms, const char *format, ...) __attribute__((format(printf, 3, 4)));

struct m19_handoff {
    const char *proc;    /* "/proc" */
    const char *kmsg;    /* "/dev/kmsg" */
    const char *android; /* "/tee": the Android chroot, detached once nothing runs in it */
    const char *newroot; /* "/newroot", built by T9 */
    const char *init;    /* "/usr/lib/systemd/systemd", inside the new root */
    pid_t self;          /* never signalled, besides PID 1 */
    unsigned settle_ms, poll_ms, pace_ms;
    int (*signal)(pid_t, int); /* kill(2) in production */
};

/* 1 for a kernel thread, 0 for a user process, -1 when the stat line cannot be read. */
int m19_stat_is_kthread(const char *line);
/* Counts user processes other than PID 1 and self, and sends each SIGKILL when kill_them is set.
 * Kernel threads are never counted or signalled. An unreadable entry is counted. */
int m19_sweep(const struct m19_handoff *h, int kill_them);
/* Does not return on success: systemd is PID 1. On failure it returns -1 and sets *moved when
 * the root had already changed, so the caller knows which display binary is reachable. */
int m19_handoff(int tty_fd, const struct m19_handoff *h, int *moved);

struct m19_report {
    const char *tty, *kmsg, *proc1_exe, *block, *mountinfo, *systemctl, *journalctl, *analyze, *display, *expected_init;
    unsigned settle_ms, poll_ms, beat_ms, pace_ms, log_ms, command_ms, final_ms, tty_wait_ms;
    /* R3 only, when desktop is set: Xorg and XFCE, the refresh rate and a touch window. */
    unsigned desktop, x_wait_ms, session_wait_ms, touch_ms;
    double want_hz;
    const char *xdpyinfo, *xrandr, *xinput, *ps, *proc, *interrupts, *card, *touch_name, *xorg_logs[2];
    const char *guard_unit, *guard_marker, *battery_temp, *thermal;
};

/* R3's guard, a service of its own beside the desktop. It stops the desktop units and paints YELLOW
 * when the battery or any thermal zone runs hot, when the CPU stays busy, or when the session runs
 * long. It reads sensors and /proc only; its one action is stopping the desktop. */
struct m19_guard {
    const char *battery_temp, *thermal, *stat, *kmsg, *systemctl, *display, *marker, *units[3];
    unsigned period_ms, note_ms, busy_limit, busy_ms, session_ms, run_ms, command_ms, final_ms;
    long battery_limit; /* tenths of a degree, as power_supply reports */
    long zone_limit;    /* thousandths of a degree, as thermal zones report */
};

int m19_guard_main(const struct m19_guard *g);

/* Rate of vertical blanks on the first CRTC that answers, from the kernel's own timestamps. */
int m19_vblank_rate(const char *card, double *hz);

/* Runs under systemd, never as PID 1. Waits for the boot to settle, sends the evidence, then
 * execs the display: GREEN when every check passed, YELLOW otherwise. */
int m19_report_main(const struct m19_report *c);

#endif
