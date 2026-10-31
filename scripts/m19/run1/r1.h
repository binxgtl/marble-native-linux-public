/* M19 R1 runtime: USB evidence first, then read-only unlock steps, then export. */
#ifndef M19_R1_H
#define M19_R1_H

#include <stddef.h>

#define M19_HOST_HELLO "M19HOST1"
#define M19_DEVICE_STEP "M19STEP"
#define M19_DEVICE_BEAT "M19BEAT"
#define M19_DEVICE_LOG "M19LOG1"
#define M19_STEPS_MAX 8
#define M19_WRITE_WARNING "Trying to write to read-only block-device"

enum m19_step_flags {
    M19_STEP_REQUIRED = 1, /* a failure stops the steps that follow */
    M19_STEP_ALWAYS = 2,   /* runs even after a failure, so the evidence is complete */
};

struct m19_step {
    const char *name;
    const char *path;
    unsigned ms;
    unsigned flags;
};

struct m19_run {
    const char *bootstrap, *adsp, *connector, *display, *tty, *kmsg, *boot_log, *logcat;
    const struct m19_step *steps;
    unsigned step_count;
    unsigned bootstrap_ms, display_ms, blue_ms, final_ms, poll_ms, pace_ms, link_ms, log_ms, beat_ms;
    /* Filled in by m19_run_main(). */
    int tty_fd, connector_in, connector_out, all_ok, write_warning, link_lost, ran[M19_STEPS_MAX], results[M19_STEPS_MAX];
    char line[128];
    size_t line_at;
    long adsp_pid;
};

enum m19_run_end { M19_END_PASS, M19_END_NOT_PASS, M19_END_LINK, M19_END_BOOTSTRAP };

/* Returns when PID 1 has nothing left to do. The caller holds and must never exit. */
enum m19_run_end m19_run_main(struct m19_run *r);

#endif
