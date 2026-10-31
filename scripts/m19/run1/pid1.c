/* M19 R1 PID 1. Reports and holds. There is no reboot path and no switch_root. */
#define _GNU_SOURCE
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include "r1.h"

static const struct m19_step steps[] = {
    {"T0-extract", "/m19/t0-extract", 120000, M19_STEP_REQUIRED},
    {"T1-services", "/m19/t1-start", 150000, M19_STEP_REQUIRED},
    {"T2-unlock", "/m19/t2-unlock", 90000, M19_STEP_REQUIRED},
    {"T5-mount", "/m19/t5-mount", 30000, M19_STEP_REQUIRED},
    {"T6-read", "/m19/t6-read", 30000, M19_STEP_REQUIRED},
    {"T7-overlay", "/m19/t7-overlay", 30000, 0},
    {"T8-writes", "/m19/t8-writes", 30000, M19_STEP_REQUIRED | M19_STEP_ALWAYS},
};

static struct m19_run run = {
    .bootstrap = "/m19/bootstrap", .adsp = "/m19/adsp", .connector = "/sbin/m15-connector", .display = "/sbin/m16-display",
    .tty = "/dev/ttyGS0", .kmsg = "/dev/kmsg", .boot_log = "/run/m19/bootstrap.log", .logcat = "/tee/tmp/m19/logcat.txt",
    .steps = steps, .step_count = sizeof(steps) / sizeof(steps[0]),
    .bootstrap_ms = 120000, .display_ms = 20000, .blue_ms = 3000, .final_ms = 600000, .poll_ms = 5, .pace_ms = 20,
    .link_ms = 420000, .log_ms = 300000, .beat_ms = 5000,
};

int main(void)
{
    if (getpid() != 1)
        return 64;
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_DFL);
    (void)m19_run_main(&run);
    /* PID 1 must never exit, and this runtime has no reboot path. Long-power ends the run. */
    for (;;) {
        int status;
        while (waitpid(-1, &status, WNOHANG) > 0) {
        }
        (void)poll(NULL, 0, 100);
    }
}
