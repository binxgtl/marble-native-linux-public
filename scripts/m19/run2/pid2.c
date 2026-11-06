/* M19 R2 PID 1. R1's steps, unchanged up to T6, then T9 builds the new root and T8 counts writes.
 * Only a full PASS hands over to systemd. Any other ending holds, as R1 did; nothing restarts the phone.
 * Run as "m19-report report" by systemd, the same binary is the R2 evidence reporter. */
#define _GNU_SOURCE
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "r2.h"

static const struct m19_step steps[] = {
    {"T0-extract", "/m19/t0-extract", 120000, M19_STEP_REQUIRED},
    {"T1-services", "/m19/t1-start", 150000, M19_STEP_REQUIRED},
    {"T2-unlock", "/m19/t2-unlock", 90000, M19_STEP_REQUIRED | M19_STEP_OWNED},
    {"T5-mount", "/m19/t5-mount", 30000, M19_STEP_REQUIRED},
    {"T6-read", "/m19/t6-read", 30000, M19_STEP_REQUIRED},
    {"T9-root", "/m19/t9-root", 120000, M19_STEP_REQUIRED},
    {"T8-writes", "/m19/t8-writes", 30000, M19_STEP_REQUIRED | M19_STEP_ALWAYS},
};

static struct m19_run run = {
    .bootstrap = "/m19/bootstrap", .adsp = "/m19/adsp", .connector = "/sbin/m15-connector", .display = "/sbin/m16-display",
    .tty = "/dev/ttyGS0", .kmsg = "/dev/kmsg", .boot_log = "/run/m19/bootstrap.log", .logcat = "/tee/tmp/m19/logcat.txt",
    .steps = steps, .step_count = sizeof(steps) / sizeof(steps[0]),
    .bootstrap_ms = 120000, .display_ms = 20000, .blue_ms = 3000, .final_ms = 600000, .poll_ms = 5, .pace_ms = 20,
    .link_ms = 420000, .log_ms = 300000, .beat_ms = 5000,
};

static const struct m19_report report = {
    .tty = "/dev/ttyGS0", .kmsg = "/dev/kmsg", .proc1_exe = "/proc/1/exe", .block = "/sys/block", .mountinfo = "/proc/self/mountinfo",
    .systemctl = "/usr/bin/systemctl", .journalctl = "/usr/bin/journalctl", .analyze = "/usr/bin/systemd-analyze",
    .display = "/run/m19/m16-display", .expected_init = "/usr/lib/systemd/systemd",
    .settle_ms = 240000, .poll_ms = 1000, .beat_ms = 5000, .pace_ms = 20, .log_ms = 300000, .command_ms = 30000, .final_ms = 600000,
    .tty_wait_ms = 30000,
};

static void hold(void)
{
    /* PID 1 must never exit, and nothing here restarts the phone. Long-press ends the run. */
    for (;;) {
        while (waitpid(-1, NULL, WNOHANG) > 0) {
        }
        (void)poll(NULL, 0, 100);
    }
}

int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "report"))
        return getpid() == 1 ? 64 : m19_report_main(&report);
    if (getpid() != 1 || argc != 1)
        return 64;
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_DFL);
    if (m19_run_main(&run) == M19_END_PASS) {
        struct m19_handoff handoff = {.proc = "/proc", .kmsg = "/dev/kmsg", .android = "/tee", .newroot = "/newroot",
                                      .init = "/usr/lib/systemd/systemd", .self = getpid(), .settle_ms = 10000, .poll_ms = 20,
                                      .pace_ms = 20, .signal = kill};
        int moved = 0;
        (void)m19_handoff(run.tty_fd, &handoff, &moved);
        /* Only a failed hand-off returns. The sweep stopped the GREEN painter, so YELLOW can take the panel. */
        char *argv_display[] = {moved ? "/run/m19/m16-display" : "/sbin/m16-display", "00ffff00", "600000", NULL};
        if (fork() == 0) {
            execv(argv_display[0], argv_display);
            _exit(127);
        }
    }
    hold();
}
