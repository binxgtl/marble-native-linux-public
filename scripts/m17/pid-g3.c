/* M17 G3 PID 1 (docs/m17-g3.md): M19 R1's runtime, unchanged, on the SUSFS kernel, with one step, K1-keys.
 * The bootstrap loads M19's 102 modules and starts the ADSP; the USB link to the PC comes up; K1 loads reboot-mode and
 * qcom-pon and records both volume keys; the log goes to the PC. Then, only if the log was sent, the phone restarts
 * through the kernel's reboot path with qcom-pon loaded: the second question G3 answers. Any earlier ending holds, as
 * every M19 run did, and a long-press ends it. */
#define _GNU_SOURCE
#include <poll.h>
#include <signal.h>
#include <sys/reboot.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../m19/run1/r1.h"

static const struct m19_step steps[] = {
    {"K1-keys", "/m17/keys", 180000, M19_STEP_REQUIRED},
};

static struct m19_run run = {
    .bootstrap = "/m19/bootstrap", .adsp = "/m19/adsp", .connector = "/sbin/m15-connector", .display = "/sbin/m16-display",
    .tty = "/dev/ttyGS0", .kmsg = "/dev/kmsg", .boot_log = "/run/m19/bootstrap.log", .logcat = "/run/m19/no-logcat",
    .steps = steps, .step_count = sizeof(steps) / sizeof(steps[0]),
    .bootstrap_ms = 120000, .display_ms = 20000, .blue_ms = 3000, .final_ms = 600000, .poll_ms = 5, .pace_ms = 20,
    .link_ms = 420000, .log_ms = 300000, .beat_ms = 5000,
};

/* The colour stays this long before the restart, so the operator sees how the run ended. */
#define REBOOT_AFTER_MS 15000

int main(void)
{
    if (getpid() != 1)
        return 64;
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_DFL);
    enum m19_run_end end = m19_run_main(&run);
    if (end == M19_END_PASS || end == M19_END_NOT_PASS) {
        (void)poll(NULL, 0, REBOOT_AFTER_MS);
        sync();
        (void)reboot(RB_AUTOBOOT);
    }
    /* No log, or the restart refused: hold. Long-power ends the run. */
    for (;;) {
        int status;
        while (waitpid(-1, &status, WNOHANG) > 0) {
        }
        (void)poll(NULL, 0, 100);
    }
}
