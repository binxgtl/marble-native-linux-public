/* M18 R3 m18-bye (docs/m18-r3.md): started by poweroff.target and reboot.target once the X server has stopped, with
 * argv[0] "@m18-bye" so that systemd's final killing spares it: the spinner turns until the reset. The panel is taken
 * with the selector's KMS code (scripts/m17/kms.c, hardware-proven on this panel). Its timeline goes to
 * /var/lib/m19/m18-shutdown.log: the start, whether the panel was taken, and a line a second, until the root turns
 * read-only at the end of the shutdown. No arguments; never PID 1. */
#define _GNU_SOURCE
#include "bye.h"
#include "kms.h"
#ifdef M18_R3B
#include "shutdown-trace.h"
#endif

#include <time.h>
#include <unistd.h>

#define LOG "/var/lib/m19/m18-shutdown.log"

int main(int argc, char **argv) {
    (void)argv;
    if (argc != 1 || getpid() <= 1)
        return 64;
    (void)m18_bye_log(LOG, "start");
    struct m17_kms k;
    int shown = m17_kms_open(&k, "/dev/dri/card0") == 0;
    (void)m18_bye_log(LOG, shown ? "kms=open" : "kms=failed");
    const struct timespec pause = {0, M18_BYE_FRAME_MS * 1000000L};
    for (unsigned frame = 0;; frame++) {
        if (shown) {
            uint32_t pitch = 0;
            uint32_t *pixels = m17_kms_pixels(&k, (int)(frame & 1u), &pitch);
            m18_bye_frame(pixels, M18_BYE_W, M18_BYE_H, pitch, frame, frame < 2u);
            if (m17_kms_show(&k, (int)(frame & 1u))) {
                shown = 0;
                (void)m18_bye_log(LOG, "kms=lost");
            }
        }
        if (frame % 30u == 0u) {
            (void)m18_bye_log(LOG, "alive");
#ifdef M18_R3B
            if (frame / 30u < 12u && m18_shutdown_snapshot("/proc", LOG, getpid()) < 0)
                (void)m18_bye_log(LOG, "procs=unavailable");
#endif
        }
        nanosleep(&pause, NULL);
    }
}
