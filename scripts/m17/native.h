/* M17 G5: PID 1 on the native path without the PC (docs/m17-g5.md).
 *
 * M19 R1's flow (scripts/m19/run1/r1.c) with the USB link taken out, for a boot the selector started:
 *   the bootstrap (the payload, the modules the selector did not load, the card node, then R5a's audio stage);
 *   BLUE; the ADSP, as M19's adsp script starts it; the steps, R9's, in order and with R1's rules (a required step's
 *   failure stops the rest but the ALWAYS ones; the unlock step owns its process group);
 *   the log, written into the tree for Android to read afterwards; GREEN when every required step passed, YELLOW
 *   otherwise, RED when the bootstrap or the ADSP held.
 * Every line also goes to the kernel log, as M17NAT. No reboot path exists, and nothing waits for a PC. */
#ifndef M17_NATIVE_H
#define M17_NATIVE_H

#include <stddef.h>

#include "../m19/run1/r1.h" /* struct m19_step, its flags and M19_STEPS_MAX */

struct m17_native {
    const char *bootstrap, *adsp, *display, *kmsg, *boot_log, *logcat;
    /* The tree's /var/lib/m19 as PID 1 sees it once T5 has mounted /data, and the log's name there. The log before
     * is kept as NAME.1. Every directory on the way is opened without following a link. */
    const char *log_dir, *log_name;
    const struct m19_step *steps;
    unsigned step_count;
    unsigned bootstrap_ms, adsp_ms, display_ms, blue_ms, final_ms;
    /* Filled in by m17_native_main(). */
    int all_ok, write_warning, ownership_unresolved, adsp_rc, log_rc;
    int ran[M19_STEPS_MAX], results[M19_STEPS_MAX];
    unsigned long long step_ms[M19_STEPS_MAX];
    long adsp_pid;
};

enum m17_native_end { M17_END_PASS, M17_END_NOT_PASS, M17_END_ADSP, M17_END_BOOTSTRAP };

/* Returns when PID 1 has nothing left to run. The caller hands over on a PASS and otherwise holds. */
enum m17_native_end m17_native_main(struct m17_native *n);

/* The log on disk carries no identifier: the kernel's command line (it holds androidboot.serialno), anything after
 * "serialno", and every MAC address are blanked, line by line, in place. Returns the new size. */
size_t m17_redact(char *text, size_t size);

/* Writes `size` bytes as <dir>/<name> through a temporary name, synced, the previous file kept as <name>.1. Every
 * component of dir is opened without following a link; only its last component may be created (0755).
 * 0 or -errno. */
int m17_write_log(const char *dir, const char *name, const void *data, size_t size);

#endif
