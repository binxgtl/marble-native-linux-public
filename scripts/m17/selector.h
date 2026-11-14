/* M17 selector, PID 1 in boot_a's ramdisk (docs/m17-dual-boot-selector.md, option A; docs/m17-g4.md).
 *
 *   early mounts; a boot that is not normal (charger, alarm, FFBM): Android at once, nothing loaded
 *   the module list (the keys and the display, every one a module Android loads itself, its own copy)
 *   the display card; the menu on the panel; the 10 s window on both volume keys
 *   the menu torn down and its disable verified, whatever the window chose
 *   native only on Volume Down and only when this build has a native path; everything else Android
 *   Android: early mounts undone, then exec /init.stock, the stock first stage, as PID 1
 *
 * Every failure on the way goes to Android. The flow is here, behind an operations table, so tests drive it. */
#ifndef M17_SELECTOR_H
#define M17_SELECTOR_H

#include "select.h"

struct m17_selector_ops {
    void *user;
    void (*log)(void *user, const char *line);
    int (*mount_early)(void *user);
    /* /proc/cmdline and /proc/bootconfig; <0 when absent */
    int (*read_cmdline)(void *user, char *buf, unsigned room);
    int (*read_bootconfig)(void *user, char *buf, unsigned room);
    int (*load_modules)(void *user, const char *cmdline); /* failures count; the selector goes on */
    int (*wait_card)(void *user);                         /* the DRM card and its node */
    int (*wait_keys)(void *user);                         /* both key devices and their nodes */
    int (*menu_open)(void *user);                         /* the panel's first frame */
    /* The window with its countdown on the panel; the choice, as m17_run_window gives it. */
    enum m17_choice (*window)(void *user, struct m17_window *w);
    /* G4b: the panel handed on lit: M17_KMS_OK (no plane) or M17_KMS_LIT_BLACK (a black frame); after a failure,
     * M17_KMS_FAILED or M17_KMS_UNSAFE_ROLLBACK, the panel off as in G4a. */
    int (*menu_close)(void *user);
    int (*unmount_early)(void *user);
    int (*exec_android)(void *user); /* returns only on failure */
    int (*run_native)(void *user);   /* NULL: this build has no native path */
};

struct m17_selector_result {
    int normal, modules_failed, card, keys, menu, menu_closed;
    enum m17_choice choice;
    enum m17_reason why;
    int native_ran;
};

/* Runs the selector. Returns only when /init.stock could not be executed (or, with a native path, when it ended). */
int m17_selector_run(const struct m17_selector_ops *o, struct m17_selector_result *r);

#endif
