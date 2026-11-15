/* M17 G3 K1-keys: both volume keys on the SUSFS kernel, read natively (docs/m17-g3.md).
 *  1. Volume Up's gpio-keys must already exist: M19's bootstrap loads pinctrl-spmi-gpio.
 *  2. reboot-mode.ko and qcom-pon.ko are loaded from the vendor ramdisk's /lib/modules; qcom-pon creates PMK8350 PON's
 *     resin and pwrkey, and the already loaded pm8941-pwrkey binds them as pmic_resin and pmic_pwrkey.
 *  3. Each key's readiness is timed, its node made from sysfs's number, and it is opened by name.
 *  4. For the window, every key event is recorded, and the selector's state machine is fed the same events to show what
 *     it would have chosen.
 * keys_ok: both keys found, and each pressed and released at least once, with no read error. */
#ifndef M17_G3_H
#define M17_G3_H

#include <stdint.h>
#include <stdio.h>

#define M17_KEY_POWER 116u
#define M17_POWER_DEVICE "pmic_pwrkey"

struct m17_g3 {
    const char *sys_root, *dev_root, *modules_dir;
    int make_nodes;  /* mknod each event node from sysfs (the phone); tests make FIFOs */
    int require_chr; /* the node must be the character device sysfs numbers */
    int (*load)(const char *path); /* finit_module, or a test's stand-in: 0 or -errno */
    uint64_t (*now_ms)(void);
    unsigned up_wait_ms, down_wait_ms, window_ms, settle_ms, poll_ms;
    unsigned select_ms; /* the selector's own window for its observation: M17_WINDOW_MS on the phone */
    FILE *out;
};

struct m17_g3_result {
    int up_found, down_found, power_found, read_error;
    long long up_ready_ms, down_ready_ms, power_ready_ms; /* -1: never */
    int reboot_mode_rc, pon_rc;
    unsigned up_press, up_release, down_press, down_release, power_press, power_release, events;
    int choice, why; /* the selector's first choice over the window's events */
    int keys_ok;
};

/* Runs K1. 0 when keys_ok, 1 otherwise. */
int m17_g3_run(const struct m17_g3 *g, struct m17_g3_result *r);

#endif
