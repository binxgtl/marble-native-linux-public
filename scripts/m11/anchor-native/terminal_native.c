/* G8 native end of a custodian boot — see terminal_native.h. */
#define _GNU_SOURCE
#include "terminal_native.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/reboot.h>
#include <unistd.h>

static void ops_exit(void *u) { (void)u; _exit(0); }
static int ops_reboot(void *u) { (void)u; return reboot(RB_AUTOBOOT) ? -errno : -EIO; }
m11_terminal_ops m11_terminal_ops_default(void) {
    return (m11_terminal_ops){.exit_fn = ops_exit, .reboot_fn = ops_reboot, .user = NULL,
                              .panic_path = "/proc/sys/kernel/panic"};
}

static int read_panic(const char *path) {
    if (!path) return INT_MIN;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return INT_MIN;
    char b[32]; ssize_t n = read(fd, b, sizeof b - 1);
    close(fd);
    if (n <= 0) return INT_MIN;
    b[n] = 0;
    char *end; long v = strtol(b, &end, 10);
    if (end == b || (*end && *end != '\n') || v < INT_MIN + 1 || v > INT_MAX) return INT_MIN;
    return (int)v;
}

static void record(m11_terminal_native *t, const char *end, const char *note) {
    const m11_boot_ledger *b = t->c->boot;
    char panic[16], path[32];
    if (t->panic == INT_MIN) { snprintf(panic, sizeof panic, "unknown"); snprintf(path, sizeof path, "unknown"); }
    else {
        snprintf(panic, sizeof panic, "%d", t->panic);
        if (t->panic < 0) snprintf(path, sizeof path, "immediate");
        else if (t->panic == 0) snprintf(path, sizeof path, "hang");
        else snprintf(path, sizeof path, "after_%ds", t->panic);
    }
    int n = snprintf(t->record, sizeof t->record,
                     "<6>M11TERMINAL v=1 boot=%llu action=%s end=%s anchors_held=%u/%u pool=%s panic=%s "
                     "reset_path=%s map_attempted=%d unmap_attempted=%d note=%s\n",
                     (unsigned long long)b->boot_epoch, m11_terminal_action_name(t->action), end,
                     t->anchors_held, t->nanchors, !t->pool ? "none" : t->pool_held ? "held" : "NOT_HELD",
                     panic, path, b->dsp_map_attempted ? 1 : 0, b->dsp_unmap_attempted ? 1 : 0, note);
    if (n < 0 || (size_t)n >= sizeof t->record) { t->sink_failed = 1; return; }
    if (t->sink && t->sink->append_fn(t->sink->user, t->record, (size_t)n) != 0) t->sink_failed = 1;
}

/* Never closes, never reboots: marks the anchors retained, checks what is still held, records,
 * and ends the boot through exit_fn. */
static int end_retaining(m11_terminal_native *t, const char *note) {
    t->anchors_held = 0;
    for (unsigned i = 0; i < t->nanchors; i++) {
        m11_pid1_anchor *a = t->anchors[i];
        int held = a->state == M11_ANCHOR_HELD && m11_anchor_check(a) == 0;
        m11_anchor_end e;
        (void)m11_anchor_end_boot(a, M11_TERMINAL_RESET_RETAINING_ANCHORS, &e); /* RETAIN, never REBOOT */
        t->anchors_held += held ? 1u : 0u;
    }
    t->pool_held = t->pool ? m11_dmabuf_census_pid(t->pool, getpid(), 1) == 0 : 0;
    record(t, "pid1_exit", note);
    t->ops.exit_fn(t->ops.user);
    return -EFAULT; /* exit_fn returned */
}

int m11_terminal_native_end(m11_terminal_native *t, uint64_t now_ms) {
    if (!t || !t->c || !t->c->boot || t->nanchors > 2 || !t->ops.exit_fn || !t->ops.reboot_fn) return -EINVAL;
    for (unsigned i = 0; i < t->nanchors; i++) if (!t->anchors[i]) return -EINVAL;
    t->orderly_failed = t->reboot_failed = t->sink_failed = 0;
    (void)m11_custodian_tick(t->c, now_ms);
    t->action = m11_custodian_terminal_action(t->c);
    if (t->action == M11_TERMINAL_HOLD || t->action == M11_TERMINAL_HOLD_RECONCILE) return -EBUSY;
    t->panic = read_panic(t->ops.panic_path);

    if (t->action == M11_TERMINAL_ORDERLY_SHUTDOWN && m11_custodian_reboot_permitted(t->c) &&
        !t->c->boot->dsp_map_attempted) {
        int ok = 1;
        for (unsigned i = 0; ok && i < t->nanchors; i++) {
            m11_pid1_anchor *a = t->anchors[i];
            if (a->state == M11_ANCHOR_HELD && m11_anchor_final_close(a) != 0) ok = 0;
            m11_anchor_end e;
            if (ok && (m11_anchor_end_boot(a, M11_TERMINAL_ORDERLY_SHUTDOWN, &e) != 0 || e != M11_ANCHOR_END_REBOOT)) ok = 0;
        }
        if (ok) {
            t->anchors_held = 0;
            t->pool_held = t->pool ? m11_dmabuf_census_pid(t->pool, getpid(), 1) == 0 : 0;
            record(t, "reboot", "never_mapped");
            if (t->ops.reboot_fn(t->ops.user) != 0) { t->reboot_failed = 1; return end_retaining(t, "reboot_failed"); }
            t->reboot_failed = 1; /* reboot_fn returned success without rebooting */
            return end_retaining(t, "reboot_returned");
        }
        t->orderly_failed = 1;
        return end_retaining(t, "orderly_failed");
    }
    return end_retaining(t, t->c->boot->dsp_map_attempted ? "mapped_boot" : "tainted");
}
