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

static int is_open(int fd) { return fd >= 0 && fcntl(fd, F_GETFD) != -1; }

/* The truth about the anchor fds: the numbers captured before any close (the adapter forgets
 * them after a refused close_pair while the fds stay open), else the adapter's current ones. */
static unsigned anchor_fds_open(const m11_terminal_native *t) {
    unsigned n = 0;
    for (unsigned i = 0; i < t->nanchors; i++) {
        int a = t->saved ? t->saved_fd[i][0] : t->anchors[i]->anchor_fd;
        int g = t->saved ? t->saved_fd[i][1] : t->anchors[i]->guard_fd;
        n += (unsigned)is_open(a) + (unsigned)is_open(g);
    }
    return n;
}

/* Custodian regions that still own a dma-buf fd, and how many of those are sealed pool buffers. */
static int in_pool(const m11_dmabuf_pool *p, int fd) {
    return p && p->count && fd >= p->base && fd < p->base + 2 * (int)p->count && (fd - p->base) % 2 == 0;
}
static void count_regions(m11_terminal_native *t) {
    t->regions = t->regions_in_pool = 0;
    for (unsigned i = 0; i < M11_CUSTODIAN_REGIONS; i++) {
        if (!t->c->occupied[i] || t->c->regions[i].dma_buf_fd < 0) continue;
        t->regions++;
        if (in_pool(t->pool, t->c->regions[i].dma_buf_fd)) t->regions_in_pool++;
    }
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
    count_regions(t);
    int n = snprintf(t->record, sizeof t->record,
                     "<6>M11TERMINAL v=2 boot=%llu action=%s end=%s anchors_held=%u/%u anchor_fds_open=%u/%u pool=%s "
                     "panic=%s reset_path=%s map_attempted=%d unmap_attempted=%d regions=%u in_pool=%u note=%s\n",
                     (unsigned long long)b->boot_epoch, m11_terminal_action_name(t->action), end,
                     t->anchors_held, t->nanchors, anchor_fds_open(t), 2u * t->nanchors,
                     !t->pool ? "none" : t->pool_held ? "held" : "NOT_HELD", panic, path,
                     b->dsp_map_attempted ? 1 : 0, b->dsp_unmap_attempted ? 1 : 0,
                     t->regions, t->regions_in_pool, note);
    if (n < 0 || (size_t)n >= sizeof t->record) { t->sink_failed = 1; return; }
    if (t->sink && t->sink->append_fn(t->sink->user, t->record, (size_t)n) != 0) t->sink_failed = 1;
}

/* Never closes, never reboots: marks the anchors retained, checks what is still held, records
 * (a sink failure never blocks), and ends the boot through exit_fn. */
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

/* Before any close: every anchor must be HELD with no refusing latch and pass its check (identity,
 * CLOEXEC, census), or
 * be legitimately finished (dropped with no close error or hidden reference, or never bound).
 * Anything else (LENT to a worker, RETAINED, FAILED, a failing check) closes nothing. */
static int anchors_ready(m11_terminal_native *t) {
    for (unsigned i = 0; i < t->nanchors; i++) {
        m11_pid1_anchor *a = t->anchors[i];
        if (a->state == M11_ANCHOR_HELD) {
            /* a refusing latch would fail its final close later, possibly after another closed */
            if ((a->latches & M11_ANCHOR_LATCH_REFUSE) || m11_anchor_check(a) != 0) return 0;
            continue;
        }
        if (a->state == M11_ANCHOR_UNBOUND) continue;
        if (a->state == M11_ANCHOR_OWNER_FDS_DROPPED &&
            !(a->latches & (M11_ANCHOR_LATCH_CLOSE_ERROR | M11_ANCHOR_LATCH_HIDDEN_REFERENCE))) continue;
        return 0;
    }
    return 1;
}

int m11_terminal_native_end(m11_terminal_native *t, uint64_t now_ms) {
    if (!t || !t->c || !t->c->boot || t->nanchors > 2 || !t->ops.exit_fn || !t->ops.reboot_fn) return -EINVAL;
    for (unsigned i = 0; i < t->nanchors; i++) if (!t->anchors[i]) return -EINVAL;
    t->orderly_failed = t->reboot_failed = t->sink_failed = t->saved = 0;
    (void)m11_custodian_tick(t->c, now_ms);
    t->action = m11_custodian_terminal_action(t->c);
    if (t->force_retain_note) { /* an ownership violation: the record keeps the custodian's own decision */
        t->panic = read_panic(t->ops.panic_path);
        return end_retaining(t, t->force_retain_note);
    }
    if (t->action == M11_TERMINAL_HOLD || t->action == M11_TERMINAL_HOLD_RECONCILE) return -EBUSY;
    t->panic = read_panic(t->ops.panic_path);

    if (t->action == M11_TERMINAL_ORDERLY_SHUTDOWN && m11_custodian_reboot_permitted(t->c) &&
        !t->c->boot->dsp_map_attempted) {
        if (!anchors_ready(t)) { t->orderly_failed = 1; return end_retaining(t, "anchor_not_held"); }
        for (unsigned i = 0; i < t->nanchors; i++) {
            t->saved_fd[i][0] = t->anchors[i]->anchor_fd;
            t->saved_fd[i][1] = t->anchors[i]->guard_fd;
        }
        t->saved = 1;
        unsigned closed = 0;
        for (unsigned i = 0; i < t->nanchors; i++) {
            m11_pid1_anchor *a = t->anchors[i];
            if (a->state != M11_ANCHOR_HELD) continue;
            if (m11_anchor_final_close(a) != 0) {
                t->orderly_failed = 1;
                return end_retaining(t, closed ? "partial_final_close" : "orderly_failed");
            }
            closed++;
        }
        for (unsigned i = 0; i < t->nanchors; i++) {
            m11_anchor_end e;
            if (m11_anchor_end_boot(t->anchors[i], M11_TERMINAL_ORDERLY_SHUTDOWN, &e) != 0 || e != M11_ANCHOR_END_REBOOT) {
                t->orderly_failed = 1;
                return end_retaining(t, "orderly_failed");
            }
        }
        t->anchors_held = 0;
        t->pool_held = t->pool ? m11_dmabuf_census_pid(t->pool, getpid(), 1) == 0 : 0;
        record(t, "reboot", "never_mapped");
        if (t->ops.reboot_fn(t->ops.user) != 0) { t->reboot_failed = 1; return end_retaining(t, "reboot_failed"); }
        t->reboot_failed = 1; /* reboot_fn returned success without rebooting */
        return end_retaining(t, "reboot_returned");
    }
    return end_retaining(t, t->c->boot->dsp_map_attempted ? "mapped_boot" : "tainted");
}
