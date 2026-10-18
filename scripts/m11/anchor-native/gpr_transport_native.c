/* G2 native GPR transport over PID1's endpoint anchor, with the G6 PD monitor — see
 * gpr_transport_native.h. */
#define _GNU_SOURCE
#include "gpr_transport_native.h"
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifndef ENETRESET
#define ENETRESET 102
#endif

static uint64_t mono_ms(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) return 0;
    return (uint64_t)t.tv_sec * 1000u + (uint64_t)t.tv_nsec / 1000000u;
}

/* The fd is usable only while this process holds the anchor alone. */
static int held_fd(m11_gpr_native_link *l) {
    const m11_pid1_anchor *a = l->anchor;
    if (!a || a->state != M11_ANCHOR_HELD || a->anchor_fd < 0 || a->owner_pid != getpid()) {
        l->refused_io++;
        return -EBADF;
    }
    return a->anchor_fd;
}

/* G6: 0 while the PD is UP (or no monitor), -ENETRESET once it is not; latched for the boot. */
static void pd_latch(m11_gpr_native_link *l) {
    if (!l->pd_down) { l->pd_down = 1; l->pd_downs++; }
}
static int pd_ok(m11_gpr_native_link *l) {
    if (!l->pd) return 0;
    if (l->pd_down) return -ENETRESET;
    l->pd_pumps++;
    if (l->pd->pump_fn(l->pd->user, mono_ms()) != 1) { pd_latch(l); return -ENETRESET; }
    return 0;
}

static int t_open(void *user) {
    m11_gpr_native_link *l = user;
    int fd = held_fd(l);
    if (fd < 0) return fd;
    int rc = pd_ok(l);
    if (rc) return rc;
    l->opens++;
    return fd;
}

static int t_close(void *user, int fd) {
    m11_gpr_native_link *l = user;
    (void)fd; /* never closed here: the anchor's final close is the endpoint's only release */
    l->detaches++;
    return 0;
}

static int t_write(void *user, int fd, const uint8_t *buf, size_t len) {
    m11_gpr_native_link *l = user;
    int own = held_fd(l);
    if (own < 0) return own;
    if (fd != own || !buf || !len || len > (size_t)INT_MAX) return -EINVAL;
    int rc;
    if ((rc = pd_ok(l))) return rc; /* no TX once DOWN */
    ssize_t n;
    do n = write(own, buf, len); while (n < 0 && errno == EINTR);
    if (n < 0) return -errno;
    l->writes++;
    return (int)n;
}

static int t_poll_read(void *user, int fd, uint8_t *buf, size_t cap, uint32_t timeout_ms) {
    m11_gpr_native_link *l = user;
    int own = held_fd(l);
    if (own < 0) return own;
    if (fd != own || !buf || !cap) return -EINVAL;
    int rc;
    if ((rc = pd_ok(l))) return rc;
    uint64_t start = mono_ms(), deadline = start + timeout_ms;
    if (!start) return -EIO;
    for (;;) {
        uint64_t now = mono_ms();
        if (!now) return -EIO;
        uint64_t left = now >= deadline ? 0 : deadline - now;
        struct pollfd p[2] = {{.fd = own, .events = POLLIN}, {.fd = l->pd ? l->pd->fd : -1, .events = POLLIN}};
        nfds_t nfds = l->pd ? 2 : 1;
        int pr = poll(p, nfds, left > (uint64_t)INT_MAX ? INT_MAX : (int)left);
        if (pr < 0) {
            if (errno == EINTR) continue;
            return -errno;
        }
        if (pr == 0) { l->timeouts++; return 0; }
        if (nfds == 2 && p[1].revents) {
            /* The monitor first: a DOWN ends the wait before any endpoint data of the same instant. */
            if ((p[1].revents & POLLIN) && (rc = pd_ok(l))) return rc;
            if (p[1].revents & (POLLHUP | POLLERR | POLLNVAL)) { pd_latch(l); return -ENETRESET; }
        }
        if (p[0].revents & POLLNVAL) return -EBADF;
        if (p[0].revents & POLLIN) {
            ssize_t n;
            do n = read(own, buf, cap); while (n < 0 && errno == EINTR);
            if (n < 0) return -errno;
            if (n == 0) return -EPIPE;          /* peer gone: a transport error, not a timeout */
            if ((size_t)n > (size_t)INT_MAX) return -EMSGSIZE;
            l->reads++;
            return (int)n;
        }
        if (p[0].revents & POLLHUP) return -EPIPE;
        if (p[0].revents & POLLERR) return -EIO;
    }
}

int m11_gpr_native_transport(m11_gpr_native_link *link, const m11_pid1_anchor *anchor,
                             m11_gpr_transport_t *out) {
    if (!link || !anchor || !out) return -EINVAL;
    memset(link, 0, sizeof *link);
    link->anchor = anchor;
    *out = (m11_gpr_transport_t){.open_fn = t_open, .close_fn = t_close, .write_fn = t_write,
                                 .poll_read_fn = t_poll_read, .user = link};
    return 0;
}

int m11_gpr_native_transport_pd(m11_gpr_native_link *link, const m11_pid1_anchor *anchor,
                                const m11_pd_monitor *pd, m11_gpr_transport_t *out) {
    if (!pd || pd->fd < 0 || !pd->pump_fn) return -EINVAL;
    int rc = m11_gpr_native_transport(link, anchor, out);
    if (rc) return rc;
    link->pd = pd;
    return 0;
}

int m11_gpr_native_pd_pump(m11_gpr_native_link *link) {
    if (!link || !link->pd) return -EINVAL;
    return pd_ok(link);
}
