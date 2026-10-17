/* G2 native GPR transport over PID1's endpoint anchor — see gpr_transport_native.h. */
#define _GNU_SOURCE
#include "gpr_transport_native.h"
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

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

static int t_open(void *user) {
    m11_gpr_native_link *l = user;
    int fd = held_fd(l);
    if (fd >= 0) l->opens++;
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
    uint64_t start = mono_ms(), deadline = start + timeout_ms;
    if (!start) return -EIO;
    for (;;) {
        uint64_t now = mono_ms();
        if (!now) return -EIO;
        uint64_t left = now >= deadline ? 0 : deadline - now;
        struct pollfd p = {.fd = own, .events = POLLIN};
        int pr = poll(&p, 1, left > (uint64_t)INT_MAX ? INT_MAX : (int)left);
        if (pr < 0) {
            if (errno == EINTR) continue;
            return -errno;
        }
        if (pr == 0) { l->timeouts++; return 0; }
        if (p.revents & POLLNVAL) return -EBADF;
        if (p.revents & POLLIN) {
            ssize_t n;
            do n = read(own, buf, cap); while (n < 0 && errno == EINTR);
            if (n < 0) return -errno;
            if (n == 0) return -EPIPE;          /* peer gone: a transport error, not a timeout */
            if ((size_t)n > (size_t)INT_MAX) return -EMSGSIZE;
            l->reads++;
            return (int)n;
        }
        if (p.revents & POLLHUP) return -EPIPE;
        if (p.revents & POLLERR) return -EIO;
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
