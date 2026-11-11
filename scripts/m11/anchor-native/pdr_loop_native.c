/* G6 PDR event loop — see pdr_loop_native.h. */
#define _GNU_SOURCE
#include "pdr_loop_native.h"
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <time.h>

#ifndef ENETRESET
#define ENETRESET 102
#endif

static uint64_t mono_ms(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) return 0;
    return (uint64_t)t.tv_sec * 1000u + (uint64_t)t.tv_nsec / 1000000u;
}

int m11_pdr_loop_init(m11_pdr_loop *l, m11_custodian *c, m11_gpr_native_link *link) {
    if (!l || !c || !c->mgr || !c->mgr->gpr || !link || !link->pd) return -EINVAL;
    *l = (m11_pdr_loop){.c = c, .link = link};
    return 0;
}

m11_terminal_action m11_pdr_loop_settle(m11_pdr_loop *l, uint64_t now_ms) {
    if (!l || !l->c) return M11_TERMINAL_RESET_RETAINING_ANCHORS;
    int down = l->link->pd_down || l->c->mgr->gpr->pdr_down;
    if (down && !l->down_reported) {
        l->down_reported = 1;
        m11_custodian_pd_down(l->c, now_ms);
    }
    return m11_custodian_terminal_action(l->c);
}

int m11_pdr_loop_idle(m11_pdr_loop *l, uint32_t budget_ms, uint64_t now_ms) {
    if (!l || !l->c) return -EINVAL;
    l->idle_waits++;
    int rc = m11_gpr_native_pd_pump(l->link); /* traffic that arrived before the wait */
    uint64_t start = mono_ms(), deadline = start + budget_ms;
    while (!rc) {
        uint64_t now = mono_ms();
        if (!now || !start) { rc = -EIO; break; }
        if (now >= deadline) break;
        uint64_t left = deadline - now;
        struct pollfd p = {.fd = l->link->pd->fd, .events = POLLIN};
        int pr = poll(&p, 1, left > (uint64_t)INT_MAX ? INT_MAX : (int)left);
        if (pr < 0) { if (errno == EINTR) continue; rc = -errno; break; }
        if (pr == 0) break;
        if (p.revents & POLLIN) rc = m11_gpr_native_pd_pump(l->link);
        if (!rc && (p.revents & (POLLHUP | POLLERR | POLLNVAL))) {
            /* a lost monitor is a lost PD: latch through the transport, never reconnect */
            l->link->pd_down = 1; l->link->pd_downs++;
            rc = -ENETRESET;
        }
    }
    (void)m11_pdr_loop_settle(l, now_ms); /* the caller's clock: the custodian ledger's only clock */
    return rc;
}
