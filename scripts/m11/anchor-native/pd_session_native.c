/* Production P1: long-session SERVREG v1 listener and its QRTR adapter — see pd_session_native.h.
 * The wire rules follow the frozen codec (runtime/audio_pd.c, docs/m11-audio-pd-ownership.md);
 * the session rules are the long-running ones described in the header. */
#define _GNU_SOURCE
#include "pd_session_native.h"
#include <errno.h>
#include <limits.h>
#include <linux/qrtr.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#ifndef AF_QIPCRTR
#define AF_QIPCRTR 42
#endif

static uint16_t u16(const unsigned char *p) { return (uint16_t)(p[0] | (unsigned)p[1] << 8); }
static uint32_t u32(const unsigned char *p) { return (uint32_t)u16(p) | (uint32_t)u16(p + 2) << 16; }
static void p16(unsigned char *p, uint16_t n) { p[0] = (unsigned char)n; p[1] = (unsigned char)(n >> 8); }
static void p32(unsigned char *p, uint32_t n) { p16(p, (uint16_t)n); p16(p + 2, (uint16_t)(n >> 16)); }

static int end(m11_pds *s, m11_pds_fault f) {
    if (s->phase != M11_PDS_ENDED) { s->fault = f; s->phase = M11_PDS_ENDED; }
    return -1;
}
static int send_to(m11_pds *s, uint32_t node, uint32_t port, const void *b, size_t n) {
    s->tx++;
    return s->send(s->ctx, node, port, b, n) ? end(s, M11_PDS_IO) : 0;
}
static int lookup(m11_pds *s, uint32_t cmd) {
    unsigned char b[20] = {0};
    p32(b, cmd); p32(b + 4, M11_PDS_SERVICE); p32(b + 8, M11_PDS_INSTANCE);
    if (cmd == 11) { p32(b + 12, s->local_node); p32(b + 16, s->local_port); }
    return send_to(s, s->local_node, M11_PDS_CTRL_PORT, b, sizeof b);
}
/* 1..65535, never 0, never an outstanding id. */
static uint16_t txn(m11_pds *s) {
    for (int i = 0; i < 4; i++) {
        uint16_t t = s->next_txn ? s->next_txn : 1;
        s->next_txn = (uint16_t)(t == 65535 ? 1 : t + 1);
        if (t != s->register_txn && t != s->ack_txn) return t;
    }
    return 0;
}
static size_t tlv(unsigned char *b, unsigned char t, const void *v, size_t n) {
    b[0] = t; p16(b + 1, (uint16_t)n); memcpy(b + 3, v, n); return n + 3;
}
static int request(m11_pds *s, uint16_t id, uint16_t t, unsigned char *b, size_t n) {
    b[0] = 0; p16(b + 1, t); p16(b + 3, id); p16(b + 5, (uint16_t)(n - 7));
    return send_to(s, s->node, s->port, b, n);
}
/* The listener's withdrawal (enable = 0), as the frozen codec's stop sends it. */
static int unregistration(m11_pds *s) {
    unsigned char b[M11_PDS_WIRE_MAX] = {0}, e = 0;
    size_t n = 7; n += tlv(b + n, 1, &e, 1); n += tlv(b + n, 2, M11_PDS_PATH, sizeof(M11_PDS_PATH) - 1);
    if (!(s->register_txn = txn(s))) return end(s, M11_PDS_MALFORMED);
    s->register_deadline = s->now + M11_PDS_TXN_TIMEOUT_MS;
    return request(s, 0x20, s->register_txn, b, n);
}
static int registration(m11_pds *s) {
    unsigned char b[M11_PDS_WIRE_MAX] = {0}, e = 1;
    size_t n = 7; n += tlv(b + n, 1, &e, 1); n += tlv(b + n, 2, M11_PDS_PATH, sizeof(M11_PDS_PATH) - 1);
    if (!(s->register_txn = txn(s))) return end(s, M11_PDS_MALFORMED);
    s->register_deadline = s->now + M11_PDS_TXN_TIMEOUT_MS;
    return request(s, 0x20, s->register_txn, b, n);
}
static int ack(m11_pds *s) {
    unsigned char b[M11_PDS_WIRE_MAX] = {0}, t[2];
    p16(t, s->indication_txn);
    size_t n = 7; n += tlv(b + n, 1, M11_PDS_PATH, sizeof(M11_PDS_PATH) - 1); n += tlv(b + n, 2, t, 2);
    if (!(s->ack_txn = txn(s))) return end(s, M11_PDS_MALFORMED);
    s->ack_deferred = 0;
    s->ack_deadline = s->now + M11_PDS_TXN_TIMEOUT_MS;
    return request(s, 0x23, s->ack_txn, b, n);
}
/* Before the first READY: READY once registered, nothing outstanding and the PD UP. */
static void settle(m11_pds *s) {
    if (s->phase == M11_PDS_ENDED || !s->registered) return;
    if (s->state == M11_PDS_UP && !s->register_txn && !s->ack_txn) { s->phase = M11_PDS_READY; s->ever_ready = 1; }
    else if (s->phase != M11_PDS_READY) s->phase = M11_PDS_WAIT_UP;
}
static int deadlines(m11_pds *s, uint64_t now) {
    if (now < s->now) return end(s, M11_PDS_CLOCK);
    s->now = now;
    if (s->phase == M11_PDS_ENDED) return -1;
    if (!s->ever_ready && now >= s->ready_deadline) return end(s, M11_PDS_DEADLINE); /* only until the first READY */
    if ((s->register_txn && now >= s->register_deadline) || (s->ack_txn && now >= s->ack_deadline))
        return end(s, M11_PDS_DEADLINE);
    return 0;
}

int m11_pds_begin(m11_pds *s, uint32_t node, uint32_t port, uint64_t now, uint32_t budget,
                  int (*send)(void *, uint32_t, uint32_t, const void *, size_t), void *ctx) {
    memset(s, 0, sizeof *s);
    s->phase = M11_PDS_DISCOVERY; s->now = now; s->ready_deadline = now + budget;
    s->local_node = node; s->local_port = port; s->next_txn = 1; s->send = send; s->ctx = ctx;
    if (!send || !port || port >= M11_PDS_CTRL_PORT || !budget || budget > 10000u) return end(s, M11_PDS_MALFORMED);
    return lookup(s, 10);
}
int m11_pds_tick(m11_pds *s, uint64_t now) { return deadlines(s, now); }

struct value { const unsigned char *b; size_t n; };
static int values(const unsigned char *b, size_t n, struct value v[256]) {
    memset(v, 0, 256 * sizeof *v);
    for (size_t pos = 7; pos < n;) {
        if (n - pos < 3) return -1;
        unsigned t = b[pos]; size_t len = u16(b + pos + 1); pos += 3;
        if (v[t].b || len > n - pos) return -1;
        v[t].b = b + pos; v[t].n = len; pos += len;
    }
    return 0;
}
static int only(const struct value v[256], unsigned a, unsigned b, unsigned c) {
    for (unsigned i = 0; i < 256; i++) if (v[i].b && i != a && i != b && i != c) return 0;
    return 1;
}
static int result_ok(const struct value *v) { return v->b && v->n == 4 && !u32(v->b); }
static int path_ok(const struct value *v) {
    return v->b && v->n == sizeof(M11_PDS_PATH) - 1 && !memcmp(v->b, M11_PDS_PATH, v->n);
}
static int valid_state(uint32_t x) { return x == M11_PDS_UP || x == M11_PDS_DOWN || x == 0x2fffffff || x == 0x7fffffff; }

static int control(m11_pds *s, uint32_t node, const unsigned char *b, size_t n) {
    if (node != s->local_node || n != 20) return end(s, M11_PDS_MALFORMED);
    uint32_t cmd = u32(b), a = u32(b + 4), c = u32(b + 8), d = u32(b + 12), e = u32(b + 16);
    switch (cmd) {
    case 4: case 5: /* NEW_SERVER / DEL_SERVER: service, instance, node, port */
        if (cmd == 4 && !a && !c && !d && !e) return 0; /* end of the lookup listing */
        if (a != M11_PDS_SERVICE || c != M11_PDS_INSTANCE || d == s->local_node || !e || e >= M11_PDS_CTRL_PORT)
            return end(s, M11_PDS_PEER_LOST);
        if (cmd == 5) return end(s, M11_PDS_PEER_LOST);
        if (s->peer) return d == s->node && e == s->port ? 0 : end(s, M11_PDS_PEER_LOST);
        if (s->phase == M11_PDS_ENDED) return -1;
        s->peer = 1; s->node = d; s->port = e; s->phase = M11_PDS_REGISTERING;
        return registration(s);
    case 3: /* BYE: node */
        return s->peer && a == s->node ? end(s, M11_PDS_PEER_LOST) : 0;
    case 6: /* DEL_CLIENT: node, port */
        return s->peer && a == s->node && c == s->port ? end(s, M11_PDS_PEER_LOST) : 0;
    case 7: /* RESUME_TX: flow control only */
        return 0;
    default: /* anything else cannot be read as UP */
        return end(s, M11_PDS_PEER_LOST);
    }
}

int m11_pds_receive(m11_pds *s, uint32_t node, uint32_t port, const void *data, size_t n, uint64_t now) {
    const unsigned char *b = data;
    if (deadlines(s, now)) return -1;
    if (!data) return end(s, M11_PDS_MALFORMED);
    s->rx++;
    if (port == M11_PDS_CTRL_PORT) return control(s, node, b, n);
    if (!s->peer || node != s->node || port != s->port || n < 7 || n > M11_PDS_WIRE_MAX || u16(b + 5) != n - 7)
        return end(s, M11_PDS_MALFORMED);
    struct value v[256];
    if (values(b, n, v)) return end(s, M11_PDS_MALFORMED);
    uint16_t id = u16(b + 3), t = u16(b + 1);
    if (s->phase == M11_PDS_STOPPING) { /* only the withdrawal's response; anything else fails the stop */
        if (!(b[0] == 2 && id == 0x20 && t && t == s->register_txn) || !only(v, 2, 16, 2) || !result_ok(&v[2]))
            return end(s, M11_PDS_MALFORMED);
        s->register_txn = 0; s->unregister_ok = 1; s->registered = 0;
        if (lookup(s, 11)) return -1; /* DEL_LOOKUP */
        s->phase = M11_PDS_STOPPED;
        return 0;
    }
    if (b[0] == 2 && id == 0x20 && t && t == s->register_txn) { /* registration response */
        if (!only(v, 2, 16, 2) || !result_ok(&v[2]) || !v[16].b || v[16].n != 4 || !valid_state(u32(v[16].b)))
            return end(s, M11_PDS_MALFORMED);
        s->register_txn = 0; s->registered = 1;
        if (!s->indications) s->state = u32(v[16].b); /* an indication wins over a delayed snapshot */
        settle(s);
        return 0;
    }
    if (b[0] == 4 && id == 0x22) { /* state indication */
        if (!only(v, 1, 2, 3) || !v[1].b || v[1].n != 4 || !path_ok(&v[2]) || !v[3].b || v[3].n != 2 ||
            !valid_state(u32(v[1].b)) || s->ack_txn || s->ack_deferred)
            return end(s, M11_PDS_MALFORMED);
        s->indications++; s->indication_txn = u16(v[3].b); s->indication_state = s->state = u32(v[1].b);
        if (s->state != M11_PDS_UP && s->ever_ready) {
            end(s, M11_PDS_NOT_UP); /* terminal; the ACK below still goes out unless resources are busy */
            if (s->resources_busy) { s->ack_deferred = 1; return -1; }
            (void)ack(s);
            return -1;
        }
        if (s->state != M11_PDS_UP && s->resources_busy) { s->ack_deferred = 1; settle(s); return 0; }
        int rc = ack(s);
        if (s->phase != M11_PDS_READY) settle(s); /* READY persists through an UP re-indication */
        return rc;
    }
    if (b[0] == 2 && id == 0x23 && t && t == s->ack_txn) { /* ACK response */
        if (!only(v, 2, 2, 2) || !result_ok(&v[2])) return end(s, M11_PDS_MALFORMED);
        s->ack_txn = 0;
        settle(s);
        return s->phase == M11_PDS_ENDED ? -1 : 0;
    }
    return end(s, M11_PDS_MALFORMED);
}

void m11_pds_resources_busy(m11_pds *s) { s->resources_busy = 1; }
int m11_pds_stop(m11_pds *s, uint64_t now_ms) {
    if (s->phase == M11_PDS_STOPPED) return 0;
    if (s->phase == M11_PDS_STOPPING) return 1;
    /* only a READY, idle session with nothing busy: a deferred ACK is never sent here */
    if (s->resources_busy || s->phase != M11_PDS_READY || s->ack_txn || s->ack_deferred || s->register_txn) return -1;
    if (deadlines(s, now_ms)) return -1;
    s->phase = M11_PDS_STOPPING; s->unregister_sent = 1;
    return unregistration(s) ? -1 : 1;
}
int m11_pds_resources_released(m11_pds *s) {
    s->resources_busy = 0;
    return s->ack_deferred ? ack(s) : 0;
}

/* ------------------------------------ QRTR adapter ------------------------------------ */
static int q_socket(void *u) {
    (void)u;
    int fd = socket(AF_QIPCRTR, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    return fd < 0 ? -errno : fd;
}
static int q_getsockname(void *u, int fd, uint32_t *node, uint32_t *port) {
    (void)u;
    struct sockaddr_qrtr a; socklen_t len = sizeof a;
    memset(&a, 0, sizeof a);
    if (getsockname(fd, (struct sockaddr *)&a, &len) || len != sizeof a || a.sq_family != AF_QIPCRTR) return -EIO;
    if (!a.sq_port) { /* bind to the socket's own node (qrtr_bind refuses any other) to get a port */
        a.sq_port = 0;
        len = sizeof a;
        if (bind(fd, (struct sockaddr *)&a, sizeof a) || getsockname(fd, (struct sockaddr *)&a, &len) ||
            len != sizeof a || a.sq_family != AF_QIPCRTR || !a.sq_port) return -EIO;
    }
    *node = a.sq_node; *port = a.sq_port;
    return 0;
}
static int q_sendto(void *u, int fd, uint32_t node, uint32_t port, const void *b, size_t n) {
    (void)u;
    struct sockaddr_qrtr a = {.sq_family = AF_QIPCRTR, .sq_node = node, .sq_port = port};
    ssize_t r = sendto(fd, b, n, MSG_DONTWAIT, (struct sockaddr *)&a, sizeof a); /* qrtr refuses other flags */
    return r == (ssize_t)n ? 0 : r < 0 ? -errno : -EIO;
}
static ssize_t q_recvfrom(void *u, int fd, void *b, size_t cap, uint32_t *node, uint32_t *port) {
    (void)u;
    struct sockaddr_qrtr a; socklen_t len = sizeof a;
    ssize_t n = recvfrom(fd, b, cap, MSG_DONTWAIT | MSG_TRUNC, (struct sockaddr *)&a, &len);
    if (n < 0) return errno == EAGAIN || errno == EWOULDBLOCK ? -EAGAIN : -errno;
    if ((size_t)n > cap || len != sizeof a || a.sq_family != AF_QIPCRTR) return -EMSGSIZE;
    *node = a.sq_node; *port = a.sq_port;
    return n;
}
static int q_close(void *u, int fd) { (void)u; return close(fd) ? -errno : 0; }
const m11_qrtr_sys m11_qrtr_libc = {q_socket, q_getsockname, q_sendto, q_recvfrom, q_close, NULL};

static uint64_t mono_ms(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) return 0;
    return (uint64_t)t.tv_sec * 1000u + (uint64_t)t.tv_nsec / 1000000u;
}
static int mon_send(void *ctx, uint32_t node, uint32_t port, const void *b, size_t n) {
    m11_pdmon *m = ctx;
    return m->sys->sendto_fn(m->sys->u, m->fd, node, port, b, n);
}
int m11_pdmon_pump(void *user, uint64_t now_ms) {
    m11_pdmon *m = user;
    for (;;) {
        unsigned char b[M11_PDS_WIRE_MAX + 1]; uint32_t node = 0, port = 0;
        ssize_t n = m->sys->recvfrom_fn(m->sys->u, m->fd, b, sizeof b, &node, &port);
        if (n == -EAGAIN) break;
        if (n < 0 || (size_t)n > M11_PDS_WIRE_MAX) { end(&m->pds, n < 0 ? M11_PDS_IO : M11_PDS_MALFORMED); break; }
        m->datagrams++;
        (void)m11_pds_receive(&m->pds, node, port, b, (size_t)n, now_ms);
    }
    (void)m11_pds_tick(&m->pds, now_ms);
    return m11_pds_up(&m->pds) ? 1 : 0;
}
int m11_pdmon_open(m11_pdmon *m, const m11_qrtr_sys *sys, uint64_t now_ms, uint32_t budget_ms) {
    if (!m || !budget_ms) return -EINVAL;
    memset(m, 0, sizeof *m);
    m->fd = -1;
    m->sys = sys ? sys : &m11_qrtr_libc;
    int fd = m->sys->socket_fn(m->sys->u);
    if (fd < 0) return fd;
    uint32_t node = 0, port = 0;
    int rc = m->sys->getsockname_fn(m->sys->u, fd, &node, &port);
    if (rc) { (void)m->sys->close_fn(m->sys->u, fd); return rc; }
    m->fd = fd;
    if (m11_pds_begin(&m->pds, node, port, now_ms, budget_ms, mon_send, m)) {
        (void)m->sys->close_fn(m->sys->u, fd); m->fd = -1;
        return -EIO;
    }
    m->monitor = (m11_pd_monitor){.fd = fd, .pump_fn = m11_pdmon_pump, .user = m};
    return 0;
}
int m11_pdmon_wait_up(m11_pdmon *m, uint32_t budget_ms) {
    uint64_t start = mono_ms(), deadline = start + budget_ms;
    while (start) {
        uint64_t now = mono_ms();
        if (m11_pdmon_pump(m, now) == 1) return 0;
        if (m->pds.phase == M11_PDS_ENDED || !now || now >= deadline) break;
        struct pollfd p = {.fd = m->fd, .events = POLLIN};
        uint64_t left = deadline - now;
        if (poll(&p, 1, left > (uint64_t)INT_MAX ? INT_MAX : (int)left) < 0 && errno != EINTR) break;
    }
    return -ENETRESET;
}
int m11_pdmon_retire(m11_pdmon *m, uint32_t budget_ms) {
    if (!m || m->fd < 0 || !budget_ms || budget_ms > M11_PDS_TXN_TIMEOUT_MS) return -EINVAL;
    uint64_t start = mono_ms(), deadline = start + budget_ms;
    (void)m11_pdmon_pump(m, start); /* what arrived before the stop */
    int rc = start ? m11_pds_stop(&m->pds, start) : -1;
    if (rc < 0) return -EBUSY;     /* refused: the socket stays open, the session unchanged */
    while (m->pds.phase == M11_PDS_STOPPING) {
        uint64_t now = mono_ms();
        if (!now || now >= deadline) break;
        struct pollfd p = {.fd = m->fd, .events = POLLIN};
        uint64_t left = deadline - now;
        if (poll(&p, 1, left > (uint64_t)INT_MAX ? INT_MAX : (int)left) < 0 && errno != EINTR) break;
        (void)m11_pdmon_pump(m, mono_ms());
    }
    const int stopped = m->pds.phase == M11_PDS_STOPPED;
    int crc = m->sys->close_fn(m->sys->u, m->fd); /* the kernel withdraws the port (DEL_CLIENT) */
    m->fd = -1; m->monitor.fd = -1;
    if (!stopped) return -ETIMEDOUT;
    return crc ? -EIO : 0;
}
