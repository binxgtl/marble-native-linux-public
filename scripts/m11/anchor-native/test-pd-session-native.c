/* Production P1 stand-in test: the long-session SERVREG listener through its QRTR adapter, over a
 * fixture QRTR (a pollable pipe plus a datagram queue with node/port addresses), then the adapter's
 * monitor inside the G6 transport. No QRTR, no QMI peer, no device. */
#ifndef M11_CUSTODIAN_NATIVE
#error "test-pd-session-native.c builds only with M11_CUSTODIAN_NATIVE"
#endif
#define _GNU_SOURCE
#include "pd_session_native.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* ---- fixture QRTR ---- */
#define LOCAL 1u
#define LPORT 0x4001u
#define PEER 5u
#define PPORT 0x40u
#define QMAX 64
static struct dg { uint32_t node, port; size_t n; unsigned char b[160]; } rxq[QMAX], txl[256];
static unsigned rxh, rxt, ntx; static int pipefd[2] = {-1, -1}, fail_send_at = -1;
static int f_socket(void *u) { (void)u; assert(pipe2(pipefd, O_NONBLOCK | O_CLOEXEC) == 0); return pipefd[0]; }
static int f_getsockname(void *u, int fd, uint32_t *n, uint32_t *p) { (void)u; assert(fd == pipefd[0]); *n = LOCAL; *p = LPORT; return 0; }
static int f_sendto(void *u, int fd, uint32_t node, uint32_t port, const void *b, size_t n) {
    (void)u; assert(fd == pipefd[0] && n <= sizeof txl[0].b && ntx < 256);
    if ((int)ntx == fail_send_at) return -EIO;
    txl[ntx].node = node; txl[ntx].port = port; txl[ntx].n = n; memcpy(txl[ntx].b, b, n); ntx++;
    return 0;
}
static ssize_t f_recvfrom(void *u, int fd, void *b, size_t cap, uint32_t *node, uint32_t *port) {
    (void)u; assert(fd == pipefd[0]);
    if (rxh == rxt) return -EAGAIN;
    char c; assert(read(pipefd[0], &c, 1) == 1);
    struct dg *d = &rxq[rxh++ % QMAX];
    if (d->n > cap) return -EMSGSIZE;
    memcpy(b, d->b, d->n); *node = d->node; *port = d->port;
    return (ssize_t)d->n;
}
static int f_close(void *u, int fd) { (void)u; close(fd); close(pipefd[1]); pipefd[0] = pipefd[1] = -1; return 0; }
static const m11_qrtr_sys fx = {f_socket, f_getsockname, f_sendto, f_recvfrom, f_close, NULL};
static void enqueue(uint32_t node, uint32_t port, const void *b, size_t n) {
    struct dg *d = &rxq[rxt++ % QMAX]; d->node = node; d->port = port; d->n = n; memcpy(d->b, b, n);
    assert(write(pipefd[1], "x", 1) == 1);
}

/* ---- wire builders ---- */
static void p16(unsigned char *p, uint16_t n) { p[0] = (unsigned char)n; p[1] = (unsigned char)(n >> 8); }
static void p32(unsigned char *p, uint32_t n) { p16(p, (uint16_t)n); p16(p + 2, (uint16_t)(n >> 16)); }
static uint16_t g16(const unsigned char *p) { return (uint16_t)(p[0] | p[1] << 8); }
static uint32_t g32(const unsigned char *p) { return (uint32_t)g16(p) | (uint32_t)g16(p + 2) << 16; }
static void ctrl(uint32_t cmd, uint32_t a, uint32_t b, uint32_t c, uint32_t d) {
    unsigned char m[20]; p32(m, cmd); p32(m + 4, a); p32(m + 8, b); p32(m + 12, c); p32(m + 16, d);
    enqueue(LOCAL, M11_PDS_CTRL_PORT, m, sizeof m);
}
static size_t tlv(unsigned char *b, unsigned char t, const void *v, size_t n) { b[0] = t; p16(b + 1, (uint16_t)n); memcpy(b + 3, v, n); return n + 3; }
static void qmi(unsigned char type, uint16_t txn, uint16_t id, unsigned char *b, size_t n) {
    b[0] = type; p16(b + 1, txn); p16(b + 3, id); p16(b + 5, (uint16_t)(n - 7)); enqueue(PEER, PPORT, b, n);
}
static uint16_t last_txn(uint16_t id) { /* the most recent request of this id we sent */
    for (int i = (int)ntx - 1; i >= 0; i--) if (txl[i].n >= 7 && g16(txl[i].b + 3) == id) return g16(txl[i].b + 1);
    return 0;
}
static unsigned count_tx(uint16_t id) { unsigned c = 0; for (unsigned i = 0; i < ntx; i++) if (txl[i].n >= 7 && txl[i].port == PPORT && g16(txl[i].b + 3) == id) c++; return c; }
static void reg_response(uint32_t state) {
    unsigned char b[64] = {0}, r[4] = {0}, s[4]; p32(s, state);
    size_t n = 7; n += tlv(b + n, 2, r, 4); n += tlv(b + n, 16, s, 4);
    qmi(2, last_txn(0x20), 0x20, b, n);
}
static void indication(uint32_t state, uint16_t itxn) {
    unsigned char b[96] = {0}, s[4], t[2]; p32(s, state); p16(t, itxn);
    size_t n = 7; n += tlv(b + n, 1, s, 4); n += tlv(b + n, 2, M11_PDS_PATH, sizeof(M11_PDS_PATH) - 1); n += tlv(b + n, 3, t, 2);
    qmi(4, 0x0101, 0x22, b, n);
}
static void ack_response(void) {
    unsigned char b[32] = {0}, r[4] = {0};
    size_t n = 7; n += tlv(b + n, 2, r, 4);
    qmi(2, last_txn(0x23), 0x23, b, n);
}

static m11_pdmon M;
static void fresh(uint64_t t) {
    if (M.fd >= 0 && pipefd[0] >= 0) f_close(NULL, M.fd);
    rxh = rxt = ntx = 0; fail_send_at = -1;
    assert(m11_pdmon_open(&M, &fx, t, 5000) == 0 && M.fd == pipefd[0] && M.monitor.fd == M.fd);
}
static void to_ready(uint64_t t) {
    fresh(t);
    ctrl(4, M11_PDS_SERVICE, M11_PDS_INSTANCE, PEER, PPORT);
    assert(m11_pdmon_pump(&M, t + 1) == 0);
    reg_response(M11_PDS_UP);
    assert(m11_pdmon_pump(&M, t + 2) == 1);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGPIPE, SIG_IGN);
    M.fd = -1;

    /* 1. bring-up on the wire */
    fresh(1000);
    assert(ntx == 1 && txl[0].node == LOCAL && txl[0].port == M11_PDS_CTRL_PORT && txl[0].n == 20);
    assert(g32(txl[0].b) == 10 && g32(txl[0].b + 4) == M11_PDS_SERVICE && g32(txl[0].b + 8) == M11_PDS_INSTANCE);
    assert(m11_pdmon_pump(&M, 1001) == 0 && M.pds.phase == M11_PDS_DISCOVERY);
    ctrl(4, M11_PDS_SERVICE, M11_PDS_INSTANCE, PEER, PPORT);
    assert(m11_pdmon_pump(&M, 1002) == 0 && M.pds.phase == M11_PDS_REGISTERING);
    assert(ntx == 2 && txl[1].node == PEER && txl[1].port == PPORT && g16(txl[1].b + 3) == 0x20 && txl[1].b[0] == 0);
    assert(txl[1].b[7] == 1 && g16(txl[1].b + 8) == 1 && txl[1].b[10] == 1); /* TLV1: enable = 1 */
    assert(txl[1].b[11] == 2 && !memcmp(txl[1].b + 14, M11_PDS_PATH, sizeof(M11_PDS_PATH) - 1));
    ctrl(4, 0, 0, 0, 0); /* end of the lookup listing */
    reg_response(M11_PDS_UP);
    assert(m11_pdmon_pump(&M, 1003) == 1 && M.pds.phase == M11_PDS_READY);
    printf("PASS bring-up: NEW_LOOKUP (service 0x42, instance 74), registration to the announced peer, READY on an UP snapshot\n");

    /* 2. no session deadline once READY */
    assert(m11_pdmon_pump(&M, 1003 + 600000) == 1 && m11_pdmon_pump(&M, 1003 + 3600000) == 1);
    printf("PASS long session: still UP an hour after READY (the frozen codec ends at 10 s)\n");

    /* 3. an UP re-indication keeps READY through its ACK */
    indication(M11_PDS_UP, 7);
    assert(m11_pdmon_pump(&M, 3601010) == 1);
    assert(count_tx(0x23) == 1 && g16(txl[ntx - 1].b + 3) == 0x23 && g16(txl[ntx - 1].b + 7 + 3 + sizeof(M11_PDS_PATH) - 1 + 3) == 7);
    ack_response();
    assert(m11_pdmon_pump(&M, 3601020) == 1);
    printf("PASS UP re-indication: acknowledged, READY throughout\n");

    /* 4. DOWN is terminal and acknowledged; nothing makes it UP again */
    to_ready(10000);
    indication(M11_PDS_DOWN, 9);
    assert(m11_pdmon_pump(&M, 10010) == 0 && M.pds.phase == M11_PDS_ENDED && M.pds.fault == M11_PDS_NOT_UP);
    assert(count_tx(0x23) == 1);
    indication(M11_PDS_UP, 10);
    assert(m11_pdmon_pump(&M, 10020) == 0);
    printf("PASS DOWN after READY: terminal, acknowledged, never UP again\n");

    /* 5. DOWN while resources are busy: the ACK waits for their release */
    to_ready(20000);
    m11_pds_resources_busy(&M.pds);
    unsigned before = ntx;
    indication(M11_PDS_DOWN, 11);
    assert(m11_pdmon_pump(&M, 20010) == 0 && ntx == before && M.pds.ack_deferred);
    assert(m11_pds_resources_released(&M.pds) == 0 && ntx == before + 1 && g16(txl[ntx - 1].b + 3) == 0x23);
    printf("PASS DOWN while resources are busy: not UP at once, the ACK deferred until release\n");

    /* 6. control traffic */
    to_ready(30000);
    ctrl(7, 0, 0, 0, 0);                 assert(m11_pdmon_pump(&M, 30010) == 1); /* RESUME_TX */
    ctrl(6, PEER, PPORT + 1, 0, 0);      assert(m11_pdmon_pump(&M, 30011) == 1); /* DEL_CLIENT, other port */
    ctrl(3, PEER + 1, 0, 0, 0);          assert(m11_pdmon_pump(&M, 30012) == 1); /* BYE, other node */
    ctrl(4, M11_PDS_SERVICE, M11_PDS_INSTANCE, PEER, PPORT); assert(m11_pdmon_pump(&M, 30013) == 1); /* same server again */
    ctrl(6, PEER, PPORT, 0, 0);          assert(m11_pdmon_pump(&M, 30014) == 0 && M.pds.fault == M11_PDS_PEER_LOST);
    to_ready(31000); ctrl(3, PEER, 0, 0, 0); assert(m11_pdmon_pump(&M, 31010) == 0);
    to_ready(32000); ctrl(5, M11_PDS_SERVICE, M11_PDS_INSTANCE, PEER, PPORT); assert(m11_pdmon_pump(&M, 32010) == 0);
    to_ready(33000); ctrl(2, 0, 0, 0, 0); int hello = m11_pdmon_pump(&M, 33010); assert(hello == 0);
    to_ready(34000); ctrl(4, M11_PDS_SERVICE, M11_PDS_INSTANCE, PEER + 2, PPORT); assert(m11_pdmon_pump(&M, 34010) == 0);
    printf("PASS control: RESUME_TX and other endpoints ignored; DEL_CLIENT/BYE of the peer, DEL_SERVER, another server, unknown types end the session\n");

    /* 7. malformed or foreign datagrams */
    to_ready(40000); { unsigned char b[16] = {0}; qmi(2, 1, 0x20, b, 9); } assert(m11_pdmon_pump(&M, 40010) == 0); /* bad TLV */
    to_ready(41000); { unsigned char b[7] = {2, 1, 0, 0x20, 0, 5, 0}; enqueue(PEER, PPORT, b, 7); } assert(m11_pdmon_pump(&M, 41010) == 0); /* length */
    to_ready(42000); { unsigned char b[10] = {0}; enqueue(PEER + 1, PPORT, b, 10); } assert(m11_pdmon_pump(&M, 42010) == 0); /* foreign node */
    to_ready(43000); { unsigned char b[20] = {0}; enqueue(LOCAL, M11_PDS_CTRL_PORT, b, 12); } assert(m11_pdmon_pump(&M, 43010) == 0); /* short control */
    printf("PASS malformed TLVs, length mismatch, a foreign sender and a short control message end the session\n");

    /* 8. deadlines and the clock */
    fresh(50000); assert(m11_pdmon_pump(&M, 54999) == 0 && M.pds.phase == M11_PDS_DISCOVERY);
    assert(m11_pdmon_pump(&M, 55000) == 0 && M.pds.fault == M11_PDS_DEADLINE);
    fresh(60000); ctrl(4, M11_PDS_SERVICE, M11_PDS_INSTANCE, PEER, PPORT); assert(m11_pdmon_pump(&M, 60001) == 0);
    assert(m11_pdmon_pump(&M, 62001) == 0 && M.pds.fault == M11_PDS_DEADLINE); /* registration unanswered for 2 s */
    to_ready(70000); indication(M11_PDS_UP, 12); assert(m11_pdmon_pump(&M, 70010) == 1);
    assert(m11_pdmon_pump(&M, 72010) == 0 && M.pds.fault == M11_PDS_DEADLINE); /* an ACK unanswered for 2 s */
    to_ready(80000); assert(m11_pdmon_pump(&M, 79999) == 0 && M.pds.fault == M11_PDS_CLOCK);
    printf("PASS deadlines: discovery budget, 2 s registration and ACK timeouts; a clock going backwards ends the session\n");

    /* 9. transaction ids wrap and a send error ends the session */
    to_ready(90000);
    M.pds.next_txn = 65535;
    indication(M11_PDS_UP, 13); assert(m11_pdmon_pump(&M, 90010) == 1 && last_txn(0x23) == 65535);
    ack_response(); assert(m11_pdmon_pump(&M, 90020) == 1);
    indication(M11_PDS_UP, 14); assert(m11_pdmon_pump(&M, 90030) == 1 && last_txn(0x23) == 1);
    fresh(95000); fail_send_at = 1; ctrl(4, M11_PDS_SERVICE, M11_PDS_INSTANCE, PEER, PPORT);
    assert(m11_pdmon_pump(&M, 95010) == 0 && M.pds.fault == M11_PDS_IO);
    printf("PASS transaction ids wrap 65535 -> 1; a send error ends the session\n");

    /* 10. the adapter's monitor in the G6 transport: a queued DOWN stops the TX */
    to_ready(100000);
    indication(M11_PDS_DOWN, 15);
    int sv[2]; assert(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv) == 0);
    m11_pid1_anchor ep; memset(&ep, 0, sizeof ep); ep.state = M11_ANCHOR_HELD; ep.anchor_fd = sv[0]; ep.owner_pid = getpid();
    m11_gpr_native_link link; m11_gpr_transport_t t;
    assert(m11_gpr_native_transport_pd(&link, &ep, &M.monitor, &t) == 0);
    unsigned char pkt[32] = {0};
    int w = t.write_fn(t.user, sv[0], pkt, sizeof pkt);
    assert(w == -ENETRESET && link.pd_down && link.writes == 0);
    close(sv[0]); close(sv[1]);
    printf("PASS monitor in the G6 transport: the DOWN pumped before the write refuses the TX (-ENETRESET)\n");

    /* 12. B5 retire (stop): only from READY with nothing busy; the withdrawal, DEL_LOOKUP, STOPPED */
    to_ready(110000);
    unsigned b0 = ntx;
    assert(m11_pds_stop(&M.pds, 110001) == 1 && M.pds.phase == M11_PDS_STOPPING && ntx == b0 + 1);
    assert(g16(txl[ntx - 1].b + 3) == 0x20 && txl[ntx - 1].b[7] == 1 && txl[ntx - 1].b[10] == 0); /* enable = 0 */
    { unsigned char b[32] = {0}, r[4] = {0}; size_t n = 7; n += tlv(b + n, 2, r, 4); qmi(2, last_txn(0x20), 0x20, b, n); }
    assert(m11_pdmon_pump(&M, 110002) == 0 && M.pds.phase == M11_PDS_STOPPED && M.pds.unregister_ok);
    assert(ntx == b0 + 2 && txl[ntx - 1].port == M11_PDS_CTRL_PORT && g32(txl[ntx - 1].b) == 11 &&
           g32(txl[ntx - 1].b + 12) == LOCAL && g32(txl[ntx - 1].b + 16) == LPORT);
    assert(m11_pds_stop(&M.pds, 110003) == 0);
    to_ready(111000); m11_pds_resources_busy(&M.pds); b0 = ntx;
    int busy_stop = m11_pds_stop(&M.pds, 111001);
    assert(busy_stop == -1 && M.pds.phase == M11_PDS_READY && ntx == b0);
    to_ready(112000); indication(M11_PDS_DOWN, 16); assert(m11_pdmon_pump(&M, 112010) == 0);
    assert(m11_pds_stop(&M.pds, 112011) == -1);
    to_ready(113000); assert(m11_pds_stop(&M.pds, 113001) == 1); indication(M11_PDS_UP, 17);
    assert(m11_pdmon_pump(&M, 113002) == 0 && M.pds.phase == M11_PDS_ENDED); /* anything else while stopping fails it */
    printf("PASS B5 retire: from READY only, never while resources are busy or after the session ended; withdrawal (enable 0), DEL_LOOKUP, STOPPED; any other datagram fails the stop\n");

    /* 11. the production socket path on this host */
    m11_pdmon real; int rc = m11_pdmon_open(&real, NULL, 1, 5000);
    printf("INFO AF_QIPCRTR on this host: open rc=%d fd=%d (not asserted beyond cleanup)\n", rc, real.fd);
    assert(rc == 0 || real.fd == -1);
    printf("PASS production P1 PD session and QRTR monitor (fixture QRTR, G6 transport)\n");
    return 0;
}
