/* G2 stand-in test: the REAL custodian GPR engine over the native anchor transport. The endpoint
 * stand-in is one end of an AF_UNIX SOCK_SEQPACKET pair (one read = one packet, like the endpoint
 * character device); a forked peer plays the ADSP side. No device, driver or kernel module. */
#ifndef M11_CUSTODIAN_NATIVE
#error "test-gpr-transport-native.c builds only with M11_CUSTODIAN_NATIVE"
#endif
#define _GNU_SOURCE
#include "gpr_transport_native.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

enum peer_mode { READY, SILENT, CLOSE_AFTER_READ, HANGUP };

static void peer(int fd, enum peer_mode mode) {
    alarm(10); /* a peer can never hang the suite */
    if (mode == HANGUP) _exit(0);
    uint8_t rx[M11_GPR_MAX_PKT_BYTES];
    ssize_t n = recv(fd, rx, sizeof rx, 0);
    if (n <= 0) _exit(2);
    if (mode == CLOSE_AFTER_READ) _exit(0);
    if (mode == SILENT) { sleep(3); _exit(0); }
    m11_gpr_hdr_t h; const uint8_t *pl; size_t pll;
    if (m11_gpr_validate_packet(rx, (size_t)n, &h, &pl, &pll) < 0) _exit(3);
    if (h.opcode != M11_APM_CMD_GET_SPF_STATE) _exit(4);
    uint32_t ready = 1u; uint8_t tx[64]; size_t txl = 0;
    if (m11_gpr_pack_packet_ex(tx, sizeof tx, &txl, M11_GPR_DOMAIN_APPS, M11_GPR_DOMAIN_ADSP, 0,
                               h.src_port, h.dst_port, h.token, M11_APM_CMD_RSP_GET_SPF_STATE,
                               &ready, sizeof ready) < 0) _exit(5);
    if (send(fd, tx, txl, 0) != (ssize_t)txl) _exit(6);
    sleep(1);
    _exit(0);
}

struct rig { int sv[2]; pid_t pid; m11_pid1_anchor a; m11_gpr_native_link link;
             m11_gpr_transport_t t; m11_gpr_engine_t eng; };

static void start(struct rig *r, enum peer_mode mode) {
    memset(r, 0, sizeof *r);
    assert(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, r->sv) == 0);
    r->pid = fork(); assert(r->pid >= 0);
    if (r->pid == 0) { close(r->sv[0]); peer(r->sv[1], mode); }
    close(r->sv[1]);
    r->a.state = M11_ANCHOR_HELD; r->a.anchor_fd = r->sv[0]; r->a.owner_pid = getpid();
    assert(m11_gpr_native_transport(&r->link, &r->a, &r->t) == 0);
    assert(m11_gpr_engine_init(&r->eng, &r->t, 0x0100u) == 0);
}
static void stop(struct rig *r) {
    /* Close our end FIRST: a peer still blocked in recv (nothing was ever sent) then sees EOF. */
    close(r->sv[0]);
    int st; assert(waitpid(r->pid, &st, 0) == r->pid);
}
static int open_fds(void) {
    DIR *d = opendir("/proc/self/fd"); assert(d); int n = 0;
    for (struct dirent *e; (e = readdir(d));) if (e->d_name[0] != '.') n++;
    closedir(d); return n;
}
static long ms_since(struct timespec s) {
    struct timespec e; clock_gettime(CLOCK_MONOTONIC, &e);
    return (e.tv_sec - s.tv_sec) * 1000L + (e.tv_nsec - s.tv_nsec) / 1000000L;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0); /* progress survives a timeout kill (stdout is a pipe in CI) */
    signal(SIGPIPE, SIG_IGN); /* the socket stand-in raises SIGPIPE; the endpoint device does not */
    struct rig r; uint32_t state = 0, dsp = 0;

    /* 1+2. open creates no fd and returns the anchor's; a READY round-trip through the engine. */
    start(&r, READY);
    int before = open_fds();
    assert(m11_gpr_engine_open(&r.eng) == 0 && r.eng.held_fd == r.sv[0] && open_fds() == before);
    assert(m11_gpr_query_spf_state(&r.eng, 2000, &state) == 0 && state == 1u);
    assert(r.link.opens == 1 && r.link.writes == 1 && r.link.reads == 1);
    /* 6. close detaches only: the fd stays open; the engine never reopens. */
    assert(m11_gpr_engine_close(&r.eng) == 0 && r.link.detaches == 1);
    assert(fcntl(r.sv[0], F_GETFD) != -1);
    assert(m11_gpr_engine_open(&r.eng) == -EBUSY);
    stop(&r);
    printf("PASS open returns the anchor fd and creates none; READY round-trip; close detaches without closing\n");

    /* 3. no reply: -ETIMEDOUT at the deadline, not before, not unbounded. */
    start(&r, SILENT);
    assert(m11_gpr_engine_open(&r.eng) == 0);
    struct timespec t0; clock_gettime(CLOCK_MONOTONIC, &t0);
    int rc = m11_gpr_engine_transact(&r.eng, M11_APM_MODULE_IID, M11_APM_CMD_GET_SPF_STATE,
                                     NULL, 0, 300, &dsp, NULL, 0, NULL);
    long el = ms_since(t0);
    assert(rc == -ETIMEDOUT && el >= 280 && el < 2500 && r.link.timeouts >= 1);
    assert(r.eng.last_tx_status == M11_GPR_TX_SENT);
    stop(&r);
    printf("PASS no reply times out at the transaction deadline (%ld ms of 300)\n", el);

    /* 4a. the peer reads then goes away: EOF is a transport error, never a timeout. */
    start(&r, CLOSE_AFTER_READ);
    assert(m11_gpr_engine_open(&r.eng) == 0);
    rc = m11_gpr_query_spf_state(&r.eng, 2000, &state);
    assert(rc == -EPIPE && r.eng.last_tx_status == M11_GPR_TX_SENT);
    stop(&r);
    /* 4b. the peer is already gone: the write fails and the engine records a write error. */
    start(&r, HANGUP);
    { int st; assert(waitpid(r.pid, &st, 0) == r.pid); r.pid = 0; }
    assert(m11_gpr_engine_open(&r.eng) == 0);
    rc = m11_gpr_query_spf_state(&r.eng, 2000, &state);
    assert(rc == -EPIPE && r.eng.last_tx_status == M11_GPR_TX_WRITE_ERROR);
    close(r.sv[0]);
    printf("PASS peer EOF and a write after hangup are transport errors (-EPIPE), not timeouts\n");

    /* 5. refusals: a LENT anchor, a foreign owner, or a state change after open. */
    start(&r, SILENT);
    r.a.state = M11_ANCHOR_LENT;
    assert(m11_gpr_engine_open(&r.eng) == -EBADF);
    r.a.state = M11_ANCHOR_HELD; r.a.owner_pid = getpid() + 1;
    assert(m11_gpr_engine_open(&r.eng) == -EBADF);
    r.a.owner_pid = getpid();
    assert(m11_gpr_engine_open(&r.eng) == 0);
    r.a.state = M11_ANCHOR_LENT;
    rc = m11_gpr_engine_transact(&r.eng, M11_APM_MODULE_IID, M11_APM_CMD_GET_SPF_STATE,
                                 NULL, 0, 300, &dsp, NULL, 0, NULL);
    assert(rc == -EBADF && r.link.writes == 0 && r.link.refused_io >= 3);
    r.a.state = M11_ANCHOR_OWNER_FDS_DROPPED;
    uint8_t b[8];
    assert(r.t.poll_read_fn(r.t.user, r.sv[0], b, sizeof b, 10) == -EBADF);
    stop(&r);
    printf("PASS I/O refused unless the anchor is HELD by this process (LENT, foreign owner, released)\n");

    /* 7. argument checks. */
    m11_gpr_native_link l; m11_gpr_transport_t t; m11_pid1_anchor a; memset(&a, 0, sizeof a);
    assert(m11_gpr_native_transport(NULL, &a, &t) == -EINVAL);
    assert(m11_gpr_native_transport(&l, NULL, &t) == -EINVAL);
    assert(m11_gpr_native_transport(&l, &a, NULL) == -EINVAL);
    printf("PASS G2 native GPR transport over the anchor (real engine, SEQPACKET stand-in)\n");
    return 0;
}
