/* Production P3 stand-in test: the PID1 entry (P1 monitor + P2 boot + composed runner + G8 terminal)
 * over a fake sysfs/procfs tree, a scratch /dev and a fixture QRTR that crosses processes:
 *  - the QRTR "socket" is one end of an AF_UNIX datagram pair, each datagram prefixed with the
 *    sender's or destination's node and port; the real P1 session (pd_session_native) runs over it;
 *  - the stand-in on the other end, forked before the entry runs (it never holds an anchor, pool
 *    buffer or the heap), answers the SERVREG lookup, registration and ACKs, sends a DOWN on demand,
 *    and on the endpoint's pty slave answers GPR packets, refusing any whose intent record is not
 *    already in the journal file;
 *  - stand-in numbers as in P2: endpoint 5:2 (pty multiplexer), ION 1:3, its CMA twin 1:5, heap 1:7.
 * The terminal's exit/reboot hooks report what the boot holds. Each case runs in a child (a private
 * mount namespace as root). No device, QRTR, driver or reboot. */
#ifndef M11_CUSTODIAN_NATIVE
#error "test-entry-native.c builds only with M11_CUSTODIAN_NATIVE"
#endif
#define _GNU_SOURCE
#include "custodian_entry_native.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

static char base[256], root[320];
static int in_case;
static m11_entry_config CFG;
static m11_entry E;
static char p_sys[400], p_proc[400], p_dev[400], p_ep[400], p_ion[400], p_cma[400], p_hdir[400], p_hnode[400];
static char p_cmdline[400], p_journal[400];
static int report_fd = -1;
static void say(const char *s) { (void)!write(report_fd, s, strlen(s)); }

static void put(const char *rel, const char *text) {
    char path[600], dir[600];
    snprintf(path, sizeof path, "%s/%s", root, rel);
    snprintf(dir, sizeof dir, "%s", path);
    for (char *s = dir + strlen(root) + 1; (s = strchr(s, '/')); s++) { *s = 0; (void)mkdir(dir, 0755); *s = '/'; }
    FILE *f = fopen(path, "w"); assert(f && fputs(text, f) >= 0 && fclose(f) == 0);
}
static int absent(const char *p) { struct stat st; return lstat(p, &st) && errno == ENOENT; }

/* ---- fixture QRTR over an AF_UNIX datagram pair: [node u32][port u32][payload] ---- */
#define LOCAL 1u
#define LPORT 0x4001u
#define PEER 5u
#define PPORT 0x40u
static int qs[2] = {-1, -1};
static unsigned sockets, acks_sent, regs_sent;
static void p16(unsigned char *p, uint16_t n) { p[0] = (unsigned char)n; p[1] = (unsigned char)(n >> 8); }
static void p32(unsigned char *p, uint32_t n) { p16(p, (uint16_t)n); p16(p + 2, (uint16_t)(n >> 16)); }
static uint16_t g16(const unsigned char *p) { return (uint16_t)(p[0] | p[1] << 8); }
static uint32_t g32(const unsigned char *p) { return (uint32_t)g16(p) | (uint32_t)g16(p + 2) << 16; }
static int f_socket(void *u) { (void)u; sockets++; return qs[0]; }
static int f_getsockname(void *u, int fd, uint32_t *n, uint32_t *p) { (void)u; assert(fd == qs[0]); *n = LOCAL; *p = LPORT; return 0; }
static int f_sendto(void *u, int fd, uint32_t node, uint32_t port, const void *b, size_t n) {
    (void)u; unsigned char m[8 + 160];
    if (fd != qs[0] || n > 160) return -EINVAL;
    p32(m, node); p32(m + 4, port); memcpy(m + 8, b, n);
    if (port == PPORT && n >= 7 && g16((const unsigned char *)b + 3) == 0x23) acks_sent++;
    if (port == PPORT && n >= 7 && g16((const unsigned char *)b + 3) == 0x20) regs_sent++;
    return send(fd, m, n + 8, MSG_DONTWAIT) == (ssize_t)(n + 8) ? 0 : -EIO;
}
static ssize_t f_recvfrom(void *u, int fd, void *b, size_t cap, uint32_t *node, uint32_t *port) {
    (void)u; unsigned char m[8 + 256];
    ssize_t r = recv(fd, m, sizeof m, MSG_DONTWAIT);
    if (r < 0) return errno == EAGAIN ? -EAGAIN : -errno;
    if (r < 8 || (size_t)(r - 8) > cap) return -EMSGSIZE;
    *node = g32(m); *port = g32(m + 4); memcpy(b, m + 8, (size_t)r - 8);
    return r - 8;
}
static int f_close(void *u, int fd) { (void)u; return close(fd) ? -errno : 0; }
static const m11_qrtr_sys fxq = {f_socket, f_getsockname, f_sendto, f_recvfrom, f_close, NULL};

/* ---- fixture syscalls: the heap and ION stand-ins are recognised by their numbers ---- */
static int rdev_is(int fd, dev_t d) { struct stat st; return !fstat(fd, &st) && S_ISCHR(st.st_mode) && st.st_rdev == d; }
static int fx_ioctl(int fd, unsigned long req, void *arg) {
    if (req == M11_DMA_HEAP_IOCTL_ALLOC) {
        m11_dma_heap_allocation_data *d = arg;
        if (!rdev_is(fd, makedev(1, 7))) { errno = EBADF; return -1; }
        int m = memfd_create("m11-entry", MFD_CLOEXEC);
        if (m < 0 || ftruncate(m, (off_t)d->len)) return -1;
        d->fd = (uint32_t)m; return 0;
    }
    if (req == M11_DMA_BUF_IOCTL_SYNC) return 0;
    if (req == M11_MSM_AUDIO_ION_MAP_PHYS || req == M11_MSM_AUDIO_ION_UNMAP) return rdev_is(fd, makedev(1, 3)) ? 0 : (errno = EBADF, -1);
    errno = ENOTTY; return -1;
}
static int fx_munmap(void *a, size_t l) { return munmap(a, l); }
static const m11_shmem_native_sys fx_sys = {fx_ioctl, mmap, fx_munmap, close};

/* ---- the ADSP + PD stand-in ---- */
enum pmode { P_UP, P_NEVER_UP };
static void q_send(int q, uint32_t node, uint32_t port, const unsigned char *b, size_t n) {
    unsigned char m[8 + 160]; p32(m, node); p32(m + 4, port); memcpy(m + 8, b, n);
    if (send(q, m, n + 8, 0) != (ssize_t)(n + 8)) _exit(130);
}
static void q_ctrl(int q, uint32_t cmd, uint32_t a, uint32_t b, uint32_t c, uint32_t d) {
    unsigned char m[20]; p32(m, cmd); p32(m + 4, a); p32(m + 8, b); p32(m + 12, c); p32(m + 16, d);
    q_send(q, LOCAL, M11_PDS_CTRL_PORT, m, sizeof m);
}
static size_t tlv(unsigned char *b, unsigned char t, const void *v, size_t n) { b[0] = t; p16(b + 1, (uint16_t)n); memcpy(b + 3, v, n); return n + 3; }
static void q_qmi(int q, unsigned char type, uint16_t txn, uint16_t id, unsigned char *b, size_t n) {
    b[0] = type; p16(b + 1, txn); p16(b + 3, id); p16(b + 5, (uint16_t)(n - 7)); q_send(q, PEER, PPORT, b, n);
}
static void q_down(int q) {
    unsigned char b[96] = {0}, s[4], t[2]; p32(s, M11_PDS_DOWN); p16(t, 0x0102);
    size_t n = 7; n += tlv(b + n, 1, s, 4); n += tlv(b + n, 2, M11_PDS_PATH, sizeof(M11_PDS_PATH) - 1); n += tlv(b + n, 3, t, 2);
    q_qmi(q, 4, 0x0101, 0x22, b, n);
    say("PEER down_sent\n");
}
static void qrtr_in(int q, enum pmode pm) {
    unsigned char m[8 + 256];
    ssize_t r = recv(q, m, sizeof m, MSG_DONTWAIT);
    if (r < 8) return;
    uint32_t port = g32(m + 4); const unsigned char *pl = m + 8; size_t n = (size_t)r - 8;
    if (port == M11_PDS_CTRL_PORT) {
        if (n == 20 && g32(pl) == 10) { /* NEW_LOOKUP: one server, then the end of the listing */
            q_ctrl(q, 4, M11_PDS_SERVICE, M11_PDS_INSTANCE, PEER, PPORT);
            q_ctrl(q, 4, 0, 0, 0, 0);
        }
        return;
    }
    if (port != PPORT || n < 7) return;
    uint16_t txn = g16(pl + 1), id = g16(pl + 3);
    unsigned char b[64] = {0}, res[4] = {0}, st[4];
    if (id == 0x20) {
        p32(st, pm == P_UP ? M11_PDS_UP : M11_PDS_DOWN);
        size_t k = 7; k += tlv(b + k, 2, res, 4); k += tlv(b + k, 16, st, 4);
        q_qmi(q, 2, txn, 0x20, b, k);
    } else if (id == 0x23) {
        size_t k = 7; k += tlv(b + k, 2, res, 4);
        q_qmi(q, 2, txn, 0x23, b, k);
    }
}
static int journal_has(const char *want) {
    static char seen[65536];
    int fd = open(p_journal, O_RDONLY | O_CLOEXEC); if (fd < 0) return 0;
    ssize_t n = read(fd, seen, sizeof seen - 1); close(fd);
    if (n < 0) return 0;
    seen[n] = 0;
    return strstr(seen, want) != NULL;
}
static int peer_pty = -1;
static int ptyfd_write(const uint8_t *b, size_t n) { return write(peer_pty, b, n) == (ssize_t)n ? 0 : -1; }
static void gpr_in(int q, uint8_t *buf, size_t *len, int down_on_map, int *got) {
    while (*len >= 4) {
        uint32_t w; memcpy(&w, buf, 4);
        size_t size = w >> 8;
        if (size < M11_GPR_HDR_BYTES || size > 512) _exit(124);
        if (*len < size) break;
        m11_gpr_hdr_t h; const uint8_t *pl; size_t pll;
        if (m11_gpr_validate_packet(buf, size, &h, &pl, &pll) < 0) _exit(125);
        (*got)++;
        char want[48]; snprintf(want, sizeof want, "op=%08x tok=%08x", h.opcode, h.token);
        if (!journal_has(want)) { say("PEER_VIOLATION\n"); _exit(110); }
        uint8_t tx[64]; size_t txl = 0; int rc = 0, answer = 1;
        if (h.opcode == M11_APM_CMD_SHARED_MEM_MAP_REGIONS) {
            if (down_on_map) { q_down(q); answer = 0; }
            else {
                m11_apm_rsp_shared_mem_map_t r = {.mem_map_handle = 0xA0000001u};
                rc = m11_gpr_pack_packet_ex(tx, sizeof tx, &txl, M11_GPR_DOMAIN_APPS, M11_GPR_DOMAIN_ADSP, 0, h.src_port,
                                            h.dst_port, h.token, M11_APM_CMDRSP_SHARED_MEM_MAP_REGIONS, &r, sizeof r);
            }
        } else {
            m11_gpr_ibasic_rsp_t r = {.cmd_opcode = h.opcode, .status = 0};
            rc = m11_gpr_pack_packet_ex(tx, sizeof tx, &txl, M11_GPR_DOMAIN_APPS, M11_GPR_DOMAIN_ADSP, 0, h.src_port,
                                        h.dst_port, h.token, M11_GPR_IBASIC_RSP_RESULT, &r, sizeof r);
        }
        if (rc < 0) _exit(127);
        if (answer && ptyfd_write(tx, txl)) _exit(128);
        char b[48]; snprintf(b, sizeof b, "PEER n=%d\n", *got); say(b);
        memmove(buf, buf + size, *len - size); *len -= size;
    }
}
static void peer(int q, int ctl, int ack, enum pmode pm) {
    alarm(30);
    prctl(PR_SET_PDEATHSIG, SIGKILL); /* ends with the case child, never before it */
    uint8_t buf[1024]; size_t len = 0; int got = 0, down_on_map = 0;
    for (;;) {
        struct pollfd p[3] = {{.fd = q, .events = POLLIN}, {.fd = ctl, .events = POLLIN}, {.fd = peer_pty, .events = POLLIN}};
        int n = poll(p, peer_pty >= 0 ? 3 : 2, -1);
        if (n < 0) { if (errno == EINTR) continue; _exit(120); }
        if (p[0].revents & POLLIN) qrtr_in(q, pm);
        if (p[1].revents & (POLLIN | POLLHUP)) {
            char c[200]; ssize_t r = read(ctl, c, sizeof c - 1);
            if (r <= 0) for (;;) pause(); /* the case is ending: stay until it is gone */
            c[r] = 0;
            if (c[0] == 'S') {
                struct termios t;
                peer_pty = open(c + 1, O_RDWR | O_NOCTTY | O_CLOEXEC);
                if (peer_pty < 0 || tcgetattr(peer_pty, &t)) _exit(121);
                cfmakeraw(&t);
                if (tcsetattr(peer_pty, TCSANOW, &t)) _exit(121);
            } else if (c[0] == 'D') q_down(q);
            else if (c[0] == 'M') down_on_map = 1;
            if (write(ack, "k", 1) != 1) _exit(122);
        }
        if (peer_pty >= 0 && (p[2].revents & (POLLIN | POLLHUP | POLLERR))) {
            ssize_t r = read(peer_pty, buf + len, sizeof buf - len);
            if (r <= 0) { close(peer_pty); peer_pty = -1; say("PEER pty_closed\n"); continue; }
            len += (size_t)r;
            gpr_in(q, buf, &len, down_on_map, &got);
        }
    }
}
static int ctl_w = -1, ack_r = -1;
static void start_peer(enum pmode pm) {
    int c[2], a[2];
    assert(socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, qs) == 0 && pipe2(c, O_CLOEXEC) == 0 && pipe2(a, O_CLOEXEC) == 0);
    pid_t p = fork(); assert(p >= 0);
    if (p == 0) { close(qs[0]); close(c[1]); close(a[0]); peer(qs[1], c[0], a[1], pm); }
    close(qs[1]); close(c[0]); close(a[1]);
    ctl_w = c[1]; ack_r = a[0];
}
static void cmd(const char *c) {
    assert(write(ctl_w, c, strlen(c)) == (ssize_t)strlen(c));
    char k; assert(read(ack_r, &k, 1) == 1 && k == 'k');
}

/* ---- terminal hooks: what the boot holds when it ends ---- */
static int is_open(int fd) { return fd >= 0 && fcntl(fd, F_GETFD) != -1; }
static void last_terminal(char *out, size_t cap) {
    static char j[65536];
    snprintf(out, cap, "none");
    int fd = open(p_journal, O_RDONLY | O_CLOEXEC); if (fd < 0) return;
    ssize_t n = read(fd, j, sizeof j - 1); close(fd);
    if (n <= 0) return;
    j[n] = 0;
    char *last = NULL;
    for (char *s = j; (s = strstr(s, "<6>M11TERMINAL")); s++) last = s;
    if (!last) return;
    size_t k = strcspn(last, "\n");
    snprintf(out, cap, "%.*s", (int)(k < cap - 1 ? k : cap - 1), last);
}
static int anchors_open(void) {
    if (E.runner.term.saved)
        return is_open(E.runner.term.saved_fd[0][0]) + is_open(E.runner.term.saved_fd[0][1]) +
               is_open(E.runner.term.saved_fd[1][0]) + is_open(E.runner.term.saved_fd[1][1]);
    int n = 0; /* never closed by the end: a bound anchor (HELD, or RETAINED by the retaining end) keeps its numbers */
    if (E.boot.endpoint.state != M11_ANCHOR_UNBOUND) n += is_open(E.boot.endpoint.anchor_fd) + is_open(E.boot.endpoint.guard_fd);
    if (E.boot.ion.state != M11_ANCHOR_UNBOUND) n += is_open(E.boot.ion.anchor_fd) + is_open(E.boot.ion.guard_fd);
    return n;
}
static void report(const char *kind) {
    char rec[600], b[1300];
    last_terminal(rec, sizeof rec);
    int n = snprintf(b, sizeof b,
        "%s phase=%d fail_step=%d fail_rc=%d hold=%u busy=%d deferred=%d acks_sent=%u regs=%u sockets=%u spawner=%d "
        "anchors_open=%d/4 ep_node=%d ion_node=%d session_rc=%d intents=%u why=%u rec=%s\n",
        kind, E.phase, E.fail_step, E.fail_rc, E.hold_rounds, E.pdmon.pds.resources_busy, E.pdmon.pds.ack_deferred,
        acks_sent, regs_sent, sockets, E.boot.spawner.pid > 0, anchors_open(), !absent(p_ep), !absent(p_ion),
        E.session_rc, E.runner.map_intents, E.runner.census_why, rec);
    if (n > 0) (void)!write(report_fd, b, (size_t)n < sizeof b ? (size_t)n : sizeof b - 1);
}
static int exit_returns;
static void t_exit(void *u) { (void)u; report("EXIT"); if (!exit_returns) _exit(42); }
static int t_reboot(void *u) { (void)u; report("REBOOT"); _exit(43); }

/* ---- the case world ---- */
static const char *PROC_OK = "Character devices:\n  1 msm_audio_ion\n  1 msm_audio_ion_cma\n  1 dma_heap\n  5 aud_pasthru_adsp\n\nBlock devices:\n  7 loop\n";
static const char *GOOD = "console=ttyMSM0 iommu.strict=1 rdinit=/init\n";
static void tree(const char *cmdline) {
    static unsigned seq;
    snprintf(root, sizeof root, "%s/t%ld-%u", base, (long)getpid(), seq++);
    assert(mkdir(root, 0700) == 0);
    put("sys/class/aud_pasthru_adsp/aud_pasthru_adsp/dev", "5:2\n");
    put("sys/dev/char/5:2/uevent", "MAJOR=5\nMINOR=2\nDEVNAME=aud_pasthru_adsp\n");
    put("sys/class/msm_audio_ion/msm_audio_ion/dev", "1:3\n");
    put("sys/dev/char/1:3/uevent", "MAJOR=1\nMINOR=3\nDEVNAME=msm_audio_ion\n");
    put("sys/class/msm_audio_ion_cma/msm_audio_ion_cma/dev", "1:5\n");
    put("sys/dev/char/1:5/uevent", "MAJOR=1\nMINOR=5\nDEVNAME=msm_audio_ion_cma\n");
    put("sys/class/dma_heap/system/dev", "1:7\n");
    put("sys/dev/char/1:7/uevent", "MAJOR=1\nMINOR=7\nDEVNAME=dma_heap/system\n");
    put("proc_devices", PROC_OK);
    put("cmdline", cmdline);
    put("journal", "");
    snprintf(p_sys, sizeof p_sys, "%s/sys", root); snprintf(p_proc, sizeof p_proc, "%s/proc_devices", root);
    snprintf(p_cmdline, sizeof p_cmdline, "%s/cmdline", root); snprintf(p_journal, sizeof p_journal, "%s/journal", root);
    snprintf(p_dev, sizeof p_dev, "%s/dev", root); assert(mkdir(p_dev, 0755) == 0 && chmod(p_dev, 0755) == 0);
    if (in_case && geteuid() == 0) { /* a pty multiplexer node opens only next to a devpts "pts" */
        char pts[460]; snprintf(pts, sizeof pts, "%s/pts", p_dev);
        assert(mkdir(pts, 0755) == 0 && mount("/dev/pts", pts, NULL, MS_BIND, NULL) == 0);
    }
    snprintf(p_ep, sizeof p_ep, "%s/dev/ep_node", root); snprintf(p_ion, sizeof p_ion, "%s/dev/ion_node", root);
    snprintf(p_cma, sizeof p_cma, "%s/dev/cma_node", root);
    snprintf(p_hdir, sizeof p_hdir, "%s/dev/heap", root); snprintf(p_hnode, sizeof p_hnode, "%s/dev/heap/system", root);
    static const char *const job[] = {"/bin/true", NULL};
    static const char *const *const jobs[] = {job};
    CFG = m11_entry_config_default();
    CFG.boot = (m11_boot_config){.sys = p_sys, .proc_devices = p_proc,
        .endpoint = {"aud_pasthru_adsp", "aud_pasthru_adsp", p_ep, 0}, .ion = {"msm_audio_ion", "msm_audio_ion", p_ion, 0},
        .ion_cma = {"msm_audio_ion_cma", "msm_audio_ion_cma", p_cma, 0},
        .heap = {.sys = p_sys, .proc_devices = p_proc, .dev_dir = p_hdir, .node = p_hnode, .require_kernel_fs = 0, .require_root = 1},
        .require_root = 1, .census_root = getpid(), .spawner_commands = jobs, .spawner_count = 1, .spawner_require_drop = geteuid() == 0};
    CFG.qrtr = &fxq; CFG.pd_ready_budget_ms = 400; CFG.cmdline_path = p_cmdline; CFG.journal_path = p_journal;
    CFG.journal_require_kmsg = 0; CFG.require_pid1 = 0; CFG.pool_count = 2; CFG.pool_len = 4096; CFG.pool_base = 200;
    CFG.sys = &fx_sys; CFG.timeout_ms = 300; CFG.recovery_budget_ms = 2000; CFG.hold_idle_ms = 50; CFG.boot_epoch = 31;
    CFG.terminal_ops = (m11_terminal_ops){.exit_fn = t_exit, .reboot_fn = t_reboot, .user = NULL, .panic_path = "/nonexistent-m11/panic"};
}

/* ---- sessions (production has none) ---- */
static void handshake(m11_entry *e) { /* after both seals: unlock the pty and hand its slave to the stand-in */
    int fd = e->runner.cfg.endpoint->anchor_fd; char slave[128], c[160];
    assert(unlockpt(fd) == 0 && ptsname_r(fd, slave, sizeof slave) == 0);
    snprintf(c, sizeof c, "S%s", slave); cmd(c);
}
static int s_map_hold(void *u, m11_entry *e) {
    (void)u; handshake(e);
    unsigned s; int rc = m11_crunner_map(&e->runner, 4096, m11_entry_now_ms(), &s);
    char b[160]; snprintf(b, sizeof b, "MAP rc=%d busy=%d intents=%u\n", rc, e->pdmon.pds.resources_busy, e->runner.map_intents); say(b);
    cmd("D"); /* the PD goes DOWN while the region is mapped; nothing pumps it before the end */
    return rc;
}
static int s_down_on_map(void *u, m11_entry *e) {
    (void)u; handshake(e); cmd("M");
    unsigned s; int rc = m11_crunner_map(&e->runner, 4096, m11_entry_now_ms(), &s);
    char b[160]; snprintf(b, sizeof b, "MAP rc=%d unresolved=%d busy=%d deferred=%d acks_sent=%u\n", rc,
                          s < M11_CUSTODIAN_REGIONS && e->runner.cust.regions[s].state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED,
                          e->pdmon.pds.resources_busy, e->pdmon.pds.ack_deferred, acks_sent); say(b);
    return rc;
}
static int s_down_unmapped(void *u, m11_entry *e) {
    (void)u; cmd("D");
    int rc = m11_crunner_idle(&e->runner, 300, m11_entry_now_ms());
    char b[160]; snprintf(b, sizeof b, "IDLE rc=%d busy=%d deferred=%d acks_sent=%u\n", rc, e->pdmon.pds.resources_busy,
                          e->pdmon.pds.ack_deferred, acks_sent); say(b);
    return rc;
}

/* ---- cases ---- */
static void entry_case(const char *cmdline, enum pmode pm, int (*session)(void *, m11_entry *)) {
    tree(cmdline); start_peer(pm);
    CFG.session_fn = session;
    int rc = m11_entry_run(&E, &CFG);
    char b[64]; snprintf(b, sizeof b, "RETURNED rc=%d\n", rc); say(b);
    _exit(0);
}
static void c_never_mapped(void) { entry_case(GOOD, P_UP, NULL); }
static void c_map_hold(void) { entry_case(GOOD, P_UP, s_map_hold); }
static void c_down_on_map(void) { entry_case(GOOD, P_UP, s_down_on_map); }
static void c_down_unmapped(void) { entry_case(GOOD, P_UP, s_down_unmapped); }
static void c_pd_never_up(void) { entry_case(GOOD, P_NEVER_UP, NULL); }
static void c_cmdline_refused(void) { entry_case("console=ttyMSM0 iommu.strict=0\n", P_UP, NULL); }
static void c_boot_refused(void) {
    tree(GOOD); start_peer(P_UP); put("dev/ep_node", "keep");
    int rc = m11_entry_run(&E, &CFG);
    char b[64]; snprintf(b, sizeof b, "RETURNED rc=%d\n", rc); say(b);
    _exit(0);
}
static void c_journal_not_kmsg(void) {
    tree(GOOD); start_peer(P_UP); CFG.journal_require_kmsg = 1;
    int rc = m11_entry_run(&E, &CFG);
    char b[64]; snprintf(b, sizeof b, "RETURNED rc=%d\n", rc); say(b);
    _exit(0);
}
/* -EPERM (not PID1) and -EINVAL touch nothing and do not use up the one call; the first real call
 * does; every later call is -EALREADY. */
static void c_calls(void) {
    tree("console=ttyMSM0 iommu.strict=0\n"); start_peer(P_UP);
    m11_entry_config pid1 = CFG; pid1.require_pid1 = 1;
    m11_entry_config bad = CFG; bad.pd_ready_budget_ms = 10001;
    int perm = m11_entry_run(&E, &pid1), inval = m11_entry_run(&E, &bad);
    exit_returns = 1;
    int first = m11_entry_run(&E, &CFG);
    const int phase = E.phase, fstep = E.fail_step;
    int second = m11_entry_run(&E, &CFG);
    char b[256]; snprintf(b, sizeof b, "CALLS perm=%d inval=%d first=%d second=%d phase=%d/%d fail_step=%d/%d\n",
                          perm, inval, first, second, phase, E.phase, fstep, E.fail_step);
    say(b); _exit(0);
}

static void stdio_off_null(void) {
    for (int fd = 0; fd < 3; fd++) {
        struct stat st;
        if (fstat(fd, &st) || !S_ISCHR(st.st_mode) || st.st_rdev != makedev(1, 3)) continue;
        int p[2]; assert(!pipe(p)); assert(dup2(fd == 0 ? p[0] : p[1], fd) == fd); close(p[0]); close(p[1]);
    }
}
static int run(void (*fn)(void), char *rep, size_t cap) {
    int p[2]; assert(pipe(p) == 0);
    fflush(stdout);
    pid_t c = fork(); assert(c >= 0);
    if (c == 0) {
        close(p[0]); report_fd = p[1]; stdio_off_null();
        if (geteuid() == 0) assert(unshare(CLONE_NEWNS) == 0 && mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == 0);
        in_case = 1;
        fn(); _exit(98);
    }
    close(p[1]);
    size_t have = 0; ssize_t n;
    while (have + 1 < cap && (n = read(p[0], rep + have, cap - 1 - have)) > 0) have += (size_t)n;
    rep[have] = 0; close(p[0]);
    int st; assert(waitpid(c, &st, 0) == c);
    if (WIFSIGNALED(st) && WTERMSIG(st) == SIGABRT) abort();
    return WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
}
static int rm_one(const char *p, const struct stat *s, int f, struct FTW *w) { (void)s; (void)f; (void)w; return remove(p); }
static unsigned hold_of(const char *rep) { const char *h = strstr(rep, " hold="); return h ? (unsigned)atoi(h + 6) : 0; }

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGPIPE, SIG_IGN);
    snprintf(base, sizeof base, "%s/m11-entry-XXXXXX", argc > 1 ? argv[1] : "/tmp");
    assert(mkdtemp(base));

    /* production defaults */
    m11_entry_config d = m11_entry_config_default();
    assert(!strcmp(d.cmdline_path, "/proc/cmdline") && !strcmp(d.journal_path, "/dev/kmsg") && d.journal_require_kmsg &&
           d.require_pid1 && d.qrtr == NULL && d.pd_ready_budget_ms == 10000 && d.session_fn == NULL && d.proc_root == NULL &&
           d.sys == NULL && d.terminal_ops.exit_fn && d.terminal_ops.reboot_fn && !strcmp(d.terminal_ops.panic_path, "/proc/sys/kernel/panic"));
    assert(!strcmp(d.boot.endpoint.node, "/dev/aud_pasthru_adsp") && !strcmp(d.boot.ion.node, "/dev/msm_audio_ion") &&
           d.boot.census_root == 0 && d.boot.require_root && d.boot.spawner_require_drop && d.boot.spawner_count == 1 &&
           d.boot.spawner_commands && !strcmp(d.boot.spawner_commands[0][2], "/m11/control"));
    printf("PASS default entry: PID1 only, /dev/kmsg (1:11) journal, /proc/cmdline, the AF_QIPCRTR monitor (10 s bring-up), the real nodes, no session (never maps), production terminal ops\n");

    char rep[4096]; int st;
    st = run(c_calls, rep, sizeof rep); printf("INFO st=%d %s", st, rep);
    assert(st == 0 && strstr(rep, "CALLS perm=-1 inval=-22 first=-14 second=-114 phase=1/1 fail_step=3/3"));
    printf("PASS entry calls: not PID1 and a bad configuration touch nothing and do not count; the first real call does, a second is refused and changes nothing\n");

    st = run(c_journal_not_kmsg, rep, sizeof rep); printf("INFO st=%d %s", st, rep);
    assert(st == 42 && strstr(rep, "EXIT phase=0 fail_step=2 fail_rc=-19 ") && strstr(rep, "sockets=0 spawner=0") && strstr(rep, "rec=none"));
    printf("PASS entry refused when the journal is not the kernel log: nothing written to it, no socket, no spawner; PID1 exit\n");

    st = run(c_cmdline_refused, rep, sizeof rep); printf("INFO st=%d %s", st, rep);
    assert(st == 42 && strstr(rep, "EXIT phase=1 fail_step=3 fail_rc=-1 ") && strstr(rep, "sockets=0 spawner=0 anchors_open=0/4 ep_node=0"));
    assert(strstr(rep, "action=START_FAILED end=pid1_exit phase=cmdline step=3 rc=-1 anchors_held=0/2 boot_stage=0"));
    printf("PASS entry refused by the effective cmdline before anything is opened: no PD socket, no spawner, no node; START_FAILED journaled, PID1 exit\n");

    st = run(c_pd_never_up, rep, sizeof rep); printf("INFO st=%d %s", st, rep);
    assert(st == 42 && strstr(rep, "EXIT phase=2 fail_step=4 fail_rc=-102 ") && strstr(rep, "regs=1 sockets=1 spawner=0 anchors_open=0/4 ep_node=0"));
    assert(strstr(rep, "action=START_FAILED end=pid1_exit phase=pd_up step=4 rc=-102 anchors_held=0/2 boot_stage=0"));
    printf("PASS entry with a PD that never comes UP (P1 session over the fixture QRTR): no spawner, no node, nothing bound; START_FAILED, PID1 exit\n");

    st = run(c_boot_refused, rep, sizeof rep); printf("INFO st=%d %s", st, rep);
    assert(st == 42 && strstr(rep, "EXIT phase=3 fail_step=3 fail_rc=-17 ") && strstr(rep, "spawner=1 anchors_open=0/4"));
    assert(strstr(rep, "action=START_FAILED end=pid1_exit phase=boot step=3 rc=-17 anchors_held=0/2 boot_stage=2"));
    printf("PASS entry with a refused boot (an endpoint node already exists): the P2 failure is journaled with its step, nothing bound or closed; PID1 exit\n");

    if (geteuid() != 0) {
        printf("SKIP root cases (mknod, anchor binds, seals, the runner): not root\n");
        (void)nftw(base, rm_one, 16, FTW_DEPTH | FTW_PHYS);
        printf("PASS production P3 PID1 entry (unprivileged sections)\n");
        return 0;
    }
    st = run(c_never_mapped, rep, sizeof rep); printf("INFO st=%d %s", st, rep);
    assert(st == 43 && strstr(rep, "REBOOT phase=7 fail_step=0 fail_rc=0 hold=0 busy=0 deferred=0 acks_sent=0 regs=1 sockets=1 spawner=1 anchors_open=0/4 ep_node=0 ion_node=0"));
    assert(strstr(rep, "action=ORDERLY_SHUTDOWN end=reboot") && !strstr(rep, "PEER n="));
    printf("PASS entry, production shape (no session): P1 UP, P2 boot (nodes made, bound, sealed, removed), runner start, close, G8 orderly end: both anchors final-closed, reboot; nothing sent\n");

    st = run(c_map_hold, rep, sizeof rep); printf("INFO st=%d %s", st, rep);
    assert(strstr(rep, "MAP rc=0 busy=1 intents=1") && strstr(rep, "PEER n=1") && strstr(rep, "PEER down_sent") && !strstr(rep, "PEER_VIOLATION"));
    assert(st == 42 && strstr(rep, "EXIT phase=7 ") && strstr(rep, "busy=1 deferred=1 acks_sent=0") && strstr(rep, "anchors_open=4/4"));
    assert(hold_of(rep) >= 1 && strstr(rep, "action=RESET_RETAINING_ANCHORS end=pid1_exit"));
    printf("PASS entry with a mapped region left: the MAP intent latched resources busy before the TX; the end holds (HOLD) waiting on the monitor until the PD DOWN, which is NOT acknowledged; then the retaining end holding every anchor\n");

    st = run(c_down_on_map, rep, sizeof rep); printf("INFO st=%d %s", st, rep);
    assert(strstr(rep, "MAP rc=-102 unresolved=1 busy=1 deferred=1 acks_sent=0") && strstr(rep, "PEER n=1"));
    assert(st == 42 && strstr(rep, "EXIT phase=7 ") && strstr(rep, "acks_sent=0") && strstr(rep, "anchors_open=4/4"));
    assert(strstr(rep, "action=RESET_RETAINING_ANCHORS end=pid1_exit"));
    printf("PASS entry with the PD DOWN during the MAP: -ENETRESET, region unresolved, the DOWN ACK deferred (never sent); retaining end\n");

    st = run(c_down_unmapped, rep, sizeof rep); printf("INFO st=%d %s", st, rep);
    assert(strstr(rep, "IDLE rc=-102 busy=0 deferred=0 acks_sent=1") && !strstr(rep, "PEER n="));
    assert(st == 42 && strstr(rep, "EXIT phase=7 ") && strstr(rep, "intents=0") && strstr(rep, "anchors_open=4/4"));
    assert(strstr(rep, "action=RESET_RETAINING_ANCHORS end=pid1_exit"));
    printf("PASS entry with the PD DOWN before any MAP: acknowledged at once (nothing mapped), retaining end (a PD DOWN loses the kernel imports)\n");

    (void)nftw(base, rm_one, 16, FTW_DEPTH | FTW_PHYS);
    printf("PASS production P3 PID1 entry (root sections)\n");
    return 0;
}
