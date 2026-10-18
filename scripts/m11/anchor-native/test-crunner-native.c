/* The composed native custodian runner core (G1-G8) under one stand-in harness.
 *  - endpoint anchor: a real adapter on /dev/ptmx (actual Linux backend); GPR packets travel over the
 *    raw pty to the forked ADSP stand-in on the slave side;
 *  - ION anchor: a real adapter on /dev/null; ION ioctls reach a fixture syscall table;
 *  - both sealed by the real owner seal; the heap is /dev/zero with a fixture DMA_HEAP_IOCTL_ALLOC
 *    (memfd buffers);
 *  - the ADSP stand-in also drives the PD monitor pipe and reads the journal pipe: it refuses any
 *    packet whose intent record is not already there.
 * Each case runs in a child; the terminal's exit/reboot hooks report what is held when the boot
 * ends. No device, driver, QRTR or reboot. */
#ifndef M11_CUSTODIAN_NATIVE
#error "test-crunner-native.c builds only with M11_CUSTODIAN_NATIVE"
#endif
#define _GNU_SOURCE
#include "custodian_runner_native.h"
#include "m11_anchor_owner.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define POOL_BASE 200
#define POOL_K 2

/* ---- fixture syscalls ---- */
static int fx_heap = -1, fx_ion = -1;
static int fx_ioctl(int fd, unsigned long req, void *arg) {
    if (req == M11_DMA_HEAP_IOCTL_ALLOC) {
        m11_dma_heap_allocation_data *d = arg;
        if (fd != fx_heap) { errno = EBADF; return -1; }
        int m = memfd_create("m11-crunner", MFD_CLOEXEC);
        if (m < 0 || ftruncate(m, (off_t)d->len)) return -1;
        d->fd = (uint32_t)m;
        return 0;
    }
    if (req == M11_DMA_BUF_IOCTL_SYNC) return 0;
    if (req == M11_MSM_AUDIO_ION_MAP_PHYS || req == M11_MSM_AUDIO_ION_UNMAP) return fd == fx_ion ? 0 : (errno = EBADF, -1);
    errno = ENOTTY; return -1;
}
static int fx_munmap(void *a, size_t l) { return munmap(a, l); }
static const m11_shmem_native_sys fx_sys = {fx_ioctl, mmap, fx_munmap, close};

/* ---- the ADSP + PD + journal stand-in on the pty slave ---- */
enum mode { ANSWER, DOWN_ON_MAP, PRE_DOWN };
static int report_fd = -1;
static void say(const char *s) { (void)!write(report_fd, s, strlen(s)); }
static void peer(const char *slave, int journal, int mon, int ready, enum mode m) {
    alarm(15);
    prctl(PR_SET_PDEATHSIG, SIGKILL); /* ends with the case child, never before it */
    int fd = open(slave, O_RDWR | O_NOCTTY);
    struct termios t;
    if (fd < 0 || tcgetattr(fd, &t)) _exit(120);
    cfmakeraw(&t);
    if (tcsetattr(fd, TCSANOW, &t)) _exit(121);
    if (m == PRE_DOWN && write(mon, "D", 1) != 1) _exit(122);
    if (write(ready, "R", 1) != 1) _exit(123);
    close(ready);
    say("PEER n=0 ok\n");
    static char seen[16384]; size_t have = 0;
    int got = 0;
    uint8_t buf[512]; size_t len = 0;
    for (;;) {
        ssize_t n = read(fd, buf + len, sizeof buf - len);
        if (n <= 0) {
            /* The endpoint anchor was final-closed (or the child ended). Stay alive until the child
             * dies: an exiting child of PID1 scans as inconclusive and would refuse the next anchor's
             * census (a real constraint: PID1 enters its terminal with no exiting children). */
            char b[64]; snprintf(b, sizeof b, "PEER n=%d ok\n", got); say(b);
            for (;;) pause();
        }
        len += (size_t)n;
        while (len >= 4) {
            uint32_t w; memcpy(&w, buf, 4);
            size_t size = w >> 8;
            if (size < M11_GPR_HDR_BYTES || size > sizeof buf) _exit(124);
            if (len < size) break;
            m11_gpr_hdr_t h; const uint8_t *pl; size_t pll;
            if (m11_gpr_validate_packet(buf, size, &h, &pl, &pll) < 0) _exit(125);
            got++;
            for (;;) { ssize_t r = read(journal, seen + have, sizeof seen - 1 - have); if (r <= 0) break; have += (size_t)r; }
            seen[have] = 0;
            char want[48]; snprintf(want, sizeof want, "op=%08x tok=%08x", h.opcode, h.token);
            if (!strstr(seen, want)) { say("PEER_VIOLATION\n"); _exit(110); }
            uint8_t tx[64]; size_t txl = 0; int rc = 0, answer = 1;
            if (h.opcode == M11_APM_CMD_SHARED_MEM_MAP_REGIONS) {
                if (m == DOWN_ON_MAP) { if (write(mon, "D", 1) != 1) _exit(126); answer = 0; }
                else {
                    if (write(mon, "U", 1) != 1) _exit(126);
                    m11_apm_rsp_shared_mem_map_t r = {.mem_map_handle = 0xA0000001u};
                    rc = m11_gpr_pack_packet_ex(tx, sizeof tx, &txl, M11_GPR_DOMAIN_APPS, M11_GPR_DOMAIN_ADSP, 0, h.src_port,
                                                h.dst_port, h.token, M11_APM_CMDRSP_SHARED_MEM_MAP_REGIONS, &r, sizeof r);
                }
            } else {
                if (write(mon, "U", 1) != 1) _exit(126);
                m11_gpr_ibasic_rsp_t r = {.cmd_opcode = h.opcode, .status = 0};
                rc = m11_gpr_pack_packet_ex(tx, sizeof tx, &txl, M11_GPR_DOMAIN_APPS, M11_GPR_DOMAIN_ADSP, 0, h.src_port,
                                            h.dst_port, h.token, M11_GPR_IBASIC_RSP_RESULT, &r, sizeof r);
            }
            if (rc < 0) _exit(127);
            if (answer) (void)!write(fd, tx, txl);
            { char b[64]; snprintf(b, sizeof b, "PEER n=%d ok\n", got); say(b); } /* running count */
            memmove(buf, buf + size, len - size); len -= size;
        }
    }
}

/* ---- PD monitor (any 'D' or EOF is not UP) and the tee journal sink ---- */
static int pump(void *user, uint64_t now) {
    (void)now;
    int fd = *(int *)user;
    for (;;) {
        char b[16]; ssize_t n = read(fd, b, sizeof b);
        if (n < 0) return errno == EAGAIN ? 1 : 0;
        if (n == 0) return 0;
        if (memchr(b, 'D', (size_t)n)) return 0;
    }
}
static m11_intent_fd_sink jfd; static m11_intent_sink jfd_sink;
static int sink_fail; static unsigned nrec; static int saw_map, saw_unmap, saw_terminal;
static int tee_append(void *u, const char *rec, size_t len) {
    (void)u;
    if (sink_fail) return -EIO;
    int rc = jfd_sink.append_fn(jfd_sink.user, rec, len);
    if (!rc) {
        nrec++;
        if (strstr(rec, " op=0100100c ")) saw_map = 1;
        if (strstr(rec, " op=0100100d ")) saw_unmap = 1;
        if (!strncmp(rec, "<6>M11TERMINAL", 14)) saw_terminal = 1;
    }
    return rc;
}
static const m11_intent_sink jsink = {tee_append, NULL};

/* ---- the case world ---- */
static const m11_anchor_contract evidence = {.endpoint_has_no_flush = true,
    .release_on_last_fput_only = true, .owner_single_threaded = true};
static m11_anchor_linux le, li;
static m11_pid1_anchor ep, io;
static m11_crunner R; static m11_crunner_config C; static m11_pd_monitor mon;
static int mon_fd = -1, ep_a, ep_g, io_a, io_g, region_fd = -1;

static int is_open(int fd) { return fd >= 0 && fcntl(fd, F_GETFD) != -1; }
static uint64_t ms(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000u + (uint64_t)t.tv_nsec / 1000000u;
}
static void report(const char *what) {
    char b[900];
    int anchors = is_open(ep_a) + is_open(ep_g) + is_open(io_a) + is_open(io_g), pool = 0;
    for (int f = POOL_BASE; f < POOL_BASE + 2 * POOL_K; f++) pool += is_open(f);
    int rp = region_fd >= POOL_BASE && region_fd < POOL_BASE + 2 * POOL_K && (region_fd - POOL_BASE) % 2 == 0;
    int n = snprintf(b, sizeof b, "%s anchors=%d/4 pool=%d/%d region_in_pool=%d records=%u map=%d unmap=%d terminal=%d rec=%s\n",
                     what, anchors, pool, 2 * POOL_K, rp, nrec, saw_map, saw_unmap, saw_terminal, R.term.record);
    if (n > 0) (void)!write(report_fd, b, (size_t)n < sizeof b ? (size_t)n : sizeof b - 1);
}
static void t_exit(void *u) { (void)u; report("EXIT"); _exit(42); }
static int t_reboot(void *u) { (void)u; report("REBOOT"); _exit(43); }

static void stdio_off_null(void) {
    for (int fd = 0; fd < 3; fd++) {
        struct stat st;
        if (fstat(fd, &st) || !S_ISCHR(st.st_mode) || st.st_rdev != makedev(1, 3)) continue;
        int p[2]; assert(!pipe(p)); assert(dup2(fd == 0 ? p[0] : p[1], fd) == fd); close(p[0]); close(p[1]);
    }
}
/* returns start's rc; *step the failing step */
static int world(enum mode m, const char *cmdline, int *step) {
    stdio_off_null();
    int jp[2], mp[2], rp[2];
    assert(pipe2(jp, O_CLOEXEC) == 0 && pipe2(mp, O_CLOEXEC) == 0 && pipe2(rp, O_CLOEXEC) == 0);
    m11_anchor_ops oe, oi; struct stat se, si;
    assert(!stat("/dev/ptmx", &se) && !stat("/dev/null", &si));
    assert(!m11_anchor_linux_ops(&le, "/dev/ptmx", getpid(), &oe) && !m11_anchor_linux_ops(&li, "/dev/null", getpid(), &oi));
    assert(!m11_anchor_bind(&ep, &oe, NULL, &evidence, getpid(), (uint64_t)se.st_rdev));
    assert(!m11_anchor_bind(&io, &oi, NULL, &evidence, getpid(), (uint64_t)si.st_rdev));
    ep_a = ep.anchor_fd; ep_g = ep.guard_fd; io_a = io.anchor_fd; io_g = io.guard_fd;
    char slave[128];
    assert(grantpt(ep.anchor_fd) == 0 && unlockpt(ep.anchor_fd) == 0 && ptsname_r(ep.anchor_fd, slave, sizeof slave) == 0);
    pid_t p = fork(); assert(p >= 0);
    if (p == 0) { /* the stand-in never keeps an anchor reference */
        close(ep_a); close(ep_g); close(io_a); close(io_g);
        close(jp[1]); close(mp[0]); close(rp[0]);
        if (fcntl(jp[0], F_SETFL, O_NONBLOCK)) _exit(119);
        peer(slave, jp[0], mp[1], rp[1], m);
    }
    close(jp[0]); close(mp[1]); close(rp[1]);
    char c; assert(read(rp[0], &c, 1) == 1 && c == 'R'); close(rp[0]);
    m11_pid1_anchor *both[2] = {&ep, &io};
    assert(m11_anchor_owner_seal_pairs(both, NULL, 2) == 0);
    fx_ion = io.anchor_fd;
    struct stat zs; assert(stat("/dev/zero", &zs) == 0);
    fx_heap = open("/dev/zero", O_RDONLY | O_CLOEXEC); assert(fx_heap >= 0);
    assert(m11_intent_sink_fd(&jfd, jp[1], &jfd_sink) == 0);
    mon_fd = mp[0]; assert(fcntl(mon_fd, F_SETFL, O_NONBLOCK) == 0);
    mon = (m11_pd_monitor){.fd = mon_fd, .pump_fn = pump, .user = &mon_fd};
    C = (m11_crunner_config){.endpoint = &ep, .ion = &io, .heap_fd = fx_heap, .heap_rdev = zs.st_rdev,
        .pool_count = POOL_K, .pool_len = 4096, .pool_base = POOL_BASE, .sys = &fx_sys, .pd = &mon, .journal = &jsink,
        .terminal_ops = {.exit_fn = t_exit, .reboot_fn = t_reboot, .user = NULL, .panic_path = "/nonexistent-m11/panic"},
        .cmdline = cmdline, .boot_epoch = 11, .timeout_ms = 300, .recovery_budget_ms = 2000, .src_port = 0x0100u};
    return m11_crunner_start(&R, &C, ms(), step);
}
static const char *GOOD = "console=ttyMSM0 iommu.strict=1 rdinit=/init";

static void c_happy(void) {
    int step; int rc = world(ANSWER, GOOD, &step);
    char b[96]; snprintf(b, sizeof b, "START rc=%d step=%d heap_open=%d\n", rc, step, is_open(fx_heap)); say(b);
    assert(rc == 0 && step == 0);
    unsigned s; assert(m11_crunner_map(&R, 4096, ms(), &s) == 0);
    region_fd = R.cust.regions[s].dma_buf_fd;
    assert(m11_crunner_idle(&R, 50, ms()) == 0);
    assert(m11_crunner_retire(&R, s, ms()) == 0 && m11_crunner_close(&R) == 0);
    (void)m11_crunner_end(&R, ms());
    _exit(99);
}
static void c_never_mapped(void) {
    int step; assert(world(ANSWER, GOOD, &step) == 0);
    assert(m11_crunner_close(&R) == 0);
    (void)m11_crunner_end(&R, ms());
    _exit(99);
}
static void c_down_on_map(void) {
    int step; assert(world(DOWN_ON_MAP, GOOD, &step) == 0);
    unsigned s; int rc = m11_crunner_map(&R, 4096, ms(), &s);
    region_fd = R.cust.regions[s].dma_buf_fd;
    char b[160];
    snprintf(b, sizeof b, "MAP rc=%d unresolved=%d imports_lost=%d\n", rc,
             R.cust.regions[s].state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED, R.cust.kernel_imports_lost);
    say(b);
    (void)m11_crunner_end(&R, ms());
    _exit(99);
}
static void c_foreign_holder(void) {
    int step; assert(world(ANSWER, GOOD, &step) == 0);
    int go[2]; assert(pipe(go) == 0);
    pid_t f = fork(); assert(f >= 0);
    if (f == 0) { /* a post-seal fork: holds every inherited anchor and pool fd */
        prctl(PR_SET_PDEATHSIG, SIGKILL); close(report_fd); close(go[0]);
        (void)!write(go[1], "f", 1); for (;;) pause();
    }
    close(go[1]); char c; assert(read(go[0], &c, 1) == 1);
    unsigned s; int rc = m11_crunner_map(&R, 4096, ms(), &s);
    char b[96]; snprintf(b, sizeof b, "MAP rc=%d census_failed=%d\n", rc, R.census_failed); say(b);
    (void)m11_crunner_close(&R);
    (void)m11_crunner_end(&R, ms());
    _exit(99);
}
static void c_cmdline_refused(void) {
    int step; int rc = world(ANSWER, "console=ttyMSM0 iommu.strict=0", &step);
    char b[128]; snprintf(b, sizeof b, "START rc=%d step=%d heap_open=%d pool_fd=%d\n", rc, step, is_open(fx_heap), is_open(POOL_BASE));
    say(b); _exit(0);
}
static void c_pd_down_at_start(void) {
    int step; int rc = world(PRE_DOWN, GOOD, &step);
    char b[128]; snprintf(b, sizeof b, "START rc=%d step=%d heap_open=%d pool_fd=%d\n", rc, step, is_open(fx_heap), is_open(POOL_BASE));
    say(b); _exit(0);
}
static void c_sink_fails(void) {
    int step; assert(world(ANSWER, GOOD, &step) == 0);
    sink_fail = 1;
    unsigned s; int rc = m11_crunner_map(&R, 4096, ms(), &s);
    int ret = m11_crunner_end(&R, ms());
    char b[160]; snprintf(b, sizeof b, "MAP rc=%d unresolved=%d END=%d records=%u\n", rc,
                          R.cust.regions[s].state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED, ret, nrec);
    say(b); _exit(0);
}

static int peer_count(const char *rep) {
    int best = -1;
    for (const char *p = rep; (p = strstr(p, "PEER n=")); p += 7) { int n = atoi(p + 7); if (n > best) best = n; }
    return best;
}
static int run(void (*fn)(void), char *rep, size_t cap) {
    int p[2]; assert(pipe(p) == 0);
    fflush(stdout);
    pid_t c = fork(); assert(c >= 0);
    if (c == 0) { close(p[0]); report_fd = p[1]; fn(); _exit(98); }
    close(p[1]);
    size_t have = 0; ssize_t n;
    while (have + 1 < cap && (n = read(p[0], rep + have, cap - 1 - have)) > 0) have += (size_t)n;
    rep[have] = 0; close(p[0]);
    int st; assert(waitpid(c, &st, 0) == c);
    if (WIFSIGNALED(st) && WTERMSIG(st) == SIGABRT) abort();
    return WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGPIPE, SIG_IGN);
    char rep[4096]; int st;

    st = run(c_happy, rep, sizeof rep);
    printf("INFO %s", rep);
    assert(strstr(rep, "START rc=0 step=0 heap_open=0"));
    assert(st == 42 && strstr(rep, "EXIT anchors=4/4 pool=4/4 region_in_pool=1 records=3 map=1 unmap=1 terminal=1"));
    assert(strstr(rep, "action=RESET_RETAINING_ANCHORS end=pid1_exit anchors_held=2/2 anchor_fds_open=4/4 pool=held"));
    assert(peer_count(rep) == 2 && !strstr(rep, "PEER_VIOLATION"));
    printf("PASS composed boot: start (gate, PD up, pool from the heap, heap closed, seals, journal, census), MAP of a pool buffer, idle, UNMAP, close, PID1 exit holding every anchor and pool fd; each packet's record preceded it\n");

    st = run(c_never_mapped, rep, sizeof rep);
    printf("INFO %s", rep);
    assert(st == 43 && strstr(rep, "REBOOT anchors=0/4 pool=4/4") && strstr(rep, "action=ORDERLY_SHUTDOWN end=reboot"));
    assert(peer_count(rep) == 0);
    printf("PASS composed never-mapped boot: both anchors final-closed, terminal journaled, reboot; nothing sent\n");

    st = run(c_down_on_map, rep, sizeof rep);
    printf("INFO %s", rep);
    assert(strstr(rep, "MAP rc=-102 unresolved=1 imports_lost=1"));
    assert(st == 42 && strstr(rep, "EXIT anchors=4/4 pool=4/4 region_in_pool=1") && strstr(rep, "regions=1 in_pool=1 note=mapped_boot"));
    assert(peer_count(rep) == 1);
    printf("PASS composed PD DOWN during MAP: -ENETRESET, region unresolved, custodian told at once, PID1 exit holding everything\n");

    st = run(c_foreign_holder, rep, sizeof rep);
    printf("INFO %s", rep);
    assert(strstr(rep, "MAP rc=-130 census_failed=1") && peer_count(rep) == 0);
    assert(st == 42 && strstr(rep, "EXIT anchors=4/4") && strstr(rep, "note=anchor_not_held"));
    printf("PASS composed census: a foreign holder (post-seal fork) refuses the MAP before any TX and keeps every anchor at the end\n");

    st = run(c_cmdline_refused, rep, sizeof rep);
    printf("INFO %s", rep);
    assert(st == 0 && strstr(rep, "START rc=-1 step=1 heap_open=1 pool_fd=0") && peer_count(rep) == 0);
    printf("PASS composed start refused by the effective cmdline (iommu.strict=0): no pool, heap untouched, nothing sent\n");

    st = run(c_pd_down_at_start, rep, sizeof rep);
    printf("INFO %s", rep);
    assert(st == 0 && strstr(rep, "START rc=-102 step=2 heap_open=1 pool_fd=0") && peer_count(rep) == 0);
    printf("PASS composed start refused while the PD is not UP: no pool, nothing sent\n");

    st = run(c_sink_fails, rep, sizeof rep);
    printf("INFO %s", rep);
    assert(st == 0 && strstr(rep, "unresolved=1 END=-16 records=0") && peer_count(rep) == 0);
    printf("PASS composed journal failure: no TX, region unresolved, the end is held (HOLD_RECONCILE)\n");

    printf("PASS composed native custodian runner core (G1-G8 together over stand-ins)\n");
    return 0;
}
