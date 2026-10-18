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
#include <sys/syscall.h>
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
static int fx_fail_heap_close;
static int fx_close(int fd) { /* close(2) that reports EIO for the heap fd (released anyway, like Linux) */
    int rc = close(fd);
    if (fx_fail_heap_close && fd == fx_heap) { errno = EIO; return -1; }
    return rc;
}
static const m11_shmem_native_sys fx_sys = {fx_ioctl, mmap, fx_munmap, fx_close};

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
static int pump_up_once, pump_calls;
static int pump(void *user, uint64_t now) {
    (void)now;
    int fd = *(int *)user;
    if (pump_up_once && pump_calls++ >= 1) return 0; /* UP for the start's check, DOWN afterwards */
    for (;;) {
        char b[16]; ssize_t n = read(fd, b, sizeof b);
        if (n < 0) return errno == EAGAIN ? 1 : 0;
        if (n == 0) return 0;
        if (memchr(b, 'D', (size_t)n)) return 0;
    }
}
static m11_intent_fd_sink jfd; static m11_intent_sink jfd_sink;
static int sink_fail; static unsigned nrec; static int saw_map, saw_unmap, saw_terminal;
static char last_rec[400];
static int tee_append(void *u, const char *rec, size_t len) {
    (void)u;
    if (sink_fail) return -EIO;
    int rc = jfd_sink.append_fn(jfd_sink.user, rec, len);
    if (!rc) {
        nrec++;
        if (len < sizeof last_rec) { memcpy(last_rec, rec, len); last_rec[len] = 0; }
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
    int n = snprintf(b, sizeof b, "%s anchors=%d/4 pool=%d/%d region_in_pool=%d records=%u map=%d unmap=%d terminal=%d why=%u rec=%s\n",
                     what, anchors, pool, 2 * POOL_K, rp, nrec, saw_map, saw_unmap, saw_terminal, R.census_why,
                     R.term.record[0] ? R.term.record : last_rec);
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
static unsigned cfg_pool_count = POOL_K;
static const char *cfg_proc_root; /* NULL: the real /proc */
static int cfg_no_intent; static unsigned intents; /* the MAP-intent hook (P3 wires the PD session's busy latch) */
static void count_intent(void *u) { assert(u == &intents); intents++; }
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
        .pool_count = cfg_pool_count, .pool_len = 4096, .pool_base = POOL_BASE, .sys = &fx_sys, .pd = &mon, .journal = &jsink,
        .terminal_ops = {.exit_fn = t_exit, .reboot_fn = t_reboot, .user = NULL, .panic_path = "/nonexistent-m11/panic"},
        .cmdline = cmdline, .boot_epoch = 11, .timeout_ms = 300, .recovery_budget_ms = 2000, .src_port = 0x0100u,
        .proc_root = cfg_proc_root, .map_intent_fn = cfg_no_intent ? NULL : count_intent, .map_intent_user = &intents};
    return m11_crunner_start(&R, &C, ms(), step);
}
static const char *GOOD = "console=ttyMSM0 iommu.strict=1 rdinit=/init";

static void c_happy(void) {
    int step; int rc = world(ANSWER, GOOD, &step);
    char b[96]; snprintf(b, sizeof b, "START rc=%d step=%d heap_open=%d\n", rc, step, is_open(fx_heap)); say(b);
    assert(rc == 0 && step == 0);
    unsigned s; assert(m11_crunner_map(&R, 4096, ms(), &s) == 0);
    assert(intents == 1 && R.map_intents == 1); /* the intent hook ran once, before the MAP */
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
/* A post-seal fork of PID1. drop_anchors: it gives up both anchor pairs with the one close each seal
 * permits, close_range(anchor, guard, 0), and so holds only the pool buffers it cannot close. */
static void foreign(int drop_anchors) {
    int go[2]; assert(pipe(go) == 0);
    pid_t f = fork(); assert(f >= 0);
    if (f == 0) {
        /* PID1's seal made it non-dumpable; an unprivileged harness could not read this child's fds
         * and the census would fail as inconclusive. Readable, it must fail for what it holds. */
        prctl(PR_SET_PDEATHSIG, SIGKILL); prctl(PR_SET_DUMPABLE, 1, 0, 0, 0); close(report_fd); close(go[0]);
        int ok = 1;
        if (drop_anchors)
            ok = syscall(SYS_close_range, (unsigned)ep_a, (unsigned)ep_g, 0u) == 0 &&
                 syscall(SYS_close_range, (unsigned)io_a, (unsigned)io_g, 0u) == 0 && is_open(POOL_BASE);
        (void)!write(go[1], ok ? "y" : "n", 1); for (;;) pause();
    }
    close(go[1]); char c; assert(read(go[0], &c, 1) == 1 && c == 'y'); close(go[0]);
}
static void c_foreign_holder(void) {
    int step; assert(world(ANSWER, GOOD, &step) == 0);
    foreign(0);
    int crc = m11_crunner_close(&R);
    unsigned s; int mrc = m11_crunner_map(&R, 4096, ms(), &s);
    char b[160]; snprintf(b, sizeof b, "CLOSE rc=%d closed=%d census_failed=%d imports_lost=%d MAP rc=%d why=%u\n",
                          crc, R.cust.closed, R.census_failed, R.cust.kernel_imports_lost, mrc, R.census_why); say(b);
    (void)m11_crunner_end(&R, ms());
    _exit(99);
}
static void c_pool_only_holder(void) {
    int step; assert(world(ANSWER, GOOD, &step) == 0);
    foreign(1);
    unsigned s; int rc = m11_crunner_map(&R, 4096, ms(), &s);
    char b[160]; snprintf(b, sizeof b, "MAP rc=%d census_failed=%d imports_lost=%d anchor_check=%d why=%u\n", rc, R.census_failed,
                          R.cust.kernel_imports_lost, m11_anchor_check(&ep) == 0 && m11_anchor_check(&io) == 0, R.census_why); say(b);
    (void)m11_crunner_end(&R, ms());
    _exit(99);
}
static void c_idle_census(void) {
    int step; assert(world(ANSWER, GOOD, &step) == 0);
    foreign(0);
    int rc = m11_crunner_idle(&R, 20, ms());
    char b[128]; snprintf(b, sizeof b, "IDLE rc=%d census_failed=%d imports_lost=%d why=%u\n", rc, R.census_failed, R.cust.kernel_imports_lost, R.census_why); say(b);
    (void)m11_crunner_end(&R, ms());
    _exit(99);
}
static void c_end_census(void) {
    int step; assert(world(ANSWER, GOOD, &step) == 0);
    assert(m11_crunner_close(&R) == 0);
    foreign(0); /* appears after a clean close, before the end */
    (void)m11_crunner_end(&R, ms());
    _exit(99);
}
static void partial(enum mode m, const char *cmdline) {
    int step; int rc = world(m, cmdline, &step);
    char b[160]; snprintf(b, sizeof b, "START rc=%d step=%d started=%d heap_open=%d heapfd=%d pool_fd=%d\n", rc, step,
                          R.started, is_open(fx_heap), R.cfg.heap_fd, is_open(POOL_BASE));
    say(b);
    (void)m11_crunner_end(&R, ms());
    say("END returned\n");
    _exit(0);
}
static void c_cmdline_refused(void) { partial(ANSWER, "console=ttyMSM0 iommu.strict=0"); }
static void c_pd_down_at_start(void) { partial(PRE_DOWN, GOOD); }
static void c_build_fails(void) { cfg_pool_count = 0; partial(ANSWER, GOOD); }
static void c_heap_close_fails(void) { fx_fail_heap_close = 1; partial(ANSWER, GOOD); }
static void c_step4_fails(void) { pump_up_once = 1; partial(ANSWER, GOOD); }
/* A clean, never-mapped boot whose census fails only through a descendant holding pool buffers: the
 * custodian alone would choose the orderly reboot (anchors pass their checks). */
static void c_pool_holder_after_close(void) {
    int step; assert(world(ANSWER, GOOD, &step) == 0);
    assert(m11_crunner_close(&R) == 0);
    foreign(1);
    (void)m11_crunner_end(&R, ms());
    _exit(99);
}
/* A fake proc tree for the tree census: one readable unrelated process, plus (unreadable) a process
 * that exists but whose stat cannot be read, or (gone) an entry whose directory no longer exists. */
static char fake_proc[64];
static void make_fake_proc(int unreadable) {
    snprintf(fake_proc, sizeof fake_proc, "/tmp/m11-proc-XXXXXX");
    assert(mkdtemp(fake_proc));
    char p[160];
    snprintf(p, sizeof p, "%s/1", fake_proc); assert(mkdir(p, 0755) == 0);
    snprintf(p, sizeof p, "%s/1/stat", fake_proc);
    FILE *f = fopen(p, "w"); assert(f && fputs("1 (init) S 0 1 1 0 -1\n", f) >= 0 && fclose(f) == 0);
    if (unreadable) {
        snprintf(p, sizeof p, "%s/4242", fake_proc); assert(mkdir(p, 0755) == 0);
        snprintf(p, sizeof p, "%s/4242/stat", fake_proc);
        f = fopen(p, "w"); assert(f && fputs("4242 (x) S 1 1 1 0 -1\n", f) >= 0 && fclose(f) == 0);
        assert(chmod(p, 0) == 0);
    } else {
        char t[160]; snprintf(t, sizeof t, "%s/no-such-dir", fake_proc);
        snprintf(p, sizeof p, "%s/4243", fake_proc); assert(symlink(t, p) == 0);
    }
    cfg_proc_root = fake_proc;
}
static void c_proc_unreadable(void) {
    make_fake_proc(1);
    int step; int rc = world(ANSWER, GOOD, &step);
    char b[128]; snprintf(b, sizeof b, "START rc=%d step=%d started=%d why=%u\n", rc, step, R.started, R.census_why); say(b);
    (void)m11_crunner_end(&R, ms());
    _exit(99);
}
static void c_proc_gone(void) {
    make_fake_proc(0);
    int step; int rc = world(ANSWER, GOOD, &step);
    char b[128]; snprintf(b, sizeof b, "START rc=%d step=%d started=%d why=%u\n", rc, step, R.started, R.census_why); say(b);
    _exit(0);
}
static void c_second_start(void) {
    int step; assert(world(ANSWER, GOOD, &step) == 0);
    int rc = m11_crunner_start(&R, &C, ms(), &step);
    char b[128]; snprintf(b, sizeof b, "SECOND rc=%d pool_count=%u started=%d stage=%d\n", rc, R.pool.count, R.started, R.stage);
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

/* No MAP-intent hook: every MAP is refused before the census, the import or any TX. */
static void c_no_intent(void) {
    cfg_no_intent = 1;
    int step; assert(world(ANSWER, GOOD, &step) == 0);
    unsigned s; int rc = m11_crunner_map(&R, 4096, ms(), &s);
    char b[160]; snprintf(b, sizeof b, "MAP rc=%d slot=%d intents=%u attempted=%d\n", rc, (int)s, R.map_intents,
                          (int)R.boot.dsp_map_attempted); say(b);
    assert(m11_crunner_close(&R) == 0);
    (void)m11_crunner_end(&R, ms());
    _exit(99);
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
    assert(strstr(rep, "CLOSE rc=-130 closed=0 census_failed=1 imports_lost=0 MAP rc=-130 why=19") && peer_count(rep) == 0);
    assert(st == 42 && strstr(rep, "EXIT anchors=4/4") && strstr(rep, "action=HOLD end=pid1_exit") && strstr(rep, "note=foreign_holder_why=19"));
    printf("PASS composed census on close: a foreign holder refuses the close (custodian stays open, ledger untainted) and the MAP; the end is forced retaining\n");

    st = run(c_pool_only_holder, rep, sizeof rep);
    printf("INFO %s", rep);
    assert(strstr(rep, "MAP rc=-130 census_failed=1 imports_lost=0 anchor_check=1 why=16") && peer_count(rep) == 0);
    assert(st == 42 && strstr(rep, "EXIT anchors=4/4 pool=4/4") && strstr(rep, "note=foreign_holder_why=16"));
    printf("PASS composed tree census: a descendant holding only pool buffers (anchors dropped) fails the census before any TX\n");

    st = run(c_idle_census, rep, sizeof rep);
    printf("INFO %s", rep);
    assert(strstr(rep, "IDLE rc=-130 census_failed=1 imports_lost=0 why=19") && st == 42 && strstr(rep, "note=foreign_holder_why=19"));
    printf("PASS composed census after idle: a foreign holder found while idle forces the retaining end\n");

    st = run(c_end_census, rep, sizeof rep);
    printf("INFO %s", rep);
    assert(st == 42 && strstr(rep, "EXIT anchors=4/4") && strstr(rep, "why=19") && strstr(rep, "action=ORDERLY_SHUTDOWN end=pid1_exit") && strstr(rep, "note=foreign_holder_why=19"));
    printf("PASS composed census in end: a foreign holder after a clean close turns the orderly end into the retaining one\n");

    st = run(c_pool_holder_after_close, rep, sizeof rep);
    printf("INFO %s", rep);
    assert(st == 42 && strstr(rep, "EXIT anchors=4/4 pool=4/4") && strstr(rep, "action=ORDERLY_SHUTDOWN end=pid1_exit") && strstr(rep, "note=foreign_holder_why=16"));
    printf("PASS composed census in end: a descendant holding only pool buffers after a clean close prevents the orderly reboot the custodian alone would choose\n");

    st = run(c_cmdline_refused, rep, sizeof rep);
    printf("INFO %s", rep);
    assert(strstr(rep, "START rc=-1 step=1 started=0 heap_open=1") && peer_count(rep) == 0 && !strstr(rep, "END returned"));
    assert(st == 42 && strstr(rep, "EXIT anchors=4/4 pool=0/4") && strstr(rep, "action=START_FAILED end=pid1_exit step=1") && strstr(rep, "pool=none heap_open=1"));
    printf("PASS composed start refused by the effective cmdline: no pool, heap untouched, nothing sent; the end is START_FAILED step=1, PID1 exit\n");

    st = run(c_pd_down_at_start, rep, sizeof rep);
    printf("INFO %s", rep);
    assert(strstr(rep, "START rc=-102 step=2 started=0") && st == 42 && strstr(rep, "action=START_FAILED end=pid1_exit step=2"));
    printf("PASS composed start refused while the PD is not UP: START_FAILED step=2, PID1 exit\n");

    st = run(c_build_fails, rep, sizeof rep);
    printf("INFO %s", rep);
    assert(strstr(rep, "START rc=-22 step=3 started=0 heap_open=1") && st == 42 && strstr(rep, "step=3 anchor_fds_open=4/4 pool=none heap_open=1"));
    printf("PASS composed pool build failure: START_FAILED step=3 with the heap fd untouched\n");

    st = run(c_heap_close_fails, rep, sizeof rep);
    printf("INFO %s", rep);
    assert(strstr(rep, "START rc=-5 step=3 started=0 heap_open=0 heapfd=-1 pool_fd=1"));
    assert(st == 42 && strstr(rep, "EXIT anchors=4/4 pool=4/4") && strstr(rep, "step=3 anchor_fds_open=4/4 pool=held heap_open=0"));
    printf("PASS composed heap close error: the fd is treated as released (never reused), START_FAILED step=3 holding the pool\n");

    st = run(c_step4_fails, rep, sizeof rep);
    printf("INFO %s", rep);
    assert(strstr(rep, "START rc=-102 step=4 started=0 heap_open=0") && peer_count(rep) == 0);
    assert(st == 42 && strstr(rep, "EXIT anchors=4/4 pool=4/4") && strstr(rep, "action=START_FAILED end=pid1_exit step=4 anchor_fds_open=4/4 pool=held"));
    printf("PASS composed start failing after the sealed pool (engine open at PD DOWN): START_FAILED step=4, PID1 exit holding anchors and pool\n");

    if (geteuid() != 0) { /* root reads a mode-0 file: the unreadable case needs an unprivileged harness */
        st = run(c_proc_unreadable, rep, sizeof rep);
        printf("INFO %s", rep);
        assert(strstr(rep, "START rc=-130 step=6 started=1 why=16") && st == 42 && strstr(rep, "note=foreign_holder_why=16"));
        printf("PASS composed tree census: a process that exists but whose /proc stat cannot be read fails the census (fail closed)\n");
    } else printf("SKIP unreadable /proc entry case: running as root\n");

    st = run(c_proc_gone, rep, sizeof rep);
    printf("INFO %s", rep);
    assert(st == 0 && strstr(rep, "START rc=0 step=0 started=1 why=0"));
    printf("PASS composed tree census: a process gone between readdir and read is not counted\n");

    st = run(c_second_start, rep, sizeof rep);
    printf("INFO %s", rep);
    assert(st == 0 && strstr(rep, "SECOND rc=-114 pool_count=2 started=1 stage=6"));
    printf("PASS composed start is one-shot: a second start is refused and leaves the running state intact\n");

    st = run(c_sink_fails, rep, sizeof rep);
    printf("INFO %s", rep);
    assert(st == 0 && strstr(rep, "unresolved=1 END=-16 records=0") && peer_count(rep) == 0);
    printf("PASS composed journal failure: no TX, region unresolved, the end is held (HOLD_RECONCILE)\n");

    st = run(c_no_intent, rep, sizeof rep);
    printf("INFO %s", rep);
    assert(strstr(rep, "MAP rc=-1 slot=-1 intents=0 attempted=0") && peer_count(rep) == 0);
    assert(st == 43 && strstr(rep, "action=ORDERLY_SHUTDOWN end=reboot"));
    printf("PASS composed MAP without the MAP-intent hook: refused before any import or TX; the boot stays never-mapped\n");

    printf("PASS composed native custodian runner core (G1-G8 together over stand-ins)\n");
    return 0;
}
