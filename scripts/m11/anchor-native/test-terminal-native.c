/* G8 stand-in test: the native end of a custodian boot. Each case runs in a child that binds two
 * real anchor adapters on stand-ins (/dev/ptmx endpoint, /dev/null ION; actual Linux backend), seals
 * them with the real owner seal, and drives the REAL custodian, manager and engine (G2 transport to a
 * forked ADSP stand-in, G3 backend over fixture syscalls with the real ION anchor). The test's
 * exit_fn / reboot_fn report, at the moment the boot ends, which fds are still open and the terminal
 * record. No device, driver or reboot. */
#ifndef M11_CUSTODIAN_NATIVE
#error "test-terminal-native.c builds only with M11_CUSTODIAN_NATIVE"
#endif
#define _GNU_SOURCE
#include "terminal_native.h"
#include "gpr_transport_native.h"
#include "m11_anchor_owner.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* ---- fixture syscalls: memfd dma-bufs from a /dev/zero "heap"; ION ioctls on the real ION anchor ---- */
static int fx_heap = -1, fx_ion = -1;
static int fx_ioctl(int fd, unsigned long req, void *arg) {
    if (req == M11_DMA_HEAP_IOCTL_ALLOC) {
        m11_dma_heap_allocation_data *d = arg;
        if (fd != fx_heap) { errno = EBADF; return -1; }
        int m = memfd_create("m11-g8", MFD_CLOEXEC);
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

/* ---- the ADSP stand-in (forked BEFORE the anchors exist, so it never holds them) ---- */
static void peer(int ep) {
    alarm(10);
    for (;;) {
        uint8_t rx[M11_GPR_MAX_PKT_BYTES], tx[64]; size_t txl = 0;
        ssize_t n = recv(ep, rx, sizeof rx, 0);
        if (n <= 0) _exit(0);
        m11_gpr_hdr_t h; const uint8_t *pl; size_t pll;
        if (m11_gpr_validate_packet(rx, (size_t)n, &h, &pl, &pll) < 0) _exit(100);
        int rc;
        if (h.opcode == M11_APM_CMD_SHARED_MEM_MAP_REGIONS) {
            m11_apm_rsp_shared_mem_map_t r = {.mem_map_handle = 0xA0000001u};
            rc = m11_gpr_pack_packet_ex(tx, sizeof tx, &txl, M11_GPR_DOMAIN_APPS, M11_GPR_DOMAIN_ADSP, 0, h.src_port,
                                        h.dst_port, h.token, M11_APM_CMDRSP_SHARED_MEM_MAP_REGIONS, &r, sizeof r);
        } else {
            m11_gpr_ibasic_rsp_t r = {.cmd_opcode = h.opcode, .status = 0};
            rc = m11_gpr_pack_packet_ex(tx, sizeof tx, &txl, M11_GPR_DOMAIN_APPS, M11_GPR_DOMAIN_ADSP, 0, h.src_port,
                                        h.dst_port, h.token, M11_GPR_IBASIC_RSP_RESULT, &r, sizeof r);
        }
        if (rc < 0) _exit(104);
        (void)send(ep, tx, txl, 0);
    }
}

/* ---- per-case world ---- */
static const m11_anchor_contract evidence = {.endpoint_has_no_flush = true,
    .release_on_last_fput_only = true, .owner_single_threaded = true};
static m11_anchor_linux le, li;
static m11_pid1_anchor ep, io, tep;
static m11_gpr_native_link glink; static m11_gpr_transport_t gt; static m11_gpr_engine_t eng;
static m11_shmem_native_link slink; static m11_shmem_backend_t sb; static m11_shmem_mgr_t mgr;
static m11_boot_ledger boot; static m11_custodian cust; static m11_dmabuf_pool pool;
static m11_terminal_native term;
static int report_fd = -1, ep_a, ep_g, io_a, io_g;
static char panic_path[300];

static int is_open(int fd) { return fd >= 0 && fcntl(fd, F_GETFD) != -1; }
static uint64_t ms(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000u + (uint64_t)t.tv_nsec / 1000000u;
}
static void report(const char *what) {
    char b[512];
    int open_now = is_open(ep_a) + is_open(ep_g) + is_open(io_a) + is_open(io_g);
    int pool_open = pool.count ? is_open(pool.base) + is_open(pool.base + 1) : -1;
    int n = snprintf(b, sizeof b, "%s fds_open=%d/4 pool_open=%d %s", what, open_now, pool_open, term.record);
    if (n > 0) (void)!write(report_fd, b, (size_t)n < sizeof b ? (size_t)n : sizeof b - 1);
}
static void t_exit(void *u) { (void)u; report("EXIT"); _exit(42); }
static int reboot_mode; /* 0: "reboots" (child ends 43); 1: fails */
static int t_reboot(void *u) { (void)u; if (reboot_mode) return -EIO; report("REBOOT"); _exit(43); }

static void stdio_off_null(void) {
    for (int fd = 0; fd < 3; fd++) {
        struct stat st;
        if (fstat(fd, &st) || !S_ISCHR(st.st_mode) || st.st_rdev != makedev(1, 3)) continue;
        int p[2]; assert(!pipe(p)); assert(dup2(fd == 0 ? p[0] : p[1], fd) == fd); close(p[0]); close(p[1]);
    }
}
static void world(int with_pool) {
    stdio_off_null();
    int sv[2]; assert(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv) == 0);
    pid_t p = fork(); assert(p >= 0);
    if (p == 0) { close(sv[0]); peer(sv[1]); }
    close(sv[1]);
    /* the real adapters, sealed */
    m11_anchor_ops oe, oi; struct stat se, si;
    assert(!stat("/dev/ptmx", &se) && !stat("/dev/null", &si));
    assert(!m11_anchor_linux_ops(&le, "/dev/ptmx", getpid(), &oe) && !m11_anchor_linux_ops(&li, "/dev/null", getpid(), &oi));
    assert(!m11_anchor_bind(&ep, &oe, NULL, &evidence, getpid(), (uint64_t)se.st_rdev));
    assert(!m11_anchor_bind(&io, &oi, NULL, &evidence, getpid(), (uint64_t)si.st_rdev));
    m11_pid1_anchor *both[2] = {&ep, &io};
    assert(m11_anchor_owner_seal_pairs(both, NULL, 2) == 0);
    ep_a = ep.anchor_fd; ep_g = ep.guard_fd; io_a = io.anchor_fd; io_g = io.guard_fd;
    fx_ion = io.anchor_fd;
    fx_heap = open("/dev/zero", O_RDONLY | O_CLOEXEC); assert(fx_heap >= 0);
    if (with_pool) {
        assert(m11_dmabuf_pool_build(&pool, fx_heap, 2, 8192, 200, &fx_sys) == 0);
        const int base[2] = {ep.anchor_fd, io.anchor_fd};
        assert(m11_dmabuf_pool_seal(&pool, base, 2) == 0);
    }
    /* the engine's transport: the SEQPACKET stand-in (the pty anchor cannot carry GPR) */
    tep.state = M11_ANCHOR_HELD; tep.anchor_fd = sv[0]; tep.owner_pid = getpid();
    assert(m11_gpr_native_transport(&glink, &tep, &gt) == 0);
    assert(m11_gpr_engine_init(&eng, &gt, 0x0100u) == 0 && m11_gpr_engine_open(&eng) == 0);
    assert(m11_shmem_native_backend(&slink, &io, fx_heap, &fx_sys, &sb) == 0);
    assert(m11_shmem_mgr_init(&mgr, &sb, &eng, 300) == 0);
    assert(m11_model_new_boot(&boot, 9, ms()) == 0);
    const m11_custodian_model_contract ct = {true, true, true, true, true, true, true};
    assert(m11_custodian_init(&cust, &boot, &mgr, &ct, 2000) == 0);
    term = (m11_terminal_native){.c = &cust, .anchors = {&ep, &io}, .nanchors = 2,
                                 .pool = with_pool ? &pool : NULL, .sink = NULL,
                                 .ops = {.exit_fn = t_exit, .reboot_fn = t_reboot, .user = NULL, .panic_path = panic_path}};
}
static void end_and_report(void) {
    int rc = m11_terminal_native_end(&term, ms());
    char b[32]; snprintf(b, sizeof b, "RET=%d", rc);
    report(b);
    _exit(0);
}

/* ---- cases ---- */
static void c_never_mapped(void) { world(0); assert(m11_custodian_close(&cust) == 0); end_and_report(); }
static void c_mapped(void) {
    world(1); unsigned s;
    assert(m11_custodian_map(&cust, 4096, ms(), &s) == 0 && m11_custodian_retire(&cust, s, ms()) == 0);
    assert(m11_custodian_close(&cust) == 0);
    end_and_report();
}
static void c_hold(void) { world(0); unsigned s; assert(m11_custodian_map(&cust, 4096, ms(), &s) == 0); end_and_report(); }
static void c_pd_down(void) { world(0); m11_custodian_pd_down(&cust, ms()); end_and_report(); }
static void c_orderly_refused(void) {
    world(0); assert(m11_custodian_close(&cust) == 0);
    term.anchors[0] = &io; term.anchors[1] = &ep;  /* the refusing anchor first: nothing closed */
    io.latches |= M11_ANCHOR_LATCH_SECOND_OFD;     /* a second open file description was seen */
    end_and_report();
}
static void c_reboot_fails(void) { world(0); assert(m11_custodian_close(&cust) == 0); reboot_mode = 1; end_and_report(); }

static int run(void (*fn)(void), char *rep, size_t cap) {
    int p[2]; assert(pipe(p) == 0);
    fflush(stdout);
    pid_t c = fork(); assert(c >= 0);
    if (c == 0) { close(p[0]); report_fd = p[1]; fn(); _exit(99); }
    close(p[1]);
    size_t have = 0; ssize_t n;
    while (have + 1 < cap && (n = read(p[0], rep + have, cap - 1 - have)) > 0) have += (size_t)n;
    rep[have] = 0; close(p[0]);
    int st; assert(waitpid(c, &st, 0) == c);
    if (WIFSIGNALED(st) && WTERMSIG(st) == SIGABRT) abort();
    return WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
}
static void set_panic(const char *text) {
    if (!text) { snprintf(panic_path, sizeof panic_path, "/nonexistent-m11/panic"); return; }
    snprintf(panic_path, sizeof panic_path, "/tmp/m11-g8-panic-XXXXXX");
    int fd = mkstemp(panic_path); assert(fd >= 0);
    assert(write(fd, text, strlen(text)) == (ssize_t)strlen(text) && close(fd) == 0);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGPIPE, SIG_IGN);
    char rep[1024]; int st;

    set_panic(NULL);
    st = run(c_never_mapped, rep, sizeof rep);
    printf("INFO %s", rep);
    assert(st == 43 && strstr(rep, "REBOOT fds_open=0/4") && strstr(rep, "action=ORDERLY_SHUTDOWN end=reboot anchors_held=0/2"));
    assert(strstr(rep, "panic=unknown reset_path=unknown map_attempted=0"));
    printf("PASS never-mapped boot: both anchors final-closed, then reboot; panic sysctl unreadable is recorded\n");

    set_panic("-1\n");
    st = run(c_mapped, rep, sizeof rep);
    printf("INFO %s", rep);
    assert(st == 42 && strstr(rep, "EXIT fds_open=4/4 pool_open=2") && strstr(rep, "end=pid1_exit anchors_held=2/2 pool=held"));
    assert(strstr(rep, "action=RESET_RETAINING_ANCHORS") && strstr(rep, "reset_path=immediate map_attempted=1 unmap_attempted=1 note=mapped_boot"));
    printf("PASS mapped boot (even fully torn down): PID1 exit with all four anchor fds and the pool held; no reboot\n");

    st = run(c_hold, rep, sizeof rep);
    printf("INFO %s", rep);
    assert(st == 0 && strstr(rep, "RET=-16 fds_open=4/4"));
    printf("PASS HOLD (a region still mapped): the end is refused, nothing closed\n");

    set_panic("0\n");
    st = run(c_pd_down, rep, sizeof rep);
    printf("INFO %s", rep);
    assert(st == 42 && strstr(rep, "EXIT fds_open=4/4") && strstr(rep, "anchors_held=2/2 pool=none panic=0 reset_path=hang map_attempted=0"));
    printf("PASS PD DOWN on a never-mapped boot: reset end holding the anchors; panic=0 recorded as a hang\n");

    st = run(c_orderly_refused, rep, sizeof rep);
    printf("INFO %s", rep);
    assert(st == 42 && strstr(rep, "EXIT fds_open=4/4") && strstr(rep, "note=orderly_failed"));
    printf("PASS orderly end with a refused final close: falls to the reset end, nothing closed, no reboot\n");

    st = run(c_reboot_fails, rep, sizeof rep);
    printf("INFO %s", rep);
    assert(st == 42 && strstr(rep, "EXIT fds_open=0/4") && strstr(rep, "note=reboot_failed"));
    printf("PASS reboot(2) failing after the orderly closes: PID1 exit, never a retry\n");

    m11_terminal_native bad; memset(&bad, 0, sizeof bad);
    assert(m11_terminal_native_end(&bad, 0) == -EINVAL);
    m11_terminal_ops d = m11_terminal_ops_default();
    assert(d.exit_fn && d.reboot_fn && !strcmp(d.panic_path, "/proc/sys/kernel/panic"));
    printf("PASS G8 native terminal (real adapters, owner seal, custodian, manager and engine)\n");
    return 0;
}
