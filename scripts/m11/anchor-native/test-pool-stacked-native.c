/* G5 follow-up: the dma-buf pool seal stacked on the REAL owner seal in one process. Two real
 * anchor adapters (pty multiplexer and null stand-ins, bound by the actual Linux backend, as in
 * test-ion-seal.c) are sealed with m11_anchor_owner_seal_pairs; the pool (memfd buffers from a
 * fixture heap ioctl) is then built and sealed with the base pairs. Seccomp applies every filter,
 * so each check below holds only if the intersection is right. The real endpoint and ION nodes
 * are never named; no driver. Each case runs in a child (the seals are irreversible). */
#ifndef M11_CUSTODIAN_NATIVE
#error "test-pool-stacked-native.c builds only with M11_CUSTODIAN_NATIVE"
#endif
#define _GNU_SOURCE
#include "dmabuf_pool_native.h"
#include "m11_anchor_owner.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <unistd.h>

static int fx_heap = -1, fx_ion = -1, fx_imported[1024];
static int fx_ioctl(int fd, unsigned long req, void *arg) {
    if (req == M11_DMA_HEAP_IOCTL_ALLOC) {
        m11_dma_heap_allocation_data *d = arg;
        assert(fd == fx_heap);
        int m = memfd_create("m11-pool", MFD_CLOEXEC);
        assert(m >= 0 && ftruncate(m, (off_t)d->len) == 0);
        d->fd = (uint32_t)m;
        return 0;
    }
    if (req == M11_MSM_AUDIO_ION_MAP_PHYS || req == M11_MSM_AUDIO_ION_UNMAP) {
        int v = (int)(uintptr_t)arg;
        assert(fd == fx_ion && v >= 0 && v < 1024);
        fx_imported[v] = req == M11_MSM_AUDIO_ION_MAP_PHYS;
        return 0;
    }
    errno = ENOTTY; return -1;
}
static int fx_munmap(void *a, size_t l) { return munmap(a, l); }
static const m11_shmem_native_sys fx_sys = {fx_ioctl, mmap, fx_munmap, close};

static int refused(long rc) { return rc == -1 && errno == EPERM; }
static long crange(unsigned a, unsigned b, unsigned f) { return syscall(SYS_close_range, a, b, f); }
static int is_open(int fd) { return fcntl(fd, F_GETFD) != -1; }
static void in_child(void (*fn)(void)) {
    pid_t c = fork(); assert(c >= 0);
    if (c == 0) { fn(); _exit(0); }
    int st; assert(waitpid(c, &st, 0) == c);
    if (WIFSIGNALED(st) && WTERMSIG(st) == SIGABRT) abort();
    assert(WIFEXITED(st) && WEXITSTATUS(st) == 0);
}

static const m11_anchor_contract evidence = {.endpoint_has_no_flush = true,
    .release_on_last_fput_only = true, .owner_single_threaded = true};
/* The stand-in census counts every holder of the null device: move stdio off it first. */
static void stdio_off_null(void) {
    for (int fd = 0; fd < 3; fd++) {
        struct stat st;
        if (fstat(fd, &st) || !S_ISCHR(st.st_mode) || st.st_rdev != makedev(1, 3)) continue;
        int p[2]; assert(!pipe(p)); assert(dup2(fd == 0 ? p[0] : p[1], fd) == fd); close(p[0]); close(p[1]);
    }
}
static m11_anchor_linux le, li;
static m11_pid1_anchor ep, io;
static void bind_both(void) {
    stdio_off_null();
    m11_anchor_ops oe, oi; struct stat se, si;
    assert(!stat("/dev/ptmx", &se) && !stat("/dev/null", &si));
    assert(!m11_anchor_linux_ops(&le, "/dev/ptmx", getpid(), &oe) && !m11_anchor_linux_ops(&li, "/dev/null", getpid(), &oi));
    assert(!m11_anchor_bind(&ep, &oe, NULL, &evidence, getpid(), (uint64_t)se.st_rdev));
    assert(!m11_anchor_bind(&io, &oi, NULL, &evidence, getpid(), (uint64_t)si.st_rdev));
    fx_ion = io.anchor_fd;
}
static void owner_seal(void) {
    m11_pid1_anchor *both[2] = {&ep, &io};
    assert(m11_anchor_owner_seal_pairs(both, NULL, 2) == 0);
}
#define BASE 200
#define K 4
#define LEN 8192
static m11_dmabuf_pool pool;
static void pool_build(void) {
    fx_heap = open("/dev/zero", O_RDONLY | O_CLOEXEC); assert(fx_heap >= 0); /* not the null stand-in */
    assert(m11_dmabuf_pool_build(&pool, fx_heap, K, LEN, BASE, &fx_sys) == 0);
}
static void pool_seal(int with_base) {
    const int base[2] = {ep.anchor_fd, io.anchor_fd};
    assert(m11_dmabuf_pool_seal(&pool, base, with_base ? 2u : 0u) == 0);
}

/* Every protection of both seals at once, the pooled backend through the real ION anchor, then
 * both owner final closes; the pool outlives them. */
static void both_sealed_checks(void) {
    int x = open("/dev/zero", O_RDONLY | O_CLOEXEC); assert(x >= 0);
    /* owner seal still in force */
    assert(refused(close(io.anchor_fd)) && refused(close(ep.guard_fd)));
    assert(refused(dup3(x, io.guard_fd, 0)) && refused(dup(ep.anchor_fd)));
    assert(refused(syscall(SYS_mknodat, AT_FDCWD, "/nonexistent-m11", S_IFCHR | 0600, makedev(1, 3))));
    char *const argv[] = {"/bin/true", NULL}, *const env[] = {NULL};
    assert(refused(execve(argv[0], argv, env)));
    /* pool seal in force */
    assert(refused(close(BASE)) && refused(crange(BASE, BASE + 1, 0)));
    assert(refused(dup3(x, BASE + 3, 0)) && refused(fcntl(BASE, F_SETFD, 0)));
    /* nothing wider than an exact base pair */
    assert(refused(crange((unsigned)ep.anchor_fd, (unsigned)io.guard_fd, 0)) && refused(crange(0, ~0u, 0)));
    assert(refused(crange(BASE, BASE + 2 * K - 1, 0)));
    /* unreserved numbers and fork still work */
    assert(close(x) == 0);
    pid_t c = fork(); assert(c >= 0);
    if (c == 0) _exit(0);
    int st; assert(waitpid(c, &st, 0) == c && WIFEXITED(st) && WEXITSTATUS(st) == 0);
    /* the pooled backend over the real ION anchor */
    m11_shmem_native_link l; m11_shmem_backend_t b; int fd = -1;
    assert(m11_shmem_native_backend_pool(&l, &io, &pool, &fx_sys, &b) == 0);
    assert(b.dma_heap_alloc_fn(b.user, LEN, &fd) == 0 && fd == BASE);
    void *v = b.mmap_fn(b.user, fd, LEN); assert(v);
    assert(b.ion_import_fd_fn(b.user, fd, false) == 0 && fx_imported[fd]);
    assert(b.ion_unmap_fd_fn(b.user, fd, false) == 0 && b.munmap_fn(b.user, v, LEN) == 0);
    assert(b.close_fd_fn(b.user, fd) == 0 && l.pool_returns == 1 && is_open(BASE));
    assert(m11_dmabuf_census_pid(&pool, getpid(), 1) == 0);
    assert(m11_anchor_check(&ep) == 0 && m11_anchor_check(&io) == 0);
    /* both owner final closes pass both filters */
    assert(m11_anchor_final_close(&io) == 0 && io.state == M11_ANCHOR_OWNER_FDS_DROPPED);
    assert(m11_anchor_final_close(&ep) == 0 && ep.state == M11_ANCHOR_OWNER_FDS_DROPPED);
    for (int n = BASE; n < BASE + 2 * K; n++) assert(is_open(n));
    assert(m11_dmabuf_census_pid(&pool, getpid(), 1) == 0);
}

static void case_owner_then_pool(void) { bind_both(); owner_seal(); pool_build(); pool_seal(1); both_sealed_checks(); }
static void case_pool_then_owner(void) { bind_both(); pool_build(); pool_seal(1); owner_seal(); both_sealed_checks(); }
static void case_pool_without_base(void) {
    bind_both(); owner_seal(); pool_build(); pool_seal(0);
    const int a = io.anchor_fd, g = io.guard_fd; /* the adapter forgets them on a failed close_pair */
    int rc = m11_anchor_final_close(&io);
    assert(rc == -EPERM && is_open(a) && is_open(g) && (io.latches & M11_ANCHOR_LATCH_CLOSE_ERROR));
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    in_child(case_owner_then_pool);
    printf("PASS stacked, owner seal then pool seal: both seals' refusals hold together; pooled backend over the real ION anchor; both owner final closes pass; the pool outlives them\n");
    in_child(case_pool_then_owner);
    printf("PASS stacked, pool seal then owner seal: same result in the other order\n");
    in_child(case_pool_without_base);
    printf("PASS intersection: a pool seal that omits the base pairs blocks the owner's final close\n");
    printf("PASS G5 pool seal stacked on the real owner seal (two real adapters on stand-ins)\n");
    return 0;
}
