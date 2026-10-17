/* G5 stand-in test: the dma-buf pool (memfd-backed buffers from a fixture heap ioctl), its seccomp
 * pool seal, the dma-buf census, and the G3 backend in pooled mode. The pool build and the seal are
 * one-shot per process, so they run in a child; an assertion there aborts the parent too. No
 * dma-heap or ION driver; unprivileged (seccomp under NO_NEW_PRIVS). */
#ifndef M11_CUSTODIAN_NATIVE
#error "test-dmabuf-pool-native.c builds only with M11_CUSTODIAN_NATIVE"
#endif
#define _GNU_SOURCE
#include "dmabuf_pool_native.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

/* ---- fixture syscalls: heap alloc -> memfd; ION import/unmap recorded; the rest is libc ---- */
static int fx_heap = -1, fx_ion = -1, fx_imported[1024];
static unsigned fx_allocs, fx_closes;
static int fx_ioctl(int fd, unsigned long req, void *arg) {
    if (req == M11_DMA_HEAP_IOCTL_ALLOC) {
        m11_dma_heap_allocation_data *d = arg;
        assert(fd == fx_heap && d->fd_flags == (O_RDWR | O_CLOEXEC) && d->heap_flags == 0);
        int m = memfd_create("m11-pool", MFD_CLOEXEC);
        assert(m >= 0 && ftruncate(m, (off_t)d->len) == 0);
        d->fd = (uint32_t)m; fx_allocs++;
        return 0;
    }
    if (req == M11_MSM_AUDIO_ION_MAP_PHYS || req == M11_MSM_AUDIO_ION_UNMAP) {
        int v = (int)(uintptr_t)arg;
        assert(fd == fx_ion && v >= 0 && v < 1024 && fx_imported[v] == (req == M11_MSM_AUDIO_ION_UNMAP));
        fx_imported[v] = req == M11_MSM_AUDIO_ION_MAP_PHYS;
        return 0;
    }
    errno = ENOTTY; return -1;
}
static int fx_close(int fd) { fx_closes++; return close(fd); }
static int fx_munmap(void *a, size_t l) { return munmap(a, l); }
static const m11_shmem_native_sys fx_sys = {fx_ioctl, mmap, fx_munmap, fx_close};

static void in_child(void (*fn)(void)) {
    pid_t c = fork(); assert(c >= 0);
    if (c == 0) { fn(); _exit(0); }
    int st; assert(waitpid(c, &st, 0) == c);
    if (WIFSIGNALED(st) && WTERMSIG(st) == SIGABRT) abort();
    assert(WIFEXITED(st) && WEXITSTATUS(st) == 0);
}
static int is_open(int fd) { return fcntl(fd, F_GETFD) != -1; }
static int denied(long rc) { return rc == -1 && errno == EPERM; }
static void heap_open(void) { fx_heap = open("/dev/null", O_RDONLY | O_CLOEXEC); assert(fx_heap >= 0); }

#define BASE 200
#define K 4
#define LEN 8192
/* stand-in owner-seal pairs (endpoint, ION) at fixed numbers */
static void base_pairs(void) {
    for (int n = 100; n < 104; n++) { int f = open("/dev/null", O_RDONLY); assert(f >= 0 && dup3(f, n, O_CLOEXEC) == n && close(f) == 0); }
}

/* ---- refusals of the one-shot build (each in its own child) ---- */
static void case_busy_range(void) {
    m11_dmabuf_pool p; heap_open();
    int f = open("/dev/null", O_RDONLY); assert(f >= 0 && dup3(f, BASE + 3, 0) == BASE + 3);
    assert(m11_dmabuf_pool_build(&p, fx_heap, K, LEN, BASE, &fx_sys) == -EBUSY && fx_allocs == 0);
    assert(m11_dmabuf_pool_build(&p, fx_heap, K, LEN, BASE + 100, &fx_sys) == -EALREADY);
}
static void case_bad_args(void) {
    m11_dmabuf_pool p; heap_open();
    assert(m11_dmabuf_pool_build(NULL, fx_heap, K, LEN, BASE, &fx_sys) == -EINVAL);
    assert(m11_dmabuf_pool_build(&p, -1, K, LEN, BASE, &fx_sys) == -EINVAL);
    assert(m11_dmabuf_pool_build(&p, fx_heap, 0, LEN, BASE, &fx_sys) == -EINVAL);
    assert(m11_dmabuf_pool_build(&p, fx_heap, M11_DMABUF_POOL_MAX + 1, LEN, BASE, &fx_sys) == -EINVAL);
    assert(m11_dmabuf_pool_build(&p, fx_heap, K, 100, BASE, &fx_sys) == -EINVAL);
    assert(m11_dmabuf_pool_build(&p, fx_heap, K, LEN, 2, &fx_sys) == -EINVAL);
    assert(fx_allocs == 0);
}
static void case_libc_heap(void) { /* the real DMA_HEAP ioctl on a non-heap node: nothing pinned */
    m11_dmabuf_pool p; heap_open();
    assert(m11_dmabuf_pool_build(&p, fx_heap, K, LEN, BASE, NULL) == -ENOTTY && p.count == 0);
    for (int n = BASE; n < BASE + 2 * K; n++) assert(!is_open(n));
}

/* ---- the main path: build, seal, census, pooled backend (one child) ---- */
static void main_path(void) {
    m11_dmabuf_pool p; heap_open(); base_pairs();
    fx_ion = open("/dev/null", O_RDWR | O_CLOEXEC); assert(fx_ion >= 0);

    /* build */
    assert(m11_dmabuf_pool_build(&p, fx_heap, K, LEN, BASE, &fx_sys) == 0 && fx_allocs == K);
    assert(p.count == K && p.len == LEN && p.base == BASE && p.owner_pid == getpid() && !p.sealed);
    for (unsigned i = 0; i < K; i++) {
        int a = m11_dmabuf_pool_fd(&p, i); struct stat s1, s2;
        assert(fstat(a, &s1) == 0 && fstat(a + 1, &s2) == 0 && s1.st_ino == s2.st_ino && s1.st_ino == p.ino[i]);
        assert(s1.st_dev == p.dev && (fcntl(a, F_GETFD) & FD_CLOEXEC) && (fcntl(a + 1, F_GETFD) & FD_CLOEXEC));
        for (unsigned j = 0; j < i; j++) assert(p.ino[j] != p.ino[i]);
    }
    unsigned char *wa = mmap(NULL, LEN, PROT_READ | PROT_WRITE, MAP_SHARED, BASE, 0);
    unsigned char *rg = mmap(NULL, LEN, PROT_READ, MAP_SHARED, BASE + 1, 0);
    assert(wa != MAP_FAILED && rg != MAP_FAILED);
    memset(wa, 0x3C, LEN); assert(rg[0] == 0x3C && rg[LEN - 1] == 0x3C); /* anchor and guard: one buffer */
    munmap(wa, LEN); munmap(rg, LEN);
    assert(m11_dmabuf_census_pid(&p, getpid(), 1) == 0);
    printf("PASS pool: %u buffers pinned at anchor/guard pairs from %d (one inode per pair, one device, CLOEXEC); census holds\n", K, BASE);

    /* the pooled backend refuses an unsealed pool; the seal installs once */
    m11_pid1_anchor ion; memset(&ion, 0, sizeof ion); ion.state = M11_ANCHOR_HELD; ion.anchor_fd = fx_ion; ion.owner_pid = getpid();
    m11_shmem_native_link l; m11_shmem_backend_t b;
    assert(m11_shmem_native_backend_pool(&l, &ion, &p, &fx_sys, &b) == -EPERM);
    const int base_anchors[2] = {100, 102}, overlapping[1] = {BASE + 1};
    assert(m11_dmabuf_pool_seal(&p, overlapping, 1) == -EINVAL && !p.sealed);
    assert(m11_dmabuf_pool_seal(&p, base_anchors, 2) == 0 && p.sealed);
    assert(m11_dmabuf_pool_seal(&p, base_anchors, 2) == -EINVAL);
    printf("PASS pooled backend refuses an unsealed pool; the pool seal rejects overlap and installs once\n");

    /* what the seal refuses and permits */
    assert(denied(syscall(SYS_close_range, BASE, BASE + 1, 0)));
    assert(denied(close(BASE)));
    assert(denied(close(BASE + 1)));
    assert(denied(dup(BASE)));
    int x = open("/dev/null", O_RDONLY); assert(x >= 0);
    assert(denied(dup3(x, BASE + 2, 0)));
    assert(denied(dup2(x, BASE + 3)));
    assert(denied(fcntl(BASE, F_SETFD, 0)));
    assert(denied(fcntl(BASE, F_DUPFD, 0)));
    assert(denied(fcntl(BASE + 1, F_DUPFD_CLOEXEC, 0)));
    assert(denied(syscall(SYS_close_range, 100, 103, 0)));
    assert(denied(syscall(SYS_close_range, 300, 400, 0)));
    assert(is_open(BASE) && is_open(BASE + 1) && (fcntl(BASE, F_GETFD) & FD_CLOEXEC));
    assert(syscall(SYS_close_range, 100, 101, 0) == 0 && !is_open(100) && !is_open(101));
    assert(syscall(SYS_close_range, 102, 103, 0) == 0 && !is_open(102));
    assert(close(x) == 0);
    void *m = mmap(NULL, LEN, PROT_READ, MAP_SHARED, BASE + 2, 0); assert(m != MAP_FAILED && munmap(m, LEN) == 0);
    printf("PASS pool seal: no close, dup, dup2/dup3 onto, fcntl dup/setfd or close_range of a pool number; base pairs' exact close_range still permitted\n");

    /* census: a post-seal fork holds pool buffers and cannot drop them */
    int go[2], ack[2]; assert(pipe(go) == 0 && pipe(ack) == 0);
    pid_t g = fork(); assert(g >= 0);
    if (g == 0) {
        char c;
        int ok = denied(close(BASE)) && denied(syscall(SYS_close_range, BASE, BASE + 2 * K - 1, 0));
        if (write(ack[1], ok ? "y" : "n", 1) != 1 || read(go[0], &c, 1) != 1) _exit(1);
        _exit(0);
    }
    char c; assert(read(ack[0], &c, 1) == 1 && c == 'y');
    assert(m11_dmabuf_census_pid(&p, g, 0) == -1);  /* the fork holds pool buffers */
    assert(m11_dmabuf_census_pid(&p, g, 1) == 0);   /* ...at exactly PID1's numbers */
    assert(write(go[1], "x", 1) == 1);
    int st; assert(waitpid(g, &st, 0) == g && WIFEXITED(st) && WEXITSTATUS(st) == 0);
    assert(m11_dmabuf_census_pid(&p, getpid(), 1) == 0);
    printf("PASS census: a post-seal fork holds pool buffers (refused) and cannot drop them\n");

    /* the G3 backend in pooled mode */
    assert(m11_shmem_native_backend_pool(&l, &ion, &p, &fx_sys, &b) == 0 && l.heap_fd == -1);
    int fd = -1, fd2 = -1;
    assert(b.dma_heap_alloc_fn(b.user, 4096, &fd) == -EINVAL && fd == -1); /* only the pool size */
    unsigned allocs = fx_allocs;
    assert(b.dma_heap_alloc_fn(b.user, LEN, &fd) == 0 && fd == BASE && fx_allocs == allocs);
    assert(b.dma_heap_alloc_fn(b.user, LEN, &fd2) == 0 && fd2 == BASE + 2);
    void *v = b.mmap_fn(b.user, fd, LEN); assert(v);
    assert(b.dma_buf_sync_fn(b.user, fd, M11_DMA_BUF_SYNC_START_RW) == -ENOTTY); /* memfd: no sync ioctl */
    assert(b.ion_import_fd_fn(b.user, fd, false) == 0 && fx_imported[fd]);
    assert(b.close_fd_fn(b.user, fd) == -EBUSY);
    assert(b.ion_unmap_fd_fn(b.user, fd, false) == 0 && b.munmap_fn(b.user, v, LEN) == 0);
    unsigned closes = fx_closes;
    assert(b.close_fd_fn(b.user, fd) == 0);
    assert(l.pool_returns == 1 && l.closes == 0 && fx_closes == closes && l.close_errors == 0);
    assert(is_open(BASE) && is_open(BASE + 1));
    assert(b.dma_heap_alloc_fn(b.user, LEN, &fd) == 0 && fd == BASE); /* the same buffer again */
    int f3, f4, f5;
    assert(b.dma_heap_alloc_fn(b.user, LEN, &f3) == 0 && b.dma_heap_alloc_fn(b.user, LEN, &f4) == 0);
    assert(b.dma_heap_alloc_fn(b.user, LEN, &f5) == -ENOSPC);
    assert(m11_dmabuf_census_pid(&p, getpid(), 1) == 0);
    printf("PASS pooled backend: pool-size buffers only, no ioctl, close returns the buffer without close(2), reuse, exhaustion\n");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    /* 1. pure census rule */
    m11_dmabuf_pool p = {.count = 2, .len = LEN, .base = 50, .dev = 9};
    p.ino[0] = 11; p.ino[1] = 12;
    m11_fd_ident full[] = {{50, 9, 11}, {51, 9, 11}, {52, 9, 12}, {53, 9, 12}, {7, 3, 11}};
    m11_fd_ident wrong[] = {{50, 9, 11}, {51, 9, 11}, {52, 9, 11}, {53, 9, 12}};
    m11_fd_ident extra[] = {{50, 9, 11}, {51, 9, 11}, {52, 9, 12}, {53, 9, 12}, {60, 9, 13}};
    m11_fd_ident twice[] = {{50, 9, 11}, {50, 9, 11}, {51, 9, 11}, {52, 9, 12}, {53, 9, 12}};
    m11_fd_ident other[] = {{4, 3, 1}, {5, 8, 2}};
    assert(m11_census_dmabuf(&p, full, 5, 1) == 0);
    assert(m11_census_dmabuf(&p, full, 3, 1) == -1);   /* 53 missing */
    assert(m11_census_dmabuf(&p, wrong, 4, 1) == -1);
    assert(m11_census_dmabuf(&p, extra, 5, 1) == -1);
    assert(m11_census_dmabuf(&p, twice, 5, 1) == -1);
    assert(m11_census_dmabuf(&p, full, 5, 0) == -1);
    assert(m11_census_dmabuf(&p, other, 2, 0) == 0);
    printf("PASS dma-buf census rule: PID1 exactly the pool pairs at their inodes; any other process none\n");

    /* 2. one-shot build refusals */
    in_child(case_bad_args);
    in_child(case_busy_range);
    in_child(case_libc_heap);
    printf("PASS pool build refused: bad arguments, an occupied range, a non-heap node (libc); one-shot after a failure\n");

    /* 3-6. build, seal, census, pooled backend */
    in_child(main_path);
    printf("PASS G5 dma-buf pool anchors (fixture heap, real seccomp pool seal, census, pooled backend)\n");
    return 0;
}
