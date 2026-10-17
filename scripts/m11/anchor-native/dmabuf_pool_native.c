/* G5 dma-buf pool anchors, pool seal and census — see dmabuf_pool_native.h. */
#define _GNU_SOURCE
#include "dmabuf_pool_native.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#if defined(__x86_64__)
#define POOL_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define POOL_ARCH AUDIT_ARCH_AARCH64
#else
#error "pool seal is defined for x86_64 and aarch64 only"
#endif

static int pool_built;

int m11_dmabuf_pool_build(m11_dmabuf_pool *p, int heap_fd, unsigned count, size_t len, int base,
                          const m11_shmem_native_sys *sys) {
    if (!p) return -EINVAL;
    memset(p, 0, sizeof *p);
    if (heap_fd < 0 || !count || count > M11_DMABUF_POOL_MAX || !len ||
        len % M11_SHMEM_PAGE_ALIGNMENT || base < 3) return -EINVAL;
    if (pool_built) return -EALREADY;
    pool_built = 1;
    if (!sys) sys = &m11_shmem_native_libc;
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) || rl.rlim_cur <= (rlim_t)base + 2u * count) return -EMFILE;
    for (int n = base; n < base + 2 * (int)count; n++)
        if (fcntl(n, F_GETFD) != -1 || errno != EBADF) return -EBUSY; /* the range must be free */

    unsigned made = 0;
    int rc = 0;
    for (; made < count; made++) {
        m11_dma_heap_allocation_data d = {.len = len, .fd = 0, .fd_flags = O_RDWR | O_CLOEXEC, .heap_flags = 0};
        int r;
        do r = sys->ioctl_fn(heap_fd, M11_DMA_HEAP_IOCTL_ALLOC, &d); while (r < 0 && errno == EINTR);
        if (r < 0) { rc = -errno; break; }
        int src = (int)d.fd, a = base + 2 * (int)made;
        struct stat s0, s1, s2;
        if (src < 0 || src == a || src == a + 1 || fstat(src, &s0) ||
            dup3(src, a, O_CLOEXEC) != a) { rc = -EIO; if (src >= 0) close(src); break; }
        if (dup3(src, a + 1, O_CLOEXEC) != a + 1) { rc = -EIO; close(src); close(a); break; }
        close(src);
        if (fstat(a, &s1) || fstat(a + 1, &s2) || s1.st_ino != s0.st_ino || s2.st_ino != s0.st_ino ||
            s1.st_dev != s0.st_dev || s2.st_dev != s0.st_dev || (made && s0.st_dev != p->dev)) {
            rc = -EIO; close(a); close(a + 1); break;
        }
        for (unsigned j = 0; j < made; j++)
            if (p->ino[j] == s0.st_ino) { rc = -EIO; break; }
        if (rc) { close(a); close(a + 1); break; }
        p->dev = s0.st_dev;
        p->ino[made] = s0.st_ino;
    }
    if (rc) {
        for (unsigned j = 0; j < made; j++) { close(base + 2 * (int)j); close(base + 2 * (int)j + 1); }
        memset(p, 0, sizeof *p);
        return rc;
    }
    p->count = count; p->len = len; p->base = base; p->owner_pid = getpid();
    return 0;
}

/* ------------------------------------ pool seal ------------------------------------ */
#define POOL_SEAL_MAX 512u
struct prog { struct sock_filter f[POOL_SEAL_MAX]; unsigned n; int overflow; };
static void put(struct prog *p, struct sock_filter x) {
    if (p->n < POOL_SEAL_MAX) p->f[p->n++] = x; else p->overflow = 1;
}
#define STMT(c, k) put(p, (struct sock_filter)BPF_STMT((c), (k)))
#define JUMP(c, k, t, f) put(p, (struct sock_filter)BPF_JUMP((c), (k), (t), (f)))
#define RET_DENY (SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA))
static uint32_t arg_lo(unsigned i) { return (uint32_t)(offsetof(struct seccomp_data, args) + 8u * i); }

/* Syscall `nr` whose argument `i` names a pool number: refused. Entered and left with nr loaded. */
static void reserved(struct prog *p, uint32_t nr, unsigned i, const uint32_t *r, unsigned k) {
    JUMP(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, (uint8_t)(k + 3));
    STMT(BPF_LD | BPF_W | BPF_ABS, arg_lo(i));
    for (unsigned j = 0; j < k; j++) JUMP(BPF_JMP | BPF_JEQ | BPF_K, r[j], (uint8_t)(k - j), 0);
    STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    STMT(BPF_RET | BPF_K, RET_DENY);
}
static void build(struct prog *p, const uint32_t *r, unsigned k, const uint32_t *b, unsigned nb) {
    STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch));
    JUMP(BPF_JMP | BPF_JEQ | BPF_K, POOL_ARCH, 1, 0);
    STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
    STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr));
#if defined(__x86_64__)
    JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x40000000u, 0, 1); /* x32 ABI aliases */
    STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
    reserved(p, __NR_dup2, 1, r, k);
#endif
    reserved(p, __NR_close, 0, r, k);
    reserved(p, __NR_dup, 0, r, k);
    reserved(p, __NR_dup3, 1, r, k);
    /* fcntl on a pool number: F_DUPFD, F_DUPFD_CLOEXEC, F_SETFD and F_SETFL refused. */
    JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_fcntl, 0, (uint8_t)(k + 9));
    STMT(BPF_LD | BPF_W | BPF_ABS, arg_lo(0));
    for (unsigned j = 0; j < k; j++) JUMP(BPF_JMP | BPF_JEQ | BPF_K, r[j], (uint8_t)(k - j), 0);
    STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    STMT(BPF_LD | BPF_W | BPF_ABS, arg_lo(1));
    JUMP(BPF_JMP | BPF_JEQ | BPF_K, F_DUPFD, 4, 0);
    JUMP(BPF_JMP | BPF_JEQ | BPF_K, F_DUPFD_CLOEXEC, 3, 0);
    JUMP(BPF_JMP | BPF_JEQ | BPF_K, F_SETFD, 2, 0);
    JUMP(BPF_JMP | BPF_JEQ | BPF_K, F_SETFL, 1, 0);
    STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    STMT(BPF_RET | BPF_K, RET_DENY);
    /* close_range: only the base pairs' exact (anchor, anchor + 1, 0); never a pool pair. */
    JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_close_range, 0, (uint8_t)(7 * nb + 1));
    for (unsigned i = 0; i < nb; i++) {
        STMT(BPF_LD | BPF_W | BPF_ABS, arg_lo(0));
        JUMP(BPF_JMP | BPF_JEQ | BPF_K, b[i], 0, 5);
        STMT(BPF_LD | BPF_W | BPF_ABS, arg_lo(1));
        JUMP(BPF_JMP | BPF_JEQ | BPF_K, b[i] + 1, 0, (uint8_t)(7 * (nb - i) - 4));
        STMT(BPF_LD | BPF_W | BPF_ABS, arg_lo(2));
        JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, (uint8_t)(7 * (nb - i) - 6));
        STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    }
    STMT(BPF_RET | BPF_K, RET_DENY); /* every other close_range: refused */
    STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
}

int m11_dmabuf_pool_seal(m11_dmabuf_pool *pool, const int *base_anchors, unsigned nbase) {
    static struct prog prog;
    if (!pool || !pool->count || pool->sealed || nbase > M11_DMABUF_POOL_MAX_BASE ||
        (nbase && !base_anchors)) return -EINVAL;
    if (pool->owner_pid != getpid()) return -EPERM;
    uint32_t r[2 * M11_DMABUF_POOL_MAX], b[M11_DMABUF_POOL_MAX_BASE];
    unsigned k = 0;
    for (unsigned i = 0; i < pool->count; i++) {
        r[k++] = (uint32_t)m11_dmabuf_pool_fd(pool, i);
        r[k++] = (uint32_t)m11_dmabuf_pool_fd(pool, i) + 1u;
    }
    const int lo = pool->base, hi = pool->base + 2 * (int)pool->count - 1;
    for (unsigned i = 0; i < nbase; i++) {
        int a = base_anchors[i];
        if (a < 0 || a == 0x7fffffff || (a + 1 >= lo && a <= hi)) return -EINVAL; /* disjoint from the pool */
        for (unsigned j = 0; j < i; j++)
            if (a <= base_anchors[j] + 1 && base_anchors[j] <= a + 1) return -EINVAL;
        b[i] = (uint32_t)a;
    }
    memset(&prog, 0, sizeof prog);
    struct prog *p = &prog;
    build(p, r, k, b, nbase);
    if (p->overflow) return -E2BIG;
    struct sock_fprog fp = {(unsigned short)p->n, p->f};
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) return -errno;
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &fp, 0, 0)) return -errno;
    pool->sealed = 1;
    return 0;
}

/* -------------------------------------- census -------------------------------------- */
int m11_census_dmabuf(const m11_dmabuf_pool *pool, const m11_fd_ident *e, unsigned n, int pid1) {
    if (!pool || !pool->count || (n && !e)) return -1;
    unsigned char seen[2 * M11_DMABUF_POOL_MAX] = {0};
    for (unsigned i = 0; i < n; i++) {
        if (e[i].dev != (unsigned long long)pool->dev) continue;
        if (!pid1) return -1;                         /* nobody else holds a pool buffer */
        int off = e[i].fd - pool->base;
        if (off < 0 || off >= 2 * (int)pool->count) return -1; /* a dma-buf outside the pool numbers */
        if (seen[off] || e[i].ino != (unsigned long long)pool->ino[off / 2]) return -1;
        seen[off] = 1;
    }
    if (pid1)
        for (unsigned i = 0; i < 2 * pool->count; i++) if (!seen[i]) return -1;
    return 0;
}

int m11_dmabuf_census_pid(const m11_dmabuf_pool *pool, pid_t pid, int pid1) {
    m11_fd_ident e[1024];
    char path[64], item[64 + 256 + 8];
    snprintf(path, sizeof path, "/proc/%ld/fd", (long)pid);
    DIR *d = opendir(path);
    if (!d) return -1;
    unsigned n = 0;
    int ok = 1;
    for (;;) {
        errno = 0;
        struct dirent *de = readdir(d);
        if (!de) { if (errno) ok = 0; break; }
        char *end;
        long v = strtol(de->d_name, &end, 10);
        if (de->d_name[0] < '0' || de->d_name[0] > '9' || *end || v < 0) continue;
        if (n == sizeof e / sizeof *e) { ok = 0; break; }
        snprintf(item, sizeof item, "%s/%s", path, de->d_name);
        struct stat st;
        if (stat(item, &st)) { ok = 0; break; }      /* a racing close is inconclusive: reject */
        e[n++] = (m11_fd_ident){.fd = (int)v, .dev = (unsigned long long)st.st_dev,
                                .ino = (unsigned long long)st.st_ino};
    }
    closedir(d);
    return ok ? m11_census_dmabuf(pool, e, n, pid1) : -1;
}
