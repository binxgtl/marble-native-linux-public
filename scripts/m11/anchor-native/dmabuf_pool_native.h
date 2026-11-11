/* G5 (docs/m11-custodian-native-integration.md): dma-buf anchoring for the native custodian.
 * Built only in the reviewed M11_CUSTODIAN_NATIVE build; never part of a candidate.
 *
 * Every dma-buf the custodian may ever map is a PID1 anchor allocated up front:
 *  - the pool is built once per process from the G4 heap fd: `count` buffers of one size, each held
 *    at a pair of fd numbers (anchor = base + 2i, guard = anchor + 1, FD_CLOEXEC), all in one
 *    contiguous range that must be free; both numbers of a pair are the same buffer (same inode),
 *    every buffer is a distinct inode, and all share one device (the dma-buf pseudo filesystem);
 *  - the pool seal is an extra seccomp filter, installed after the owner seal: no close, dup, dup2,
 *    dup3 or fcntl F_DUPFD / F_DUPFD_CLOEXEC / F_SETFD / F_SETFL on any pool number, and no
 *    close_range except exactly (anchor, anchor + 1, 0) of the owner seal's base pairs (endpoint,
 *    ION), so the owner seal's own permitted closes keep working. Pool pairs have NO permitted
 *    close: their backing lives until PID1 exits. The owner seal (qualification/ownership,
 *    a frozen candidate input) is not changed; seccomp applies every filter, so the result is
 *    the intersection;
 *  - census: PID1 holds the pool device only at the pool numbers, each at its own inode, all of
 *    them present; any other process holds no fd on the pool device at all (a post-seal fork of
 *    PID1 is therefore a census failure: post-seal jobs come from the pre-bind spawner).
 */
#ifndef M11_DMABUF_POOL_NATIVE_H
#define M11_DMABUF_POOL_NATIVE_H
#ifndef M11_CUSTODIAN_NATIVE
#error "dmabuf_pool_native requires the reviewed M11_CUSTODIAN_NATIVE build"
#endif
#include "shmem_backend_native.h"
#include <stddef.h>
#include <sys/types.h>

#define M11_DMABUF_POOL_MAX 8u /* = M11_SHMEM_NATIVE_MAX_BUFS: a pooled link tracks every buffer */
#define M11_DMABUF_POOL_MAX_BASE 2u

typedef struct m11_dmabuf_pool {
    unsigned count;
    size_t len;
    int base;                              /* first pool number; anchor_i = base + 2i */
    dev_t dev;                             /* the pool's (pseudo filesystem) device */
    ino_t ino[M11_DMABUF_POOL_MAX];
    int owner_pid;
    int sealed;
} m11_dmabuf_pool;

/* One-shot per process: allocate `count` buffers of `len` (page multiple) from `heap_fd` with
 * DMA_HEAP_IOCTL_ALLOC through `sys` (NULL = libc) and pin each at its pair from `base`.
 * 0, or a negative errno with nothing allocated or pinned. */
int m11_dmabuf_pool_build(m11_dmabuf_pool *, int heap_fd, unsigned count, size_t len, int base,
                          const m11_shmem_native_sys *sys);
static inline int m11_dmabuf_pool_fd(const m11_dmabuf_pool *p, unsigned i) { return p->base + 2 * (int)i; }

/* Install the pool seal (owner only, once). base_anchors: the owner seal's pairs (anchor fds,
 * guard = anchor + 1), 0..M11_DMABUF_POOL_MAX_BASE of them. 0 or a negative errno. */
int m11_dmabuf_pool_seal(m11_dmabuf_pool *, const int *base_anchors, unsigned nbase);

/* Pure census rule over one process's fds (fd, st_dev, st_ino). pid1: the pool rule above;
 * otherwise: no entry on the pool device. 0 allowed, -1 refused. */
typedef struct { int fd; unsigned long long dev, ino; } m11_fd_ident;
int m11_census_dmabuf(const m11_dmabuf_pool *, const m11_fd_ident *, unsigned n, int pid1);
/* The rule applied to /proc/<pid>/fd (-1 also on any scan error). */
int m11_dmabuf_census_pid(const m11_dmabuf_pool *, pid_t pid, int pid1);

#endif
