/* G3 (docs/m11-custodian-native-integration.md): the native shmem backend for the custodian's
 * region manager (qualification/runtime-repair/m11_shmem.h). Built only in the reviewed
 * M11_CUSTODIAN_NATIVE build; never part of a candidate.
 *
 * Rules:
 *  - every call runs only in the process that bound the link (dma-buf fd numbers are per fd table:
 *    the ION import and the OFFSET_MODE MAP must name the same PID1 fd number);
 *  - only dma-buf fds this link allocated are touched; a foreign or stale fd number is refused
 *    with -EBADF before any syscall;
 *  - allocation: one DMA_HEAP_IOCTL_ALLOC on the caller's heap fd (O_RDWR | O_CLOEXEC, no heap
 *    flags); mmap is MAP_SHARED read/write of the whole buffer, at most one mapping per fd;
 *  - DMA_BUF_IOCTL_SYNC accepts exactly START|RW (0x3) and END|RW (0x7);
 *  - ION import / unmap (0x40046161 / 0x40046162, dma-buf fd by value) go through the ION anchor
 *    and only while it is HELD by the calling process; hyp_assign is refused (-EPERM) and the
 *    hyp-assign ioctls are never issued (VMID semantics UNKNOWN);
 *  - close refuses (-EBUSY) while the fd is still mmapped or imported; otherwise the fd leaves the
 *    table BEFORE close(2) and close reports success even if close(2) failed, because Linux
 *    releases the descriptor in every case but EBADF. This is the explicit consumed-fd disposition
 *    m11_shmem.h requires: an error return always means the fd was not touched, so the manager's
 *    retry can never close a reused fd number. close(2) errors are counted, never retried.
 */
#ifndef M11_SHMEM_BACKEND_NATIVE_H
#define M11_SHMEM_BACKEND_NATIVE_H
#ifndef M11_CUSTODIAN_NATIVE
#error "shmem_backend_native requires the reviewed M11_CUSTODIAN_NATIVE build"
#endif
#include "../qualification/runtime-repair/m11_shmem.h"
#include "../qualification/ownership/m11_pid1_anchor.h"
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* linux/dma-heap.h: _IOWR('H', 0, struct dma_heap_allocation_data) */
#define M11_DMA_HEAP_IOCTL_ALLOC 0xC0184800u
typedef struct {
    uint64_t len;
    uint32_t fd;
    uint32_t fd_flags;
    uint64_t heap_flags;
} m11_dma_heap_allocation_data;
/* linux/dma-buf.h */
typedef struct { uint64_t flags; } m11_dma_buf_sync;

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(m11_dma_heap_allocation_data) == 24u, "dma_heap_allocation_data is 24 bytes");
_Static_assert(sizeof(m11_dma_buf_sync) == 8u, "dma_buf_sync is 8 bytes");
#endif

/* The syscalls the backend issues. Production uses libc (m11_shmem_native_libc); the stand-in
 * test substitutes a fixture so the ioctl numbers and argument layouts are exercised without a
 * driver. Each returns like libc (-1 and errno). */
typedef struct {
    int (*ioctl_fn)(int fd, unsigned long req, void *arg);
    void *(*mmap_fn)(void *addr, size_t len, int prot, int flags, int fd, off_t off);
    int (*munmap_fn)(void *addr, size_t len);
    int (*close_fn)(int fd);
} m11_shmem_native_sys;

extern const m11_shmem_native_sys m11_shmem_native_libc;

#define M11_SHMEM_NATIVE_MAX_BUFS 8

typedef struct {
    int fd;           /* -1 = free slot */
    size_t len;
    void *vaddr;      /* NULL = not mapped */
    int imported;     /* the ION fd list holds this fd number */
} m11_shmem_native_buf;

typedef struct {
    const m11_pid1_anchor *ion_anchor;   /* PID1's /dev/msm_audio_ion anchor; never owned here */
    int heap_fd;                         /* /dev/dma_heap/system, opened by the caller (G4) */
    int bound_pid;
    const m11_shmem_native_sys *sys;
    m11_shmem_native_buf bufs[M11_SHMEM_NATIVE_MAX_BUFS];
    uint32_t allocs, maps, unmaps, syncs, imports, unimports, closes;
    uint32_t refused, hyp_refused, close_errors;
    int last_close_errno;
} m11_shmem_native_link;

/* Bind a link and fill the manager backend (user = link). sys NULL = libc. -EINVAL on NULLs or a
 * negative heap fd. */
int m11_shmem_native_backend(m11_shmem_native_link *link, const m11_pid1_anchor *ion_anchor,
                             int heap_fd, const m11_shmem_native_sys *sys,
                             m11_shmem_backend_t *out);

/* 1 when `fd` is a dma-buf this link allocated and the ION fd list holds it, else 0. */
int m11_shmem_native_imported(const m11_shmem_native_link *link, int fd);
/* Number of dma-buf fds this link still holds. */
unsigned m11_shmem_native_held(const m11_shmem_native_link *link);

#endif
