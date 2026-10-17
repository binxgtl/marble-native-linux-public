/* G3 native shmem backend — see shmem_backend_native.h. */
#define _GNU_SOURCE
#include "shmem_backend_native.h"
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

static int libc_ioctl(int fd, unsigned long req, void *arg) { return ioctl(fd, req, arg); }
const m11_shmem_native_sys m11_shmem_native_libc = {
    .ioctl_fn = libc_ioctl, .mmap_fn = mmap, .munmap_fn = munmap, .close_fn = close,
};

static int bound(m11_shmem_native_link *l) {
    if (l->bound_pid != getpid()) { l->refused++; return 0; }
    return 1;
}

static m11_shmem_native_buf *find(m11_shmem_native_link *l, int fd) {
    if (fd < 0) return NULL;
    for (size_t i = 0; i < M11_SHMEM_NATIVE_MAX_BUFS; i++)
        if (l->bufs[i].fd == fd) return &l->bufs[i];
    return NULL;
}

/* The ION fd is usable only while this process holds the anchor alone. */
static int ion_fd(m11_shmem_native_link *l) {
    const m11_pid1_anchor *a = l->ion_anchor;
    if (!a || a->state != M11_ANCHOR_HELD || a->anchor_fd < 0 || a->owner_pid != getpid()) {
        l->refused++;
        return -EBADF;
    }
    return a->anchor_fd;
}

static int b_alloc(void *user, size_t aligned_bytes, int *out_dma_fd) {
    m11_shmem_native_link *l = user;
    if (!out_dma_fd) return -EINVAL;
    *out_dma_fd = -1;
    if (!bound(l)) return -EPERM;
    if (!aligned_bytes || aligned_bytes % M11_SHMEM_PAGE_ALIGNMENT) return -EINVAL;
    m11_shmem_native_buf *slot = NULL;
    for (size_t i = 0; !slot && i < M11_SHMEM_NATIVE_MAX_BUFS; i++)
        if (l->bufs[i].fd < 0) slot = &l->bufs[i];
    if (!slot) return -ENOSPC;
    m11_dma_heap_allocation_data d = {.len = aligned_bytes, .fd = 0,
                                      .fd_flags = O_RDWR | O_CLOEXEC, .heap_flags = 0};
    int rc;
    do rc = l->sys->ioctl_fn(l->heap_fd, M11_DMA_HEAP_IOCTL_ALLOC, &d); while (rc < 0 && errno == EINTR);
    if (rc < 0) return -errno;
    int fd = (int)d.fd;
    if (fd < 0 || find(l, fd)) {
        /* A table collision cannot come from the kernel; refuse it and leave the number alone. */
        l->refused++;
        return -EPROTO;
    }
    *slot = (m11_shmem_native_buf){.fd = fd, .len = aligned_bytes, .vaddr = NULL, .imported = 0};
    l->allocs++;
    *out_dma_fd = fd;
    return 0;
}

static void *b_mmap(void *user, int dma_fd, size_t aligned_bytes) {
    m11_shmem_native_link *l = user;
    if (!bound(l)) return NULL;
    m11_shmem_native_buf *b = find(l, dma_fd);
    if (!b || b->vaddr || aligned_bytes != b->len) { l->refused++; return NULL; }
    void *p = l->sys->mmap_fn(NULL, b->len, PROT_READ | PROT_WRITE, MAP_SHARED, b->fd, 0);
    if (p == MAP_FAILED || !p) return NULL;
    b->vaddr = p;
    l->maps++;
    return p;
}

static int b_munmap(void *user, void *vaddr, size_t aligned_bytes) {
    m11_shmem_native_link *l = user;
    if (!bound(l)) return -EPERM;
    m11_shmem_native_buf *b = NULL;
    for (size_t i = 0; vaddr && i < M11_SHMEM_NATIVE_MAX_BUFS; i++)
        if (l->bufs[i].fd >= 0 && l->bufs[i].vaddr == vaddr) b = &l->bufs[i];
    if (!b || aligned_bytes != b->len) { l->refused++; return -EINVAL; }
    if (l->sys->munmap_fn(b->vaddr, b->len) < 0) return -errno;
    b->vaddr = NULL;
    l->unmaps++;
    return 0;
}

static int b_sync(void *user, int dma_fd, uint64_t sync_flags) {
    m11_shmem_native_link *l = user;
    if (!bound(l)) return -EPERM;
    m11_shmem_native_buf *b = find(l, dma_fd);
    if (!b) { l->refused++; return -EBADF; }
    if (sync_flags != M11_DMA_BUF_SYNC_START_RW && sync_flags != M11_DMA_BUF_SYNC_END_RW) {
        l->refused++;
        return -EINVAL;
    }
    m11_dma_buf_sync s = {.flags = sync_flags};
    int rc;
    do rc = l->sys->ioctl_fn(b->fd, M11_DMA_BUF_IOCTL_SYNC, &s); while (rc < 0 && errno == EINTR);
    if (rc < 0) return -errno;
    l->syncs++;
    return 0;
}

static int b_import(void *user, int dma_fd, bool hyp_assign) {
    m11_shmem_native_link *l = user;
    if (!bound(l)) return -EPERM;
    if (hyp_assign) { l->hyp_refused++; return -EPERM; } /* never issues 0x4004616D */
    m11_shmem_native_buf *b = find(l, dma_fd);
    if (!b || b->imported) { l->refused++; return -EBADF; }
    int ion = ion_fd(l);
    if (ion < 0) return ion;
    /* _IOW('a', 97, int) with the dma-buf fd passed by value (m11_shmem.h). */
    if (l->sys->ioctl_fn(ion, M11_MSM_AUDIO_ION_MAP_PHYS, (void *)(uintptr_t)(unsigned)b->fd) < 0)
        return -errno;
    b->imported = 1;
    l->imports++;
    return 0;
}

static int b_unimport(void *user, int dma_fd, bool hyp_assign) {
    m11_shmem_native_link *l = user;
    if (!bound(l)) return -EPERM;
    if (hyp_assign) { l->hyp_refused++; return -EPERM; } /* never issues 0x4004616E */
    m11_shmem_native_buf *b = find(l, dma_fd);
    if (!b || !b->imported) { l->refused++; return -EBADF; }
    int ion = ion_fd(l);
    if (ion < 0) return ion;
    if (l->sys->ioctl_fn(ion, M11_MSM_AUDIO_ION_UNMAP, (void *)(uintptr_t)(unsigned)b->fd) < 0)
        return -errno;
    b->imported = 0;
    l->unimports++;
    return 0;
}

static int b_close(void *user, int dma_fd) {
    m11_shmem_native_link *l = user;
    if (!bound(l)) return -EPERM;
    m11_shmem_native_buf *b = find(l, dma_fd);
    if (!b) { l->refused++; return -EBADF; }
    if (b->vaddr || b->imported) { l->refused++; return -EBUSY; }
    int fd = b->fd;
    *b = (m11_shmem_native_buf){.fd = -1};
    /* consumed: the descriptor is released whatever close(2) reports; never retried */
    if (l->sys->close_fn(fd) < 0) { l->close_errors++; l->last_close_errno = errno; }
    l->closes++;
    return 0;
}

int m11_shmem_native_backend(m11_shmem_native_link *link, const m11_pid1_anchor *ion_anchor,
                             int heap_fd, const m11_shmem_native_sys *sys,
                             m11_shmem_backend_t *out) {
    if (!link || !ion_anchor || heap_fd < 0 || !out) return -EINVAL;
    memset(link, 0, sizeof *link);
    for (size_t i = 0; i < M11_SHMEM_NATIVE_MAX_BUFS; i++) link->bufs[i].fd = -1;
    link->ion_anchor = ion_anchor;
    link->heap_fd = heap_fd;
    link->bound_pid = getpid();
    link->sys = sys ? sys : &m11_shmem_native_libc;
    *out = (m11_shmem_backend_t){
        .dma_heap_alloc_fn = b_alloc, .mmap_fn = b_mmap, .munmap_fn = b_munmap,
        .close_fd_fn = b_close, .dma_buf_sync_fn = b_sync,
        .ion_import_fd_fn = b_import, .ion_unmap_fd_fn = b_unimport, .user = link,
    };
    return 0;
}

int m11_shmem_native_imported(const m11_shmem_native_link *link, int fd) {
    if (!link || fd < 0) return 0;
    for (size_t i = 0; i < M11_SHMEM_NATIVE_MAX_BUFS; i++)
        if (link->bufs[i].fd == fd) return link->bufs[i].imported;
    return 0;
}

unsigned m11_shmem_native_held(const m11_shmem_native_link *link) {
    unsigned n = 0;
    for (size_t i = 0; link && i < M11_SHMEM_NATIVE_MAX_BUFS; i++) n += link->bufs[i].fd >= 0;
    return n;
}
