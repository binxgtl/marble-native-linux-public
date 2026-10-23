/* G3 stand-in test: the native shmem backend against a fixture syscall table (memfd-backed
 * dma-bufs, a recorded ION fd list), then the REAL region manager and engine over the G2 transport
 * with a forked peer answering MAP/UNMAP on a SOCK_SEQPACKET endpoint stand-in. No device, driver
 * or kernel module; the ION ioctl numbers reach only the fixture. */
#ifndef M11_CUSTODIAN_NATIVE
#error "test-shmem-backend-native.c builds only with M11_CUSTODIAN_NATIVE"
#endif
#define _GNU_SOURCE
#include "shmem_backend_native.h"
#include "gpr_transport_native.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

/* ---- fixture syscalls ---- */
#define FX_MAX 64
static struct {
    int heap_fd, ion_fd;
    int live[FX_MAX];        /* memfds handed out as dma-bufs and not yet closed */
    int imported[FX_MAX];    /* the stand-in ION fd list, keyed by fd number like the driver */
    int fail_alloc_errno, close_fail;
    unsigned allocs, syncs, ion_calls, hyp_calls, closes, mmaps;
    uint64_t last_sync;
} fx;

static int fx_dmabuf(int fd) { return fd >= 0 && fd < FX_MAX && fx.live[fd]; }

static int fx_ioctl(int fd, unsigned long req, void *arg) {
    switch (req) {
    case M11_DMA_HEAP_IOCTL_ALLOC: {
        m11_dma_heap_allocation_data *d = arg;
        assert(fd == fx.heap_fd);
        assert(d->fd_flags == (O_RDWR | O_CLOEXEC) && d->heap_flags == 0 && d->len % 4096 == 0);
        if (fx.fail_alloc_errno) { errno = fx.fail_alloc_errno; return -1; }
        int m = memfd_create("m11-dmabuf", MFD_CLOEXEC);
        assert(m >= 0 && m < FX_MAX && ftruncate(m, (off_t)d->len) == 0);
        fx.live[m] = 1; d->fd = (uint32_t)m; fx.allocs++;
        return 0;
    }
    case M11_DMA_BUF_IOCTL_SYNC:
        assert(fx_dmabuf(fd));
        fx.last_sync = ((m11_dma_buf_sync *)arg)->flags; fx.syncs++;
        return 0;
    case M11_MSM_AUDIO_ION_MAP_PHYS: {
        int v = (int)(uintptr_t)arg;
        assert(fd == fx.ion_fd && fx_dmabuf(v) && !fx.imported[v]);
        fx.imported[v] = 1; fx.ion_calls++;
        return 0;
    }
    case M11_MSM_AUDIO_ION_UNMAP: {
        int v = (int)(uintptr_t)arg;
        assert(fd == fx.ion_fd && fx_dmabuf(v) && fx.imported[v]);
        fx.imported[v] = 0; fx.ion_calls++;
        return 0;
    }
    case M11_MSM_AUDIO_ION_MAP_HYP_ASSIGN:
    case M11_MSM_AUDIO_ION_UNMAP_HYP:
        fx.hyp_calls++; errno = EPERM; return -1;
    default:
        errno = ENOTTY; return -1;
    }
}
static void *fx_mmap(void *a, size_t len, int prot, int flags, int fd, off_t off) {
    assert(fx_dmabuf(fd) && prot == (PROT_READ | PROT_WRITE) && flags == MAP_SHARED && off == 0);
    fx.mmaps++;
    return mmap(a, len, prot, flags, fd, off);
}
static int fx_munmap(void *a, size_t len) { return munmap(a, len); }
static int fx_close(int fd) {
    assert(fx_dmabuf(fd) && !fx.imported[fd]); /* the backend never drops an imported buffer */
    fx.live[fd] = 0; fx.closes++;
    int rc = close(fd);
    if (fx.close_fail) { errno = EIO; return -1; } /* Linux: released anyway */
    return rc;
}
static const m11_shmem_native_sys fx_sys = {fx_ioctl, fx_mmap, fx_munmap, fx_close};

static m11_pid1_anchor ion_anchor;
static void fx_reset(void) {
    if (fx.heap_fd > 0) close(fx.heap_fd);
    if (fx.ion_fd > 0) close(fx.ion_fd);
    memset(&fx, 0, sizeof fx);
    fx.heap_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
    fx.ion_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
    assert(fx.heap_fd >= 0 && fx.ion_fd >= 0);
    memset(&ion_anchor, 0, sizeof ion_anchor);
    ion_anchor.state = M11_ANCHOR_HELD; ion_anchor.anchor_fd = fx.ion_fd; ion_anchor.owner_pid = getpid();
}
static int fd_open(int fd) { return fcntl(fd, F_GETFD) != -1; }

/* ---- DSP peer for the end-to-end cases; its exit status is the number of packets it took ---- */
enum peer_mode { ANSWER, SILENT };
static void peer(int fd, enum peer_mode mode) {
    alarm(10);
    int got = 0;
    for (;;) {
        uint8_t rx[M11_GPR_MAX_PKT_BYTES];
        ssize_t n = recv(fd, rx, sizeof rx, 0);
        if (n <= 0) _exit(got);
        got++;
        if (mode == SILENT) continue;
        m11_gpr_hdr_t h; const uint8_t *pl; size_t pll;
        if (m11_gpr_validate_packet(rx, (size_t)n, &h, &pl, &pll) < 0) _exit(100);
        uint8_t tx[64]; size_t txl = 0; int rc;
        if (h.opcode == M11_APM_CMD_SHARED_MEM_MAP_REGIONS) {
            m11_apm_cmd_shared_mem_map_regions_t c;
            if (pll != sizeof c || h.client_data != M11_GPR_CLIENT_DATA_SHMEM_OFFSET_MODE) _exit(101);
            memcpy(&c, pl, sizeof c);
            if (c.mem_pool_id != 3 || c.num_regions != 1 || c.property_flag != M11_APM_MEMORY_MAP_OFFSET_MODE ||
                c.shm_addr_msw != 0 || c.mem_size_bytes != 4096) _exit(102);
            /* No kernel here rewrites shm_addr_lsw: it still carries the dma-buf fd number, which
             * the handle echoes so the test can compare it with the fd the ION list imported. */
            m11_apm_rsp_shared_mem_map_t r = {.mem_map_handle = 0xA0000000u | c.shm_addr_lsw};
            rc = m11_gpr_pack_packet_ex(tx, sizeof tx, &txl, M11_GPR_DOMAIN_APPS, M11_GPR_DOMAIN_ADSP, 0,
                                        h.src_port, h.dst_port, h.token,
                                        M11_APM_CMDRSP_SHARED_MEM_MAP_REGIONS, &r, sizeof r);
        } else if (h.opcode == M11_APM_CMD_SHARED_MEM_UNMAP_REGIONS) {
            m11_gpr_ibasic_rsp_t r = {.cmd_opcode = h.opcode, .status = 0};
            rc = m11_gpr_pack_packet_ex(tx, sizeof tx, &txl, M11_GPR_DOMAIN_APPS, M11_GPR_DOMAIN_ADSP, 0,
                                        h.src_port, h.dst_port, h.token,
                                        M11_GPR_IBASIC_RSP_RESULT, &r, sizeof r);
        } else {
            _exit(103);
        }
        if (rc < 0 || send(fd, tx, txl, 0) != (ssize_t)txl) _exit(104);
    }
}

struct rig { int sv[2]; pid_t pid; m11_pid1_anchor ep; m11_gpr_native_link glink;
             m11_gpr_transport_t t; m11_gpr_engine_t eng; m11_shmem_native_link slink;
             m11_shmem_backend_t b; m11_shmem_mgr_t mgr; };
static void rig_start(struct rig *r, enum peer_mode mode) {
    memset(r, 0, sizeof *r);
    fx_reset();
    assert(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, r->sv) == 0);
    r->pid = fork(); assert(r->pid >= 0);
    if (r->pid == 0) { close(r->sv[0]); peer(r->sv[1], mode); }
    close(r->sv[1]);
    r->ep.state = M11_ANCHOR_HELD; r->ep.anchor_fd = r->sv[0]; r->ep.owner_pid = getpid();
    assert(m11_gpr_native_transport(&r->glink, &r->ep, &r->t) == 0);
    assert(m11_gpr_engine_init(&r->eng, &r->t, 0x0100u) == 0 && m11_gpr_engine_open(&r->eng) == 0);
    assert(m11_shmem_native_backend(&r->slink, &ion_anchor, fx.heap_fd, &fx_sys, &r->b) == 0);
    assert(m11_shmem_mgr_init(&r->mgr, &r->b, &r->eng, 300) == 0);
}
static int rig_stop(struct rig *r) { /* returns the number of packets the peer took */
    close(r->sv[0]);
    int st; assert(waitpid(r->pid, &st, 0) == r->pid && WIFEXITED(st));
    return WEXITSTATUS(st);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGPIPE, SIG_IGN);
    m11_shmem_native_link l; m11_shmem_backend_t b; int fd = -1; void *p;

    /* 1. bind argument checks. */
    fx_reset();
    assert(m11_shmem_native_backend(NULL, &ion_anchor, fx.heap_fd, &fx_sys, &b) == -EINVAL);
    assert(m11_shmem_native_backend(&l, NULL, fx.heap_fd, &fx_sys, &b) == -EINVAL);
    assert(m11_shmem_native_backend(&l, &ion_anchor, -1, &fx_sys, &b) == -EINVAL);
    assert(m11_shmem_native_backend(&l, &ion_anchor, fx.heap_fd, &fx_sys, NULL) == -EINVAL);
    printf("PASS bind refuses NULLs and a negative heap fd\n");

    /* 2. full local round trip. */
    assert(m11_shmem_native_backend(&l, &ion_anchor, fx.heap_fd, &fx_sys, &b) == 0);
    assert(b.dma_heap_alloc_fn(b.user, 4096, &fd) == 0 && fx_dmabuf(fd) && m11_shmem_native_held(&l) == 1);
    assert((p = b.mmap_fn(b.user, fd, 4096)) != NULL);
    assert(b.mmap_fn(b.user, fd, 4096) == NULL); /* one mapping per fd */
    assert(b.dma_buf_sync_fn(b.user, fd, M11_DMA_BUF_SYNC_START_RW) == 0 && fx.last_sync == 0x3);
    memset(p, 0x5A, 4096);
    assert(b.dma_buf_sync_fn(b.user, fd, M11_DMA_BUF_SYNC_END_RW) == 0 && fx.last_sync == 0x7);
    assert(b.ion_import_fd_fn(b.user, fd, false) == 0 && fx.imported[fd] && m11_shmem_native_imported(&l, fd));
    assert(b.ion_import_fd_fn(b.user, fd, false) == -EBADF); /* never imported twice */
    assert(b.ion_unmap_fd_fn(b.user, fd, false) == 0 && !fx.imported[fd]);
    assert(b.munmap_fn(b.user, p, 4096) == 0);
    assert(b.close_fd_fn(b.user, fd) == 0 && !fd_open(fd) && m11_shmem_native_held(&l) == 0);
    assert(l.close_errors == 0 && fx.ion_calls == 2 && fx.hyp_calls == 0);
    printf("PASS alloc/mmap/sync/import/unimport/munmap/close round trip on a memfd-backed fixture\n");

    /* 3. hyp_assign is refused before any ioctl. */
    assert(b.dma_heap_alloc_fn(b.user, 4096, &fd) == 0);
    unsigned ion_before = fx.ion_calls;
    assert(b.ion_import_fd_fn(b.user, fd, true) == -EPERM);
    assert(fx.hyp_calls == 0 && fx.ion_calls == ion_before && !fx.imported[fd] && l.hyp_refused == 1);
    assert(b.ion_unmap_fd_fn(b.user, fd, true) == -EPERM && fx.hyp_calls == 0);
    printf("PASS hyp_assign refused; no hyp-assign ioctl issued\n");

    /* 4. sync flags. */
    unsigned syncs = fx.syncs;
    assert(b.dma_buf_sync_fn(b.user, fd, M11_DMA_BUF_SYNC_READ) == -EINVAL);
    assert(b.dma_buf_sync_fn(b.user, fd, M11_DMA_BUF_SYNC_END) == -EINVAL);
    assert(b.dma_buf_sync_fn(b.user, fd, 0x8) == -EINVAL && fx.syncs == syncs);
    printf("PASS sync accepts only START|RW and END|RW\n");

    /* 5. foreign fd numbers: the heap fd and a never-allocated number. */
    int heap = fx.heap_fd;
    assert(b.dma_buf_sync_fn(b.user, heap, M11_DMA_BUF_SYNC_START_RW) == -EBADF);
    assert(b.ion_import_fd_fn(b.user, heap, false) == -EBADF);
    assert(b.close_fd_fn(b.user, heap) == -EBADF && fd_open(heap));
    assert(b.mmap_fn(b.user, heap, 4096) == NULL);
    assert(b.close_fd_fn(b.user, 1000) == -EBADF && fx.syncs == syncs && fx.closes == 1);
    printf("PASS foreign fd numbers refused before any syscall\n");

    /* 6. close is refused while the buffer is mmapped or imported. */
    assert((p = b.mmap_fn(b.user, fd, 4096)) != NULL);
    assert(b.close_fd_fn(b.user, fd) == -EBUSY && fd_open(fd));
    assert(b.munmap_fn(b.user, p, 4096) == 0);
    assert(b.ion_import_fd_fn(b.user, fd, false) == 0);
    assert(b.close_fd_fn(b.user, fd) == -EBUSY && fd_open(fd) && fx.imported[fd]);
    printf("PASS close refused while mmapped or imported\n");

    /* 7. ION I/O needs the ION anchor HELD by this process. */
    ion_before = fx.ion_calls;
    ion_anchor.state = M11_ANCHOR_LENT;
    assert(b.ion_unmap_fd_fn(b.user, fd, false) == -EBADF);
    ion_anchor.state = M11_ANCHOR_HELD; ion_anchor.owner_pid = getpid() + 1;
    assert(b.ion_unmap_fd_fn(b.user, fd, false) == -EBADF);
    ion_anchor.owner_pid = getpid(); ion_anchor.state = M11_ANCHOR_OWNER_FDS_DROPPED;
    assert(b.ion_unmap_fd_fn(b.user, fd, false) == -EBADF);
    assert(fx.ion_calls == ion_before && fx.imported[fd]);
    ion_anchor.state = M11_ANCHOR_HELD;
    assert(b.ion_unmap_fd_fn(b.user, fd, false) == 0 && !fx.imported[fd]);
    printf("PASS ION I/O refused unless the ION anchor is HELD by this process\n");

    /* 8. a failing close(2) still consumed the fd: success, counted, never retried. */
    fx.close_fail = 1;
    unsigned closes = fx.closes;
    assert(b.close_fd_fn(b.user, fd) == 0);
    assert(!fd_open(fd) && l.close_errors == 1 && l.last_close_errno == EIO && m11_shmem_native_held(&l) == 0);
    assert(b.close_fd_fn(b.user, fd) == -EBADF && fx.closes == closes + 1);
    fx.close_fail = 0;
    printf("PASS close(2) failure is a consumed fd: reported as success, counted, never retried\n");

    /* 9. allocation failure and a full table. */
    fx.fail_alloc_errno = ENOMEM;
    assert(b.dma_heap_alloc_fn(b.user, 4096, &fd) == -ENOMEM && fd == -1 && m11_shmem_native_held(&l) == 0);
    fx.fail_alloc_errno = 0;
    assert(b.dma_heap_alloc_fn(b.user, 100, &fd) == -EINVAL); /* unaligned */
    int many[M11_SHMEM_NATIVE_MAX_BUFS];
    for (int i = 0; i < M11_SHMEM_NATIVE_MAX_BUFS; i++) assert(b.dma_heap_alloc_fn(b.user, 4096, &many[i]) == 0);
    unsigned allocs = fx.allocs;
    assert(b.dma_heap_alloc_fn(b.user, 4096, &fd) == -ENOSPC && fx.allocs == allocs);
    for (int i = 0; i < M11_SHMEM_NATIVE_MAX_BUFS; i++) assert(b.close_fd_fn(b.user, many[i]) == 0);
    printf("PASS allocation failure, unaligned size and a full table leave nothing held\n");

    /* 10. production syscalls: the real DMA_HEAP ioctl on a non-heap node fails cleanly. */
    m11_shmem_native_link real; m11_shmem_backend_t rb;
    assert(m11_shmem_native_backend(&real, &ion_anchor, fx.heap_fd, NULL, &rb) == 0 && real.sys == &m11_shmem_native_libc);
    assert(rb.dma_heap_alloc_fn(rb.user, 4096, &fd) == -ENOTTY && fd == -1 && m11_shmem_native_held(&real) == 0);
    printf("PASS libc backend: DMA_HEAP_IOCTL_ALLOC on a non-heap node returns -ENOTTY, nothing held\n");

    /* 11. another process cannot use the link (its fd table is not PID1's). */
    assert(b.dma_heap_alloc_fn(b.user, 4096, &fd) == 0);
    pid_t c = fork(); assert(c >= 0);
    if (c == 0) {
        int x = -1;
        _exit(b.dma_heap_alloc_fn(b.user, 4096, &x) == -EPERM && b.close_fd_fn(b.user, fd) == -EPERM &&
              b.ion_import_fd_fn(b.user, fd, false) == -EPERM ? 0 : 1);
    }
    int st; assert(waitpid(c, &st, 0) == c && WIFEXITED(st) && WEXITSTATUS(st) == 0);
    assert(fd_open(fd) && b.close_fd_fn(b.user, fd) == 0);
    printf("PASS a forked process is refused by the link\n");

    /* 12. end to end: the MAP names the same fd number the ION list imported; the UNMAP research
     * path (driven directly) is ACKed but releases nothing: post-MAP hold (CP2 criterion 5). */
    struct rig r; m11_shmem_region_t reg;
    rig_start(&r, ANSWER);
    assert(m11_shmem_alloc_and_map(&r.mgr, M11_SHMEM_MODE_DMA_ION_OFFSET, 100, false, &reg) == 0);
    assert(reg.state == M11_SHMEM_STATE_DSP_MAP_ACKNOWLEDGED);
    assert(reg.mem_map_handle == (0xA0000000u | (uint32_t)reg.dma_buf_fd));
    assert(fx.imported[reg.dma_buf_fd] && m11_shmem_native_imported(&r.slink, reg.dma_buf_fd));
    memset(reg.vaddr, 0x11, 4096);
    assert(m11_shmem_end_cpu_access(&r.mgr, &reg) == 0 && reg.cpu_cache_clean_for_dsp);
    int mapped_fd = reg.dma_buf_fd;
    assert(m11_shmem_unmap_and_free(&r.mgr, &reg) == -EPERM && reg.state == M11_SHMEM_STATE_DSP_UNMAP_ACKNOWLEDGED);
    assert(reg.map_tx_started && !reg.map_tx_unsent_proof && reg.dma_buf_fd == mapped_fd && reg.vaddr && reg.ion_imported);
    assert(fx.imported[mapped_fd] && fd_open(mapped_fd) && m11_shmem_native_held(&r.slink) == 1);
    memset(reg.vaddr, 0x33, 4096); /* the backing is still mapped */
    assert(m11_shmem_unmap_and_free(&r.mgr, &reg) == -EPERM && fd_open(mapped_fd)); /* a retry releases nothing either */
    assert(m11_shmem_mgr_audit(&r.mgr, &reg, 1) == 0 && reg.cleanup_error == 0);
    assert(rig_stop(&r) == 2);
    printf("PASS end to end: MAP carries the imported fd number; the UNMAP research path's ACK releases nothing (post-MAP hold): import, mapping and fd retained\n");

    /* 12b. end to end: a submit refused before write_fn (engine closed: NOT_ATTEMPTED) is the only
     * post-intent failure that releases; the native unimport, munmap and close all run. */
    rig_start(&r, ANSWER);
    assert(m11_gpr_engine_close(&r.eng) == 0);
    assert(m11_shmem_alloc_and_map(&r.mgr, M11_SHMEM_MODE_DMA_ION_OFFSET, 4096, false, &reg) < 0);
    assert(r.eng.last_tx_status == M11_GPR_TX_NOT_ATTEMPTED && reg.map_tx_started && reg.map_tx_unsent_proof);
    assert(reg.state == M11_SHMEM_STATE_RELEASED && reg.dma_buf_fd < 0 && !reg.vaddr && !reg.ion_imported);
    assert(m11_shmem_native_held(&r.slink) == 0 && m11_shmem_mgr_audit(&r.mgr, &reg, 1) == 0 && reg.cleanup_error == 0);
    assert(rig_stop(&r) == 0);
    printf("PASS end to end: a MAP refused before write_fn (proven unsent) releases import, mapping and fd; nothing sent\n");

    /* 13. end to end: no MAP answer -> ownership unresolved, every local handle retained. */
    rig_start(&r, SILENT);
    assert(m11_shmem_alloc_and_map(&r.mgr, M11_SHMEM_MODE_DMA_ION_OFFSET, 4096, false, &reg) == -ETIMEDOUT);
    assert(reg.state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED);
    assert(m11_shmem_unmap_and_free(&r.mgr, &reg) == -EBUSY);
    assert(fx.imported[reg.dma_buf_fd] && fd_open(reg.dma_buf_fd) && reg.vaddr && m11_shmem_native_held(&r.slink) == 1);
    memset(reg.vaddr, 0x22, 4096); /* the backing is still mapped */
    assert(m11_shmem_mgr_audit(&r.mgr, &reg, 1) == 0);
    assert(rig_stop(&r) == 1);
    printf("PASS end to end: unanswered MAP leaves the region unresolved with import, mapping and fd retained\n");

    /* 14. end to end: hyp_assign through the manager is refused before anything is sent. */
    rig_start(&r, SILENT);
    assert(m11_shmem_alloc_and_map(&r.mgr, M11_SHMEM_MODE_DMA_ION_OFFSET, 4096, true, &reg) == -EPERM);
    assert(reg.state == M11_SHMEM_STATE_RELEASED && m11_shmem_native_held(&r.slink) == 0 && fx.hyp_calls == 0);
    assert(rig_stop(&r) == 0);
    printf("PASS end to end: hyp_assign refused before any packet; local handles released\n");

    printf("PASS G3 native shmem backend (fixture syscalls, real manager and engine over the G2 transport)\n");
    return 0;
}
