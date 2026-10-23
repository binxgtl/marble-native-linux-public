#ifndef M11_RUNTIME_REPAIR_SHMEM_H
#define M11_RUNTIME_REPAIR_SHMEM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "m11_gpr_engine.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Stock marble /dev/msm_audio_ion ioctl numbers.
 * Verified against:
 *   - audpkt_ion_dlkm.ko (audpkt_ion_ioctl @ 0x1017bc)
 *   - liblx-osal.so (ar_osal_shmem_alloc_and_map @ 0x1328c, free_and_unmap @ 0x13490)
 * Note: 0x40046161 is _IOW('a', 97, int) and takes the DMA-BUF fd by value;
 * it imports the DMA-BUF into kernel msm_audio_ion_fd_list and does NOT write
 * a physical address back to userspace.
 */
#define M11_MSM_AUDIO_ION_MAP_PHYS       0x40046161u
#define M11_MSM_AUDIO_ION_UNMAP          0x40046162u
#define M11_MSM_AUDIO_ION_MAP_HYP_ASSIGN 0x4004616Du
#define M11_MSM_AUDIO_ION_UNMAP_HYP      0x4004616Eu

/*
 * DMA_BUF_IOCTL_SYNC evidence, kept separate on purpose (P5 audit):
 *   BINARY (instruction words recorded in test_runtime_repair_py.py, not re-verified
 *   against the ROM in the hardening session): liblx-osal.so ar_shmem_alloc issues
 *   ioctl(dma_fd, 0x40086200, {flags = 0x3 START|RW}) and ar_shmem_free issues
 *   {flags = 0x7 END|RW} before munmap. Nothing recorded shows stock calling END before
 *   a GRAPH_OPEN; stock keeps the bracket open from allocation to free.
 *   LINUX SEMANTICS (inferred): END on a buffer attached through 0x40046161 syncs the CPU
 *   cache for the attached device, so END before the ADSP reads CPU-written data is a
 *   sound ordering for a cached /dev/dma_heap/system buffer.
 *   MOCK ASSUMPTION: m11_strict_mock.c rejects GRAPH_OPEN while the bracket is open. A
 *   real ADSP cannot observe the CPU bracket, so that rule is test scaffolding, not a
 *   hardware fact.
 *   HARDWARE UNKNOWN: whether marble needs END before the ADSP reads, and whether stock
 *   works without it. The END-before-GRAPH_OPEN order below is a PROPOSED design.
 */
#define M11_DMA_BUF_IOCTL_SYNC      0x40086200u /* _IOW('b', 0, struct dma_buf_sync) */
#define M11_DMA_BUF_SYNC_READ       (1ULL << 0)
#define M11_DMA_BUF_SYNC_WRITE      (2ULL << 0)
#define M11_DMA_BUF_SYNC_RW         (M11_DMA_BUF_SYNC_READ | M11_DMA_BUF_SYNC_WRITE) /* 0x3 */
#define M11_DMA_BUF_SYNC_START      (0ULL << 2)
#define M11_DMA_BUF_SYNC_END        (1ULL << 2) /* 0x4 */
#define M11_DMA_BUF_SYNC_START_RW   (M11_DMA_BUF_SYNC_START | M11_DMA_BUF_SYNC_RW)   /* 0x3 */
#define M11_DMA_BUF_SYNC_END_RW     (M11_DMA_BUF_SYNC_END   | M11_DMA_BUF_SYNC_RW)   /* 0x7 */

/*
 * APM Shared Memory Map constants.
 * Verified against:
 *   - apm_memmap_api.h (APM_MEMORY_MAP_SHMEM8_4K_POOL = 3)
 *   - libar-gsl.so (gsl_shmem_map_page_to_spf @ 0x00125370: mov w8, #3; mov w9, #4)
 *   - audio_pkt_dlkm.ko (audpkt_chk_and_update_physical_addr @ 0x1001f4)
 */
#define M11_APM_MEMORY_MAP_SHMEM8_4K_POOL 3u
#define M11_APM_MEMORY_MAP_IS_VIRTUAL     0x00000001u /* Bit 0: Virtual (FORBIDDEN on marble) */
#define M11_APM_MEMORY_MAP_UNCACHED       0x00000002u /* Bit 1: Uncached */
#define M11_APM_MEMORY_MAP_OFFSET_MODE    0x00000004u /* Bit 2: Offset mode (REQUIRED on marble) */

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(M11_APM_MEMORY_MAP_SHMEM8_4K_POOL == 3u,
               "APM_MEMORY_MAP_SHMEM8_4K_POOL must equal 3 per apm_memmap_api.h and libar-gsl.so");
#endif

#define M11_SHMEM_PAGE_ALIGNMENT          4096u

typedef enum {
    M11_SHMEM_MODE_DMA_ION_OFFSET = 0,
    M11_SHMEM_MODE_VIRTUAL_INCOMPATIBLE = 1, /* Upstream ar_osal_shmem_virtual.c (REJECTED) */
} m11_shmem_mode_t;

/*
 * Explicit 10-state shared-memory resource ownership state machine.
 *
 * Remote ownership (does the ADSP still map these pages?) and local cleanup (are the
 * dma-buf fd / mmap / msm_audio_ion import still held?) are tracked separately:
 *   OWNERSHIP_UNRESOLVED        remote mapping state is UNKNOWN; never release anything.
 *   LOCAL_RELEASE_PENDING       remote ownership is PROVEN gone (never sent, explicit NACK,
 *                               or UNMAP ACK); only local handles remain and release may be
 *                               retried without sending another DSP command.
 */
typedef enum {
    M11_SHMEM_STATE_NOT_ALLOCATED = 0,
    M11_SHMEM_STATE_ALLOCATED = 1,
    M11_SHMEM_STATE_KERNEL_IMPORT_ESTABLISHED = 2,
    M11_SHMEM_STATE_DSP_MAP_REQUESTED = 3,
    M11_SHMEM_STATE_DSP_MAP_ACKNOWLEDGED = 4,
    M11_SHMEM_STATE_DSP_UNMAP_REQUESTED = 5,
    M11_SHMEM_STATE_DSP_UNMAP_ACKNOWLEDGED = 6,
    M11_SHMEM_STATE_RELEASED = 7,
    M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED = 8,
    M11_SHMEM_STATE_LOCAL_RELEASE_PENDING = 9,
} m11_shmem_state_t;

/* Why remote ownership is unresolved, or why local release is pending. */
typedef enum {
    M11_SHMEM_CAUSE_NONE = 0,
    M11_SHMEM_CAUSE_MAP_WRITE_ERROR,     /* write_fn < 0 after MAP; packet fate unknown */
    M11_SHMEM_CAUSE_MAP_SHORT_WRITE,     /* write_fn short after MAP; packet fate unknown */
    M11_SHMEM_CAUSE_MAP_TIMEOUT,         /* MAP sent, no response inside the deadline */
    M11_SHMEM_CAUSE_MAP_TRANSPORT_ERR,   /* transport errno while waiting for the MAP response */
    M11_SHMEM_CAUSE_MAP_PDR,             /* ENETRESET: remote state cannot be determined */
    M11_SHMEM_CAUSE_MAP_AMBIGUOUS_RSP,   /* response without a usable mem_map_handle */
    M11_SHMEM_CAUSE_UNMAP_WRITE_ERROR,
    M11_SHMEM_CAUSE_UNMAP_SHORT_WRITE,
    M11_SHMEM_CAUSE_UNMAP_TIMEOUT,
    M11_SHMEM_CAUSE_UNMAP_TRANSPORT_ERR,
    M11_SHMEM_CAUSE_UNMAP_PDR,
    M11_SHMEM_CAUSE_UNMAP_NACK,          /* DSP refused UNMAP: mapping state unknown */
    M11_SHMEM_CAUSE_LOCAL_RELEASE_FAILED /* remote proven gone, a local step failed */
} m11_shmem_cause_t;

typedef enum {
    M11_SHMEM_ORPHAN_NONE = 0,
    M11_SHMEM_ORPHAN_MAP,
    M11_SHMEM_ORPHAN_UNMAP,
} m11_shmem_orphan_kind_t;

/*
 * Wire-exact 20-byte payload of APM_CMD_SHARED_MEM_MAP_REGIONS (0x0100100C) -> 44-byte GPR pkt.
 * In stock OFFSET_MODE (hdr.client_data == 1, property_flag == 0x4):
 *   - userspace sets shm_addr_lsw = (uint32_t)dma_buf_fd and shm_addr_msw = 0
 *   - kernel audio_pkt_dlkm.ko intercepts the packet on write(), resolves dma_buf_fd
 *     via audpkt_ion_dlkm.ko (msm_audio_get_phy_addr), and overwrites shm_addr_lsw/msw
 *     in-place with the DMA-BUF physical IOVA before gpr_send_pkt().
 */
typedef struct __attribute__((packed)) {
    uint16_t mem_pool_id;     /* +0x18 in pkt: 3 (APM_MEMORY_MAP_SHMEM8_4K_POOL) */
    uint16_t num_regions;     /* +0x1a in pkt: 1 */
    uint32_t property_flag;   /* +0x1c in pkt: 0x4 (OFFSET_MODE) */
    uint32_t shm_addr_lsw;    /* +0x20 in pkt: dma_buf_fd from userspace -> IOVA in kernel */
    uint32_t shm_addr_msw;    /* +0x24 in pkt: 0 from userspace -> IOVA high word in kernel */
    uint32_t mem_size_bytes;  /* +0x28 in pkt: 4096-byte aligned size */
} m11_apm_cmd_shared_mem_map_regions_t;

/* Wire-exact 4-byte payload of APM_CMD_SHARED_MEM_UNMAP_REGIONS (0x0100100D) -> 28-byte GPR pkt */
typedef struct __attribute__((packed)) {
    uint32_t mem_map_handle;  /* +0x18 in pkt */
} m11_apm_cmd_shared_mem_unmap_regions_t;

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(m11_apm_cmd_shared_mem_map_regions_t) == 20u,
               "m11_apm_cmd_shared_mem_map_regions_t must be 20 bytes");
_Static_assert(sizeof(m11_apm_cmd_shared_mem_unmap_regions_t) == 4u,
               "m11_apm_cmd_shared_mem_unmap_regions_t must be 4 bytes");
#endif

typedef struct {
    m11_shmem_state_t state;
    int               dma_buf_fd;
    void             *vaddr;
    size_t            requested_bytes;
    size_t            aligned_bytes;
    uint32_t          mem_map_handle;
    bool              ion_imported;
    bool              dsp_mapped;
    bool              hyp_assigned;
    bool              cpu_access_active;       /* true after DMA_BUF_SYNC_START_RW (0x3) */
    bool              cpu_cache_clean_for_dsp; /* true after DMA_BUF_SYNC_END_RW (0x7) post-write */
    uint32_t          sync_start_count;
    uint32_t          sync_end_count;
    uint32_t          sync_end_failures;       /* END_RW ioctls that returned an error (any path) */
    /*
     * last_error: the primary error of the path that produced the current state. It is NOT
     * overwritten by later refused releases (-EBUSY) or by cleanup failures. It is 0 while the
     * region is healthy (DSP_MAP_ACKNOWLEDGED) and keeps the history once RELEASED.
     * cleanup_error: the latest secondary error of a cleanup step (a failing local release
     * step, or a failing CPU-bracket close on an error path); never replaces last_error.
     */
    int               last_error;
    int               cleanup_error;
    /* Remote-ownership proof: true only while the ADSP is PROVEN not to map these pages. */
    bool              remote_inactive;
    /* Current reason for OWNERSHIP_UNRESOLVED / LOCAL_RELEASE_PENDING (reconcile may refine it). */
    m11_shmem_cause_t cause;
    /* Late-response correlation for an outstanding MAP/UNMAP (see m11_shmem_reconcile). */
    m11_shmem_orphan_kind_t orphan_kind;
    uint32_t          orphan_token;
    /* NULL when a late response can still resolve ownership; else why it cannot. */
    const char       *blocker;
    bool              counted_unresolved;      /* counted once in mgr->unresolved_regions */
    bool              counted_local_pending;   /* counted once in mgr->local_release_pending_regions */
} m11_shmem_region_t;

/*
 * Pluggable OS/driver backend modeling /dev/dma_heap/system and /dev/msm_audio_ion.
 * Notice ion_import_fd_fn takes dma_fd by value (matching ioctl 0x40046161) and
 * does NOT return a physical address to userspace.
 * dma_buf_sync_fn models ioctl(dma_fd, DMA_BUF_IOCTL_SYNC [0x40086200], &sync).
 */
typedef struct {
    int   (*dma_heap_alloc_fn)(void *user, size_t aligned_bytes, int *out_dma_fd);
    void *(*mmap_fn)(void *user, int dma_fd, size_t aligned_bytes);
    int   (*munmap_fn)(void *user, void *vaddr, size_t aligned_bytes);
    int   (*close_fd_fn)(void *user, int dma_fd);
    int   (*dma_buf_sync_fn)(void *user, int dma_fd, uint64_t sync_flags);
    int   (*ion_import_fd_fn)(void *user, int dma_fd, bool hyp_assign);
    int   (*ion_unmap_fd_fn)(void *user, int dma_fd, bool hyp_assign);
    void *user;
} m11_shmem_backend_t;

typedef struct {
    m11_shmem_backend_t backend;
    m11_gpr_engine_t   *gpr;
    uint32_t            timeout_ms;
    /* Accounting counters for leak & unresolved ownership detection */
    uint32_t            active_dma_fds;
    uint32_t            active_mmaps;
    uint32_t            active_ion_imports;
    uint32_t            active_dsp_maps;
    uint32_t            unresolved_regions;           /* remote ownership UNKNOWN */
    uint32_t            local_release_pending_regions; /* remote proven gone, local handles left */
} m11_shmem_mgr_t;

const char *m11_shmem_state_name(m11_shmem_state_t state);
size_t      m11_shmem_align_size(size_t requested_bytes);

int m11_shmem_pack_map_regions_pkt(uint8_t *out_buf, size_t out_cap, size_t *out_len,
                                   uint32_t src_port, uint32_t token,
                                   int dma_buf_fd, size_t aligned_bytes);

int m11_shmem_pack_unmap_regions_pkt(uint8_t *out_buf, size_t out_cap, size_t *out_len,
                                     uint32_t src_port, uint32_t token,
                                     uint32_t mem_map_handle);

int m11_shmem_mgr_init(m11_shmem_mgr_t *mgr, const m11_shmem_backend_t *backend,
                       m11_gpr_engine_t *gpr, uint32_t timeout_ms);

int m11_shmem_begin_cpu_access(m11_shmem_mgr_t *mgr, m11_shmem_region_t *region);
int m11_shmem_end_cpu_access(m11_shmem_mgr_t *mgr, m11_shmem_region_t *region);

int m11_shmem_alloc_and_map(m11_shmem_mgr_t *mgr, m11_shmem_mode_t mode,
                            size_t requested_bytes, bool hyp_assign,
                            m11_shmem_region_t *out_region);

/*
 * Releases a region. Safe to call repeatedly:
 *   - OWNERSHIP_UNRESOLVED / *_REQUESTED -> -EBUSY, nothing released (remote state unknown)
 *   - LOCAL_RELEASE_PENDING              -> retries ONLY the remaining local steps; no DSP
 *                                           command is sent again
 *   - DSP_MAP_ACKNOWLEDGED               -> sends one UNMAP; local release only after its ACK
 */
int m11_shmem_unmap_and_free(m11_shmem_mgr_t *mgr, m11_shmem_region_t *region);

/*
 * Collects the late response of an outstanding MAP/UNMAP for an UNRESOLVED region.
 *   0       ownership resolved (MAP ACK adopted -> DSP_MAP_ACKNOWLEDGED; MAP NACK -> local
 *           release done; UNMAP ACK -> remote released)
 *   -ETIMEDOUT / transport errno: still unresolved, a later call may succeed
 *   -ENETRESET / -ENOENT / -EPROTO / -EREMOTEIO: unresolved with a recorded blocker; the
 *           region stays OWNERSHIP_UNRESOLVED and nothing is freed
 * Never infers that a mapping disappeared; only an ACK/NACK that matches the outstanding
 * token and peer changes ownership state.
 */
int m11_shmem_reconcile(m11_shmem_mgr_t *mgr, m11_shmem_region_t *region, uint32_t timeout_ms);

const char *m11_shmem_cause_name(m11_shmem_cause_t cause);

/*
 * Cross-checks the manager counters against the regions the caller still owns. Returns a
 * bitmask of mismatching counters (0 = consistent): 1=dma_fds 2=mmaps 4=ion_imports
 * 8=dsp_maps 16=unresolved 32=local_release_pending.
 */
uint32_t m11_shmem_mgr_audit(const m11_shmem_mgr_t *mgr, const m11_shmem_region_t *regions,
                             size_t count);

#ifdef __cplusplus
}
#endif

#endif /* M11_RUNTIME_REPAIR_SHMEM_H */
