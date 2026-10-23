#include "m11_shmem.h"

#include <errno.h>
#include <string.h>

#ifndef ENETRESET
#define ENETRESET 102
#endif

/*
 * Blocker texts. A non-NULL region->blocker means a late response can NOT resolve ownership
 * any more, so the region stays OWNERSHIP_UNRESOLVED until a stock-evidenced policy exists.
 */
static const char B_PDR[] =
    "PDR/ENETRESET latched: the engine can never receive the late response; remote mapping "
    "state is UNKNOWN and is not inferred";
static const char B_LOST[] =
    "orphan correlation lost (engine closed or token no longer tracked); remote mapping state "
    "is UNKNOWN";
static const char B_NO_ORPHAN[] =
    "no outstanding MAP/UNMAP transaction to correlate; remote mapping state is UNKNOWN";
static const char B_UNMAP_NACK[] =
    "DSP refused SHARED_MEM_UNMAP_REGIONS; mapping state is UNKNOWN and no stock-evidenced "
    "recovery policy exists";
static const char B_AMBIGUOUS_MAP[] =
    "MAP response carried no usable mem_map_handle; mapping state is UNKNOWN and cannot be "
    "addressed by an UNMAP";
static const char B_NO_HANDLE[] =
    "region is marked DSP-mapped without a mem_map_handle; cannot address an UNMAP";
static const char B_NO_PROOF[] =
    "local release requested without proof that the ADSP no longer maps the pages";
static const char B_UNKNOWN_TX[] =
    "request was handed to write_fn but its fate is unknown and no response can be correlated";

const char *m11_shmem_state_name(m11_shmem_state_t state) {
    switch (state) {
        case M11_SHMEM_STATE_NOT_ALLOCATED:             return "NOT_ALLOCATED";
        case M11_SHMEM_STATE_ALLOCATED:                 return "ALLOCATED";
        case M11_SHMEM_STATE_KERNEL_IMPORT_ESTABLISHED: return "KERNEL_IMPORT_ESTABLISHED";
        case M11_SHMEM_STATE_DSP_MAP_REQUESTED:         return "DSP_MAP_REQUESTED";
        case M11_SHMEM_STATE_DSP_MAP_ACKNOWLEDGED:      return "DSP_MAP_ACKNOWLEDGED";
        case M11_SHMEM_STATE_DSP_UNMAP_REQUESTED:       return "DSP_UNMAP_REQUESTED";
        case M11_SHMEM_STATE_DSP_UNMAP_ACKNOWLEDGED:    return "DSP_UNMAP_ACKNOWLEDGED";
        case M11_SHMEM_STATE_RELEASED:                  return "RELEASED";
        case M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED:      return "OWNERSHIP_UNRESOLVED";
        case M11_SHMEM_STATE_LOCAL_RELEASE_PENDING:     return "LOCAL_RELEASE_PENDING";
        default:                                        return "INVALID_SHMEM_STATE";
    }
}

const char *m11_shmem_cause_name(m11_shmem_cause_t cause) {
    switch (cause) {
        case M11_SHMEM_CAUSE_NONE:                 return "NONE";
        case M11_SHMEM_CAUSE_MAP_WRITE_ERROR:      return "MAP_WRITE_ERROR";
        case M11_SHMEM_CAUSE_MAP_SHORT_WRITE:      return "MAP_SHORT_WRITE";
        case M11_SHMEM_CAUSE_MAP_TIMEOUT:          return "MAP_TIMEOUT";
        case M11_SHMEM_CAUSE_MAP_TRANSPORT_ERR:    return "MAP_TRANSPORT_ERR";
        case M11_SHMEM_CAUSE_MAP_PDR:              return "MAP_PDR";
        case M11_SHMEM_CAUSE_MAP_AMBIGUOUS_RSP:    return "MAP_AMBIGUOUS_RSP";
        case M11_SHMEM_CAUSE_UNMAP_WRITE_ERROR:    return "UNMAP_WRITE_ERROR";
        case M11_SHMEM_CAUSE_UNMAP_SHORT_WRITE:    return "UNMAP_SHORT_WRITE";
        case M11_SHMEM_CAUSE_UNMAP_TIMEOUT:        return "UNMAP_TIMEOUT";
        case M11_SHMEM_CAUSE_UNMAP_TRANSPORT_ERR:  return "UNMAP_TRANSPORT_ERR";
        case M11_SHMEM_CAUSE_UNMAP_PDR:            return "UNMAP_PDR";
        case M11_SHMEM_CAUSE_UNMAP_NACK:           return "UNMAP_NACK";
        case M11_SHMEM_CAUSE_LOCAL_RELEASE_FAILED: return "LOCAL_RELEASE_FAILED";
        default:                                   return "INVALID_SHMEM_CAUSE";
    }
}

size_t m11_shmem_align_size(size_t requested_bytes) {
    if (requested_bytes == 0) return 0;
    size_t mask = (size_t)M11_SHMEM_PAGE_ALIGNMENT - 1u;
    if (requested_bytes > ((size_t)-1) - mask) return 0;
    return (requested_bytes + mask) & ~mask;
}

int m11_shmem_pack_map_regions_pkt(uint8_t *out_buf, size_t out_cap, size_t *out_len,
                                   uint32_t src_port, uint32_t token,
                                   int dma_buf_fd, size_t aligned_bytes) {
    if (!out_buf || !out_len || dma_buf_fd < 0) return -EINVAL;
    size_t aligned = m11_shmem_align_size(aligned_bytes);
    if (aligned == 0 || aligned != aligned_bytes || aligned > 0x7FFFFFFFu) {
        return -EINVAL;
    }

    m11_apm_cmd_shared_mem_map_regions_t cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.mem_pool_id = M11_APM_MEMORY_MAP_SHMEM8_4K_POOL; /* 3 */
    cmd.num_regions = 1u;
    cmd.property_flag = M11_APM_MEMORY_MAP_OFFSET_MODE;  /* 0x4 */
    cmd.shm_addr_lsw = (uint32_t)dma_buf_fd;
    cmd.shm_addr_msw = 0u;
    cmd.mem_size_bytes = (uint32_t)aligned;

    return m11_gpr_pack_packet_ex(out_buf, out_cap, out_len,
                                  M11_GPR_DOMAIN_ADSP, M11_GPR_DOMAIN_APPS,
                                  M11_GPR_CLIENT_DATA_SHMEM_OFFSET_MODE, /* client_data = 1 */
                                  M11_APM_MODULE_IID, src_port,
                                  token, M11_APM_CMD_SHARED_MEM_MAP_REGIONS,
                                  &cmd, sizeof(cmd));
}

int m11_shmem_pack_unmap_regions_pkt(uint8_t *out_buf, size_t out_cap, size_t *out_len,
                                     uint32_t src_port, uint32_t token,
                                     uint32_t mem_map_handle) {
    if (!out_buf || !out_len || mem_map_handle == 0u) return -EINVAL;
    m11_apm_cmd_shared_mem_unmap_regions_t cmd = {
        .mem_map_handle = mem_map_handle,
    };
    return m11_gpr_pack_packet(out_buf, out_cap, out_len,
                               M11_APM_MODULE_IID, src_port,
                               token, M11_APM_CMD_SHARED_MEM_UNMAP_REGIONS,
                               &cmd, sizeof(cmd));
}

int m11_shmem_mgr_init(m11_shmem_mgr_t *mgr, const m11_shmem_backend_t *backend,
                       m11_gpr_engine_t *gpr, uint32_t timeout_ms) {
    if (!mgr || !backend || !gpr || timeout_ms == 0 ||
        !backend->dma_heap_alloc_fn || !backend->mmap_fn ||
        !backend->munmap_fn || !backend->close_fd_fn ||
        !backend->dma_buf_sync_fn ||
        !backend->ion_import_fd_fn || !backend->ion_unmap_fd_fn) {
        return -EINVAL;
    }
    memset(mgr, 0, sizeof(*mgr));
    mgr->backend = *backend;
    mgr->gpr = gpr;
    mgr->timeout_ms = timeout_ms;
    return 0;
}

/* ------------------------------------------------------------------------------------------
 * Counter bookkeeping. unresolved_regions / local_release_pending_regions count a region at
 * most once, no matter how often the same region re-enters the state (P4: the old code did
 * unresolved_regions++ on every failed retry, so the counter drifted).
 * ---------------------------------------------------------------------------------------- */
static void count_unresolved(m11_shmem_mgr_t *mgr, m11_shmem_region_t *region) {
    if (!region->counted_unresolved) {
        region->counted_unresolved = true;
        mgr->unresolved_regions++;
    }
}

static void uncount_unresolved(m11_shmem_mgr_t *mgr, m11_shmem_region_t *region) {
    if (region->counted_unresolved) {
        region->counted_unresolved = false;
        if (mgr->unresolved_regions > 0u) mgr->unresolved_regions--;
    }
}

static void count_local_pending(m11_shmem_mgr_t *mgr, m11_shmem_region_t *region) {
    if (!region->counted_local_pending) {
        region->counted_local_pending = true;
        mgr->local_release_pending_regions++;
    }
}

static void uncount_local_pending(m11_shmem_mgr_t *mgr, m11_shmem_region_t *region) {
    if (region->counted_local_pending) {
        region->counted_local_pending = false;
        if (mgr->local_release_pending_regions > 0u) mgr->local_release_pending_regions--;
    }
}

static void clear_orphan(m11_shmem_region_t *region) {
    region->orphan_kind = M11_SHMEM_ORPHAN_NONE;
    region->orphan_token = 0u;
}

/*
 * Enters OWNERSHIP_UNRESOLVED: the ADSP may still map the pages, so nothing may be freed.
 * If the engine still tracks `token` as an orphan, a late response can resolve ownership
 * (blocker == NULL, see m11_shmem_reconcile). Otherwise the region keeps `blocker`.
 */
static void mark_unresolved(m11_shmem_mgr_t *mgr, m11_shmem_region_t *region,
                            m11_shmem_cause_t cause, int err,
                            m11_shmem_orphan_kind_t kind, uint32_t token,
                            const char *blocker) {
    uncount_local_pending(mgr, region);
    region->state = M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED;
    region->remote_inactive = false;
    region->cause = cause;
    if (err < 0) region->last_error = err;

    if (kind != M11_SHMEM_ORPHAN_NONE && token != 0u &&
        m11_gpr_engine_orphan_tracked(mgr->gpr, token)) {
        region->orphan_kind = kind;
        region->orphan_token = token;
        region->blocker = NULL;
    } else {
        clear_orphan(region);
        region->blocker = blocker ? blocker : B_UNKNOWN_TX;
    }
    count_unresolved(mgr, region);
}

/* Remote ownership is PROVEN gone but a local step still fails: keep the retry state. */
static void mark_local_pending(m11_shmem_mgr_t *mgr, m11_shmem_region_t *region, int err) {
    uncount_unresolved(mgr, region);
    clear_orphan(region);
    region->blocker = NULL;
    region->state = M11_SHMEM_STATE_LOCAL_RELEASE_PENDING;
    region->cause = M11_SHMEM_CAUSE_LOCAL_RELEASE_FAILED;
    region->cleanup_error = err;
    if (region->last_error == 0) region->last_error = err; /* never overwrite the primary error */
    count_local_pending(mgr, region);
}

int m11_shmem_begin_cpu_access(m11_shmem_mgr_t *mgr, m11_shmem_region_t *region) {
    if (!mgr || !region || !mgr->backend.dma_buf_sync_fn) return -EINVAL;
    if (region->dma_buf_fd < 0 || !region->vaddr) return -EINVAL;

    int rc = mgr->backend.dma_buf_sync_fn(mgr->backend.user,
                                          region->dma_buf_fd,
                                          M11_DMA_BUF_SYNC_START_RW);
    if (rc < 0) {
        region->last_error = rc;
        return rc;
    }
    region->cpu_access_active = true;
    region->cpu_cache_clean_for_dsp = false;
    region->sync_start_count++;
    return 0;
}

int m11_shmem_end_cpu_access(m11_shmem_mgr_t *mgr, m11_shmem_region_t *region) {
    if (!mgr || !region || !mgr->backend.dma_buf_sync_fn) return -EINVAL;
    if (region->dma_buf_fd < 0 || !region->vaddr) return -EINVAL;
    if (!region->cpu_access_active) {
        region->last_error = -EPROTO;
        return -EPROTO;
    }

    int rc = mgr->backend.dma_buf_sync_fn(mgr->backend.user,
                                          region->dma_buf_fd,
                                          M11_DMA_BUF_SYNC_END_RW);
    if (rc < 0) {
        /* The END ioctl failed: the bracket is still open and nothing is known to be synced. */
        region->cpu_cache_clean_for_dsp = false;
        region->sync_end_failures++;
        region->last_error = rc;
        return rc;
    }
    region->cpu_access_active = false;
    /*
     * LINUX SEMANTICS (inferred, not stock-verified): system_heap only cleans caches for
     * attached dma_buf_attachments, so a clean-for-DSP claim is made only when the
     * msm_audio_ion attachment (0x40046161 -> ion_imported) already exists.
     */
    region->cpu_cache_clean_for_dsp = region->ion_imported;
    region->sync_end_count++;
    return 0;
}

/*
 * Releases the LOCAL handles (END bracket, msm_audio_ion import, mmap, dma-buf fd). Callable
 * ONLY when the ADSP is proven not to map the pages (region->remote_inactive).
 *
 * Every step is idempotent through the handle it owns (ion_imported / vaddr / dma_buf_fd), so a
 * failed step leaves the region in LOCAL_RELEASE_PENDING and a later call resumes exactly at the
 * failed step. No DSP command is ever sent from here.
 */
static int release_local_handles(m11_shmem_mgr_t *mgr, m11_shmem_region_t *region) {
    if (!region->remote_inactive) {
        /* Defence in depth: refuse, touch nothing. */
        return -EBUSY;
    }

    if (region->vaddr != NULL && region->cpu_access_active && region->dma_buf_fd >= 0) {
        /*
         * Match liblx-osal.so ar_shmem_free (@ 0xc5e4..0xc5fc): DMA_BUF_IOCTL_SYNC with
         * flags = 0x7 (END_RW) before munmap/ion_unmap/close. A failure here only costs a
         * cache-maintenance call on memory the ADSP no longer maps, so it is recorded
         * (sync_end_failures) but does not block the release.
         */
        int src = mgr->backend.dma_buf_sync_fn(mgr->backend.user,
                                               region->dma_buf_fd,
                                               M11_DMA_BUF_SYNC_END_RW);
        region->cpu_access_active = false;
        region->cpu_cache_clean_for_dsp = false;
        if (src == 0) {
            region->sync_end_count++;
        } else {
            region->sync_end_failures++;
        }
    }

    if (region->ion_imported && region->dma_buf_fd >= 0) {
        int rc = mgr->backend.ion_unmap_fd_fn(mgr->backend.user,
                                              region->dma_buf_fd,
                                              region->hyp_assigned);
        if (rc < 0) {
            mark_local_pending(mgr, region, rc);
            return rc;
        }
        region->ion_imported = false;
        if (mgr->active_ion_imports > 0) mgr->active_ion_imports--;
    }

    if (region->vaddr != NULL) {
        int rc = mgr->backend.munmap_fn(mgr->backend.user, region->vaddr, region->aligned_bytes);
        if (rc < 0) {
            mark_local_pending(mgr, region, rc);
            return rc;
        }
        region->vaddr = NULL;
        if (mgr->active_mmaps > 0) mgr->active_mmaps--;
    }

    if (region->dma_buf_fd >= 0) {
        int rc = mgr->backend.close_fd_fn(mgr->backend.user, region->dma_buf_fd);
        if (rc < 0) {
            mark_local_pending(mgr, region, rc);
            return rc;
        }
        region->dma_buf_fd = -1;
        if (mgr->active_dma_fds > 0) mgr->active_dma_fds--;
    }

    uncount_local_pending(mgr, region);
    uncount_unresolved(mgr, region);
    clear_orphan(region);
    region->blocker = NULL;
    region->cleanup_error = 0;
    region->requested_bytes = 0;
    region->aligned_bytes = 0;
    region->state = M11_SHMEM_STATE_RELEASED;
    return 0;
}

int m11_shmem_alloc_and_map(m11_shmem_mgr_t *mgr, m11_shmem_mode_t mode,
                            size_t requested_bytes, bool hyp_assign,
                            m11_shmem_region_t *out_region) {
    if (!mgr || !out_region || requested_bytes == 0) return -EINVAL;
    memset(out_region, 0, sizeof(*out_region));
    out_region->state = M11_SHMEM_STATE_NOT_ALLOCATED;
    out_region->dma_buf_fd = -1;

    /*
     * Stock marble ADSP runs behind an SMMU/hypervisor and requires DMA-BUF +
     * msm_audio_ion (0x40046161) + APM_CMD_SHARED_MEM_MAP_REGIONS (0x0100100C)
     * with mem_pool_id = 3, client_data = 1, and property_flag = 0x4 (OFFSET_MODE).
     * Hard-reject virtual mode.
     */
    if (mode != M11_SHMEM_MODE_DMA_ION_OFFSET) {
        out_region->last_error = -EOPNOTSUPP;
        return -EOPNOTSUPP;
    }

    size_t aligned = m11_shmem_align_size(requested_bytes);
    if (aligned == 0 || aligned > 0x7FFFFFFFu) {
        out_region->last_error = -EINVAL;
        return -EINVAL;
    }

    int dma_fd = -1;
    int rc = mgr->backend.dma_heap_alloc_fn(mgr->backend.user, aligned, &dma_fd);
    if (rc < 0 || dma_fd < 0) {
        int err = (rc < 0) ? rc : -ENOMEM;
        out_region->last_error = err;
        return err;
    }
    mgr->active_dma_fds++;
    out_region->dma_buf_fd = dma_fd;
    out_region->requested_bytes = requested_bytes;
    out_region->aligned_bytes = aligned;
    out_region->hyp_assigned = hyp_assign;
    /* Nothing has been sent to the ADSP yet, so it provably maps nothing. */
    out_region->remote_inactive = true;
    out_region->state = M11_SHMEM_STATE_ALLOCATED;

    void *vaddr = mgr->backend.mmap_fn(mgr->backend.user, dma_fd, aligned);
    if (!vaddr) {
        out_region->last_error = -ENOMEM;
        (void)release_local_handles(mgr, out_region);
        return -ENOMEM;
    }
    mgr->active_mmaps++;
    out_region->vaddr = vaddr;

    /*
     * Step 1b: Match liblx-osal.so ar_shmem_alloc (@ 0xc398..0xc3b0):
     * begin CPU access via ioctl(dma_fd, DMA_BUF_IOCTL_SYNC [0x40086200], { flags = 0x3 }).
     */
    rc = m11_shmem_begin_cpu_access(mgr, out_region);
    if (rc < 0) {
        out_region->last_error = rc;
        (void)release_local_handles(mgr, out_region);
        return rc;
    }

    /*
     * Step 2: Import dma_fd into kernel msm_audio_ion_fd_list via 0x40046161
     * (and 0x4004616d if hyp_assign). No physical address is returned to userspace.
     */
    rc = mgr->backend.ion_import_fd_fn(mgr->backend.user, dma_fd, hyp_assign);
    if (rc < 0) {
        out_region->last_error = rc;
        (void)release_local_handles(mgr, out_region);
        return rc;
    }
    mgr->active_ion_imports++;
    out_region->ion_imported = true;
    out_region->state = M11_SHMEM_STATE_KERNEL_IMPORT_ESTABLISHED;

    /*
     * Step 3: Build stock OFFSET_MODE APM_CMD_SHARED_MEM_MAP_REGIONS payload:
     *   mem_pool_id   = 3 (M11_APM_MEMORY_MAP_SHMEM8_4K_POOL)
     *   num_regions   = 1
     *   property_flag = 0x4 (M11_APM_MEMORY_MAP_OFFSET_MODE)
     *   shm_addr_lsw  = (uint32_t)dma_fd
     *   shm_addr_msw  = 0
     *   mem_size_bytes = (uint32_t)aligned
     * Sent with GPR hdr.client_data = 1 so audio_pkt_dlkm.ko intercepts and
     * replaces shm_addr_lsw/msw with the DMA-BUF physical IOVA in kernel space.
     */
    m11_apm_cmd_shared_mem_map_regions_t cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.mem_pool_id = M11_APM_MEMORY_MAP_SHMEM8_4K_POOL;
    cmd.num_regions = 1u;
    cmd.property_flag = M11_APM_MEMORY_MAP_OFFSET_MODE;
    cmd.shm_addr_lsw = (uint32_t)dma_fd;
    cmd.shm_addr_msw = 0u;
    cmd.mem_size_bytes = (uint32_t)aligned;

    uint32_t tok = 0;
    rc = m11_gpr_engine_submit_ex(mgr->gpr, M11_GPR_CLIENT_DATA_SHMEM_OFFSET_MODE,
                                  M11_APM_MODULE_IID, M11_APM_CMD_SHARED_MEM_MAP_REGIONS,
                                  &cmd, sizeof(cmd), &tok);
    if (rc < 0) {
        if (mgr->gpr->last_tx_status == M11_GPR_TX_NOT_ATTEMPTED) {
            /*
             * Proven pre-write failure in userspace (write_fn was never invoked): the kernel
             * driver and RPMSG transport never saw the packet, so the ADSP maps nothing and
             * the local handles can be released.
             */
            out_region->last_error = rc;
            (void)release_local_handles(mgr, out_region);
            return rc;
        }
        /*
         * write_fn() was invoked and returned an error or a short write. audio_pkt_write
         * (@ 0x0010170c) and gpr_send_pkt (@ 0x00101484) give no contract that no packet was
         * accepted, so the ADSP mapping state is UNKNOWN. The engine keeps the token reserved
         * (orphan) unless the transport reported PDR; a late MAP response can then still be
         * collected with m11_shmem_reconcile().
         */
        m11_shmem_cause_t cause = M11_SHMEM_CAUSE_MAP_WRITE_ERROR;
        if (rc == -ENETRESET) {
            cause = M11_SHMEM_CAUSE_MAP_PDR;
        } else if (mgr->gpr->last_tx_status == M11_GPR_TX_SHORT_WRITE) {
            cause = M11_SHMEM_CAUSE_MAP_SHORT_WRITE;
        }
        mark_unresolved(mgr, out_region, cause, rc, M11_SHMEM_ORPHAN_MAP, tok,
                        (cause == M11_SHMEM_CAUSE_MAP_PDR) ? B_PDR : B_UNKNOWN_TX);
        return rc;
    }

    /* Packet has been transmitted; DSP mapping is now in flight */
    out_region->remote_inactive = false;
    out_region->state = M11_SHMEM_STATE_DSP_MAP_REQUESTED;

    m11_apm_rsp_shared_mem_map_t rsp = {0};
    size_t rsp_len = 0;
    uint32_t dsp_status = 0;
    rc = m11_gpr_engine_wait_token(mgr->gpr, tok, mgr->timeout_ms,
                                   &dsp_status, &rsp, sizeof(rsp), &rsp_len);
    if (rc < 0) {
        if (rc == -EREMOTEIO && dsp_status != 0u) {
            /*
             * Explicit DSP NACK (0x02001005 with non-zero status) for THIS token: the ADSP
             * rejected the request, so it created no mapping. Roll back local resources.
             */
            out_region->remote_inactive = true;
            out_region->last_error = rc;
            (void)release_local_handles(mgr, out_region);
            return rc;
        }
        if (rc == -ENOSPC && !m11_gpr_engine_orphan_tracked(mgr->gpr, tok)) {
            /* A response was consumed but is unusable (no handle can be extracted). */
            mark_unresolved(mgr, out_region, M11_SHMEM_CAUSE_MAP_AMBIGUOUS_RSP, rc,
                            M11_SHMEM_ORPHAN_NONE, 0u, B_AMBIGUOUS_MAP);
            return rc;
        }
        /*
         * Timeout, transport error or PDR AFTER 0x0100100C was transmitted: the ADSP may have
         * created the mapping. The engine kept the token reserved (orphan) except after PDR.
         */
        m11_shmem_cause_t cause = M11_SHMEM_CAUSE_MAP_TRANSPORT_ERR;
        if (rc == -ETIMEDOUT) {
            cause = M11_SHMEM_CAUSE_MAP_TIMEOUT;
        } else if (rc == -ENETRESET || mgr->gpr->pdr_down) {
            cause = M11_SHMEM_CAUSE_MAP_PDR;
        }
        mark_unresolved(mgr, out_region, cause, rc, M11_SHMEM_ORPHAN_MAP, tok,
                        (cause == M11_SHMEM_CAUSE_MAP_PDR) ? B_PDR : B_UNKNOWN_TX);
        return rc;
    }

    if (rsp_len != sizeof(rsp) || rsp.mem_map_handle == 0u) {
        /*
         * Ambiguous/invalid response after the map request was sent: the response is consumed
         * and carries no handle, so quarantine instead of freeing potentially mapped pages.
         */
        mark_unresolved(mgr, out_region, M11_SHMEM_CAUSE_MAP_AMBIGUOUS_RSP, -EREMOTEIO,
                        M11_SHMEM_ORPHAN_NONE, 0u, B_AMBIGUOUS_MAP);
        return -EREMOTEIO;
    }

    mgr->active_dsp_maps++;
    out_region->dsp_mapped = true;
    out_region->mem_map_handle = rsp.mem_map_handle;
    out_region->state = M11_SHMEM_STATE_DSP_MAP_ACKNOWLEDGED;
    out_region->cause = M11_SHMEM_CAUSE_NONE;
    out_region->last_error = 0;
    return 0;
}

int m11_shmem_unmap_and_free(m11_shmem_mgr_t *mgr, m11_shmem_region_t *region) {
    if (!mgr || !region) return -EINVAL;

    if (region->state == M11_SHMEM_STATE_NOT_ALLOCATED ||
        region->state == M11_SHMEM_STATE_RELEASED) {
        return 0;
    }

    /*
     * Remote state unknown, or a DSP request still in flight without a usable answer: never free
     * local backing underneath the DSP. The primary error is preserved (not overwritten).
     */
    if (region->state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED ||
        region->state == M11_SHMEM_STATE_DSP_MAP_REQUESTED ||
        region->state == M11_SHMEM_STATE_DSP_UNMAP_REQUESTED) {
        return -EBUSY;
    }

    if (region->state == M11_SHMEM_STATE_LOCAL_RELEASE_PENDING) {
        if (!region->remote_inactive) {
            /* Inconsistent: LOCAL_RELEASE_PENDING must carry the remote-inactive proof. */
            mark_unresolved(mgr, region, M11_SHMEM_CAUSE_LOCAL_RELEASE_FAILED, -EPROTO,
                            M11_SHMEM_ORPHAN_NONE, 0u, B_NO_PROOF);
            return -EPROTO;
        }
        /* Retry ONLY the remaining local steps; no DSP command is sent again. */
        return release_local_handles(mgr, region);
    }

    if (region->state == M11_SHMEM_STATE_DSP_MAP_ACKNOWLEDGED) {
        if (!region->dsp_mapped || region->mem_map_handle == 0u) {
            mark_unresolved(mgr, region, M11_SHMEM_CAUSE_UNMAP_WRITE_ERROR, -EPROTO,
                            M11_SHMEM_ORPHAN_NONE, 0u, B_NO_HANDLE);
            return -EPROTO;
        }

        m11_apm_cmd_shared_mem_unmap_regions_t cmd = {
            .mem_map_handle = region->mem_map_handle,
        };
        region->state = M11_SHMEM_STATE_DSP_UNMAP_REQUESTED;

        uint32_t tok = 0;
        int rc = m11_gpr_engine_submit_ex(mgr->gpr, M11_GPR_CLIENT_DATA_DEFAULT,
                                          M11_APM_MODULE_IID,
                                          M11_APM_CMD_SHARED_MEM_UNMAP_REGIONS,
                                          &cmd, sizeof(cmd), &tok);
        if (rc < 0) {
            if (mgr->gpr->last_tx_status == M11_GPR_TX_NOT_ATTEMPTED) {
                if (rc == -ENETRESET || mgr->gpr->pdr_down) {
                    /*
                     * Nothing was sent, but the ADSP subsystem restarted since the MAP was
                     * ACKed. The recorded handle can no longer be trusted and the engine can
                     * never talk to the new instance, so ownership is UNKNOWN, not "mapped".
                     */
                    mark_unresolved(mgr, region, M11_SHMEM_CAUSE_UNMAP_PDR, rc,
                                    M11_SHMEM_ORPHAN_NONE, 0u, B_PDR);
                    return rc;
                }
                /* Nothing reached write_fn: the mapping is exactly as it was. Retryable. */
                region->state = M11_SHMEM_STATE_DSP_MAP_ACKNOWLEDGED;
                region->last_error = rc;
                return rc;
            }
            m11_shmem_cause_t cause = M11_SHMEM_CAUSE_UNMAP_WRITE_ERROR;
            if (rc == -ENETRESET) {
                cause = M11_SHMEM_CAUSE_UNMAP_PDR;
            } else if (mgr->gpr->last_tx_status == M11_GPR_TX_SHORT_WRITE) {
                cause = M11_SHMEM_CAUSE_UNMAP_SHORT_WRITE;
            }
            mark_unresolved(mgr, region, cause, rc, M11_SHMEM_ORPHAN_UNMAP, tok,
                            (cause == M11_SHMEM_CAUSE_UNMAP_PDR) ? B_PDR : B_UNKNOWN_TX);
            return rc;
        }

        uint32_t dsp_status = 0;
        rc = m11_gpr_engine_wait_token(mgr->gpr, tok, mgr->timeout_ms,
                                       &dsp_status, NULL, 0, NULL);
        if (rc < 0) {
            /*
             * The DSP unmap was NOT acknowledged. Do not clear dsp_mapped and do not free
             * anything. A timeout/transport error keeps the orphan so a late ACK can still
             * resolve it; a NACK or PDR cannot.
             */
            if (rc == -EREMOTEIO && dsp_status != 0u) {
                mark_unresolved(mgr, region, M11_SHMEM_CAUSE_UNMAP_NACK, rc,
                                M11_SHMEM_ORPHAN_NONE, 0u, B_UNMAP_NACK);
                return rc;
            }
            m11_shmem_cause_t cause = M11_SHMEM_CAUSE_UNMAP_TRANSPORT_ERR;
            if (rc == -ETIMEDOUT) {
                cause = M11_SHMEM_CAUSE_UNMAP_TIMEOUT;
            } else if (rc == -ENETRESET || mgr->gpr->pdr_down) {
                cause = M11_SHMEM_CAUSE_UNMAP_PDR;
            }
            mark_unresolved(mgr, region, cause, rc, M11_SHMEM_ORPHAN_UNMAP, tok,
                            (cause == M11_SHMEM_CAUSE_UNMAP_PDR) ? B_PDR : B_UNKNOWN_TX);
            return rc;
        }

        /* UNMAP ACKed: the ADSP no longer maps the pages. Only local handles remain. */
        region->dsp_mapped = false;
        region->mem_map_handle = 0u;
        if (mgr->active_dsp_maps > 0) mgr->active_dsp_maps--;
        region->remote_inactive = true;
        region->state = M11_SHMEM_STATE_DSP_UNMAP_ACKNOWLEDGED;
    }

    return release_local_handles(mgr, region);
}

int m11_shmem_reconcile(m11_shmem_mgr_t *mgr, m11_shmem_region_t *region, uint32_t timeout_ms) {
    if (!mgr || !region) return -EINVAL;
    if (region->state != M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED) return -EINVAL;
    if (region->orphan_kind == M11_SHMEM_ORPHAN_NONE || region->orphan_token == 0u) {
        if (!region->blocker) region->blocker = B_NO_ORPHAN;
        return -ENOENT;
    }

    const bool is_map = (region->orphan_kind == M11_SHMEM_ORPHAN_MAP);
    const uint32_t tok = region->orphan_token;
    uint8_t rsp_buf[16];
    memset(rsp_buf, 0, sizeof(rsp_buf));
    size_t rsp_len = 0u;
    uint32_t dsp_status = 0u;
    uint32_t rsp_opcode = 0u;

    int rc = m11_gpr_engine_orphan_poll(mgr->gpr, tok, timeout_ms, &dsp_status, &rsp_opcode,
                                        rsp_buf, sizeof(rsp_buf), &rsp_len);

    if (rc == -ENETRESET) {
        clear_orphan(region);
        region->cause = is_map ? M11_SHMEM_CAUSE_MAP_PDR : M11_SHMEM_CAUSE_UNMAP_PDR;
        region->blocker = B_PDR;
        return -ENETRESET;
    }
    if (rc == -ENOENT) {
        clear_orphan(region);
        region->blocker = B_LOST;
        return -ENOENT;
    }
    if (rc == -EREMOTEIO) {
        /* The late response was an explicit DSP NACK for our token (consumed by the engine). */
        clear_orphan(region);
        if (is_map) {
            /* MAP refused: the ADSP created no mapping, local handles are free to go. */
            uncount_unresolved(mgr, region);
            region->remote_inactive = true;
            region->cause = M11_SHMEM_CAUSE_NONE;
            region->blocker = NULL;
            region->last_error = -EREMOTEIO;
            int lrc = release_local_handles(mgr, region);
            return (lrc < 0) ? lrc : 0;
        }
        region->cause = M11_SHMEM_CAUSE_UNMAP_NACK;
        region->blocker = B_UNMAP_NACK;
        return -EREMOTEIO;
    }
    if (rc < 0) {
        /* -ETIMEDOUT (still outstanding) or a transport errno: the orphan stays tracked. */
        if (rc != -ETIMEDOUT) {
            region->cause = is_map ? M11_SHMEM_CAUSE_MAP_TRANSPORT_ERR
                                   : M11_SHMEM_CAUSE_UNMAP_TRANSPORT_ERR;
        }
        return rc;
    }

    /* rc == 0: an ACK (dsp_status == 0) that matched the token and peer was consumed. */
    clear_orphan(region);
    if (is_map) {
        m11_apm_rsp_shared_mem_map_t rsp;
        memset(&rsp, 0, sizeof(rsp));
        if (rsp_opcode != M11_APM_CMDRSP_SHARED_MEM_MAP_REGIONS || rsp_len != sizeof(rsp)) {
            region->cause = M11_SHMEM_CAUSE_MAP_AMBIGUOUS_RSP;
            region->blocker = B_AMBIGUOUS_MAP;
            return -EPROTO;
        }
        memcpy(&rsp, rsp_buf, sizeof(rsp));
        if (rsp.mem_map_handle == 0u) {
            region->cause = M11_SHMEM_CAUSE_MAP_AMBIGUOUS_RSP;
            region->blocker = B_AMBIGUOUS_MAP;
            return -EPROTO;
        }
        /* The late MAP ACK is the DSP's answer to our request: adopt the handle. */
        mgr->active_dsp_maps++;
        region->dsp_mapped = true;
        region->mem_map_handle = rsp.mem_map_handle;
        region->remote_inactive = false;
        uncount_unresolved(mgr, region);
        region->blocker = NULL;
        region->cause = M11_SHMEM_CAUSE_NONE;
        region->last_error = 0;
        region->state = M11_SHMEM_STATE_DSP_MAP_ACKNOWLEDGED;
        return 0;
    }

    /* Late UNMAP ACK: the ADSP no longer maps the pages. */
    region->dsp_mapped = false;
    region->mem_map_handle = 0u;
    if (mgr->active_dsp_maps > 0) mgr->active_dsp_maps--;
    region->remote_inactive = true;
    uncount_unresolved(mgr, region);
    region->blocker = NULL;
    region->cause = M11_SHMEM_CAUSE_NONE;
    region->state = M11_SHMEM_STATE_DSP_UNMAP_ACKNOWLEDGED;
    int lrc = release_local_handles(mgr, region);
    return (lrc < 0) ? lrc : 0;
}

uint32_t m11_shmem_mgr_audit(const m11_shmem_mgr_t *mgr, const m11_shmem_region_t *regions,
                             size_t count) {
    if (!mgr || (!regions && count > 0)) return 0xFFFFFFFFu;

    uint32_t fds = 0, maps = 0, ion = 0, dsp = 0, unres = 0, pend = 0;
    for (size_t i = 0; i < count; i++) {
        const m11_shmem_region_t *r = &regions[i];
        if (r->state == M11_SHMEM_STATE_NOT_ALLOCATED) continue;
        if (r->dma_buf_fd >= 0) fds++;
        if (r->vaddr != NULL) maps++;
        if (r->ion_imported) ion++;
        if (r->dsp_mapped) dsp++;
        if (r->state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED) unres++;
        if (r->state == M11_SHMEM_STATE_LOCAL_RELEASE_PENDING) pend++;
    }

    uint32_t mask = 0u;
    if (mgr->active_dma_fds != fds) mask |= 1u;
    if (mgr->active_mmaps != maps) mask |= 2u;
    if (mgr->active_ion_imports != ion) mask |= 4u;
    if (mgr->active_dsp_maps != dsp) mask |= 8u;
    if (mgr->unresolved_regions != unres) mask |= 16u;
    if (mgr->local_release_pending_regions != pend) mask |= 32u;
    return mask;
}
