#include "m11_shmem.h"

#include <errno.h>
#include <string.h>

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
        default:                                        return "INVALID_SHMEM_STATE";
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
        region->cpu_cache_clean_for_dsp = false;
        region->last_error = rc;
        return rc;
    }
    region->cpu_access_active = false;
    /*
     * Linux system_heap.c only cleans caches for attached dma_buf_attachments.
     * Therefore cache lines are only guaranteed clean for ADSP DMA if the
     * msm_audio_ion attachment (0x40046161 -> ion_imported) was already established.
     */
    region->cpu_cache_clean_for_dsp = region->ion_imported;
    region->sync_end_count++;
    return 0;
}

/*
 * Releases local kernel-import / mmap / dma_buf_fd handles ONLY when it is
 * proven that the ADSP holds no active mapping to the underlying pages.
 * If any local release operation fails, ownership transitions to
 * M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED and the failed handle stays accounted.
 */
static int release_local_handles_when_dsp_inactive(m11_shmem_mgr_t *mgr,
                                                   m11_shmem_region_t *region) {
    int first_err = 0;

    if (region->vaddr != NULL && region->cpu_access_active && region->dma_buf_fd >= 0) {
        /*
         * Match liblx-osal.so ar_shmem_free (@ 0xc5e4..0xc5fc): issue
         * DMA_BUF_IOCTL_SYNC (0x40086200) with flags = 0x7 (DMA_BUF_SYNC_END_RW)
         * before munmap/ion_unmap/close.
         */
        int src = mgr->backend.dma_buf_sync_fn(mgr->backend.user,
                                               region->dma_buf_fd,
                                               M11_DMA_BUF_SYNC_END_RW);
        region->cpu_access_active = false;
        region->cpu_cache_clean_for_dsp = false;
        if (src == 0) {
            region->sync_end_count++;
        }
    }

    if (region->ion_imported && region->dma_buf_fd >= 0) {
        int rc = mgr->backend.ion_unmap_fd_fn(mgr->backend.user,
                                              region->dma_buf_fd,
                                              region->hyp_assigned);
        if (rc < 0) {
            if (first_err == 0) first_err = rc;
            region->state = M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED;
            region->last_error = first_err;
            mgr->unresolved_regions++;
            return first_err;
        }
        region->ion_imported = false;
        if (mgr->active_ion_imports > 0) mgr->active_ion_imports--;
    }

    if (region->vaddr != NULL) {
        int rc = mgr->backend.munmap_fn(mgr->backend.user, region->vaddr, region->aligned_bytes);
        if (rc < 0) {
            if (first_err == 0) first_err = rc;
            region->state = M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED;
            region->last_error = first_err;
            mgr->unresolved_regions++;
            return first_err;
        }
        region->vaddr = NULL;
        if (mgr->active_mmaps > 0) mgr->active_mmaps--;
    }

    if (region->dma_buf_fd >= 0) {
        int rc = mgr->backend.close_fd_fn(mgr->backend.user, region->dma_buf_fd);
        if (rc < 0) {
            if (first_err == 0) first_err = rc;
            region->state = M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED;
            region->last_error = first_err;
            mgr->unresolved_regions++;
            return first_err;
        }
        region->dma_buf_fd = -1;
        if (mgr->active_dma_fds > 0) mgr->active_dma_fds--;
    }

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
    out_region->state = M11_SHMEM_STATE_ALLOCATED;

    void *vaddr = mgr->backend.mmap_fn(mgr->backend.user, dma_fd, aligned);
    if (!vaddr) {
        (void)release_local_handles_when_dsp_inactive(mgr, out_region);
        out_region->last_error = -ENOMEM;
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
        (void)release_local_handles_when_dsp_inactive(mgr, out_region);
        out_region->last_error = rc;
        return rc;
    }

    /*
     * Step 2: Import dma_fd into kernel msm_audio_ion_fd_list via 0x40046161
     * (and 0x4004616d if hyp_assign). No physical address is returned to userspace.
     */
    rc = mgr->backend.ion_import_fd_fn(mgr->backend.user, dma_fd, hyp_assign);
    if (rc < 0) {
        (void)release_local_handles_when_dsp_inactive(mgr, out_region);
        out_region->last_error = rc;
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
             * Proven pre-write failure in userspace (write_fn was never invoked):
             * the kernel driver and RPMSG transport never saw the packet.
             * Safe and mandatory to unmap ION and release local resources cleanly.
             */
            (void)release_local_handles_when_dsp_inactive(mgr, out_region);
            out_region->last_error = rc;
            return rc;
        }
        /*
         * write_fn() was invoked and returned an error (M11_GPR_TX_WRITE_ERROR) or
         * short write (M11_GPR_TX_SHORT_WRITE).
         * Binary audit of audio_pkt_dlkm.ko (audio_pkt_write @ 0x0010170c) and
         * gpr_dlkm.ko (gpr_send_pkt @ 0x00101484) proves that audio_pkt_write
         * checks `count >= (hdr >> 8)` and forwards gpr_send_pkt() / rpmsg_trysend()
         * return codes without providing a userspace contract that no packet was
         * accepted on write error or partial write.
         * Remote DSP mapping state is therefore UNKNOWN and ownership MUST be
         * quarantined as M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED without freeing
         * the underlying ION/DMA-BUF pages.
         */
        out_region->state = M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED;
        out_region->last_error = rc;
        mgr->unresolved_regions++;
        return rc;
    }

    /* Packet has been transmitted; DSP mapping is now in flight */
    out_region->state = M11_SHMEM_STATE_DSP_MAP_REQUESTED;

    m11_apm_rsp_shared_mem_map_t rsp = {0};
    size_t rsp_len = 0;
    uint32_t dsp_status = 0;
    rc = m11_gpr_engine_wait_token(mgr->gpr, tok, mgr->timeout_ms,
                                   &dsp_status, &rsp, sizeof(rsp), &rsp_len);
    if (rc < 0) {
        if (rc == -EREMOTEIO && dsp_status != 0u) {
            /*
             * Explicit DSP NACK (0x02001005 with non-zero status): the ADSP
             * explicitly rejected the mapping request, so no remote mapping exists.
             * Roll back kernel ION import and local DMA-BUF cleanly.
             */
            (void)release_local_handles_when_dsp_inactive(mgr, out_region);
            out_region->last_error = rc;
            return rc;
        }
        /*
         * Timeout, PDR, or transport error AFTER 0x0100100C was transmitted:
         * remote DSP mapping state is UNKNOWN. Never free the underlying ION/DMA-BUF
         * pages while the ADSP SMMU may still hold or complete the mapping.
         */
        out_region->state = M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED;
        out_region->last_error = rc;
        mgr->unresolved_regions++;
        return rc;
    }

    if (rsp_len != sizeof(rsp) || rsp.mem_map_handle == 0u) {
        /*
         * Ambiguous/invalid response from DSP after map request was sent:
         * quarantine ownership rather than freeing potentially mapped pages.
         */
        out_region->state = M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED;
        out_region->last_error = -EREMOTEIO;
        mgr->unresolved_regions++;
        return -EREMOTEIO;
    }

    mgr->active_dsp_maps++;
    out_region->dsp_mapped = true;
    out_region->mem_map_handle = rsp.mem_map_handle;
    out_region->state = M11_SHMEM_STATE_DSP_MAP_ACKNOWLEDGED;
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
     * If ownership is already unresolved or a DSP request is still in flight
     * without acknowledgement, refuse to free local backing underneath the DSP.
     */
    if (region->state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED ||
        region->state == M11_SHMEM_STATE_DSP_MAP_REQUESTED ||
        region->state == M11_SHMEM_STATE_DSP_UNMAP_REQUESTED) {
        region->last_error = -EBUSY;
        return -EBUSY;
    }

    if (region->state == M11_SHMEM_STATE_DSP_MAP_ACKNOWLEDGED) {
        if (!region->dsp_mapped || region->mem_map_handle == 0u) {
            region->state = M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED;
            region->last_error = -EPROTO;
            mgr->unresolved_regions++;
            return -EPROTO;
        }

        m11_apm_cmd_shared_mem_unmap_regions_t cmd = {
            .mem_map_handle = region->mem_map_handle,
        };
        region->state = M11_SHMEM_STATE_DSP_UNMAP_REQUESTED;

        uint32_t dsp_status = 0;
        int rc = m11_gpr_engine_transact(mgr->gpr, M11_APM_MODULE_IID,
                                         M11_APM_CMD_SHARED_MEM_UNMAP_REGIONS,
                                         &cmd, sizeof(cmd), mgr->timeout_ms,
                                         &dsp_status, NULL, 0, NULL);
        if (rc < 0) {
            /*
             * DSP unmap was NOT acknowledged (timeout, NACK, or PDR).
             * Do NOT clear dsp_mapped or free the underlying ION/DMA-BUF memory!
             */
            region->state = M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED;
            region->last_error = rc;
            mgr->unresolved_regions++;
            return rc;
        }

        region->dsp_mapped = false;
        region->mem_map_handle = 0u;
        if (mgr->active_dsp_maps > 0) mgr->active_dsp_maps--;
        region->state = M11_SHMEM_STATE_DSP_UNMAP_ACKNOWLEDGED;
    }

    return release_local_handles_when_dsp_inactive(mgr, region);
}
