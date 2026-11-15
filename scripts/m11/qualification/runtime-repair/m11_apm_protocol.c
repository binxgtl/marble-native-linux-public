#include "m11_apm_protocol.h"

#include <errno.h>
#include <string.h>

static bool is_valid_graph_mgmt_opcode(uint32_t opcode) {
    return (opcode == M11_APM_CMD_GRAPH_PREPARE ||
            opcode == M11_APM_CMD_GRAPH_START ||
            opcode == M11_APM_CMD_GRAPH_STOP ||
            opcode == M11_APM_CMD_GRAPH_CLOSE);
}

size_t m11_apm_subgraph_list_param_aligned_bytes(uint32_t num_sub_graphs) {
    if (num_sub_graphs == 0u || num_sub_graphs > M11_APM_MAX_SUBGRAPHS_PER_CMD) {
        return 0u;
    }
    /*
     * Per libar-gsl.so (gsl_graph_close_sgids_and_connections @ 0x00121d30):
     *   uVar14 = num_sub_graphs * 4 + 0x14 (16B param header + 4B count + 4B * N)
     *   uVar2  = (uVar14 + 7) & ~7u
     */
    size_t unaligned = (size_t)num_sub_graphs * 4u + 0x14u;
    return (unaligned + 7u) & ~(size_t)7u;
}

size_t m11_apm_graph_mgmt_inband_payload_bytes(uint32_t num_sub_graphs) {
    size_t param_aligned = m11_apm_subgraph_list_param_aligned_bytes(num_sub_graphs);
    if (param_aligned == 0u) return 0u;
    /*
     * Per libar-gsl.so (gsl_graph_prepare.cfi @ 0x0011cb48 / gsl_graph_start.cfi @ 0x0011d554):
     *   uVar2 = (num_sub_graphs * 4 + 0x2b) & ~7u
     *         = sizeof(m11_apm_cmd_header_t) [16] + param_aligned
     */
    return sizeof(m11_apm_cmd_header_t) + param_aligned;
}

int m11_apm_write_subgraph_list_block(uint8_t *out_buf, size_t out_cap, size_t *out_len,
                                      const uint32_t *sub_graph_ids, uint32_t num_sub_graphs) {
    if (!out_buf || !out_len || !sub_graph_ids) return -EINVAL;
    size_t aligned_bytes = m11_apm_subgraph_list_param_aligned_bytes(num_sub_graphs);
    if (aligned_bytes == 0u) return -EINVAL;
    if (out_cap < aligned_bytes) return -EMSGSIZE;

    for (uint32_t i = 0; i < num_sub_graphs; i++) {
        if (sub_graph_ids[i] == 0u) return -EINVAL;
    }

    memset(out_buf, 0, aligned_bytes);

    m11_apm_module_param_data_t param_hdr;
    param_hdr.module_instance_id = M11_APM_MODULE_IID;          /* 1 */
    param_hdr.param_id = M11_APM_PARAM_ID_SUB_GRAPH_LIST;       /* 0x08001005 */
    param_hdr.param_size = (num_sub_graphs + 1u) * 4u;          /* unpadded: 12 for 2 SGs, 20 for 4 SGs */
    param_hdr.error_code = 0u;

    memcpy(out_buf, &param_hdr, sizeof(param_hdr));
    memcpy(out_buf + sizeof(param_hdr), &num_sub_graphs, sizeof(uint32_t));
    memcpy(out_buf + sizeof(param_hdr) + sizeof(uint32_t),
           sub_graph_ids, (size_t)num_sub_graphs * sizeof(uint32_t));

    *out_len = aligned_bytes;
    return 0;
}

int m11_apm_validate_subgraph_list_block(const uint8_t *buf, size_t len,
                                         uint32_t *out_num_sub_graphs,
                                         uint32_t *out_sub_graph_ids,
                                         size_t max_sub_graphs) {
    if (!buf || len < sizeof(m11_apm_module_param_data_t) + 8u) return -EBADMSG;
    if ((len & 7u) != 0u) return -EBADMSG;

    m11_apm_module_param_data_t param_hdr;
    memcpy(&param_hdr, buf, sizeof(param_hdr));
    if (param_hdr.module_instance_id != M11_APM_MODULE_IID ||
        param_hdr.param_id != M11_APM_PARAM_ID_SUB_GRAPH_LIST ||
        param_hdr.error_code != 0u) {
        return -EPROTO;
    }

    uint32_t num_sgs = 0u;
    memcpy(&num_sgs, buf + sizeof(param_hdr), sizeof(uint32_t));
    if (num_sgs == 0u || num_sgs > M11_APM_MAX_SUBGRAPHS_PER_CMD) return -EBADMSG;

    uint32_t expected_param_size = (num_sgs + 1u) * 4u;
    size_t expected_aligned = m11_apm_subgraph_list_param_aligned_bytes(num_sgs);
    if (param_hdr.param_size != expected_param_size || len != expected_aligned) {
        return -EBADMSG;
    }

    /* Verify that any 8-byte alignment tail padding is zero */
    size_t unpadded_total = sizeof(param_hdr) + (size_t)expected_param_size;
    for (size_t i = unpadded_total; i < len; i++) {
        if (buf[i] != 0u) return -EBADMSG;
    }

    const uint8_t *sg_ptr = buf + sizeof(param_hdr) + sizeof(uint32_t);
    for (uint32_t i = 0; i < num_sgs; i++) {
        uint32_t sg_id = 0u;
        memcpy(&sg_id, sg_ptr + (size_t)i * sizeof(uint32_t), sizeof(uint32_t));
        if (sg_id == 0u) return -EBADMSG;
        if (out_sub_graph_ids) {
            if ((size_t)i >= max_sub_graphs) return -ENOSPC;
            out_sub_graph_ids[i] = sg_id;
        }
    }

    if (out_num_sub_graphs) *out_num_sub_graphs = num_sgs;
    return 0;
}

int m11_apm_build_graph_mgmt_inband_payload(uint8_t *out_buf, size_t out_cap, size_t *out_len,
                                            const uint32_t *sub_graph_ids, uint32_t num_sub_graphs) {
    if (!out_buf || !out_len || !sub_graph_ids) return -EINVAL;
    size_t total_payload = m11_apm_graph_mgmt_inband_payload_bytes(num_sub_graphs);
    if (total_payload == 0u) return -EINVAL;
    if (out_cap < total_payload) return -EMSGSIZE;

    size_t block_len = 0u;
    int rc = m11_apm_write_subgraph_list_block(out_buf + sizeof(m11_apm_cmd_header_t),
                                               out_cap - sizeof(m11_apm_cmd_header_t),
                                               &block_len, sub_graph_ids, num_sub_graphs);
    if (rc < 0) return rc;

    m11_apm_cmd_header_t cmd_hdr;
    cmd_hdr.payload_address_lsw = 0u;
    cmd_hdr.payload_address_msw = 0u;
    cmd_hdr.mem_map_handle = 0u;
    cmd_hdr.payload_size = (uint32_t)block_len;
    memcpy(out_buf, &cmd_hdr, sizeof(cmd_hdr));

    *out_len = sizeof(cmd_hdr) + block_len;
    return 0;
}

int m11_apm_pack_graph_mgmt_cmd(uint8_t *out_buf, size_t out_cap, size_t *out_len,
                                uint32_t src_port, uint32_t token, uint32_t opcode,
                                const uint32_t *sub_graph_ids, uint32_t num_sub_graphs) {
    if (!is_valid_graph_mgmt_opcode(opcode)) return -EINVAL;
    uint8_t payload[256];
    size_t payload_len = 0u;
    int rc = m11_apm_build_graph_mgmt_inband_payload(payload, sizeof(payload), &payload_len,
                                                     sub_graph_ids, num_sub_graphs);
    if (rc < 0) return rc;

    return m11_gpr_pack_packet(out_buf, out_cap, out_len,
                               M11_APM_MODULE_IID, src_port,
                               token, opcode, payload, payload_len);
}

int m11_apm_validate_graph_mgmt_inband_payload(const uint8_t *payload, size_t payload_len,
                                               uint32_t *out_num_sub_graphs,
                                               uint32_t *out_sub_graph_ids,
                                               size_t max_sub_graphs) {
    if (!payload || payload_len < sizeof(m11_apm_cmd_header_t) + sizeof(m11_apm_module_param_data_t) + 8u) {
        return -EBADMSG;
    }

    m11_apm_cmd_header_t cmd_hdr;
    memcpy(&cmd_hdr, payload, sizeof(cmd_hdr));
    if (cmd_hdr.payload_address_lsw != 0u ||
        cmd_hdr.payload_address_msw != 0u ||
        cmd_hdr.mem_map_handle != 0u) {
        return -EPROTO;
    }
    if ((size_t)cmd_hdr.payload_size != payload_len - sizeof(m11_apm_cmd_header_t)) {
        return -EBADMSG;
    }

    return m11_apm_validate_subgraph_list_block(payload + sizeof(m11_apm_cmd_header_t),
                                                cmd_hdr.payload_size,
                                                out_num_sub_graphs,
                                                out_sub_graph_ids,
                                                max_sub_graphs);
}

int m11_apm_build_graph_open_oob(uint8_t *shm_vaddr, size_t shm_capacity,
                                 uint32_t shm_offset_bytes, uint32_t mem_map_handle,
                                 const uint32_t *sub_graph_ids, uint32_t num_sub_graphs,
                                 m11_apm_cmd_header_t *out_cmd_hdr,
                                 size_t *out_shm_written) {
    if (!shm_vaddr || !sub_graph_ids || !out_cmd_hdr || mem_map_handle == 0u) {
        return -EINVAL;
    }
    if ((shm_offset_bytes & 7u) != 0u || (size_t)shm_offset_bytes >= shm_capacity) {
        return -EINVAL;
    }

    size_t written = 0u;
    int rc = m11_apm_write_subgraph_list_block(shm_vaddr + shm_offset_bytes,
                                               shm_capacity - (size_t)shm_offset_bytes,
                                               &written, sub_graph_ids, num_sub_graphs);
    if (rc < 0) return rc;

    out_cmd_hdr->payload_address_lsw = shm_offset_bytes;
    out_cmd_hdr->payload_address_msw = 0u;
    out_cmd_hdr->mem_map_handle = mem_map_handle;
    out_cmd_hdr->payload_size = (uint32_t)written;
    if (out_shm_written) *out_shm_written = written;
    return 0;
}

int m11_apm_transact_graph_open_oob(m11_gpr_engine_t *gpr,
                                    void *shm_vaddr, size_t shm_capacity,
                                    uint32_t shm_offset_bytes, uint32_t mem_map_handle,
                                    const uint32_t *sub_graph_ids, uint32_t num_sub_graphs,
                                    uint32_t timeout_ms, uint32_t *out_dsp_status) {
    if (!gpr || !shm_vaddr) return -EINVAL;
    m11_apm_cmd_header_t cmd_hdr;
    int rc = m11_apm_build_graph_open_oob((uint8_t *)shm_vaddr, shm_capacity,
                                          shm_offset_bytes, mem_map_handle,
                                          sub_graph_ids, num_sub_graphs,
                                          &cmd_hdr, NULL);
    if (rc < 0) return rc;

    return m11_gpr_engine_transact(gpr, M11_APM_MODULE_IID, M11_APM_CMD_GRAPH_OPEN,
                                   &cmd_hdr, sizeof(cmd_hdr), timeout_ms,
                                   out_dsp_status, NULL, 0, NULL);
}

int m11_apm_transact_graph_open_region(m11_gpr_engine_t *gpr,
                                       m11_shmem_mgr_t *shmem_mgr,
                                       m11_shmem_region_t *region,
                                       uint32_t shm_offset_bytes,
                                       const uint32_t *sub_graph_ids, uint32_t num_sub_graphs,
                                       uint32_t timeout_ms, uint32_t *out_dsp_status) {
    if (!gpr || !shmem_mgr || !region || !sub_graph_ids) return -EINVAL;
    gpr->last_tx_status = M11_GPR_TX_NOT_ATTEMPTED;
    if (region->state != M11_SHMEM_STATE_DSP_MAP_ACKNOWLEDGED ||
        !region->vaddr || !region->ion_imported ||
        !region->dsp_mapped || region->mem_map_handle == 0u) {
        return -EPROTO;
    }

    /*
     * 1. CPU-access bracket (DMA_BUF_IOCTL_SYNC 0x40086200, START_RW 0x3).
     *    `opened_here` records whether THIS call issued the START: only a bracket this call
     *    opened is closed again on an error path. A bracket that was already open on entry
     *    (stock keeps it open from allocation) is left as found.
     */
    bool opened_here = false;
    int rc = 0;
    if (!region->cpu_access_active) {
        rc = m11_shmem_begin_cpu_access(shmem_mgr, region);
        if (rc < 0) return rc; /* START failed: no bracket is open, nothing to close */
        opened_here = true;
    }

    /*
     * 2. Write the 8-byte-aligned APM_PARAM_ID_SUB_GRAPH_LIST (0x08001005) block into the
     *    mmap'd DMA-BUF region at shm_offset_bytes. CPU cache lines are now dirty with
     *    respect to ADSP DMA. The builder validates every input before it writes the first
     *    byte, so a build failure leaves the shared memory untouched.
     */
    region->cpu_cache_clean_for_dsp = false;
    m11_apm_cmd_header_t cmd_hdr;
    rc = m11_apm_build_graph_open_oob((uint8_t *)region->vaddr, region->aligned_bytes,
                                      shm_offset_bytes, region->mem_map_handle,
                                      sub_graph_ids, num_sub_graphs,
                                      &cmd_hdr, NULL);
    if (rc < 0) {
        /*
         * P5: do not leak the bracket this call opened. The primary error (the build failure)
         * is returned unchanged; a failing cleanup END is recorded (sync_end_failures,
         * cleanup_error, cpu_access_active stays true) but never replaces it.
         */
        if (opened_here) {
            int crc = m11_shmem_end_cpu_access(shmem_mgr, region);
            region->last_error = rc;
            if (crc < 0) region->cleanup_error = crc;
        } else {
            region->last_error = rc;
        }
        return rc;
    }

    /*
     * 3. END_RW (0x7) before transmitting GRAPH_OPEN. PROPOSED DESIGN, not a stock-confirmed
     *    ordering: stock was only observed to START at allocation and END at free (see the
     *    evidence note in m11_shmem.h). Linux dma-buf semantics make END the point where CPU
     *    writes become visible to attached devices, so this order is the conservative choice.
     *    If END fails, the bracket is still open and no cache sync may be claimed, so
     *    GRAPH_OPEN is NOT sent and the END error is returned.
     */
    rc = m11_shmem_end_cpu_access(shmem_mgr, region);
    if (rc < 0) return rc;

    if (region->cpu_access_active || !region->cpu_cache_clean_for_dsp) {
        return -EIO;
    }

    return m11_gpr_engine_transact(gpr, M11_APM_MODULE_IID, M11_APM_CMD_GRAPH_OPEN,
                                   &cmd_hdr, sizeof(cmd_hdr), timeout_ms,
                                   out_dsp_status, NULL, 0, NULL);
}

int m11_apm_transact_graph_mgmt(m11_gpr_engine_t *gpr, uint32_t opcode,
                                const uint32_t *sub_graph_ids, uint32_t num_sub_graphs,
                                uint32_t timeout_ms, uint32_t *out_dsp_status) {
    if (!gpr || !is_valid_graph_mgmt_opcode(opcode)) return -EINVAL;
    uint8_t payload[256];
    size_t payload_len = 0u;
    int rc = m11_apm_build_graph_mgmt_inband_payload(payload, sizeof(payload), &payload_len,
                                                     sub_graph_ids, num_sub_graphs);
    if (rc < 0) return rc;

    return m11_gpr_engine_transact(gpr, M11_APM_MODULE_IID, opcode,
                                   payload, payload_len, timeout_ms,
                                   out_dsp_status, NULL, 0, NULL);
}
