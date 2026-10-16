#include "m11_strict_mock.h"

#include <errno.h>
#include <string.h>

#ifndef ENETRESET
#define ENETRESET 102
#endif

void m11_strict_mock_init(m11_strict_mock_t *m) {
    if (!m) return;
    memset(m, 0, sizeof(*m));
    m->spf_state = 1u;
    for (size_t i = 0; i < M11_MOCK_MAX_SHM_SLOTS; i++) {
        m->shm_slots[i].dma_fd = -1;
        m->shm_slots[i].kernel_iova = 0x80010000ULL + (uint64_t)i * 0x10000ULL;
    }
}

int m11_strict_mock_enqueue_raw_rx(m11_strict_mock_t *m, const uint8_t *pkt, size_t len) {
    if (!m || !pkt || len == 0 || len > M11_GPR_MAX_PKT_BYTES) return -EINVAL;
    if (m->rx_tail - m->rx_head >= M11_MOCK_MAX_QUEUE) return -ENOSPC;
    size_t idx = m->rx_tail % M11_MOCK_MAX_QUEUE;
    memcpy(m->rx_queue[idx], pkt, len);
    m->rx_lens[idx] = len;
    m->rx_tail++;
    return 0;
}

static int enqueue_rsp_pkt(m11_strict_mock_t *m, uint32_t src_port, uint32_t dst_port,
                           uint32_t token, uint32_t opcode,
                           const void *payload, size_t payload_len) {
    uint8_t dst_dom = M11_GPR_DOMAIN_APPS;
    uint8_t src_dom = M11_GPR_DOMAIN_ADSP;
    if (m->wrong_peer_on_rsp) {
        src_dom = M11_GPR_DOMAIN_MODEM;
    }
    if (m->wrong_token_on_rsp) {
        token ^= 0x5555u;
    }
    if (m->wrong_opcode_on_rsp) {
        opcode = 0x02FFFFFFu;
    }
    uint8_t pkt[M11_GPR_MAX_PKT_BYTES];
    size_t pkt_len = 0u;
    int rc = m11_gpr_pack_packet_ex(pkt, sizeof(pkt), &pkt_len,
                                    dst_dom, src_dom,
                                    M11_GPR_CLIENT_DATA_DEFAULT,
                                    dst_port, src_port,
                                    token, opcode, payload, payload_len);
    if (rc < 0) return rc;
    if (m->hold_next_rsp) {
        m->hold_next_rsp = false;
        if (m->held_count >= M11_MOCK_MAX_HELD) return -ENOSPC;
        memcpy(m->held_pkt[m->held_count], pkt, pkt_len);
        m->held_len[m->held_count] = pkt_len;
        m->held_count++;
        return 0;
    }
    rc = m11_strict_mock_enqueue_raw_rx(m, pkt, pkt_len);
    if (rc == 0 && m->duplicate_next_rsp) {
        m->duplicate_next_rsp = false;
        rc = m11_strict_mock_enqueue_raw_rx(m, pkt, pkt_len);
    }
    return rc;
}

size_t m11_strict_mock_release_held(m11_strict_mock_t *m) {
    size_t moved = 0u;
    if (!m) return 0u;
    for (size_t i = 0; i < m->held_count; i++) {
        if (m11_strict_mock_enqueue_raw_rx(m, m->held_pkt[i], m->held_len[i]) == 0) moved++;
        if (m->duplicate_next_rsp) {
            /* A duplicated late ACK: the same packet arrives twice. */
            (void)m11_strict_mock_enqueue_raw_rx(m, m->held_pkt[i], m->held_len[i]);
        }
    }
    m->duplicate_next_rsp = false;
    m->held_count = 0u;
    return moved;
}

static int enqueue_ibasic_rsp(m11_strict_mock_t *m, uint32_t src_port, uint32_t dst_port,
                              uint32_t token, uint32_t cmd_opcode, uint32_t status) {
    m11_gpr_ibasic_rsp_t ib = {
        .cmd_opcode = cmd_opcode,
        .status = status,
    };
    return enqueue_rsp_pkt(m, src_port, dst_port, token,
                           M11_GPR_IBASIC_RSP_RESULT, &ib, sizeof(ib));
}

static m11_mock_shm_slot_t *find_shm_slot_by_fd(m11_strict_mock_t *m, int dma_fd) {
    for (size_t i = 0; i < M11_MOCK_MAX_SHM_SLOTS; i++) {
        if (m->shm_slots[i].allocated && m->shm_slots[i].dma_fd == dma_fd) {
            return &m->shm_slots[i];
        }
    }
    return NULL;
}

static m11_mock_shm_slot_t *find_shm_slot_by_handle(m11_strict_mock_t *m, uint32_t handle) {
    if (handle == 0u) return NULL;
    for (size_t i = 0; i < M11_MOCK_MAX_SHM_SLOTS; i++) {
        if (m->shm_slots[i].allocated && m->shm_slots[i].dsp_map_handle == handle) {
            return &m->shm_slots[i];
        }
    }
    return NULL;
}

static m11_mock_shm_slot_t *find_shm_slot_by_iova(m11_strict_mock_t *m, uint64_t iova) {
    for (size_t i = 0; i < M11_MOCK_MAX_SHM_SLOTS; i++) {
        if (m->shm_slots[i].allocated && m->shm_slots[i].ion_imported &&
            m->shm_slots[i].kernel_iova == iova) {
            return &m->shm_slots[i];
        }
    }
    return NULL;
}

static bool match_vi_subgraphs(const uint32_t *sgs, uint32_t count) {
    return (count == 2u && sgs[0] == 0xB00000D5u && sgs[1] == 0xB00000CEu);
}

static bool match_rx_subgraphs(const uint32_t *sgs, uint32_t count) {
    return (count == 4u &&
            sgs[0] == 0xB0000023u &&
            sgs[1] == 0xB0000024u &&
            sgs[2] == 0xB0000025u &&
            sgs[3] == 0xB0000002u);
}

/* Mock GPR transport callbacks */
static int mock_gpr_open(void *user) {
    m11_strict_mock_t *m = (m11_strict_mock_t *)user;
    if (m->gpr_fd_open) return -EBUSY;
    m->gpr_fd_open = true;
    return 42;
}

static int mock_gpr_close(void *user, int fd) {
    m11_strict_mock_t *m = (m11_strict_mock_t *)user;
    if (!m->gpr_fd_open || fd != 42) return -EBADF;
    m->gpr_fd_open = false;
    return 0;
}

static int mock_gpr_write(void *user, int fd, const uint8_t *buf, size_t len) {
    m11_strict_mock_t *m = (m11_strict_mock_t *)user;
    if (!m->gpr_fd_open || fd != 42) return -EBADF;
    if (!buf || len < M11_GPR_HDR_BYTES || len > M11_GPR_MAX_PKT_BYTES) {
        m->rejected_hdr_count++;
        m->last_reject_reason = -EBADMSG;
        return -EBADMSG;
    }

    uint8_t work[M11_GPR_MAX_PKT_BYTES];
    size_t work_len = len;
    memcpy(work, buf, len);

    /* Apply optional TX mutations BEFORE kernel/ADSP validation */
    if (m->mutate_swap_gpr_domain_and_port) {
        /*
         * Mutate canonical v0 header into old broken Argon layout:
         * place dst_port at +0x04, src_port at +0x08, dst_domain at +0x0c, src_domain at +0x0d.
         */
        uint8_t dst_dom = work[4];
        uint8_t src_dom = work[5];
        uint16_t cdata = 0;
        memcpy(&cdata, work + 6, 2);
        uint32_t src_p = 0, dst_p = 0;
        memcpy(&src_p, work + 8, 4);
        memcpy(&dst_p, work + 12, 4);
        memcpy(work + 4, &dst_p, 4);
        memcpy(work + 8, &src_p, 4);
        work[12] = dst_dom;
        work[13] = src_dom;
        memcpy(work + 14, &cdata, 2);
    }
    if (m->mutate_mem_pool_id_to_4 && len >= M11_GPR_HDR_BYTES + sizeof(m11_apm_cmd_shared_mem_map_regions_t)) {
        uint32_t op = 0;
        memcpy(&op, work + 0x14, 4);
        if (op == M11_APM_CMD_SHARED_MEM_MAP_REGIONS) {
            uint16_t bad_pool = 4u;
            memcpy(work + 0x18, &bad_pool, 2);
        }
    }
    if (m->mutate_fake_phys_addr_in_map && len >= M11_GPR_HDR_BYTES + sizeof(m11_apm_cmd_shared_mem_map_regions_t)) {
        uint32_t op = 0;
        memcpy(&op, work + 0x14, 4);
        if (op == M11_APM_CMD_SHARED_MEM_MAP_REGIONS) {
            uint32_t fake_pa = 0x80001000u;
            memcpy(work + 0x20, &fake_pa, 4);
        }
    }
    if (m->mutate_clear_client_data_on_map) {
        uint32_t op = 0;
        memcpy(&op, work + 0x14, 4);
        if (op == M11_APM_CMD_SHARED_MEM_MAP_REGIONS) {
            work[6] = 0u;
        }
    }
    if (m->mutate_set_cfg_dst_port_to_1) {
        uint32_t op = 0;
        memcpy(&op, work + 0x14, 4);
        if (op == M11_APM_CMD_SET_CFG || op == M11_APM_CMD_GET_CFG) {
            uint32_t port1 = M11_APM_MODULE_IID;
            memcpy(work + 0x0c, &port1, 4);
        }
    }
    if (m->mutate_raw_subgraph_array_on_graph_cmd) {
        uint32_t op = 0;
        memcpy(&op, work + 0x14, 4);
        if (op == M11_APM_CMD_GRAPH_PREPARE || op == M11_APM_CMD_GRAPH_START ||
            op == M11_APM_CMD_GRAPH_STOP || op == M11_APM_CMD_GRAPH_CLOSE) {
            /* Strip apm_cmd_header_t and 0x08001005 header, leaving raw 8B/16B sg array */
            uint32_t raw_sgs[2] = { 0xB00000D5u, 0xB00000CEu };
            work_len = M11_GPR_HDR_BYTES + sizeof(raw_sgs);
            uint32_t new_hdr = m11_gpr_make_header_word(0u, 6u, (uint32_t)work_len);
            memcpy(work, &new_hdr, 4);
            memcpy(work + M11_GPR_HDR_BYTES, raw_sgs, sizeof(raw_sgs));
        }
    }

    memcpy(m->last_tx_pkt, work, work_len);
    m->last_tx_len = work_len;
    m->tx_pkt_count++;

    /*
     * Layer 1: Kernel gpr_dlkm.ko wire header & source-port admission check.
     */
    m11_gpr_hdr_t hdr;
    const uint8_t *pl = NULL;
    size_t pl_len = 0u;
    int rc = m11_gpr_validate_packet(work, work_len, &hdr, &pl, &pl_len);
    if (rc < 0 ||
        hdr.dst_domain_id != M11_GPR_DOMAIN_ADSP ||
        hdr.src_domain_id != M11_GPR_DOMAIN_APPS ||
        !m11_gpr_is_valid_src_port(hdr.src_port) ||
        hdr.token == 0u) {
        m->rejected_hdr_count++;
        m->last_reject_reason = -EINVAL;
        return -EINVAL;
    }

    /*
     * Layer 2: Kernel audio_pkt_dlkm.ko (audpkt_chk_and_update_physical_addr @ 0x1001f4)
     * intercepts opcode 0x0100100C when hdr.client_data == 1, looks up (int)shm_addr_lsw
     * in audpkt_ion_dlkm.ko's msm_audio_ion_fd_list, and overwrites shm_addr_lsw/msw
     * with the DMA-BUF physical IOVA in-place before gpr_send_pkt().
     */
    if (hdr.opcode == M11_APM_CMD_SHARED_MEM_UNMAP_REGIONS) {
        if (m->fail_gpr_write_on_unmap) {
            m->last_reject_reason = -EIO;
            return -EIO;
        }
        if (m->short_gpr_write_on_unmap) {
            m->last_reject_reason = -EIO;
            return (int)M11_GPR_HDR_BYTES;
        }
    }
    if (hdr.opcode == M11_APM_CMD_GRAPH_OPEN && m->fail_gpr_write_on_graph_open) {
        m->last_reject_reason = -EIO;
        return -EIO;
    }
    if (hdr.opcode == M11_APM_CMD_SHARED_MEM_MAP_REGIONS) {
        if (m->fail_gpr_write_on_map) {
            m->last_reject_reason = -EIO;
            return -EIO;
        }
        if (m->short_gpr_write_on_map) {
            /*
             * Simulate a partial/short write return from write_fn().
             * Per audio_pkt_dlkm.ko (audio_pkt_write @ 0x0010170c), userspace cannot
             * assume a short write or driver error guarantees no packet reached ADSP.
             */
            m->last_reject_reason = -EIO;
            return (int)M11_GPR_HDR_BYTES;
        }
        if (hdr.client_data == M11_GPR_CLIENT_DATA_SHMEM_OFFSET_MODE) {
            if (pl_len < sizeof(m11_apm_cmd_shared_mem_map_regions_t)) {
                m->rejected_shmem_count++;
                m->last_reject_reason = -EBADMSG;
                return -EBADMSG;
            }
            m11_apm_cmd_shared_mem_map_regions_t map_cmd;
            memcpy(&map_cmd, pl, sizeof(map_cmd));
            m11_mock_shm_slot_t *slot = find_shm_slot_by_fd(m, (int)map_cmd.shm_addr_lsw);
            if (!slot || !slot->ion_imported || map_cmd.shm_addr_msw != 0u) {
                /* Kernel msm_audio_get_phy_addr lookup failed! */
                m->rejected_shmem_count++;
                m->last_reject_reason = -EFAULT;
                return -EFAULT;
            }
            /* Kernel rewrites shm_addr_lsw / shm_addr_msw in-place to the DMA-BUF IOVA */
            map_cmd.shm_addr_lsw = (uint32_t)(slot->kernel_iova & 0xFFFFFFFFULL);
            map_cmd.shm_addr_msw = (uint32_t)(slot->kernel_iova >> 32);
            memcpy(work + M11_GPR_HDR_BYTES, &map_cmd, sizeof(map_cmd));
            pl = work + M11_GPR_HDR_BYTES;
        }
    }

    /*
     * Layer 3: Modeled ADSP APM (port 1) and Awinic SP_RX Module (port 0x42D3) dispatch.
     */
    switch (hdr.opcode) {
        case M11_APM_CMD_GET_SPF_STATE: {
            if (hdr.dst_port != M11_APM_MODULE_IID || pl_len != 0u) {
                m->rejected_hdr_count++;
                (void)enqueue_ibasic_rsp(m, hdr.dst_port, hdr.src_port, hdr.token, hdr.opcode, 1u);
                break;
            }
            m11_apm_rsp_get_spf_state_t rsp = { .status = m->spf_state };
            (void)enqueue_rsp_pkt(m, M11_APM_MODULE_IID, hdr.src_port, hdr.token,
                                  M11_APM_CMD_RSP_GET_SPF_STATE, &rsp, sizeof(rsp));
            break;
        }

        case M11_APM_CMD_SHARED_MEM_MAP_REGIONS: {
            m->map_cmd_count++;
            if (m->drop_shmem_map_rsp) break;
            if (hdr.dst_port != M11_APM_MODULE_IID ||
                pl_len != sizeof(m11_apm_cmd_shared_mem_map_regions_t)) {
                m->rejected_shmem_count++;
                m->last_reject_reason = -EPROTO;
                (void)enqueue_ibasic_rsp(m, hdr.dst_port, hdr.src_port, hdr.token, hdr.opcode, 1u);
                break;
            }
            m11_apm_cmd_shared_mem_map_regions_t map_cmd;
            memcpy(&map_cmd, pl, sizeof(map_cmd));

            uint64_t iova = ((uint64_t)map_cmd.shm_addr_msw << 32) | map_cmd.shm_addr_lsw;
            m11_mock_shm_slot_t *slot = find_shm_slot_by_iova(m, iova);

            /*
             * Stock ADSP APM requires:
             *   - mem_pool_id == 3 (APM_MEMORY_MAP_SHMEM8_4K_POOL)
             *   - num_regions == 1
             *   - property_flag == 0x4 (APM_MEMORY_MAP_OFFSET_MODE)
             *   - kernel-translated IOVA matching an active msm_audio_ion import
             */
            if (m->nack_shmem_map ||
                hdr.client_data != M11_GPR_CLIENT_DATA_SHMEM_OFFSET_MODE ||
                map_cmd.mem_pool_id != M11_APM_MEMORY_MAP_SHMEM8_4K_POOL ||
                map_cmd.num_regions != 1u ||
                map_cmd.property_flag != M11_APM_MEMORY_MAP_OFFSET_MODE ||
                !slot ||
                map_cmd.mem_size_bytes != slot->aligned_bytes) {
                m->rejected_shmem_count++;
                m->last_reject_reason = -EREMOTEIO;
                (void)enqueue_ibasic_rsp(m, M11_APM_MODULE_IID, hdr.src_port, hdr.token, hdr.opcode, 1u);
                break;
            }

            if (m->zero_handle_shmem_map_rsp) {
                m11_apm_rsp_shared_mem_map_t bad_rsp = { .mem_map_handle = 0u };
                (void)enqueue_rsp_pkt(m, M11_APM_MODULE_IID, hdr.src_port, hdr.token,
                                      M11_APM_CMDRSP_SHARED_MEM_MAP_REGIONS, &bad_rsp, sizeof(bad_rsp));
                break;
            }

            slot->dsp_map_handle = 0xA0000001u + (uint32_t)(slot - m->shm_slots);
            m11_apm_rsp_shared_mem_map_t rsp = { .mem_map_handle = slot->dsp_map_handle };
            (void)enqueue_rsp_pkt(m, M11_APM_MODULE_IID, hdr.src_port, hdr.token,
                                  M11_APM_CMDRSP_SHARED_MEM_MAP_REGIONS, &rsp, sizeof(rsp));
            break;
        }

        case M11_APM_CMD_SHARED_MEM_UNMAP_REGIONS: {
            m->unmap_cmd_count++;
            if (m->drop_shmem_unmap_rsp) break;
            if (hdr.dst_port != M11_APM_MODULE_IID ||
                pl_len != sizeof(m11_apm_cmd_shared_mem_unmap_regions_t)) {
                m->rejected_shmem_count++;
                (void)enqueue_ibasic_rsp(m, hdr.dst_port, hdr.src_port, hdr.token, hdr.opcode, 1u);
                break;
            }
            m11_apm_cmd_shared_mem_unmap_regions_t unmap_cmd;
            memcpy(&unmap_cmd, pl, sizeof(unmap_cmd));
            m11_mock_shm_slot_t *slot = find_shm_slot_by_handle(m, unmap_cmd.mem_map_handle);
            if (m->nack_shmem_unmap || !slot) {
                m->rejected_shmem_count++;
                (void)enqueue_ibasic_rsp(m, M11_APM_MODULE_IID, hdr.src_port, hdr.token, hdr.opcode, 1u);
                break;
            }
            slot->dsp_map_handle = 0u;
            (void)enqueue_ibasic_rsp(m, M11_APM_MODULE_IID, hdr.src_port, hdr.token, hdr.opcode, 0u);
            break;
        }

        case M11_APM_CMD_GRAPH_OPEN: {
            m->graph_open_cmd_count++;
            if (m->drop_graph_open_rsp) break;
            if (hdr.dst_port != M11_APM_MODULE_IID || pl_len != sizeof(m11_apm_cmd_header_t)) {
                m->rejected_graph_count++;
                m->last_reject_reason = -EBADMSG;
                (void)enqueue_ibasic_rsp(m, hdr.dst_port, hdr.src_port, hdr.token, hdr.opcode, 1u);
                break;
            }
            m11_apm_cmd_header_t cmd_hdr;
            memcpy(&cmd_hdr, pl, sizeof(cmd_hdr));
            m11_mock_shm_slot_t *slot = find_shm_slot_by_handle(m, cmd_hdr.mem_map_handle);
            if (m->nack_graph_open || !slot || cmd_hdr.payload_address_msw != 0u ||
                (size_t)cmd_hdr.payload_address_lsw + (size_t)cmd_hdr.payload_size > slot->aligned_bytes) {
                m->rejected_graph_count++;
                m->last_reject_reason = -EPROTO;
                (void)enqueue_ibasic_rsp(m, M11_APM_MODULE_IID, hdr.src_port, hdr.token, hdr.opcode, 1u);
                break;
            }

            /*
             * MOCK ASSUMPTION (test scaffolding, NOT a statement about the real ADSP):
             * this mock rejects GRAPH_OPEN while the CPU bracket is open or the cache is not
             * marked clean. A real ADSP cannot observe the CPU-side DMA_BUF_IOCTL_SYNC
             * bracket, and no stock evidence was recorded that stock issues END_RW before
             * GRAPH_OPEN (stock was only observed to START at allocation, END at free).
             * The rule exists so the proposed END-before-GRAPH_OPEN design in
             * m11_apm_transact_graph_open_region() is exercised, nothing more.
             */
            if (slot->cpu_access_active || !slot->cache_clean_for_dsp) {
                m->rejected_graph_count++;
                m->rejected_cache_sync_count++;
                m->last_reject_reason = -EAGAIN;
                (void)enqueue_ibasic_rsp(m, M11_APM_MODULE_IID, hdr.src_port, hdr.token, hdr.opcode, 1u);
                break;
            }

            uint32_t sgs[M11_APM_MAX_SUBGRAPHS_PER_CMD];
            uint32_t num_sgs = 0u;
            int vrc = m11_apm_validate_subgraph_list_block(
                slot->mem + cmd_hdr.payload_address_lsw,
                cmd_hdr.payload_size,
                &num_sgs, sgs, M11_APM_MAX_SUBGRAPHS_PER_CMD);
            if (vrc < 0) {
                m->rejected_graph_count++;
                m->last_reject_reason = vrc;
                (void)enqueue_ibasic_rsp(m, M11_APM_MODULE_IID, hdr.src_port, hdr.token, hdr.opcode, 1u);
                break;
            }

            if (match_vi_subgraphs(sgs, num_sgs)) {
                m->vi_tx_opened = true;
            } else if (match_rx_subgraphs(sgs, num_sgs)) {
                m->rx_opened = true;
            } else {
                m->rejected_graph_count++;
                m->last_reject_reason = -ENOENT;
                (void)enqueue_ibasic_rsp(m, M11_APM_MODULE_IID, hdr.src_port, hdr.token, hdr.opcode, 1u);
                break;
            }
            (void)enqueue_ibasic_rsp(m, M11_APM_MODULE_IID, hdr.src_port, hdr.token, hdr.opcode, 0u);
            break;
        }

        case M11_APM_CMD_GRAPH_PREPARE:
        case M11_APM_CMD_GRAPH_START:
        case M11_APM_CMD_GRAPH_STOP:
        case M11_APM_CMD_GRAPH_CLOSE: {
            if (hdr.opcode == M11_APM_CMD_GRAPH_PREPARE && m->pdr_on_graph_prepare) {
                return -ENETRESET;
            }
            if (hdr.opcode == M11_APM_CMD_GRAPH_START && m->drop_graph_start_rsp) break;
            if (hdr.opcode == M11_APM_CMD_GRAPH_STOP && m->drop_graph_stop_rsp) break;
            if (hdr.opcode == M11_APM_CMD_GRAPH_CLOSE && m->drop_graph_close_rsp) break;

            if (hdr.dst_port != M11_APM_MODULE_IID) {
                m->rejected_graph_count++;
                m->last_reject_reason = -EPROTO;
                (void)enqueue_ibasic_rsp(m, hdr.dst_port, hdr.src_port, hdr.token, hdr.opcode, 1u);
                break;
            }

            uint32_t sgs[M11_APM_MAX_SUBGRAPHS_PER_CMD];
            uint32_t num_sgs = 0u;
            int vrc = m11_apm_validate_graph_mgmt_inband_payload(
                pl, pl_len, &num_sgs, sgs, M11_APM_MAX_SUBGRAPHS_PER_CMD);
            if (vrc < 0 || (hdr.opcode == M11_APM_CMD_GRAPH_CLOSE && m->nack_graph_close)) {
                m->rejected_graph_count++;
                m->last_reject_reason = (vrc < 0) ? vrc : -EREMOTEIO;
                (void)enqueue_ibasic_rsp(m, M11_APM_MODULE_IID, hdr.src_port, hdr.token, hdr.opcode, 1u);
                break;
            }

            bool is_vi = match_vi_subgraphs(sgs, num_sgs);
            bool is_rx = match_rx_subgraphs(sgs, num_sgs);
            if (!is_vi && !is_rx) {
                m->rejected_graph_count++;
                m->last_reject_reason = -ENOENT;
                (void)enqueue_ibasic_rsp(m, M11_APM_MODULE_IID, hdr.src_port, hdr.token, hdr.opcode, 1u);
                break;
            }

            if (hdr.opcode == M11_APM_CMD_GRAPH_PREPARE) {
                if ((is_vi && !m->vi_tx_opened) || (is_rx && !m->rx_opened)) {
                    m->rejected_graph_count++;
                    (void)enqueue_ibasic_rsp(m, M11_APM_MODULE_IID, hdr.src_port, hdr.token, hdr.opcode, 1u);
                    break;
                }
                if (is_vi) m->vi_tx_prepared = true;
                if (is_rx) m->rx_prepared = true;
            } else if (hdr.opcode == M11_APM_CMD_GRAPH_START) {
                if ((is_vi && !m->vi_tx_prepared) || (is_rx && !m->rx_prepared)) {
                    m->rejected_graph_count++;
                    (void)enqueue_ibasic_rsp(m, M11_APM_MODULE_IID, hdr.src_port, hdr.token, hdr.opcode, 1u);
                    break;
                }
                if (is_vi) m->vi_tx_started = true;
                if (is_rx) m->rx_started = true;
            } else if (hdr.opcode == M11_APM_CMD_GRAPH_STOP) {
                if (is_vi) m->vi_tx_started = false;
                if (is_rx) m->rx_started = false;
            } else if (hdr.opcode == M11_APM_CMD_GRAPH_CLOSE) {
                if (is_vi) { m->vi_tx_opened = false; m->vi_tx_prepared = false; }
                if (is_rx) { m->rx_opened = false; m->rx_prepared = false; }
            }

            (void)enqueue_ibasic_rsp(m, M11_APM_MODULE_IID, hdr.src_port, hdr.token, hdr.opcode, 0u);
            break;
        }

        case M11_APM_CMD_SET_CFG: {
            if (m->drop_set_cfg_rsp) break;
            uint32_t ch = 0u, q12_re = 0u;
            int vrc = m11_aw_validate_cfg_req_pkt(work, work_len, M11_APM_CMD_SET_CFG, &ch, &q12_re);
            bool ch_nack = (vrc == 0 && ch < 2u && ((m->nack_set_cfg_ch_mask >> ch) & 1u) != 0u);
            if (vrc < 0 || m->nack_set_cfg || ch_nack || !m->vi_tx_opened || !m->vi_tx_prepared) {
                m->rejected_cfg_count++;
                m->last_reject_reason = (vrc < 0) ? vrc : -EPROTO;
                (void)enqueue_ibasic_rsp(m, hdr.dst_port, hdr.src_port, hdr.token, hdr.opcode, 1u);
                break;
            }
            m->stored_q12_re[ch] = q12_re;
            if (((m->ack_lost_set_cfg_ch_mask >> ch) & 1u) != 0u) break; /* applied, no ACK */
            (void)enqueue_ibasic_rsp(m, M11_AW_SP_RX_MODULE_IID, hdr.src_port, hdr.token, hdr.opcode, 0u);
            break;
        }

        case M11_APM_CMD_GET_CFG: {
            uint32_t ch = 0u, unused_q12 = 0u;
            int vrc = m11_aw_validate_cfg_req_pkt(work, work_len, M11_APM_CMD_GET_CFG, &ch, &unused_q12);
            if (vrc < 0 || !m->vi_tx_opened || !m->vi_tx_prepared) {
                m->rejected_cfg_count++;
                m->last_reject_reason = (vrc < 0) ? vrc : -EPROTO;
                (void)enqueue_ibasic_rsp(m, hdr.dst_port, hdr.src_port, hdr.token, hdr.opcode, 1u);
                break;
            }

            if (((m->drop_get_cfg_rsp_ch_mask >> ch) & 1u) != 0u) break;

            m11_apm_rsp_aw_re_get_cfg_t rsp;
            memset(&rsp, 0, sizeof(rsp));
            rsp.status = 0u;
            (void)m11_aw_build_re_envelope_48(ch, M11_MARBLE_CH0_FACTORY_MOHM, &rsp.env);
            rsp.env.q12_re = m->stored_q12_re[ch];
            if (m->corrupt_get_cfg_q12 || ((m->corrupt_get_cfg_ch_mask >> ch) & 1u) != 0u) {
                rsp.env.q12_re ^= 0x1234u;
            }

            size_t rsp_len = sizeof(rsp);
            if (m->truncate_get_cfg_rsp) {
                rsp_len = 20u; /* Truncated payload (< 52 bytes) */
            }
            (void)enqueue_rsp_pkt(m, M11_AW_SP_RX_MODULE_IID, hdr.src_port, hdr.token,
                                  M11_APM_CMD_RSP_GET_CFG, &rsp, rsp_len);
            break;
        }

        default:
            (void)enqueue_ibasic_rsp(m, hdr.dst_port, hdr.src_port, hdr.token, hdr.opcode, 1u);
            break;
    }

    if (hdr.opcode == M11_APM_CMD_SHARED_MEM_MAP_REGIONS && m->deliver_then_fail_write_on_map) {
        m->last_reject_reason = -EIO;
        return -EIO; /* the ADSP already processed it; the host only sees the error */
    }
    if (hdr.opcode == M11_APM_CMD_SHARED_MEM_UNMAP_REGIONS && m->deliver_then_fail_write_on_unmap) {
        m->last_reject_reason = -EIO;
        return -EIO;
    }
    return (int)len;
}

static int mock_gpr_poll_read(void *user, int fd, uint8_t *buf, size_t cap, uint32_t timeout_ms) {
    (void)timeout_ms;
    m11_strict_mock_t *m = (m11_strict_mock_t *)user;
    m->poll_read_call_count++;
    if (m->poll_read_errno < 0) return m->poll_read_errno;
    if (!m->gpr_fd_open || fd != 42) return -EBADF;
    if (m->rx_head == m->rx_tail) return 0; /* Timeout */

    size_t idx = m->rx_head % M11_MOCK_MAX_QUEUE;
    size_t pkt_len = m->rx_lens[idx];
    if (pkt_len > cap) return -EMSGSIZE;
    memcpy(buf, m->rx_queue[idx], pkt_len);
    m->rx_head++;
    return (int)pkt_len;
}

/* Mock DMA-BUF / msm_audio_ion callbacks */
static int mock_dma_heap_alloc(void *user, size_t aligned_bytes, int *out_dma_fd) {
    m11_strict_mock_t *m = (m11_strict_mock_t *)user;
    if (m->fail_dma_alloc) return -ENOMEM;
    if (!out_dma_fd || aligned_bytes == 0 || aligned_bytes > M11_MOCK_SHM_SLOT_BYTES) {
        return -EINVAL;
    }
    for (size_t i = 0; i < M11_MOCK_MAX_SHM_SLOTS; i++) {
        if (!m->shm_slots[i].allocated) {
            memset(&m->shm_slots[i], 0, sizeof(m->shm_slots[i]));
            m->shm_slots[i].allocated = true;
            m->shm_slots[i].dma_fd = M11_MOCK_DMA_FD_BASE + (int)i;
            m->shm_slots[i].aligned_bytes = aligned_bytes;
            m->shm_slots[i].kernel_iova = 0x80010000ULL + (uint64_t)i * 0x10000ULL;
            *out_dma_fd = m->shm_slots[i].dma_fd;
            return 0;
        }
    }
    return -ENOSPC;
}

static void *mock_mmap(void *user, int dma_fd, size_t aligned_bytes) {
    m11_strict_mock_t *m = (m11_strict_mock_t *)user;
    if (m->fail_mmap) return NULL;
    m11_mock_shm_slot_t *slot = find_shm_slot_by_fd(m, dma_fd);
    if (!slot || slot->mmap_active || slot->aligned_bytes != aligned_bytes) return NULL;
    slot->mmap_active = true;
    return slot->mem;
}

static int mock_munmap(void *user, void *vaddr, size_t aligned_bytes) {
    m11_strict_mock_t *m = (m11_strict_mock_t *)user;
    for (size_t i = 0; i < M11_MOCK_MAX_SHM_SLOTS; i++) {
        if (m->shm_slots[i].allocated && m->shm_slots[i].mem == vaddr &&
            m->shm_slots[i].dsp_map_handle != 0u) {
            m->unsafe_release_attempts++;
        }
    }
    if (m->fail_munmap) return -EIO;
    for (size_t i = 0; i < M11_MOCK_MAX_SHM_SLOTS; i++) {
        if (m->shm_slots[i].allocated && m->shm_slots[i].mmap_active &&
            m->shm_slots[i].mem == vaddr && m->shm_slots[i].aligned_bytes == aligned_bytes) {
            m->shm_slots[i].mmap_active = false;
            return 0;
        }
    }
    return -EINVAL;
}

static int mock_close_fd(void *user, int dma_fd) {
    m11_strict_mock_t *m = (m11_strict_mock_t *)user;
    m11_mock_shm_slot_t *slot = find_shm_slot_by_fd(m, dma_fd);
    if (slot && slot->dsp_map_handle != 0u) m->unsafe_release_attempts++;
    if (m->fail_close_fd) return -EIO;
    if (!slot || slot->mmap_active || slot->ion_imported || slot->dsp_map_handle != 0u) {
        return -EBUSY;
    }
    slot->allocated = false;
    slot->dma_fd = -1;
    return 0;
}

static int mock_dma_buf_sync(void *user, int dma_fd, uint64_t sync_flags) {
    m11_strict_mock_t *m = (m11_strict_mock_t *)user;
    m11_mock_shm_slot_t *slot = find_shm_slot_by_fd(m, dma_fd);
    if (!slot || !slot->mmap_active) return -EINVAL;

    if (sync_flags == M11_DMA_BUF_SYNC_START_RW) {
        if (m->fail_dma_buf_sync_start) return m->sync_start_errno ? m->sync_start_errno : -EIO;
        slot->cpu_access_active = true;
        slot->cache_clean_for_dsp = false;
        slot->sync_start_count++;
        return 0;
    }
    if (sync_flags == M11_DMA_BUF_SYNC_END_RW) {
        if (m->fail_dma_buf_sync_end) return m->sync_end_errno ? m->sync_end_errno : -EIO;
        if (!slot->cpu_access_active) return -EPROTO;
        if (m->skip_dma_buf_sync_end) {
            /*
             * Fault injection: pretend ioctl succeeded while leaving CPU cache
             * dirty / unsynchronized so ADSP GRAPH_OPEN catches the missing sync.
             */
            return 0;
        }
        slot->cpu_access_active = false;
        slot->cache_clean_for_dsp = slot->ion_imported;
        slot->sync_end_count++;
        return 0;
    }
    return -EINVAL;
}

static int mock_ion_import_fd(void *user, int dma_fd, bool hyp_assign) {
    m11_strict_mock_t *m = (m11_strict_mock_t *)user;
    if (m->fail_ion_import) return -EFAULT;
    m11_mock_shm_slot_t *slot = find_shm_slot_by_fd(m, dma_fd);
    if (!slot || slot->ion_imported) return -EINVAL;
    slot->ion_imported = true;
    slot->hyp_assigned = hyp_assign;
    return 0;
}

static int mock_ion_unmap_fd(void *user, int dma_fd, bool hyp_assign) {
    m11_strict_mock_t *m = (m11_strict_mock_t *)user;
    m11_mock_shm_slot_t *slot = find_shm_slot_by_fd(m, dma_fd);
    if (slot && slot->dsp_map_handle != 0u) m->unsafe_release_attempts++;
    if (m->fail_ion_unmap) return -EIO;
    if (!slot || !slot->ion_imported || slot->hyp_assigned != hyp_assign || slot->dsp_map_handle != 0u) {
        return -EBUSY;
    }
    slot->ion_imported = false;
    slot->hyp_assigned = false;
    return 0;
}

void m11_strict_mock_bind(m11_strict_mock_t *m,
                          m11_gpr_transport_t *out_transport,
                          m11_shmem_backend_t *out_shmem_backend) {
    if (out_transport) {
        memset(out_transport, 0, sizeof(*out_transport));
        out_transport->open_fn = mock_gpr_open;
        out_transport->close_fn = mock_gpr_close;
        out_transport->write_fn = mock_gpr_write;
        out_transport->poll_read_fn = mock_gpr_poll_read;
        out_transport->user = m;
    }
    if (out_shmem_backend) {
        memset(out_shmem_backend, 0, sizeof(*out_shmem_backend));
        out_shmem_backend->dma_heap_alloc_fn = mock_dma_heap_alloc;
        out_shmem_backend->mmap_fn = mock_mmap;
        out_shmem_backend->munmap_fn = mock_munmap;
        out_shmem_backend->close_fd_fn = mock_close_fd;
        out_shmem_backend->dma_buf_sync_fn = mock_dma_buf_sync;
        out_shmem_backend->ion_import_fd_fn = mock_ion_import_fd;
        out_shmem_backend->ion_unmap_fd_fn = mock_ion_unmap_fd;
        out_shmem_backend->user = m;
    }
}
