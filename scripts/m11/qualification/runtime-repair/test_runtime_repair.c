#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "m11_apm_protocol.h"
#include "m11_aw_protection.h"
#include "m11_gpr_engine.h"
#include "m11_offline_sim.h"
#include "m11_shmem.h"
#include "m11_strict_mock.h"

#ifndef ENETRESET
#define ENETRESET 102
#endif

/*
 * Old broken Argon GPR header struct reproduced solely to prove that the
 * new ABI validator and strict mock deterministically reject the old layout.
 */
typedef struct __attribute__((packed)) {
    uint32_t header;
    uint32_t dst_port;
    uint32_t src_port;
    uint8_t  dst_domain_id;
    uint8_t  src_domain_id;
    uint16_t client_data;
    uint32_t token;
    uint32_t opcode;
} old_argon_broken_gpr_hdr_t;

static void test_gate_a_gpr_wire_abi(void) {
    /* 1. Verify golden 24-byte APM_CMD_GET_SPF_STATE packet byte-for-byte */
    static const uint8_t expected_spf_pkt[24] = {
        0x60, 0x18, 0x00, 0x00, /* +0x00: ver=0, hdr_dwords=6, pkt_bytes=24 (0x00001860) */
        0x02,                   /* +0x04: dst_domain_id = 2 (ADSP) */
        0x03,                   /* +0x05: src_domain_id = 3 (APPS) */
        0x00,                   /* +0x06: client_data = 0 */
        0x00,                   /* +0x07: reserved = 0 */
        0x01, 0x20, 0x00, 0x00, /* +0x08: src_port = 0x00002001 */
        0x01, 0x00, 0x00, 0x00, /* +0x0c: dst_port = 0x00000001 */
        0x44, 0x33, 0x22, 0x11, /* +0x10: token = 0x11223344 */
        0x21, 0x10, 0x00, 0x01, /* +0x14: opcode = 0x01001021 (APM_CMD_GET_SPF_STATE) */
    };

    uint8_t pkt[64];
    size_t pkt_len = 0u;
    int rc = m11_gpr_pack_packet(pkt, sizeof(pkt), &pkt_len,
                                 M11_APM_MODULE_IID, 0x2001u,
                                 0x11223344u, M11_APM_CMD_GET_SPF_STATE,
                                 NULL, 0u);
    assert(rc == 0);
    assert(pkt_len == 24u);
    assert(memcmp(pkt, expected_spf_pkt, 24u) == 0);

    m11_gpr_hdr_t parsed_hdr;
    const uint8_t *pl = NULL;
    size_t pl_len = 99u;
    assert(m11_gpr_validate_packet(pkt, pkt_len, &parsed_hdr, &pl, &pl_len) == 0);
    assert(parsed_hdr.dst_domain_id == M11_GPR_DOMAIN_ADSP);
    assert(parsed_hdr.src_domain_id == M11_GPR_DOMAIN_APPS);
    assert(parsed_hdr.client_data == 0u);
    assert(parsed_hdr.reserved == 0u);
    assert(parsed_hdr.src_port == 0x2001u);
    assert(parsed_hdr.dst_port == 1u);
    assert(parsed_hdr.token == 0x11223344u);
    assert(parsed_hdr.opcode == M11_APM_CMD_GET_SPF_STATE);
    assert(pl_len == 0u);

    /* 2. Prove the old broken Argon header layout fails strict validation */
    old_argon_broken_gpr_hdr_t broken;
    memset(&broken, 0, sizeof(broken));
    broken.header = m11_gpr_make_header_word(0u, 6u, 24u);
    broken.dst_port = M11_APM_MODULE_IID;
    broken.src_port = 0x2001u;
    broken.dst_domain_id = M11_GPR_DOMAIN_ADSP;
    broken.src_domain_id = M11_GPR_DOMAIN_APPS;
    broken.client_data = 0u;
    broken.token = 1u;
    broken.opcode = M11_APM_CMD_GET_SPF_STATE;
    /* In canonical v0 offset +0x05, broken.dst_port byte 1 is 0x00 -> src_domain_id == 0 -> REJECTED! */
    assert(m11_gpr_validate_packet((const uint8_t *)&broken, sizeof(broken), NULL, NULL, NULL) == -EBADMSG);

    /* 3. Verify kernel dynamic source-port admission rules */
    assert(!m11_gpr_is_valid_src_port(0u));
    assert(!m11_gpr_is_valid_src_port(0x0003u)); /* spf_core_dlkm reserved */
    assert(!m11_gpr_is_valid_src_port(0x0017u)); /* audio_pkt_dlkm reserved */
    assert(!m11_gpr_is_valid_src_port(0x8000u)); /* negative 16-bit signed truncation */
    assert(!m11_gpr_is_valid_src_port(0x20010001u)); /* high 16 bits truncated by (short)port */
    assert(m11_gpr_is_valid_src_port(0x2001u));
    assert(m11_gpr_is_valid_src_port(0x2002u));
    assert(m11_gpr_is_valid_src_port(0x7FFFu));

    m11_strict_mock_t mock;
    m11_gpr_transport_t tp;
    m11_gpr_engine_t gpr;
    m11_strict_mock_init(&mock);
    m11_strict_mock_bind(&mock, &tp, NULL);
    assert(m11_gpr_engine_init(&gpr, &tp, 0u) == -EINVAL);
    assert(m11_gpr_engine_init(&gpr, &tp, 0x0003u) == -EINVAL);
    assert(m11_gpr_engine_init(&gpr, &tp, 0x0017u) == -EINVAL);
    assert(m11_gpr_engine_init(&gpr, &tp, 0x8000u) == -EINVAL);
    assert(m11_gpr_engine_init(&gpr, &tp, 0x2001u) == 0);

    /* 4. Verify peer identity, token correlation, and malformed RX rejection */
    assert(m11_gpr_engine_open(&gpr) == 0);
    mock.wrong_peer_on_rsp = true;
    uint32_t spf_state = 0u;
    assert(m11_gpr_query_spf_state(&gpr, 50u, &spf_state) == -ETIMEDOUT);
    assert(gpr.rx_dropped_malformed > 0u);
    mock.wrong_peer_on_rsp = false;

    mock.wrong_token_on_rsp = true;
    assert(m11_gpr_query_spf_state(&gpr, 50u, &spf_state) == -ETIMEDOUT);
    assert(gpr.rx_dropped_unknown_token > 0u);
    mock.wrong_token_on_rsp = false;

    /*
     * 5. P2a Regression: Transport errors in poll_read_fn (-EBADF, -ENODEV, -EPIPE, -EFAULT)
     * MUST abort m11_gpr_engine_wait_token immediately on the first poll_read_fn call
     * and return the exact transport errno (never spinning 64 times into -ETIMEDOUT).
     */
    static const int fatal_transport_errnos[] = { -EBADF, -ENODEV, -EPIPE, -EFAULT, -EINVAL };
    for (size_t i = 0; i < sizeof(fatal_transport_errnos) / sizeof(fatal_transport_errnos[0]); i++) {
        int expected_err = fatal_transport_errnos[i];
        mock.rx_head = mock.rx_tail; /* flush any queued RX packets */
        mock.poll_read_errno = expected_err;
        mock.poll_read_call_count = 0u;
        int qrc = m11_gpr_query_spf_state(&gpr, 50u, &spf_state);
        assert(qrc == expected_err);
        assert(qrc != -ETIMEDOUT);
        assert(gpr.last_rx_status == M11_GPR_RX_TRANSPORT_ERR);
        assert(mock.poll_read_call_count == 1u);
    }
    mock.poll_read_errno = 0;

    /*
     * Verify that a droppable stale/malformed packet followed by a valid response
     * skips the first packet (M11_GPR_RX_DROPPED_PACKET) and delivers the valid response.
     */
    {
        mock.rx_head = mock.rx_tail;
        uint8_t stale_pkt[32];
        size_t stale_len = 0u;
        m11_apm_rsp_get_spf_state_t stale_rsp = { .status = 1u };
        assert(m11_gpr_pack_packet_ex(stale_pkt, sizeof(stale_pkt), &stale_len,
                                      M11_GPR_DOMAIN_APPS, M11_GPR_DOMAIN_ADSP,
                                      M11_GPR_CLIENT_DATA_DEFAULT,
                                      0x2001u, M11_APM_MODULE_IID,
                                      0xDEAD9999u, M11_APM_CMD_RSP_GET_SPF_STATE,
                                      &stale_rsp, sizeof(stale_rsp)) == 0);
        assert(m11_strict_mock_enqueue_raw_rx(&mock, stale_pkt, stale_len) == 0);
        uint32_t prev_unknown = gpr.rx_dropped_unknown_token;
        assert(m11_gpr_query_spf_state(&gpr, 50u, &spf_state) == 0);
        assert(spf_state == 1u);
        assert(gpr.rx_dropped_unknown_token == prev_unknown + 1u);
        assert(gpr.last_rx_status == M11_GPR_RX_OK);
    }

    assert(m11_gpr_engine_close(&gpr) == 0);
}

/* Post-MAP hold: a held region keeps its mock slot and counters, so the next section starts
 * from a fresh fixture (the counters it asserts are relative to an empty manager). */
static void fresh_fixture(m11_strict_mock_t *mock, m11_gpr_transport_t *tp, m11_shmem_backend_t *sb,
                          m11_gpr_engine_t *gpr, m11_shmem_mgr_t *shmem) {
    m11_strict_mock_init(mock);
    m11_strict_mock_bind(mock, tp, sb);
    assert(m11_gpr_engine_init(gpr, tp, 0x2002u) == 0);
    assert(m11_gpr_engine_open(gpr) == 0);
    assert(m11_shmem_mgr_init(shmem, sb, gpr, 50u) == 0);
}

static void test_gate_b_dma_ion_offset_mode(void) {
    /* 1. Verify golden 44-byte APM_CMD_SHARED_MEM_MAP_REGIONS (0x0100100C) packet */
    static const uint8_t expected_map_pkt[44] = {
        0x60, 0x2C, 0x00, 0x00, /* +0x00: ver=0, hdr_dwords=6, pkt_bytes=44 (0x00002C60) */
        0x02,                   /* +0x04: dst_domain_id = 2 (ADSP) */
        0x03,                   /* +0x05: src_domain_id = 3 (APPS) */
        0x01,                   /* +0x06: client_data = 1 (GSL_SHMEM_MAP_OFFSET_MODE) */
        0x00,                   /* +0x07: reserved = 0 */
        0x02, 0x20, 0x00, 0x00, /* +0x08: src_port = 0x00002002 */
        0x01, 0x00, 0x00, 0x00, /* +0x0c: dst_port = 0x00000001 (APM) */
        0x01, 0x00, 0x00, 0x00, /* +0x10: token = 1 */
        0x0C, 0x10, 0x00, 0x01, /* +0x14: opcode = 0x0100100C */
        0x03, 0x00,             /* +0x18: mem_pool_id = 3 (APM_MEMORY_MAP_SHMEM8_4K_POOL) */
        0x01, 0x00,             /* +0x1a: num_regions = 1 */
        0x04, 0x00, 0x00, 0x00, /* +0x1c: property_flag = 0x4 (OFFSET_MODE) */
        0x64, 0x00, 0x00, 0x00, /* +0x20: shm_addr_lsw = 100 (dma_buf_fd) */
        0x00, 0x00, 0x00, 0x00, /* +0x24: shm_addr_msw = 0 */
        0x00, 0x50, 0x00, 0x00, /* +0x28: mem_size_bytes = 20480 (0x5000) */
    };

    uint8_t pkt[64];
    size_t pkt_len = 0u;
    assert(m11_shmem_pack_map_regions_pkt(pkt, sizeof(pkt), &pkt_len,
                                          0x2002u, 1u, 100, 20480u) == 0);
    assert(pkt_len == 44u);
    assert(memcmp(pkt, expected_map_pkt, 44u) == 0);

    /* 2. Happy path through the ownership state machine + DMA_BUF_IOCTL_SYNC tracking */
    m11_strict_mock_t mock;
    m11_gpr_transport_t tp;
    m11_shmem_backend_t sb;
    m11_gpr_engine_t gpr;
    m11_shmem_mgr_t shmem;

    m11_strict_mock_init(&mock);
    m11_strict_mock_bind(&mock, &tp, &sb);
    assert(m11_gpr_engine_init(&gpr, &tp, 0x2002u) == 0);
    assert(m11_gpr_engine_open(&gpr) == 0);
    assert(m11_shmem_mgr_init(&shmem, &sb, &gpr, 50u) == 0);

    m11_shmem_region_t reg;
    assert(m11_shmem_alloc_and_map(&shmem, M11_SHMEM_MODE_DMA_ION_OFFSET, 16416u, false, &reg) == 0);
    assert(reg.state == M11_SHMEM_STATE_DSP_MAP_ACKNOWLEDGED);
    assert(reg.dma_buf_fd == 100);
    assert(reg.ion_imported && reg.dsp_mapped);
    assert(reg.cpu_access_active && !reg.cpu_cache_clean_for_dsp);
    assert(reg.sync_start_count == 1u && reg.sync_end_count == 0u);
    assert(reg.mem_map_handle != 0u);
    assert(shmem.active_dma_fds == 1u && shmem.active_mmaps == 1u &&
           shmem.active_ion_imports == 1u && shmem.active_dsp_maps == 1u &&
           shmem.unresolved_regions == 0u);

    /*
     * Post-MAP hold (CP2 criterion 5, L3): the UNMAP research path is ACKed, but a region whose
     * MAP was transmitted is never released locally: no END sync, no ION unmap, no munmap, no close.
     */
    assert(reg.map_tx_started && !reg.map_tx_unsent_proof);
    assert(m11_shmem_unmap_and_free(&shmem, &reg) == -EPERM);
    assert(reg.state == M11_SHMEM_STATE_DSP_UNMAP_ACKNOWLEDGED && reg.remote_inactive && !reg.dsp_mapped);
    assert(reg.dma_buf_fd == 100 && reg.vaddr && reg.ion_imported && reg.cpu_access_active);
    assert(reg.sync_end_count == 0u);
    assert(shmem.active_dma_fds == 1u && shmem.active_mmaps == 1u &&
           shmem.active_ion_imports == 1u && shmem.active_dsp_maps == 0u &&
           shmem.unresolved_regions == 0u);
    assert(mock.unmap_cmd_count == 1u && mock.unsafe_release_attempts == 0u);
    assert(m11_shmem_unmap_and_free(&shmem, &reg) == -EPERM && reg.ion_imported && mock.unmap_cmd_count == 1u);
    assert(m11_gpr_engine_close(&gpr) == 0);
    fresh_fixture(&mock, &tp, &sb, &gpr, &shmem);

    /* 3. Fault injection at every proven pre-write transition: must roll back cleanly without leaking ION */
    mock.fail_mmap = true;
    assert(m11_shmem_alloc_and_map(&shmem, M11_SHMEM_MODE_DMA_ION_OFFSET, 4096u, false, &reg) == -ENOMEM);
    assert(reg.state == M11_SHMEM_STATE_RELEASED);
    assert(shmem.active_dma_fds == 0u && shmem.unresolved_regions == 0u);
    mock.fail_mmap = false;

    mock.fail_dma_buf_sync_start = true;
    assert(m11_shmem_alloc_and_map(&shmem, M11_SHMEM_MODE_DMA_ION_OFFSET, 4096u, false, &reg) == -EIO);
    assert(reg.state == M11_SHMEM_STATE_RELEASED);
    assert(shmem.active_dma_fds == 0u && shmem.active_mmaps == 0u && shmem.unresolved_regions == 0u);
    mock.fail_dma_buf_sync_start = false;

    mock.fail_ion_import = true;
    assert(m11_shmem_alloc_and_map(&shmem, M11_SHMEM_MODE_DMA_ION_OFFSET, 4096u, false, &reg) == -EFAULT);
    assert(reg.state == M11_SHMEM_STATE_RELEASED);
    assert(shmem.active_dma_fds == 0u && shmem.active_mmaps == 0u && shmem.active_ion_imports == 0u);
    mock.fail_ion_import = false;

    /*
     * Proven pre-write failure AFTER ION import (submit_ex fails with -ENOSPC before
     * invoking write_fn -> M11_GPR_TX_NOT_ATTEMPTED): safe and mandatory to unmap ION
     * and release local handles cleanly.
     */
    for (size_t i = 0; i < M11_GPR_MAX_PENDING; i++) {
        gpr.slots[i].in_use = true;
    }
    assert(m11_shmem_alloc_and_map(&shmem, M11_SHMEM_MODE_DMA_ION_OFFSET, 4096u, false, &reg) == -ENOSPC);
    assert(gpr.last_tx_status == M11_GPR_TX_NOT_ATTEMPTED);
    assert(reg.state == M11_SHMEM_STATE_RELEASED);
    assert(shmem.active_ion_imports == 0u && shmem.active_mmaps == 0u &&
           shmem.active_dma_fds == 0u && shmem.unresolved_regions == 0u);
    for (size_t i = 0; i < M11_GPR_MAX_PENDING; i++) {
        gpr.slots[i].in_use = false;
    }

    /*
     * Explicit DSP NACK (0x02001005 status=1) for a transmitted MAP: no firmware contract proves
     * that a NACK created no mapping, so the backing is held (post-MAP hold), never rolled back.
     */
    mock.nack_shmem_map = true;
    assert(m11_shmem_alloc_and_map(&shmem, M11_SHMEM_MODE_DMA_ION_OFFSET, 4096u, false, &reg) == -EREMOTEIO);
    assert(reg.state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED && reg.cause == M11_SHMEM_CAUSE_MAP_NACK);
    assert(reg.map_tx_started && !reg.map_tx_unsent_proof && reg.blocker != NULL);
    assert(shmem.active_ion_imports == 1u && shmem.active_mmaps == 1u &&
           shmem.active_dma_fds == 1u && shmem.unresolved_regions == 1u);
    assert(m11_shmem_unmap_and_free(&shmem, &reg) == -EBUSY && reg.ion_imported && mock.unmap_cmd_count == 0u);
    mock.nack_shmem_map = false;
    assert(m11_gpr_engine_close(&gpr) == 0);
    fresh_fixture(&mock, &tp, &sb, &gpr, &shmem);

    /*
     * 4. P1 Regression: write_fn() error (-EIO) or short write (24 < 44) on 0x0100100C.
     * Because audio_pkt_write (0x0010170c) / gpr_send_pkt (0x00101484) does NOT guarantee
     * that a negative errno or short write occurred before RPMSG transmission, remote DSP
     * state is UNKNOWN. Ownership MUST transition to M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED
     * and MUST NOT free ION/DMA-BUF!
     */
    mock.fail_gpr_write_on_map = true;
    assert(m11_shmem_alloc_and_map(&shmem, M11_SHMEM_MODE_DMA_ION_OFFSET, 4096u, false, &reg) == -EIO);
    assert(gpr.last_tx_status == M11_GPR_TX_WRITE_ERROR);
    assert(reg.state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED);
    assert(shmem.unresolved_regions == 1u);
    assert(shmem.active_ion_imports == 1u && shmem.active_mmaps == 1u && shmem.active_dma_fds == 1u);
    assert(m11_shmem_unmap_and_free(&shmem, &reg) == -EBUSY);
    mock.fail_gpr_write_on_map = false;

    m11_shmem_region_t reg_short;
    mock.short_gpr_write_on_map = true;
    assert(m11_shmem_alloc_and_map(&shmem, M11_SHMEM_MODE_DMA_ION_OFFSET, 4096u, false, &reg_short) == -EIO);
    assert(gpr.last_tx_status == M11_GPR_TX_SHORT_WRITE);
    assert(reg_short.state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED);
    assert(shmem.unresolved_regions == 2u);
    assert(shmem.active_ion_imports == 2u && shmem.active_mmaps == 2u && shmem.active_dma_fds == 2u);
    assert(m11_shmem_unmap_and_free(&shmem, &reg_short) == -EBUSY);
    mock.short_gpr_write_on_map = false;

    /*
     * 5. Post-TX timeout on 0x0100100C: remote DSP mapping state is UNKNOWN.
     * Ownership MUST transition to OWNERSHIP_UNRESOLVED and retain local handles!
     */
    m11_shmem_region_t reg_timeout;
    mock.drop_shmem_map_rsp = true;
    assert(m11_shmem_alloc_and_map(&shmem, M11_SHMEM_MODE_DMA_ION_OFFSET, 4096u, false, &reg_timeout) == -ETIMEDOUT);
    assert(reg_timeout.state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED);
    assert(shmem.unresolved_regions == 3u);
    assert(shmem.active_ion_imports == 3u && shmem.active_mmaps == 3u && shmem.active_dma_fds == 3u);
    assert(m11_shmem_unmap_and_free(&shmem, &reg_timeout) == -EBUSY);
    assert(reg_timeout.state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED);
    mock.drop_shmem_map_rsp = false;

    /*
     * 6. Unmap failure after DSP map acknowledged: must transition to OWNERSHIP_UNRESOLVED
     * and refuse to free backing memory underneath active DSP mapping!
     */
    m11_shmem_region_t reg2;
    assert(m11_shmem_alloc_and_map(&shmem, M11_SHMEM_MODE_DMA_ION_OFFSET, 4096u, false, &reg2) == 0);
    assert(reg2.state == M11_SHMEM_STATE_DSP_MAP_ACKNOWLEDGED);
    mock.drop_shmem_unmap_rsp = true;
    assert(m11_shmem_unmap_and_free(&shmem, &reg2) == -ETIMEDOUT);
    assert(reg2.state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED);
    assert(reg2.dsp_mapped);
    assert(shmem.active_dsp_maps == 1u);
    assert(shmem.unresolved_regions == 4u);
    mock.drop_shmem_unmap_rsp = false;

    assert(m11_gpr_engine_close(&gpr) == 0);
}

static void test_gate_c_apm_cfg_and_graph_cmds(void) {
    /*
     * Section 5: 9 Required Binary Fixtures for SET_CFG / GET_CFG / RSP_GET_CFG
     */
    uint8_t pkt[128];
    size_t pkt_len = 0u;
    uint32_t ch = 99u, q12 = 0u;

    /* Fixture 1: Valid SET_CFG request (88B packet, dst_port = 0x42D3) */
    assert(m11_aw_pack_set_cfg_pkt(pkt, sizeof(pkt), &pkt_len,
                                   0x2001u, 0x10u, 0u, M11_MARBLE_CH0_FACTORY_MOHM) == 0);
    assert(pkt_len == 88u);
    assert(m11_aw_validate_cfg_req_pkt(pkt, pkt_len, M11_APM_CMD_SET_CFG, &ch, &q12) == 0);
    assert(ch == 0u && q12 == M11_MARBLE_CH0_FACTORY_Q12);

    /* Fixture 2: Valid GET_CFG request (88B packet, dst_port = 0x42D3, q12_re = 0) */
    assert(m11_aw_pack_get_cfg_pkt(pkt, sizeof(pkt), &pkt_len, 0x2001u, 0x11u, 1u) == 0);
    assert(pkt_len == 88u);
    assert(m11_aw_validate_cfg_req_pkt(pkt, pkt_len, M11_APM_CMD_GET_CFG, &ch, &q12) == 0);
    assert(ch == 1u && q12 == 0u);

    /* Fixture 3: Valid GET_CFG response (76B packet, src_port = 0x42D3, status = 0) */
    assert(m11_aw_pack_get_cfg_rsp_pkt(pkt, sizeof(pkt), &pkt_len,
                                       0x2001u, 0x11u, 0u, 1u, M11_MARBLE_CH1_FACTORY_MOHM) == 0);
    assert(pkt_len == 76u);
    assert(m11_aw_validate_get_cfg_rsp_pkt(pkt, pkt_len, 0x2001u, 0x11u,
                                           1u, M11_MARBLE_CH1_FACTORY_Q12) == 0);

    /* Fixture 4: Invalid response length (truncated 60B packet) */
    uint8_t bad_len_pkt[128];
    memcpy(bad_len_pkt, pkt, pkt_len);
    uint32_t trunc_hdr = m11_gpr_make_header_word(0u, 6u, 60u);
    memcpy(bad_len_pkt, &trunc_hdr, 4u);
    assert(m11_aw_validate_get_cfg_rsp_pkt(bad_len_pkt, 60u, 0x2001u, 0x11u,
                                           1u, M11_MARBLE_CH1_FACTORY_Q12) == -EBADMSG);

    /* Fixture 5: Wrong module instance (dst_port = 1 on SET_CFG, or iid = 0x42D4 in RSP) */
    uint8_t bad_iid_pkt[128];
    assert(m11_aw_pack_set_cfg_pkt(bad_iid_pkt, sizeof(bad_iid_pkt), &pkt_len,
                                   0x2001u, 0x10u, 0u, M11_MARBLE_CH0_FACTORY_MOHM) == 0);
    uint32_t wrong_dst = M11_APM_MODULE_IID;
    memcpy(bad_iid_pkt + 0x0c, &wrong_dst, 4u);
    assert(m11_aw_validate_cfg_req_pkt(bad_iid_pkt, pkt_len, M11_APM_CMD_SET_CFG, &ch, &q12) == -EPROTO);

    /* Fixture 6: Wrong parameter ID (0x10013D25 static blob ID instead of 0x10013D2A) */
    uint8_t bad_pid_pkt[128];
    memcpy(bad_pid_pkt, pkt, 76u);
    uint32_t wrong_pid = M11_AW_ACDB_STATIC_PARAM_25;
    memcpy(bad_pid_pkt + 24u + 4u + 4u, &wrong_pid, 4u);
    assert(m11_aw_validate_get_cfg_rsp_pkt(bad_pid_pkt, 76u, 0x2001u, 0x11u,
                                           1u, M11_MARBLE_CH1_FACTORY_Q12) == -EPROTO);

    /* Fixture 7: Wrong token */
    assert(m11_aw_validate_get_cfg_rsp_pkt(pkt, 76u, 0x2001u, 0x9999u,
                                           1u, M11_MARBLE_CH1_FACTORY_Q12) == -ESTALE);

    /* Fixture 8 & 9: Missing acknowledgement (-ETIMEDOUT) and DSP error status (-EREMOTEIO) */
    uint8_t err_status_pkt[128];
    assert(m11_aw_pack_get_cfg_rsp_pkt(err_status_pkt, sizeof(err_status_pkt), &pkt_len,
                                       0x2001u, 0x11u, 1u, 1u, M11_MARBLE_CH1_FACTORY_MOHM) == 0);
    assert(m11_aw_validate_get_cfg_rsp_pkt(err_status_pkt, pkt_len, 0x2001u, 0x11u,
                                           1u, M11_MARBLE_CH1_FACTORY_Q12) == -EREMOTEIO);

    /*
     * Section 6: APM Graph Command Serialization (PREPARE / START / STOP / CLOSE / OPEN)
     */
    const uint32_t vi_sgs[2] = { 0xB00000D5u, 0xB00000CEu };
    const uint32_t rx_sgs[4] = { 0xB0000023u, 0xB0000024u, 0xB0000025u, 0xB0000002u };

    assert(m11_apm_subgraph_list_param_aligned_bytes(2u) == 32u);
    assert(m11_apm_graph_mgmt_inband_payload_bytes(2u) == 48u);
    assert(m11_apm_subgraph_list_param_aligned_bytes(4u) == 40u);
    assert(m11_apm_graph_mgmt_inband_payload_bytes(4u) == 56u);

    uint8_t graph_pkt[128];
    size_t graph_pkt_len = 0u;
    assert(m11_apm_pack_graph_mgmt_cmd(graph_pkt, sizeof(graph_pkt), &graph_pkt_len,
                                       0x2001u, 5u, M11_APM_CMD_GRAPH_PREPARE,
                                       vi_sgs, 2u) == 0);
    assert(graph_pkt_len == 72u); /* 24B GPR header + 48B payload */

    uint32_t parsed_sgs[4] = {0};
    uint32_t parsed_num = 0u;
    assert(m11_apm_validate_graph_mgmt_inband_payload(
               graph_pkt + 24u, graph_pkt_len - 24u, &parsed_num, parsed_sgs, 4u) == 0);
    assert(parsed_num == 2u && parsed_sgs[0] == 0xB00000D5u && parsed_sgs[1] == 0xB00000CEu);

    assert(m11_apm_pack_graph_mgmt_cmd(graph_pkt, sizeof(graph_pkt), &graph_pkt_len,
                                       0x2001u, 6u, M11_APM_CMD_GRAPH_START,
                                       rx_sgs, 4u) == 0);
    assert(graph_pkt_len == 80u); /* 24B GPR header + 56B payload */

    /* Prove old raw 8B and 16B subgraph arrays are rejected */
    assert(m11_apm_validate_graph_mgmt_inband_payload(
               (const uint8_t *)vi_sgs, sizeof(vi_sgs), &parsed_num, parsed_sgs, 4u) == -EBADMSG);
    assert(m11_apm_validate_graph_mgmt_inband_payload(
               (const uint8_t *)rx_sgs, sizeof(rx_sgs), &parsed_num, parsed_sgs, 4u) == -EBADMSG);

    /*
     * P2b Regression: Out-of-band GRAPH_OPEN CPU/DMA cache coherency contract
     * (DMA_BUF_IOCTL_SYNC 0x40086200: START_RW 0x3 -> CPU write -> END_RW 0x7).
     */
    {
        m11_strict_mock_t mock;
        m11_gpr_transport_t tp;
        m11_shmem_backend_t sb;
        m11_gpr_engine_t gpr;
        m11_shmem_mgr_t shmem;
        m11_shmem_region_t reg;
        uint32_t dsp_status = 0u;

        m11_strict_mock_init(&mock);
        m11_strict_mock_bind(&mock, &tp, &sb);
        assert(m11_gpr_engine_init(&gpr, &tp, 0x2001u) == 0);
        assert(m11_gpr_engine_open(&gpr) == 0);
        assert(m11_shmem_mgr_init(&shmem, &sb, &gpr, 50u) == 0);
        assert(m11_shmem_alloc_and_map(&shmem, M11_SHMEM_MODE_DMA_ION_OFFSET, 16416u, false, &reg) == 0);

        /*
         * 1. Raw m11_apm_transact_graph_open_oob() without DMA_BUF_SYNC_END_RW (0x7)
         *    leaves CPU cache dirty (slot->cpu_access_active == true, cache_clean_for_dsp == false)
         *    and MUST be rejected by strict ADSP mock!
         */
        assert(m11_apm_transact_graph_open_oob(&gpr, reg.vaddr, reg.aligned_bytes,
                                               0u, reg.mem_map_handle,
                                               vi_sgs, 2u, 50u, &dsp_status) == -EREMOTEIO);
        assert(mock.rejected_cache_sync_count == 1u);
        assert(mock.last_reject_reason == -EAGAIN);

        /*
         * 2. Failing DMA_BUF_SYNC_END_RW (0x7) inside m11_apm_transact_graph_open_region()
         *    MUST abort pre-TX (-EIO) before transmitting GRAPH_OPEN.
         */
        mock.fail_dma_buf_sync_end = true;
        assert(m11_apm_transact_graph_open_region(&gpr, &shmem, &reg, 0u,
                                                  vi_sgs, 2u, 50u, &dsp_status) == -EIO);
        assert(gpr.last_tx_status == M11_GPR_TX_NOT_ATTEMPTED);
        assert(!reg.cpu_cache_clean_for_dsp);
        mock.fail_dma_buf_sync_end = false;

        /*
         * 3. Synchronized m11_apm_transact_graph_open_region() flushes CPU caches
         *    via DMA_BUF_SYNC_END_RW (0x7) and succeeds for both VI TX (offset 0)
         *    and Speaker RX (offset 64).
         */
        assert(m11_apm_transact_graph_open_region(&gpr, &shmem, &reg, 0u,
                                                  vi_sgs, 2u, 50u, &dsp_status) == 0);
        assert(!reg.cpu_access_active && reg.cpu_cache_clean_for_dsp);
        assert(reg.sync_start_count == 1u && reg.sync_end_count == 1u);

        assert(m11_apm_transact_graph_open_region(&gpr, &shmem, &reg, 64u,
                                                  rx_sgs, 4u, 50u, &dsp_status) == 0);
        assert(!reg.cpu_access_active && reg.cpu_cache_clean_for_dsp);
        assert(reg.sync_start_count == 2u && reg.sync_end_count == 2u);

        /* post-MAP hold: the UNMAP research path's ACK releases nothing */
        assert(m11_shmem_unmap_and_free(&shmem, &reg) == -EPERM);
        assert(reg.state == M11_SHMEM_STATE_DSP_UNMAP_ACKNOWLEDGED && reg.ion_imported && reg.vaddr);
        assert(m11_gpr_engine_close(&gpr) == 0);
    }
}

static void test_gate_d_speaker_protection(void) {
    assert(m11_aw_mohm_to_q12(M11_MARBLE_CH0_FACTORY_MOHM) == M11_MARBLE_CH0_FACTORY_Q12);
    assert(m11_aw_mohm_to_q12(M11_MARBLE_CH1_FACTORY_MOHM) == M11_MARBLE_CH1_FACTORY_Q12);

    /* Distinguish static ACDB parameter IDs from runtime SET_CFG parameter ID 0x10013D2A */
    assert(M11_PARAM_ID_SP_TH_VI_R0_T0 == 0x10013D2Au);
    assert(M11_AW_ACDB_STATIC_PARAM_25 == 0x10013D25u);
    assert(M11_PARAM_ID_SP_TH_VI_R0_T0 != M11_AW_ACDB_STATIC_PARAM_25);

    m11_aw_safety_context_t ctx = {
        .aw_dev_0_switch = 0,
        .aw_dev_1_switch = 0,
        .amp_enable_requested = false,
        .vi_tx_subgraph_opened = true,
        .vi_tx_subgraph_prepared = true,
        .vi_tx_module_iid = M11_AW_VI_TX_MODULE_IID,
        .sp_rx_module_iid = M11_AW_SP_RX_MODULE_IID,
    };
    assert(m11_aw_validate_safety_context(&ctx) == 0);

    ctx.amp_enable_requested = true;
    assert(m11_aw_validate_safety_context(&ctx) == -EACCES);
    ctx.amp_enable_requested = false;

    ctx.vi_tx_subgraph_prepared = false;
    assert(m11_aw_validate_safety_context(&ctx) == -EDESTADDRREQ);
}

static int run_single_sim_with_mock(m11_strict_mock_t *mock,
                                    const m11_sim_config_t *cfg,
                                    m11_sim_report_t *out_report) {
    m11_gpr_transport_t tp;
    m11_shmem_backend_t sb;
    m11_gpr_engine_t gpr;
    m11_shmem_mgr_t shmem;

    m11_strict_mock_bind(mock, &tp, &sb);
    int rc = m11_gpr_engine_init(&gpr, &tp, 0x2001u);
    assert(rc == 0);
    rc = m11_shmem_mgr_init(&shmem, &sb, &gpr, 50u);
    assert(rc == 0);

    return m11_sim_run_speaker_qualification(cfg, &gpr, &shmem, 50u, out_report);
}

static void test_gate_e_simulator_and_mutations(void) {
    m11_sim_config_t cfg;
    m11_sim_default_marble_config(&cfg);

    /* 0. Baseline positive simulation with strict kernel+ADSP mock */
    m11_strict_mock_t mock;
    m11_sim_report_t rep;
    m11_strict_mock_init(&mock);
    int rc = run_single_sim_with_mock(&mock, &cfg, &rep);
    assert(rc == 0);
    assert(rep.spf_ready && rep.shmem_mapped && rep.vi_tx_opened && rep.vi_tx_prepared &&
           rep.rx_opened && rep.rx_prepared && rep.cal_applied_and_verified && rep.graphs_started);
    /* Post-MAP hold: graphs stopped and closed, no UNMAP, the region and the endpoint held. */
    assert(rep.post_map_hold && rep.retaining_teardown && !rep.clean_teardown);
    assert(rep.primary_errno == 0 && rep.cleanup_errno == 0);
    assert(rep.final_shmem_state == M11_SHMEM_STATE_DSP_MAP_ACKNOWLEDGED);
    assert(rep.retained_region_valid && rep.endpoint_close_deferred && rep.gpr_close_count == 0u);
    assert(rep.unresolved_ownership == 0u && rep.leaked_resources == 5u); /* fd, mmap, import, DSP map, endpoint */
    assert(mock.map_cmd_count == 1u && mock.unmap_cmd_count == 0u && mock.unsafe_release_attempts == 0u);
    assert(rep.simulation_boundary != NULL && strlen(rep.simulation_boundary) > 20u);

    /*
     * Section 9 — Required Mutation Tests (10 Baseline + 3 P1/P2 Hardening Mutations)
     */

    /* Mutation 1: Swap GPR domain and port fields */
    m11_strict_mock_init(&mock);
    mock.mutate_swap_gpr_domain_and_port = true;
    rc = run_single_sim_with_mock(&mock, &cfg, &rep);
    assert(rc == -EINVAL);
    assert(mock.rejected_hdr_count > 0u);

    /* Mutation 2: Change mem_pool_id from 3 to 4 */
    m11_strict_mock_init(&mock);
    mock.mutate_mem_pool_id_to_4 = true;
    rc = run_single_sim_with_mock(&mock, &cfg, &rep);
    assert(rc == -EREMOTEIO);
    assert(mock.rejected_shmem_count > 0u);
    assert(!rep.shmem_mapped);

    /*
     * Mutation 3: Replace DMA-BUF fd with a fake physical address (0x80001000).
     * write_fn() returns -EFAULT; per P1 ownership safety rules, any write_fn()
     * error on 0x0100100C quarantines ownership as OWNERSHIP_UNRESOLVED.
     */
    m11_strict_mock_init(&mock);
    mock.mutate_fake_phys_addr_in_map = true;
    rc = run_single_sim_with_mock(&mock, &cfg, &rep);
    assert(rc == -EFAULT);
    assert(mock.rejected_shmem_count > 0u);
    assert(rep.final_shmem_state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED);
    assert(rep.unresolved_ownership == 1u);
    assert(!rep.clean_teardown);

    /* Mutation 4: Clear client_data on OFFSET_MODE map */
    m11_strict_mock_init(&mock);
    mock.mutate_clear_client_data_on_map = true;
    rc = run_single_sim_with_mock(&mock, &cfg, &rep);
    assert(rc == -EREMOTEIO);
    assert(mock.rejected_shmem_count > 0u);
    assert(!rep.shmem_mapped);

    /*
     * Mutation 5: Send SET_CFG to port 1 instead of 0x42D3.
     * Case 5a (wire mutation): caller expects reply from 0x42D3, wire packet goes to port 1;
     *   ADSP port 1 rejects SET_CFG and replies from src_port=1, which GPR engine drops as
     *   a peer-port mismatch (-EPROTO -> -ETIMEDOUT).
     * Case 5b (caller addresses port 1 directly, as old Argon did): ADSP port 1 replies with
     *   IBASIC_RSP NACK (status=1) -> -EREMOTEIO.
     */
    m11_strict_mock_init(&mock);
    mock.mutate_set_cfg_dst_port_to_1 = true;
    rc = run_single_sim_with_mock(&mock, &cfg, &rep);
    assert(rc == -ETIMEDOUT);
    assert(mock.rejected_cfg_count > 0u);
    assert(mock.last_reject_reason == -EPROTO);
    assert(!rep.cal_applied_and_verified);

    {
        m11_gpr_transport_t tp;
        m11_gpr_engine_t gpr;
        m11_strict_mock_init(&mock);
        m11_strict_mock_bind(&mock, &tp, NULL);
        assert(m11_gpr_engine_init(&gpr, &tp, 0x2001u) == 0);
        assert(m11_gpr_engine_open(&gpr) == 0);
        m11_apm_aw_re_cfg_pkt_t set_pkt;
        memset(&set_pkt, 0, sizeof(set_pkt));
        set_pkt.cmd_hdr.payload_size = sizeof(m11_aw_re_envelope_48_t);
        assert(m11_aw_build_re_envelope_48(0u, M11_MARBLE_CH0_FACTORY_MOHM, &set_pkt.env) == 0);
        uint32_t dsp_status = 0u;
        int drc = m11_gpr_engine_transact(&gpr, M11_APM_MODULE_IID, M11_APM_CMD_SET_CFG,
                                          &set_pkt, sizeof(set_pkt), 50u,
                                          &dsp_status, NULL, 0, NULL);
        assert(drc == -EREMOTEIO);
        assert(dsp_status == 1u);
        assert(mock.rejected_cfg_count == 1u);
        assert(m11_gpr_engine_close(&gpr) == 0);
    }

    /* Mutation 6: Send raw subgraph arrays without apm_cmd_header_t / 0x08001005 */
    m11_strict_mock_init(&mock);
    mock.mutate_raw_subgraph_array_on_graph_cmd = true;
    rc = run_single_sim_with_mock(&mock, &cfg, &rep);
    assert(rc == -EREMOTEIO);
    assert(mock.rejected_graph_count > 0u);
    assert(!rep.vi_tx_prepared);

    /* Mutation 7: Truncate GET_CFG response */
    m11_strict_mock_init(&mock);
    mock.truncate_get_cfg_rsp = true;
    rc = run_single_sim_with_mock(&mock, &cfg, &rep);
    assert(rc == -EBADMSG);
    assert(!rep.cal_applied_and_verified);

    /* Mutation 8: Drop GRAPH_CLOSE acknowledgement */
    m11_strict_mock_init(&mock);
    mock.drop_graph_close_rsp = true;
    rc = run_single_sim_with_mock(&mock, &cfg, &rep);
    assert(rc == -ETIMEDOUT);
    assert(rep.cleanup_errno == -ETIMEDOUT);
    assert(!rep.clean_teardown);

    /* Mutation 9: Fail SHARED_MEM_MAP_REGIONS after ION import (post-TX timeout -> unresolved) */
    m11_strict_mock_init(&mock);
    mock.drop_shmem_map_rsp = true;
    rc = run_single_sim_with_mock(&mock, &cfg, &rep);
    assert(rc == -ETIMEDOUT);
    assert(rep.final_shmem_state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED);
    assert(rep.unresolved_ownership == 1u);
    assert(!rep.clean_teardown);

    /* Mutation 10: Cleanup succeeds after primary failure -> primary failure MUST be preserved */
    m11_strict_mock_init(&mock);
    mock.nack_set_cfg = true;
    rc = run_single_sim_with_mock(&mock, &cfg, &rep);
    assert(rc == -EREMOTEIO);
    assert(rep.primary_errno == -EREMOTEIO);
    assert(rep.cleanup_errno == 0);
    assert(!rep.cal_applied_and_verified);
    assert(!rep.graphs_started);
    assert(rep.retaining_teardown && !rep.clean_teardown && mock.unmap_cmd_count == 0u);

    /* Mutation 11 (P1): Short write on SHARED_MEM_MAP_REGIONS -> OWNERSHIP_UNRESOLVED */
    m11_strict_mock_init(&mock);
    mock.short_gpr_write_on_map = true;
    rc = run_single_sim_with_mock(&mock, &cfg, &rep);
    assert(rc == -EIO);
    assert(rep.final_shmem_state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED);
    assert(rep.unresolved_ownership == 1u);
    assert(!rep.clean_teardown);

    /* Mutation 12 (P2a): poll_read_fn returns -ENODEV -> immediate exit without masking as -ETIMEDOUT */
    m11_strict_mock_init(&mock);
    mock.poll_read_errno = -ENODEV;
    rc = run_single_sim_with_mock(&mock, &cfg, &rep);
    assert(rc == -ENODEV);
    assert(rep.primary_errno == -ENODEV);
    assert(mock.poll_read_call_count == 1u);

    /* Mutation 13 (P2b): Skip DMA_BUF_SYNC_END_RW (0x7) before GRAPH_OPEN -> rejected by the MOCK (a mock rule, not stock evidence; see m11_shmem.h) */
    m11_strict_mock_init(&mock);
    mock.skip_dma_buf_sync_end = true;
    rc = run_single_sim_with_mock(&mock, &cfg, &rep);
    assert(rc == -EREMOTEIO);
    assert(mock.rejected_cache_sync_count == 1u);
    assert(mock.last_reject_reason == -EAGAIN);
    assert(!rep.vi_tx_opened);
    assert(rep.retaining_teardown && !rep.clean_teardown && mock.unmap_cmd_count == 0u);

    /* Additional check: PDR during prepare leaves remote state unverified -> clean_teardown == false */
    m11_strict_mock_init(&mock);
    mock.pdr_on_graph_prepare = true;
    rc = run_single_sim_with_mock(&mock, &cfg, &rep);
    assert(rc == -ENETRESET);
    assert(rep.primary_errno == -ENETRESET);
    assert(!rep.clean_teardown && !rep.retaining_teardown);
    assert(rep.final_shmem_state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED);
    assert(mock.unmap_cmd_count == 0u);
    /* Post-MAP hold: PD down while held is recorded as unknown without entering the UNMAP call */
    assert(rep.post_map_hold && !rep.unmap_attempted && rep.shmem_cause == M11_SHMEM_CAUSE_MAP_PDR);
    assert(rep.cleanup_errno == -ENETRESET && rep.retained_region_valid && rep.endpoint_close_deferred);
}

int main(void) {
    test_gate_a_gpr_wire_abi();
    test_gate_b_dma_ion_offset_mode();
    test_gate_c_apm_cfg_and_graph_cmds();
    test_gate_d_speaker_protection();
    test_gate_e_simulator_and_mutations();
    printf("PASS m11_runtime_repair C verification and 13-mutation suite (%s)\n",
           M11_SIM_BOUNDARY_DESCRIPTION);
    return 0;
}
