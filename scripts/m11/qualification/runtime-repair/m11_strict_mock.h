#ifndef M11_RUNTIME_REPAIR_STRICT_MOCK_H
#define M11_RUNTIME_REPAIR_STRICT_MOCK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "m11_apm_protocol.h"
#include "m11_aw_protection.h"
#include "m11_gpr_engine.h"
#include "m11_shmem.h"

#ifdef __cplusplus
extern "C" {
#endif

#define M11_MOCK_MAX_QUEUE       32u
#define M11_MOCK_MAX_HELD        4u
#define M11_MOCK_MAX_SHM_SLOTS   4u
#define M11_MOCK_SHM_SLOT_BYTES  20480u
#define M11_MOCK_DMA_FD_BASE     100

typedef struct {
    bool     allocated;
    bool     mmap_active;
    bool     ion_imported;
    bool     hyp_assigned;
    bool     cpu_access_active;
    bool     cache_clean_for_dsp;
    uint32_t sync_start_count;
    uint32_t sync_end_count;
    int      dma_fd;
    size_t   aligned_bytes;
    uint64_t kernel_iova;
    uint32_t dsp_map_handle;
    uint8_t  mem[M11_MOCK_SHM_SLOT_BYTES];
} m11_mock_shm_slot_t;

typedef struct {
    /* Transport & kernel/ADSP state */
    bool     gpr_fd_open;
    uint32_t spf_state; /* 1 = ready, 0 = not ready */
    uint32_t stored_q12_re[2];
    bool     vi_tx_opened;
    bool     vi_tx_prepared;
    bool     vi_tx_started;
    bool     rx_opened;
    bool     rx_prepared;
    bool     rx_started;

    /* Queued RX packets from ADSP to APPS */
    uint8_t  rx_queue[M11_MOCK_MAX_QUEUE][M11_GPR_MAX_PKT_BYTES];
    size_t   rx_lens[M11_MOCK_MAX_QUEUE];
    size_t   rx_head;
    size_t   rx_tail;

    /*
     * Held (delayed) responses. With hold_next_rsp set, the NEXT response the modeled ADSP
     * generates is parked here instead of being queued, while the ADSP-side state change has
     * already happened. m11_strict_mock_release_held() queues them later: that is how a
     * late ACK (after the host timed out) is modeled. MOCK ONLY: it is not stock evidence
     * about how or when the real ADSP answers.
     */
    uint8_t  held_pkt[M11_MOCK_MAX_HELD][M11_GPR_MAX_PKT_BYTES];
    size_t   held_len[M11_MOCK_MAX_HELD];
    size_t   held_count;

    /* Last TX packet captured for inspection */
    uint8_t  last_tx_pkt[M11_GPR_MAX_PKT_BYTES];
    size_t   last_tx_len;
    uint32_t tx_pkt_count;
    uint32_t poll_read_call_count;

    /* Kernel DMA-BUF / msm_audio_ion table */
    m11_mock_shm_slot_t shm_slots[M11_MOCK_MAX_SHM_SLOTS];

    /* Rejection / diagnostic counters */
    uint32_t rejected_hdr_count;
    uint32_t rejected_shmem_count;
    uint32_t rejected_graph_count;
    uint32_t rejected_cfg_count;
    uint32_t rejected_cache_sync_count;
    int      last_reject_reason;

    /* Command accounting seen by the modeled ADSP (after kernel admission) */
    uint32_t map_cmd_count;
    uint32_t unmap_cmd_count;
    uint32_t graph_open_cmd_count;
    /*
     * Safety oracle: incremented whenever the host asks to release a local handle (ion unmap,
     * munmap, close) of a slot the modeled ADSP still maps. Must stay 0: it is independent of
     * the return codes the mock gives for such a request.
     */
    uint32_t unsafe_release_attempts;

    /* Fault & mutation injection controls */
    bool     fail_dma_alloc;
    bool     fail_mmap;
    bool     fail_dma_buf_sync_start;
    bool     fail_dma_buf_sync_end;
    bool     skip_dma_buf_sync_end;
    bool     fail_ion_import;
    bool     fail_ion_unmap;
    bool     fail_munmap;
    bool     fail_close_fd;
    bool     fail_gpr_write_on_map;
    bool     short_gpr_write_on_map;
    int      poll_read_errno;
    bool     drop_shmem_map_rsp;
    bool     nack_shmem_map;
    bool     zero_handle_shmem_map_rsp;
    bool     drop_shmem_unmap_rsp;
    bool     nack_shmem_unmap;
    bool     drop_graph_open_rsp;
    bool     nack_graph_open;
    bool     pdr_on_graph_prepare;
    bool     drop_graph_start_rsp;
    bool     drop_graph_stop_rsp;
    bool     drop_graph_close_rsp;
    bool     nack_graph_close;
    bool     nack_set_cfg;
    bool     drop_set_cfg_rsp;
    bool     corrupt_get_cfg_q12;
    bool     truncate_get_cfg_rsp;
    bool     wrong_peer_on_rsp;
    bool     wrong_token_on_rsp;
    bool     wrong_opcode_on_rsp;

    /* Late / duplicate / unsafe-write modeling (hardening suite) */
    bool     hold_next_rsp;                  /* park the next ADSP response (see held_pkt) */
    bool     duplicate_next_rsp;             /* queue the next ADSP response twice */
    bool     deliver_then_fail_write_on_map; /* ADSP gets MAP, write_fn still returns -EIO */
    bool     deliver_then_fail_write_on_unmap;
    bool     fail_gpr_write_on_unmap;        /* write_fn -EIO, ADSP never sees UNMAP */
    bool     short_gpr_write_on_unmap;
    bool     fail_gpr_write_on_graph_open;   /* write_fn -EIO on GRAPH_OPEN */

    /*
     * Errno returned by an injected dma-buf sync failure (0 = the historical -EIO). A distinctive
     * value lets a test prove that the caller surfaces the PRIMARY error instead of a generic one.
     */
    int      sync_start_errno;
    int      sync_end_errno;

    /* Per-channel Awinic faults: bit0 = ch0, bit1 = ch1 */
    uint32_t nack_set_cfg_ch_mask;           /* ADSP refuses SET_CFG for those channels */
    uint32_t ack_lost_set_cfg_ch_mask;       /* ADSP APPLIES SET_CFG but no ACK is sent */
    uint32_t corrupt_get_cfg_ch_mask;        /* GET_CFG reports a wrong q12 for those channels */
    uint32_t drop_get_cfg_rsp_ch_mask;       /* GET_CFG gets no response for those channels */

    /* Mutation hooks on outgoing TX packets before strict kernel/DSP validation */
    bool     mutate_swap_gpr_domain_and_port;
    bool     mutate_mem_pool_id_to_4;
    bool     mutate_fake_phys_addr_in_map;
    bool     mutate_clear_client_data_on_map;
    bool     mutate_set_cfg_dst_port_to_1;
    bool     mutate_raw_subgraph_array_on_graph_cmd;
} m11_strict_mock_t;

void m11_strict_mock_init(m11_strict_mock_t *m);

void m11_strict_mock_bind(m11_strict_mock_t *m,
                          m11_gpr_transport_t *out_transport,
                          m11_shmem_backend_t *out_shmem_backend);

int m11_strict_mock_enqueue_raw_rx(m11_strict_mock_t *m, const uint8_t *pkt, size_t len);

/* Moves every held response into the RX queue (oldest first). Returns the number moved. */
size_t m11_strict_mock_release_held(m11_strict_mock_t *m);

#ifdef __cplusplus
}
#endif

#endif /* M11_RUNTIME_REPAIR_STRICT_MOCK_H */
