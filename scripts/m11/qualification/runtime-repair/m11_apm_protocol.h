#ifndef M11_RUNTIME_REPAIR_APM_PROTOCOL_H
#define M11_RUNTIME_REPAIR_APM_PROTOCOL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "m11_gpr_engine.h"
#include "m11_shmem.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * APM Subgraph & Container Parameter IDs (apm_sub_graph_api.h / apm_container_api.h / apm_module_api.h)
 * Verified against libar-gsl.so:
 *   - gsl_graph_prepare.cfi @ 0x0011cb48
 *   - gsl_graph_start.cfi @ 0x0011d554
 *   - gsl_graph_stop_single_gkv @ 0x0011dcdc
 *   - gsl_graph_close_sgids_and_connections @ 0x00121d30
 *   - gsl_graph_open_sgids_and_connections @ 0x00120f0c
 */
#define M11_APM_PARAM_ID_CONTAINER_CONFIG 0x08001000u
#define M11_APM_PARAM_ID_SUB_GRAPH_CONFIG 0x08001001u
#define M11_APM_PARAM_ID_MODULES_LIST     0x08001002u
#define M11_APM_PARAM_ID_MODULE_PROP      0x08001003u
#define M11_APM_PARAM_ID_MODULE_CONN      0x08001004u
#define M11_APM_PARAM_ID_SUB_GRAPH_LIST   0x08001005u

#define M11_APM_MAX_SUBGRAPHS_PER_CMD     16u

/* 16-byte APM command header (apm_api.h: struct apm_cmd_header_t) */
typedef struct __attribute__((packed)) {
    uint32_t payload_address_lsw; /* +0x00: 0 for in-band; offset/IOVA LSW for OOB */
    uint32_t payload_address_msw; /* +0x04: 0 for in-band; offset/IOVA MSW for OOB */
    uint32_t mem_map_handle;      /* +0x08: 0 for in-band; non-zero handle for OOB */
    uint32_t payload_size;        /* +0x0c: size in bytes of parameter payload */
} m11_apm_cmd_header_t;

/* 16-byte APM module parameter data header (apm_api.h: struct apm_module_param_data_t) */
typedef struct __attribute__((packed)) {
    uint32_t module_instance_id;  /* +0x00: 1 (M11_APM_MODULE_IID) or target module IID */
    uint32_t param_id;            /* +0x04: e.g. 0x08001005 (M11_APM_PARAM_ID_SUB_GRAPH_LIST) */
    uint32_t param_size;          /* +0x08: unpadded parameter payload bytes */
    uint32_t error_code;          /* +0x0c: 0 on request */
} m11_apm_module_param_data_t;

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(m11_apm_cmd_header_t) == 16u, "m11_apm_cmd_header_t must be 16 bytes");
_Static_assert(sizeof(m11_apm_module_param_data_t) == 16u, "m11_apm_module_param_data_t must be 16 bytes");
#endif

/*
 * Computes the exact 8-byte-aligned parameter block size for APM_PARAM_ID_SUB_GRAPH_LIST
 * (including 16B m11_apm_module_param_data_t + 4B num_sub_graphs + 4B * num_sub_graphs):
 *   ((num_sub_graphs * 4 + 0x1b) & ~7u)
 *   - For 2 subgraphs (VI TX): 32 bytes
 *   - For 4 subgraphs (Speaker RX): 40 bytes
 */
size_t m11_apm_subgraph_list_param_aligned_bytes(uint32_t num_sub_graphs);

/*
 * Computes the exact in-band GPR payload size for GRAPH_PREPARE / START / STOP / CLOSE:
 *   ((num_sub_graphs * 4 + 0x2b) & ~7u) = 16B apm_cmd_header_t + aligned param block
 *   - For 2 subgraphs (VI TX): 48 bytes (72-byte GPR packet)
 *   - For 4 subgraphs (Speaker RX): 56 bytes (80-byte GPR packet)
 */
size_t m11_apm_graph_mgmt_inband_payload_bytes(uint32_t num_sub_graphs);

/*
 * Writes an 8-byte-aligned APM_PARAM_ID_SUB_GRAPH_LIST (0x08001005) block into out_buf.
 * Used both for out-of-band shared-memory payloads (GRAPH_OPEN / OOB GRAPH_CLOSE)
 * and as the body following apm_cmd_header_t in in-band graph management commands.
 */
int m11_apm_write_subgraph_list_block(uint8_t *out_buf, size_t out_cap, size_t *out_len,
                                      const uint32_t *sub_graph_ids, uint32_t num_sub_graphs);

/*
 * Validates an 8-byte-aligned APM_PARAM_ID_SUB_GRAPH_LIST (0x08001005) block.
 */
int m11_apm_validate_subgraph_list_block(const uint8_t *buf, size_t len,
                                         uint32_t *out_num_sub_graphs,
                                         uint32_t *out_sub_graph_ids,
                                         size_t max_sub_graphs);

/*
 * Builds an in-band GPR payload (16B apm_cmd_header_t + 0x08001005 block) for
 * GRAPH_PREPARE (0x01001001), GRAPH_START (0x01001002), GRAPH_STOP (0x01001003),
 * or GRAPH_CLOSE (0x01001004).
 */
int m11_apm_build_graph_mgmt_inband_payload(uint8_t *out_buf, size_t out_cap, size_t *out_len,
                                            const uint32_t *sub_graph_ids, uint32_t num_sub_graphs);

/*
 * Packs a complete in-band GPR packet (24B GPR header + in-band payload) for
 * GRAPH_PREPARE, GRAPH_START, GRAPH_STOP, or GRAPH_CLOSE.
 */
int m11_apm_pack_graph_mgmt_cmd(uint8_t *out_buf, size_t out_cap, size_t *out_len,
                                uint32_t src_port, uint32_t token, uint32_t opcode,
                                const uint32_t *sub_graph_ids, uint32_t num_sub_graphs);

/*
 * Validates an in-band GPR payload for GRAPH_PREPARE / START / STOP / CLOSE.
 */
int m11_apm_validate_graph_mgmt_inband_payload(const uint8_t *payload, size_t payload_len,
                                               uint32_t *out_num_sub_graphs,
                                               uint32_t *out_sub_graph_ids,
                                               size_t max_sub_graphs);

/*
 * Writes a GRAPH_OPEN (0x01001000) subgraph-list definition into a mapped shared-memory
 * buffer at offset `shm_offset_bytes` and builds the 16-byte out-of-band apm_cmd_header_t
 * (40-byte total GPR packet, matching libar-gsl.so gsl_graph_open_sgids_and_connections).
 */
int m11_apm_build_graph_open_oob(uint8_t *shm_vaddr, size_t shm_capacity,
                                 uint32_t shm_offset_bytes, uint32_t mem_map_handle,
                                 const uint32_t *sub_graph_ids, uint32_t num_sub_graphs,
                                 m11_apm_cmd_header_t *out_cmd_hdr,
                                 size_t *out_shm_written);

/*
 * Transacts an out-of-band APM_CMD_GRAPH_OPEN (0x01001000) using a raw shared-memory
 * pointer without executing DMA_BUF_IOCTL_SYNC. Prefer m11_apm_transact_graph_open_region()
 * so CPU cache lines are explicitly synchronized before ADSP DMA read.
 */
int m11_apm_transact_graph_open_oob(m11_gpr_engine_t *gpr,
                                    void *shm_vaddr, size_t shm_capacity,
                                    uint32_t shm_offset_bytes, uint32_t mem_map_handle,
                                    const uint32_t *sub_graph_ids, uint32_t num_sub_graphs,
                                    uint32_t timeout_ms, uint32_t *out_dsp_status);

/*
 * Transacts an out-of-band APM_CMD_GRAPH_OPEN (0x01001000) using a mapped
 * m11_shmem_region_t with explicit CPU/DMA cache synchronization
 * (DMA_BUF_IOCTL_SYNC 0x40086200: START_RW 0x3 -> CPU write -> END_RW 0x7 -> GPR TX).
 */
int m11_apm_transact_graph_open_region(m11_gpr_engine_t *gpr,
                                       m11_shmem_mgr_t *shmem_mgr,
                                       m11_shmem_region_t *region,
                                       uint32_t shm_offset_bytes,
                                       const uint32_t *sub_graph_ids, uint32_t num_sub_graphs,
                                       uint32_t timeout_ms, uint32_t *out_dsp_status);

/*
 * Transacts an in-band APM_CMD_GRAPH_PREPARE / START / STOP / CLOSE using the
 * stock-compatible apm_cmd_header_t + APM_PARAM_ID_SUB_GRAPH_LIST (0x08001005) framing.
 */
int m11_apm_transact_graph_mgmt(m11_gpr_engine_t *gpr, uint32_t opcode,
                                const uint32_t *sub_graph_ids, uint32_t num_sub_graphs,
                                uint32_t timeout_ms, uint32_t *out_dsp_status);

#ifdef __cplusplus
}
#endif

#endif /* M11_RUNTIME_REPAIR_APM_PROTOCOL_H */
