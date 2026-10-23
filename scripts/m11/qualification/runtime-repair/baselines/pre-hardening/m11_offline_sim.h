#ifndef M11_RUNTIME_REPAIR_OFFLINE_SIM_H
#define M11_RUNTIME_REPAIR_OFFLINE_SIM_H

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

#define M11_SIM_BOUNDARY_DESCRIPTION \
    "Application -> real C11 GPR/APM/OFFSET_MODE serializer & 9-state ownership engine -> " \
    "strict mock kernel (gpr_dlkm + audpkt_ion_dlkm + audio_pkt_dlkm) & modeled ADSP endpoint " \
    "(no physical hardware/ADSP/amplifier)"

typedef struct {
    bool     acdb_resolved;
    uint32_t rx_subgraphs[4];     /* 0xb0000023, 0xb0000024, 0xb0000025, 0xb0000002 */
    uint32_t vi_tx_subgraphs[2];  /* 0xb00000d5, 0xb00000ce */
    uint32_t hw_ep_rx_iid;        /* 0x428f */
    uint32_t sp_rx_iid;           /* 0x42d3 */
    uint32_t vi_tx_iid;           /* 0x42d4 */
    uint32_t sample_rate_hz;      /* 96000 */
    uint32_t bit_width;           /* 32 */
    uint32_t num_channels;        /* 3 */
    uint32_t lpaif_type;          /* 2 (LPAIF_TERTIARY) */
    bool     enable_vi_tx_graph;  /* Must be true for speaker protection */
    int      aw_dev_0_switch;     /* Software pre-check: must be 0 (Disable) */
    int      aw_dev_1_switch;     /* Software pre-check: must be 0 (Disable) */
    bool     amp_enable_requested;/* Must be false */
    uint8_t  calr_bytes[8];       /* 8-byte LE32 mOhm pair */
    size_t   calr_len;
} m11_sim_config_t;

typedef struct {
    bool              spf_ready;
    bool              shmem_mapped;
    bool              vi_tx_opened;
    bool              vi_tx_prepared;
    bool              vi_tx_started;
    bool              rx_opened;
    bool              rx_prepared;
    bool              rx_started;
    bool              cal_applied_and_verified;
    bool              graphs_started;
    bool              clean_teardown;
    int               primary_errno;
    int               cleanup_errno;
    m11_shmem_state_t final_shmem_state;
    uint32_t          gpr_open_count;
    uint32_t          gpr_close_count;
    uint32_t          unresolved_ownership;
    uint32_t          leaked_resources;
    const char       *simulation_boundary;
} m11_sim_report_t;

void m11_sim_default_marble_config(m11_sim_config_t *cfg);

int m11_sim_run_speaker_qualification(const m11_sim_config_t *cfg,
                                      m11_gpr_engine_t *gpr,
                                      m11_shmem_mgr_t *shmem,
                                      uint32_t timeout_ms,
                                      m11_sim_report_t *out_report);

#ifdef __cplusplus
}
#endif

#endif /* M11_RUNTIME_REPAIR_OFFLINE_SIM_H */
