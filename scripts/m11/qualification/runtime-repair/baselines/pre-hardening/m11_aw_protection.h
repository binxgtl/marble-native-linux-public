#ifndef M11_RUNTIME_REPAIR_AW_PROTECTION_H
#define M11_RUNTIME_REPAIR_AW_PROTECTION_H

#ifdef M11_ALLOW_AMP_ENABLE
#error "M11_ALLOW_AMP_ENABLE is strictly forbidden: amplifier enable is blocked in offline/pre-qualification code"
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "m11_apm_protocol.h"
#include "m11_gpr_engine.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Stock marble Awinic Speaker Protection module & parameter IDs.
 * Independently verified against:
 *   - Forte_acdb_cal.acdb (SHA-256 dbc60be1796963bea9c6ef29ac472f47ebc01b9c7ca8dfae9cb617df1b8c4349)
 *   - libar-pal.so (SpeakerProtection::spkrProtProcessingMode @ 0x0015c0e8)
 *   - libar-gsl.so (gsl_apm_config_inband @ 0x00118278, gsl_apm_get_config_inband @ 0x00118d8c)
 */
#define M11_AW_SP_RX_MODULE_MID          0x10013D01u
#define M11_AW_SP_RX_MODULE_IID          0x000042D3u
#define M11_AW_VI_TX_MODULE_MID          0x10013D00u
#define M11_AW_VI_TX_MODULE_IID          0x000042D4u

/* Graph metadata tags (ACDB static metadata, NOT runtime DSP param IDs) */
#define M11_AW_ACDB_TAG_SPKR_RX          0xC0000029u
#define M11_AW_ACDB_TAG_VI_TX            0xC0000028u

/* ACDB static calibration-table parameter IDs on IID 0x42D3 in subgraph 0xB0000002 */
#define M11_AW_ACDB_STATIC_PARAM_11      0x10013D11u /* 4 bytes */
#define M11_AW_ACDB_STATIC_PARAM_25      0x10013D25u /* 16,416 bytes */
#define M11_AW_ACDB_STATIC_PARAM_30      0x10013D30u /* 8 bytes */

/* Subgraph IDs in stock Forte_acdb_cal.acdb */
#define M11_AW_SUBGRAPH_SPKR_RX          0xB0000002u
#define M11_AW_SUBGRAPH_VI_TX_DEV        0xB00000D5u
#define M11_AW_SUBGRAPH_VI_TX_STRM       0xB00000CEu

/* Runtime PAL/DSP SET_CFG / GET_CFG parameter ID and channel selectors */
#define M11_PARAM_ID_SP_TH_VI_R0_T0      0x10013D2Au
#define M11_AW_CH0_PARAM_SELECTOR        0x10013D1Bu /* top 0x34 RE_L */
#define M11_AW_CH1_PARAM_SELECTOR        0x10013D1Cu /* bottom 0x35 RE_R */

#define M11_AW_RE_MIN_MOHM               3000
#define M11_AW_RE_MAX_MOHM               12000
#define M11_AW_RE_PAL_ABI_MAX_MOHM       524287

/* Identity-locked marble factory calibration constants (for test verification only) */
#define M11_MARBLE_CH0_FACTORY_MOHM      6372
#define M11_MARBLE_CH0_FACTORY_Q12       26099u
#define M11_MARBLE_CH1_FACTORY_MOHM      7003
#define M11_MARBLE_CH1_FACTORY_Q12       28684u

/*
 * Exact 48-byte PAL SpeakerProtection::setAwReValue envelope:
 *   [0..15]  apm_module_param_data_t: (iid=0x42D3, param_id=0x10013D2A, param_size=28, error_code=0)
 *   [16..43] inner 28B:               (0, 0x10013D1B + ch, 1, 0, 0, 0, q12_re)
 *   [44..47] 8B alignment padding:    0
 */
typedef struct __attribute__((packed)) {
    uint32_t module_instance_id; /* 0x000042D3 */
    uint32_t param_id;           /* 0x10013D2A */
    uint32_t param_size;         /* 28 */
    uint32_t error_code;         /* 0 */
    uint32_t inner_reserved0;    /* 0 */
    uint32_t channel_selector;   /* 0x10013D1B + ch */
    uint32_t inner_op;           /* 1 */
    uint32_t inner_zero0;        /* 0 */
    uint32_t inner_zero1;        /* 0 */
    uint32_t inner_zero2;        /* 0 */
    uint32_t q12_re;             /* ((uint32_t)re_mohm << 12) / 1000 */
    uint32_t pad_align8;         /* 0 */
} m11_aw_re_envelope_48_t;

/*
 * 64-byte in-band APM_CMD_SET_CFG (0x01001006) / APM_CMD_GET_CFG (0x01001007) payload
 * -> 88-byte GPR packet addressed to dst_port = 0x42D3 (M11_AW_SP_RX_MODULE_IID).
 */
typedef struct __attribute__((packed)) {
    m11_apm_cmd_header_t    cmd_hdr;
    m11_aw_re_envelope_48_t env;
} m11_apm_aw_re_cfg_pkt_t;

/*
 * 52-byte in-band APM_CMD_RSP_GET_CFG (0x02001000) payload (4B status + 48B env)
 * -> 76-byte GPR packet originating from src_port = 0x42D3 (M11_AW_SP_RX_MODULE_IID).
 */
typedef struct __attribute__((packed)) {
    uint32_t                status;
    m11_aw_re_envelope_48_t env;
} m11_apm_rsp_aw_re_get_cfg_t;

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(m11_aw_re_envelope_48_t) == 48u, "m11_aw_re_envelope_48_t must be 48 bytes");
_Static_assert(sizeof(m11_apm_aw_re_cfg_pkt_t) == 64u, "m11_apm_aw_re_cfg_pkt_t must be 64 bytes");
_Static_assert(sizeof(m11_apm_rsp_aw_re_get_cfg_t) == 52u, "m11_apm_rsp_aw_re_get_cfg_t must be 52 bytes");
#endif

typedef struct {
    int32_t  re_mohm[2];
    uint32_t q12_re[2];
} m11_aw_cal_pair_t;

typedef struct {
    int      aw_dev_0_switch;        /* Software caller pre-check: must be 0 (Disable) */
    int      aw_dev_1_switch;        /* Software caller pre-check: must be 0 (Disable) */
    bool     amp_enable_requested;   /* Must be false */
    bool     vi_tx_subgraph_opened;  /* 0xb00000d5 -> 0xb00000ce */
    bool     vi_tx_subgraph_prepared;
    uint32_t vi_tx_module_iid;       /* Must be 0x42D4 */
    uint32_t sp_rx_module_iid;       /* Must be 0x42D3 */
} m11_aw_safety_context_t;

uint32_t m11_aw_mohm_to_q12(int32_t re_mohm);

int m11_aw_parse_calr_pair(const uint8_t *buf, size_t len, m11_aw_cal_pair_t *out_pair);

int m11_aw_build_re_envelope_48(uint32_t channel, int32_t re_mohm,
                                m11_aw_re_envelope_48_t *out_env);

int m11_aw_pack_set_cfg_pkt(uint8_t *out_buf, size_t out_cap, size_t *out_len,
                            uint32_t src_port, uint32_t token,
                            uint32_t channel, int32_t re_mohm);

int m11_aw_pack_get_cfg_pkt(uint8_t *out_buf, size_t out_cap, size_t *out_len,
                            uint32_t src_port, uint32_t token,
                            uint32_t channel);

int m11_aw_pack_get_cfg_rsp_pkt(uint8_t *out_buf, size_t out_cap, size_t *out_len,
                                uint32_t dst_port, uint32_t token,
                                uint32_t status, uint32_t channel, int32_t re_mohm);

int m11_aw_validate_cfg_req_pkt(const uint8_t *pkt, size_t pkt_len,
                                uint32_t expected_opcode,
                                uint32_t *out_channel, uint32_t *out_q12_re);

int m11_aw_validate_get_cfg_rsp_pkt(const uint8_t *pkt, size_t pkt_len,
                                    uint32_t expected_dst_port, uint32_t expected_token,
                                    uint32_t expected_channel, uint32_t expected_q12_re);

int m11_aw_validate_safety_context(const m11_aw_safety_context_t *ctx);

int m11_aw_apply_and_verify_re_dsp(m11_gpr_engine_t *gpr,
                                   const m11_aw_safety_context_t *safety_ctx,
                                   const m11_aw_cal_pair_t *cal,
                                   uint32_t timeout_ms);

#ifdef __cplusplus
}
#endif

#endif /* M11_RUNTIME_REPAIR_AW_PROTECTION_H */
