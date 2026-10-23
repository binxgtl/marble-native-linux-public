#include "m11_aw_protection.h"

#include <errno.h>
#include <string.h>

uint32_t m11_aw_mohm_to_q12(int32_t re_mohm) {
    if (re_mohm <= 0 || re_mohm > M11_AW_RE_PAL_ABI_MAX_MOHM) return 0u;
    return (((uint32_t)re_mohm) << 12) / 1000u;
}

int m11_aw_parse_calr_pair(const uint8_t *buf, size_t len, m11_aw_cal_pair_t *out_pair) {
    if (!buf || !out_pair) return -EINVAL;
    if (len != 8u) return -EBADMSG;

    int32_t ch0 = 0, ch1 = 0;
    memcpy(&ch0, buf, 4u);
    memcpy(&ch1, buf + 4u, 4u);

    if (ch0 < M11_AW_RE_MIN_MOHM || ch0 > M11_AW_RE_MAX_MOHM ||
        ch1 < M11_AW_RE_MIN_MOHM || ch1 > M11_AW_RE_MAX_MOHM) {
        return -ERANGE;
    }

    memset(out_pair, 0, sizeof(*out_pair));
    out_pair->re_mohm[0] = ch0;
    out_pair->re_mohm[1] = ch1;
    out_pair->q12_re[0] = m11_aw_mohm_to_q12(ch0);
    out_pair->q12_re[1] = m11_aw_mohm_to_q12(ch1);
    return 0;
}

int m11_aw_build_re_envelope_48(uint32_t channel, int32_t re_mohm,
                                m11_aw_re_envelope_48_t *out_env) {
    if (!out_env || channel > 1u) return -EINVAL;
    if (re_mohm < M11_AW_RE_MIN_MOHM || re_mohm > M11_AW_RE_MAX_MOHM) return -ERANGE;

    memset(out_env, 0, sizeof(*out_env));
    out_env->module_instance_id = M11_AW_SP_RX_MODULE_IID; /* 0x42D3 */
    out_env->param_id = M11_PARAM_ID_SP_TH_VI_R0_T0;       /* 0x10013D2A */
    out_env->param_size = 28u;
    out_env->error_code = 0u;
    out_env->inner_reserved0 = 0u;
    out_env->channel_selector = M11_AW_CH0_PARAM_SELECTOR + channel;
    out_env->inner_op = 1u;
    out_env->inner_zero0 = 0u;
    out_env->inner_zero1 = 0u;
    out_env->inner_zero2 = 0u;
    out_env->q12_re = m11_aw_mohm_to_q12(re_mohm);
    out_env->pad_align8 = 0u;
    return 0;
}

int m11_aw_pack_set_cfg_pkt(uint8_t *out_buf, size_t out_cap, size_t *out_len,
                            uint32_t src_port, uint32_t token,
                            uint32_t channel, int32_t re_mohm) {
    if (!out_buf || !out_len || token == 0u) return -EINVAL;

    m11_apm_aw_re_cfg_pkt_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.cmd_hdr.payload_address_lsw = 0u;
    cfg.cmd_hdr.payload_address_msw = 0u;
    cfg.cmd_hdr.mem_map_handle = 0u;
    cfg.cmd_hdr.payload_size = (uint32_t)sizeof(m11_aw_re_envelope_48_t);

    int rc = m11_aw_build_re_envelope_48(channel, re_mohm, &cfg.env);
    if (rc < 0) return rc;

    /*
     * Stock libar-gsl.so (gsl_graph_set_custom_config / gsl_apm_config_inband @ 0x00118278)
     * sends single-parameter custom SET_CFG directly to dst_port = module_instance_id (0x42D3).
     */
    return m11_gpr_pack_packet(out_buf, out_cap, out_len,
                               M11_AW_SP_RX_MODULE_IID, src_port,
                               token, M11_APM_CMD_SET_CFG,
                               &cfg, sizeof(cfg));
}

int m11_aw_pack_get_cfg_pkt(uint8_t *out_buf, size_t out_cap, size_t *out_len,
                            uint32_t src_port, uint32_t token,
                            uint32_t channel) {
    if (!out_buf || !out_len || token == 0u || channel > 1u) return -EINVAL;

    m11_apm_aw_re_cfg_pkt_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.cmd_hdr.payload_address_lsw = 0u;
    cfg.cmd_hdr.payload_address_msw = 0u;
    cfg.cmd_hdr.mem_map_handle = 0u;
    cfg.cmd_hdr.payload_size = (uint32_t)sizeof(m11_aw_re_envelope_48_t);

    int rc = m11_aw_build_re_envelope_48(channel, M11_MARBLE_CH0_FACTORY_MOHM, &cfg.env);
    if (rc < 0) return rc;
    cfg.env.q12_re = 0u; /* Clear value field in GET_CFG query */

    /*
     * Stock libar-gsl.so (gsl_graph_get_custom_config / gsl_apm_get_config_inband @ 0x00118d8c)
     * sends single-parameter custom GET_CFG directly to dst_port = module_instance_id (0x42D3).
     */
    return m11_gpr_pack_packet(out_buf, out_cap, out_len,
                               M11_AW_SP_RX_MODULE_IID, src_port,
                               token, M11_APM_CMD_GET_CFG,
                               &cfg, sizeof(cfg));
}

int m11_aw_pack_get_cfg_rsp_pkt(uint8_t *out_buf, size_t out_cap, size_t *out_len,
                                uint32_t dst_port, uint32_t token,
                                uint32_t status, uint32_t channel, int32_t re_mohm) {
    if (!out_buf || !out_len || dst_port == 0u || token == 0u) return -EINVAL;

    m11_apm_rsp_aw_re_get_cfg_t rsp;
    memset(&rsp, 0, sizeof(rsp));
    rsp.status = status;
    int rc = m11_aw_build_re_envelope_48(channel, re_mohm, &rsp.env);
    if (rc < 0) return rc;

    return m11_gpr_pack_packet_ex(out_buf, out_cap, out_len,
                                  M11_GPR_DOMAIN_APPS, M11_GPR_DOMAIN_ADSP,
                                  M11_GPR_CLIENT_DATA_DEFAULT,
                                  dst_port, M11_AW_SP_RX_MODULE_IID,
                                  token, M11_APM_CMD_RSP_GET_CFG,
                                  &rsp, sizeof(rsp));
}

int m11_aw_validate_cfg_req_pkt(const uint8_t *pkt, size_t pkt_len,
                                uint32_t expected_opcode,
                                uint32_t *out_channel, uint32_t *out_q12_re) {
    if (!pkt) return -EINVAL;
    if (expected_opcode != M11_APM_CMD_SET_CFG &&
        expected_opcode != M11_APM_CMD_GET_CFG) {
        return -EINVAL;
    }

    m11_gpr_hdr_t hdr;
    const uint8_t *pl = NULL;
    size_t pl_len = 0u;
    int rc = m11_gpr_validate_packet(pkt, pkt_len, &hdr, &pl, &pl_len);
    if (rc < 0) return rc;

    if (hdr.dst_domain_id != M11_GPR_DOMAIN_ADSP ||
        hdr.src_domain_id != M11_GPR_DOMAIN_APPS ||
        hdr.client_data != M11_GPR_CLIENT_DATA_DEFAULT ||
        hdr.token == 0u) {
        return -EPROTO;
    }
    if (!m11_gpr_is_valid_src_port(hdr.src_port)) {
        return -EPROTO;
    }
    /* Single-parameter SET_CFG / GET_CFG must target module instance 0x42D3, NOT port 1 */
    if (hdr.dst_port != M11_AW_SP_RX_MODULE_IID) {
        return -EPROTO;
    }
    if (hdr.opcode != expected_opcode) {
        return -EPROTO;
    }
    if (pl_len != sizeof(m11_apm_aw_re_cfg_pkt_t)) {
        return -EBADMSG;
    }

    m11_apm_aw_re_cfg_pkt_t cfg;
    memcpy(&cfg, pl, sizeof(cfg));
    if (cfg.cmd_hdr.payload_address_lsw != 0u ||
        cfg.cmd_hdr.payload_address_msw != 0u ||
        cfg.cmd_hdr.mem_map_handle != 0u ||
        cfg.cmd_hdr.payload_size != sizeof(m11_aw_re_envelope_48_t)) {
        return -EBADMSG;
    }
    if (cfg.env.module_instance_id != M11_AW_SP_RX_MODULE_IID ||
        cfg.env.param_id != M11_PARAM_ID_SP_TH_VI_R0_T0 ||
        cfg.env.param_size != 28u ||
        cfg.env.error_code != 0u ||
        cfg.env.inner_reserved0 != 0u ||
        cfg.env.inner_op != 1u ||
        cfg.env.inner_zero0 != 0u ||
        cfg.env.inner_zero1 != 0u ||
        cfg.env.inner_zero2 != 0u ||
        cfg.env.pad_align8 != 0u) {
        return -EPROTO;
    }

    uint32_t ch = 0u;
    if (cfg.env.channel_selector == M11_AW_CH0_PARAM_SELECTOR) {
        ch = 0u;
    } else if (cfg.env.channel_selector == M11_AW_CH1_PARAM_SELECTOR) {
        ch = 1u;
    } else {
        return -EPROTO;
    }

    if (expected_opcode == M11_APM_CMD_SET_CFG) {
        uint32_t min_q12 = m11_aw_mohm_to_q12(M11_AW_RE_MIN_MOHM);
        uint32_t max_q12 = m11_aw_mohm_to_q12(M11_AW_RE_MAX_MOHM);
        if (cfg.env.q12_re < min_q12 || cfg.env.q12_re > max_q12) {
            return -ERANGE;
        }
    } else {
        if (cfg.env.q12_re != 0u) return -EBADMSG;
    }

    if (out_channel) *out_channel = ch;
    if (out_q12_re) *out_q12_re = cfg.env.q12_re;
    return 0;
}

int m11_aw_validate_get_cfg_rsp_pkt(const uint8_t *pkt, size_t pkt_len,
                                    uint32_t expected_dst_port, uint32_t expected_token,
                                    uint32_t expected_channel, uint32_t expected_q12_re) {
    if (!pkt || expected_dst_port == 0u || expected_token == 0u || expected_channel > 1u) {
        return -EINVAL;
    }

    m11_gpr_hdr_t hdr;
    const uint8_t *pl = NULL;
    size_t pl_len = 0u;
    int rc = m11_gpr_validate_packet(pkt, pkt_len, &hdr, &pl, &pl_len);
    if (rc < 0) return rc;

    if (hdr.dst_domain_id != M11_GPR_DOMAIN_APPS ||
        hdr.src_domain_id != M11_GPR_DOMAIN_ADSP ||
        hdr.src_port != M11_AW_SP_RX_MODULE_IID ||
        hdr.dst_port != expected_dst_port) {
        return -EPROTO;
    }
    if (hdr.token != expected_token) {
        return -ESTALE;
    }
    if (hdr.opcode != M11_APM_CMD_RSP_GET_CFG) {
        return -EPROTO;
    }
    if (pl_len != sizeof(m11_apm_rsp_aw_re_get_cfg_t)) {
        return -EBADMSG;
    }

    m11_apm_rsp_aw_re_get_cfg_t rsp;
    memcpy(&rsp, pl, sizeof(rsp));
    if (rsp.status != 0u || rsp.env.error_code != 0u) {
        return -EREMOTEIO;
    }
    if (rsp.env.module_instance_id != M11_AW_SP_RX_MODULE_IID) {
        return -EPROTO;
    }
    if (rsp.env.param_id != M11_PARAM_ID_SP_TH_VI_R0_T0) {
        return -EPROTO;
    }
    if (rsp.env.param_size != 28u ||
        rsp.env.inner_reserved0 != 0u ||
        rsp.env.channel_selector != (M11_AW_CH0_PARAM_SELECTOR + expected_channel) ||
        rsp.env.inner_op != 1u ||
        rsp.env.inner_zero0 != 0u ||
        rsp.env.inner_zero1 != 0u ||
        rsp.env.inner_zero2 != 0u ||
        rsp.env.pad_align8 != 0u ||
        rsp.env.q12_re != expected_q12_re) {
        return -EBADMSG;
    }
    return 0;
}

int m11_aw_validate_safety_context(const m11_aw_safety_context_t *ctx) {
    if (!ctx) return -EINVAL;

    /*
     * FAIL-CLOSED AMPLIFIER GATE:
     * Never permit any amplifier enable request, and require both Awinic switches
     * (aw_dev_0_switch and aw_dev_1_switch) to be 0 (Disable).
     */
    if (ctx->amp_enable_requested || ctx->aw_dev_0_switch != 0 || ctx->aw_dev_1_switch != 0) {
        return -EACCES;
    }

    /*
     * VI FEEDBACK SUBGRAPH DEPENDENCY GATE:
     * Stock marble Speaker Protection RX (MID 0x10013d01, IID 0x42d3 in subgraph 0xb0000002)
     * requires VI Feedback TX (MID 0x10013d00, IID 0x42d4 in subgraphs 0xb00000d5 -> 0xb00000ce)
     * to be opened and prepared before RX calibration/protection can be qualified.
     */
    if (!ctx->vi_tx_subgraph_opened || !ctx->vi_tx_subgraph_prepared) {
        return -EDESTADDRREQ;
    }
    if (ctx->vi_tx_module_iid != M11_AW_VI_TX_MODULE_IID ||
        ctx->sp_rx_module_iid != M11_AW_SP_RX_MODULE_IID) {
        return -EPROTO;
    }
    return 0;
}

int m11_aw_apply_and_verify_re_dsp(m11_gpr_engine_t *gpr,
                                   const m11_aw_safety_context_t *safety_ctx,
                                   const m11_aw_cal_pair_t *cal,
                                   uint32_t timeout_ms) {
    if (!gpr || !safety_ctx || !cal || timeout_ms == 0) return -EINVAL;

    int rc = m11_aw_validate_safety_context(safety_ctx);
    if (rc < 0) return rc;

    for (uint32_t ch = 0; ch < 2u; ch++) {
        m11_apm_aw_re_cfg_pkt_t set_pkt;
        memset(&set_pkt, 0, sizeof(set_pkt));
        set_pkt.cmd_hdr.payload_address_lsw = 0u;
        set_pkt.cmd_hdr.payload_address_msw = 0u;
        set_pkt.cmd_hdr.mem_map_handle = 0u;
        set_pkt.cmd_hdr.payload_size = (uint32_t)sizeof(m11_aw_re_envelope_48_t);

        rc = m11_aw_build_re_envelope_48(ch, cal->re_mohm[ch], &set_pkt.env);
        if (rc < 0) return rc;

        /*
         * Stock libar-gsl.so routes single-parameter in-band APM_CMD_SET_CFG and
         * APM_CMD_GET_CFG to dst_port = sp_rx_module_iid (0x42D3), NOT port 1.
         */
        uint32_t dsp_status = 0;
        rc = m11_gpr_engine_transact(gpr, safety_ctx->sp_rx_module_iid, M11_APM_CMD_SET_CFG,
                                     &set_pkt, sizeof(set_pkt), timeout_ms,
                                     &dsp_status, NULL, 0, NULL);
        if (rc < 0) return rc;

        m11_apm_aw_re_cfg_pkt_t get_req = set_pkt;
        get_req.env.q12_re = 0u;

        m11_apm_rsp_aw_re_get_cfg_t get_rsp;
        memset(&get_rsp, 0, sizeof(get_rsp));
        size_t rsp_len = 0;
        rc = m11_gpr_engine_transact(gpr, safety_ctx->sp_rx_module_iid, M11_APM_CMD_GET_CFG,
                                     &get_req, sizeof(get_req), timeout_ms,
                                     &dsp_status, &get_rsp, sizeof(get_rsp), &rsp_len);
        if (rc < 0) return rc;
        if (rsp_len != sizeof(get_rsp)) return -EBADMSG;

        if (get_rsp.status != 0u || get_rsp.env.error_code != 0u) {
            return -EREMOTEIO;
        }
        if (get_rsp.env.module_instance_id != M11_AW_SP_RX_MODULE_IID ||
            get_rsp.env.param_id != M11_PARAM_ID_SP_TH_VI_R0_T0 ||
            get_rsp.env.param_size != 28u ||
            get_rsp.env.inner_reserved0 != 0u ||
            get_rsp.env.channel_selector != (M11_AW_CH0_PARAM_SELECTOR + ch) ||
            get_rsp.env.inner_op != 1u ||
            get_rsp.env.inner_zero0 != 0u ||
            get_rsp.env.inner_zero1 != 0u ||
            get_rsp.env.inner_zero2 != 0u ||
            get_rsp.env.pad_align8 != 0u ||
            get_rsp.env.q12_re != cal->q12_re[ch]) {
            return -EBADMSG;
        }
    }

    return 0;
}
