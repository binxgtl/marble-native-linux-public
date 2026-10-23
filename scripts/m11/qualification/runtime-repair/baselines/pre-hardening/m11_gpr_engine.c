#include "m11_gpr_engine.h"

#include <errno.h>
#include <string.h>

#ifndef ENETRESET
#define ENETRESET 102
#endif

bool m11_gpr_is_valid_src_port(uint32_t src_port) {
    /*
     * Stock gpr_dlkm.ko (__gpr_send_pkt / gpr_Allowed_send_pkt) truncates
     * dynamic service ports via (short)port in idr_find(svcs_idr, (short)port)
     * where idr_alloc_cyclic uses range [1, 0x7FFF].
     * Ports 0x0003 (spf_core_dlkm.ko) and 0x0017 (audio_pkt_dlkm.ko fallback)
     * are statically registered in kernel space and rejected on userspace open.
     */
    if (src_port == 0u || src_port > M11_GPR_MAX_VALID_DYNAMIC_SRC_PORT) {
        return false;
    }
    if (src_port == M11_GPR_KERNEL_RESERVED_PORT_SPF_CORE ||
        src_port == M11_GPR_KERNEL_RESERVED_PORT_AUDIO_PKT) {
        return false;
    }
    return true;
}

uint32_t m11_gpr_make_header_word(uint32_t version, uint32_t hdr_dwords, uint32_t pkt_bytes) {
    return (version & 0xFu) | ((hdr_dwords & 0xFu) << 4) | ((pkt_bytes & 0xFFFFFFu) << 8);
}

void m11_gpr_unpack_header_word(uint32_t word, uint32_t *version,
                                uint32_t *hdr_dwords, uint32_t *pkt_bytes) {
    if (version) *version = word & 0xFu;
    if (hdr_dwords) *hdr_dwords = (word >> 4) & 0xFu;
    if (pkt_bytes) *pkt_bytes = (word >> 8) & 0xFFFFFFu;
}

static uint32_t expected_rsp_for_req(uint32_t req_opcode) {
    switch (req_opcode) {
        case M11_APM_CMD_GET_SPF_STATE:
            return M11_APM_CMD_RSP_GET_SPF_STATE;
        case M11_APM_CMD_SHARED_MEM_MAP_REGIONS:
            return M11_APM_CMDRSP_SHARED_MEM_MAP_REGIONS;
        case M11_APM_CMD_GET_CFG:
            return M11_APM_CMD_RSP_GET_CFG;
        default:
            return M11_GPR_IBASIC_RSP_RESULT;
    }
}

int m11_gpr_pack_packet_ex(uint8_t *out_buf, size_t out_cap, size_t *out_len,
                           uint8_t dst_domain_id, uint8_t src_domain_id,
                           uint8_t client_data,
                           uint32_t dst_port, uint32_t src_port,
                           uint32_t token, uint32_t opcode,
                           const void *payload, size_t payload_len) {
    if (!out_buf || !out_len) return -EINVAL;
    if (payload_len > 0 && !payload) return -EINVAL;
    if (dst_domain_id == 0u || src_domain_id == 0u || dst_port == 0u || src_port == 0u) {
        return -EINVAL;
    }
    if (payload_len > M11_GPR_MAX_PKT_BYTES - M11_GPR_HDR_BYTES) return -EMSGSIZE;
    size_t total = M11_GPR_HDR_BYTES + payload_len;
    if (total > out_cap) return -EMSGSIZE;

    m11_gpr_hdr_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.header = m11_gpr_make_header_word(M11_GPR_HDR_VERSION, M11_GPR_HDR_DWORDS, (uint32_t)total);
    hdr.dst_domain_id = dst_domain_id;
    hdr.src_domain_id = src_domain_id;
    hdr.client_data = client_data;
    hdr.reserved = 0u;
    hdr.src_port = src_port;
    hdr.dst_port = dst_port;
    hdr.token = token;
    hdr.opcode = opcode;

    memcpy(out_buf, &hdr, sizeof(hdr));
    if (payload_len > 0) {
        memcpy(out_buf + sizeof(hdr), payload, payload_len);
    }
    *out_len = total;
    return 0;
}

int m11_gpr_pack_packet(uint8_t *out_buf, size_t out_cap, size_t *out_len,
                        uint32_t dst_port, uint32_t src_port,
                        uint32_t token, uint32_t opcode,
                        const void *payload, size_t payload_len) {
    return m11_gpr_pack_packet_ex(out_buf, out_cap, out_len,
                                  M11_GPR_DOMAIN_ADSP, M11_GPR_DOMAIN_APPS,
                                  M11_GPR_CLIENT_DATA_DEFAULT,
                                  dst_port, src_port, token, opcode,
                                  payload, payload_len);
}

int m11_gpr_validate_packet(const uint8_t *buf, size_t len,
                            m11_gpr_hdr_t *out_hdr,
                            const uint8_t **out_payload, size_t *out_payload_len) {
    if (!buf || len < M11_GPR_HDR_BYTES || len > M11_GPR_MAX_PKT_BYTES) return -EBADMSG;

    m11_gpr_hdr_t hdr;
    memcpy(&hdr, buf, sizeof(hdr));

    uint32_t ver = 0, hdr_dwords = 0, pkt_bytes = 0;
    m11_gpr_unpack_header_word(hdr.header, &ver, &hdr_dwords, &pkt_bytes);
    if (ver != M11_GPR_HDR_VERSION || hdr_dwords != M11_GPR_HDR_DWORDS) return -EBADMSG;
    if (pkt_bytes < M11_GPR_HDR_BYTES || pkt_bytes != len) return -EBADMSG;
    if (hdr.reserved != 0u) return -EBADMSG;
    if (hdr.dst_domain_id == 0u || hdr.src_domain_id == 0u) return -EBADMSG;
    if (hdr.src_port == 0u || hdr.dst_port == 0u) return -EBADMSG;

    if (out_hdr) *out_hdr = hdr;
    if (out_payload) *out_payload = buf + M11_GPR_HDR_BYTES;
    if (out_payload_len) *out_payload_len = len - M11_GPR_HDR_BYTES;
    return 0;
}

int m11_gpr_engine_init(m11_gpr_engine_t *eng, const m11_gpr_transport_t *transport,
                        uint32_t src_port) {
    if (!eng || !transport || !transport->open_fn || !transport->close_fn ||
        !transport->write_fn || !transport->poll_read_fn ||
        !m11_gpr_is_valid_src_port(src_port)) {
        return -EINVAL;
    }
    memset(eng, 0, sizeof(*eng));
    eng->transport = *transport;
    eng->held_fd = -1;
    eng->src_port = src_port;
    eng->next_token = 1u;
    return 0;
}

void m11_gpr_engine_set_event_cb(m11_gpr_engine_t *eng, m11_gpr_event_cb_t cb, void *user) {
    if (!eng) return;
    eng->event_cb = cb;
    eng->event_cb_user = user;
}

int m11_gpr_engine_open(m11_gpr_engine_t *eng) {
    if (!eng) return -EINVAL;
    if (eng->pdr_down) return -ENETRESET;
    /* Enforce single held-fd invariant: never re-open or open multiple fds */
    if (eng->is_open || eng->open_count > 0) return -EBUSY;

    int fd = eng->transport.open_fn(eng->transport.user);
    if (fd < 0) {
        if (fd == -ENETRESET) eng->pdr_down = true;
        return fd;
    }
    eng->held_fd = fd;
    eng->is_open = true;
    eng->open_count++;
    return 0;
}

int m11_gpr_engine_close(m11_gpr_engine_t *eng) {
    if (!eng) return -EINVAL;
    if (!eng->is_open) return 0;

    int fd = eng->held_fd;
    eng->held_fd = -1;
    eng->is_open = false;
    eng->close_count++;
    memset(eng->slots, 0, sizeof(eng->slots));
    return eng->transport.close_fn(eng->transport.user, fd);
}

int m11_gpr_engine_submit_ex(m11_gpr_engine_t *eng, uint8_t client_data,
                             uint32_t dst_port, uint32_t opcode,
                             const void *payload, size_t payload_len, uint32_t *out_token) {
    if (!eng) return -EINVAL;
    eng->last_tx_status = M11_GPR_TX_NOT_ATTEMPTED;
    if (!out_token || dst_port == 0u) return -EINVAL;
    if (eng->pdr_down) return -ENETRESET;
    if (!eng->is_open || eng->held_fd < 0) return -EBADF;

    m11_gpr_slot_t *slot = NULL;
    for (size_t i = 0; i < M11_GPR_MAX_PENDING; i++) {
        if (!eng->slots[i].in_use) {
            slot = &eng->slots[i];
            break;
        }
    }
    if (!slot) return -ENOSPC;

    uint32_t tok = eng->next_token++;
    if (eng->next_token == 0) eng->next_token = 1u;

    uint8_t pkt[M11_GPR_MAX_PKT_BYTES];
    size_t pkt_len = 0;
    int rc = m11_gpr_pack_packet_ex(pkt, sizeof(pkt), &pkt_len,
                                    M11_GPR_DOMAIN_ADSP, M11_GPR_DOMAIN_APPS,
                                    client_data, dst_port, eng->src_port,
                                    tok, opcode, payload, payload_len);
    if (rc < 0) return rc;

    memset(slot, 0, sizeof(*slot));
    slot->in_use = true;
    slot->token = tok;
    slot->dst_port = dst_port;
    slot->req_opcode = opcode;
    slot->expected_rsp_opcode = expected_rsp_for_req(opcode);

    int wrc = eng->transport.write_fn(eng->transport.user, eng->held_fd, pkt, pkt_len);
    if (wrc < 0) {
        memset(slot, 0, sizeof(*slot));
        eng->last_tx_status = M11_GPR_TX_WRITE_ERROR;
        if (wrc == -ENETRESET) eng->pdr_down = true;
        return wrc;
    }
    if ((size_t)wrc != pkt_len) {
        memset(slot, 0, sizeof(*slot));
        eng->last_tx_status = M11_GPR_TX_SHORT_WRITE;
        return -EIO;
    }

    eng->last_tx_status = M11_GPR_TX_SENT;
    *out_token = tok;
    return 0;
}

int m11_gpr_engine_submit(m11_gpr_engine_t *eng, uint32_t dst_port, uint32_t opcode,
                          const void *payload, size_t payload_len, uint32_t *out_token) {
    return m11_gpr_engine_submit_ex(eng, M11_GPR_CLIENT_DATA_DEFAULT,
                                    dst_port, opcode, payload, payload_len, out_token);
}

int m11_gpr_engine_pump_once(m11_gpr_engine_t *eng, uint32_t timeout_ms) {
    if (!eng) return -EINVAL;
    eng->last_rx_status = M11_GPR_RX_TRANSPORT_ERR;
    if (eng->pdr_down) return -ENETRESET;
    if (!eng->is_open || eng->held_fd < 0) return -EBADF;

    uint8_t rx[M11_GPR_MAX_PKT_BYTES];
    int rrc = eng->transport.poll_read_fn(eng->transport.user, eng->held_fd, rx, sizeof(rx), timeout_ms);
    if (rrc < 0) {
        if (rrc == -ENETRESET) eng->pdr_down = true;
        return rrc;
    }
    if (rrc == 0) return -ETIMEDOUT;
    if ((size_t)rrc > sizeof(rx)) {
        eng->rx_dropped_malformed++;
        eng->last_rx_status = M11_GPR_RX_DROPPED_PACKET;
        return -EMSGSIZE;
    }

    m11_gpr_hdr_t hdr;
    const uint8_t *pl = NULL;
    size_t pl_len = 0;
    if (m11_gpr_validate_packet(rx, (size_t)rrc, &hdr, &pl, &pl_len) < 0) {
        eng->rx_dropped_malformed++;
        eng->last_rx_status = M11_GPR_RX_DROPPED_PACKET;
        return -EBADMSG;
    }

    /* Validate peer domain and destination port routing */
    if (hdr.dst_domain_id != M11_GPR_DOMAIN_APPS ||
        hdr.src_domain_id != M11_GPR_DOMAIN_ADSP ||
        hdr.dst_port != eng->src_port) {
        eng->rx_dropped_malformed++;
        eng->last_rx_status = M11_GPR_RX_DROPPED_PACKET;
        return -EBADMSG;
    }

    /* Check if this is an unsolicited event (token == 0) */
    if (hdr.token == 0) {
        eng->rx_unsolicited_events++;
        eng->last_rx_status = M11_GPR_RX_OK;
        if (eng->event_cb) {
            eng->event_cb(eng->event_cb_user, &hdr, pl, pl_len);
        }
        return 0;
    }

    m11_gpr_slot_t *slot = NULL;
    for (size_t i = 0; i < M11_GPR_MAX_PENDING; i++) {
        if (eng->slots[i].in_use && eng->slots[i].token == hdr.token) {
            slot = &eng->slots[i];
            break;
        }
    }
    if (!slot || slot->completed) {
        eng->rx_dropped_unknown_token++;
        eng->last_rx_status = M11_GPR_RX_DROPPED_PACKET;
        return -ESTALE;
    }

    /* Verify that the response originated from the target service/module port */
    if (hdr.src_port != slot->dst_port) {
        eng->rx_dropped_malformed++;
        eng->last_rx_status = M11_GPR_RX_DROPPED_PACKET;
        return -EPROTO;
    }

    /* Validate response opcode correlation and exact payload bounds */
    if (hdr.opcode == M11_GPR_IBASIC_RSP_RESULT) {
        if (pl_len != sizeof(m11_gpr_ibasic_rsp_t)) {
            eng->rx_dropped_malformed++;
            eng->last_rx_status = M11_GPR_RX_DROPPED_PACKET;
            return -EBADMSG;
        }
        m11_gpr_ibasic_rsp_t ib;
        memcpy(&ib, pl, sizeof(ib));
        if (ib.cmd_opcode != slot->req_opcode) {
            eng->rx_dropped_malformed++;
            eng->last_rx_status = M11_GPR_RX_DROPPED_PACKET;
            return -EPROTO;
        }
        slot->dsp_status = ib.status;
    } else if (hdr.opcode == slot->expected_rsp_opcode) {
        if (hdr.opcode == M11_APM_CMD_RSP_GET_SPF_STATE) {
            if (pl_len != sizeof(m11_apm_rsp_get_spf_state_t)) {
                eng->rx_dropped_malformed++;
                eng->last_rx_status = M11_GPR_RX_DROPPED_PACKET;
                return -EBADMSG;
            }
            slot->dsp_status = 0;
        } else if (hdr.opcode == M11_APM_CMDRSP_SHARED_MEM_MAP_REGIONS) {
            if (pl_len != sizeof(m11_apm_rsp_shared_mem_map_t)) {
                eng->rx_dropped_malformed++;
                eng->last_rx_status = M11_GPR_RX_DROPPED_PACKET;
                return -EBADMSG;
            }
            slot->dsp_status = 0;
        } else if (hdr.opcode == M11_APM_CMD_RSP_GET_CFG) {
            if (pl_len < sizeof(m11_apm_rsp_get_cfg_t) ||
                ((pl_len - sizeof(m11_apm_rsp_get_cfg_t)) % 8u) != 0u) {
                eng->rx_dropped_malformed++;
                eng->last_rx_status = M11_GPR_RX_DROPPED_PACKET;
                return -EBADMSG;
            }
            m11_apm_rsp_get_cfg_t gc;
            memcpy(&gc, pl, sizeof(gc));
            slot->dsp_status = gc.status;
        }
    } else {
        eng->rx_dropped_malformed++;
        eng->last_rx_status = M11_GPR_RX_DROPPED_PACKET;
        return -EPROTO;
    }

    slot->rsp_opcode = hdr.opcode;
    slot->rsp_payload_len = pl_len;
    if (pl_len > 0) {
        memcpy(slot->rsp_payload, pl, pl_len);
    }
    slot->completed = true;
    eng->last_rx_status = M11_GPR_RX_OK;
    return 0;
}

int m11_gpr_engine_wait_token(m11_gpr_engine_t *eng, uint32_t token, uint32_t timeout_ms,
                              uint32_t *out_dsp_status,
                              void *out_rsp_payload, size_t rsp_cap, size_t *out_rsp_len) {
    if (!eng || token == 0) return -EINVAL;
    if (eng->pdr_down) return -ENETRESET;

    m11_gpr_slot_t *slot = NULL;
    for (size_t i = 0; i < M11_GPR_MAX_PENDING; i++) {
        if (eng->slots[i].in_use && eng->slots[i].token == token) {
            slot = &eng->slots[i];
            break;
        }
    }
    if (!slot) return -ENOENT;

    uint32_t guard_iters = 0;
    while (!slot->completed) {
        if (++guard_iters > 64u) {
            memset(slot, 0, sizeof(*slot));
            return -ETIMEDOUT;
        }
        int prc = m11_gpr_engine_pump_once(eng, timeout_ms);
        if (prc < 0 && eng->last_rx_status == M11_GPR_RX_TRANSPORT_ERR) {
            /*
             * Fatal transport/fd error from poll_read_fn or engine state
             * (e.g. -ETIMEDOUT, -ENETRESET, -EIO, -EBADF, -ENODEV, -EPIPE, -EFAULT):
             * abort immediately and surface the exact errno instead of spinning
             * and masking it behind -ETIMEDOUT.
             */
            memset(slot, 0, sizeof(*slot));
            return prc;
        }
        /* Unrelated/stale/malformed packets (M11_GPR_RX_DROPPED_PACKET) are dropped and counted; keep pumping */
    }

    uint32_t dsp_rc = slot->dsp_status;
    if (out_dsp_status) *out_dsp_status = dsp_rc;
    if (dsp_rc != 0) {
        memset(slot, 0, sizeof(*slot));
        return -EREMOTEIO;
    }
    if (out_rsp_len) *out_rsp_len = slot->rsp_payload_len;
    if (out_rsp_payload) {
        if (rsp_cap < slot->rsp_payload_len) {
            memset(slot, 0, sizeof(*slot));
            return -ENOSPC;
        }
        memcpy(out_rsp_payload, slot->rsp_payload, slot->rsp_payload_len);
    }

    memset(slot, 0, sizeof(*slot));
    return 0;
}

int m11_gpr_engine_transact_ex(m11_gpr_engine_t *eng, uint8_t client_data,
                               uint32_t dst_port, uint32_t opcode,
                               const void *payload, size_t payload_len, uint32_t timeout_ms,
                               uint32_t *out_dsp_status,
                               void *out_rsp_payload, size_t rsp_cap, size_t *out_rsp_len) {
    uint32_t tok = 0;
    int rc = m11_gpr_engine_submit_ex(eng, client_data, dst_port, opcode,
                                      payload, payload_len, &tok);
    if (rc < 0) return rc;
    return m11_gpr_engine_wait_token(eng, tok, timeout_ms, out_dsp_status,
                                     out_rsp_payload, rsp_cap, out_rsp_len);
}

int m11_gpr_engine_transact(m11_gpr_engine_t *eng, uint32_t dst_port, uint32_t opcode,
                            const void *payload, size_t payload_len, uint32_t timeout_ms,
                            uint32_t *out_dsp_status,
                            void *out_rsp_payload, size_t rsp_cap, size_t *out_rsp_len) {
    return m11_gpr_engine_transact_ex(eng, M11_GPR_CLIENT_DATA_DEFAULT,
                                      dst_port, opcode, payload, payload_len, timeout_ms,
                                      out_dsp_status, out_rsp_payload, rsp_cap, out_rsp_len);
}

int m11_gpr_query_spf_state(m11_gpr_engine_t *eng, uint32_t timeout_ms, uint32_t *out_spf_state) {
    if (!eng || !out_spf_state) return -EINVAL;
    m11_apm_rsp_get_spf_state_t rsp = {0};
    size_t rsp_len = 0;
    uint32_t dsp_status = 0;
    int rc = m11_gpr_engine_transact(eng, M11_APM_MODULE_IID, M11_APM_CMD_GET_SPF_STATE,
                                     NULL, 0, timeout_ms, &dsp_status,
                                     &rsp, sizeof(rsp), &rsp_len);
    if (rc < 0) return rc;
    if (rsp_len != sizeof(rsp)) return -EBADMSG;
    *out_spf_state = rsp.status;
    return (rsp.status == 1u) ? 0 : -EAGAIN;
}
