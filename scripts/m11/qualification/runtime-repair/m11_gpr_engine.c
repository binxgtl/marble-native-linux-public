#define _POSIX_C_SOURCE 200809L

#include "m11_gpr_engine.h"

#include <errno.h>
#include <string.h>
#include <time.h>

#ifndef ENETRESET
#define ENETRESET 102
#endif

bool m11_gpr_is_valid_src_port(uint32_t src_port) {
    /*
     * Stock gpr_dlkm.ko (__gpr_send_pkt / gpr_Allowed_send_pkt) truncates
     * dynamic service ports via (short)port in idr_find(svcs_idr, (short)port)
     * where idr_alloc_cyclic uses range [1, 0x7FFF].
     * Our client policy excludes the static kernel ports 0x0003 (spf_core)
     * and 0x0017 (audio_pkt fallback). open(2) has no source-port argument;
     * kernel routing evidence is not a kernel userspace-open admission test.
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
        case M11_DATA_CMD_WR_SH_MEM_EP_DATA_BUFFER_V2:
            return M11_DATA_CMD_RSP_WR_SH_MEM_EP_DATA_BUFFER_DONE_V2;
        case M11_DATA_CMD_WR_SH_MEM_EP_EOS:
            return M11_DATA_CMD_RSP_WR_SH_MEM_EP_EOS_RENDERED;
        case M11_DATA_CMD_RD_SH_MEM_EP_DATA_BUFFER_V2:
            return M11_DATA_CMD_RSP_RD_SH_MEM_EP_DATA_BUFFER_DONE_V2;
        default:
            return M11_GPR_IBASIC_RSP_RESULT;
    }
}

bool m11_gpr_opcode_retains_on_timeout(uint32_t opcode) {
    /*
     * Only the two opcodes whose outcome changes ADSP-side ownership of host pages. A late
     * response to either decides whether the DSP still maps the region.
     */
    return opcode == M11_APM_CMD_SHARED_MEM_MAP_REGIONS ||
           opcode == M11_APM_CMD_SHARED_MEM_UNMAP_REGIONS;
}

uint64_t m11_gpr_monotonic_ms(void *unused) {
    (void)unused;
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0u;
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

void m11_gpr_engine_set_clock(m11_gpr_engine_t *eng, m11_gpr_clock_ms_fn fn, void *user) {
    if (!eng) return;
    eng->clock_fn = fn;
    eng->clock_user = user;
}

static uint64_t engine_now_ms(const m11_gpr_engine_t *eng) {
    if (eng->clock_fn) return eng->clock_fn(eng->clock_user);
    return m11_gpr_monotonic_ms(NULL);
}

static bool token_in_use(const m11_gpr_engine_t *eng, uint32_t token) {
    for (size_t i = 0; i < M11_GPR_MAX_PENDING; i++) {
        if (eng->slots[i].in_use && eng->slots[i].token == token) return true;
    }
    return false;
}

static m11_gpr_slot_t *find_slot(m11_gpr_engine_t *eng, uint32_t token) {
    for (size_t i = 0; i < M11_GPR_MAX_PENDING; i++) {
        if (eng->slots[i].in_use && eng->slots[i].token == token) return &eng->slots[i];
    }
    return NULL;
}

/*
 * Ends an unsuccessful wait. A response may still arrive for a request that changes
 * ADSP-side ownership, so such a slot stays reserved (orphaned) and keeps its token.
 * After PDR the engine can never receive it, so the slot is dropped and counted.
 */
static void slot_wait_failed(m11_gpr_engine_t *eng, m11_gpr_slot_t *slot) {
    if (slot->retain_on_timeout) {
        if (eng->pdr_down) {
            eng->orphans_lost++;
        } else {
            slot->orphaned = true;
            /* A valid response can have arrived after the deadline during pump_once.
             * Preserve it for explicit reconciliation, without changing the timed-out
             * transaction into success or requiring a second response from the DSP. */
            return;
        }
    }
    memset(slot, 0, sizeof(*slot));
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
    for (size_t i = 0; i < M11_GPR_MAX_PENDING; i++) {
        if (eng->slots[i].in_use && eng->slots[i].orphaned) eng->orphans_lost++;
    }
    memset(eng->slots, 0, sizeof(eng->slots));
    return eng->transport.close_fn(eng->transport.user, fd);
}

int m11_gpr_engine_submit_ex(m11_gpr_engine_t *eng, uint8_t client_data,
                             uint32_t dst_port, uint32_t opcode,
                             const void *payload, size_t payload_len, uint32_t *out_token) {
    if (!eng) return -EINVAL;
    eng->last_tx_status = M11_GPR_TX_NOT_ATTEMPTED;
    if (out_token) *out_token = 0u;
    if (!out_token || dst_port == 0u) return -EINVAL;
    if (eng->pdr_down) return -ENETRESET;
    if (!eng->is_open || eng->held_fd < 0) return -EBADF;
    if (eng->token_space_exhausted || eng->next_token == 0u) return -EOVERFLOW;

    m11_gpr_slot_t *slot = NULL;
    for (size_t i = 0; i < M11_GPR_MAX_PENDING; i++) {
        if (!eng->slots[i].in_use) {
            slot = &eng->slots[i];
            break;
        }
    }
    if (!slot) return -ENOSPC;

    /*
     * Never hand out a token that a still-reserved (pending or orphaned) slot owns, so a
     * late response to an old transaction cannot be mistaken for a new one after the
     * 32-bit token counter wraps.
     */
    uint32_t tok = 0u;
    for (size_t tries = 0; tries <= M11_GPR_MAX_PENDING; tries++) {
        if (eng->token_space_exhausted) return -EOVERFLOW;
        uint32_t cand = eng->next_token++;
        if (eng->next_token == 0) eng->token_space_exhausted = true;
        if (cand != 0u && !token_in_use(eng, cand)) {
            tok = cand;
            break;
        }
    }
    if (tok == 0u) return -EBUSY;

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
    slot->retain_on_timeout = m11_gpr_opcode_retains_on_timeout(opcode);
    if (opcode == M11_DATA_CMD_WR_SH_MEM_EP_EOS) {
        memset(&eng->eos_ev, 0, sizeof(eng->eos_ev));
        eng->eos_ev.token = tok;
    }

    int wrc = eng->transport.write_fn(eng->transport.user, eng->held_fd, pkt, pkt_len);
    *out_token = tok; /* valid from here on, even if write_fn failed */
    if (wrc < 0) {
        eng->last_tx_status = M11_GPR_TX_WRITE_ERROR;
        if (wrc == -ENETRESET) eng->pdr_down = true;
        slot_wait_failed(eng, slot);
        return wrc;
    }
    if ((size_t)wrc != pkt_len) {
        eng->last_tx_status = M11_GPR_TX_SHORT_WRITE;
        slot_wait_failed(eng, slot);
        return -EIO;
    }

    eng->last_tx_status = M11_GPR_TX_SENT;
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
        if (hdr.opcode == M11_DATA_CMD_RSP_WR_SH_MEM_EP_EOS_RENDERED && eng->eos_ev.token) {
            eng->eos_ev.event_count++;
            memset(eng->eos_ev.event_word, 0, sizeof(eng->eos_ev.event_word));
            memcpy(eng->eos_ev.event_word, pl, pl_len < 8u ? pl_len : 8u);
        }
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
    if (eng->eos_ev.token && hdr.token == eng->eos_ev.token &&
        hdr.opcode == M11_DATA_CMD_RSP_WR_SH_MEM_EP_EOS_RENDERED) {
        eng->eos_ev.rendered_count++;
        eng->eos_ev.rendered_len = (uint32_t)pl_len;
        eng->eos_ev.rendered_port = hdr.src_port;
        memset(eng->eos_ev.rendered_word, 0, sizeof(eng->eos_ev.rendered_word));
        memcpy(eng->eos_ev.rendered_word, pl, pl_len < 8u ? pl_len : 8u);
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
        if (slot->req_opcode == M11_DATA_CMD_WR_SH_MEM_EP_EOS) {
            /* stock gsl_gpr_callback frees it, whatever the status: the EOS completes on EOS_RENDERED only */
            eng->eos_ev.ibasic_count++;
            eng->eos_ev.ibasic_status = ib.status;
            eng->last_rx_status = M11_GPR_RX_OK;
            return 0;
        }
        if (ib.status == 0u && slot->expected_rsp_opcode != M11_GPR_IBASIC_RSP_RESULT) {
            /*
             * P6: a bare success ACK for a request whose success response carries data.
             * The command was received, but the required data response has not arrived, so
             * the transaction is not complete and must not be reported as a success. Keep
             * the slot pending (a data response may still follow) and count the anomaly.
             * Whether stock ever sends ACK-then-data is UNKNOWN; upstream Linux q6apm
             * treats IBASIC as the completion/failure channel and data as a separate opcode.
             */
            slot->ack_without_data = true;
            eng->rx_ibasic_ack_without_data++;
            eng->last_rx_status = M11_GPR_RX_OK;
            return 0;
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
        } else {
            /* the three data-command completions: exact sizes, the status word at its offset */
            size_t want = 0u, at = 0u;
            if (hdr.opcode == M11_DATA_CMD_RSP_WR_SH_MEM_EP_DATA_BUFFER_DONE_V2) { want = 32u; at = 12u; }
            else if (hdr.opcode == M11_DATA_CMD_RSP_WR_SH_MEM_EP_EOS_RENDERED) { want = 8u; at = 4u; }
            else if (hdr.opcode == M11_DATA_CMD_RSP_RD_SH_MEM_EP_DATA_BUFFER_DONE_V2) { want = 56u; at = 0u; }
            if (!want || pl_len != want) {
                eng->rx_dropped_malformed++;
                eng->last_rx_status = M11_GPR_RX_DROPPED_PACKET;
                return -EBADMSG;
            }
            uint32_t st;
            memcpy(&st, pl + at, sizeof(st));
            /* EOS RENDERED carries a render status, not an error code: 1 rendered, 2 dropped; stock gsl_handle_eos
             * (libar-gsl gsl_gpr_callback, 0x120238) calls any other value invalid. Only "rendered" completes. */
            if (hdr.opcode == M11_DATA_CMD_RSP_WR_SH_MEM_EP_EOS_RENDERED) st = st == 1u ? 0u : st ? st : UINT32_MAX;
            slot->dsp_status = st;
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

/*
 * Shared wait loop for wait_token (transaction) and orphan_poll (late response).
 * Returns 0 once the slot completed; otherwise the failure errno WITHOUT touching the slot,
 * so each caller applies its own policy (clear, orphan, or keep waiting).
 */
static int wait_slot_deadline(m11_gpr_engine_t *eng, m11_gpr_slot_t *slot, uint32_t timeout_ms) {
    uint64_t start = engine_now_ms(eng);
    uint64_t deadline = start + (uint64_t)timeout_ms;
    uint64_t last_now = start;
    uint64_t stalled = 0u;
    uint64_t watchdog_start = m11_gpr_monotonic_ms(NULL);

    for (;;) {
        if (slot->completed) return 0;

        uint64_t now = engine_now_ms(eng);
        uint64_t remaining = (deadline > now) ? (deadline - now) : 0u;
        if (remaining > timeout_ms) remaining = timeout_ms; /* clock stepped back */

        int prc = m11_gpr_engine_pump_once(eng, (uint32_t)remaining);
        if (slot->completed) {
            /* A transport/callback can overrun its supplied remaining budget. */
            if (engine_now_ms(eng) > deadline) return -ETIMEDOUT;
            return 0;
        }
        if (prc < 0 && eng->last_rx_status == M11_GPR_RX_TRANSPORT_ERR) {
            /*
             * Real transport/fd error (or poll timeout) from poll_read_fn or engine state
             * (-ETIMEDOUT, -ENETRESET, -EIO, -EBADF, -ENODEV, -EPIPE, -EFAULT, ...):
             * surface the exact errno instead of masking it.
             */
            return prc;
        }
        /*
         * Events and dropped packets (M11_GPR_RX_DROPPED_PACKET / unsolicited) are counted by
         * pump_once and never fail a transaction that is still inside its deadline.
         */
        now = engine_now_ms(eng);
        if (now >= deadline) return -ETIMEDOUT;

        /* Guard against a broken injected clock that never advances. */
        if (now == last_now) {
            if (++stalled > (1ull << 20)) return -ETIMEDOUT;
            if ((stalled % 1024u) == 0u) {
                /* Backpressure a readable flood while the clock does not progress.
                 * Do not cap the number of legitimate events inside a deadline. */
                struct timespec pause = { .tv_sec = 0, .tv_nsec = 1000000 };
                (void)nanosleep(&pause, NULL);
            }
        } else {
            last_now = now;
            stalled = 0u;
        }
        /* An injected clock must not turn a stalled/backward-clock test into an
         * unbounded wait. This watchdog does not establish a bound on blocking
         * kernel write/close callbacks; runtime supervision is still required. */
        if (eng->clock_fn && m11_gpr_monotonic_ms(NULL) - watchdog_start >= timeout_ms)
            return -ETIMEDOUT;
    }
}

static int consume_slot_result(m11_gpr_slot_t *slot, uint32_t *out_dsp_status,
                               uint32_t *out_rsp_opcode,
                               void *out_rsp_payload, size_t rsp_cap, size_t *out_rsp_len) {
    uint32_t dsp_rc = slot->dsp_status;
    if (out_dsp_status) *out_dsp_status = dsp_rc;
    if (out_rsp_opcode) *out_rsp_opcode = slot->rsp_opcode;
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

static int wait_token_observed(m11_gpr_engine_t *eng, uint32_t token, uint32_t timeout_ms,
                              uint32_t *out_dsp_status,
                              void *out_rsp_payload, size_t rsp_cap, size_t *out_rsp_len, bool *status_valid) {
    if (status_valid) *status_valid = false;
    if (!eng || token == 0) return -EINVAL;
    if (eng->pdr_down) return -ENETRESET;

    m11_gpr_slot_t *slot = find_slot(eng, token);
    if (!slot) return -ENOENT;
    if (slot->orphaned) return -EALREADY; /* late responses are collected via orphan_poll */

    int wrc = wait_slot_deadline(eng, slot, timeout_ms);
    if (wrc < 0) {
        slot_wait_failed(eng, slot);
        return wrc;
    }
    if (status_valid) *status_valid = true; /* matched completed response, not TX/queue acceptance */
    return consume_slot_result(slot, out_dsp_status, NULL, out_rsp_payload, rsp_cap, out_rsp_len);
}

int m11_gpr_engine_wait_token(m11_gpr_engine_t *eng, uint32_t token, uint32_t timeout_ms,
                              uint32_t *out_dsp_status,
                              void *out_rsp_payload, size_t rsp_cap, size_t *out_rsp_len) {
    return wait_token_observed(eng, token, timeout_ms, out_dsp_status,
                               out_rsp_payload, rsp_cap, out_rsp_len, NULL);
}

int m11_gpr_engine_transact_observed(m11_gpr_engine_t *eng, uint32_t dst_port, uint32_t opcode,
                                     const void *payload, size_t payload_len, uint32_t timeout_ms,
                                     uint32_t *dsp_status, bool *status_valid,
                                     void *rsp, size_t cap, size_t *rsp_len) {
    if (status_valid) *status_valid = false;
    if (dsp_status) *dsp_status = 0;
    uint32_t token = 0;
    int rc = m11_gpr_engine_submit_ex(eng, M11_GPR_CLIENT_DATA_DEFAULT, dst_port, opcode,
                                      payload, payload_len, &token);
    if (rc < 0) return rc;
    return wait_token_observed(eng, token, timeout_ms, dsp_status, rsp, cap, rsp_len, status_valid);
}

bool m11_gpr_engine_orphan_tracked(const m11_gpr_engine_t *eng, uint32_t token) {
    if (!eng || token == 0u || eng->pdr_down) return false;
    for (size_t i = 0; i < M11_GPR_MAX_PENDING; i++) {
        if (eng->slots[i].in_use && eng->slots[i].orphaned && eng->slots[i].token == token) {
            return true;
        }
    }
    return false;
}

uint32_t m11_gpr_engine_orphan_count(const m11_gpr_engine_t *eng) {
    uint32_t n = 0u;
    if (!eng) return 0u;
    for (size_t i = 0; i < M11_GPR_MAX_PENDING; i++) {
        if (eng->slots[i].in_use && eng->slots[i].orphaned) n++;
    }
    return n;
}

int m11_gpr_engine_orphan_poll(m11_gpr_engine_t *eng, uint32_t token, uint32_t timeout_ms,
                               uint32_t *out_dsp_status, uint32_t *out_rsp_opcode,
                               void *out_rsp_payload, size_t rsp_cap, size_t *out_rsp_len) {
    if (!eng || token == 0u) return -EINVAL;
    if (eng->pdr_down) return -ENETRESET;
    m11_gpr_slot_t *slot = find_slot(eng, token);
    if (!slot || !slot->orphaned) return -ENOENT;
    if (!eng->is_open || eng->held_fd < 0) return -EBADF;

    if (!slot->completed) {
        int wrc = wait_slot_deadline(eng, slot, timeout_ms);
        if (wrc < 0) {
            if (eng->pdr_down) {
                eng->orphans_lost++;
                memset(slot, 0, sizeof(*slot));
                return -ENETRESET;
            }
            return wrc; /* orphan and its token stay reserved */
        }
    }
    if (out_rsp_payload && rsp_cap < slot->rsp_payload_len && slot->dsp_status == 0u) {
        return -ENOSPC; /* not consumed; caller may retry with a larger buffer */
    }
    return consume_slot_result(slot, out_dsp_status, out_rsp_opcode,
                               out_rsp_payload, rsp_cap, out_rsp_len);
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
