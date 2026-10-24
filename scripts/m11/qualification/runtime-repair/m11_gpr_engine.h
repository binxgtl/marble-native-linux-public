#ifndef M11_RUNTIME_REPAIR_GPR_ENGINE_H
#define M11_RUNTIME_REPAIR_GPR_ENGINE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Runtime hardening API marker (P1 deadline wait, P2 orphan tracking, P3 per-channel
 * report, P4 local-release retry, P5 bracket closure, P6 ack-without-data).
 * Regression tests use it to compile the new-API portions only on hardened trees.
 */
#define M11_RUNTIME_HARDENING_API_VERSION 1

/* GPR Domain IDs (include/linux/soc/qcom/apr.h / gpr_ids_domains.h) */
#define M11_GPR_DOMAIN_MODEM 1u
#define M11_GPR_DOMAIN_ADSP  2u
#define M11_GPR_DOMAIN_APPS  3u

/* Kernel client_data flag for GSL_SHMEM_MAP_OFFSET_MODE (audio_pkt_dlkm.ko) */
#define M11_GPR_CLIENT_DATA_DEFAULT           0u
#define M11_GPR_CLIENT_DATA_SHMEM_OFFSET_MODE 1u

/* Static kernel GPR service ports reserved in spf_core_dlkm.ko / audio_pkt_dlkm.ko */
#define M11_GPR_KERNEL_RESERVED_PORT_SPF_CORE  0x0003u
#define M11_GPR_KERNEL_RESERVED_PORT_AUDIO_PKT 0x0017u
#define M11_GPR_MAX_VALID_DYNAMIC_SRC_PORT     0x7FFFu

/* Well-known SPF / APM / PRM Module Instance IDs */
#define M11_APM_MODULE_IID 0x00000001u
#define M11_PRM_MODULE_IID 0x02001006u

/* APM / GPR Command & Response Opcodes (apm_api.h / gpr_api_inline.h) */
#define M11_APM_CMD_GRAPH_OPEN               0x01001000u
#define M11_APM_CMD_GRAPH_PREPARE            0x01001001u
#define M11_APM_CMD_GRAPH_START              0x01001002u
#define M11_APM_CMD_GRAPH_STOP               0x01001003u
#define M11_APM_CMD_GRAPH_CLOSE              0x01001004u
#define M11_APM_CMD_SET_CFG                  0x01001006u
#define M11_APM_CMD_GET_CFG                  0x01001007u
#define M11_APM_CMD_SHARED_MEM_MAP_REGIONS   0x0100100Cu
#define M11_APM_CMD_SHARED_MEM_UNMAP_REGIONS 0x0100100Du
#define M11_APM_CMD_CLOSE_ALL                0x01001013u
#define M11_APM_CMD_GET_SPF_STATE            0x01001021u

#define M11_APM_CMD_RSP_GET_CFG               0x02001000u
#define M11_APM_CMDRSP_SHARED_MEM_MAP_REGIONS 0x02001001u
#define M11_GPR_IBASIC_RSP_RESULT             0x02001005u
#define M11_APM_CMD_RSP_GET_SPF_STATE         0x02001007u

/* Shared-memory end point data commands (wr_sh_mem_ep_api.h / rd_sh_mem_ep_api.h, P5 speaker session).
 * They go to the end point's module instance, not to APM; each completes on its own response opcode. */
#define M11_DATA_CMD_WR_SH_MEM_EP_DATA_BUFFER_V2           0x0400100Au
#define M11_DATA_CMD_WR_SH_MEM_EP_EOS                      0x04001002u
#define M11_DATA_CMD_RD_SH_MEM_EP_DATA_BUFFER_V2           0x0400100Bu
#define M11_DATA_CMD_RSP_WR_SH_MEM_EP_DATA_BUFFER_DONE_V2  0x05001004u /* 32 B, status at +12 */
#define M11_DATA_CMD_RSP_WR_SH_MEM_EP_EOS_RENDERED         0x05001001u /* 8 B, render status at +4: 1 rendered
                                                                         * (completes), 2 dropped, else invalid */
#define M11_DATA_CMD_RSP_RD_SH_MEM_EP_DATA_BUFFER_DONE_V2  0x05001005u /* 56 B, status at +0 */

#define M11_GPR_HDR_VERSION   0u
#define M11_GPR_HDR_DWORDS    6u
#define M11_GPR_HDR_BYTES     24u
#define M11_GPR_MAX_PKT_BYTES 4096u
#define M11_GPR_MAX_PENDING   16u

/*
 * Canonical 24-byte GPR v0 packet header (little-endian wire format).
 * Independently verified against:
 *   - include/linux/soc/qcom/apr.h (struct gpr_hdr)
 *   - gpr_api.h (struct gpr_pkt_t)
 *   - gpr_dlkm.ko (__gpr_send_pkt @ 0x1013a8, gpr_Allowed_send_pkt @ 0x100258)
 *   - audio_pkt_dlkm.ko (audpkt_chk_and_update_physical_addr @ 0x1001f4)
 *   - libar-gpr.so (gpr_init_Lock_and_send_pkt @ 0x10474)
 *   - scripts/m11/runtime/gpr_packet.py
 */
typedef struct __attribute__((packed)) {
    uint32_t header;        /* +0x00: [3:0]=ver(0), [7:4]=hdr_size_dwords(6), [31:8]=pkt_size_bytes */
    uint8_t  dst_domain_id; /* +0x04: destination domain ID (2 = ADSP, 3 = APPS) */
    uint8_t  src_domain_id; /* +0x05: source domain ID (3 = APPS, 2 = ADSP) */
    uint8_t  client_data;   /* +0x06: client data (1 = OFFSET_MODE shmem map intercept) */
    uint8_t  reserved;      /* +0x07: must be 0 */
    uint32_t src_port;      /* +0x08: source service/module instance port */
    uint32_t dst_port;      /* +0x0c: destination service/module instance port */
    uint32_t token;         /* +0x10: transaction correlation token */
    uint32_t opcode;        /* +0x14: command/response/event opcode */
} m11_gpr_hdr_t;

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(m11_gpr_hdr_t) == 24u, "m11_gpr_hdr_t must be 24 bytes");
_Static_assert(offsetof(m11_gpr_hdr_t, header) == 0x00u, "header must be at +0x00");
_Static_assert(offsetof(m11_gpr_hdr_t, dst_domain_id) == 0x04u, "dst_domain_id must be at +0x04");
_Static_assert(offsetof(m11_gpr_hdr_t, src_domain_id) == 0x05u, "src_domain_id must be at +0x05");
_Static_assert(offsetof(m11_gpr_hdr_t, client_data) == 0x06u, "client_data must be at +0x06");
_Static_assert(offsetof(m11_gpr_hdr_t, reserved) == 0x07u, "reserved must be at +0x07");
_Static_assert(offsetof(m11_gpr_hdr_t, src_port) == 0x08u, "src_port must be at +0x08");
_Static_assert(offsetof(m11_gpr_hdr_t, dst_port) == 0x0Cu, "dst_port must be at +0x0C");
_Static_assert(offsetof(m11_gpr_hdr_t, token) == 0x10u, "token must be at +0x10");
_Static_assert(offsetof(m11_gpr_hdr_t, opcode) == 0x14u, "opcode must be at +0x14");
#endif

typedef struct __attribute__((packed)) {
    uint32_t cmd_opcode;
    uint32_t status;
} m11_gpr_ibasic_rsp_t;

typedef struct __attribute__((packed)) {
    uint32_t status; /* 1 = SPF ready, 0 = not ready */
} m11_apm_rsp_get_spf_state_t;

typedef struct __attribute__((packed)) {
    uint32_t mem_map_handle;
} m11_apm_rsp_shared_mem_map_t;

typedef struct __attribute__((packed)) {
    uint32_t status;
} m11_apm_rsp_get_cfg_t;

/* Pluggable transport backend (mockable for offline testing) */
typedef struct {
    int  (*open_fn)(void *user);
    int  (*close_fn)(void *user, int fd);
    int  (*write_fn)(void *user, int fd, const uint8_t *buf, size_t len);
    int  (*poll_read_fn)(void *user, int fd, uint8_t *buf, size_t cap, uint32_t timeout_ms);
    void *user;
} m11_gpr_transport_t;

typedef void (*m11_gpr_event_cb_t)(void *cb_user, const m11_gpr_hdr_t *hdr,
                                   const uint8_t *payload, size_t payload_len);

typedef struct {
    bool     in_use;
    uint32_t token;
    uint32_t dst_port;
    uint32_t req_opcode;
    uint32_t expected_rsp_opcode;
    bool     completed;
    uint32_t rsp_opcode;
    uint32_t dsp_status;
    uint8_t  rsp_payload[M11_GPR_MAX_PKT_BYTES - M11_GPR_HDR_BYTES];
    size_t   rsp_payload_len;
    /*
     * Ownership-bearing requests (SHARED_MEM_MAP/UNMAP_REGIONS) keep their slot, and
     * therefore their token, reserved after a wait failure so a late response can still
     * be correlated. A reserved slot is "orphaned" until m11_gpr_engine_orphan_poll()
     * consumes the response or the engine is closed/PDR-latched.
     */
    bool     retain_on_timeout;
    bool     orphaned;
    /*
     * IBASIC_RSP_RESULT status 0 arrived for a request whose success response carries
     * data (GET_CFG, GET_SPF_STATE, MAP_REGIONS). The command was acknowledged but the
     * required data response is still outstanding; this is NOT a completed transaction.
     */
    bool     ack_without_data;
} m11_gpr_slot_t;

/*
 * Explicit TX disposition for m11_gpr_engine_submit_ex:
 * Stock audio_pkt_write (0x0010170c in audio_pkt_dlkm.ko) only checks
 * count >= (hdr.header >> 8) before calling gpr_send_pkt -> rpmsg_trysend,
 * and can return negative errnos both before and inside gpr_send_pkt.
 * Therefore, ONLY M11_GPR_TX_NOT_ATTEMPTED (failed in userspace before
 * transport.write_fn was invoked) proves that no packet reached the kernel/wire.
 * Any write_fn error (< 0) or short write (!= pkt_len) leaves remote state UNKNOWN.
 */
typedef enum {
    M11_GPR_TX_NONE = 0,
    M11_GPR_TX_NOT_ATTEMPTED = 1, /* Failed in userspace before write_fn was called */
    M11_GPR_TX_WRITE_ERROR = 2,   /* write_fn returned < 0; remote wire/DSP state UNKNOWN */
    M11_GPR_TX_SHORT_WRITE = 3,   /* write_fn returned != pkt_len; remote wire/DSP state UNKNOWN */
    M11_GPR_TX_SENT = 4,          /* Full packet accepted by write_fn */
} m11_gpr_tx_status_t;

/*
 * Explicit RX disposition for m11_gpr_engine_pump_once:
 * Distinguishes fatal transport/fd errors (poll_read_fn < 0, timeout, closed fd, PDR)
 * from droppable wire packets (malformed header, wrong peer, stale/unknown token)
 * so m11_gpr_engine_wait_token never masks transport errors behind -ETIMEDOUT.
 */
typedef enum {
    M11_GPR_RX_OK = 0,
    M11_GPR_RX_DROPPED_PACKET = 1, /* Packet read (rrc > 0) but malformed/stale/unmatched */
    M11_GPR_RX_TRANSPORT_ERR = 2,  /* Engine state error, timeout, or poll_read_fn < 0 */
} m11_gpr_rx_status_t;

/* Monotonic millisecond clock (injectable for deterministic tests). */
typedef uint64_t (*m11_gpr_clock_ms_fn)(void *user);

typedef struct {
    m11_gpr_transport_t transport;
    int                 held_fd;
    bool                is_open;
    bool                pdr_down; /* permanently latched on -ENETRESET (102) */
    uint32_t            open_count;
    uint32_t            close_count;
    uint32_t            src_port;
    uint32_t            next_token;
    bool                token_space_exhausted; /* never wrap into a retired token in this session */
    m11_gpr_tx_status_t last_tx_status;
    m11_gpr_rx_status_t last_rx_status;
    uint32_t            rx_dropped_unknown_token;
    uint32_t            rx_dropped_malformed;
    uint32_t            rx_unsolicited_events;
    m11_gpr_event_cb_t  event_cb;
    void               *event_cb_user;
    m11_gpr_clock_ms_fn clock_fn;      /* NULL = CLOCK_MONOTONIC */
    void               *clock_user;
    uint32_t            rx_ibasic_ack_without_data;
    uint32_t            orphans_lost;  /* orphaned slots discarded by close or PDR */
    m11_gpr_slot_t      slots[M11_GPR_MAX_PENDING];
} m11_gpr_engine_t;

bool     m11_gpr_is_valid_src_port(uint32_t src_port);
uint32_t m11_gpr_make_header_word(uint32_t version, uint32_t hdr_dwords, uint32_t pkt_bytes);
void     m11_gpr_unpack_header_word(uint32_t word, uint32_t *version,
                                    uint32_t *hdr_dwords, uint32_t *pkt_bytes);

int m11_gpr_pack_packet_ex(uint8_t *out_buf, size_t out_cap, size_t *out_len,
                           uint8_t dst_domain_id, uint8_t src_domain_id,
                           uint8_t client_data,
                           uint32_t dst_port, uint32_t src_port,
                           uint32_t token, uint32_t opcode,
                           const void *payload, size_t payload_len);

int m11_gpr_pack_packet(uint8_t *out_buf, size_t out_cap, size_t *out_len,
                        uint32_t dst_port, uint32_t src_port,
                        uint32_t token, uint32_t opcode,
                        const void *payload, size_t payload_len);

int m11_gpr_validate_packet(const uint8_t *buf, size_t len,
                            m11_gpr_hdr_t *out_hdr,
                            const uint8_t **out_payload, size_t *out_payload_len);

int  m11_gpr_engine_init(m11_gpr_engine_t *eng, const m11_gpr_transport_t *transport,
                         uint32_t src_port);
void m11_gpr_engine_set_event_cb(m11_gpr_engine_t *eng, m11_gpr_event_cb_t cb, void *user);
int  m11_gpr_engine_open(m11_gpr_engine_t *eng);
int  m11_gpr_engine_close(m11_gpr_engine_t *eng);

/* Default CLOCK_MONOTONIC clock in milliseconds; usable as m11_gpr_clock_ms_fn. */
uint64_t m11_gpr_monotonic_ms(void *unused);
void     m11_gpr_engine_set_clock(m11_gpr_engine_t *eng, m11_gpr_clock_ms_fn fn, void *user);

/* True for requests whose timed-out transaction may have changed remote ownership. */
bool m11_gpr_opcode_retains_on_timeout(uint32_t opcode);

/*
 * Orphan tracking. An orphan is an ownership-bearing request whose wait ended without a
 * usable response (timeout or transport error, not PDR and not an explicit NACK).
 *   m11_gpr_engine_orphan_tracked: token is still reserved and a late response is accepted.
 *   m11_gpr_engine_orphan_poll:    wait up to timeout_ms for that late response.
 *     -ENOENT    no such orphan (never tracked, already consumed, or lost to close/PDR)
 *     -ETIMEDOUT still outstanding; the orphan stays tracked and its token stays reserved
 *     -ENETRESET engine is PDR-latched; orphan correlation can never resolve
 *     0          response consumed (out_rsp_opcode / payload filled)
 *     -EREMOTEIO response consumed and it was an explicit DSP NACK
 *     other <0   transport errno, orphan stays tracked
 */
bool     m11_gpr_engine_orphan_tracked(const m11_gpr_engine_t *eng, uint32_t token);
uint32_t m11_gpr_engine_orphan_count(const m11_gpr_engine_t *eng);
int m11_gpr_engine_orphan_poll(m11_gpr_engine_t *eng, uint32_t token, uint32_t timeout_ms,
                               uint32_t *out_dsp_status, uint32_t *out_rsp_opcode,
                               void *out_rsp_payload, size_t rsp_cap, size_t *out_rsp_len);

/* Async submit + pump + wait APIs (enables out-of-order response and client_data testing) */
/*
 * submit_ex: *out_token is zeroed on entry and set to the transaction token as soon as a
 * packet was handed to write_fn, including when write_fn then failed. Callers need that
 * token to correlate a late response for ownership-bearing requests.
 */
int m11_gpr_engine_submit_ex(m11_gpr_engine_t *eng, uint8_t client_data,
                             uint32_t dst_port, uint32_t opcode,
                             const void *payload, size_t payload_len, uint32_t *out_token);
int m11_gpr_engine_submit(m11_gpr_engine_t *eng, uint32_t dst_port, uint32_t opcode,
                          const void *payload, size_t payload_len, uint32_t *out_token);
int m11_gpr_engine_pump_once(m11_gpr_engine_t *eng, uint32_t timeout_ms);
/*
 * wait_token: timeout_ms is ONE absolute CLOCK_MONOTONIC deadline for the whole
 * transaction, not a per-poll value. Each poll_read_fn call receives only the time that
 * is left. poll_read_fn must block up to that time before returning 0 (returning 0 is
 * reported as -ETIMEDOUT). Unsolicited events and dropped (stale/malformed/wrong-peer)
 * packets never fail a transaction that is still inside its deadline, and they cannot
 * extend it. Transport errors are returned with their exact errno.
 */
int m11_gpr_engine_wait_token(m11_gpr_engine_t *eng, uint32_t token, uint32_t timeout_ms,
                              uint32_t *out_dsp_status,
                              void *out_rsp_payload, size_t rsp_cap, size_t *out_rsp_len);

/* Synchronous round-trip helpers */
int m11_gpr_engine_transact_ex(m11_gpr_engine_t *eng, uint8_t client_data,
                               uint32_t dst_port, uint32_t opcode,
                               const void *payload, size_t payload_len, uint32_t timeout_ms,
                               uint32_t *out_dsp_status,
                               void *out_rsp_payload, size_t rsp_cap, size_t *out_rsp_len);
/* Observation only: status_valid means a matched completed response was consumed.
 * False for admission/TX/timeout/PD errors, even when their errno is EREMOTEIO.
 * A true zero status does not establish DSP quiescence or physical USB delivery. */
int m11_gpr_engine_transact_observed(m11_gpr_engine_t *, uint32_t dst_port, uint32_t opcode,
                                     const void *, size_t, uint32_t timeout_ms,
                                     uint32_t *dsp_status, bool *status_valid,
                                     void *rsp, size_t cap, size_t *rsp_len);
int m11_gpr_engine_transact(m11_gpr_engine_t *eng, uint32_t dst_port, uint32_t opcode,
                            const void *payload, size_t payload_len, uint32_t timeout_ms,
                            uint32_t *out_dsp_status,
                            void *out_rsp_payload, size_t rsp_cap, size_t *out_rsp_len);

/* High-level APM SPF state readiness probe (0x01001021 -> 0x02001007) */
int m11_gpr_query_spf_state(m11_gpr_engine_t *eng, uint32_t timeout_ms, uint32_t *out_spf_state);

#ifdef __cplusplus
}
#endif

#endif /* M11_RUNTIME_REPAIR_GPR_ENGINE_H */
