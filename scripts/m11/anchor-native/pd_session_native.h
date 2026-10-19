/* Production P1 (docs/m11-custodian-native-integration.md): a long-session SERVREG v1 listener for
 * the audio PD, and its QRTR adapter as the G6 PD monitor. Built only in the reviewed
 * M11_CUSTODIAN_NATIVE build; never part of a candidate.
 *
 * Why not the frozen codec (runtime/audio_pd.c): it serves a one-query boot. It has a whole-session
 * deadline (at most 10 s), a 96-record transcript that overflows into INVALID, transaction ids that
 * stop at 65535, and it drops to WAIT_UP while acknowledging any indication, so an UP re-indication
 * would read as "not UP" to the G6 transport (a false DOWN). The custodian needs the PD watched for
 * as long as it runs.
 *
 * Same wire rules as the frozen codec (pinned stock instance 74, path msm/adsp/audio_pd, service
 * 0x42, QMI layout and strict TLV parsing). Session rules:
 *  - DISCOVERY -> REGISTERING -> WAIT_UP -> READY, all bounded by ready_budget (<= 10 s); a
 *    registration or an ACK unanswered for 2 s is a fault;
 *  - once READY there is no session deadline; READY persists while an UP indication is
 *    acknowledged; any indication other than UP, a DEL_SERVER for the service, a BYE or DEL_CLIENT
 *    naming the peer, any other unknown control message, a malformed or foreign datagram, a clock
 *    going backwards, or a send error ends the session (terminal: never UP again, no reconnect);
 *    RESUME_TX and DEL_CLIENT/BYE for other endpoints are ignored;
 *  - a non-UP indication is acknowledged at once unless resources are busy (the custodian may have
 *    mapped memory): then the ACK is deferred until m11_pds_resources_released, as the frozen codec
 *    does, so the PD's restart is not acknowledged while the ADSP may still reach our pages;
 *  - transaction ids wrap 65535 -> 1 (never 0, never the outstanding one).
 * Times are milliseconds on CLOCK_MONOTONIC.
 */
#ifndef M11_PD_SESSION_NATIVE_H
#define M11_PD_SESSION_NATIVE_H
#ifndef M11_CUSTODIAN_NATIVE
#error "pd_session_native requires the reviewed M11_CUSTODIAN_NATIVE build"
#endif
#include "gpr_transport_native.h"
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define M11_PDS_CTRL_PORT 0xfffffffeu
#define M11_PDS_SERVICE 0x42u
#define M11_PDS_INSTANCE ((74u << 8) | 1u)
#define M11_PDS_PATH "msm/adsp/audio_pd"
#define M11_PDS_UP 0x1fffffffu
#define M11_PDS_DOWN 0x0fffffffu
#define M11_PDS_WIRE_MAX 128u
#define M11_PDS_TXN_TIMEOUT_MS 2000u

typedef enum { M11_PDS_DISCOVERY, M11_PDS_REGISTERING, M11_PDS_WAIT_UP, M11_PDS_READY, M11_PDS_ENDED,
               M11_PDS_STOPPING, M11_PDS_STOPPED } m11_pds_phase;
typedef enum { M11_PDS_OK, M11_PDS_MALFORMED, M11_PDS_PEER_LOST, M11_PDS_NOT_UP, M11_PDS_DEADLINE,
               M11_PDS_IO, M11_PDS_CLOCK } m11_pds_fault;

typedef struct {
    m11_pds_phase phase;
    m11_pds_fault fault;
    uint32_t local_node, local_port, node, port, state;
    uint16_t next_txn, register_txn, ack_txn, indication_txn;
    uint32_t indication_state;
    int peer, registered, ever_ready, ack_deferred, resources_busy, unregister_sent, unregister_ok;
    uint64_t now, ready_deadline, register_deadline, ack_deadline;
    uint32_t rx, tx, indications;
    int (*send)(void *ctx, uint32_t node, uint32_t port, const void *b, size_t n);
    void *ctx;
} m11_pds;

/* Starts discovery (NEW_LOOKUP). 0, or -1 with the session ended. */
int m11_pds_begin(m11_pds *, uint32_t local_node, uint32_t local_port, uint64_t now_ms, uint32_t ready_budget_ms,
                  int (*send)(void *, uint32_t, uint32_t, const void *, size_t), void *ctx);
int m11_pds_receive(m11_pds *, uint32_t node, uint32_t port, const void *data, size_t n, uint64_t now_ms);
int m11_pds_tick(m11_pds *, uint64_t now_ms);
static inline int m11_pds_up(const m11_pds *s) { return s->phase == M11_PDS_READY; }
void m11_pds_resources_busy(m11_pds *);
int m11_pds_resources_released(m11_pds *);
/* B5 retire, as the frozen codec's stop: only from READY with nothing busy, outstanding or deferred
 * (else -1, session unchanged). Sends the withdrawal (registration, enable = 0); on its response
 * sends DEL_LOOKUP and reaches STOPPED. Any other datagram while STOPPING ends the session (a failed
 * stop). 1 while stopping, 0 once STOPPED. */
int m11_pds_stop(m11_pds *, uint64_t now_ms);

/* ---- the QRTR adapter: the G6 PD monitor ---- */
typedef struct {
    int (*socket_fn)(void *u);                                         /* fd, or -errno */
    int (*getsockname_fn)(void *u, int fd, uint32_t *node, uint32_t *port);
    int (*sendto_fn)(void *u, int fd, uint32_t node, uint32_t port, const void *b, size_t n); /* 0 = whole */
    ssize_t (*recvfrom_fn)(void *u, int fd, void *b, size_t cap, uint32_t *node, uint32_t *port); /* -EAGAIN: empty */
    int (*close_fn)(void *u, int fd);
    void *u;
} m11_qrtr_sys;
extern const m11_qrtr_sys m11_qrtr_libc; /* AF_QIPCRTR datagrams, MSG_DONTWAIT only */

typedef struct {
    int fd;
    const m11_qrtr_sys *sys;
    m11_pds pds;
    m11_pd_monitor monitor;  /* fd + pump for m11_gpr_native_transport_pd / m11_pdr_loop */
    uint32_t datagrams;
} m11_pdmon;

/* Open the socket, read its own node/port, start discovery. 0 or -errno (nothing left open). */
int m11_pdmon_open(m11_pdmon *, const m11_qrtr_sys *sys, uint64_t now_ms, uint32_t ready_budget_ms);
/* Pump until READY or the session ends (bounded by budget). 0 when UP, -ENETRESET otherwise. */
int m11_pdmon_wait_up(m11_pdmon *, uint32_t budget_ms);
/* The monitor's pump: drain every pending datagram into the session, tick, report UP (1) or not (0). */
int m11_pdmon_pump(void *user, uint64_t now_ms);
/* B5: withdraw the listener before the ADSP is stopped (Run23 retired its listener there): stop,
 * pump until STOPPED within budget_ms (1..2000), then close the socket. 0 when stopped and closed;
 * -EBUSY when the stop is refused (socket left open); -ETIMEDOUT/-EIO otherwise (socket closed). */
int m11_pdmon_retire(m11_pdmon *, uint32_t budget_ms);

#endif
