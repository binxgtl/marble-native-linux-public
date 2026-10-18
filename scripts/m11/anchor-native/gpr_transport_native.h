/* G2 (docs/m11-custodian-native-integration.md): the native GPR transport for the custodian's
 * engine (qualification/runtime-repair/m11_gpr_engine.h), carried over PID1's endpoint anchor.
 * Built only in the reviewed M11_CUSTODIAN_NATIVE build.
 *
 * Rules:
 *  - open_fn opens nothing: it returns the anchor's fd, and only while the anchor is HELD by the
 *    calling process (the engine itself refuses a second open);
 *  - write_fn / poll_read_fn re-check that on EVERY call: a LENT anchor (a worker shares the open
 *    file description) or a released / retained / failed one refuses I/O with -EBADF;
 *  - write_fn is one write(2) (retried only on EINTR, which transfers nothing); its byte count goes
 *    to the engine unchanged, so a short write or an error leaves remote state UNKNOWN as the
 *    engine already classifies it;
 *  - poll_read_fn blocks at most the remaining time and returns 0 on timeout; a read of one packet
 *    returns its length; EOF and poll error conditions are transport errors, never a timeout;
 *  - close_fn NEVER closes: it only detaches the engine. The endpoint's single release stays the
 *    anchor's own final close (m11_anchor_final_close), which the boot's terminal decision governs.
 */
#ifndef M11_GPR_TRANSPORT_NATIVE_H
#define M11_GPR_TRANSPORT_NATIVE_H
#ifndef M11_CUSTODIAN_NATIVE
#error "gpr_transport_native requires the reviewed M11_CUSTODIAN_NATIVE build"
#endif
#include "../qualification/runtime-repair/m11_gpr_engine.h"
#include "../qualification/ownership/m11_pid1_anchor.h"
#include <stdint.h>

/* G6: the PD (PDR) monitor every blocking wait pumps. `fd` is readable when PD traffic is pending
 * (the QRTR socket in production); pump_fn is non-blocking and returns 1 while the audio PD is UP,
 * anything else once it is not (DOWN, peer lost, invalid, error): terminal for the boot. */
typedef struct {
    int fd;
    int (*pump_fn)(void *user, uint64_t now_ms);
    void *user;
} m11_pd_monitor;

typedef struct {
    const m11_pid1_anchor *anchor;   /* PID1's endpoint anchor; never owned by this link */
    uint32_t opens, detaches, refused_io, writes, reads, timeouts;
    const m11_pd_monitor *pd;        /* G6: NULL = no monitor (G2 behaviour) */
    int pd_down;                     /* latched for the boot once the monitor is not UP */
    uint32_t pd_pumps, pd_downs;
} m11_gpr_native_link;

/* Bind a link to an anchor and fill the engine transport (user = link). -EINVAL on NULLs. */
int m11_gpr_native_transport(m11_gpr_native_link *link, const m11_pid1_anchor *anchor,
                             m11_gpr_transport_t *out);
/* G6: as above, with a PD monitor. Then: open, write and poll_read pump the monitor first and
 * return -ENETRESET once it is not UP (the engine latches pdr_down on it); a write after DOWN never
 * reaches write(2); a wait polls the endpoint AND the monitor, and a DOWN (or a monitor hangup)
 * ends it at once with -ENETRESET, before any endpoint data pending at the same time. */
int m11_gpr_native_transport_pd(m11_gpr_native_link *link, const m11_pid1_anchor *anchor,
                                const m11_pd_monitor *pd, m11_gpr_transport_t *out);
/* G6: pump the monitor once (non-blocking). 0 while UP, -ENETRESET once DOWN (latched). */
int m11_gpr_native_pd_pump(m11_gpr_native_link *link);

#endif
