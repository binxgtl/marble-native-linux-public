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

typedef struct {
    const m11_pid1_anchor *anchor;   /* PID1's endpoint anchor; never owned by this link */
    uint32_t opens, detaches, refused_io, writes, reads, timeouts;
} m11_gpr_native_link;

/* Bind a link to an anchor and fill the engine transport (user = link). -EINVAL on NULLs. */
int m11_gpr_native_transport(m11_gpr_native_link *link, const m11_pid1_anchor *anchor,
                             m11_gpr_transport_t *out);

#endif
