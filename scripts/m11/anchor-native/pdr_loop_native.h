/* G6 (docs/m11-custodian-native-integration.md): the PDR side of the custodian's single-threaded
 * event loop. Built only in the reviewed M11_CUSTODIAN_NATIVE build; never part of a candidate.
 *
 * Rules:
 *  - every blocking wait pumps the PD monitor: transaction waits through the G6 transport
 *    (gpr_transport_native.h), idle waits through m11_pdr_loop_idle, which blocks on the monitor
 *    alone and never on the endpoint;
 *  - a PD that is not UP (DOWN, peer lost, invalid, monitor hangup) latches for the boot. The
 *    transport then refuses every TX and ends every wait with -ENETRESET, so the engine latches
 *    pdr_down and the region manager takes its PDR path (an in-flight MAP or UNMAP becomes
 *    OWNERSHIP_UNRESOLVED with the PDR blocker; nothing is freed);
 *  - m11_pdr_loop_settle, called after EVERY custodian call and by the idle wait, reports the DOWN to
 *    the custodian exactly once (m11_custodian_pd_down: PD_DOWN taint, kernel imports lost), which
 *    makes RESET_RETAINING_ANCHORS the boot's only end. PD DOWN is not ADSP DMA quiescence: nothing
 *    is unmapped, freed or closed here, and there is no reconnect.
 */
#ifndef M11_PDR_LOOP_NATIVE_H
#define M11_PDR_LOOP_NATIVE_H
#ifndef M11_CUSTODIAN_NATIVE
#error "pdr_loop_native requires the reviewed M11_CUSTODIAN_NATIVE build"
#endif
#include "gpr_transport_native.h"
#include "../qualification/ownership/m11_custodian.h"

typedef struct {
    m11_custodian *c;
    m11_gpr_native_link *link;
    int down_reported;
    uint32_t idle_waits;
} m11_pdr_loop;

/* The link must carry a PD monitor and the custodian's engine must be the one on that link's
 * transport (the caller wires both). -EINVAL otherwise. */
int m11_pdr_loop_init(m11_pdr_loop *, m11_custodian *, m11_gpr_native_link *);
/* Report a latched DOWN (transport or engine) to the custodian once; returns the terminal action. */
m11_terminal_action m11_pdr_loop_settle(m11_pdr_loop *, uint64_t now_ms);
/* Idle wait of up to budget_ms on the monitor only, pumping it on traffic; then settle.
 * 0 while UP, -ENETRESET once DOWN, other negative errno on a poll error (also settled). */
int m11_pdr_loop_idle(m11_pdr_loop *, uint32_t budget_ms, uint64_t now_ms);

#endif
