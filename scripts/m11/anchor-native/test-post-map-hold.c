/* CP2 criterion 5, post-MAP hold (docs/m11-argon-cp2-c5-hold-design.md): layer tests of the REAL custodian (L1)
 * and region manager (L3) against the strict mock. Offline only (M11_OWNERSHIP_OFFLINE); mock ground truth, no
 * firmware claim. Each section tests one proof obligation; test.sh mutants name the assertion that must fail.
 *   P1 never-mapped behaviour unchanged
 *   T1/T2 retire and close refused after a MAP intent (no UNMAP on the wire, nothing released)
 *   T3 every mapped state ends retaining (never HOLD, HOLD_RECONCILE or ORDERLY)
 *   T5 every post-TX MAP failure keeps backing and ownership (NACK, write error, delivered-then-error, short
 *      write, lost response, response without a handle, transport/PDR error)
 *   T6 a late MAP NACK through reconcile is held
 *   T7 the UNMAP research path (driven directly, no journal in this rig) never releases a transmitted region
 *   T8 a pre-TX failure releases, and only with proof that write_fn was never entered (alloc, import; submit
 *      refused with the engine closed, PDR latched, token space exhausted or no slot)
 *   T3b PD down while held is recorded as unknown through the region manager, with no UNMAP and no release */
#ifndef M11_OWNERSHIP_OFFLINE
#error "test-post-map-hold.c builds only in the offline qualification mode"
#endif
#include "m11_custodian.h"
#include "m11_strict_mock.h"
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

static m11_strict_mock_t mock;
static m11_gpr_engine_t eng;
static m11_shmem_mgr_t mgr;
static m11_boot_ledger boot;
static m11_custodian c;
static uint64_t now;

static void fixture(void) {
    m11_gpr_transport_t tp; m11_shmem_backend_t be;
    memset(&boot, 0, sizeof boot); memset(&c, 0, sizeof c);
    m11_strict_mock_init(&mock); m11_strict_mock_bind(&mock, &tp, &be);
    assert(!m11_gpr_engine_init(&eng, &tp, 0x2002u) && !m11_gpr_engine_open(&eng));
    assert(!m11_shmem_mgr_init(&mgr, &be, &eng, 10));
    now = 100;
    assert(!m11_model_new_boot(&boot, 17, now));
    m11_custodian_model_contract ct = {.exclusive_importer = true, .no_other_endpoint = true, .no_pcm_clients = true,
        .strict_iommu = true, .graph_quiescent = true, .nack_atomicity_model = true, .final_anchor_pid1 = true};
    assert(!m11_custodian_init(&c, &boot, &mgr, &ct, 1000));
}
/* the region still owns every local handle */
static int held(const m11_shmem_region_t *r) {
    return r->dma_buf_fd >= 0 && r->vaddr != NULL && r->ion_imported &&
           r->state != M11_SHMEM_STATE_RELEASED && r->state != M11_SHMEM_STATE_NOT_ALLOCATED;
}
/* mock ground truth: a buffer is still allocated, CPU-mapped and ION-imported */
static int mock_held(void) {
    for (unsigned k = 0; k < M11_MOCK_MAX_SHM_SLOTS; k++)
        if (mock.shm_slots[k].allocated && mock.shm_slots[k].mmap_active && mock.shm_slots[k].ion_imported) return 1;
    return 0;
}
static int final_action(m11_terminal_action a) {
    return a == M11_TERMINAL_RESET_RETAINING_ANCHORS || a == M11_TERMINAL_UNSAFE_LAST_CLOSE_OCCURRED;
}

static void post_tx_case(int kind) {
    fixture(); unsigned s = UINT_MAX;
    switch (kind) {
    case 0: mock.nack_shmem_map = true; break;
    case 1: mock.fail_gpr_write_on_map = true; break;
    case 2: mock.deliver_then_fail_write_on_map = true; break;
    case 3: mock.short_gpr_write_on_map = true; break;
    case 4: mock.drop_shmem_map_rsp = true; break;
    case 5: mock.zero_handle_shmem_map_rsp = true; break;
    default: mock.poll_read_errno = -ENETRESET; break;
    }
    int rc = m11_custodian_map(&c, 4096, ++now, &s);
    mock.poll_read_errno = 0;
    printf("INFO post-TX kind=%d rc=%d slot=%u\n", kind, rc, s);
    assert(rc < 0 && s < M11_CUSTODIAN_REGIONS);
    m11_shmem_region_t *r = &c.regions[s];
    printf("INFO post-TX kind=%d state=%s cause=%s\n", kind, m11_shmem_state_name(r->state), m11_shmem_cause_name(r->cause));
    assert(r->map_tx_started && !r->map_tx_unsent_proof);
    assert(r->state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED && r->cause != M11_SHMEM_CAUSE_NONE);
    assert(c.occupied[s] && held(r) && mock_held() && !mock.unsafe_release_attempts);
    assert(mgr.active_dma_fds == 1 && mgr.active_mmaps == 1 && mgr.active_ion_imports == 1);
    assert(m11_shmem_unmap_and_free(&mgr, r) == -EBUSY && held(r) && mock.unmap_cmd_count == 0);
    if (kind == 0) assert(r->cause == M11_SHMEM_CAUSE_MAP_NACK && r->blocker != NULL);
    assert(m11_custodian_terminal_action(&c) == M11_TERMINAL_RESET_RETAINING_ANCHORS);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    unsigned i = UINT_MAX, s = UINT_MAX;
    m11_shmem_region_t *r;

    /* P1: a never-mapped boot behaves as before rev 5 */
    fixture();
    assert(m11_custodian_retire(&c, 0, ++now) == -EINVAL);
    assert(m11_custodian_terminal_action(&c) == M11_TERMINAL_HOLD && !m11_custodian_reboot_permitted(&c));
    assert(m11_custodian_close(&c) == 0 && m11_custodian_close(&c) == -EALREADY);
    assert(m11_custodian_terminal_action(&c) == M11_TERMINAL_ORDERLY_SHUTDOWN && m11_custodian_reboot_permitted(&c));
    assert(!boot.dsp_map_attempted && mock.tx_pkt_count == 0);
    puts("PASS P1 never-mapped boot unchanged: retire -EINVAL, HOLD while open, one close, then ORDERLY_SHUTDOWN");

    /* T1: retire after a MAP ACK */
    fixture();
    assert(m11_custodian_map(&c, 4096, ++now, &i) == 0 && i < M11_CUSTODIAN_REGIONS);
    assert(c.regions[i].state == M11_SHMEM_STATE_DSP_MAP_ACKNOWLEDGED && c.regions[i].map_tx_started && !c.regions[i].map_tx_unsent_proof);
    uint32_t tx0 = mock.tx_pkt_count, reasons0 = boot.reasons;
    assert(m11_custodian_retire(&c, i, ++now) == -EPERM);
    assert(mock.unmap_cmd_count == 0 && mock.tx_pkt_count == tx0);
    assert(c.occupied[i] && held(&c.regions[i]) && c.regions[i].state == M11_SHMEM_STATE_DSP_MAP_ACKNOWLEDGED && mock_held());
    assert(mgr.active_dma_fds == 1 && mgr.active_mmaps == 1 && mgr.active_ion_imports == 1 && mgr.active_dsp_maps == 1);
    assert(!boot.dsp_unmap_attempted && boot.reasons == reasons0 && !mock.unsafe_release_attempts);
    assert(m11_custodian_retire(&c, i, ++now) == -EPERM && mock.unmap_cmd_count == 0); /* every later retire too */
    puts("PASS T1 retire after a MAP ACK is refused at the custodian: no UNMAP on the wire, nothing released, no taint");

    /* T2: close after a MAP intent (same boot) */
    uint32_t closes0 = eng.close_count;
    assert(m11_custodian_close(&c) == -EPERM);
    assert(eng.is_open && eng.close_count == closes0 && !c.closed && held(&c.regions[i]));
    puts("PASS T2 close after a MAP intent is refused: the endpoint last-close never runs");

    /* T3: every mapped state ends retaining */
    for (int ev = 0; ev < 8; ev++) {
        fixture(); s = UINT_MAX;
        assert(m11_custodian_map(&c, 4096, ++now, &s) == 0);
        switch (ev) {
        case 0: break;                                                     /* clean, region mapped */
        case 1: m11_custodian_worker_exit(&c, ++now); break;               /* tainted, live owner */
        case 2: m11_custodian_pd_down(&c, ++now); break;
        case 3: m11_custodian_global_cleanup(&c, ++now); break;
        case 4: m11_custodian_owner_exit(&c, ++now); break;
        case 5: m11_custodian_supervisor_exit(&c, true, ++now); break;
        case 6: m11_custodian_supervisor_exit(&c, false, ++now); break;    /* UNSAFE_LAST_CLOSE */
        default: m11_custodian_worker_exit(&c, ++now); now += 5000; (void)m11_custodian_tick(&c, now); break;
        }
        m11_terminal_action a = m11_custodian_terminal_action(&c);
        printf("INFO mapped state %d: terminal=%s\n", ev, m11_terminal_action_name(a));
        assert(final_action(a));
        assert(!m11_custodian_reboot_permitted(&c));
        assert(ev == 6 ? a == M11_TERMINAL_UNSAFE_LAST_CLOSE_OCCURRED : a == M11_TERMINAL_RESET_RETAINING_ANCHORS);
        assert(m11_custodian_retire(&c, s, ++now) == -EPERM && m11_custodian_close(&c) == -EPERM);
        assert(c.occupied[s] && held(&c.regions[s]) && mock.unmap_cmd_count == 0);
    }
    puts("PASS T3 every mapped state (clean, worker exit, PD down, global cleanup, owner exit, supervisor exit, deadline) ends retaining; retire and close refused");

    /* T5: every post-TX MAP failure keeps backing and ownership */
    for (int kind = 0; kind < 7; kind++) post_tx_case(kind);
    puts("PASS T5 post-TX MAP failures (NACK, write error, delivered then error, short write, lost response, no handle, PDR) keep backing and ownership");

    /* T6: a late MAP NACK collected through reconcile is held */
    fixture(); s = UINT_MAX;
    mock.hold_next_rsp = true; mock.nack_shmem_map = true;
    assert(m11_custodian_map(&c, 4096, ++now, &s) == -ETIMEDOUT && s < M11_CUSTODIAN_REGIONS);
    mock.nack_shmem_map = false;
    r = &c.regions[s];
    assert(r->state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED && r->orphan_kind == M11_SHMEM_ORPHAN_MAP);
    assert(m11_strict_mock_release_held(&mock) == 1);
    int lrc = m11_shmem_reconcile(&mgr, r, 10);
    printf("INFO late NACK reconcile rc=%d state=%s\n", lrc, m11_shmem_state_name(r->state));
    assert(lrc == -EREMOTEIO);
    assert(r->state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED && r->cause == M11_SHMEM_CAUSE_MAP_NACK && r->blocker != NULL);
    assert(held(r) && mock_held() && !mock.unsafe_release_attempts && mgr.active_ion_imports == 1);
    puts("PASS T6 a late MAP NACK through reconcile is held (OWNERSHIP_UNRESOLVED, cause MAP_NACK)");

    /* T7a: late MAP ACK adopted, then the UNMAP research path driven directly: the ACK never releases */
    fixture(); s = UINT_MAX;
    mock.hold_next_rsp = true;
    assert(m11_custodian_map(&c, 4096, ++now, &s) == -ETIMEDOUT && s < M11_CUSTODIAN_REGIONS);
    assert(m11_strict_mock_release_held(&mock) == 1);
    r = &c.regions[s];
    assert(m11_shmem_reconcile(&mgr, r, 10) == 0 && r->state == M11_SHMEM_STATE_DSP_MAP_ACKNOWLEDGED);
    assert(m11_custodian_retire(&c, s, ++now) == -EPERM && mock.unmap_cmd_count == 0);
    int urc = m11_shmem_unmap_and_free(&mgr, r);
    printf("INFO research UNMAP rc=%d state=%s\n", urc, m11_shmem_state_name(r->state));
    assert(mock.unmap_cmd_count == 1);
    assert(urc == -EPERM && r->state == M11_SHMEM_STATE_DSP_UNMAP_ACKNOWLEDGED && held(r) && mock_held());
    assert(mgr.active_dma_fds == 1 && mgr.active_mmaps == 1 && mgr.active_ion_imports == 1);
    assert(m11_shmem_unmap_and_free(&mgr, r) == -EPERM && held(r) && mock.unmap_cmd_count == 1);
    /* T7b: a late UNMAP ACK through reconcile releases nothing either */
    fixture(); s = UINT_MAX;
    assert(m11_custodian_map(&c, 4096, ++now, &s) == 0);
    r = &c.regions[s]; mock.hold_next_rsp = true;
    assert(m11_shmem_unmap_and_free(&mgr, r) == -ETIMEDOUT && r->state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED);
    assert(m11_strict_mock_release_held(&mock) == 1);
    int rrc = m11_shmem_reconcile(&mgr, r, 10);
    assert(rrc == -EPERM && r->state == M11_SHMEM_STATE_DSP_UNMAP_ACKNOWLEDGED && held(r) && mock_held());
    /* T7c: a (forged) LOCAL_RELEASE_PENDING claim on a transmitted region is refused at the choke point */
    m11_shmem_region_t forged = *r;
    forged.state = M11_SHMEM_STATE_LOCAL_RELEASE_PENDING; forged.remote_inactive = true;
    int frc = m11_shmem_unmap_and_free(&mgr, &forged);
    assert(frc == -EPERM && forged.dma_buf_fd >= 0 && forged.vaddr != NULL && forged.ion_imported && mock_held());
    puts("PASS T7 UNMAP research path (driven directly): ACK, late ACK and LOCAL_RELEASE_PENDING never release a transmitted region");

    /* T8: pre-TX failures release, and only with proof that write_fn was never entered */
    fixture(); s = UINT_MAX;
    mock.fail_dma_alloc = true;
    assert(m11_custodian_map(&c, 4096, ++now, &s) < 0 && s < M11_CUSTODIAN_REGIONS);
    assert(!c.occupied[s] && !c.regions[s].map_tx_started && mgr.active_dma_fds == 0 && mock.tx_pkt_count == 0);
    assert(m11_custodian_terminal_action(&c) == M11_TERMINAL_RESET_RETAINING_ANCHORS); /* the MAP intent was recorded */
    fixture(); s = UINT_MAX;
    mock.fail_ion_import = true;
    assert(m11_custodian_map(&c, 4096, ++now, &s) < 0 && !c.occupied[s] && !c.regions[s].map_tx_started);
    assert(c.regions[s].state == M11_SHMEM_STATE_RELEASED && mgr.active_dma_fds == 0 && mgr.active_mmaps == 0 && !mock_held());
    fixture();
    m11_shmem_region_t pre; memset(&pre, 0, sizeof pre);
    assert(m11_gpr_engine_close(&eng) == 0);
    int prc = m11_shmem_alloc_and_map(&mgr, M11_SHMEM_MODE_DMA_ION_OFFSET, 4096, false, &pre);
    printf("INFO pre-TX submit rc=%d tx_status=%d state=%s\n", prc, (int)eng.last_tx_status, m11_shmem_state_name(pre.state));
    assert(prc < 0 && eng.last_tx_status == M11_GPR_TX_NOT_ATTEMPTED && mock.map_cmd_count == 0);
    assert(pre.map_tx_started && pre.map_tx_unsent_proof && pre.state == M11_SHMEM_STATE_RELEASED);
    assert(mgr.active_dma_fds == 0 && mgr.active_mmaps == 0 && mgr.active_ion_imports == 0 && !mock_held());
    /* T8b: PDR latched before the submit (region manager driven directly: the custodian refuses a MAP on a
     * latched engine before it records any intent) */
    fixture(); memset(&pre, 0, sizeof pre);
    eng.pdr_down = true;
    prc = m11_shmem_alloc_and_map(&mgr, M11_SHMEM_MODE_DMA_ION_OFFSET, 4096, false, &pre);
    printf("INFO pre-TX PDR rc=%d tx_status=%d state=%s\n", prc, (int)eng.last_tx_status, m11_shmem_state_name(pre.state));
    assert(prc == -ENETRESET && eng.last_tx_status == M11_GPR_TX_NOT_ATTEMPTED && mock.map_cmd_count == 0 && mock.tx_pkt_count == 0);
    assert(pre.map_tx_started && pre.map_tx_unsent_proof && pre.state == M11_SHMEM_STATE_RELEASED);
    assert(mgr.active_dma_fds == 0 && mgr.active_mmaps == 0 && mgr.active_ion_imports == 0 && !mock_held());
    assert(m11_shmem_note_pd_down(&mgr, &pre) == -EINVAL && pre.state == M11_SHMEM_STATE_RELEASED); /* never sent */
    /* T8c: token space exhausted, through the custodian (the MAP intent is recorded first) */
    fixture(); s = UINT_MAX;
    eng.token_space_exhausted = true;
    assert(m11_custodian_map(&c, 4096, ++now, &s) == -EOVERFLOW && s < M11_CUSTODIAN_REGIONS);
    assert(eng.last_tx_status == M11_GPR_TX_NOT_ATTEMPTED && mock.map_cmd_count == 0 && mock.tx_pkt_count == 0);
    r = &c.regions[s];
    assert(r->map_tx_started && r->map_tx_unsent_proof && r->state == M11_SHMEM_STATE_RELEASED && !c.occupied[s]);
    assert(mgr.active_dma_fds == 0 && mgr.active_mmaps == 0 && mgr.active_ion_imports == 0 && !mock_held());
    assert(boot.dsp_map_attempted && m11_custodian_terminal_action(&c) == M11_TERMINAL_RESET_RETAINING_ANCHORS);
    /* T8d: every engine slot reserved (region manager driven directly: the custodian refuses while any
     * request is pending) */
    fixture(); memset(&pre, 0, sizeof pre);
    for (unsigned k = 0; k < M11_GPR_MAX_PENDING; k++) eng.slots[k].in_use = true;
    prc = m11_shmem_alloc_and_map(&mgr, M11_SHMEM_MODE_DMA_ION_OFFSET, 4096, false, &pre);
    assert(prc == -ENOSPC && eng.last_tx_status == M11_GPR_TX_NOT_ATTEMPTED && mock.map_cmd_count == 0 && mock.tx_pkt_count == 0);
    assert(pre.map_tx_started && pre.map_tx_unsent_proof && pre.state == M11_SHMEM_STATE_RELEASED);
    assert(mgr.active_dma_fds == 0 && mgr.active_mmaps == 0 && mgr.active_ion_imports == 0 && !mock_held());
    puts("PASS T8 pre-TX failures (alloc, import; submit refused before write_fn: engine closed, PDR latched, token space exhausted, no slot) release; only NOT_ATTEMPTED is proof (write errors are held, T5)");

    /* T3b: PD down while a transmitted region is held. The region manager records UNKNOWN (cause MAP_PDR)
     * with no UNMAP and no release, once, and only on a PDR-latched engine. */
    fixture(); s = UINT_MAX;
    assert(m11_custodian_map(&c, 4096, ++now, &s) == 0);
    r = &c.regions[s];
    uint32_t tx1 = mock.tx_pkt_count;
    assert(m11_shmem_note_pd_down(&mgr, r) == -EINVAL && r->state == M11_SHMEM_STATE_DSP_MAP_ACKNOWLEDGED); /* engine live */
    eng.pdr_down = true;
    assert(m11_shmem_note_pd_down(&mgr, r) == -ENETRESET);
    assert(r->state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED && r->cause == M11_SHMEM_CAUSE_MAP_PDR && r->blocker != NULL);
    assert(held(r) && mock_held() && mock.tx_pkt_count == tx1 && mock.unmap_cmd_count == 0 && mgr.unresolved_regions == 1);
    assert(m11_shmem_note_pd_down(&mgr, r) == -EINVAL && mgr.unresolved_regions == 1); /* once */
    assert(m11_shmem_unmap_and_free(&mgr, r) == -EBUSY && held(r) && mock.unmap_cmd_count == 0);
    m11_custodian_pd_down(&c, ++now);
    assert(m11_custodian_terminal_action(&c) == M11_TERMINAL_RESET_RETAINING_ANCHORS && c.occupied[s]);
    puts("PASS T3b PD down while held: recorded as unknown (OWNERSHIP_UNRESOLVED, cause MAP_PDR) with no UNMAP and no release; a live engine is refused");

    puts("PASS post-MAP hold layers (real custodian L1 and region manager L3; strict mock; offline)");
    return 0;
}
