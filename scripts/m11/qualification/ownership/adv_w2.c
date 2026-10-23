/* TEST-ONLY adversarial W2 harness (deadline / engine clock). Mock and model only.
 * A probe records the ENGINE clock (without advancing it) at the instant every
 * SHARED_MEM_UNMAP_REGIONS is transmitted. Property, per retire() call:
 *   UNMAP is transmitted only if (t_tx - t_before) < B + s,
 * where t_before is the engine clock just before the call, s the clock step and
 * B = min(mgr timeout, custodian deadline - now). Plus: never after the custodian
 * deadline, never after a custodian clock regression, never in a call whose engine
 * clock ran backwards before the budget check.
 * Rev 5 (post-MAP hold): every scenario MAPs first, so every retire() must be refused
 * (-EPERM) and no UNMAP is ever transmitted, whatever the budget, deadline or clock.
 * Usage: adv_w2 */
#include "m11_custodian.h"
#include "../runtime-repair/m11_strict_mock.h"
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

static m11_strict_mock_t mock;
static m11_gpr_engine_t eng;
static m11_shmem_mgr_t mgr;
static m11_boot_ledger boot;
static m11_custodian c;
static uint64_t fake = 1000, step;
static long long regress_at = -1, reads;
static int (*orig_write)(void *, int, const uint8_t *, size_t);
static unsigned unmap_tx; static uint64_t t_tx; static long long reads_at_tx;
static unsigned viol, runs, unmap_calls, refused_calls, characterized, mid_regression_unmaps, not_refused;
/* first/last value READ by the code under test since mark_call was raised */
static int mark_call; static uint64_t first_val, last_val, last_before_tx;
static uint64_t clk(void *u) {
    (void)u; reads++;
    if (regress_at >= 0 && reads >= regress_at) { if (fake > 0) fake -= 1; }
    else fake += step;
    if (mark_call) { first_val = fake; mark_call = 0; }
    last_val = fake;
    return fake;
}
static int probe_write(void *u, int fd, const uint8_t *pkt, size_t len) {
    uint32_t op = 0;
    if (len >= 0x18u) memcpy(&op, pkt + 0x14, sizeof op);
    if (op == M11_APM_CMD_SHARED_MEM_UNMAP_REGIONS) {
        unmap_tx++; t_tx = fake; reads_at_tx = reads; last_before_tx = last_val; }
    return orig_write(u, fd, pkt, len);
}
static void fixture(uint32_t timeout) {
    m11_gpr_transport_t tp; m11_shmem_backend_t be;
    memset(&boot,0,sizeof(boot)); memset(&c,0,sizeof(c));
    m11_strict_mock_init(&mock); m11_strict_mock_bind(&mock,&tp,&be);
    orig_write = tp.write_fn; tp.write_fn = probe_write;
    (void)m11_gpr_engine_init(&eng,&tp,0x2002u); (void)m11_gpr_engine_open(&eng);
    (void)m11_shmem_mgr_init(&mgr,&be,&eng,timeout);
    m11_gpr_engine_set_clock(&eng, clk, NULL); regress_at = -1;
    m11_custodian_model_contract ct={.exclusive_importer=true,.no_other_endpoint=true,
        .no_pcm_clients=true,.strict_iommu=true,.graph_quiescent=true,
        .nack_atomicity_model=true,.final_anchor_pid1=true};
    (void)m11_model_new_boot(&boot,17,100);
    (void)m11_custodian_init(&c,&boot,&mgr,&ct,100);
}
enum { V_DIRECT, V_LATE_MAP, V_LATE_MAP_REGRESS, V_CUST_REGRESS, V_PAST_DEADLINE, V_COUNT };
static const char *vname[V_COUNT] = {"direct-unmap","late-map-reconcile","late-map+engine-regress",
    "custodian-clock-regress","past-deadline"};
static void bad(const char *what, int v, uint64_t s, uint32_t T, uint32_t L, int rc) {
    viol++;
    printf("VIOLATION %s v=%s step=%llu T=%u L=%u rc=%d t_tx-t_before=%llu\n", what, vname[v],
           (unsigned long long)s, T, L, rc, (unsigned long long)t_tx);
}
int main(void) {
    static const uint64_t steps[] = {1,2,3,4,5,7,9,11,13};
    static const uint32_t Ts[] = {4,6,10,16,25};
    static const uint32_t Ls[] = {1,2,3,5,8,13,21,50,99};
    for (int v = 0; v < V_COUNT; v++)
    for (unsigned si = 0; si < sizeof steps/sizeof *steps; si++)
    for (unsigned ti = 0; ti < sizeof Ts/sizeof *Ts; ti++)
    for (unsigned li = 0; li < sizeof Ls/sizeof *Ls; li++)
    for (int k = 1; k <= (v == V_LATE_MAP_REGRESS ? 6 : 1); k++) {
        uint64_t s = steps[si]; uint32_t T = Ts[ti], L = Ls[li];
        /* Build the scenario with a fine clock (step 1) so setup itself never times out;
         * the swept step applies only to the retire() call under test. */
        step = 1; fixture(T); unmap_tx = 0; runs++;
        unsigned slot = UINT_MAX; int rc;
        uint64_t due;
        if (v == V_DIRECT || v == V_CUST_REGRESS || v == V_PAST_DEADLINE) {
            if (m11_custodian_map(&c,4096,100,&slot)) { bad("setup-map", v, s, T, L, -1); continue; }
            m11_custodian_worker_exit(&c,101); due = boot.recovery_due_ms;   /* 201 */
        } else {
            mock.hold_next_rsp = true;
            rc = m11_custodian_map(&c,4096,100,&slot);
            if (rc != -ETIMEDOUT) { bad("setup-late-map", v, s, T, L, rc); continue; }
            if (m11_strict_mock_release_held(&mock) != 1) { bad("setup-release", v, s, T, L, -1); continue; }
            due = boot.recovery_due_ms;                                       /* 200 */
        }
        step = s;
        unsigned before = unmap_tx; uint64_t t_before = fake;
        if (v == V_CUST_REGRESS) {
            (void)m11_custodian_tick(&c, 150);
            rc = m11_custodian_retire(&c, slot, 149);
            int rc2 = m11_custodian_retire(&c, slot, 160);
            if (unmap_tx != before || rc >= 0 || rc2 >= 0) bad("UNMAP/success after custodian clock regression", v, s, T, L, rc);
            if (rc != -EPERM || rc2 != -EPERM) { not_refused++; bad("retire not refused after a MAP intent (post-MAP hold)", v, s, T, L, rc); }
            refused_calls++; continue;
        }
        if (v == V_PAST_DEADLINE) {
            rc = m11_custodian_retire(&c, slot, due + L - 1);
            if (unmap_tx != before || rc >= 0) bad("UNMAP/success at or after the custodian deadline", v, s, T, L, rc);
            if (rc != -EPERM) { not_refused++; bad("retire not refused after a MAP intent (post-MAP hold)", v, s, T, L, rc); }
            refused_calls++; continue;
        }
        if (v == V_LATE_MAP_REGRESS) regress_at = reads + k;    /* k-th engine read in this call regresses */
        uint64_t now = due - L;
        mark_call = 1;
        rc = m11_custodian_retire(&c, slot, now);
        mark_call = 0;
        if (rc != -EPERM) { not_refused++; bad("retire not refused after a MAP intent (post-MAP hold)", v, s, T, L, rc); }
        uint32_t B = T < L ? T : L;
        if (unmap_tx != before) {
            unmap_calls++;
            uint64_t d = t_tx - t_before;
            bool regressed_before_tx = (v == V_LATE_MAP_REGRESS && reads_at_tx >= regress_at);
            if (regressed_before_tx) {
                /* The custodian's own reads are first_val (budget start) and last_before_tx
                 * (post-reconcile check). end < start must refuse; a dip that stays >= start
                 * leaves a measured elapsed that must still be under the budget. */
                if (last_before_tx < first_val)
                    bad("UNMAP although the engine clock at the budget check was below its start", v, s, T, L, rc);
                else if (!(last_before_tx - first_val < (uint64_t)B)) {
                    t_tx = last_before_tx - first_val; bad("UNMAP with measured elapsed >= budget after a clock dip", v, s, T, L, rc); }
                else mid_regression_unmaps++;
            } else if (!(d < (uint64_t)B + s)) {
                t_tx = d; bad("UNMAP after the shared budget was spent", v, s, T, L, rc); }
        } else refused_calls++;
    }
    /* Characterization only (not asserted): a STALLED injected engine clock. The engine's
     * real-time watchdog bounds the wait; elapsed engine time stays 0, so the budget is
     * not considered spent. Production uses CLOCK_MONOTONIC (clock_fn == NULL). */
    step = 0; fixture(10); unmap_tx = 0;
    unsigned slot = UINT_MAX; mock.hold_next_rsp = true;
    (void)m11_custodian_map(&c,4096,100,&slot); (void)m11_strict_mock_release_held(&mock);
    int rc = m11_custodian_retire(&c, slot, 150); characterized++;
    printf("CHARACTERIZED stalled-engine-clock: retire rc=%d UNMAP TX=%u (engine clock authority; "
           "watchdog bounds waits in real time)\n", rc, unmap_tx);
    printf("CHARACTERIZED mid-call engine-clock dips that stayed >= the budget start and still "
           "allowed UNMAP (measured elapsed < budget): %u (custodian assumes a monotonic engine clock)\n",
           mid_regression_unmaps);
    printf("SUMMARY runs=%u calls_with_unmap=%u calls_refused_or_no_unmap=%u not_refused=%u violations=%u\n",
           runs, unmap_calls, refused_calls, not_refused, viol);
    /* Rev 5: the budget path is unreachable after a MAP intent; any UNMAP call is itself a failure. */
    int ok = viol == 0 && unmap_calls == 0 && not_refused == 0 && refused_calls == runs;
    puts(ok ? "PASS W2 adversarial: every retire after a MAP intent refused (post-MAP hold); no UNMAP under any budget, deadline or clock regression"
            : "FAIL W2 adversarial");
    return ok ? 0 : 1;
}
