/* TEST-ONLY adversarial W1 harness (graph ledger / unsafe UNMAP). Mock and model only.
 * A probe wraps the GPR write callback and inspects every SHARED_MEM_UNMAP_REGIONS at
 * the moment it is transmitted, against MOCK GROUND TRUTH (modeled ADSP graph flags),
 * the custodian ledger and the foreign-traffic latch. Every graph-setup x event x
 * region-count combination runs the full release-attempt sequence.
 * Usage: adv_w1            (prints a table and a summary; non-zero exit on violation) */
#include "m11_custodian.h"
#include "../runtime-repair/m11_apm_protocol.h"
#include "../runtime-repair/m11_strict_mock.h"
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static m11_strict_mock_t mock;
static m11_gpr_engine_t eng;
static m11_shmem_mgr_t mgr;
static m11_boot_ledger boot;
static m11_custodian c;
static uint64_t fake_ms, now;
static unsigned nregions;
static int (*orig_write)(void *, int, const uint8_t *, size_t);
static unsigned unmap_tx, viol_gt, viol_ledger, viol_foreign, viol_unsafe, viol_close, viol_reboot,
                 viol_mono, viol_expect, setup_err, live_fail, scenarios, checks;
static const char *cur = "";
static const uint32_t RX[4]={0xB0000023u,0xB0000024u,0xB0000025u,0xB0000002u};
static const uint32_t VI[2]={0xB00000D5u,0xB00000CEu};
static uint64_t step_clock(void *u) { (void)u; fake_ms += 3u; return fake_ms; }
static bool mock_graph(void) {
    return mock.rx_opened || mock.rx_prepared || mock.rx_started ||
           mock.vi_tx_opened || mock.vi_tx_prepared || mock.vi_tx_started;
}
static bool ledger_busy(void) {
    for (unsigned g=0; g<M11_CUSTODIAN_GRAPHS; g++) if (c.graphs[g].state!=M11_GRAPH_FREE) return true;
    return false;
}
static bool any_region(void) {
    for (unsigned i=0;i<M11_CUSTODIAN_REGIONS;i++) if (c.occupied[i]) return true;
    return false;
}
static int probe_write(void *u, int fd, const uint8_t *pkt, size_t len) {
    uint32_t op=0;
    if (len >= 0x18u) memcpy(&op, pkt + 0x14, sizeof op);
    if (op == M11_APM_CMD_SHARED_MEM_UNMAP_REGIONS) {
        unmap_tx++; checks++;
        if (mock_graph()) { viol_gt++; printf("VIOLATION[GT] %s: UNMAP TX while modeled ADSP graph exists "
            "(rx o/p/s=%d/%d/%d vi o/p/s=%d/%d/%d)\n", cur, mock.rx_opened, mock.rx_prepared, mock.rx_started,
            mock.vi_tx_opened, mock.vi_tx_prepared, mock.vi_tx_started); }
        if (ledger_busy()) { viol_ledger++; printf("VIOLATION[LEDGER] %s: UNMAP TX while ledger holds a graph\n", cur); }
        if (boot.reasons & M11_TAINT_FOREIGN_TRAFFIC) { viol_foreign++;
            printf("VIOLATION[FOREIGN-POLICY] %s: UNMAP TX after undeclared GPR traffic was latched\n", cur); }
    }
    return orig_write(u, fd, pkt, len);
}
static void fixture(unsigned nreg) {
    m11_gpr_transport_t tp; m11_shmem_backend_t be;
    memset(&boot,0,sizeof(boot)); memset(&c,0,sizeof(c));
    m11_strict_mock_init(&mock); m11_strict_mock_bind(&mock,&tp,&be);
    orig_write = tp.write_fn; tp.write_fn = probe_write;
    if (m11_gpr_engine_init(&eng,&tp,0x2002u) || m11_gpr_engine_open(&eng) ||
        m11_shmem_mgr_init(&mgr,&be,&eng,10)) { setup_err++; return; }
    m11_gpr_engine_set_clock(&eng,step_clock,NULL);
    now = 100;
    m11_custodian_model_contract ct={.exclusive_importer=true,.no_other_endpoint=true,
        .no_pcm_clients=true,.strict_iommu=true,.graph_quiescent=true,
        .nack_atomicity_model=true,.final_anchor_pid1=true};
    if (m11_model_new_boot(&boot,17,now) || m11_custodian_init(&c,&boot,&mgr,&ct,100)) { setup_err++; return; }
    nregions = nreg;
    for (unsigned r=0;r<nreg;r++) { unsigned s=UINT_MAX; if (m11_custodian_map(&c,4096,++now,&s)) setup_err++; }
}
static unsigned vi_region(void) { return nregions > 1 ? 1u : 0u; }
static uint32_t vi_off(void) { return nregions > 1 ? 0u : 512u; }
static int gopen(const uint32_t *sgs, uint32_t n, unsigned r, uint32_t off, unsigned *g) {
    return m11_custodian_graph_open(&c, r, off, sgs, n, ++now, g);
}
static int gcmd(unsigned g, uint32_t op) { return m11_custodian_graph_cmd(&c, g, op, ++now); }
#define EXPECT(cond) do { if (!(cond)) { setup_err++; printf("SETUP-ERROR %s line %d: %s\n", cur, __LINE__, #cond); } } while (0)

enum { G_NONE, G_OPEN, G_PREP, G_START, G_LOST_OPEN, G_HELD_OPEN, G_WERR_OPEN, G_HELD_PREP,
       G_LOST_START, G_HELD_START, G_LOST_STOP, G_HELD_STOP, G_LOST_CLOSE, G_HELD_CLOSE,
       G_NACK_CLOSE, G_TWO, G_FOREIGN_FULL, G_FOREIGN_OPEN, G_LEDGER_THEN_FOREIGN_CLOSE,
       G_LEDGER_PLUS_FOREIGN_VI, G_COUNT };
static const char *gname[G_COUNT] = {"none","open","prepared","started","lost-open-rsp","held-open-rsp",
    "open-write-err","held-prepare-rsp","lost-start-rsp","held-start-rsp","lost-stop-rsp","held-stop-rsp",
    "lost-close-rsp","held-close-rsp","close-nack","two-graphs","foreign-open-prep-start","foreign-open",
    "ledger-start+foreign-stop-close","ledger-open+foreign-vi-open"};
static void setup_graph(int gi) {
    unsigned g=UINT_MAX, g2=UINT_MAX; uint32_t st=0;
    switch (gi) {
    case G_NONE: break;
    case G_OPEN: EXPECT(!gopen(RX,4,0,0,&g)); break;
    case G_PREP: EXPECT(!gopen(RX,4,0,0,&g)); EXPECT(!gcmd(g,M11_APM_CMD_GRAPH_PREPARE)); break;
    case G_START: EXPECT(!gopen(RX,4,0,0,&g)); EXPECT(!gcmd(g,M11_APM_CMD_GRAPH_PREPARE));
        EXPECT(!gcmd(g,M11_APM_CMD_GRAPH_START)); break;
    case G_LOST_OPEN: mock.drop_graph_open_rsp=true; EXPECT(gopen(RX,4,0,0,&g)==-ETIMEDOUT);
        mock.drop_graph_open_rsp=false; break;
    case G_HELD_OPEN: mock.hold_next_rsp=true; EXPECT(gopen(RX,4,0,0,&g)==-ETIMEDOUT); break;
    case G_WERR_OPEN: mock.fail_gpr_write_on_graph_open=true; EXPECT(gopen(RX,4,0,0,&g)<0);
        mock.fail_gpr_write_on_graph_open=false; break;
    case G_HELD_PREP: EXPECT(!gopen(RX,4,0,0,&g)); mock.hold_next_rsp=true;
        EXPECT(gcmd(g,M11_APM_CMD_GRAPH_PREPARE)==-ETIMEDOUT); break;
    case G_LOST_START: EXPECT(!gopen(RX,4,0,0,&g)); EXPECT(!gcmd(g,M11_APM_CMD_GRAPH_PREPARE));
        mock.drop_graph_start_rsp=true; EXPECT(gcmd(g,M11_APM_CMD_GRAPH_START)==-ETIMEDOUT);
        mock.drop_graph_start_rsp=false; break;
    case G_HELD_START: EXPECT(!gopen(RX,4,0,0,&g)); EXPECT(!gcmd(g,M11_APM_CMD_GRAPH_PREPARE));
        mock.hold_next_rsp=true; EXPECT(gcmd(g,M11_APM_CMD_GRAPH_START)==-ETIMEDOUT); break;
    case G_LOST_STOP: setup_graph(G_START); g=0; mock.drop_graph_stop_rsp=true;
        EXPECT(gcmd(g,M11_APM_CMD_GRAPH_STOP)==-ETIMEDOUT); mock.drop_graph_stop_rsp=false; break;
    case G_HELD_STOP: setup_graph(G_START); g=0; mock.hold_next_rsp=true;
        EXPECT(gcmd(g,M11_APM_CMD_GRAPH_STOP)==-ETIMEDOUT); break;
    case G_LOST_CLOSE: EXPECT(!gopen(RX,4,0,0,&g)); mock.drop_graph_close_rsp=true;
        EXPECT(gcmd(g,M11_APM_CMD_GRAPH_CLOSE)==-ETIMEDOUT); mock.drop_graph_close_rsp=false; break;
    case G_HELD_CLOSE: EXPECT(!gopen(RX,4,0,0,&g)); mock.hold_next_rsp=true;
        EXPECT(gcmd(g,M11_APM_CMD_GRAPH_CLOSE)==-ETIMEDOUT); break;
    case G_NACK_CLOSE: EXPECT(!gopen(RX,4,0,0,&g)); mock.nack_graph_close=true;
        EXPECT(gcmd(g,M11_APM_CMD_GRAPH_CLOSE)==-EREMOTEIO); mock.nack_graph_close=false;
        EXPECT(c.graphs[g].state==M11_GRAPH_OPEN); break;
    case G_TWO: setup_graph(G_START); EXPECT(!gopen(VI,2,vi_region(),vi_off(),&g2)); break;
    case G_FOREIGN_FULL:
        EXPECT(!m11_apm_transact_graph_open_region(&eng,&mgr,&c.regions[0],0,RX,4,10,&st));
        EXPECT(!m11_apm_transact_graph_mgmt(&eng,M11_APM_CMD_GRAPH_PREPARE,RX,4,10,&st));
        EXPECT(!m11_apm_transact_graph_mgmt(&eng,M11_APM_CMD_GRAPH_START,RX,4,10,&st)); break;
    case G_FOREIGN_OPEN:
        EXPECT(!m11_apm_transact_graph_open_region(&eng,&mgr,&c.regions[0],0,RX,4,10,&st)); break;
    case G_LEDGER_THEN_FOREIGN_CLOSE: setup_graph(G_START);
        EXPECT(!m11_apm_transact_graph_mgmt(&eng,M11_APM_CMD_GRAPH_STOP,RX,4,10,&st));
        EXPECT(!m11_apm_transact_graph_mgmt(&eng,M11_APM_CMD_GRAPH_CLOSE,RX,4,10,&st)); break;
    case G_LEDGER_PLUS_FOREIGN_VI: EXPECT(!gopen(RX,4,0,0,&g));
        EXPECT(!m11_apm_transact_graph_open_region(&eng,&mgr,&c.regions[vi_region()],vi_off(),VI,2,10,&st)); break;
    }
}
enum { E_NONE, E_WORKER, E_FOREIGN_PENDING, E_FOREIGN_DONE, E_LATE_ACKS, E_PD_DOWN, E_GLOBAL,
       E_OWNER, E_DEADLINE, E_CLOCK_BACK, E_SUP_PID1, E_SUP_OTHER, E_FOREIGN_CLOSE, E_COUNT };
static const char *ename[E_COUNT] = {"none","worker-exit","foreign-pending","foreign-completed",
    "late-acks","pd-down","global-cleanup","owner-exit","worker+deadline","clock-regression",
    "supervisor-pid1","supervisor-nonpid1","foreign-close"};
static void apply_event(int ei) {
    uint32_t t=0, st=0;
    switch (ei) {
    case E_NONE: break;
    case E_WORKER: m11_custodian_worker_exit(&c, ++now); break;
    case E_FOREIGN_PENDING: (void)m11_gpr_engine_submit(&eng,M11_APM_MODULE_IID,M11_APM_CMD_GET_SPF_STATE,NULL,0,&t); break;
    case E_FOREIGN_DONE: (void)m11_gpr_query_spf_state(&eng,10,&st); break;
    case E_LATE_ACKS: (void)m11_strict_mock_release_held(&mock); break;
    case E_PD_DOWN: m11_custodian_pd_down(&c, ++now); break;
    case E_GLOBAL: m11_custodian_global_cleanup(&c, ++now); break;
    case E_OWNER: m11_custodian_owner_exit(&c, ++now); break;
    case E_DEADLINE: m11_custodian_worker_exit(&c, ++now); now += 1000; (void)m11_custodian_tick(&c, now); break;
    case E_CLOCK_BACK: (void)m11_custodian_tick(&c, ++now); (void)m11_custodian_tick(&c, now - 5); break;
    case E_SUP_PID1: m11_custodian_supervisor_exit(&c, true, ++now); break;
    case E_SUP_OTHER: m11_custodian_supervisor_exit(&c, false, ++now); break;
    case E_FOREIGN_CLOSE: (void)m11_gpr_engine_close(&eng); break;
    }
}
static m11_adsp_state st0; static uint32_t reasons0;
static void step_check(const char *what) {
    checks++;
    if (mock.unsafe_release_attempts) { viol_unsafe++; printf("VIOLATION[UNSAFE-RELEASE] %s after %s\n", cur, what); mock.unsafe_release_attempts=0; }
    if ((unsigned)boot.state < (unsigned)st0 || (boot.reasons & reasons0) != reasons0) {
        viol_mono++; printf("VIOLATION[TAINT-MONOTONE] %s after %s\n", cur, what); }
    st0 = boot.state; reasons0 = boot.reasons;
    if (m11_custodian_reboot_permitted(&c) && (any_region() || ledger_busy() || boot.state!=M11_ADSP_CLEAN)) {
        viol_reboot++; printf("VIOLATION[REBOOT] %s after %s\n", cur, what); }
}
static void retire_all(int times, const char *what) {
    for (int k=0;k<times;k++)
        for (unsigned i=0;i<M11_CUSTODIAN_REGIONS;i++) if (c.occupied[i]) (void)m11_custodian_retire(&c,i,++now);
    step_check(what);
}
static void try_close(const char *what) {
    m11_adsp_state s=boot.state; bool held=any_region()||ledger_busy();
    uint32_t closes=eng.close_count; uint32_t tok=eng.next_token;
    int rc=m11_custodian_close(&c);
    if (!rc && (s!=M11_ADSP_CLEAN || held)) { viol_close++; printf("VIOLATION[LAST-CLOSE] %s at %s\n", cur, what); }
    (void)closes; (void)tok;
    step_check(what);
}
static void manual_close_graphs(void) {
    for (unsigned g=0; g<M11_CUSTODIAN_GRAPHS; g++) {
        if (c.graphs[g].state==M11_GRAPH_STARTED) (void)gcmd(g,M11_APM_CMD_GRAPH_STOP);
        if (c.graphs[g].state==M11_GRAPH_OPEN || c.graphs[g].state==M11_GRAPH_PREPARED)
            (void)gcmd(g,M11_APM_CMD_GRAPH_CLOSE);
    }
}
static bool expect_no_unmap(int gi, int ei) {
    if (gi>=G_LOST_OPEN && gi<=G_HELD_CLOSE) return true;           /* ledger UNKNOWN pins all */
    if (gi>=G_FOREIGN_FULL) return true;                             /* undeclared graph traffic */
    switch (ei) { case E_FOREIGN_PENDING: case E_FOREIGN_DONE: case E_PD_DOWN: case E_GLOBAL:
        case E_OWNER: case E_DEADLINE: case E_CLOCK_BACK: case E_SUP_PID1: case E_SUP_OTHER:
        case E_FOREIGN_CLOSE: return true; default: return false; }
}
static bool expect_liveness(int gi, int ei) {
    bool known = gi==G_NONE || gi==G_OPEN || gi==G_PREP || gi==G_START || gi==G_NACK_CLOSE || gi==G_TWO;
    return known && (ei==E_NONE || ei==E_WORKER || ei==E_LATE_ACKS);
}
static void run(int gi, int ei, unsigned nreg) {
    static char id[160];
    snprintf(id, sizeof id, "[G=%s E=%s R=%u]", gname[gi], ename[ei], nreg); cur = id;
    unsigned unmap_before = unmap_tx, err_before = setup_err;
    fixture(nreg); st0 = boot.state; reasons0 = boot.reasons;
    setup_graph(gi); step_check("setup");
    apply_event(ei); step_check("event");
    retire_all(2, "S1 retire x2");
    try_close("S2 close");
    (void)m11_strict_mock_release_held(&mock); retire_all(1, "S3 late acks + retire");
    (void)m11_custodian_graph_teardown(&c, ++now); retire_all(2, "S4 teardown + retire x2");
    manual_close_graphs(); retire_all(1, "S5 manual STOP/CLOSE + retire");
    (void)m11_strict_mock_release_held(&mock); (void)m11_custodian_graph_teardown(&c, ++now);
    retire_all(2, "S6 late acks + teardown + retire x2");
    bool released_all = !any_region();
    m11_terminal_action pre = m11_custodian_terminal_action(&c);
    try_close("S7 close");
    m11_terminal_action after_close = m11_custodian_terminal_action(&c);
    now += 10000; (void)m11_custodian_tick(&c, now); retire_all(1, "S8 past deadline + retire");
    unsigned unmaps = unmap_tx - unmap_before;
    scenarios++;
    if (expect_no_unmap(gi, ei) && unmaps) { viol_expect++; printf("VIOLATION[EXPECTED-NO-UNMAP] %s unmaps=%u\n", id, unmaps); }
    if (expect_liveness(gi, ei)) {
        bool ok = released_all && unmaps == nreg && !ledger_busy();
        if (ei==E_WORKER) ok = ok && pre==M11_TERMINAL_HOLD_RECONCILE;
        /* Rev 4: a boot that DSP-mapped ends by reset even after a clean teardown. */
        else ok = ok && after_close==M11_TERMINAL_RESET_RETAINING_ANCHORS && !m11_custodian_reboot_permitted(&c);
        if (!ok) { live_fail++; printf("LIVENESS-FAIL %s released=%d unmaps=%u ledger=%d pre=%s after_close=%s\n",
            id, released_all, unmaps, ledger_busy(), m11_terminal_action_name(pre), m11_terminal_action_name(after_close)); }
    }
    if (setup_err != err_before) printf("NOTE %s had setup errors\n", id);
    printf("%-64s unmaps=%u released=%d ledger=%d state=%d reasons=0x%03x terminal=%s\n", id, unmaps,
           released_all, ledger_busy(), (int)boot.state, (unsigned)boot.reasons,
           m11_terminal_action_name(m11_custodian_terminal_action(&c)));
}
/* Minimal reproducer for the suspected "second retire after latched foreign traffic". */
static void minimal_w1b(void) {
    uint32_t st=0; cur = "[MINIMAL W1b]";
    unsigned before = unmap_tx; unsigned gt_before = viol_gt;
    fixture(1);
    (void)m11_apm_transact_graph_open_region(&eng,&mgr,&c.regions[0],0,RX,4,10,&st);
    (void)m11_apm_transact_graph_mgmt(&eng,M11_APM_CMD_GRAPH_PREPARE,RX,4,10,&st);
    (void)m11_apm_transact_graph_mgmt(&eng,M11_APM_CMD_GRAPH_START,RX,4,10,&st);
    m11_custodian_worker_exit(&c, ++now);
    int rc1 = m11_custodian_retire(&c, 0, ++now);
    int rc2 = m11_custodian_retire(&c, 0, ++now);
    printf("MINIMAL W1b: mock rx_started=%d; retire#1 rc=%d; retire#2 rc=%d; UNMAP TX=%u; "
           "GT violations=%u; region released=%d; reasons=0x%03x\n", mock.rx_started, rc1, rc2,
           unmap_tx - before, viol_gt - gt_before, !c.occupied[0], (unsigned)boot.reasons);
}
int main(void) {
    minimal_w1b();
    for (int gi=0; gi<G_COUNT; gi++)
        for (int ei=0; ei<E_COUNT; ei++)
            for (unsigned nreg=1; nreg<=2; nreg++) run(gi, ei, nreg);
    printf("SUMMARY scenarios=%u checks=%u unmap_tx=%u | VIOLATIONS ground-truth=%u ledger=%u "
           "foreign-policy=%u unsafe-release=%u last-close=%u reboot=%u taint-monotone=%u "
           "expected-no-unmap=%u | liveness-fail=%u setup-errors=%u\n", scenarios, checks, unmap_tx,
           viol_gt, viol_ledger, viol_foreign, viol_unsafe, viol_close, viol_reboot, viol_mono,
           viol_expect, live_fail, setup_err);
    unsigned safety = viol_gt + viol_ledger + viol_foreign + viol_unsafe + viol_close + viol_reboot +
                      viol_mono + viol_expect;
    puts(safety ? "FAIL W1 adversarial: safety violations above" :
         (live_fail || setup_err) ? "FAIL W1 adversarial: no safety violation, but liveness/setup failures" :
         "PASS W1 adversarial: no UNMAP/release under any modeled graph, unknown ledger or foreign traffic");
    return (safety || live_fail || setup_err) ? 1 : 0;
}
