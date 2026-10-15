/* Bounded, seeded state-machine fuzz of the offline custodian against the strict mock.
 * Invariants are checked against MOCK GROUND TRUTH (modeled ADSP graph/map state), and a
 * transport probe checks every MAP/UNMAP at the instant it is transmitted. Mock-only; it
 * qualifies no firmware behavior.
 * Reproducibility: every random draw is its own statement (never two draws in one argument
 * list), so a seed yields the same operation sequence under every compiler.
 * Usage: fuzz_custodian <seed> <scenarios> <ops_per_scenario>                          */
#include "m11_custodian.h"
#include "../runtime-repair/m11_strict_mock.h"
#include <assert.h>
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
static uint64_t eng_ms, now_ms, rng;
static unsigned long long g_seed; static unsigned g_sc, g_op;
static const uint32_t RX[4]={0xB0000023u,0xB0000024u,0xB0000025u,0xB0000002u};
static const uint32_t VI[2]={0xB00000D5u,0xB00000CEu};
static int (*orig_write)(void *, int, const uint8_t *, size_t);
static uint64_t step_clock(void *u) { (void)u; eng_ms += 3u; return eng_ms; }
static uint64_t next(void) { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return rng; }
static unsigned pick(unsigned n) { return (unsigned)(next() % n); }
static bool chance(unsigned pct) { return pick(100u) < pct; }

static struct { unsigned long ops, unmap_ok, map_ok, graph_started, graph_unknown, lost_ack,
    late_ack_release, foreign_simple, foreign_graph, worker_death, latch_refusal, repeat_retire,
    teardown_after_worker, reset, unsafe, orderly, nack, unmap_tx, map_tx, oneshot_refusal; } cov;

static void fail(const char *why) {
    fprintf(stderr,"FUZZ VIOLATION seed=%llu scenario=%u op=%u: %s\n",g_seed,g_sc,g_op,why);
    exit(1);
}
static bool mock_graph(void) {
    return mock.rx_opened||mock.rx_prepared||mock.rx_started||
           mock.vi_tx_opened||mock.vi_tx_prepared||mock.vi_tx_started;
}
static bool ledger_empty(void) {
    for (unsigned g=0; g<M11_CUSTODIAN_GRAPHS; g++) if (c.graphs[g].state!=M11_GRAPH_FREE) return false;
    return true;
}
static bool any_region(void) {
    for (unsigned i=0;i<M11_CUSTODIAN_REGIONS;i++) if (c.occupied[i]) return true;
    return false;
}
/* Every MAP/UNMAP is judged at the instant the packet leaves, before the mock reacts. */
static int probe_write(void *u, int fd, const uint8_t *pkt, size_t len) {
    uint32_t op=0;
    if (len >= 0x18u) memcpy(&op, pkt + 0x14, sizeof op);
    if (op == M11_APM_CMD_SHARED_MEM_UNMAP_REGIONS) {
        cov.unmap_tx++;
        if (mock_graph()) fail("UNMAP transmitted while the modeled ADSP holds a graph");
        if (!ledger_empty()) fail("UNMAP transmitted while the ledger holds a graph");
        if (boot.reasons & (M11_TAINT_FOREIGN_TRAFFIC|M11_TAINT_GRAPH_UNKNOWN))
            fail("UNMAP transmitted after FOREIGN_TRAFFIC/GRAPH_UNKNOWN was latched");
    } else if (op == M11_APM_CMD_SHARED_MEM_MAP_REGIONS) {
        cov.map_tx++;
        if (boot.state != M11_ADSP_CLEAN) fail("MAP transmitted from a non-CLEAN boot");
#if M11_CUSTODIAN_API_REVISION >= 4
        if (boot.dsp_unmap_attempted) fail("MAP transmitted after a DSP UNMAP in the same boot");
#endif
    }
    return orig_write(u, fd, pkt, len);
}
static void fixture(void) {
    m11_gpr_transport_t tp; m11_shmem_backend_t be;
    memset(&boot,0,sizeof(boot)); memset(&c,0,sizeof(c));
    m11_strict_mock_init(&mock); m11_strict_mock_bind(&mock,&tp,&be);
    orig_write = tp.write_fn; tp.write_fn = probe_write;
    assert(!m11_gpr_engine_init(&eng,&tp,0x2002u));
    assert(!m11_gpr_engine_open(&eng));
    assert(!m11_shmem_mgr_init(&mgr,&be,&eng,10));
    eng_ms=1000; now_ms=100;
    m11_gpr_engine_set_clock(&eng,step_clock,NULL);
    assert(!m11_model_new_boot(&boot,17,now_ms));
    m11_custodian_model_contract ct={.exclusive_importer=true,.no_other_endpoint=true,
        .no_pcm_clients=true,.strict_iommu=true,.graph_quiescent=true,
        .nack_atomicity_model=true,.final_anchor_pid1=true};
    assert(!m11_custodian_init(&c,&boot,&mgr,&ct,150));
}
static void clear_faults(void) {
    mock.drop_graph_open_rsp=mock.drop_graph_close_rsp=mock.drop_graph_stop_rsp=false;
    mock.drop_graph_start_rsp=false;
    mock.nack_graph_open=mock.nack_graph_close=false;
    mock.nack_shmem_map=mock.nack_shmem_unmap=false;
    mock.fail_gpr_write_on_graph_open=false;
    mock.deliver_then_fail_write_on_map=mock.short_gpr_write_on_map=false;
    mock.fail_ion_unmap=mock.fail_close_fd=mock.fail_dma_buf_sync_end=false;
}
/* Background faults for any operation (low rates). */
static void inject_faults(void) {
    if (chance(4)) mock.hold_next_rsp=true;
    if (chance(2)) { mock.nack_shmem_map=true; cov.nack++; }
    if (chance(2)) mock.nack_shmem_unmap=true;
    if (chance(2)) mock.deliver_then_fail_write_on_map=true;
    if (chance(2)) mock.short_gpr_write_on_map=true;
    if (chance(2)) mock.fail_ion_unmap=true;
    if (chance(2)) mock.fail_close_fd=true;
    if (chance(2)) { mock.fail_dma_buf_sync_end=true; mock.sync_end_errno=-EPIPE; }
}
/* Graph-step faults: lost (dropped) reply, late (held) reply, NACK, write error. */
static void graph_fault(uint32_t op) {
    unsigned f=pick(100u);
    if (f < 8) { mock.hold_next_rsp=true; return; }
    if (f < 14) {
        cov.lost_ack++;
        if (op==M11_APM_CMD_GRAPH_OPEN) mock.drop_graph_open_rsp=true;
        else if (op==M11_APM_CMD_GRAPH_START) mock.drop_graph_start_rsp=true;
        else if (op==M11_APM_CMD_GRAPH_STOP) mock.drop_graph_stop_rsp=true;
        else if (op==M11_APM_CMD_GRAPH_CLOSE) mock.drop_graph_close_rsp=true;
        return;
    }
    if (f < 18) {
        cov.nack++;
        if (op==M11_APM_CMD_GRAPH_OPEN) mock.nack_graph_open=true;
        else if (op==M11_APM_CMD_GRAPH_CLOSE) mock.nack_graph_close=true;
        return;
    }
    if (f < 20 && op==M11_APM_CMD_GRAPH_OPEN) mock.fail_gpr_write_on_graph_open=true;
}
static unsigned rank(m11_adsp_state s) { return (unsigned)s; }
static bool terminal_final(m11_terminal_action a) {
    return a==M11_TERMINAL_RESET_RETAINING_ANCHORS || a==M11_TERMINAL_UNSAFE_LAST_CLOSE_OCCURRED;
}
static unsigned pick_region(void) {
    unsigned start=pick(M11_CUSTODIAN_REGIONS);
    for (unsigned k=0;k<M11_CUSTODIAN_REGIONS;k++) {
        unsigned r=(start+k)%M11_CUSTODIAN_REGIONS;
        if (c.occupied[r]) return r;
    }
    return UINT_MAX;
}
static void note_graph_states(void) {
    for (unsigned g=0; g<M11_CUSTODIAN_GRAPHS; g++)
        if (c.graphs[g].state==M11_GRAPH_UNKNOWN) { cov.graph_unknown++; return; }
}
/* OPEN -> PREPARE -> START through the custodian, each step possibly faulted.
 * depth: 0 open only, 1 +prepare, 2 +start; UINT_MAX draws it. */
static void graph_lifecycle(unsigned depth) {
    unsigned r=pick_region();
    if (r==UINT_MAX) return;
    bool vi=chance(50);
    unsigned g=UINT_MAX;
    graph_fault(M11_APM_CMD_GRAPH_OPEN);
    int rc=m11_custodian_graph_open(&c,r,vi?512u:0u,vi?VI:RX,vi?2u:4u,now_ms,&g);
    clear_faults();
    if (rc || g==UINT_MAX) return;
    if (depth==UINT_MAX) depth=pick(3u);
    if (depth >= 1) {
        graph_fault(M11_APM_CMD_GRAPH_PREPARE);
        rc=m11_custodian_graph_cmd(&c,g,M11_APM_CMD_GRAPH_PREPARE,++now_ms);
        clear_faults();
        if (rc) return;
    }
    if (depth >= 2) {
        graph_fault(M11_APM_CMD_GRAPH_START);
        rc=m11_custodian_graph_cmd(&c,g,M11_APM_CMD_GRAPH_START,++now_ms);
        clear_faults();
        if (!rc) cov.graph_started++;
    }
}
/* Undeclared traffic that changes graph state behind the custodian's back. */
static void foreign_graph(void) {
    uint32_t st=0;
    cov.foreign_graph++;
    unsigned kind=pick(3u);
    if (kind==0) {                         /* open + prepare + start a graph directly */
        unsigned r=pick_region();
        if (r==UINT_MAX || c.regions[r].state!=M11_SHMEM_STATE_DSP_MAP_ACKNOWLEDGED) return;
        bool vi=chance(50);
        const uint32_t *s=vi?VI:RX; uint32_t n=vi?2u:4u;
        if (m11_apm_transact_graph_open_region(&eng,&mgr,&c.regions[r],vi?512u:0u,s,n,10,&st)) return;
        if (chance(70) && !m11_apm_transact_graph_mgmt(&eng,M11_APM_CMD_GRAPH_PREPARE,s,n,10,&st))
            if (chance(70)) (void)m11_apm_transact_graph_mgmt(&eng,M11_APM_CMD_GRAPH_START,s,n,10,&st);
    } else if (kind==1) {                  /* stop/close a ledger graph directly */
        unsigned g=pick(M11_CUSTODIAN_GRAPHS);
        if (c.graphs[g].state==M11_GRAPH_FREE) return;
        (void)m11_apm_transact_graph_mgmt(&eng,M11_APM_CMD_GRAPH_STOP,c.graphs[g].sgs,c.graphs[g].num_sgs,10,&st);
        (void)m11_apm_transact_graph_mgmt(&eng,M11_APM_CMD_GRAPH_CLOSE,c.graphs[g].sgs,c.graphs[g].num_sgs,10,&st);
    } else {                               /* harmless-looking completed query */
        (void)m11_gpr_query_spf_state(&eng,10,&st);
    }
}
static void retire_some(bool repeat) {
    unsigned r=pick_region();
    if (r==UINT_MAX) return;
    unsigned times=1;
    if (repeat) { times=2+pick(2u); cov.repeat_retire++; }
    for (unsigned k=0;k<times && c.occupied[r];k++) {
        bool latched=(boot.reasons & (M11_TAINT_FOREIGN_TRAFFIC|M11_TAINT_GRAPH_UNKNOWN))!=0;
        int rc=m11_custodian_retire(&c,r,++now_ms);
        if (!rc) cov.unmap_ok++;
        if (latched && rc==-EBUSY) cov.latch_refusal++;
        if (latched && !rc) fail("retire succeeded after the FOREIGN/GRAPH_UNKNOWN latch");
    }
}

int main(int argc, char **argv) {
    if (argc!=4) { fprintf(stderr,"usage: %s seed scenarios ops\n",argv[0]); return 2; }
    /* 64-bit seeds must survive LLP64 hosts (unsigned long is 32-bit on Windows). */
    char *end=NULL; errno=0;
    unsigned long long seed=strtoull(argv[1],&end,0);
    if (errno || !end || *end) { fprintf(stderr,"invalid seed %s\n",argv[1]); return 2; }
    unsigned scenarios=(unsigned)strtoul(argv[2],NULL,0), ops=(unsigned)strtoul(argv[3],NULL,0);
    g_seed=seed;
    rng=seed ? seed : 0x9e3779b97f4a7c15ull;
    for (unsigned sc=0; sc<scenarios; sc++) {
        g_sc=sc;
        fixture();
        bool worker_dead=false;
        /* Prologue: START needs a CLEAN boot, which random background faults end quickly.
         * Reach a mapped (and usually STARTED) state first; graph faults still apply. A few
         * scenarios skip it, so a boot that never DSP-maps can reach ORDERLY_SHUTDOWN. */
        bool prologue=!chance(5);
        if (prologue) {
            unsigned nmap=1+pick(2u);
            for (unsigned k=0;k<nmap;k++) {
                unsigned pi=UINT_MAX;
                if (!m11_custodian_map(&c,4096u,++now_ms,&pi)) cov.map_ok++;
            }
            if (chance(75)) graph_lifecycle(2u);
        }
        for (unsigned op=0; op<ops; op++) {
            g_op=op;
            cov.ops++;
            /* pre-op snapshot (ground truth + ledger) */
            m11_adsp_state st0=boot.state; uint32_t reasons0=boot.reasons;
            bool due_set0=boot.recovery_deadline_set; uint64_t due0=boot.recovery_due_ms;
            bool rx_started0=mock.rx_started, vi_started0=mock.vi_tx_started;
            bool ledger0=ledger_empty(), regions0=any_region();
            uint32_t closes0=eng.close_count;
            uint32_t tok0=eng.next_token, open0=eng.open_count;
            bool foreign0=tok0!=c.expected_next_token||open0!=c.expected_open_count||closes0!=c.expected_close_count;
            m11_terminal_action term0=m11_custodian_terminal_action(&c);
            now_ms += 1u;
            now_ms += pick(4u);
            if (chance(3)) now_ms += 60u;
            inject_faults();
            unsigned i=UINT_MAX, g=UINT_MAX;
            int rc=0;
            bool custodian_close=false;
            unsigned which=pick(20u);
            switch (which) {
            case 0: case 1: case 2:
                rc=m11_custodian_map(&c,4096u,now_ms,&i);
                if (!rc) cov.map_ok++;
                if (rc==-EPERM) cov.oneshot_refusal++;
                break;
            case 3: case 4: retire_some(false); break;
            case 5: retire_some(true); break;
            case 6: case 7: case 8: clear_faults(); graph_lifecycle(UINT_MAX); break;
            case 9: {
                static const uint32_t opc[4]={M11_APM_CMD_GRAPH_PREPARE,M11_APM_CMD_GRAPH_START,
                    M11_APM_CMD_GRAPH_STOP,M11_APM_CMD_GRAPH_CLOSE};
                unsigned gi=pick(M11_CUSTODIAN_GRAPHS);
                unsigned oi=pick(4u);
                clear_faults(); graph_fault(opc[oi]);
                rc=m11_custodian_graph_cmd(&c,gi,opc[oi],now_ms);
                if (!rc && opc[oi]==M11_APM_CMD_GRAPH_START) cov.graph_started++;
                break; }
            case 10: case 11:
                rc=m11_custodian_graph_teardown(&c,now_ms);
                if (!rc && worker_dead) cov.teardown_after_worker++;
                break;
            case 12:
                if (chance(40)) { m11_custodian_worker_exit(&c,now_ms); worker_dead=true; cov.worker_death++; }
                break;
            case 13: if (m11_strict_mock_release_held(&mock)) cov.late_ack_release++; break;
            case 14: custodian_close=true; rc=m11_custodian_close(&c); break;
            case 15: (void)m11_custodian_tick(&c,now_ms); break;
            case 16:
                if (chance(30)) { uint32_t t=0;
                    (void)m11_gpr_engine_submit(&eng,M11_APM_MODULE_IID,M11_APM_CMD_GET_SPF_STATE,NULL,0,&t);
                    cov.foreign_simple++; }
                break;
            case 17: if (chance(35)) { clear_faults(); foreign_graph(); } break;
            default: {
                unsigned ev=pick(5u);
                unsigned p=pick(100u);
                if (ev==0 && p<15) m11_custodian_owner_exit(&c,now_ms);
                else if (ev==1 && p<15) m11_custodian_pd_down(&c,now_ms);
                else if (ev==2 && p<15) m11_custodian_global_cleanup(&c,now_ms);
                else if (ev==3 && p<25) { bool pid1=chance(50); m11_custodian_supervisor_exit(&c,pid1,now_ms); }
                break; }
            }
            (void)rc; (void)g;
            clear_faults();
            note_graph_states();
            /* I3: no local release while the modeled DSP still maps the pages. */
            if (mock.unsafe_release_attempts) fail("local release while DSP mapping alive");
            /* I4: taint, reasons and deadline are monotone. */
            if (rank(boot.state)<rank(st0) || (boot.reasons&reasons0)!=reasons0) fail("taint decreased");
            if (due_set0 && (!boot.recovery_deadline_set || boot.recovery_due_ms!=due0))
                fail("recovery deadline moved");
            /* I5: the custodian's endpoint close only from CLEAN with nothing held. */
            if (custodian_close && eng.close_count!=closes0 &&
                (st0!=M11_ADSP_CLEAN || !ledger0 || regions0 || foreign0))
                fail("endpoint last-close while tainted or holding resources");
            /* I6: terminal decision never relaxes once final; reboot only when nothing held. */
            m11_terminal_action term=m11_custodian_terminal_action(&c);
            if (terminal_final(term0) && !terminal_final(term)) fail("terminal relaxed");
            if (term==M11_TERMINAL_ORDERLY_SHUTDOWN && (any_region() || !ledger_empty() || boot.state!=M11_ADSP_CLEAN))
                fail("reboot permitted while resources held or tainted");
#if M11_CUSTODIAN_API_REVISION >= 4
            if (term==M11_TERMINAL_ORDERLY_SHUTDOWN && boot.dsp_map_attempted)
                fail("reboot permitted after a DSP MAP in this boot");
#endif
            /* I7: custodian-driven streaming starts only from a CLEAN boot. Foreign graph
             * traffic (case 17) bypasses the custodian by construction and is excluded. */
            if (which!=17 && ((!rx_started0 && mock.rx_started) || (!vi_started0 && mock.vi_tx_started)) &&
                st0!=M11_ADSP_CLEAN) fail("graph START from a tainted boot");
            /* I8: ledger references are consistent. */
            uint32_t refs=0, live=0;
            for (unsigned r=0;r<M11_CUSTODIAN_REGIONS;r++) refs+=c.region_graph_refs[r];
            for (unsigned k=0;k<M11_CUSTODIAN_GRAPHS;k++) if (c.graphs[k].state!=M11_GRAPH_FREE) live++;
            if (refs!=live) fail("graph/region reference mismatch");
            /* I9: counters agree with retained records unless imports were externally lost. */
            if (!c.kernel_imports_lost && m11_shmem_mgr_audit(&mgr,c.regions,M11_CUSTODIAN_REGIONS))
                fail("shmem accounting mismatch");
            if (term==M11_TERMINAL_RESET_RETAINING_ANCHORS) cov.reset++;
            if (term==M11_TERMINAL_UNSAFE_LAST_CLOSE_OCCURRED) cov.unsafe++;
            if (term==M11_TERMINAL_ORDERLY_SHUTDOWN) cov.orderly++;
            if (terminal_final(term) && chance(50)) break; /* end of boot */
        }
    }
    printf("fuzz seed=%llu scenarios=%u ops=%u: ops=%lu map_ok=%lu unmap_ok=%lu map_tx=%lu unmap_tx=%lu "
           "started=%lu graph_unknown=%lu lost_ack=%lu late_ack_release=%lu foreign_simple=%lu "
           "foreign_graph=%lu worker_death=%lu teardown_after_worker=%lu latch_refusal=%lu "
           "repeat_retire=%lu nack=%lu reset=%lu unsafe=%lu orderly=%lu oneshot_refusal=%lu\n", seed, scenarios, ops,
           cov.ops, cov.map_ok, cov.unmap_ok, cov.map_tx, cov.unmap_tx, cov.graph_started,
           cov.graph_unknown, cov.lost_ack, cov.late_ack_release, cov.foreign_simple,
           cov.foreign_graph, cov.worker_death, cov.teardown_after_worker, cov.latch_refusal,
           cov.repeat_retire, cov.nack, cov.reset, cov.unsafe, cov.orderly, cov.oneshot_refusal);
    /* Coverage gate: thresholds scale with the campaign; a campaign that does not reach these
     * states qualifies nothing. */
    if (scenarios>=200) {
        unsigned long s=scenarios;
        struct { const char *name; unsigned long got, need; } gate[] = {
            {"map_ok",cov.map_ok,s}, {"unmap_ok",cov.unmap_ok,s/4}, {"started",cov.graph_started,s/4},
            {"graph_unknown",cov.graph_unknown,s/4}, {"lost_ack",cov.lost_ack,s/10},
            {"late_ack_release",cov.late_ack_release,s/10}, {"foreign_simple",cov.foreign_simple,s/10},
            {"foreign_graph",cov.foreign_graph,s/10}, {"worker_death",cov.worker_death,s/10},
            {"teardown_after_worker",cov.teardown_after_worker,s/10},
            {"latch_refusal",cov.latch_refusal,s/10}, {"repeat_retire",cov.repeat_retire,s/4},
            {"reset",cov.reset,s/10}, {"unsafe",cov.unsafe,1}, {"orderly",cov.orderly,1},
#if M11_CUSTODIAN_API_REVISION >= 4
            {"oneshot_refusal",cov.oneshot_refusal,s/10},
#endif
        };
        bool ok=true;
        for (unsigned k=0;k<sizeof(gate)/sizeof(gate[0]);k++)
            if (gate[k].got < gate[k].need) {
                fprintf(stderr,"FUZZ COVERAGE INSUFFICIENT %s=%lu < %lu\n",gate[k].name,gate[k].got,gate[k].need);
                ok=false;
            }
        if (!ok) return 1;
    }
    puts("PASS custodian fuzz invariants against mock ground truth (mock only; no firmware claim)");
    return 0;
}
