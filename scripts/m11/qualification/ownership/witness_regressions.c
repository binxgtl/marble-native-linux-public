/* Before/after witness. The SAME bytes are compiled against the round-2 baseline custodian
 * (baselines/round2, placed beside this file so quoted includes resolve to it) and against the current
 * one. Uses only API common to both. Mock-only; it does not model real firmware. */
#include "m11_custodian.h"
#include "../runtime-repair/m11_apm_protocol.h"
#include "../runtime-repair/m11_strict_mock.h"
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
static uint64_t fake_ms;
static uint64_t step_clock(void *u) { (void)u; fake_ms += 3u; return fake_ms; }

static void fixture(void) {
    m11_gpr_transport_t tp; m11_shmem_backend_t be;
    memset(&boot,0,sizeof(boot)); memset(&c,0,sizeof(c));
    m11_strict_mock_init(&mock); m11_strict_mock_bind(&mock,&tp,&be);
    assert(!m11_gpr_engine_init(&eng,&tp,0x2002u));
    assert(!m11_gpr_engine_open(&eng));
    assert(!m11_shmem_mgr_init(&mgr,&be,&eng,10));
    assert(!m11_model_new_boot(&boot,17,100));
    m11_custodian_model_contract ct={.exclusive_importer=true,.no_other_endpoint=true,
        .no_pcm_clients=true,.strict_iommu=true,.graph_quiescent=true,.nack_atomicity_model=true};
#if defined(M11_CUSTODIAN_API_REVISION) && M11_CUSTODIAN_API_REVISION >= 3
    ct.final_anchor_pid1=true;
#endif
    assert(!m11_custodian_init(&c,&boot,&mgr,&ct,100));
}

int main(int argc, char **argv) {
    assert(argc==2);
    bool baseline=!strcmp(argv[1],"baseline");
    assert(baseline || !strcmp(argv[1],"fixed"));

    /* W1: a graph opened outside the custodian's knowledge (old design: worker-side)
     * is STARTED when the worker dies. Retirement must not UNMAP under it. */
    fixture(); unsigned i=UINT_MAX;
    assert(!m11_custodian_map(&c,4096,100,&i));
    static const uint32_t rx[4]={0xB0000023u,0xB0000024u,0xB0000025u,0xB0000002u};
    uint32_t st=0;
    assert(!m11_apm_transact_graph_open_region(&eng,&mgr,&c.regions[i],0,rx,4,10,&st));
    assert(!m11_apm_transact_graph_mgmt(&eng,M11_APM_CMD_GRAPH_PREPARE,rx,4,10,&st));
    assert(!m11_apm_transact_graph_mgmt(&eng,M11_APM_CMD_GRAPH_START,rx,4,10,&st));
    assert(mock.rx_started);
    m11_custodian_worker_exit(&c,101);
    int rc=m11_custodian_retire(&c,i,102);
    if (baseline) {
        /* The baseline custodian links the CURRENT region manager: its post-MAP choke point now
         * refuses the release after the UNMAP ACK, so the defect shows as the UNMAP on the wire. */
        assert(rc==-EPERM && mock.unmap_cmd_count==1 && mock.rx_started && c.occupied[i] && c.regions[i].ion_imported);
        puts("BASELINE DEFECT W1 reproduced: UNMAP sent while the modeled graph is STARTED (the backing is held only by the current region manager's post-MAP choke point)");
    } else {
        assert(rc<0 && mock.unmap_cmd_count==0 && c.occupied[i] && c.regions[i].ion_imported);
#if defined(M11_CUSTODIAN_API_REVISION) && M11_CUSTODIAN_API_REVISION >= 5
        assert(rc==-EPERM);
        puts("FIXED W1: no UNMAP under a running graph (post-MAP hold: retire refused after the MAP intent)");
#else
        puts("FIXED W1: undeclared GPR traffic latches FOREIGN_TRAFFIC; no UNMAP under a running graph");
#endif
    }

    /* W2: late-MAP reconcile and UNMAP share one budget, measured on the ENGINE clock.
     * Engine clock advances 3 ms per read: reconcile succeeds inside its own 10 ms wait,
     * but the shared budget is spent (12 ms) before UNMAP could start. */
    fixture(); mock.hold_next_rsp=true;
    assert(m11_custodian_map(&c,4096,100,&i)==-ETIMEDOUT);
    assert(m11_strict_mock_release_held(&mock)==1);
    m11_gpr_engine_set_clock(&eng,step_clock,NULL);
    rc=m11_custodian_retire(&c,i,101);
    if (baseline) {
        assert(rc==-EPERM && mock.unmap_cmd_count==1 && c.regions[i].ion_imported); /* release refused: choke point */
        puts("BASELINE DEFECT W2 reproduced: wall-clock elapsed ignores engine-clock budget; UNMAP sent after budget spent");
    } else {
#if defined(M11_CUSTODIAN_API_REVISION) && M11_CUSTODIAN_API_REVISION >= 5
        /* Post-MAP hold: no reconcile and no UNMAP after the MAP intent, whatever the budget. */
        assert(rc==-EPERM && mock.unmap_cmd_count==0 &&
               c.regions[i].state==M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED && c.regions[i].ion_imported);
        assert(m11_custodian_retire(&c,i,102)==-EPERM && mock.unmap_cmd_count==0 && c.occupied[i]);
        puts("FIXED W2: post-MAP hold: the late-MAP region is never reconciled or unmapped, it stays held (no UNMAP with or without budget)");
#else
        assert(rc==-ETIMEDOUT && mock.unmap_cmd_count==0 &&
               c.regions[i].state==M11_SHMEM_STATE_DSP_MAP_ACKNOWLEDGED);
        assert(!m11_custodian_retire(&c,i,102) && mock.unmap_cmd_count==1);
        puts("FIXED W2: shared budget measured on the engine clock; UNMAP only with remaining budget");
#endif
    }

    /* W3: kernel next_arg() strips a leading quote, so "iommu.strict=0" relaxes
     * strictness; iommu.passthrough=1 selects an identity (untranslated) domain. */
    bool q=m11_custodian_cmdline_allowed("console=null \"iommu.strict=0\"");
    bool p=m11_custodian_cmdline_allowed("console=null iommu.passthrough=1");
    if (baseline) {
        assert(q && p);
        puts("BASELINE DEFECT W3 reproduced: quoted iommu.strict=0 and iommu.passthrough=1 accepted");
    } else {
        assert(!q && !p);
        puts("FIXED W3: kernel-faithful tokenizer rejects quoted relaxation and passthrough");
    }
    printf("witness mode=%s complete\n", argv[1]);
    return 0;
}
