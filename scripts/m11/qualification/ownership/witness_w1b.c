/* Before/after witness for W1b. The SAME bytes are compiled against the pre-W1b baseline custodian
 * (baselines/round3-pre-w1b, placed beside this file so quoted includes resolve to it) and against
 * the current one. W1b: once undeclared GPR traffic was latched, a LATER retire() must still refuse;
 * in that baseline the first call refused and the second sent UNMAP under a STARTED graph.
 * Mock-only; it does not model real firmware. */
#include "m11_custodian.h"
#include "../runtime-repair/m11_apm_protocol.h"
#include "../runtime-repair/m11_strict_mock.h"
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    assert(argc==2);
    bool baseline=!strcmp(argv[1],"baseline");
    assert(baseline || !strcmp(argv[1],"fixed"));
    static m11_strict_mock_t mock; static m11_gpr_engine_t eng; static m11_shmem_mgr_t mgr;
    static m11_boot_ledger boot; static m11_custodian c;
    m11_gpr_transport_t tp; m11_shmem_backend_t be;
    m11_strict_mock_init(&mock); m11_strict_mock_bind(&mock,&tp,&be);
    assert(!m11_gpr_engine_init(&eng,&tp,0x2002u) && !m11_gpr_engine_open(&eng));
    assert(!m11_shmem_mgr_init(&mgr,&be,&eng,10) && !m11_model_new_boot(&boot,17,100));
    m11_custodian_model_contract ct={.exclusive_importer=true,.no_other_endpoint=true,
        .no_pcm_clients=true,.strict_iommu=true,.graph_quiescent=true,
        .nack_atomicity_model=true,.final_anchor_pid1=true};
    assert(!m11_custodian_init(&c,&boot,&mgr,&ct,100));
    unsigned i=UINT_MAX; uint32_t st=0;
    assert(!m11_custodian_map(&c,4096,100,&i));
    static const uint32_t rx[4]={0xB0000023u,0xB0000024u,0xB0000025u,0xB0000002u};
    assert(!m11_apm_transact_graph_open_region(&eng,&mgr,&c.regions[i],0,rx,4,10,&st));
    assert(!m11_apm_transact_graph_mgmt(&eng,M11_APM_CMD_GRAPH_PREPARE,rx,4,10,&st));
    assert(!m11_apm_transact_graph_mgmt(&eng,M11_APM_CMD_GRAPH_START,rx,4,10,&st));
    m11_custodian_worker_exit(&c,101);
    int rc1=m11_custodian_retire(&c,i,102), rc2=m11_custodian_retire(&c,i,103);
    assert(mock.rx_started);
    if (baseline) {
        /* The baseline custodian links the CURRENT region manager: its post-MAP choke point now
         * refuses the release after the UNMAP ACK, so the defect shows as the UNMAP on the wire. */
        assert(rc1==-EBUSY && (boot.reasons & M11_TAINT_FOREIGN_TRAFFIC));
        assert(rc2==-EPERM && mock.unmap_cmd_count==1 && c.occupied[i] && c.regions[i].ion_imported);
        puts("BASELINE DEFECT W1b reproduced: second retire sent UNMAP under a STARTED graph (the backing is held only by the current region manager's post-MAP choke point)");
    } else {
#if defined(M11_CUSTODIAN_API_REVISION) && M11_CUSTODIAN_API_REVISION >= 5
        /* Post-MAP hold: every retire is refused before the foreign-traffic check; the next owner
         * call that runs it (MAP) still latches the undeclared traffic. */
        assert(rc1==-EPERM && rc2==-EPERM && mock.unmap_cmd_count==0 && c.occupied[i] && c.regions[i].ion_imported);
        unsigned j=UINT_MAX;
        assert(m11_custodian_map(&c,4096,104,&j)==-EOWNERDEAD && (boot.reasons & M11_TAINT_FOREIGN_TRAFFIC));
        assert(mock.unmap_cmd_count==0 && j==UINT_MAX);
        puts("FIXED W1b: post-MAP hold refuses every retire (no UNMAP under a STARTED graph); the undeclared traffic is still latched at the next owner call");
#else
        assert(rc1==-EBUSY && (boot.reasons & M11_TAINT_FOREIGN_TRAFFIC));
        assert(rc2==-EBUSY && mock.unmap_cmd_count==0 && c.occupied[i] && c.regions[i].ion_imported);
        puts("FIXED W1b: latched foreign traffic refuses every later retire; no UNMAP under a STARTED graph");
#endif
    }
    return 0;
}
