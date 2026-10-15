#include "m11_custodian.h"
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
static m11_custodian_model_contract contract;
static unsigned cases;
static uint64_t fake_ms;
static const uint32_t RX[4]={0xB0000023u,0xB0000024u,0xB0000025u,0xB0000002u};
static const uint32_t VI[2]={0xB00000D5u,0xB00000CEu};
static int close_error(void *u, int fd) { (void)u; (void)fd; return -EIO; }
static uint64_t step_clock(void *u) { (void)u; fake_ms += 3u; return fake_ms; }
static void fixture_base(void) {
    m11_gpr_transport_t tp; m11_shmem_backend_t be;
    memset(&boot,0,sizeof(boot)); memset(&c,0,sizeof(c));
    m11_strict_mock_init(&mock); m11_strict_mock_bind(&mock,&tp,&be);
    assert(!m11_gpr_engine_init(&eng,&tp,0x2002u));
    assert(!m11_gpr_engine_open(&eng));
    assert(!m11_shmem_mgr_init(&mgr,&be,&eng,10));
    assert(!m11_model_new_boot(&boot,17,100));
    contract=(m11_custodian_model_contract){.exclusive_importer=true,.no_other_endpoint=true,
        .no_pcm_clients=true,.strict_iommu=true,.graph_quiescent=true,
        .nack_atomicity_model=true,.final_anchor_pid1=true};
}
static void fixture(void) {
    fixture_base();
    assert(!m11_custodian_init(&c,&boot,&mgr,&contract,100));
}
static unsigned map(void) {
    unsigned i=UINT_MAX;
    assert(!m11_custodian_map(&c,4096,100,&i));
    assert(i<M11_CUSTODIAN_REGIONS && c.occupied[i]);
    return i;
}
static void denied_map(void) {
    unsigned i=0; uint32_t tx=mock.tx_pkt_count, imports=mgr.active_ion_imports;
    assert(m11_custodian_map(&c,4096,boot.last_ms,&i)<0);
    assert(i==UINT_MAX && mock.tx_pkt_count==tx && mgr.active_ion_imports==imports);
}
static void safe_retention(unsigned i) {
    assert(c.occupied[i] && c.regions[i].dma_buf_fd>=0 && c.regions[i].ion_imported);
    assert(eng.is_open && mock.unsafe_release_attempts==0);
    assert(!m11_shmem_mgr_audit(&mgr,c.regions,M11_CUSTODIAN_REGIONS));
    assert(m11_custodian_close(&c)<0);
    denied_map();
}
static unsigned open_rx(unsigned region, uint64_t now) {
    unsigned g=UINT_MAX;
    assert(!m11_custodian_graph_open(&c,region,0,RX,4,now,&g));
    assert(g<M11_CUSTODIAN_GRAPHS && c.graphs[g].state==M11_GRAPH_OPEN && mock.rx_opened);
    assert(c.region_graph_refs[region]==1);
    return g;
}
static void start_rx(unsigned g, uint64_t now) {
    assert(!m11_custodian_graph_cmd(&c,g,M11_APM_CMD_GRAPH_PREPARE,now));
    assert(!m11_custodian_graph_cmd(&c,g,M11_APM_CMD_GRAPH_START,now));
    assert(c.graphs[g].state==M11_GRAPH_STARTED && mock.rx_started);
}
static void pass(const char *s) { ++cases; printf("PASS %s\n",s); }
int main(void) {
    fixture(); unsigned i=map();
    assert(m11_custodian_close(&c)==-EBUSY);
    assert(m11_custodian_terminal_action(&c)==M11_TERMINAL_HOLD && !m11_custodian_reboot_permitted(&c));
    assert(!m11_custodian_retire(&c,i,100));
    assert(mock.unmap_cmd_count==1 && !mgr.active_dma_fds);
    assert(m11_custodian_terminal_action(&c)==M11_TERMINAL_HOLD); /* endpoint still open */
    assert(!m11_custodian_close(&c)); assert(m11_custodian_close(&c)==-EALREADY);
    assert(m11_custodian_terminal_action(&c)==M11_TERMINAL_ORDERLY_SHUTDOWN);
    assert(m11_custodian_reboot_permitted(&c));
    denied_map(); pass("normal MAP/UNMAP ACK/local release/one close; reboot only when nothing is held");

    fixture(); i=map(); m11_custodian_worker_exit(&c,101);
    safe_retention(i); assert(boot.reasons&M11_TAINT_WORKER_EXIT);
    assert(!m11_custodian_retire(&c,i,102));
    assert(boot.state==M11_ADSP_TAINTED); denied_map();
    assert(m11_custodian_terminal_action(&c)==M11_TERMINAL_HOLD_RECONCILE);
    assert(m11_model_new_boot(&boot,17,102)==-EALREADY);
    m11_custodian restarted;
    assert(m11_custodian_init(&restarted,&boot,&mgr,&contract,100)==-EOWNERDEAD);
    pass("worker exit with empty graph ledger: late orderly retirement does not clear taint");

    fixture(); assert(m11_custodian_init(&restarted,&boot,&mgr,&contract,100)==-EBUSY);
    pass("single importer per boot ledger; no second owner/fd namespace");
    fixture_base(); uint32_t token=0;
    assert(!m11_gpr_engine_submit(&eng,M11_APM_MODULE_IID,M11_APM_CMD_GET_SPF_STATE,NULL,0,&token));
    assert(m11_custodian_init(&c,&boot,&mgr,&contract,100)==-EBUSY && !boot.owner_enrolled);
    pass("pending transaction from before enrollment cannot be adopted");
    fixture();
    assert(!m11_gpr_engine_submit(&eng,M11_APM_MODULE_IID,M11_APM_CMD_GET_SPF_STATE,NULL,0,&token));
    unsigned other;
    assert(m11_custodian_map(&c,4096,100,&other)==-EOWNERDEAD && !mock.map_cmd_count);
    assert(boot.reasons&M11_TAINT_FOREIGN_TRAFFIC && boot.reasons&M11_TAINT_GRAPH_UNKNOWN);
    assert(m11_custodian_close(&c)==-EOWNERDEAD && eng.is_open);
    pass("GPR traffic after enrollment that bypasses the custodian latches FOREIGN_TRAFFIC");
    fixture(); mock.hold_next_rsp=true;
    assert(!m11_gpr_engine_submit(&eng,M11_APM_MODULE_IID,M11_APM_CMD_SHARED_MEM_MAP_REGIONS,NULL,0,&token));
    assert(m11_gpr_engine_wait_token(&eng,token,10,NULL,NULL,0,NULL)==-ETIMEDOUT);
    uint32_t before=mock.tx_pkt_count;
    assert(m11_custodian_map(&c,4096,100,&other)==-EOWNERDEAD);
    assert(mock.tx_pkt_count==before && boot.reasons&M11_TAINT_REMOTE_UNKNOWN);
    pass("foreign ownership orphan taints before any allocation or MAP");
    fixture(); i=map();
    assert(!m11_gpr_engine_submit(&eng,M11_APM_MODULE_IID,M11_APM_CMD_GRAPH_OPEN,NULL,0,&token));
    assert(m11_custodian_retire(&c,i,101)==-EBUSY && !mock.unmap_cmd_count);
    safe_retention(i); pass("foreign pending graph operation blocks retirement, not merely new MAP");
    fixture(); i=map(); uint32_t st=0;
    (void)m11_gpr_query_spf_state(&eng,10,&st); /* completes or expires; never retained */
    for (unsigned k=0;k<M11_GPR_MAX_PENDING;k++) assert(!eng.slots[k].in_use);
    assert(m11_custodian_retire(&c,i,101)==-EBUSY && !mock.unmap_cmd_count);
    assert(boot.reasons&M11_TAINT_FOREIGN_TRAFFIC); safe_retention(i);
    pass("COMPLETED foreign GPR command (nothing pending) is still detected and blocks UNMAP");
    fixture(); i=map();
    assert(!m11_apm_transact_graph_open_region(&eng,&mgr,&c.regions[i],0,RX,4,10,&st));
    assert(!m11_apm_transact_graph_mgmt(&eng,M11_APM_CMD_GRAPH_PREPARE,RX,4,10,&st));
    assert(!m11_apm_transact_graph_mgmt(&eng,M11_APM_CMD_GRAPH_START,RX,4,10,&st));
    m11_custodian_worker_exit(&c,101);
    for (unsigned k=0;k<4;k++) assert(m11_custodian_retire(&c,i,102+k)==-EBUSY);
    assert(!mock.unmap_cmd_count && mock.rx_started); safe_retention(i);
    assert(!m11_custodian_graph_teardown(&c,106)); /* the ledger has nothing it may close */
    assert(m11_custodian_retire(&c,i,107)==-EBUSY && !mock.unmap_cmd_count);
    pass("latched foreign traffic refuses EVERY later retire (W1b): no UNMAP under an undeclared STARTED graph");
    /* Counterexamples from the adversarial W1 matrix, kept as directed regressions. */
    fixture(); i=map(); unsigned gx=open_rx(i,100); start_rx(gx,101);
    assert(!m11_apm_transact_graph_mgmt(&eng,M11_APM_CMD_GRAPH_STOP,RX,4,10,&st));
    assert(!m11_apm_transact_graph_mgmt(&eng,M11_APM_CMD_GRAPH_CLOSE,RX,4,10,&st));
    assert(!mock.rx_opened && c.graphs[gx].state==M11_GRAPH_STARTED);
    assert(m11_custodian_retire(&c,i,102)==-EBUSY);           /* detection call */
    assert(!m11_custodian_graph_teardown(&c,103) && c.graphs[gx].state==M11_GRAPH_FREE);
    for (unsigned k=0;k<3;k++) assert(m11_custodian_retire(&c,i,104+k)==-EBUSY);
    assert(!mock.unmap_cmd_count); safe_retention(i);
    pass("foreign STOP/CLOSE of a ledger graph: even after a clean ledger teardown, no UNMAP this boot");
    fixture(); i=map(); unsigned j2=map(); gx=open_rx(i,100);
    assert(!m11_apm_transact_graph_open_region(&eng,&mgr,&c.regions[j2],0,VI,2,10,&st));
    assert(m11_custodian_graph_teardown(&c,101)==-EOWNERDEAD); /* detection call */
    assert(!m11_custodian_graph_teardown(&c,102) && mock.vi_tx_opened && !mock.rx_opened);
    assert(m11_custodian_retire(&c,i,103)==-EBUSY && m11_custodian_retire(&c,j2,104)==-EBUSY);
    assert(m11_custodian_retire(&c,i,105)==-EBUSY && !mock.unmap_cmd_count);
    safe_retention(i); safe_retention(j2);
    pass("undeclared second graph on another region keeps every region pinned after ledger teardown");
    fixture(); i=map(); gx=open_rx(i,100); mock.hold_next_rsp=true;
    assert(m11_custodian_graph_cmd(&c,gx,M11_APM_CMD_GRAPH_CLOSE,101)==-ETIMEDOUT);
    assert(!mock.rx_opened && c.graphs[gx].state==M11_GRAPH_UNKNOWN);
    assert(m11_strict_mock_release_held(&mock)==1);
    assert(m11_custodian_retire(&c,i,102)==-EBUSY);
    assert(c.graphs[gx].state==M11_GRAPH_UNKNOWN && !mock.unmap_cmd_count);
    assert(m11_custodian_graph_teardown(&c,103)==-EOWNERDEAD);
    assert(m11_custodian_retire(&c,i,104)==-EBUSY && !mock.unmap_cmd_count); safe_retention(i);
    pass("late GRAPH_CLOSE ACK cannot resolve an UNKNOWN graph; region stays pinned");
    fixture(); i=map(); gx=open_rx(i,100);
    assert(!m11_custodian_graph_cmd(&c,gx,M11_APM_CMD_GRAPH_PREPARE,101));
    mock.hold_next_rsp=true;
    assert(m11_custodian_graph_cmd(&c,gx,M11_APM_CMD_GRAPH_START,102)==-ETIMEDOUT && mock.rx_started);
    m11_custodian_worker_exit(&c,103);
    assert(m11_custodian_graph_teardown(&c,104)==-EOWNERDEAD && mock.rx_started);
    for (unsigned k=0;k<3;k++) assert(m11_custodian_retire(&c,i,105+k)==-EBUSY);
    assert(m11_custodian_tick(&c,203)==-EOWNERDEAD && m11_custodian_retire(&c,i,203)==-EOWNERDEAD);
    assert(!mock.unmap_cmd_count);
    assert(m11_custodian_terminal_action(&c)==M11_TERMINAL_RESET_RETAINING_ANCHORS); safe_retention(i);
    pass("worker death after a late START ACK: no teardown claim, no UNMAP, terminal reset retaining anchors");
    fixture(); assert(!m11_gpr_engine_close(&eng));
    assert(m11_gpr_engine_open(&eng)==-EBUSY); /* engine never reopens in one session */
    assert(m11_custodian_map(&c,4096,100,&other)==-EOWNERDEAD && !mock.map_cmd_count);
    assert(boot.reasons&M11_TAINT_FOREIGN_TRAFFIC);
    pass("foreign endpoint close is detected through engine close counter; no reopen");
    fixture(); i=map(); unsigned second=map(); mock.hold_next_rsp=true;
    assert(m11_custodian_retire(&c,i,101)==-ETIMEDOUT);
    assert(!m11_custodian_retire(&c,second,102));
    assert(m11_strict_mock_release_held(&mock)==1);
    assert(!m11_custodian_retire(&c,i,103));
    assert(mock.unmap_cmd_count==2 && !mgr.active_ion_imports);
    assert(!(boot.reasons&M11_TAINT_FOREIGN_TRAFFIC));
    denied_map(); pass("another owned orphan does not deadlock independent region retirement");
    fixture(); i=map(); c.contract.graph_quiescent=false;
    assert(m11_custodian_retire(&c,i,100)==-EBUSY && !mock.unmap_cmd_count);
    safe_retention(i); pass("unconfirmed graph quiescence forbids UNMAP/free");
    fixture(); c.contract.graph_quiescent=false;
    assert(m11_custodian_close(&c)==-EBUSY && eng.is_open);
    assert(boot.reasons&M11_TAINT_GRAPH_UNKNOWN); denied_map();
    pass("graph unknown forbids last-close even with no recorded regions");
    fixture(); eng.transport.close_fn=close_error;
    assert(m11_custodian_close(&c)==-EIO && c.closed);
    assert(m11_custodian_close(&c)==-EALREADY);
    assert(boot.reasons&M11_TAINT_LOCAL_ERROR); denied_map();
    assert(m11_custodian_terminal_action(&c)==M11_TERMINAL_HOLD_RECONCILE);
    pass("endpoint close error does not trigger unsafe fd retry/reopen");

    fixture(); mock.hold_next_rsp=true;
    assert(m11_custodian_map(&c,4096,100,&i)==-ETIMEDOUT);
    assert(mock.shm_slots[0].dsp_map_handle && c.regions[i].orphan_token);
    safe_retention(i);
    assert(m11_strict_mock_release_held(&mock)==1);
    assert(!m11_custodian_retire(&c,i,101));
    assert(mock.map_cmd_count==1 && mock.unmap_cmd_count==1);
    assert(!mgr.active_ion_imports && boot.state==M11_ADSP_TAINTED);
    denied_map(); pass("lost/late MAP ACK reconciles exact token, no MAP resend");

    fixture(); i=map(); mock.hold_next_rsp=true;
    assert(m11_custodian_retire(&c,i,101)==-ETIMEDOUT); safe_retention(i);
    assert(!mock.shm_slots[0].dsp_map_handle); /* remote already unmapped, ACK lost */
    assert(m11_strict_mock_release_held(&mock)==1);
    assert(!m11_custodian_retire(&c,i,102));
    assert(mock.unmap_cmd_count==1); denied_map();
    pass("lost/late UNMAP ACK releases only after reconciliation, no resend");

    fixture(); mock.hold_next_rsp=true;
    assert(m11_custodian_map(&c,4096,100,&i)==-ETIMEDOUT);
    assert(m11_strict_mock_release_held(&mock)==1);
    m11_gpr_engine_set_clock(&eng,step_clock,NULL);
    assert(m11_custodian_retire(&c,i,101)==-ETIMEDOUT && mock.unmap_cmd_count==0);
    assert(c.regions[i].state==M11_SHMEM_STATE_DSP_MAP_ACKNOWLEDGED);
    assert(!m11_custodian_retire(&c,i,102) && mock.unmap_cmd_count==1);
    pass("shared reconcile+UNMAP budget is measured on the engine clock, not wall time");

    fixture(); mock.wrong_peer_on_rsp=true;
    assert(m11_custodian_map(&c,4096,100,&i)==-ETIMEDOUT); safe_retention(i);
    pass("wrong peer cannot resolve ownership");
    fixture(); mock.wrong_token_on_rsp=true;
    assert(m11_custodian_map(&c,4096,100,&i)==-ETIMEDOUT); safe_retention(i);
    pass("wrong token cannot resolve ownership");
    fixture(); mock.wrong_opcode_on_rsp=true;
    assert(m11_custodian_map(&c,4096,100,&i)<0); safe_retention(i);
    pass("wrong opcode cannot resolve ownership");
    fixture(); mock.zero_handle_shmem_map_rsp=true;
    assert(m11_custodian_map(&c,4096,100,&i)==-EREMOTEIO); safe_retention(i);
    assert(m11_custodian_retire(&c,i,101)==-ENOENT); safe_retention(i);
    pass("invalid MAP handle cannot authorize release");

    fixture(); mock.nack_shmem_map=true;
    assert(m11_custodian_map(&c,4096,100,&i)==-EREMOTEIO);
    assert(!c.occupied[i] && !mgr.active_dma_fds && boot.state==M11_ADSP_CLEAN);
    pass("atomic MAP NACK rollback MODEL ONLY");
    fixture(); i=map(); mock.nack_shmem_unmap=true;
    assert(m11_custodian_retire(&c,i,101)==-EREMOTEIO); safe_retention(i);
    pass("UNMAP NACK retains backing and taints");

    fixture(); mock.deliver_then_fail_write_on_map=true;
    assert(m11_custodian_map(&c,4096,100,&i)==-EIO); safe_retention(i);
    assert(!m11_custodian_retire(&c,i,101));
    assert(mock.map_cmd_count==1 && mock.unmap_cmd_count==1); denied_map();
    pass("write error after remote MAP delivery reconciles without replay");
    fixture(); mock.short_gpr_write_on_map=true;
    assert(m11_custodian_map(&c,4096,100,&i)<0); safe_retention(i);
    pass("short MAP write quarantines instead of rollback");

    fixture(); i=map(); mock.fail_ion_unmap=true;
    assert(m11_custodian_retire(&c,i,101)==-EIO); safe_retention(i);
    assert(c.regions[i].remote_inactive); mock.fail_ion_unmap=false;
    assert(!m11_custodian_retire(&c,i,102) && mock.unmap_cmd_count==1);
    denied_map(); pass("local ION release failure retains record; retry does not resend UNMAP");
    fixture(); i=map(); mock.fail_close_fd=true;
    assert(m11_custodian_retire(&c,i,101)==-EIO);
    assert(c.regions[i].dma_buf_fd>=0 && !c.regions[i].ion_imported);
    mock.fail_close_fd=false;
    assert(!m11_custodian_retire(&c,i,102) && mock.unmap_cmd_count==1);
    denied_map(); pass("retrying retained-fd MOCK contract; raw close adapter still BLOCKED");
    fixture(); i=map(); mock.fail_dma_buf_sync_end=true; mock.sync_end_errno=-EPIPE;
    assert(m11_custodian_retire(&c,i,101)==-EPIPE);
    assert(!c.occupied[i] && !mgr.active_dma_fds && boot.reasons&M11_TAINT_LOCAL_ERROR);
    denied_map(); pass("released handles with END error are not clean teardown");

    /* ------------------------------ graph ledger ------------------------------ */
    fixture(); i=map(); unsigned g=open_rx(i,100); start_rx(g,101);
    uint32_t tx=mock.tx_pkt_count;
    assert(m11_custodian_retire(&c,i,102)==-EBUSY && !mock.unmap_cmd_count && mock.tx_pkt_count==tx);
    assert(m11_custodian_close(&c)==-EBUSY && eng.is_open);
    assert(m11_custodian_graph_cmd(&c,g,M11_APM_CMD_GRAPH_CLOSE,102)==-EPROTO && mock.tx_pkt_count==tx);
    assert(m11_custodian_terminal_action(&c)==M11_TERMINAL_HOLD && !m11_custodian_reboot_permitted(&c));
    assert(!m11_custodian_graph_teardown(&c,103));
    assert(!mock.rx_started && !mock.rx_opened && c.graphs[g].state==M11_GRAPH_FREE);
    assert(c.region_graph_refs[i]==0 && boot.state==M11_ADSP_CLEAN);
    assert(!m11_custodian_retire(&c,i,104) && mock.unmap_cmd_count==1);
    assert(!m11_custodian_close(&c) && m11_custodian_reboot_permitted(&c));
    pass("stock ordering: graph STOP/CLOSE ACK before UNMAP; STARTED graph cannot skip STOP");

    fixture(); i=map(); g=open_rx(i,100); start_rx(g,101);
    m11_custodian_worker_exit(&c,102);
    assert(m11_custodian_retire(&c,i,103)==-EBUSY && !mock.unmap_cmd_count);
    safe_retention(i);
    unsigned g2=UINT_MAX;
    assert(m11_custodian_graph_open(&c,i,0,VI,2,103,&g2)==-EOWNERDEAD && g2==UINT_MAX);
    assert(!m11_custodian_graph_teardown(&c,104) && !mock.rx_started && !mock.rx_opened);
    assert(!m11_custodian_retire(&c,i,105) && mock.unmap_cmd_count==1);
    assert(boot.state==M11_ADSP_TAINTED && boot.reasons&M11_TAINT_WORKER_EXIT);
    assert(m11_custodian_terminal_action(&c)==M11_TERMINAL_HOLD_RECONCILE);
    assert(m11_custodian_tick(&c,202)==-EOWNERDEAD);
    assert(m11_custodian_terminal_action(&c)==M11_TERMINAL_RESET_RETAINING_ANCHORS);
    assert(m11_custodian_request_recovery(&c)==-ENOTSUP);
    pass("worker death under a STARTED graph: no UNMAP until custodian STOP/CLOSE ACK; taint stays");

    fixture(); i=map(); unsigned j=map(); mock.drop_graph_open_rsp=true;
    assert(m11_custodian_graph_open(&c,i,0,RX,4,100,&g)==-ETIMEDOUT);
    assert(g<M11_CUSTODIAN_GRAPHS && c.graphs[g].state==M11_GRAPH_UNKNOWN);
    assert(boot.reasons&M11_TAINT_GRAPH_UNKNOWN);
    assert(m11_custodian_retire(&c,j,101)==-EBUSY && m11_custodian_retire(&c,i,101)==-EBUSY);
    assert(m11_custodian_graph_teardown(&c,101)==-EOWNERDEAD);
    assert(m11_custodian_graph_cmd(&c,g,M11_APM_CMD_GRAPH_CLOSE,101)==-EOWNERDEAD);
    assert(!mock.unmap_cmd_count); safe_retention(i); safe_retention(j);
    assert(m11_custodian_tick(&c,200)==-EOWNERDEAD);
    assert(m11_custodian_terminal_action(&c)==M11_TERMINAL_RESET_RETAINING_ANCHORS);
    pass("lost GRAPH_OPEN reply: graph UNKNOWN pins every region until terminal reset");

    fixture(); i=map(); g=open_rx(i,100); mock.drop_graph_close_rsp=true;
    assert(m11_custodian_graph_cmd(&c,g,M11_APM_CMD_GRAPH_CLOSE,101)==-ETIMEDOUT);
    assert(c.graphs[g].state==M11_GRAPH_UNKNOWN && mock.rx_opened);
    assert(m11_custodian_retire(&c,i,102)==-EBUSY && !mock.unmap_cmd_count);
    safe_retention(i); pass("lost GRAPH_CLOSE reply: graph UNKNOWN, region retained");

    fixture(); i=map(); g=open_rx(i,100); mock.nack_graph_close=true;
    assert(m11_custodian_graph_cmd(&c,g,M11_APM_CMD_GRAPH_CLOSE,101)==-EREMOTEIO);
    assert(c.graphs[g].state==M11_GRAPH_OPEN && boot.state==M11_ADSP_CLEAN);
    assert(m11_custodian_retire(&c,i,102)==-EBUSY && !mock.unmap_cmd_count);
    mock.nack_graph_close=false;
    assert(!m11_custodian_graph_cmd(&c,g,M11_APM_CMD_GRAPH_CLOSE,103));
    assert(!m11_custodian_retire(&c,i,104) && mock.unmap_cmd_count==1);
    pass("GRAPH_CLOSE NACK keeps graph OPEN (atomic-NACK MODEL); region pinned until CLOSE ACK");

    fixture(); i=map(); mock.nack_graph_open=true;
    assert(m11_custodian_graph_open(&c,i,0,RX,4,100,&g)==-EREMOTEIO && g==UINT_MAX);
    assert(!c.region_graph_refs[i] && boot.state==M11_ADSP_CLEAN);
    assert(!m11_custodian_retire(&c,i,101) && mock.unmap_cmd_count==1);
    pass("GRAPH_OPEN NACK releases the ledger slot (atomic-NACK MODEL)");

    fixture(); i=map(); mock.fail_gpr_write_on_graph_open=true;
    assert(m11_custodian_graph_open(&c,i,0,RX,4,100,&g)<0);
    assert(g<M11_CUSTODIAN_GRAPHS && c.graphs[g].state==M11_GRAPH_UNKNOWN);
    assert(m11_custodian_retire(&c,i,101)==-EBUSY && !mock.unmap_cmd_count);
    safe_retention(i); pass("GRAPH_OPEN write error after packing: graph UNKNOWN, no UNMAP");

    fixture(); i=map(); g=open_rx(i,100);
    assert(!m11_custodian_graph_cmd(&c,g,M11_APM_CMD_GRAPH_PREPARE,101));
    m11_custodian_worker_exit(&c,102); tx=mock.tx_pkt_count;
    assert(m11_custodian_graph_cmd(&c,g,M11_APM_CMD_GRAPH_START,102)==-EOWNERDEAD);
    assert(mock.tx_pkt_count==tx && !mock.rx_started);
    assert(!m11_custodian_graph_cmd(&c,g,M11_APM_CMD_GRAPH_CLOSE,103) && !mock.rx_opened);
    pass("tainted boot refuses PREPARE/START; STOP/CLOSE teardown stays available");

    fixture(); i=map(); g=open_rx(i,100); tx=mock.tx_pkt_count;
    assert(m11_custodian_graph_open(&c,i,0,RX,4,100,&g2)==-EEXIST);
    assert(m11_custodian_graph_open(&c,3,0,VI,2,100,&g2)==-EINVAL);
    assert(m11_custodian_graph_open(&c,i,0,VI,0,100,&g2)==-EINVAL);
    assert(m11_custodian_graph_cmd(&c,g,0x01001006u,100)==-EINVAL);
    assert(mock.tx_pkt_count==tx); pass("graph ledger rejects overlap, unmapped region, empty list, non-graph opcode");

    fixture(); i=map(); m11_custodian_pd_down(&c,101);
    safe_retention(i); assert(m11_custodian_retire(&c,i,102)==-EOWNERDEAD);
    eng.pdr_down=false; denied_map();
    assert(m11_custodian_request_recovery(&c)==-ENOTSUP);
    assert(m11_custodian_terminal_action(&c)==M11_TERMINAL_RESET_RETAINING_ANCHORS);
    pass("PDR DOWN/UP does not prove ADSP quiescence or clear taint");
    fixture(); i=map(); m11_custodian_owner_exit(&c,101);
    safe_retention(i); assert(!boot.owner_alive);
    assert(m11_custodian_retire(&c,i,102)==-EOWNERDEAD);
    assert(!mock.unmap_cmd_count);
    assert(m11_custodian_terminal_action(&c)==M11_TERMINAL_RESET_RETAINING_ANCHORS);
    pass("custodian death marks records unknown; no fabricated cleanup");
    fixture(); i=map(); m11_custodian_global_cleanup(&c,101);
    safe_retention(i); assert(m11_custodian_retire(&c,i,102)==-EOWNERDEAD);
    pass("ASoC global crash cleanup invalidates import even with held DMA fd");

    /* --------------------------- terminal boundary ---------------------------- */
    fixture(); i=map(); m11_custodian_supervisor_exit(&c,true,101);
    assert(boot.supervisor_dead && !boot.final_anchor_released && boot.state==M11_RECOVERY_REQUIRED);
    assert(m11_custodian_terminal_action(&c)==M11_TERMINAL_RESET_RETAINING_ANCHORS);
    assert(!m11_custodian_reboot_permitted(&c) && !mock.unmap_cmd_count && c.regions[i].ion_imported);
    pass("PID1 final-anchor death: modeled panic before exit_files, no release, reset only");
    fixture(); i=map(); m11_custodian_supervisor_exit(&c,false,101);
    assert(boot.final_anchor_released && boot.reasons&M11_TAINT_GLOBAL_CLEANUP);
    assert(m11_custodian_terminal_action(&c)==M11_TERMINAL_UNSAFE_LAST_CLOSE_OCCURRED);
    assert(!m11_custodian_reboot_permitted(&c));
    pass("non-PID1 final-anchor death reaches kernel last-close: reported UNSAFE, never clean");

    fixture(); i=map(); m11_custodian_worker_exit(&c,101);
    assert(boot.recovery_due_ms==201);
    m11_custodian_worker_exit(&c,150); assert(boot.recovery_due_ms==201);
    assert(!m11_custodian_tick(&c,200));
    assert(m11_custodian_tick(&c,201)==-EOWNERDEAD);
    assert(m11_custodian_retire(&c,i,201)==-EOWNERDEAD); safe_retention(i);
    assert(m11_custodian_request_recovery(&c)==-ENOTSUP);
    pass("finite escalation deadline, never extended; no unsafe timeout free");
    fixture(); i=map(); assert(m11_custodian_tick(&c,99)==-ERANGE);
    safe_retention(i); pass("clock regression permanently closes admission");
    fixture(); c.call_inflight=true;
    unsigned dummy; assert(m11_custodian_map(&c,4096,100,&dummy)==-EBUSY);
    assert(!mock.tx_pkt_count); pass("serialized custody rejects concurrent MAP");
    fixture(); for(unsigned k=0;k<M11_CUSTODIAN_REGIONS;k++) (void)map();
    assert(m11_custodian_map(&c,4096,100,&dummy)==-ENOSPC);
    assert(mock.map_cmd_count==M11_CUSTODIAN_REGIONS); pass("bounded region registry");

    for(unsigned bit=0;bit<7;bit++) {
        fixture(); boot.owner_enrolled=false;
        switch(bit) {
        case 0:contract.exclusive_importer=false;break;
        case 1:contract.no_other_endpoint=false;break;
        case 2:contract.no_pcm_clients=false;break;
        case 3:contract.strict_iommu=false;break;
        case 4:contract.graph_quiescent=false;break;
        case 5:contract.nack_atomicity_model=false;break;
        default:contract.final_anchor_pid1=false;break;
        }
        assert(m11_custodian_init(&restarted,&boot,&mgr,&contract,100)==-EPERM);
        assert(!boot.owner_enrolled); pass("missing model precondition denies enrollment");
    }

    /* Effective cmdline gate, tokenized like ACK lib/cmdline.c next_arg(). */
    const char *good[]={"console=null iommu.strict=1","console=null","iommu.strict=\"1\"",
        "\"iommu.strict=1\"","iommu.passthrough=0","  iommu.strict=1   ","iommu_strict=0",
        "foo=\"a iommu.strict=0\"","iommu.strict=1 iommu.passthrough=0"};
    for(unsigned k=0;k<sizeof(good)/sizeof(good[0]);k++) assert(m11_custodian_cmdline_allowed(good[k]));
    const char *bad[]={NULL,"iommu.strict=0","iommu.strict=false","iommu.strict=off",
        "iommu.strict=1 iommu.strict=0","iommu.strict=", "iommu.strict=1garbage",
        "\"iommu.strict=0\"","iommu.strict=\"0\"","x\tiommu.strict=0","x\xa0" "iommu.strict=0",
        "iommu.passthrough=1","iommu.passthrough=y","iommu.passthrough=on","iommu.passthrough",
        "iommu.strict","a -- iommu.strict=0"};
    for(unsigned k=0;k<sizeof(bad)/sizeof(bad[0]);k++) assert(!m11_custodian_cmdline_allowed(bad[k]));
    static char overlong[5000]; memset(overlong,'a',sizeof(overlong)-1);
    assert(!m11_custodian_cmdline_allowed(overlong));
    pass("cmdline gate: kernel-faithful quotes/whitespace; rejects relaxed strict and passthrough");
    /* F1: pinned next_arg() reads args[i-1] with unsigned i==0 for a final lone '"'. */
    const char *ub[]={"\"","console=null \"","foo=bar \"","iommu.strict=1 \"","\t\""};
    for(unsigned k=0;k<sizeof(ub)/sizeof(ub[0]);k++) assert(!m11_custodian_cmdline_allowed(ub[k]));
    const char *near_ub[]={"console=null \"x\"","a \"   ","foo=\"","foo=bar \"\""};
    for(unsigned k=0;k<sizeof(near_ub)/sizeof(near_ub[0]);k++) assert(m11_custodian_cmdline_allowed(near_ub[k]));
    pass("cmdline gate rejects a final lone quote (pinned next_arg out-of-bounds read), not its safe neighbours");

    /* Independent destructive-release/IOMMU model. A DMA fd keeps backing alive,
     * but global cleanup still removes its attachment. Reuse exposes another buffer. */
    fixture(); i=map(); uint64_t old_iova=mock.shm_slots[0].kernel_iova;
    uint32_t remote_handle=mock.shm_slots[0].dsp_map_handle;
    mock.shm_slots[0].ion_imported=false; /* independent last-close/global cleanup model */
    assert(remote_handle && old_iova && mock.shm_slots[0].allocated);
    m11_custodian_global_cleanup(&c,101); denied_map();
    /* Counterfactual unguarded allocator: an old DSP address resolves to NEW
     * backing after reuse, although the old backing is still independently held. */
    unsigned char old_backing=0x11, new_backing=0x22;
    unsigned char *translation=&old_backing;
    translation=NULL; /* synchronous IOVA unmap before backing-reference drop */
    assert(!translation && old_backing==0x11); /* late access would fault here */
    uint64_t reused_iova=old_iova;
    translation=&new_backing; /* same-size allocator reuse: synthetic counterexample */
    assert(reused_iova==old_iova);
    *translation=0x99; /* stale DSP access now corrupts the new owner's bytes */
    assert(new_backing==0x99 && old_backing==0x11 && mock.map_cmd_count==1);
    assert(m11_custodian_request_recovery(&c)==-ENOTSUP);
    pass("IOVA-reuse counterexample denied while tainted; holding backing does not hold mapping");
    struct { int fd; unsigned char *backing; } global_list[2]={
        {100,&old_backing},{100,&new_backing}};
    unsigned char *resolved=NULL;
    for(unsigned k=0;k<2;k++) if(global_list[k].fd==100) { resolved=global_list[k].backing; break; }
    assert(resolved==&old_backing && resolved!=global_list[1].backing);
    pass("raw-fd global lookup aliases equal process fd numbers; exclusivity remains a precondition");
    printf("Custodian qualification: %u cases PASS; physical runtime and recovery BLOCKED\n",cases);
    return 0;
}
