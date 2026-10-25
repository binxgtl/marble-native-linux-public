#include "m11_custodian.h"
#include "../runtime-repair/m11_strict_mock.h"
#include "../runtime-repair/m11_aw_protection.h"
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
/* Rev 6 owner session calls (P5 speaker, W5b): the AW Re round trip through m11_custodian_cfg. */
static unsigned rt_graph;
static int via_custodian(void *u, uint32_t dst, uint32_t op, const void *pkt, size_t len, uint32_t t,
                         void *rsp, size_t cap, size_t *rl, bool *handed) {
    (void)u; (void)t;
    return m11_custodian_cfg(&c,rt_graph,dst,op,pkt,(uint32_t)len,boot.last_ms,rsp,cap,rl,handed);
}
static void rev6_session(void) {
    uint8_t blob[256]; m11_apm_cmd_header_t h; size_t w=0;
    assert(!m11_apm_build_graph_open_oob(blob,sizeof blob,0,1,VI,2,&h,&w) && h.payload_size==w);
    fixture(); unsigned i=map(), j=map(); uint32_t tx=mock.tx_pkt_count;
    /* region_write: registry and bounds before any sync; the write ENDs the bracket (clean for the DSP) */
    uint8_t pat[32]; memset(pat,0x5a,sizeof pat);
    assert(m11_custodian_region_write(&c,i,(uint32_t)c.regions[i].aligned_bytes-4u,pat,8,101)==-EINVAL);
    assert(m11_custodian_region_write(&c,3,0,pat,8,101)==-EINVAL);
    assert(m11_custodian_region_write(&c,i,0,pat,0,101)==-EINVAL);
    assert(!m11_custodian_region_write(&c,j,64,pat,32,101));
    assert(!memcmp((uint8_t *)c.regions[j].vaddr+64,pat,32) && !c.regions[j].cpu_access_active &&
           c.regions[j].cpu_cache_clean_for_dsp && mock.tx_pkt_count==tx);
    /* GRAPH_OPEN with the caller's payload (a SUB_GRAPH_LIST block the strict mock parses) */
    unsigned gv=UINT_MAX, gr=UINT_MAX, g2=UINT_MAX;
    assert(m11_custodian_graph_open_blob(&c,i,4090,blob,h.payload_size,VI,2,102,&gv)==-EINVAL && gv==UINT_MAX);
    assert(m11_custodian_graph_open_blob(&c,i,1024,blob,h.payload_size,VI,0,102,&gv)==-EINVAL);
    assert(mock.tx_pkt_count==tx);
    assert(!m11_custodian_graph_open_blob(&c,i,1024,blob,h.payload_size,VI,2,102,&gv));
    assert(gv<M11_CUSTODIAN_GRAPHS && c.graphs[gv].state==M11_GRAPH_OPEN && mock.vi_tx_opened && c.region_graph_refs[i]==1);
    assert(!memcmp((uint8_t *)c.regions[i].vaddr+1024,blob,h.payload_size));
    assert(m11_custodian_graph_open_blob(&c,i,2048,blob,h.payload_size,VI,2,102,&g2)==-EEXIST && g2==UINT_MAX);
    pass("rev 6: region_write and graph_open_blob refuse before any TX; the caller's GRAPH_OPEN payload opens a ledger graph");
    /* cfg: in band only, SET/GET only, a live graph only; refused before any TX */
    m11_apm_aw_re_cfg_pkt_t cfg; memset(&cfg,0,sizeof cfg);
    cfg.cmd_hdr.payload_size=sizeof cfg.env;
    assert(!m11_aw_build_re_envelope_48(0,6372,&cfg.env));
    tx=mock.tx_pkt_count;
    assert(m11_custodian_cfg(&c,gv^1u,0x42D3u,M11_APM_CMD_SET_CFG,&cfg,sizeof cfg,103,NULL,0,NULL,NULL)==-EPROTO);
    assert(m11_custodian_cfg(&c,gv,0x42D3u,M11_APM_CMD_GRAPH_START,&cfg,sizeof cfg,103,NULL,0,NULL,NULL)==-EINVAL);
    m11_apm_aw_re_cfg_pkt_t bad=cfg; bad.cmd_hdr.mem_map_handle=c.regions[i].mem_map_handle;
    assert(m11_custodian_cfg(&c,gv,0x42D3u,M11_APM_CMD_SET_CFG,&bad,sizeof bad,103,NULL,0,NULL,NULL)==-EINVAL);
    bad=cfg; bad.cmd_hdr.payload_size=8;
    assert(m11_custodian_cfg(&c,gv,0x42D3u,M11_APM_CMD_SET_CFG,&bad,sizeof bad,103,NULL,0,NULL,NULL)==-EINVAL);
    assert(m11_custodian_cfg(&c,gv,0x42D3u,M11_APM_CMD_SET_CFG,&cfg,20,103,NULL,0,NULL,NULL)==-EINVAL);
    assert(mock.tx_pkt_count==tx);
    /* the AW Re apply and read-back through the custodian (VI prepared, RX open) */
    assert(!m11_custodian_graph_cmd(&c,gv,M11_APM_CMD_GRAPH_PREPARE,104) && mock.vi_tx_prepared);
    assert(!m11_custodian_graph_open(&c,j,0,RX,4,104,&gr) && c.graphs[gr].state==M11_GRAPH_OPEN);
    rt_graph=gr;
    const m11_aw_safety_context_t ctx={.vi_tx_subgraph_opened=true,.vi_tx_subgraph_prepared=true,
        .vi_tx_module_iid=M11_AW_VI_TX_MODULE_IID,.sp_rx_module_iid=M11_AW_SP_RX_MODULE_IID};
    m11_aw_cal_pair_t cal={{6372,7003},{m11_aw_mohm_to_q12(6372),m11_aw_mohm_to_q12(7003)}};
    m11_aw_apply_report_t rep;
    assert(!m11_aw_apply_and_verify_re_via(via_custodian,NULL,&ctx,&cal,10,&rep) && rep.pair_re_readback_verified);
    assert(mock.stored_q12_re[0]==cal.q12_re[0] && mock.stored_q12_re[1]==cal.q12_re[1]);
    /* cfg_oob: the parameters at region:off, to APM. The strict mock models only the AW in-band SET_CFG,
     * so it NACKs this one; a configuration never changes the graph */
    tx=mock.tx_pkt_count;
    assert(m11_custodian_cfg_oob(&c,gr,i,4090,pat,32,105)==-EINVAL);
    assert(m11_custodian_cfg_oob(&c,7,i,2048,pat,32,105)==-EPROTO && mock.tx_pkt_count==tx);
    assert(m11_custodian_cfg_oob(&c,gr,i,2048,pat,32,105)==-EREMOTEIO && mock.tx_pkt_count==tx+1);
    assert(c.graphs[gr].state==M11_GRAPH_OPEN && !memcmp((uint8_t *)c.regions[i].vaddr+2048,pat,32));
    pass("rev 6: cfg in band (the AW Re round trip verified through it) and cfg_oob; malformed or graphless refused before any TX");
    /* data commands: a STARTED graph, a held region's handle, inside it; refused before any TX */
    assert(!m11_custodian_graph_cmd(&c,gv,M11_APM_CMD_GRAPH_START,106) && c.graphs[gv].state==M11_GRAPH_STARTED);
    const uint32_t hj=c.regions[j].mem_map_handle;
    uint32_t rd[8]={0,0,hj,1024,0,0,0,0}, t1=0, t2=0, pol=1, dsp=0;
    tx=mock.tx_pkt_count;
    assert(m11_custodian_data_submit(&c,gr,0x4547u,M11_DATA_CMD_RD_SH_MEM_EP_DATA_BUFFER_V2,rd,sizeof rd,107,&t1)==-EPROTO);
    rd[2]=0xDEADu;
    assert(m11_custodian_data_submit(&c,gv,0x4547u,M11_DATA_CMD_RD_SH_MEM_EP_DATA_BUFFER_V2,rd,sizeof rd,107,&t1)==-EINVAL);
    rd[2]=hj; rd[1]=1;
    assert(m11_custodian_data_submit(&c,gv,0x4547u,M11_DATA_CMD_RD_SH_MEM_EP_DATA_BUFFER_V2,rd,sizeof rd,107,&t1)==-EINVAL);
    rd[1]=0; rd[0]=4000;
    assert(m11_custodian_data_submit(&c,gv,0x4547u,M11_DATA_CMD_RD_SH_MEM_EP_DATA_BUFFER_V2,rd,sizeof rd,107,&t1)==-EINVAL);
    rd[0]=0; rd[3]=0;
    assert(m11_custodian_data_submit(&c,gv,0x4547u,M11_DATA_CMD_RD_SH_MEM_EP_DATA_BUFFER_V2,rd,sizeof rd,107,&t1)==-EINVAL);
    rd[3]=1024;
    assert(m11_custodian_data_submit(&c,gv,0x4547u,M11_DATA_CMD_RD_SH_MEM_EP_DATA_BUFFER_V2,rd,28,107,&t1)==-EINVAL);
    assert(m11_custodian_data_submit(&c,gv,0x4547u,M11_APM_CMD_SET_CFG,rd,sizeof rd,107,&t1)==-EINVAL);
    assert(m11_custodian_data_submit(&c,gv,0x40BDu,M11_DATA_CMD_WR_SH_MEM_EP_EOS,&pol,8,107,&t1)==-EINVAL);
    assert(mock.tx_pkt_count==tx);
    assert(!m11_custodian_data_submit(&c,gv,0x4547u,M11_DATA_CMD_RD_SH_MEM_EP_DATA_BUFFER_V2,rd,sizeof rd,107,&t1) && t1);
    assert(!m11_custodian_data_submit(&c,gv,0x40BDu,M11_DATA_CMD_WR_SH_MEM_EP_EOS,&pol,4,108,&t2) && t2 && mock.tx_pkt_count==tx+2);
    /* RD IBASIC error fails fast. EOS IBASIC is evidence only (stock contract);
     * without EOS_RENDERED its bounded wait must time out, not report rendered. */
    assert(m11_gpr_engine_wait_token(&eng,t1,10,&dsp,NULL,0,NULL)==-EREMOTEIO);
    dsp=UINT32_MAX;
    assert(m11_gpr_engine_wait_token(&eng,t2,10,&dsp,NULL,0,NULL)==-ETIMEDOUT);
    assert(eng.eos_ev.token==t2 && eng.eos_ev.ibasic_count==1 && eng.eos_ev.ibasic_status==1 &&
           eng.eos_ev.rendered_count==0 && dsp==UINT32_MAX && mock.tx_pkt_count==tx+2);
    /* all of it was the custodian's own traffic: no latch, and a further MAP is admitted */
    assert(!(boot.reasons & M11_TAINT_FOREIGN_TRAFFIC) && boot.state==M11_ADSP_CLEAN);
    unsigned k=UINT_MAX;
    assert(!m11_custodian_map(&c,4096,109,&k) && k<M11_CUSTODIAN_REGIONS);
    pass("rev 6: data_submit (RD, EOS) for a STARTED graph inside a held region; all session traffic is the custodian's own (MAP still admitted)");
    /* one command around the custodian is caught; after it, session calls are refused, teardown is not */
    uint32_t raw=0;
    assert(!m11_gpr_engine_submit_ex(&eng,0,0x4547u,M11_DATA_CMD_RD_SH_MEM_EP_DATA_BUFFER_V2,rd,sizeof rd,&raw));
    assert(m11_custodian_cfg(&c,gr,0x42D3u,M11_APM_CMD_GET_CFG,&cfg,sizeof cfg,110,NULL,0,NULL,NULL)==-EOWNERDEAD);
    assert(boot.reasons & M11_TAINT_FOREIGN_TRAFFIC);
    tx=mock.tx_pkt_count;
    assert(m11_custodian_region_write(&c,j,0,pat,8,111)==-EOWNERDEAD);
    assert(m11_custodian_data_submit(&c,gv,0x40BDu,M11_DATA_CMD_WR_SH_MEM_EP_EOS,&pol,4,111,&t2)==-EOWNERDEAD);
    assert(m11_custodian_cfg_oob(&c,gr,i,3072,pat,32,111)==-EOWNERDEAD && mock.tx_pkt_count==tx);
    assert(!m11_custodian_graph_cmd(&c,gv,M11_APM_CMD_GRAPH_STOP,112) && !m11_custodian_graph_cmd(&c,gv,M11_APM_CMD_GRAPH_CLOSE,113));
    assert(!m11_custodian_graph_cmd(&c,gr,M11_APM_CMD_GRAPH_CLOSE,114));
    assert(c.region_graph_refs[i]==0 && c.region_graph_refs[j]==0);
    assert(m11_custodian_terminal_action(&c)==M11_TERMINAL_RESET_RETAINING_ANCHORS && !mock.unmap_cmd_count);
    pass("rev 6: a command around the custodian latches FOREIGN_TRAFFIC; session calls then refused before TX, graph teardown still allowed; regions held");
    /* graph_open_blob outcomes: a failed END sends nothing (FREE); a lost reply is UNKNOWN */
    fixture(); i=map(); tx=mock.tx_pkt_count; mock.fail_dma_buf_sync_end=true;
    assert(m11_custodian_graph_open_blob(&c,i,1024,blob,h.payload_size,VI,2,101,&gv)<0 && gv==UINT_MAX);
    assert(mock.tx_pkt_count==tx && c.graphs[0].state==M11_GRAPH_FREE && c.region_graph_refs[i]==0 && boot.state==M11_ADSP_CLEAN);
    fixture(); i=map(); mock.drop_graph_open_rsp=true;
    assert(m11_custodian_graph_open_blob(&c,i,1024,blob,h.payload_size,VI,2,101,&gv)==-ETIMEDOUT && gv<M11_CUSTODIAN_GRAPHS);
    assert(c.graphs[gv].state==M11_GRAPH_UNKNOWN && (boot.reasons & M11_TAINT_GRAPH_UNKNOWN) && c.region_graph_refs[i]==1);
    pass("rev 6: graph_open_blob with a failed END transmits nothing and leaves the ledger FREE; a lost reply leaves it UNKNOWN");
}
/* Post-MAP hold (rev 5, CP2 criterion 5): the region still owns its backing, its MAP may have
 * been transmitted, and nothing was ever sent or released to undo it. */
static void held(unsigned i) {
    assert(c.occupied[i] && c.regions[i].dma_buf_fd>=0 && c.regions[i].vaddr && c.regions[i].ion_imported);
    assert(c.regions[i].map_tx_started && !c.regions[i].map_tx_unsent_proof);
    assert(!mock.unmap_cmd_count && !boot.dsp_unmap_attempted && mock.unsafe_release_attempts==0);
    assert(!m11_shmem_mgr_audit(&mgr,c.regions,M11_CUSTODIAN_REGIONS));
}
/* retire after a MAP intent: refused before any tick, taint or engine call; nothing sent */
static void refused(unsigned i, uint64_t now) {
    uint32_t tx=mock.tx_pkt_count, reasons=boot.reasons; m11_adsp_state st=boot.state;
    assert(m11_custodian_retire(&c,i,now)==-EPERM);
    assert(mock.tx_pkt_count==tx && boot.reasons==reasons && boot.state==st);
    held(i);
}
int main(void) {
    fixture(); unsigned i=map();
    assert(m11_custodian_close(&c)==-EPERM && !c.closed && eng.is_open);
    assert(m11_custodian_terminal_action(&c)==M11_TERMINAL_RESET_RETAINING_ANCHORS && !m11_custodian_reboot_permitted(&c));
    refused(i,100);
    assert(c.regions[i].state==M11_SHMEM_STATE_DSP_MAP_ACKNOWLEDGED && mgr.active_dsp_maps==1);
    assert(m11_custodian_close(&c)==-EPERM && eng.close_count==0);
    /* After any DSP MAP intent the only end is the retaining reset, decided at once. */
    assert(m11_custodian_terminal_action(&c)==M11_TERMINAL_RESET_RETAINING_ANCHORS);
    assert(!m11_custodian_reboot_permitted(&c));
    assert(boot.state==M11_ADSP_CLEAN && !boot.reasons);   /* a policy refusal, not a taint */
    pass("post-MAP hold: after a MAP ACK retire and close are refused (no UNMAP, nothing released, no taint); the end is the retaining reset at once, never reboot(2)");

    /* ---------------- the reboot(2) boundary (rev 4) and the post-MAP hold (rev 5) ---------------- */
    fixture();
    assert(!m11_custodian_close(&c));
    assert(!boot.dsp_map_attempted && !boot.dsp_unmap_attempted);
    assert(m11_custodian_terminal_action(&c)==M11_TERMINAL_ORDERLY_SHUTDOWN);
    assert(m11_custodian_reboot_permitted(&c));
    pass("a boot that never DSP-mapped a region may still end with reboot(2)");
    fixture(); i=map(); unsigned j1=map();
    assert(boot.dsp_map_attempted && !boot.dsp_unmap_attempted);
    refused(i,101); refused(j1,102);
    {
        /* No UNMAP was ever sent, so the rev-4 one-shot rule never fires: MAP stays open while CLEAN. */
        unsigned k=UINT_MAX;
        assert(!m11_custodian_map(&c,4096,103,&k) && k!=i && k!=j1 && c.occupied[k]);
        assert(mock.map_cmd_count==3 && !mock.unmap_cmd_count);
    }
    assert(boot.state==M11_ADSP_CLEAN && !boot.reasons);
    assert(m11_custodian_close(&c)==-EPERM);
    assert(m11_custodian_terminal_action(&c)==M11_TERMINAL_RESET_RETAINING_ANCHORS);
    pass("post-MAP hold: no region retires, so no UNMAP ever spends the one-shot rule; MAP stays open while CLEAN; no taint");
    fixture(); i=map(); unsigned g1=open_rx(i,100); (void)g1;
    refused(i,101);                                        /* refused before any transmit */
    j1=UINT_MAX; assert(!m11_custodian_map(&c,4096,102,&j1) && j1!=i && c.occupied[j1]);
    pass("a retire refused under an open graph sends nothing and spends nothing: another MAP still succeeds");

    fixture(); i=map(); m11_custodian_worker_exit(&c,101);
    safe_retention(i); assert(boot.reasons&M11_TAINT_WORKER_EXIT);
    refused(i,102);
    assert(boot.state==M11_ADSP_TAINTED); denied_map();
    assert(m11_custodian_terminal_action(&c)==M11_TERMINAL_RESET_RETAINING_ANCHORS);
    assert(m11_model_new_boot(&boot,17,102)==-EALREADY);
    m11_custodian restarted;
    assert(m11_custodian_init(&restarted,&boot,&mgr,&contract,100)==-EOWNERDEAD);
    pass("worker exit with empty graph ledger: retire refused (post-MAP hold), taint kept, the end is the retaining reset at once");

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
    refused(i,101);
    safe_retention(i); assert(boot.reasons&M11_TAINT_FOREIGN_TRAFFIC); /* latched by the refused MAP */
    pass("foreign pending graph operation: retire refused (post-MAP hold), nothing sent; the next MAP latches FOREIGN_TRAFFIC");
    fixture(); i=map(); uint32_t st=0;
    (void)m11_gpr_query_spf_state(&eng,10,&st); /* completes or expires; never retained */
    for (unsigned k=0;k<M11_GPR_MAX_PENDING;k++) assert(!eng.slots[k].in_use);
    refused(i,101);
    safe_retention(i); assert(boot.reasons&M11_TAINT_FOREIGN_TRAFFIC);
    pass("COMPLETED foreign GPR command (nothing pending): retire refused, no UNMAP; still detected at the next MAP");
    fixture(); i=map();
    assert(!m11_apm_transact_graph_open_region(&eng,&mgr,&c.regions[i],0,RX,4,10,&st));
    assert(!m11_apm_transact_graph_mgmt(&eng,M11_APM_CMD_GRAPH_PREPARE,RX,4,10,&st));
    assert(!m11_apm_transact_graph_mgmt(&eng,M11_APM_CMD_GRAPH_START,RX,4,10,&st));
    m11_custodian_worker_exit(&c,101);
    for (unsigned k=0;k<4;k++) refused(i,102+k);
    assert(mock.rx_started); safe_retention(i);
    assert(boot.reasons&M11_TAINT_FOREIGN_TRAFFIC);
    assert(!m11_custodian_graph_teardown(&c,106)); /* the ledger has nothing it may close */
    refused(i,107);
    pass("undeclared STARTED graph (W1b shape): EVERY retire refused, no UNMAP; the traffic is still latched");
    /* Counterexamples from the adversarial W1 matrix, kept as directed regressions. */
    fixture(); i=map(); unsigned gx=open_rx(i,100); start_rx(gx,101);
    assert(!m11_apm_transact_graph_mgmt(&eng,M11_APM_CMD_GRAPH_STOP,RX,4,10,&st));
    assert(!m11_apm_transact_graph_mgmt(&eng,M11_APM_CMD_GRAPH_CLOSE,RX,4,10,&st));
    assert(!mock.rx_opened && c.graphs[gx].state==M11_GRAPH_STARTED);
    refused(i,102);
    denied_map(); assert(boot.reasons&M11_TAINT_FOREIGN_TRAFFIC); /* detection call */
    assert(!m11_custodian_graph_teardown(&c,103) && c.graphs[gx].state==M11_GRAPH_FREE);
    for (unsigned k=0;k<3;k++) refused(i,104+k);
    safe_retention(i);
    pass("foreign STOP/CLOSE of a ledger graph: even after a clean ledger teardown, no UNMAP this boot");
    fixture(); i=map(); unsigned j2=map(); gx=open_rx(i,100);
    assert(!m11_apm_transact_graph_open_region(&eng,&mgr,&c.regions[j2],0,VI,2,10,&st));
    assert(m11_custodian_graph_teardown(&c,101)==-EOWNERDEAD); /* detection call */
    assert(!m11_custodian_graph_teardown(&c,102) && mock.vi_tx_opened && !mock.rx_opened);
    refused(i,103); refused(j2,104); refused(i,105);
    safe_retention(i); safe_retention(j2);
    pass("undeclared second graph on another region keeps every region pinned after ledger teardown");
    fixture(); i=map(); gx=open_rx(i,100); mock.hold_next_rsp=true;
    assert(m11_custodian_graph_cmd(&c,gx,M11_APM_CMD_GRAPH_CLOSE,101)==-ETIMEDOUT);
    assert(!mock.rx_opened && c.graphs[gx].state==M11_GRAPH_UNKNOWN);
    assert(m11_strict_mock_release_held(&mock)==1);
    refused(i,102);
    assert(c.graphs[gx].state==M11_GRAPH_UNKNOWN);
    assert(m11_custodian_graph_teardown(&c,103)==-EOWNERDEAD);
    refused(i,104); safe_retention(i);
    pass("late GRAPH_CLOSE ACK cannot resolve an UNKNOWN graph; region stays pinned");
    fixture(); i=map(); gx=open_rx(i,100);
    assert(!m11_custodian_graph_cmd(&c,gx,M11_APM_CMD_GRAPH_PREPARE,101));
    mock.hold_next_rsp=true;
    assert(m11_custodian_graph_cmd(&c,gx,M11_APM_CMD_GRAPH_START,102)==-ETIMEDOUT && mock.rx_started);
    m11_custodian_worker_exit(&c,103);
    assert(m11_custodian_graph_teardown(&c,104)==-EOWNERDEAD && mock.rx_started);
    for (unsigned k=0;k<3;k++) refused(i,105+k);
    assert(m11_custodian_tick(&c,203)==-EOWNERDEAD); refused(i,203);
    assert(m11_custodian_terminal_action(&c)==M11_TERMINAL_RESET_RETAINING_ANCHORS); safe_retention(i);
    pass("worker death after a late START ACK: no teardown claim, no UNMAP, terminal reset retaining anchors");
    fixture(); assert(!m11_gpr_engine_close(&eng));
    assert(m11_gpr_engine_open(&eng)==-EBUSY); /* engine never reopens in one session */
    assert(m11_custodian_map(&c,4096,100,&other)==-EOWNERDEAD && !mock.map_cmd_count);
    assert(boot.reasons&M11_TAINT_FOREIGN_TRAFFIC);
    pass("foreign endpoint close is detected through engine close counter; no reopen");
    fixture(); i=map(); unsigned second=map(); mock.hold_next_rsp=true;
    refused(i,101); refused(second,102);
    assert(m11_strict_mock_release_held(&mock)==0);        /* nothing was sent, nothing is in flight */
    refused(i,103);
    assert(mgr.active_ion_imports==2 && !m11_gpr_engine_orphan_count(&eng));
    assert(!(boot.reasons&M11_TAINT_FOREIGN_TRAFFIC));
    pass("post-MAP hold: two mapped regions, no UNMAP and so no UNMAP orphan; both keep their backing");
    fixture(); i=map(); c.contract.graph_quiescent=false;
    refused(i,100);
    safe_retention(i); pass("unconfirmed graph quiescence: retire refused, no UNMAP/free");
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
    refused(i,101);                                        /* no reconcile: the late ACK is not adopted */
    assert(mock.map_cmd_count==1 && c.regions[i].state==M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED);
    assert(mgr.active_ion_imports==1 && boot.state==M11_ADSP_TAINTED);
    denied_map(); pass("lost/late MAP ACK: retire refused (post-MAP hold): no reconcile, no UNMAP, no MAP resend; region held unresolved");

    fixture(); i=map(); mock.hold_next_rsp=true;
    refused(i,101);
    assert(mock.shm_slots[0].dsp_map_handle);              /* the modeled ADSP still maps it */
    assert(m11_strict_mock_release_held(&mock)==0);        /* no UNMAP, so no ACK to lose */
    refused(i,102);
    pass("post-MAP hold: no UNMAP is sent, so no UNMAP ACK can be lost or late; backing held");

    fixture(); mock.hold_next_rsp=true;
    assert(m11_custodian_map(&c,4096,100,&i)==-ETIMEDOUT);
    assert(m11_strict_mock_release_held(&mock)==1);
    m11_gpr_engine_set_clock(&eng,step_clock,NULL);
    refused(i,101);
    assert(c.regions[i].state==M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED);
    refused(i,102);
    pass("post-MAP hold: the late-MAP region is never reconciled or unmapped (the shared budget path is unreachable)");

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
    refused(i,101); safe_retention(i);
    pass("invalid MAP handle cannot authorize release");

    fixture(); mock.nack_shmem_map=true;
    assert(m11_custodian_map(&c,4096,100,&i)==-EREMOTEIO);
    assert(c.regions[i].state==M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED && c.regions[i].cause==M11_SHMEM_CAUSE_MAP_NACK);
    assert(mgr.active_dma_fds==1 && boot.state==M11_ADSP_TAINTED && boot.reasons&M11_TAINT_REMOTE_UNKNOWN);
    safe_retention(i); held(i);
    pass("MAP NACK is held (OWNERSHIP_UNRESOLVED, cause MAP_NACK): no rollback without proof that nothing was mapped");
    assert(boot.dsp_map_attempted && m11_custodian_close(&c)==-EPERM);
    assert(m11_custodian_terminal_action(&c)==M11_TERMINAL_RESET_RETAINING_ANCHORS);
    pass("a MAP that the ADSP may have seen (here NACKed): close refused, the end is the retaining reset");
    fixture(); i=map(); mock.nack_shmem_unmap=true;
    refused(i,101);
    assert(boot.state==M11_ADSP_CLEAN && !boot.reasons);
    pass("post-MAP hold: no UNMAP is sent, so no UNMAP NACK; backing retained, no taint");

    fixture(); mock.deliver_then_fail_write_on_map=true;
    assert(m11_custodian_map(&c,4096,100,&i)==-EIO); safe_retention(i);
    refused(i,101);
    assert(mock.map_cmd_count==1 && c.regions[i].state==M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED); denied_map();
    pass("write error after remote MAP delivery: held unresolved, no replay; retire refused (no UNMAP)");
    fixture(); mock.short_gpr_write_on_map=true;
    assert(m11_custodian_map(&c,4096,100,&i)<0); safe_retention(i);
    pass("short MAP write quarantines instead of rollback");

    /* Local-release faults after a transmitted MAP are never reached: the release itself is refused.
     * The release mechanics (resume, retained fd, END error) stay qualified on proven pre-TX
     * failures in runtime-repair. */
    fixture(); i=map(); mock.fail_ion_unmap=true;
    refused(i,101);
    assert(!c.regions[i].remote_inactive); mock.fail_ion_unmap=false;
    refused(i,102);
    pass("post-MAP hold: retire refused before any UNMAP or local release (ION release fault never reached)");
    fixture(); i=map(); mock.fail_close_fd=true;
    refused(i,101);
    mock.fail_close_fd=false;
    refused(i,102);
    pass("post-MAP hold: retire refused before any close (retained-fd fault never reached); raw close adapter still BLOCKED");
    fixture(); i=map(); mock.fail_dma_buf_sync_end=true; mock.sync_end_errno=-EPIPE;
    refused(i,101);
    assert(!(boot.reasons&M11_TAINT_LOCAL_ERROR));
    pass("post-MAP hold: retire refused before any END sync (END error never reached), no LOCAL_ERROR taint");

    /* ------------------------------ graph ledger ------------------------------ */
    fixture(); i=map(); unsigned g=open_rx(i,100); start_rx(g,101);
    uint32_t tx=mock.tx_pkt_count;
    refused(i,102); assert(mock.tx_pkt_count==tx);
    assert(m11_custodian_close(&c)==-EPERM && eng.is_open);
    assert(m11_custodian_graph_cmd(&c,g,M11_APM_CMD_GRAPH_CLOSE,102)==-EPROTO && mock.tx_pkt_count==tx);
    assert(m11_custodian_terminal_action(&c)==M11_TERMINAL_RESET_RETAINING_ANCHORS && !m11_custodian_reboot_permitted(&c));
    assert(!m11_custodian_graph_teardown(&c,103));
    assert(!mock.rx_started && !mock.rx_opened && c.graphs[g].state==M11_GRAPH_FREE);
    assert(c.region_graph_refs[i]==0 && boot.state==M11_ADSP_CLEAN);
    refused(i,104);
    assert(m11_custodian_close(&c)==-EPERM && !m11_custodian_reboot_permitted(&c));
    assert(m11_custodian_terminal_action(&c)==M11_TERMINAL_RESET_RETAINING_ANCHORS);
    pass("stock ordering kept: graph STOP/CLOSE only through the ledger (STARTED cannot skip STOP); after the teardown the region is still never retired");

    fixture(); i=map(); g=open_rx(i,100); start_rx(g,101);
    m11_custodian_worker_exit(&c,102);
    refused(i,103);
    safe_retention(i);
    unsigned g2=UINT_MAX;
    assert(m11_custodian_graph_open(&c,i,0,VI,2,103,&g2)==-EOWNERDEAD && g2==UINT_MAX);
    assert(!m11_custodian_graph_teardown(&c,104) && !mock.rx_started && !mock.rx_opened);
    refused(i,105);
    assert(boot.state==M11_ADSP_TAINTED && boot.reasons&M11_TAINT_WORKER_EXIT);
    assert(m11_custodian_terminal_action(&c)==M11_TERMINAL_RESET_RETAINING_ANCHORS);
    assert(m11_custodian_tick(&c,202)==-EOWNERDEAD);
    assert(m11_custodian_terminal_action(&c)==M11_TERMINAL_RESET_RETAINING_ANCHORS);
    assert(m11_custodian_request_recovery(&c)==-ENOTSUP);
    pass("worker death under a STARTED graph: the custodian still STOPs/CLOSEs it, the region is never retired; taint stays");

    fixture(); i=map(); unsigned j=map(); mock.drop_graph_open_rsp=true;
    assert(m11_custodian_graph_open(&c,i,0,RX,4,100,&g)==-ETIMEDOUT);
    assert(g<M11_CUSTODIAN_GRAPHS && c.graphs[g].state==M11_GRAPH_UNKNOWN);
    assert(boot.reasons&M11_TAINT_GRAPH_UNKNOWN);
    refused(j,101); refused(i,101);
    assert(m11_custodian_graph_teardown(&c,101)==-EOWNERDEAD);
    assert(m11_custodian_graph_cmd(&c,g,M11_APM_CMD_GRAPH_CLOSE,101)==-EOWNERDEAD);
    assert(!mock.unmap_cmd_count); safe_retention(i); safe_retention(j);
    assert(m11_custodian_tick(&c,200)==-EOWNERDEAD);
    assert(m11_custodian_terminal_action(&c)==M11_TERMINAL_RESET_RETAINING_ANCHORS);
    pass("lost GRAPH_OPEN reply: graph UNKNOWN pins every region until terminal reset");

    fixture(); i=map(); g=open_rx(i,100); mock.drop_graph_close_rsp=true;
    assert(m11_custodian_graph_cmd(&c,g,M11_APM_CMD_GRAPH_CLOSE,101)==-ETIMEDOUT);
    assert(c.graphs[g].state==M11_GRAPH_UNKNOWN && mock.rx_opened);
    refused(i,102);
    safe_retention(i); pass("lost GRAPH_CLOSE reply: graph UNKNOWN, region retained");

    fixture(); i=map(); g=open_rx(i,100); mock.nack_graph_close=true;
    assert(m11_custodian_graph_cmd(&c,g,M11_APM_CMD_GRAPH_CLOSE,101)==-EREMOTEIO);
    assert(c.graphs[g].state==M11_GRAPH_OPEN && boot.state==M11_ADSP_CLEAN);
    refused(i,102);
    mock.nack_graph_close=false;
    assert(!m11_custodian_graph_cmd(&c,g,M11_APM_CMD_GRAPH_CLOSE,103));
    refused(i,104);
    pass("GRAPH_CLOSE NACK keeps graph OPEN (atomic-NACK MODEL); after the CLOSE ACK the region is still held");

    fixture(); i=map(); mock.nack_graph_open=true;
    assert(m11_custodian_graph_open(&c,i,0,RX,4,100,&g)==-EREMOTEIO && g==UINT_MAX);
    assert(!c.region_graph_refs[i] && boot.state==M11_ADSP_CLEAN);
    refused(i,101);
    pass("GRAPH_OPEN NACK releases the ledger slot (atomic-NACK MODEL); the region stays held");

    fixture(); i=map(); mock.fail_gpr_write_on_graph_open=true;
    assert(m11_custodian_graph_open(&c,i,0,RX,4,100,&g)<0);
    assert(g<M11_CUSTODIAN_GRAPHS && c.graphs[g].state==M11_GRAPH_UNKNOWN);
    refused(i,101);
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
    safe_retention(i); refused(i,102);
    eng.pdr_down=false; denied_map();
    assert(m11_custodian_request_recovery(&c)==-ENOTSUP);
    assert(m11_custodian_terminal_action(&c)==M11_TERMINAL_RESET_RETAINING_ANCHORS);
    pass("PDR DOWN/UP does not prove ADSP quiescence or clear taint");
    fixture(); i=map(); m11_custodian_owner_exit(&c,101);
    safe_retention(i); assert(!boot.owner_alive);
    refused(i,102);
    assert(m11_custodian_terminal_action(&c)==M11_TERMINAL_RESET_RETAINING_ANCHORS);
    pass("custodian death marks records unknown; no fabricated cleanup");
    fixture(); i=map(); m11_custodian_global_cleanup(&c,101);
    safe_retention(i); refused(i,102);
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
    refused(i,201); safe_retention(i);
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
    rev6_session();
    printf("Custodian qualification: %u cases PASS; physical runtime and recovery BLOCKED\n",cases);
    return 0;
}
