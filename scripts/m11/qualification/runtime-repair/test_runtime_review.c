#define _POSIX_C_SOURCE 200809L
#include "m11_offline_sim.h"
#include "m11_strict_mock.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* Independent takeover witnesses. Every transport/backing object is a mock. */
static bool legacy;
static m11_strict_mock_t mock;
static m11_gpr_engine_t eng;
static m11_shmem_mgr_t mgr;
static void fixture(void) {
    m11_gpr_transport_t tp; m11_shmem_backend_t be;
    m11_strict_mock_init(&mock); m11_strict_mock_bind(&mock, &tp, &be);
    assert(m11_gpr_engine_init(&eng, &tp, 0x2002u) == 0);
    assert(m11_shmem_mgr_init(&mgr, &be, &eng, 10u) == 0);
}
static uint64_t now_ms;
static uint32_t request_token, request_opcode, polls;
static bool late;
static int open_stub(void *u) { (void)u; return 42; }
static int close_stub(void *u, int fd) { (void)u; (void)fd; return 0; }
static uint64_t clock_stub(void *u) { (void)u; return now_ms; }
static int write_stub(void *u, int fd, const uint8_t *p, size_t n) {
    (void)u; (void)fd; m11_gpr_hdr_t h;
    assert(m11_gpr_validate_packet(p,n,&h,NULL,NULL) == 0);
    request_token=h.token; request_opcode=h.opcode; return (int)n;
}
static int read_stub(void *u, int fd, uint8_t *p, size_t cap, uint32_t budget) {
    (void)u; (void)fd; (void)budget; polls++;
    if (!late) return -ETIMEDOUT;
    now_ms += 11u; /* callback overran the 10 ms budget, but supplies a valid ACK */
    uint32_t data = request_opcode == M11_APM_CMD_GET_SPF_STATE ? 1u : 0x55u;
    uint32_t op = request_opcode == M11_APM_CMD_GET_SPF_STATE ?
        M11_APM_CMD_RSP_GET_SPF_STATE : M11_APM_CMDRSP_SHARED_MEM_MAP_REGIONS;
    size_t n=0;
    assert(m11_gpr_pack_packet_ex(p,cap,&n,M11_GPR_DOMAIN_APPS,M11_GPR_DOMAIN_ADSP,
        0,0x2002u,1u,request_token,op,&data,sizeof(data)) == 0);
    return (int)n;
}
static void clock_fixture(void) {
    m11_gpr_transport_t tp={open_stub,close_stub,write_stub,read_stub,NULL};
    now_ms=0; polls=0; late=true;
    assert(m11_gpr_engine_init(&eng,&tp,0x2002u) == 0);
    assert(m11_gpr_engine_open(&eng) == 0);
    m11_gpr_engine_set_clock(&eng,clock_stub,NULL);
}
static void late_ack_deadline(void) {
    clock_fixture(); uint32_t state=99;
    int rc=m11_gpr_query_spf_state(&eng,10u,&state);
    assert(rc == (legacy ? 0 : -ETIMEDOUT));
    if (!legacy) assert(state == 99u);
    printf("late data ACK: rc=%d (deadline=10, receipt=11 ms)\n",rc);
    assert(m11_gpr_engine_close(&eng) == 0);
}
static void late_map_keeps_response(void) {
    clock_fixture(); uint32_t tok=0,data=0; size_t len=0;
    assert(m11_gpr_engine_submit(&eng,1u,M11_APM_CMD_SHARED_MEM_MAP_REGIONS,
        NULL,0,&tok) == 0);
    int rc=m11_gpr_engine_wait_token(&eng,tok,10u,NULL,&data,sizeof(data),&len);
    assert(rc == (legacy ? 0 : -ETIMEDOUT));
    if (!legacy) {
        assert(m11_gpr_engine_orphan_tracked(&eng,tok));
        uint32_t op=0;
        assert(m11_gpr_engine_orphan_poll(&eng,tok,0,NULL,&op,&data,sizeof(data),&len) == 0);
        assert(op == M11_APM_CMDRSP_SHARED_MEM_MAP_REGIONS && data == 0x55u);
        assert(polls == 1u); /* consume the parsed late response, do not re-read or resend */
    }
    assert(m11_gpr_engine_close(&eng) == 0);
}
static void end_errno_survives_release(void) {
    fixture(); assert(m11_gpr_engine_open(&eng) == 0); m11_shmem_region_t r;
#ifdef M11_SHMEM_POST_MAP_HOLD
    /* Post-MAP hold: a transmitted region is never released (its UNMAP ACK releases nothing), so
     * the END failure is driven through a MAP refused before write_fn, whose release runs at once. */
    mock.fail_dma_buf_sync_end=true; mock.sync_end_errno=-EPIPE;
    for (size_t i=0;i<M11_GPR_MAX_PENDING;i++) eng.slots[i].in_use=true;
    assert(m11_shmem_alloc_and_map(&mgr,M11_SHMEM_MODE_DMA_ION_OFFSET,4096,false,&r) == -ENOSPC);
    for (size_t i=0;i<M11_GPR_MAX_PENDING;i++) memset(&eng.slots[i],0,sizeof(eng.slots[i]));
    assert(r.map_tx_started && r.map_tx_unsent_proof && eng.last_tx_status == M11_GPR_TX_NOT_ATTEMPTED);
    assert(r.state == M11_SHMEM_STATE_RELEASED && r.sync_end_failures == 1u);
    assert(r.cleanup_error == -EPIPE);
    assert(m11_shmem_mgr_audit(&mgr,&r,1u) == 0u);
    assert(mock.map_cmd_count == 0u && mock.unmap_cmd_count == 0u);
    printf("END_RW error in the release of an unsent MAP: stored cleanup errno=%d\n",r.cleanup_error);
    mock.fail_dma_buf_sync_end=false;
    m11_shmem_region_t t;
    assert(m11_shmem_alloc_and_map(&mgr,M11_SHMEM_MODE_DMA_ION_OFFSET,4096,false,&t) == 0);
    assert(m11_shmem_unmap_and_free(&mgr,&t) == -EPERM && mock.unmap_cmd_count == 1u);
    assert(t.state == M11_SHMEM_STATE_DSP_UNMAP_ACKNOWLEDGED && t.ion_imported && t.vaddr && t.dma_buf_fd >= 0);
    assert(m11_shmem_mgr_audit(&mgr,&t,1u) == 0u);
#else
    assert(m11_shmem_alloc_and_map(&mgr,M11_SHMEM_MODE_DMA_ION_OFFSET,4096,false,&r) == 0);
    mock.fail_dma_buf_sync_end=true; mock.sync_end_errno=-EPIPE;
    /* Remote UNMAP ACK allows release, but does not erase a cache-maintenance failure. */
    assert(m11_shmem_unmap_and_free(&mgr,&r) == 0);
    assert(r.state == M11_SHMEM_STATE_RELEASED && r.sync_end_failures == 1u);
    assert(r.cleanup_error == (legacy ? 0 : -EPIPE));
    assert(m11_shmem_mgr_audit(&mgr,&r,1u) == 0u);
    assert(mock.unmap_cmd_count == 1u);
    printf("END_RW error after remote ACK: stored cleanup errno=%d\n",r.cleanup_error);
#endif
    assert(m11_gpr_engine_close(&eng) == 0);
}
static void retired_token_is_not_reissued_at_wrap(void) {
    clock_fixture(); late=false; eng.next_token=UINT32_MAX; uint32_t tok=0;
    assert(m11_gpr_engine_submit(&eng,1u,M11_APM_CMD_GET_SPF_STATE,NULL,0,&tok) == 0);
    assert(tok == UINT32_MAX);
    assert(m11_gpr_engine_wait_token(&eng,tok,10u,NULL,NULL,0,NULL) == -ETIMEDOUT);
    int rc=m11_gpr_engine_submit(&eng,1u,M11_APM_CMD_GET_SPF_STATE,NULL,0,&tok);
    assert(rc == (legacy ? 0 : -EOVERFLOW));
    if (!legacy) assert(tok == 0u && eng.last_tx_status == M11_GPR_TX_NOT_ATTEMPTED);
    printf("token wrap after retired request: rc=%d, next token=%u\n",rc,tok);
    assert(m11_gpr_engine_close(&eng) == 0);
}
static void simulator_retains_unknown(void) {
    fixture(); mock.drop_shmem_map_rsp=true;
    m11_sim_config_t cfg; m11_sim_report_t rep; m11_sim_default_marble_config(&cfg);
    assert(m11_sim_run_speaker_qualification(&cfg,&eng,&mgr,10u,&rep) == -ETIMEDOUT);
    assert(rep.unresolved_ownership == 1u && !rep.clean_teardown);
    assert(eng.is_open == !legacy);
    printf("unknown MAP at return: GPR closes=%u, held=%u\n",eng.close_count,eng.is_open);
#ifdef M11_RUNTIME_REVIEW_CONTAINMENT
    assert(rep.endpoint_close_deferred && rep.graph_cleanup_unresolved == false);
    assert(rep.retained_region_valid && rep.retained_region.dma_buf_fd >= 0);
    assert(rep.retained_region.orphan_token && m11_gpr_engine_orphan_tracked(&eng,rep.retained_region.orphan_token));
    assert(m11_shmem_mgr_audit(&mgr,&rep.retained_region,1u) == 0u);
    assert(m11_shmem_unmap_and_free(&mgr,&rep.retained_region) == -EBUSY);
    assert(mock.unsafe_release_attempts == 0u && mock.unmap_cmd_count == 0u);
    /* No close here. Return to test harness is NOT a real-process safety qualification. */
#endif
}
static void graph_close_uncertain_retains_backing(void) {
    fixture(); mock.drop_graph_close_rsp=true;
    m11_sim_config_t cfg; m11_sim_report_t rep; m11_sim_default_marble_config(&cfg);
    assert(m11_sim_run_speaker_qualification(&cfg,&eng,&mgr,10u,&rep) == -ETIMEDOUT);
    assert(!rep.clean_teardown);
    assert(mock.unmap_cmd_count == (legacy ? 1u : 0u));
#ifdef M11_RUNTIME_REVIEW_CONTAINMENT
    assert(rep.graph_cleanup_unresolved && rep.endpoint_close_deferred);
    assert(rep.retained_region_valid && rep.retained_region.dsp_mapped && eng.is_open);
    assert(m11_shmem_mgr_audit(&mgr,&rep.retained_region,1u) == 0u);
#endif
    printf("unconfirmed GRAPH_CLOSE: UNMAP calls=%u\n",mock.unmap_cmd_count);
}
#ifdef M11_RUNTIME_REVIEW_CONTAINMENT
static void local_retry_uses_retained_record(void) {
    m11_sim_config_t cfg; m11_sim_report_t rep; m11_sim_default_marble_config(&cfg);
#ifdef M11_SHMEM_POST_MAP_HOLD
    /* Post-MAP hold: a run whose MAP went out never releases; a pending local release needs a
     * failure before any MAP (the import) whose cleanup close then fails. */
    fixture(); mock.fail_ion_import=true; mock.fail_close_fd=true;
    assert(m11_sim_run_speaker_qualification(&cfg,&eng,&mgr,10u,&rep) == -EFAULT);
    assert(!rep.post_map_hold && mock.map_cmd_count == 0u);
#else
    fixture(); mock.fail_close_fd=true;
    assert(m11_sim_run_speaker_qualification(&cfg,&eng,&mgr,10u,&rep) == -EIO);
#endif
    assert(rep.endpoint_close_deferred && rep.retained_region_valid);
    assert(!rep.graph_cleanup_unresolved && rep.local_release_pending == 1u);
    uint32_t tx=mock.tx_pkt_count; mock.fail_close_fd=false;
    assert(m11_shmem_unmap_and_free(&mgr,&rep.retained_region) == 0);
    assert(mock.tx_pkt_count == tx && mgr.active_dma_fds == 0u);
    assert(m11_gpr_engine_close(&eng) == 0);
}
#endif
int main(int argc, char **argv) {
    setvbuf(stdout,NULL,_IONBF,0);
    legacy=argc == 2 && strcmp(argv[1],"--legacy-witness") == 0;
    late_ack_deadline(); late_map_keeps_response(); retired_token_is_not_reissued_at_wrap();
    end_errno_survives_release();
    simulator_retains_unknown(); graph_close_uncertain_retains_backing();
#ifdef M11_RUNTIME_REVIEW_CONTAINMENT
    local_retry_uses_retained_record();
#endif
    puts(legacy ? "REVIEW BASELINE DEFECTS REPRODUCED" : "RUNTIME REVIEW REGRESSION PASS; process-exit safety BLOCKED");
    return 0;
}
