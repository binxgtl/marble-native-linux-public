/* Directed qualification of the PID1 anchor adapter against the synthetic file-lifetime
 * model, a before/after witness of the current native path, and the custodian ledger
 * integration. Model only: no device, driver, ADSP or DMA claim. */
#define _GNU_SOURCE
#include "m11_pid1_anchor.h"
#include "anchor_kernel_model.h"
#include "../runtime-repair/m11_strict_mock.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

static unsigned cases;
static void pass(const char *s) { ++cases; printf("PASS %s\n",s); }

static km_kernel k;
static m11_pid1_anchor a;
static const m11_anchor_contract evidence={.endpoint_has_no_flush=true,
    .release_on_last_fput_only=true,.owner_single_threaded=true};
struct counts { unsigned worker_lost, foreign, lost, lost_released; m11_custodian *c; uint64_t now; };
static struct counts seen;
static void on_worker(void *v) {
    struct counts *s=v; s->worker_lost++;
    if (s->c) m11_custodian_worker_exit(s->c,s->now);
}
static void on_foreign(void *v) {
    struct counts *s=v; s->foreign++;
    /* Another OFD's own last close runs the global cleanup at a time PID1 does not control. */
    if (s->c) m11_custodian_global_cleanup(s->c,s->now);
}
static void on_lost(void *v, bool released) {
    struct counts *s=v; s->lost++; if (released) s->lost_released++;
    if (s->c) m11_custodian_global_cleanup(s->c,s->now);
}
static const m11_anchor_sink sink={&seen,on_worker,on_foreign,on_lost};

static int anchor_file(void) { return km_file_of(&k,0,a.anchor_fd); }
static void fresh(bool flush) {
    km_init(&k,flush); memset(&a,0,sizeof(a)); memset(&seen,0,sizeof(seen));
}
static void bound(void) {
    fresh(false);
    m11_anchor_ops ops=km_ops(&k);
    assert(!m11_anchor_bind(&a,&ops,&sink,&evidence,1,KM_ENDPOINT_RDEV));
    assert(a.state==M11_ANCHOR_HELD && k.endpoint_opens==1 && a.opens==1);
}
/* Fork a worker as the backend does: reserve, fork, report, worker accepts, worker drops
 * privilege (it can no longer open the root 0600 node). Returns the worker index. */
static int lend(void) {
    int fd=-1; k.current=0;
    assert(!m11_anchor_lend_begin(&a,&fd) && fd==a.anchor_fd);
    int w=km_fork(&k,0); assert(w>0);
    assert(!m11_anchor_lend_started(&a,k.procs[w].pid));
    k.current=w;
    assert(!m11_anchor_worker_accept(&a,fd));
    k.procs[w].privileged=false;
    k.current=0;
    return w;
}
static void worker_io(int w) { /* the borrowed fd is the anchor OFD */
    assert(km_file_of(&k,w,a.anchor_fd)==anchor_file() && km_file_of(&k,w,a.guard_fd)<0);
}

static void baseline_witness(void) {
    /* Current native path (the GPR worker's lx_open/lx_close in the forked child; PID1 never
     * holds the endpoint and census() requires PID1 to hold none). */
    fresh(false);
    int w=km_fork(&k,0); int fd=km_open(&k,w,true); assert(fd>=0);
    assert(!km_close(&k,w,fd)); km_exit(&k,w);
    assert(k.endpoint_releases==1);
    w=km_fork(&k,0); fd=km_open(&k,w,true); assert(fd>=0); km_exit(&k,w);
    assert(k.endpoint_releases==2);
    pass("BASELINE witness: every worker close or exit is the last fput (2 queries -> 2 global cleanups)");
    w=km_fork(&k,0); fd=km_open(&k,w,true); assert(fd>=0);
    assert(km_kill(&k,w) && k.endpoint_releases==3);
    pass("BASELINE witness: SIGKILL of the worker runs the kernel release (CLOSE_ALL + ION cleanup)");
    w=km_fork(&k,0); fd=km_open(&k,w,true); k.procs[w].dstate=true;
    assert(!km_kill(&k,w) && k.endpoint_releases==3);
    k.procs[w].dstate=false; km_exit(&k,w);
    assert(k.endpoint_releases==4);
    pass("BASELINE witness: a D-state worker releases later, at a time PID1 does not control");
}

int main(void) {
    baseline_witness();

    bound();
    int f=anchor_file();
    assert(f>=0 && km_file_of(&k,0,a.guard_fd)==f && km_refs_of(&k,f)==2);
    assert(a.anchor_fd>=M11_ANCHOR_RESERVED_FD && a.guard_fd==a.anchor_fd+1 && a.raw_fd==-1);
    assert(k.endpoint_releases==0);
    pass("bind: one open, two PID1 references to one OFD at reserved numbers, raw fd closed non-finally");
    m11_anchor_ops ops=km_ops(&k);
    assert(m11_anchor_bind(&a,&ops,&sink,&evidence,1,KM_ENDPOINT_RDEV)==-EALREADY && k.endpoint_opens==1);
    pass("bind is one-shot per boot");

    for (unsigned i=0;i<3;i++) {
        fresh(false); ops=km_ops(&k);
        m11_anchor_contract ct=evidence;
        if (i==0) ct.endpoint_has_no_flush=false;
        if (i==1) ct.release_on_last_fput_only=false;
        if (i==2) ct.owner_single_threaded=false;
        assert(m11_anchor_bind(&a,&ops,&sink,&ct,1,KM_ENDPOINT_RDEV)==-EPERM && k.endpoint_opens==0);
        assert(a.state==M11_ANCHOR_FAILED);
    }
    pass("bind refused before any open when a static precondition lacks evidence");
    fresh(false); ops=km_ops(&k);
    int other=km_fork(&k,0); k.current=other;
    assert(m11_anchor_bind(&a,&ops,&sink,&evidence,1,KM_ENDPOINT_RDEV)==-EPERM && k.endpoint_opens==0);
    pass("bind refused outside the owner process; nothing opened");

    fresh(false); ops=km_ops(&k);
    assert(m11_anchor_bind(&a,&ops,&sink,&evidence,1,KM_ENDPOINT_RDEV+1)==-ENODEV);
    assert(a.state==M11_ANCHOR_FAILED && a.raw_fd>=0 && km_refs_of(&k,km_file_of(&k,0,a.raw_fd))==1);
    assert(k.endpoint_releases==0 && (a.latches & M11_ANCHOR_LATCH_FD_DISCIPLINE));
    m11_anchor_end end=M11_ANCHOR_END_REBOOT;
    assert(m11_anchor_end_boot(&a,M11_TERMINAL_ORDERLY_SHUTDOWN,&end)==-EPROTO && end==M11_ANCHOR_END_PID1_EXIT);
    km_exit(&k,0); assert(k.panicked && k.endpoint_releases==0);
    pass("unproven identity: fd retained, never closed, boot ends by PID1 exit without release");
    fresh(false); ops=km_ops(&k); k.fail_dup=true;
    assert(m11_anchor_bind(&a,&ops,&sink,&evidence,1,KM_ENDPOINT_RDEV)==-EMFILE);
    assert(a.state==M11_ANCHOR_FAILED && a.raw_fd>=0 && k.endpoint_releases==0);
    pass("dup failure: the single raw reference is retained, not closed");

    bound(); f=anchor_file();
    int w=lend();
    assert(km_refs_of(&k,f)==3); worker_io(w);
    assert(!km_close(&k,w,a.anchor_fd) && km_refs_of(&k,f)==2 && k.endpoint_releases==0);
    km_exit(&k,w);
    assert(!m11_anchor_lend_end(&a,M11_WORKER_EXIT_OK) && a.state==M11_ANCHOR_HELD);
    assert(k.endpoint_releases==0 && seen.worker_lost==0);
    pass("loan: worker borrows by fork, drops its guard copy, closes and exits; no release");
    w=lend(); worker_io(w);
    assert(km_kill(&k,w) && km_refs_of(&k,f)==2 && k.endpoint_releases==0);
    assert(!m11_anchor_lend_end(&a,M11_WORKER_EXIT_ABNORMAL) && seen.worker_lost==1);
    pass("worker SIGKILL mid-transaction is a non-final close: no CLOSE_ALL, no ION cleanup");
    w=lend(); km_exit(&k,w);
    assert(!m11_anchor_lend_end(&a,M11_WORKER_EXIT_ABNORMAL) && k.endpoint_releases==0 && seen.worker_lost==1);
    pass("abnormal worker is reported once; teardown loans stay possible");
    w=lend();
    k.current=w;
    assert(km_open(&k,w,true)==-EACCES && k.endpoint_opens==1);
    assert(m11_anchor_worker_accept(&a,a.anchor_fd+5)==-ENODEV);
    k.current=0;
    assert(m11_anchor_worker_accept(&a,a.anchor_fd)==-EPERM);
    km_exit(&k,w); assert(!m11_anchor_lend_end(&a,M11_WORKER_EXIT_OK));
    pass("worker cannot open a second OFD (DAC after privilege drop); accept validates fd and caller");

    w=lend(); k.procs[w].dstate=true;
    assert(!km_kill(&k,w));
    assert(m11_anchor_lend_end(&a,M11_WORKER_UNRESOLVED)==-EINPROGRESS);
    assert(a.state==M11_ANCHOR_LENT && (a.latches & M11_ANCHOR_LATCH_WORKER_UNRESOLVED));
    int fd=-1;
    assert(m11_anchor_lend_begin(&a,&fd)==-EBUSY && m11_anchor_final_close(&a)==-EBUSY);
    end=M11_ANCHOR_END_REBOOT;
    assert(m11_anchor_end_boot(&a,M11_TERMINAL_ORDERLY_SHUTDOWN,&end)==-EPROTO && end==M11_ANCHOR_END_PID1_EXIT);
    assert(m11_anchor_end_boot(&a,M11_TERMINAL_RESET_RETAINING_ANCHORS,&end)==0 && end==M11_ANCHOR_END_PID1_EXIT);
    km_exit(&k,0); assert(k.panicked && k.endpoint_releases==0);
    pass("unresolved worker: loan never ends, no new loan, no final close; PID1 exit releases nothing");

    bound(); f=anchor_file();
    assert(!km_close(&k,0,a.anchor_fd) && k.endpoint_releases==0 && km_refs_of(&k,f)==1);
    assert(m11_anchor_check(&a)==-EBADF && (a.latches & M11_ANCHOR_LATCH_FD_DISCIPLINE));
    assert(seen.lost==1 && seen.lost_released==0);
    assert(m11_anchor_lend_begin(&a,&fd)==-EOWNERDEAD && m11_anchor_final_close(&a)==-EOWNERDEAD);
    assert(!m11_anchor_end_boot(&a,M11_TERMINAL_RESET_RETAINING_ANCHORS,&end) && end==M11_ANCHOR_END_PID1_EXIT);
    km_exit(&k,0); assert(k.endpoint_releases==0);
    pass("PID1 bug closes the anchor number: guard keeps the OFD; latched; boot ends retained");
    bound(); f=anchor_file();
    assert(!km_close(&k,0,a.guard_fd) && !km_close(&k,0,a.anchor_fd) && k.endpoint_releases==1);
    assert(m11_anchor_check(&a)==-EBADF && seen.lost==1 && seen.lost_released==1);
    pass("both PID1 references lost outside the adapter: reported as a possible global cleanup");
    bound(); f=anchor_file();
    int junk=km_open(&k,0,false);
    assert(!km_close(&k,0,a.anchor_fd) && km_dup2(&k,0,junk,a.anchor_fd)==a.anchor_fd);
    km_set_cloexec(&k,0,a.anchor_fd,true);
    assert(m11_anchor_check(&a)==-EBADF && k.endpoint_releases==0);
    pass("fd-number reuse by another file is an identity mismatch, not the anchor");
    bound();
    km_set_cloexec(&k,0,a.guard_fd,false);
    assert(m11_anchor_check(&a)==-EBADF && (a.latches & M11_ANCHOR_LATCH_FD_DISCIPLINE));
    pass("lost FD_CLOEXEC is refused: an exec'ed child would keep the endpoint");

    bound(); f=anchor_file();
    int job=km_fork(&k,0); km_exec(&k,job);
    assert(km_file_of(&k,job,a.anchor_fd)<0 && km_refs_of(&k,f)==2);
    km_exit(&k,job);
    assert(!m11_anchor_check(&a) && k.endpoint_releases==0);
    pass("fork+exec job drops its inherited references at exec (CLOEXEC); census stays clean");
    int helper=km_fork(&k,0);
    assert(m11_anchor_final_close(&a)==-EBUSY && (a.latches & M11_ANCHOR_LATCH_FOREIGN_HOLDER));
    assert(k.endpoint_releases==0 && seen.foreign==1);
    km_exec(&k,helper); km_exit(&k,helper);
    assert(m11_anchor_final_close(&a)==-EOWNERDEAD && a.state==M11_ANCHOR_HELD);
    pass("final close refused while a forked child still shares the OFD (PID1's close would not be last)");

    bound();
    int intruder=km_fork(&k,0); km_exec(&k,intruder);
    int second=km_open(&k,intruder,true); assert(second>=0 && k.endpoint_opens==2);
    assert(m11_anchor_check(&a)==-EBUSY && seen.foreign==1);
    assert(m11_anchor_lend_begin(&a,&fd)==-EOWNERDEAD);
    km_exit(&k,intruder);
    assert(k.endpoint_releases==1 && km_refs_of(&k,anchor_file())==2);
    pass("LIMIT: a second OFD is detected and latched, but its own last close still runs the global cleanup");

    bound(); k.fail_holders=true;
    assert(m11_anchor_check(&a)==-EIO && (a.latches & M11_ANCHOR_LATCH_CENSUS_ERROR));
    k.fail_holders=false;
    assert(m11_anchor_lend_begin(&a,&fd)==-EOWNERDEAD);
    pass("census error fails closed for the rest of the boot");

    bound();
    assert(!m11_anchor_lend_begin(&a,&fd) && !m11_anchor_lend_abort(&a) && a.state==M11_ANCHOR_HELD);
    assert(m11_anchor_lend_started(&a,5)==-EINVAL);
    pass("fork failure aborts the reserved loan; no worker, no release");
    w=lend();
    assert(m11_anchor_final_close(&a)==-EBUSY);
    km_exit(&k,w); assert(!m11_anchor_lend_end(&a,M11_WORKER_EXIT_OK));
    assert(m11_anchor_end_boot(&a,M11_TERMINAL_HOLD,&end)==-EBUSY && a.state==M11_ANCHOR_HELD);
    assert(m11_anchor_end_boot(&a,M11_TERMINAL_HOLD_RECONCILE,&end)==-EBUSY && a.state==M11_ANCHOR_HELD);
    f=anchor_file();
    assert(!m11_anchor_final_close(&a) && a.state==M11_ANCHOR_RELEASED && a.final_closes==1);
    assert(k.endpoint_releases==1 && k.last_released_file==f && km_refs_of(&k,f)==0);
    assert(!m11_anchor_end_boot(&a,M11_TERMINAL_ORDERLY_SHUTDOWN,&end) && end==M11_ANCHOR_END_REBOOT);
    assert(m11_anchor_final_close(&a)==-EBUSY && m11_anchor_lend_begin(&a,&fd)==-EBUSY);
    pass("final close as sole holder: the second close is the single release; then reboot is allowed");

    memset(&a,0,sizeof(a));
    assert(!m11_anchor_end_boot(&a,M11_TERMINAL_ORDERLY_SHUTDOWN,&end) && end==M11_ANCHOR_END_REBOOT);
    pass("never-bound boot: nothing held, the ledger alone decides");

    fresh(true); ops=km_ops(&k);
    m11_anchor_contract unproven=evidence; unproven.endpoint_has_no_flush=false;
    assert(m11_anchor_bind(&a,&ops,&sink,&unproven,1,KM_ENDPOINT_RDEV)==-EPERM);
    memset(&a,0,sizeof(a));
    assert(!m11_anchor_bind(&a,&ops,&sink,&evidence,1,KM_ENDPOINT_RDEV)); /* contract lies */
    unsigned flushes=k.endpoint_flushes; /* bind's own non-final raw close already ran one */
    w=lend(); km_exit(&k,w); /* guard-copy close + exit_files() of the anchor copy */
    assert(flushes==1 && k.endpoint_releases==0 && k.endpoint_flushes==flushes+2);
    pass("COUNTERFACTUAL flush driver: the anchor stops release but not driver code on a worker exit");

    /* ---------------- custodian ledger integration (strict mock engine) ---------------- */
    static m11_strict_mock_t mock; static m11_gpr_engine_t eng; static m11_shmem_mgr_t mgr;
    static m11_boot_ledger boot; static m11_custodian c;
    m11_custodian_model_contract model={.exclusive_importer=true,.no_other_endpoint=true,
        .no_pcm_clients=true,.strict_iommu=true,.graph_quiescent=true,
        .nack_atomicity_model=true,.final_anchor_pid1=true};
    for (unsigned scenario=0;scenario<3;scenario++) {
        m11_gpr_transport_t tp; m11_shmem_backend_t be;
        memset(&boot,0,sizeof(boot)); memset(&c,0,sizeof(c));
        m11_strict_mock_init(&mock); m11_strict_mock_bind(&mock,&tp,&be);
        assert(!m11_gpr_engine_init(&eng,&tp,0x2002u) && !m11_gpr_engine_open(&eng));
        assert(!m11_shmem_mgr_init(&mgr,&be,&eng,10) && !m11_model_new_boot(&boot,17,100));
        assert(!m11_custodian_init(&c,&boot,&mgr,&model,100));
        bound(); seen.c=&c; seen.now=101;
        if (scenario==0) {
            w=lend(); km_exit(&k,w); assert(!m11_anchor_lend_end(&a,M11_WORKER_EXIT_OK));
            assert(!m11_custodian_close(&c)); /* physical transport close maps to final_close */
            assert(!m11_anchor_final_close(&a) && k.endpoint_releases==1);
            assert(m11_custodian_terminal_action(&c)==M11_TERMINAL_ORDERLY_SHUTDOWN);
            assert(!m11_anchor_end_boot(&a,m11_custodian_terminal_action(&c),&end) && end==M11_ANCHOR_END_REBOOT);
            pass("ledger: never-mapped boot closes once as sole holder, then ORDERLY_SHUTDOWN reboot");
        } else if (scenario==1) {
            unsigned slot=0; assert(!m11_custodian_map(&c,4096,100,&slot));
            w=lend(); assert(km_kill(&k,w)); assert(!m11_anchor_lend_end(&a,M11_WORKER_EXIT_ABNORMAL));
            assert(boot.reasons & M11_TAINT_WORKER_EXIT);
            assert(m11_custodian_terminal_action(&c)==M11_TERMINAL_HOLD_RECONCILE);
            assert(m11_anchor_end_boot(&a,m11_custodian_terminal_action(&c),&end)==-EBUSY);
            assert(m11_custodian_tick(&c,201)==-EOWNERDEAD);
            assert(m11_custodian_terminal_action(&c)==M11_TERMINAL_RESET_RETAINING_ANCHORS);
            assert(!m11_anchor_end_boot(&a,m11_custodian_terminal_action(&c),&end) && end==M11_ANCHOR_END_PID1_EXIT);
            km_exit(&k,0); assert(k.panicked && k.endpoint_releases==0);
            pass("ledger: DSP-mapped boot, worker killed -> taint -> deadline -> PID1 exit, no release");
        } else {
            int intruder2=km_fork(&k,0); km_exec(&k,intruder2); assert(km_open(&k,intruder2,true)>=0);
            assert(m11_anchor_check(&a)==-EBUSY && c.kernel_imports_lost);
            assert(m11_custodian_terminal_action(&c)==M11_TERMINAL_RESET_RETAINING_ANCHORS);
            assert(!m11_anchor_end_boot(&a,m11_custodian_terminal_action(&c),&end) && end==M11_ANCHOR_END_PID1_EXIT);
            unsigned slot=0; assert(m11_custodian_map(&c,4096,102,&slot)<0);
            pass("ledger: foreign holder = uncontrolled global cleanup -> no MAP, PID1 exit");
        }
        seen.c=NULL;
    }
    printf("PID1 anchor model qualification: %u cases PASS; not wired to the native runner; hardware UNKNOWN\n",cases);
    return 0;
}
