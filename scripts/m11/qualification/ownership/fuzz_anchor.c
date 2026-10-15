/* Seeded state-machine fuzz of the PID1 anchor against the synthetic file-lifetime model.
 * Operations: loans with every worker fate (normal, exit without close, SIGKILL, D-state), one
 * accidental PID1 close or fd-number reuse per boot, lost FD_CLOEXEC, fork+exec jobs, forked
 * children that never exec, a second OFD opened by another process, census faults, checks and
 * final-close attempts. Invariants (R1):
 *   I1 the anchor OFD is released only inside a successful final close;
 *   I2 a successful final close is the last fput of the anchor OFD;
 *   I3 no loan or final close is granted while another process holds the anchor OFD or a
 *      second endpoint OFD exists.
 * Every draw is its own statement so the operation sequence is compiler-independent. */
#define _GNU_SOURCE
#include "m11_pid1_anchor.h"
#include "anchor_kernel_model.h"
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint64_t rng;
static uint64_t next64(void) {
    uint64_t z=(rng+=0x9e3779b97f4a7c15ull);
    z=(z^(z>>30))*0xbf58476d1ce4e5b9ull; z=(z^(z>>27))*0x94d049bb133111ebull;
    return z^(z>>31);
}
static unsigned draw(unsigned n) { return (unsigned)(next64()%n); }

enum { C_LEND, C_LEND_OK, C_KILL, C_UNRESOLVED, C_PID1_BUG, C_REUSE, C_CLOEXEC, C_JOB, C_HELPER,
       C_FOREIGN, C_CENSUS_FAULT, C_FINAL_OK, C_FINAL_REFUSED, C_LATCH_FOREIGN, C_LATCH_FD,
       C_LATCH_UNRESOLVED, C_N };
static const char *const cov_name[C_N]={"lend","lend_ok","worker_kill","worker_unresolved",
    "pid1_close_bug","fd_reuse_bug","cloexec_lost","exec_job","noexec_child","second_ofd",
    "census_fault","final_close_ok","final_close_refused","latched_foreign","latched_fd",
    "latched_unresolved"};
static unsigned long cov[C_N];
enum { R_NONE, R_HELPER, R_JOB, R_FOREIGN, R_UNRESOLVED };
static int role[KM_PROCS];
static km_kernel k;
static m11_pid1_anchor a;
static int anchor_file;
static unsigned long violations, scenario_no;
static const m11_anchor_contract evidence={.endpoint_has_no_flush=true,
    .release_on_last_fput_only=true,.owner_single_threaded=true};

static void violation(const char *what, unsigned step) {
    if (++violations<=8) printf("VIOLATION scenario %lu step %u: %s\n",scenario_no,step,what);
}
static unsigned others_holding(void) {
    unsigned n=0;
    for (int i=1;i<KM_PROCS;i++) {
        if (!k.procs[i].alive) continue;
        for (int fd=0;fd<KM_FDS;fd++) if (k.procs[i].fd[fd] && k.procs[i].fd[fd]-1==anchor_file) { n++; break; }
    }
    return n;
}
static void lend(unsigned fate, unsigned step) {
    unsigned others=others_holding();
    bool second=km_foreign_endpoint_ofd(&k,anchor_file);
    int fd=-1;
    if (m11_anchor_lend_begin(&a,&fd)) return;
    cov[C_LEND]++;
    if (others) violation("loan granted while another process held the endpoint OFD",step);
    if (second) violation("loan granted while a second endpoint OFD existed",step);
    int w=km_fork(&k,0);
    if (w<0) { (void)m11_anchor_lend_abort(&a); return; }
    (void)m11_anchor_lend_started(&a,k.procs[w].pid);
    k.current=w;
    int accepted=m11_anchor_worker_accept(&a,fd);
    k.procs[w].privileged=false;
    k.current=0;
    m11_worker_end end=M11_WORKER_EXIT_OK;
    if (accepted) { km_exit(&k,w); end=M11_WORKER_EXIT_ABNORMAL; }
    else if (fate==0) { (void)km_close(&k,w,fd); km_exit(&k,w); }
    else if (fate==1) km_exit(&k,w);
    else if (fate==2) { (void)km_kill(&k,w); end=M11_WORKER_EXIT_ABNORMAL; cov[C_KILL]++; }
    else { k.procs[w].dstate=true; (void)km_kill(&k,w); end=M11_WORKER_UNRESOLVED; role[w]=R_UNRESOLVED; cov[C_UNRESOLVED]++; }
    if (!m11_anchor_lend_end(&a,end) && end==M11_WORKER_EXIT_OK) cov[C_LEND_OK]++;
}
static int pick_child(void) {
    int live[KM_PROCS], n=0;
    for (int i=1;i<KM_PROCS;i++) if (k.procs[i].alive && role[i]!=R_NONE && role[i]!=R_UNRESOLVED) live[n++]=i;
    if (!n) return -1;
    unsigned choice=draw((unsigned)n);
    return live[choice];
}
static void scenario(unsigned steps) {
    km_init(&k,false); memset(&a,0,sizeof(a)); memset(role,0,sizeof(role));
    m11_anchor_ops ops=km_ops(&k);
    (void)m11_anchor_bind(&a,&ops,NULL,&evidence,1,KM_ENDPOINT_RDEV);
    anchor_file=km_file_of(&k,0,a.anchor_fd);
    if (anchor_file<0) { violation("bind did not leave an anchor",0); return; }
    k.oracle_file=anchor_file; /* model-only release oracle (none exists for the real endpoint) */
    bool pid1_bug=false, released_in_final=false, done=false;
    for (unsigned s=0;s<steps && !done;s++) {
        k.current=0;
        unsigned op=draw(15);
        if (op<4) lend(op,s);
        else if (op==4 || op==5) {
            if (!pid1_bug) {
                pid1_bug=true;
                unsigned which=draw(2);
                int victim=which ? a.anchor_fd : a.guard_fd;
                if (op==4) { (void)km_close(&k,0,victim); cov[C_PID1_BUG]++; }
                else {
                    int other=km_open(&k,0,false);
                    if (other>=0) { (void)km_dup2(&k,0,other,victim); (void)km_close(&k,0,other); }
                    cov[C_REUSE]++;
                }
            }
        } else if (op==6) {
            unsigned which=draw(2);
            km_set_cloexec(&k,0,which ? a.anchor_fd : a.guard_fd,false); cov[C_CLOEXEC]++;
        } else if (op==7) {
            int c=km_fork(&k,0);
            if (c>0) {
                km_exec(&k,c);
                unsigned stay=draw(2);
                if (stay) role[c]=R_JOB; else km_exit(&k,c);
            }
            cov[C_JOB]++;
        } else if (op==8) {
            int c=km_fork(&k,0);
            if (c>0) role[c]=R_HELPER;
            cov[C_HELPER]++;
        } else if (op==9) {
            int c=pick_child();
            if (c>0) {
                if (role[c]==R_HELPER) km_exec(&k,c);
                km_exit(&k,c); role[c]=R_NONE;
            }
        } else if (op==10) {
            int c=km_fork(&k,0);
            if (c>0) { km_exec(&k,c); if (km_open(&k,c,true)>=0) role[c]=R_FOREIGN; else km_exit(&k,c); }
            cov[C_FOREIGN]++;
        } else if (op==11) (void)m11_anchor_check(&a);
        else if (op==12) {
            k.fail_holders=true; (void)m11_anchor_check(&a); k.fail_holders=false; cov[C_CENSUS_FAULT]++;
        } else {
            unsigned attempt=draw(3);
            if (!attempt) {
                bool second=km_foreign_endpoint_ofd(&k,anchor_file);
                bool before=k.files[anchor_file].released;
                if (m11_anchor_final_close(&a)) cov[C_FINAL_REFUSED]++;
                else {
                    cov[C_FINAL_OK]++; done=true;
                    if (!before && k.files[anchor_file].released) released_in_final=true;
                    else violation("final close returned success but was not the last fput",s);
                    if (a.release!=(released_in_final ? M11_RELEASE_OBSERVED : M11_RELEASE_NOT_OBSERVED))
                        violation("release evidence disagrees with the oracle",s);
                    if (second) violation("final close granted while a second endpoint OFD existed",s);
                }
            }
        }
        if (k.files[anchor_file].released && !released_in_final) {
            violation("anchor OFD released outside the adapter's final close",s); done=true;
        }
    }
    if (a.latches & M11_ANCHOR_LATCH_FOREIGN_HOLDER) cov[C_LATCH_FOREIGN]++;
    if (a.latches & M11_ANCHOR_LATCH_FD_DISCIPLINE) cov[C_LATCH_FD]++;
    if (a.latches & M11_ANCHOR_LATCH_WORKER_UNRESOLVED) cov[C_LATCH_UNRESOLVED]++;
    if (a.state!=M11_ANCHOR_OWNER_FDS_DROPPED) {
        m11_anchor_end end;
        (void)m11_anchor_end_boot(&a,M11_TERMINAL_RESET_RETAINING_ANCHORS,&end);
        km_exit(&k,0); /* global init: panic before exit_files() */
        if (k.files[anchor_file].released && !released_in_final)
            violation("anchor OFD released by the PID1-exit end of boot",steps);
    }
}
int main(int argc, char **argv) {
    if (argc!=4) { fprintf(stderr,"usage: %s seed scenarios steps\n",argv[0]); return 2; }
    uint64_t seed=strtoull(argv[1],NULL,0);
    unsigned long n=strtoul(argv[2],NULL,0); unsigned steps=(unsigned)strtoul(argv[3],NULL,0);
    rng=seed;
    for (scenario_no=0;scenario_no<n;scenario_no++) scenario(steps);
    printf("SEED %" PRIu64 " scenarios %lu steps %u violations %lu\n",seed,n,steps,violations);
    printf("COVERAGE");
    for (int i=0;i<C_N;i++) printf(" %s=%lu",cov_name[i],cov[i]);
    printf("\n");
    if (violations) return 1;
    for (int i=0;i<C_N;i++) if (!cov[i]) { printf("COVERAGE GATE FAILED: %s\n",cov_name[i]); return 3; }
    printf("PASS anchor fuzz seed %" PRIu64 ": I1-I3 hold; every operation class covered\n",seed);
    return 0;
}
