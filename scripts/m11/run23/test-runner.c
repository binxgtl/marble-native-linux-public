/* Run23: executes the actual Run23 runner control flow with every syscall, runtime, anchor and
 * spawner boundary replaced. No boot, cdev, QRTR, remoteproc or endpoint call can escape.
 * Checks the R1/P1-P5 ordering: spawner before the endpoint bind; the anchor bind (the only
 * open) only after a qualified PDR UP, sealed right after it; a boot without PDR UP never
 * opens and unlinks the node before any post-bind job; no fork/exec by PID1 after the seal;
 * the single release (final close) before retire and before stop_adsp; every post-bind job
 * through the spawner; reboot only after a REBOOT end. R2 (Run23): the ION node is made and
 * bound after the endpoint bind and before PDR start; the ION anchor bind (the boot's only ION
 * open) follows the endpoint anchor bind at once; one seal covers both pairs and unlinks both
 * nodes; both anchors attach together; the worker setup includes the ION pair; a boot without
 * PDR UP unlinks both nodes; the ION final close follows the endpoint's, before retire and
 * stop_adsp; both anchors must end REBOOT. */
#define main candidate_main
#include "runner.c"
#undef main
#include <signal.h>
#include <assert.h>
#include <setjmp.h>

static jmp_buf escape;
static int mode, held, booted, sealed, forks_after_seal, pd_up;
static char trace[64][32]; static unsigned steps;
static char path[256];
static int owner_sentinel;
static void step(const char *what) { assert(steps<64); snprintf(trace[steps++],sizeof(trace[0]),"%s",what); }
static int at(const char *what) {
    for (unsigned i=0;i<steps;i++) if (!strcmp(trace[i],what)) return (int)i;
    return -1;
}
enum { OK=1, QUERY_ERROR, PD_FAIL, NO_ENDPOINT, BIND_ENDPOINT_FAIL, SPAWNER_FAIL, ANCHOR_BIND_FAIL,
       SEAL_FAIL, ATTACH_FAIL, UNRESOLVED_WORKER, FINAL_CLOSE_FAIL, JOB_UNRESOLVED, STOP_ADSP_FAIL,
       END_RETAIN, LOAN_SETUP_FAIL, AMP_NOT_DISABLED, AMP_JOB_FAIL, FATAL_SIGNAL,
       ION_ABSENT, ION_BIND_FAIL, ION_ANCHOR_BIND_FAIL, ION_FINAL_CLOSE_FAIL, MODES };
/* PID1 kmsg breadcrumbs and the fatal-signal record, captured from the wrapped write(). */
static char crumbs_seen[64][40]; static unsigned ncrumbs; static int fatal_logged;
static int crumb_at(const char *name) {
    for (unsigned i=0;i<ncrumbs;i++) if (!strcmp(crumbs_seen[i],name)) return (int)i;
    return -1;
}
/* candidate_main installs PID1 fatal-signal hold handlers (getpid is wrapped to 1); restore the
 * default actions before any test assertion so a failing assert aborts instead of looping. */
static void default_fatal(void) {
    static const int sigs[]={SIGSEGV,SIGBUS,SIGILL,SIGFPE,SIGABRT,SIGSYS,SIGTRAP};
    struct sigaction d; memset(&d,0,sizeof(d)); d.sa_handler=SIG_DFL;
    for (unsigned i=0;i<sizeof(sigs)/sizeof(*sigs);i++) (void)sigaction(sigs[i],&d,NULL);
}
static const char *last_crumb(void) { return ncrumbs ? crumbs_seen[ncrumbs-1] : ""; }

/* ------------------------------- syscall boundaries ------------------------------- */
pid_t __wrap_getpid(void) { return 1; }
mode_t __wrap_umask(mode_t mask) { (void)mask; return 0; }
pid_t __wrap_fork(void) { if (sealed) forks_after_seal++; step("fork"); return 100+(int)steps; }
static int jobs_reaped;
pid_t __wrap_waitpid(pid_t pid, int *status, int flags) {
    assert(flags==WNOHANG); jobs_reaped++;
    /* the sixth PID1 job is control amp_gate (prepare, journal, probe, start, usb_start, amp_gate) */
    *status=(mode==AMP_JOB_FAIL && jobs_reaped==6) ? 256 : 0; return pid;
}
int __wrap_poll(struct pollfd *fds, nfds_t count, int ms) {
    (void)fds; (void)count;
    if (ms==60000) { held=1; longjmp(escape,1); }
    return 0;
}
int __wrap_clock_gettime(clockid_t clock, struct timespec *t) {
    static long ticks;
    assert(clock==CLOCK_MONOTONIC || clock==CLOCK_BOOTTIME); ticks++; /* BOOTTIME: journal stamps */ t->tv_sec=1+ticks/1000; t->tv_nsec=ticks%1000*1000000L; return 0;
}
int __wrap_open(const char *p, int flags, ...) { (void)flags; snprintf(path,sizeof(path),"%s",p); return 20; }
ssize_t __wrap_read(int fd, void *b, size_t cap) {
    assert(fd==20); const char *value="1\n";
    if (strstr(path,"jseq")) value="9\n";
    if (strstr(path,"/sys/class/aud_pasthru_adsp")) { if (mode==NO_ENDPOINT) return -1; value="240:0\n"; }
    if (strstr(path,"/sys/class/msm_audio_ion_cma/")) value="242:0\n";
    else if (strstr(path,"/sys/class/msm_audio_ion/")) { if (mode==ION_ABSENT) return -1; value="241:0\n"; }
    if (strstr(path,"nonce")) value="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n";
    if (strstr(path,"identity")) value="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n";
    if (strstr(path,"amp-gate.log")) value="ALSA final result=registration-ready\nAMP_SWITCH result=switches-disabled\n";
    if (strstr(path,"amp-gate.result")) {
        step("amp_gate_result");
        value=mode==AMP_NOT_DISABLED ? "switch-not-written\n" : "switches-disabled\n";
    }
    size_t n=strlen(value); assert(n<cap); memcpy(b,value,n); return (ssize_t)n;
}
ssize_t __wrap_write(int fd, const void *b, size_t n) {
    assert(fd==20);
    const char *t=b; const char *k="<5>M11R23 pid1 step=";
    if (n>strlen(k) && !strncmp(t,k,strlen(k))) {
        assert(ncrumbs<64); size_t i=0; t+=strlen(k);
        while (i<sizeof(crumbs_seen[0])-1 && t[i]!=' ' && t[i]!='\n') { crumbs_seen[ncrumbs][i]=t[i]; i++; }
        crumbs_seen[ncrumbs++][i]=0;
    }
    if (n>20 && strstr(b,"pid1 fatal signal=11 ")) fatal_logged=1;
    return (ssize_t)n;
}
int __wrap_close(int fd) { assert(fd>=0); return 0; }
int __wrap_lstat(const char *p, struct stat *st) {
    memset(st,0,sizeof(*st)); st->st_mode=S_IFREG|0600; st->st_nlink=1; st->st_uid=st->st_gid=65534;
    (void)p; return 0;
}
int __wrap_fstat(int fd, struct stat *st) {
    assert(fd==20); memset(st,0,sizeof(*st)); st->st_mode=S_IFCHR|0400; st->st_rdev=makedev(1,11); return 0;
}
int __wrap_mknod(const char *p, mode_t m, dev_t d) {
    assert(!sealed && m==(S_IFCHR|0600));
    if (!strcmp(p,"/dev/msm_audio_ion")) { assert(d==makedev(241,0)); step("mknod_ion"); return 0; }
    assert(!strcmp(p,"/dev/aud_pasthru_adsp") && d==makedev(240,0)); return 0; /* never the CMA twin */
}
FILE *__wrap_fopen(const char *p, const char *m) {
    (void)m; assert(!strcmp(p,"/proc/devices")); FILE *f=tmpfile(); assert(f);
    assert(fputs("Character devices:\n240 aud_pasthru_adsp\n241 msm_audio_ion\n242 msm_audio_ion_cma\n",f)>=0);
    rewind(f); return f;
}
int __wrap_pipe2(int fds[2], int flags) { (void)flags; fds[0]=21; fds[1]=22; return 0; }
int __wrap_unlink(const char *p) {
    assert(!sealed);
    if (!strcmp(p,"/dev/msm_audio_ion")) { step("unlink_ion"); return 0; }
    assert(!strcmp(p,"/dev/aud_pasthru_adsp")); step("unlink_node"); return 0;
}
int __wrap_reboot(int command) { assert(command==RB_AUTOBOOT); step("reboot"); booted=1; longjmp(escape,1); }

/* ------------------------------ runtime boundaries ------------------------------ */
struct m11_audio_runtime *m11_audio_acquire_boot(void) { return (void *)&owner_sentinel; }
pid_t m11_audio_spawn_helper(struct m11_audio_runtime *r, enum m11_audio_helper role, int logfd) {
    assert(r==(void *)&owner_sentinel && logfd==20); return 500+(int)role;
}
int m11_audio_bind_endpoint(struct m11_audio_runtime *r, dev_t d) {
    assert(r==(void *)&owner_sentinel && d==makedev(240,0)); step("bind_endpoint");
    return mode==BIND_ENDPOINT_FAIL ? -1 : 0;
}
int m11_audio_start_pd(struct m11_audio_runtime *r, unsigned ms) {
    assert(r==(void *)&owner_sentinel && ms==5000); step("start_pd");
    if (mode==FATAL_SIGNAL) (void)raise(SIGSEGV); /* PID1 must log and hold, never die */
    pd_up=mode!=PD_FAIL; return pd_up ? 0 : -1;
}
int m11_audio_pump(struct m11_audio_runtime *r) { assert(r==(void *)&owner_sentinel); return 0; }
int m11_gpr_linux_query(struct m11_gpr_session *s, struct m11_gpr_result *out) {
    assert(s->runtime==(void *)&owner_sentinel && s->budget_ms==4000); step("query");
    memset(out,0,sizeof(*out)); out->close_returned=out->close_ok=out->worker_reaped=out->worker_exit_ok=out->ipc_complete=1;
    out->query_consistent=mode!=QUERY_ERROR; return mode==QUERY_ERROR ? -1 : 0;
}
int m11_audio_snapshot(const struct m11_audio_runtime *r, struct m11_audio_status *out) {
    assert(r==(void *)&owner_sentinel); memset(out,0,sizeof(*out));
    out->acquired=1; out->resources_quiescent=mode!=UNRESOLVED_WORKER;
    out->unresolved_worker=mode==UNRESOLVED_WORKER ? 42 : 0; return 0;
}
int m11_audio_retire(struct m11_audio_runtime *r) { assert(r==(void *)&owner_sentinel); step("retire"); return 0; }
int m11_audio_attach_spawner(struct m11_audio_runtime *r, pid_t pid) {
    assert(r==(void *)&owner_sentinel && pid==700); step("attach_spawner"); return 0;
}
int m11_audio_bind_ion(struct m11_audio_runtime *r, dev_t ion, dev_t cma) {
    assert(r==(void *)&owner_sentinel && ion==makedev(241,0) && cma==makedev(242,0) && !pd_up);
    step("bind_ion"); return mode==ION_BIND_FAIL ? -1 : 0;
}
int m11_audio_attach_anchors(struct m11_audio_runtime *r, m11_pid1_anchor *a, m11_pid1_anchor *ion) {
    assert(r==(void *)&owner_sentinel && a==&anchor && ion==&ion_anchor && sealed);
    step("attach_anchor"); return mode==ATTACH_FAIL ? -1 : 0;
}
int m11_gpr_anchor_attach_ion(const m11_pid1_anchor *a) {
    assert(a==&ion_anchor && sealed); step("loan_setup_ion"); return 0;
}
int m11_gpr_last_worker_status(void) { return 0; }
int m11_gpr_anchor_attach(m11_pid1_anchor *a, const int *keep, unsigned n) {
    assert(a==&anchor && n==1 && keep && *keep==20); step("loan_setup"); return mode==LOAN_SETUP_FAIL ? -1 : 0;
}

/* --------------------------- anchor and spawner boundaries --------------------------- */
int m11_spawner_start(m11_spawner *s, const char *const *const *commands, unsigned count, bool require_drop) {
    assert(s==&spawner && commands==spawner_jobs && count==2 && require_drop);
    assert(!strcmp(commands[0][2],"/m11/control") && !strcmp(commands[1][0],"/sbin/m11-checkpoint"));
    step("spawner_start");
    if (mode==SPAWNER_FAIL) return -1;
    *s=(m11_spawner){30,700,true}; return 0;
}
int m11_spawner_run_flags(m11_spawner *s, unsigned index, const char *arg, unsigned ms, unsigned flags, int *status) {
    assert(s==&spawner && (flags & M11_SPAWN_NO_KILL) && ms>0 && arg);
    char name[32]; snprintf(name,sizeof(name),"%s:%s",index==JOB_CONTROL ? "spawn" : "checkpoint",arg);
    step(name); *status=0;
    if (mode==JOB_UNRESOLVED && !strcmp(arg,"usb_stop")) return -EINPROGRESS;
    if (mode==STOP_ADSP_FAIL && !strcmp(arg,"stop_adsp")) *status=1;
    return 0;
}
int m11_spawner_stop(m11_spawner *s) { assert(s==&spawner); step("spawner_stop"); return 0; }
int m11_anchor_linux_ops(m11_anchor_linux *l, const char *p, int root, m11_anchor_ops *out) {
    assert((l==&anchor_backend && !strcmp(p,"/dev/aud_pasthru_adsp")) ||
           (l==&ion_backend && !strcmp(p,"/dev/msm_audio_ion")));
    assert(root==0 && out);
    memset(out,0,sizeof(*out)); return 0;
}
int m11_anchor_bind(m11_pid1_anchor *a, const m11_anchor_ops *ops, const m11_anchor_sink *sink,
                    const m11_anchor_contract *ct, int owner_pid, uint64_t rdev) {
    assert(ops && !sink && owner_pid==1 && !sealed);
    assert(ct->endpoint_has_no_flush && ct->release_on_last_fput_only && ct->owner_single_threaded);
    assert(pd_up); /* the boot's only opens, only after a qualified PDR UP */
    if (a==&ion_anchor) {
        assert(ct==&ion_evidence && rdev==(uint64_t)makedev(241,0) && anchor.state==M11_ANCHOR_HELD);
        step("ion_anchor_bind");
        if (mode==ION_ANCHOR_BIND_FAIL) return -ENODEV;
        a->state=M11_ANCHOR_HELD; a->bind_attempted=true; return 0;
    }
    assert(a==&anchor && ct==&evidence && rdev==(uint64_t)makedev(240,0));
    step("anchor_bind");
    if (mode==ANCHOR_BIND_FAIL) return -ENODEV;
    a->state=M11_ANCHOR_HELD; a->bind_attempted=true; return 0;
}
int m11_anchor_owner_seal_pairs(m11_pid1_anchor *const *a, const char *const *nodes, unsigned n) {
    assert(n==2 && a[0]==&anchor && a[1]==&ion_anchor && nodes);
    assert(!strcmp(nodes[0],"/dev/aud_pasthru_adsp") && !strcmp(nodes[1],"/dev/msm_audio_ion"));
    assert(anchor.state==M11_ANCHOR_HELD && ion_anchor.state==M11_ANCHOR_HELD); step("seal");
    if (mode==SEAL_FAIL) return -EPERM;
    sealed=1; return 0;
}
int m11_anchor_final_close(m11_pid1_anchor *a) {
    assert(sealed);
    if (a==&ion_anchor) {
        assert(anchor.state==M11_ANCHOR_OWNER_FDS_DROPPED); step("ion_final_close");
        if (mode==ION_FINAL_CLOSE_FAIL) return -EOWNERDEAD;
        a->state=M11_ANCHOR_OWNER_FDS_DROPPED; return 0;
    }
    assert(a==&anchor); step("final_close");
    if (mode==FINAL_CLOSE_FAIL) return -EOWNERDEAD;
    a->state=M11_ANCHOR_OWNER_FDS_DROPPED; return 0;
}
int m11_anchor_end_boot(m11_pid1_anchor *a, m11_terminal_action t, m11_anchor_end *out) {
    assert((a==&anchor || a==&ion_anchor) && t==M11_TERMINAL_ORDERLY_SHUTDOWN);
    step(a==&anchor ? "end_boot" : "ion_end_boot");
    bool reboot=mode!=END_RETAIN && (a->state==M11_ANCHOR_OWNER_FDS_DROPPED || !a->bind_attempted);
    *out=reboot ? M11_ANCHOR_END_REBOOT : M11_ANCHOR_END_RETAIN;
    return reboot ? 0 : -EPROTO;
}

int main(void) {
    static const char *post[]={"spawn:seal","spawn:usb_stop","spawn:stop_adsp","spawn:common",
                               "checkpoint:green","spawn:unmount"};
    for (mode=OK;mode<MODES;mode++) {
        held=booted=sealed=forks_after_seal=pd_up=0; steps=0; journal_sealed=0;
        ncrumbs=0; fatal_logged=0; jobs_reaped=0;
        sigset_t none; sigemptyset(&none); sigprocmask(SIG_SETMASK,&none,NULL); /* after a handler longjmp */
        memset(&result,0,sizeof(result)); memset(&anchor,0,sizeof(anchor)); memset(&ion_anchor,0,sizeof(ion_anchor));
        memset(&spawner,0,sizeof(spawner));
        if (!setjmp(escape)) { candidate_main(1,NULL); default_fatal(); assert(0); }
        default_fatal(); /* the runner's PID1 fatal-signal hold must not swallow test assertions */
        assert(held!=booted && !forks_after_seal);           /* PID1 never forks/execs after the seal */
        int spawn=at("spawner_start"), bind=at("bind_endpoint"), anch=at("anchor_bind"), seal=at("seal");
        int query=at("query"), fin=at("final_close"), retire=at("retire"), stop=at("spawn:stop_adsp");
        int pd=at("start_pd"), unlinked=at("unlink_node");
        int mk_ion=at("mknod_ion"), ion=at("bind_ion"), ianch=at("ion_anchor_bind"), ifin=at("ion_final_close");
        int unlinked_ion=at("unlink_ion");
        int gate=at("amp_gate_result");
        if (spawn>=0) assert(gate>=0 && gate<spawn);          /* the amp gate precedes the spawner */
        if (bind>=0) assert(crumb_at("amp_disabled")>=0);      /* no endpoint without Disable */
        assert(crumb_at("start")==0 && crumb_at("prepare")==1); /* PID1 breadcrumbs from the start */
        if (held && mode==ANCHOR_BIND_FAIL) assert(!strcmp(last_crumb(),"anchor_bind"));
        if (held && mode==SEAL_FAIL) assert(!strcmp(last_crumb(),"seal"));
        if (held && mode==FINAL_CLOSE_FAIL) assert(!strcmp(last_crumb(),"final_close"));
        if (held && mode==ION_ABSENT) assert(!strcmp(last_crumb(),"ion_wait"));
        if (held && mode==ION_BIND_FAIL) assert(!strcmp(last_crumb(),"ion_bind"));
        if (held && mode==ION_ANCHOR_BIND_FAIL) assert(!strcmp(last_crumb(),"ion_anchor_bind"));
        if (held && mode==ION_FINAL_CLOSE_FAIL) assert(!strcmp(last_crumb(),"ion_final_close"));
        if (booted) assert(!strcmp(last_crumb(),"reboot"));
        if (mode!=SPAWNER_FAIL && mode!=AMP_NOT_DISABLED && mode!=AMP_JOB_FAIL)
            assert(spawn>=0 && at("attach_spawner")==spawn+1);
        if (bind>=0) assert(spawn>=0 && spawn<bind);         /* the spawner predates the bind */
        if (anch>=0) assert(bind>=0 && pd>bind && anch==pd+1); /* PID1's single open only after PDR UP */
        /* R2: the ION node and its bind after the endpoint bind and before PDR start */
        if (mk_ion>=0) assert(bind>=0 && mk_ion>bind && (pd<0 || mk_ion<pd));
        if (ion>=0) assert(mk_ion>=0 && ion>mk_ion && (pd<0 || ion<pd));
        if (pd>=0) assert(ion>=0);                            /* no PDR start without the ION bind */
        if (ianch>=0) assert(anch>=0 && ianch==anch+1);       /* the ION open right after the endpoint's */
        if (seal>=0) assert(ianch>=0 && seal==ianch+1);       /* one seal over both, before anything else */
        if (query>=0) assert(seal>=0 && at("attach_anchor")>seal && at("loan_setup")<query &&
                             at("loan_setup_ion")>at("loan_setup") && at("loan_setup_ion")<query);
        if (ifin>=0) assert(fin>=0 && ifin==fin+1 && (retire<0 || ifin<retire));
        if (stop>=0 && ianch>=0) assert(ifin>=0 && ifin<stop); /* both released before the ADSP stops */
        if (unlinked_ion>=0) assert(ianch<0 && unlinked>=0 && unlinked_ion==unlinked+1);
        if (booted && ion>=0) assert(at("ion_end_boot")>at("end_boot") && at("spawner_stop")>at("ion_end_boot"));
        if (fin>=0) assert(anch>=0 && fin>query && (retire<0 || fin<retire));
        if (stop>=0 && anch>=0) assert(fin>=0 && fin<stop);  /* release before the ADSP stops */
        if (unlinked>=0) assert(anch<0 && fin<0 && unlinked>pd && unlinked<retire); /* PDR never UP: never opened */
        if (stop>=0 && bind>=0) assert(anch>=0 || (unlinked>=0 && unlinked<at("spawn:seal")));
        if (booted) {
            for (unsigned i=0;i<6;i++) {
                const char *want=post[i];
                if (mode!=OK && !strcmp(want,"checkpoint:green")) continue; /* colour depends on mode */
                assert(at(want)>=0 && (seal<0 || at(want)>seal));
            }
            assert(at("end_boot")>=0 && at("spawner_stop")>at("end_boot") && at("reboot")>at("spawner_stop"));
        }
        switch (mode) {
        case OK: assert(booted && ifin>=0 && at("checkpoint:green")>=0); break;
        case QUERY_ERROR: assert(booted && at("checkpoint:red")>=0 && fin>=0); break;
        case PD_FAIL: assert(booted && query<0 && anch<0 && fin<0 && unlinked>=0 && unlinked_ion>=0 && at("checkpoint:cyan")>=0); break;
        case NO_ENDPOINT: assert(booted && bind<0 && anch<0 && fin<0 && at("checkpoint:red")>=0); break;
        case BIND_ENDPOINT_FAIL: assert(held && anch<0 && stop<0); break;
        case SPAWNER_FAIL: assert(held && bind<0 && anch<0); break;
        case ANCHOR_BIND_FAIL: assert(held && seal<0 && query<0 && stop<0); break;
        case SEAL_FAIL: assert(held && query<0 && at("attach_anchor")<0 && stop<0); break;
        case ATTACH_FAIL: assert(held && query<0 && stop<0); break;
        case UNRESOLVED_WORKER: assert(held && query>=0 && fin<0 && retire<0 && stop<0); break;
        case FINAL_CLOSE_FAIL: assert(held && fin>=0 && retire<0 && stop<0 && at("spawn:seal")<0); break;
        case JOB_UNRESOLVED: assert(held && at("spawn:usb_stop")>=0 && stop<0); break;
        case STOP_ADSP_FAIL: assert(held && stop>=0 && at("spawn:common")<0); break;
        case END_RETAIN: assert(held && at("end_boot")>=0 && at("reboot")<0); break;
        case LOAN_SETUP_FAIL: assert(held && query<0 && fin<0 && stop<0); break;
        case AMP_NOT_DISABLED: assert(held && spawn<0 && bind<0 && anch<0 && !strcmp(last_crumb(),"amp_gate")); break;
        case AMP_JOB_FAIL: assert(held && at("amp_gate_result")<0 && spawn<0 && bind<0); break;
        case FATAL_SIGNAL: assert(held && fatal_logged && anch<0 && !strcmp(last_crumb(),"pd_begin")); break;
        case ION_ABSENT: assert(held && ion<0 && mk_ion<0 && pd<0 && anch<0 && stop<0); break;
        case ION_BIND_FAIL: assert(held && ion>=0 && pd<0 && anch<0 && stop<0); break;
        case ION_ANCHOR_BIND_FAIL: assert(held && anch>=0 && ianch>=0 && seal<0 && query<0 && stop<0); break;
        case ION_FINAL_CLOSE_FAIL: assert(held && fin>=0 && ifin>=0 && retire<0 && stop<0); break;
        }
    }
    printf("Run23 runner control flow: %d scenarios PASS (amp gate before the spawner and the endpoint, "
           "breadcrumbs localise the failing phase, a PID1 fatal signal is logged and held, "
           "spawner before the endpoint bind, the "
           "only open after PDR UP and sealed at once, no open without PDR UP, no PID1 fork after "
           "the seal, release before retire and stop_adsp, post-bind jobs via the spawner, reboot "
           "only after a REBOOT end; R2: ION node and bind before PDR start, the ION open right after "
           "the endpoint's, one seal over both pairs, both unlinked without PDR UP, the ION release "
           "right after the endpoint's, both anchors end REBOOT); no hardware\n",MODES-1);
    return 0;
}
