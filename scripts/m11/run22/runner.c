/* Run22 GPR diagnostic PID1 (scripts/m11/run22/SPEC.md): anchor-native/runner.c plus the Run22 changes.
 * One GPR GET_SPF_STATE query on a never-mapped boot; no PCM, playback, amplifier enable,
 * calibration, gain, graph or DSP memory map. R1: PID1 performs the boot's only open of the
 * endpoint (after a qualified PDR UP) and holds it (anchor + guard); the query worker borrows it.
 * P1-P5: post-bind jobs run from a spawner forked before the endpoint bind; PID1 seals itself
 * right after its open. Run22 additions: receive-only USB observer (no host acknowledgement);
 * the query requires both amplifier switches read back Disable (control amp_gate) before the
 * endpoint node exists; PID1 breadcrumbs on kmsg before every phase; a fatal signal in PID1
 * is recorded on kmsg and held instead of killing init (which would panic the kernel). */
#define _GNU_SOURCE
#include "audio_runtime.h"
#include "gpr_native.h"
#include "anchor_native.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>

static unsigned seq;
static int journal_sealed;
static char json[32769], line[66000];
static struct m11_audio_status owner;
static struct m11_gpr_result result;
static uint64_t now(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC,&t)) return 0;
    return (uint64_t)t.tv_sec*1000000000ULL+(uint64_t)t.tv_nsec;
}
static void pause10(void) { (void)poll(NULL,0,10); }
static int readtext(const char *path, char *b, size_t cap) {
    int fd=open(path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC); if (fd<0) return -1;
    ssize_t n=read(fd,b,cap-1); int rc=close(fd);
    if (n<0 || n==(ssize_t)cap-1 || rc) return -1;
    b[n]=0; return 0;
}
static int writefile(const char *path, const char *b) {
    int fd=open(path,O_WRONLY|O_CLOEXEC|O_NOFOLLOW); if (fd<0) return -1;
    size_t n=strlen(b); ssize_t rc=write(fd,b,n); int cr=close(fd);
    return rc==(ssize_t)n && !cr?0:-1;
}
static int marker(const char *path) {
    int fd=open(path,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if (fd<0) return -1;
    ssize_t n=write(fd,"1\n",2); int rc=close(fd); return n==2 && !rc?0:-1;
}
static int record(const char *operation, const char *payload, int rc) {
    size_t n=strlen(payload); uint64_t t=now();
    if (n>32768 || !t) return -1;
    int prefix=snprintf(line,sizeof(line),"M11I1 %u %llu.%09llu session %s metadata %d ",seq,
        (unsigned long long)(t/1000000000),(unsigned long long)(t%1000000000),operation,rc);
    if (prefix<0 || (size_t)prefix+2*n+2>=sizeof(line)) return -1;
    static const char hex[]="0123456789abcdef";
    size_t used=(size_t)prefix;
    for (size_t i=0;i<n;i++) { unsigned char c=(unsigned char)payload[i]; line[used++]=hex[c>>4]; line[used++]=hex[c&15]; }
    if (!n) line[used++]='-';
    line[used++]='\n';
    int fd=open("/run/m11-instrumentation/journal",O_WRONLY|O_APPEND|O_NOFOLLOW|O_CLOEXEC);
    if (fd<0) return -1;
    ssize_t got=write(fd,line,used); int cr=close(fd);
    if (got!=(ssize_t)used || cr) return -1;
    seq++; char b[32]; snprintf(b,sizeof(b),"%u\n",seq);
    return writefile("/run/m11/jseq",b);
}
/* Breadcrumbs: one kmsg line per phase on PID1's own fd, streamed live by the relay as K frames,
 * so a reset or a hang localises the last phase entered even when the journal never ships. */
/* A fresh fd per line: devkmsg rate limiting is per open file. open/write/close are
 * async-signal-safe, so the fatal handler uses the same path. */
static unsigned crumbs;
static void kmsg_line(const char *b, size_t n) {
    int fd=open("/dev/kmsg",O_WRONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC);
    if (fd<0) return;
    ssize_t w=write(fd,b,n); (void)w; /* best effort: (void) alone does not satisfy warn_unused_result */
    (void)close(fd);
}
static void crumb(const char *step) {
    char b[160];
    int n=snprintf(b,sizeof(b),"<5>M11R22 pid1 step=%s n=%u\n",step,++crumbs);
    if (n>0 && (size_t)n<sizeof(b)) kmsg_line(b,(size_t)n);
}
/* A fatal signal in PID1 would kill init and panic the kernel (immediate reboot). Record it on
 * kmsg (async-signal-safe: write and poll only) and hold instead; any other process keeps the
 * default action. Installed in PID1 before anything else; inherited by forks until exec. */
static char fatal_stack[65536];
static void fatal(int sig, siginfo_t *info, void *context) {
    (void)context;
    if (getpid()!=1) {
        struct sigaction dfl; memset(&dfl,0,sizeof(dfl)); dfl.sa_handler=SIG_DFL;
        (void)sigaction(sig,&dfl,NULL); (void)raise(sig); _exit(128+sig);
    }
    static const char hex[]="0123456789abcdef";
    char b[96]="<2>M11R22 pid1 fatal signal=00 addr=0x0000000000000000 held\n";
    b[28]=(char)('0'+sig/10%10); b[29]=(char)('0'+sig%10);
    uintptr_t a=info ? (uintptr_t)info->si_addr : 0;
    for (int i=0;i<16;i++) b[38+i]=hex[(a>>(60-4*i))&15]; /* digits after "addr=0x" */
    kmsg_line(b,strlen(b));
    for (;;) (void)poll(NULL,0,60000);
}
static int fatal_handlers(void) {
    stack_t ss={.ss_sp=fatal_stack,.ss_size=sizeof(fatal_stack),.ss_flags=0};
    if (sigaltstack(&ss,NULL)) return -1;
    struct sigaction sa; memset(&sa,0,sizeof(sa));
    sa.sa_sigaction=fatal; sa.sa_flags=SA_SIGINFO|SA_ONSTACK; sigfillset(&sa.sa_mask);
    static const int sigs[]={SIGSEGV,SIGBUS,SIGILL,SIGFPE,SIGABRT,SIGSYS,SIGTRAP};
    for (unsigned i=0;i<sizeof(sigs)/sizeof(*sigs);i++) if (sigaction(sigs[i],&sa,NULL)) return -1;
    return 0;
}
static void hold(const char *why) __attribute__((noreturn));
static void hold(const char *why) {
    char b[256]; int n=snprintf(b,sizeof(b),"<3>M11R22 pid1 hold: %s\n",why);
    if (n>0 && (size_t)n<sizeof(b)) kmsg_line(b,(size_t)n);
    if (!journal_sealed) (void)record("hold",why,1);
    for (;;) (void)poll(NULL,0,60000);
}
/* Never retry or silently kill a still-running device/control syscall. */
static int reap(pid_t pid, unsigned ms) {
    uint64_t begin=now(), until=begin+(uint64_t)ms*1000000; int status;
    if (!begin || pid<=1) return -1;
    do {
        pid_t rc=waitpid(pid,&status,WNOHANG);
        if (rc==pid) return WIFEXITED(status)?WEXITSTATUS(status):-1;
        if (rc<0 && errno!=EINTR) return -1;
        pause10();
    } while (now() && now()<until);
    hold("unresolved control/helper child; resources retained");
}
static int job(const char *script, const char *arg, unsigned ms) {
    pid_t p=fork();
    if (!p) { execl("/bin/busybox","busybox","sh",script,arg,(char *)NULL); _exit(127); }
    return reap(p,ms);
}
/* After the bind PID1 is sealed (no execve): every later job runs through the spawner, which
 * was forked before the bind and lacks CAP_MKNOD, CAP_SYS_PTRACE and CAP_DAC_READ_SEARCH. As
 * with job(), a job past its deadline is never killed: PID1 holds with resources retained. */
static m11_spawner spawner;
static const char *const control_job[]={"/bin/busybox","sh","/m11/control",NULL};
static const char *const checkpoint_job[]={"/sbin/m11-checkpoint",NULL};
static const char *const *const spawner_jobs[]={control_job,checkpoint_job};
enum { JOB_CONTROL, JOB_CHECKPOINT };
static int spawned(unsigned index, const char *arg, unsigned ms) {
    int status=0, rc=m11_spawner_run_flags(&spawner,index,arg,ms,M11_SPAWN_NO_KILL,&status);
    if (rc==-EINPROGRESS) hold("unresolved spawner job; resources retained");
    return rc || status ? -1 : 0;
}
/* Static facts, each with recorded evidence (docs/m11-argon-pid1-anchor-adapter.md section 2):
 * audio_pkt_fops has no flush; release runs on the last fput only; PID1 is single-threaded
 * (census) and the seal refuses CLONE_FILES/CLONE_THREAD. */
static const m11_anchor_contract evidence={.endpoint_has_no_flush=true,
    .release_on_last_fput_only=true,.owner_single_threaded=true};
static m11_pid1_anchor anchor;
static m11_anchor_linux anchor_backend;
static int wait_marker(const char *path, unsigned ms) {
    uint64_t begin=now(), until=begin+(uint64_t)ms*1000000; struct stat st;
    if (!begin) return -1;
    do { if (!lstat(path,&st)) return S_ISREG(st.st_mode)?0:-1; pause10(); } while (now() && now()<until);
    return -1;
}
static int hexfile(const char *path, unsigned char *out, size_t count) {
    char b[80]; if (readtext(path,b,sizeof(b)) || strlen(b)!=2*count+1 || b[2*count]!='\n') return -1;
    for (size_t i=0;i<count;i++) {
        unsigned v=0;
        for (unsigned j=0;j<2;j++) { char c=b[i*2+j]; if (c<'0' || (c>'9' && c<'a') || c>'f') return -1; v=v*16+(unsigned)(c<='9'?c-'0':c-'a'+10); }
        out[i]=(unsigned char)v;
    }
    return 0;
}
/* The kernel creates this class/cdev; we create only its RAM /dev node. */
static dev_t endpoint(void) {
    char b[256]; unsigned maj,min; char tail;
    if (readtext("/sys/class/aud_pasthru_adsp/aud_pasthru_adsp/dev",b,sizeof(b)) ||
        sscanf(b,"%u:%u %c",&maj,&min,&tail)!=2 || !maj || min) return 0;
    FILE *f=fopen("/proc/devices","re"); if (!f) return 0;
    int found=0; unsigned m; char name[128];
    while (fgets(b,sizeof(b),f)) if (sscanf(b,"%u %127s",&m,name)==2 && !strcmp(name,"aud_pasthru_adsp") && m==maj) found++;
    if (fclose(f) || found!=1) return 0;
    dev_t dev=makedev(maj,min);
    if (mknod("/dev/aud_pasthru_adsp",S_IFCHR|0600,dev)) return 0;
    return dev;
}
static int log_owner(struct m11_audio_runtime *r) {
    if (m11_audio_snapshot(r,&owner) || m11_audio_status_encode(&owner,json,sizeof(json))<0) return -1;
    return record("owner_pd",json,0);
}
struct diagnostic { int fd; uint32_t token; };
/* Runs in the contained I/O worker, never the PDR-monitor parent. A compact
 * per-event kmsg record precedes IPC and the next operation. At most nine
 * records per transaction/fd; no printf/USB wait in the parent monitor loop.
 * A write return still does NOT prove relay/host delivery. */
static int observe(void *context, const struct m11_gpr_event *e) {
    const struct diagnostic *d=context; char b[256];
    int n=snprintf(b,sizeof(b),"<6>M11GPR token=%08x stage=%u rc=%lld bytes=%u ns=%llu\n",
        d->token,e->stage,(long long)e->rc,e->size,(unsigned long long)e->monotonic_ns);
    if (n<=0 || (size_t)n>=sizeof(b)) return -1;
    return write(d->fd,b,(size_t)n)==n?0:-1;
}
/* Run22 amplifier gate, before the endpoint node exists: Run19's registration wait and its
 * Disable-only amp-switch stage (control amp_gate). Its bounded log is journaled; only
 * "switches-disabled" (both switches written Disable and read back 0 by an independent
 * process) admits the GPR query. Never retried. */
static char gate_log[32768];
static int amp_gate(void) {
    char result[64];
    int rc=job("/m11/control","amp_gate",60000);
    if (readtext("/run/m11/amp-gate.log",gate_log,sizeof(gate_log))) strcpy(gate_log,"amp-gate log unreadable");
    if (record("amp_gate",gate_log,rc)) hold("journal failed");
    if (rc || readtext("/run/m11/amp-gate.result",result,sizeof(result))) return -1;
    if (record("amp_gate_result",result,0)) hold("journal failed");
    return strcmp(result,"switches-disabled\n") ? -1 : 0;
}
int main(int argc, char **argv) {
    (void)argv;
    if (getpid()!=1 || argc!=1) return 2; /* Safe CI execution: never acts outside PID1. */
    if (fatal_handlers()) hold("fatal-signal hold handlers not installed");
    umask(077);
    crumb("start");
    crumb("prepare");
    if (job("/m11/prepare",NULL,90000)) hold("prepare failed");
    crumb("journal");
    if (job("/m11/control","journal",10000)) hold("journal init failed");
    char b[64], *end; if (readtext("/run/m11/jseq",b,sizeof(b))) hold("journal seq absent");
    seq=(unsigned)strtoul(b,&end,10); if (strcmp(end,"\n") || seq!=9) hold("journal seq invalid");
    crumb("acquire");
    struct m11_audio_runtime *r=m11_audio_acquire_boot();
    if (!r) hold("PID1 exclusive owner acquisition denied");
    if (record("ownership","boot owner acquired; endpoint still unbound; amplifier_enable_permitted=0",0)) hold("journal failed");
    int logfd=open("/run/m11/helpers.log",O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);
    if (logfd<0) hold("helper log creation");
    crumb("mapper");
    pid_t mapper=m11_audio_spawn_helper(r,M11_AUDIO_LOCATOR,logfd);
    if (mapper<=1 || wait_marker("/run/m11/pd.endpoint",5000) || job("/m11/control","probe",6000)) hold("mapper launch/probe failed");
    crumb("logger");
    pid_t logger=m11_audio_spawn_helper(r,M11_AUDIO_LOGGER,logfd);
    if (logger<=1 || close(logfd) || wait_marker("/run/m11-instrumentation/logger.ready",5000)) hold("logger launch failed");
    crumb("adsp_start");
    if (job("/m11/control","start",40000)) hold("ADSP start failed");
    crumb("usb_start");
    if (job("/m11/control","usb_start",40000)) hold("USB start failed");
    if (record("usb_started","receive-only observer (no host acknowledgement in Run22); no endpoint yet",0)) hold("journal failed");
    crumb("amp_gate");
    if (amp_gate()) hold("amplifier switches not read back Disable; endpoint and GPR query denied");
    crumb("amp_disabled");
    /* P5: the spawner exists before the endpoint is opened, so it never holds it. */
    crumb("spawner");
    if (m11_spawner_start(&spawner,spawner_jobs,2,true) || m11_audio_attach_spawner(r,spawner.pid))
        hold("job spawner start/attach failed");
    if (record("spawner","post-bind jobs: no CAP_MKNOD, CAP_SYS_PTRACE or CAP_DAC_READ_SEARCH",0)) hold("journal failed");
    const char *color="red";
    crumb("endpoint_wait");
    uint64_t begin=now(), until=begin+30000000000ULL; dev_t dev=0;
    if (!begin) hold("clock failed");
    do { dev=endpoint(); if (dev) break; pause10(); } while (now() && now()<until);
    if (!dev) {
        crumb("endpoint_absent");
        if (record("admission","endpoint metadata/bind unavailable; query not attempted",1)) hold("journal failed");
    } else {
        crumb("endpoint_bind");
        if (m11_audio_bind_endpoint(r,dev)) { (void)log_owner(r); hold("endpoint identity/owner census denied"); }
        struct diagnostic diagnostic={.fd=open("/dev/kmsg",O_WRONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC),.token=0x17000001};
        struct stat diagnostic_stat;
        if (diagnostic.fd<0 || fstat(diagnostic.fd,&diagnostic_stat) ||
            !S_ISCHR(diagnostic_stat.st_mode) || diagnostic_stat.st_rdev!=makedev(1,11)) hold("diagnostic kmsg identity failed");
        struct m11_gpr_session s={.runtime=r,.expected_device=dev,.token=diagnostic.token,
            .observe=observe,.observe_context=&diagnostic,
            .service_down_fd=-1,.cancel_fd=-1,.budget_ms=4000,.reap_grace_ms=200};
        if (hexfile("/m11/instrumentation/nonce",s.capture_nonce,16) ||
            hexfile("/m11/instrumentation/identity",s.image_sha256,32)) hold("session identity failed");
        int cancel[2]; if (pipe2(cancel,O_CLOEXEC|O_NONBLOCK)) hold("cancel pipe failed");
        s.cancel_fd=cancel[0];
        crumb("pd_begin");
        if (record("pd_begin","active listener registration; query requires qualified UP",0)) hold("journal failed");
        int pdrc=m11_audio_start_pd(r,5000), qrc=-1;
        crumb("pd_return");
        if (log_owner(r) || record("pd_return","before query; returned PDR rc",pdrc)) hold("PDR evidence failed");
        if (!pdrc) { /* PDR qualified UP: the boot's only open of the endpoint */
            /* R1: by PID1 (anchor + guard), only after a qualified PDR UP as the worker's open
             * was; then the seal: node unlinked, PID1 non-dumpable, no close/dup/exec/
             * CLONE_FILES/SCM_RIGHTS/mknod. The monitor is pumped between the steps (at most
             * 250 ms apart); a lapse latches and admission then refuses the query. */
            crumb("anchor_bind");
            m11_anchor_ops ops;
            if (m11_anchor_linux_ops(&anchor_backend,"/dev/aud_pasthru_adsp",0,&ops) ||
                m11_anchor_bind(&anchor,&ops,NULL,&evidence,1,(uint64_t)dev))
                hold("anchor bind refused; any fd it obtained is retained");
            crumb("seal");
            if (m11_anchor_owner_seal(&anchor,"/dev/aud_pasthru_adsp")) hold("owner seal failed; anchor retained");
            (void)m11_audio_pump(r);
            crumb("anchor_attach");
            if (m11_audio_attach_anchor(r,&anchor)) { (void)log_owner(r); hold("anchor census refused; anchor retained"); }
            if (record("anchor","PID1 anchor and guard held; node unlinked; owner sealed",0)) hold("journal failed");
            (void)m11_audio_pump(r);
            crumb("loan_setup");
            if (m11_gpr_anchor_attach(&anchor,&diagnostic.fd,1)) hold("anchor loan setup failed");
            crumb("query");
            qrc=m11_gpr_linux_query(&s,&result);
        } else {
            crumb("pd_not_up_unlink"); /* never opened; no post-bind job may find the node */
            if (unlink("/dev/aud_pasthru_adsp")) hold("endpoint node removal failed");
        }
        /* Retire before any logging/control child can pause the PDR monitor. */
        crumb("query_returned");
        if (m11_audio_snapshot(r,&owner)) hold("owner snapshot failed");
        if (!owner.resources_quiescent || owner.unresolved_worker) {
            (void)log_owner(r); hold("endpoint close/reap unresolved; no PDR ACK or ADSP stop");
        }
        /* The boot's single release, by PID1, while the ADSP still runs and the PDR listener is
         * still registered (where the worker's close used to release). Never-mapped boot:
         * nothing is mapped or imported. A boot whose PDR never came UP never opened. */
        crumb("final_close");
        if (!pdrc && m11_anchor_final_close(&anchor)) { (void)log_owner(r); hold("anchor final close refused; anchor retained"); }
        crumb("retire");
        int retired=m11_audio_retire(r);
        if (!pdrc) {
            if (m11_gpr_result_encode(&result,json,sizeof(json))<0 || record("spf_query",json,qrc)) hold("query evidence incomplete");
            char ws[64]; snprintf(ws,sizeof(ws),"worker wait status %d (-1: not reaped)",m11_gpr_last_worker_status());
            if (record("worker_status",ws,0)) hold("journal failed");
        }
        if (log_owner(r) || record("pd_retire","listener unregister/lookup removal",retired)) hold("owner evidence incomplete");
        if (close(cancel[0]) || close(cancel[1])) hold("cancel close failed");
        if (retired) hold("PDR retirement incomplete; ADSP and mapper retained");
        if (close(diagnostic.fd)) hold("diagnostic fd close failed");
        color=pdrc?"cyan":qrc?"red":"green";
    }
    /* Preserve the Run14 transport lifetime: seal and remove USB while its
     * ADSP-backed suppliers are still running. Capture intentionally cannot
     * certify the subsequent ADSP/mapper/unmount/result/reboot steps. */
    crumb("pre_transport_teardown");
    if (record("pre_transport_teardown","query complete or not attempted; ADSP and mapper still running; later cleanup unobserved",0)) hold("journal failed");
    journal_sealed=1; /* Never append past an attempted final digest. */
    if (spawned(JOB_CONTROL,"seal",10000) || reap(logger,5000) ||
        readtext("/run/m11-instrumentation/logger.done",b,sizeof(b)) || strcmp(b,"1\n")) hold("logger seal/drain failed");
    crumb("usb_stop");
    if (spawned(JOB_CONTROL,"usb_stop",10000)) hold("USB teardown failed");
    crumb("stop_adsp");
    if (spawned(JOB_CONTROL,"stop_adsp",40000)) hold("ADSP stop/restore failed");
    crumb("mapper_stop");
    if (marker("/run/m11/pd.stop") || reap(mapper,5000) ||
        readtext("/run/m11/pd.done",b,sizeof(b)) || strcmp(b,"1\n")) hold("mapper shutdown failed");
    crumb("common");
    if (spawned(JOB_CONTROL,"common",10000)) hold("common restore/unmount failed");
    crumb("checkpoint");
    if (spawned(JOB_CHECKPOINT,color,10000)) hold("result checkpoint failed");
    crumb("unmount");
    if (spawned(JOB_CONTROL,"unmount",10000)) hold("proc/sys teardown failed");
    /* A never-mapped boot may reboot once PID1 dropped its references (or never opened). */
    crumb("end_boot");
    m11_anchor_end ending;
    if (m11_anchor_end_boot(&anchor,M11_TERMINAL_ORDERLY_SHUTDOWN,&ending) || ending!=M11_ANCHOR_END_REBOOT)
        hold("anchor retained; reboot(2) refused");
    if (m11_spawner_stop(&spawner)) hold("spawner stop failed");
    crumb("reboot");
    (void)reboot(RB_AUTOBOOT);
    hold("reboot returned");
}
