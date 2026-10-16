/* End-to-end integrated query path on a STAND-IN: the actual anchor-native gpr_linux.c and the
 * unchanged runtime/gpr_native.c run one GET_SPF_STATE transaction through a /dev/ptmx master
 * that a sealed owner process holds as its anchor. The harness plays the DSP on the pty slave:
 * it reads the worker's 24-byte packet and answers with the 28-byte SPF state response. The
 * real endpoint, driver, ADSP and DMA are never touched. The audio runtime is replaced by the
 * four entry points the GPR layer calls (no PID1 census here; tested separately). */
#define _GNU_SOURCE
#include "anchor_native.h"
#include "audio_runtime_internal.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

static int down_pipe[2]={-1,-1}, finished;
int m11_audio_admit(struct m11_gpr_session *s) {
    s->exclusive_native_owner=1; s->service_down_fd=down_pipe[0]; return 0;
}
int m11_audio_control(struct m11_gpr_session const *s) { (void)s; return 0; }
void m11_audio_child_detach(struct m11_gpr_session const *s) { (void)s; }
void m11_audio_finish(struct m11_gpr_session *s, const struct m11_gpr_result *r) { (void)s; (void)r; finished++; }

static uint32_t get32(const unsigned char *p) {
    return (uint32_t)p[0] | (uint32_t)p[1]<<8 | (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24;
}
static void put32(unsigned char *p, uint32_t v) {
    p[0]=(unsigned char)v; p[1]=(unsigned char)(v>>8); p[2]=(unsigned char)(v>>16); p[3]=(unsigned char)(v>>24);
}
static bool hup_within(int fd, int ms) {
    struct pollfd p={fd,POLLIN,0}; int rc;
    do { rc=poll(&p,1,ms); } while (rc<0 && errno==EINTR);
    return rc>0 && (p.revents & (POLLHUP|POLLERR));
}
static int open_slave(const char *name) {
    int s=open(name,O_RDWR|O_NOCTTY|O_NONBLOCK|O_CLOEXEC); assert(s>=0);
    struct termios t; assert(!tcgetattr(s,&t)); cfmakeraw(&t); assert(!tcsetattr(s,TCSANOW,&t));
    return s;
}
static int exit_code(pid_t pid) {
    int st; pid_t rc;
    do { rc=waitpid(pid,&st,0); } while (rc<0 && errno==EINTR);
    assert(rc==pid);
    return WIFEXITED(st) ? WEXITSTATUS(st) : 128+WTERMSIG(st);
}
/* The live worker: the one child of the owner while it waits for the DSP response. */
static pid_t worker_of(pid_t owner_pid) {
    DIR *d=opendir("/proc"); assert(d); struct dirent *e; pid_t found=0;
    while ((e=readdir(d))) {
        int pid=atoi(e->d_name); if (pid<=0) continue;
        char path[64], line[256]; snprintf(path,sizeof(path),"/proc/%d/status",pid);
        FILE *f=fopen(path,"re"); if (!f) continue;
        while (fgets(line,sizeof(line),f)) {
            int pp; if (sscanf(line,"PPid:\t%d",&pp)==1) { if (pp==owner_pid) { assert(!found); found=pid; } break; }
        }
        fclose(f);
    }
    closedir(d); assert(found>0); return found;
}
static int status_value(pid_t pid, const char *key) {
    char path[64], line[256]; snprintf(path,sizeof(path),"/proc/%d/status",pid);
    FILE *f=fopen(path,"re"); assert(f); int v=-1; size_t k=strlen(key);
    while (fgets(line,sizeof(line),f)) if (!strncmp(line,key,k) && line[k]==':') { v=atoi(line+k+1); break; }
    fclose(f); return v;
}
/* Confinement is visible to anyone; the fd table only to root (the worker is non-dumpable). */
static void inspect_worker(pid_t owner_pid) {
    pid_t w=worker_of(owner_pid);
    int seccomp=status_value(w,"Seccomp"), filters=status_value(w,"Seccomp_filters");
    if (seccomp!=2 || status_value(w,"NoNewPrivs")!=1 || (filters>=0 && filters!=2))
        printf("worker seccomp filters: mode=%d filters=%d\n",seccomp,filters);
    assert(seccomp==2 && status_value(w,"NoNewPrivs")==1 && (filters<0 || filters==2));
    if (geteuid()) { puts("INFO worker fd table not inspected (needs root)"); return; }
    if (status_value(w,"Uid")!=65534) printf("worker uid %d\n",status_value(w,"Uid"));
    assert(status_value(w,"Uid")==65534);
    char dir[64]; snprintf(dir,sizeof(dir),"/proc/%d/fd",w);
    DIR *d=opendir(dir); assert(d); struct dirent *e; int ptmx=0, sockets=0, pipes=0, other=0;
    while ((e=readdir(d))) {
        int fd=atoi(e->d_name); if (e->d_name[0]=='.' || fd<=2) continue;
        char path[384], link[128]; snprintf(path,sizeof(path),"%s/%s",dir,e->d_name);
        ssize_t n=readlink(path,link,sizeof(link)-1); assert(n>0); link[n]=0;
        if (strstr(link,"ptmx")) ptmx++;
        else if (!strncmp(link,"socket:",7)) sockets++;
        else if (!strncmp(link,"pipe:",5)) pipes++;
        else { printf("worker fd hygiene: unexpected %s\n",link); other++; }
    }
    closedir(d);
    if (ptmx!=2 || sockets!=1 || pipes!=2 || other) printf("worker fd hygiene: ptmx=%d sockets=%d pipes=%d other=%d\n",ptmx,sockets,pipes,other);
    assert(ptmx==2 && sockets==1 && pipes==2 && !other);
}
static const m11_anchor_contract evidence={.endpoint_has_no_flush=true,
    .release_on_last_fput_only=true,.owner_single_threaded=true};
static void fill_session(struct m11_gpr_session *s, dev_t dev, uint32_t token, int cancel, unsigned budget) {
    memset(s,0,sizeof(*s));
    s->expected_device=dev; s->token=token; s->service_down_fd=-1; s->cancel_fd=cancel;
    s->budget_ms=budget; s->reap_grace_ms=200;
    memset(s->capture_nonce,0xaa,16); memset(s->image_sha256,0xbb,32);
}

/* The owner: bind, seal, attach, run `queries` transactions, then wait and final-close. */
static int owner(int out, int in, unsigned budget, int answer) {
    struct stat st; static m11_anchor_linux l; m11_anchor_ops ops; static m11_pid1_anchor a;
    if (pipe2(down_pipe,O_CLOEXEC|O_NONBLOCK)) return 40;
    int cancel[2]; if (pipe2(cancel,O_CLOEXEC|O_NONBLOCK)) return 40;
    if (stat("/dev/ptmx",&st) || m11_anchor_linux_ops(&l,"/dev/ptmx",getpid(),&ops)) return 41;
    if (m11_anchor_bind(&a,&ops,NULL,&evidence,getpid(),(uint64_t)st.st_rdev)) return 42;
    if (grantpt(a.anchor_fd) || unlockpt(a.anchor_fd) || !ptsname(a.anchor_fd)) return 43;
    char name[128]; snprintf(name,sizeof(name),"%s",ptsname(a.anchor_fd));
    char g;
    if (write(out,name,sizeof(name))!=(ssize_t)sizeof(name) || read(in,&g,1)!=1) return 44;
    if (m11_anchor_owner_seal(&a,NULL)) return 45;
    struct m11_gpr_session s; struct m11_gpr_result r;
    fill_session(&s,st.st_rdev,0x17000001,cancel[0],budget);
    s.runtime=NULL;
    if (m11_gpr_linux_query(&s,&r)!=-1 || r.outcome!=M11_GPR_OPEN_FAILED) return 46; /* no anchor attached */
    if (m11_gpr_anchor_attach(&a,NULL,0)) return 47;
    fill_session(&s,st.st_rdev,0x17000002,cancel[0],budget);
    int rc=m11_gpr_linux_query(&s,&r);
    if (answer) {
        if (rc || !r.query_consistent || r.outcome!=M11_GPR_SPF_READY) { fprintf(stderr,"query rc=%d outcome=%d\n",rc,r.outcome); return 48; }
    } else if (!rc || r.outcome!=M11_GPR_TIMEOUT) { fprintf(stderr,"timeout rc=%d outcome=%d\n",rc,r.outcome); return 49; }
    /* A timeout ends with the worker SIGKILLed after its deadline: still a non-final close. */
    if (!r.worker_reaped || r.unresolved_worker) return 50;
    if (answer && (!r.worker_exit_ok || !r.close_returned || !r.close_ok)) return 50;
    if (answer && a.latches) return 51;
    if (a.state!=M11_ANCHOR_HELD || (a.latches & M11_ANCHOR_LATCH_REFUSE) || a.lends!=1 || m11_anchor_check(&a)) return 51;
    if (write(out,"D",1)!=1 || read(in,&g,1)!=1) return 52;          /* harness: still no hang-up */
    if (m11_anchor_final_close(&a) || a.state!=M11_ANCHOR_OWNER_FDS_DROPPED) return 53;
    return finished==2 ? 0 : 54;
}

static void scenario(unsigned budget, int answer) {
    int o2h[2], h2o[2]; assert(!pipe2(o2h,O_CLOEXEC) && !pipe2(h2o,O_CLOEXEC));
    pid_t o=fork(); assert(o>=0);
    if (!o) { close(o2h[0]); close(h2o[1]); _exit(owner(o2h[1],h2o[0],budget,answer)); }
    close(o2h[1]); close(h2o[0]);
    char name[128]; assert(read(o2h[0],name,sizeof(name))==(ssize_t)sizeof(name));
    int dsp=open_slave(name);
    assert(write(h2o[1],"S",1)==1);
    /* The DSP side: one 24-byte GET_SPF_STATE from the worker, through the borrowed fd. */
    unsigned char tx[64]; size_t got=0; struct pollfd p={dsp,POLLIN,0};
    while (got<24) {
        assert(poll(&p,1,5000)==1 && !(p.revents & POLLHUP));
        ssize_t n=read(dsp,tx+got,sizeof(tx)-got); assert(n>0); got+=(size_t)n;
    }
    assert(got==24 && get32(tx)==0x1860 && tx[4]==2 && tx[5]==3 && get32(tx+8)==M11_GPR_SOURCE_PORT &&
           get32(tx+12)==1 && get32(tx+16)==0x17000002 && get32(tx+20)==M11_GPR_GET_SPF);
    if (answer) inspect_worker(o); /* the worker now waits (up to 4 s) for the response */
    if (answer) {
        unsigned char rx[28]={0};
        put32(rx,0x1c60); rx[4]=3; rx[5]=2; put32(rx+8,1); put32(rx+12,M11_GPR_SOURCE_PORT);
        put32(rx+16,0x17000002); put32(rx+20,M11_GPR_SPF_RESPONSE); put32(rx+24,1);
        assert(write(dsp,rx,sizeof(rx))==(ssize_t)sizeof(rx));
    }
    char c; assert(read(o2h[0],&c,1)==1 && c=='D');
    assert(!hup_within(dsp,0));                 /* the worker's exit was not the last close */
    assert(write(h2o[1],"F",1)==1);
    int rc=exit_code(o);
    if (rc) printf("owner exit %d\n",rc);
    assert(!rc && hup_within(dsp,2000));        /* PID1's final close_range released it */
    close(dsp); close(o2h[0]); close(h2o[1]);
}

int main(void) {
    setvbuf(stdout,NULL,_IONBF,0);
    alarm(60);
    scenario(4000,1);
    puts("PASS integrated query on the stand-in: refused without an anchor; with it, the confined "
         "worker borrowed the sealed owner's OFD, sent GET_SPF_STATE, read SPF_READY, exited "
         "without a release; PID1's final close released once");
    scenario(300,0);
    puts("PASS integrated query timeout on the stand-in: no response, worker stopped at its deadline "
         "(SIGKILL is a non-final close), no release; the loan ends and the final close releases once");
    alarm(0);
    printf("Integrated stand-in query qualification: 2 cases PASS as %s (real endpoint not opened)\n",
           geteuid() ? "non-root" : "root (worker dropped to 65534; fd table inspected)");
    return 0;
}
