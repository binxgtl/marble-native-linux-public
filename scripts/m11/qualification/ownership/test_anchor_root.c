/* P5 (no second opener) with real root semantics, on a STAND-IN only: a private pty-multiplexer
 * node (c 5:2) made with mknod on a private tmpfs plays the endpoint node, so it can be
 * unlinked; its slave observes the release. Must run as root (CI: sudo on a hosted runner).
 * The real endpoint, driver, ADSP and DMA are never touched.
 *   owner     binds, seals (node unlinked, non-dumpable, filter), runs jobs through a spawner
 *             forked BEFORE the bind that dropped CAP_MKNOD, CAP_SYS_PTRACE, CAP_DAC_READ_SEARCH
 *   jobs      root uid: each tries one route to a second OFD and must be refused (path,
 *             mknod, /proc reopen, pidfd_getfd; open_by_handle_at only statically, see below)
 *   controls  a full-capability root process CAN reopen through /proc and CAN mknod a second
 *             node; the census sees both (by device number), which is why jobs lose the caps */
#define _GNU_SOURCE
#include "m11_anchor_owner.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

static unsigned cases;
static void pass(const char *s) { ++cases; printf("PASS %s\n",s); }
static const m11_anchor_contract evidence={.endpoint_has_no_flush=true,
    .release_on_last_fput_only=true,.owner_single_threaded=true};
static char self_exe[256], dir[64];

/* ------------------------------------- jobs ------------------------------------- */
static int caps_dropped(void) {
    FILE *f=fopen("/proc/self/status","re"); if (!f) return 0;
    char line[256]; int seen=0, ok=1;
    unsigned long long v;
    while (fgets(line,sizeof(line),f)) {
        if (!strncmp(line,"Uid:\t0\t0\t0\t0",12)) seen|=1;
        if (sscanf(line,"CapBnd: %llx",&v)==1 || sscanf(line,"CapPrm: %llx",&v)==1 ||
            sscanf(line,"CapEff: %llx",&v)==1 || sscanf(line,"CapInh: %llx",&v)==1 ||
            sscanf(line,"CapAmb: %llx",&v)==1) {
            seen|=2;
            if (v & ((1ull<<27)|(1ull<<19)|(1ull<<2))) ok=0; /* MKNOD, SYS_PTRACE, DAC_READ_SEARCH */
        }
    }
    fclose(f);
    return ok && seen==3;
}
static int job(const char *spec) {
    char kind[32], node[128], d[64]; int pid, fd;
    if (sscanf(spec,"%31[^:]:%d:%d:%127[^:]:%63s",kind,&pid,&fd,node,d)!=5) return 3;
    char p[256];
    if (!strcmp(kind,"caps")) return caps_dropped() ? 0 : 10;
    if (!strcmp(kind,"open-path"))
        return open(node,O_RDWR|O_NOCTTY|O_CLOEXEC)<0 && errno==ENOENT ? 0 : 11;
    if (!strcmp(kind,"mknod")) {
        snprintf(p,sizeof(p),"%s/second",d);
        return mknod(p,S_IFCHR|0600,makedev(5,2))<0 && errno==EPERM ? 0 : 12;
    }
    if (!strcmp(kind,"proc-reopen")) {
        snprintf(p,sizeof(p),"/proc/%d/fd/%d",pid,fd);
        return open(p,O_RDWR|O_NOCTTY|O_CLOEXEC)<0 && (errno==EACCES || errno==EPERM) ? 0 : 13;
    }
    if (!strcmp(kind,"pidfd-getfd")) {
        long pfd=syscall(SYS_pidfd_open,pid,0);
        if (pfd<0) return 14;
        return syscall(SYS_pidfd_getfd,(int)pfd,fd,0)<0 && errno==EPERM ? 0 : 15;
    }
    return 4;
}

/* ------------------------------------ harness ------------------------------------ */
static int exit_code(pid_t pid) {
    int st; pid_t rc;
    do { rc=waitpid(pid,&st,0); } while (rc<0 && errno==EINTR);
    assert(rc==pid);
    return WIFEXITED(st) ? WEXITSTATUS(st) : 128+WTERMSIG(st);
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
static int send_q(int fd, void *arg) { (void)arg; return write(fd,"Q",1)==1 ? 0 : 1; }
struct report { int pid, anchor; char slave[128]; };
static const char *const job_argv[]={self_exe,"job",NULL};
static const char *const *const jobs[]={job_argv};
static int bind_node(m11_pid1_anchor *a, const char *node, int census_root) {
    static m11_anchor_linux l; /* ops.ctx points here; one owner per process */
    m11_anchor_ops ops; struct stat st;
    if (m11_anchor_linux_ops(&l,node,census_root,&ops) || stat(node,&st)) return -1;
    memset(a,0,sizeof(*a));
    return m11_anchor_bind(a,&ops,NULL,&evidence,getpid(),(uint64_t)st.st_rdev);
}

/* Owner that runs the five refusal jobs, a loan and the final close. */
static int positive_owner(const char *node, int out, int in) {
    m11_spawner sp;
    if (m11_spawner_start(&sp,jobs,1,true) || !sp.dropped) return 40;   /* before the bind */
    m11_pid1_anchor a;
    if (bind_node(&a,node,getpid())) return 41;
    struct report r={getpid(),a.anchor_fd,{0}};
    if (grantpt(a.anchor_fd) || unlockpt(a.anchor_fd) || !ptsname(a.anchor_fd)) return 42;
    snprintf(r.slave,sizeof(r.slave),"%s",ptsname(a.anchor_fd));
    char g;
    if (write(out,&r,sizeof(r))!=(ssize_t)sizeof(r) || read(in,&g,1)!=1) return 43;
    if (m11_anchor_owner_seal(&a,node)) return 44;
    struct stat st;
    if (!lstat(node,&st) || errno!=ENOENT) return 45;
    /* open_by_handle_at is not exercised: pinned ACK fs/fhandle.c:179 requires
     * CAP_DAC_READ_SEARCH (dropped, checked by "caps"), but hosted kernels >= 6.10 relax it for
     * CAP_SYS_ADMIN holders, so the CI kernel would not represent the device here. */
    const char *kinds[]={"caps","open-path","mknod","proc-reopen","pidfd-getfd"};
    for (unsigned i=0;i<5;i++) {
        char spec[160]; int status=-1;
        snprintf(spec,sizeof(spec),"%s:%d:%d:%s:%s",kinds[i],getpid(),a.anchor_fd,node,dir);
        int rc=m11_spawner_run(&sp,0,spec,5000,&status);
        if (rc || status) { fprintf(stderr,"job %s rc=%d status=%d\n",kinds[i],rc,status); return 50+(int)i; }
    }
    if (m11_anchor_check(&a)) return 46;
    m11_worker_end end;
    if (m11_anchor_linux_lend(&a,send_q,NULL,NULL,0,3000,1000,&end) || end!=M11_WORKER_EXIT_OK) return 47;
    if (read(in,&g,1)!=1 || m11_anchor_final_close(&a) || a.state!=M11_ANCHOR_OWNER_FDS_DROPPED) return 48;
    return m11_spawner_stop(&sp) ? 49 : 0;
}
/* Owner that only binds, seals and waits; the harness then acts as a full-capability root
 * second opener, and the owner's census must refuse. */
static int control_owner(const char *node, int census_root, int out, int in) {
    m11_pid1_anchor a;
    if (bind_node(&a,node,census_root)) return 60;
    struct report r={getpid(),a.anchor_fd,{0}};
    if (m11_anchor_owner_seal(&a,node)) return 61;
    char g;
    if (write(out,&r,sizeof(r))!=(ssize_t)sizeof(r) || read(in,&g,1)!=1) return 62;
    int rc=m11_anchor_check(&a);
    if (rc!=-EBUSY || !(a.latches & M11_ANCHOR_LATCH_FOREIGN_HOLDER)) return 63;
    if (!(a.latches & M11_ANCHOR_LATCH_SECOND_OFD)) return 64;
    return 0;
}
static const char *g_node; static int g_root, g_out, g_in, g_kind;
static int run_owner(void) {
    return g_kind ? control_owner(g_node,g_root,g_out,g_in) : positive_owner(g_node,g_out,g_in);
}
static pid_t start(int (*fn)(void), int *out_read, int *in_write) {
    int o[2], i[2]; assert(!pipe2(o,O_CLOEXEC) && !pipe2(i,O_CLOEXEC));
    pid_t pid=fork(); assert(pid>=0);
    if (!pid) { close(o[0]); close(i[1]); g_out=o[1]; g_in=i[0]; _exit(fn()); }
    close(o[1]); close(i[0]); *out_read=o[0]; *in_write=i[1];
    return pid;
}
static void make_node(const char *path) { assert(!mknod(path,S_IFCHR|0600,makedev(5,2))); }

int main(int argc, char **argv) {
    if (argc==3 && !strcmp(argv[1],"job")) return job(argv[2]);
    setvbuf(stdout,NULL,_IONBF,0);
    if (geteuid()) { puts("SKIP root qualification: not running as root"); return 77; }
    alarm(120);
    ssize_t n=readlink("/proc/self/exe",self_exe,sizeof(self_exe)-1); assert(n>0); self_exe[n]=0;
    snprintf(dir,sizeof(dir),"/tmp/m11-p5-XXXXXX"); assert(mkdtemp(dir));
    assert(!mount("m11-p5",dir,"tmpfs",MS_NOSUID|MS_NOEXEC,"mode=0700")); /* allows device nodes */
    /* A pty-multiplexer node outside devpts uses the devpts found at "pts" beside it. */
    char pts[96]; snprintf(pts,sizeof(pts),"%s/pts",dir);
    assert(!mkdir(pts,0755) && !mount("/dev/pts",pts,NULL,MS_BIND,NULL));
    char node[128]; snprintf(node,sizeof(node),"%s/standin",dir);
    make_node(node);
    int probe=open(node,O_RDWR|O_NOCTTY|O_CLOEXEC);
    if (probe<0) printf("stand-in open failed: %s
",strerror(errno));
    assert(probe>=0); close(probe);
    pass("private stand-in node c 5:2 on a private tmpfs; the backend admits it by device number");

    int out, in; struct report r;
    g_node=node; g_kind=0;
    pid_t o=start(run_owner,&out,&in);
    assert(read(out,&r,sizeof(r))==(ssize_t)sizeof(r));
    int observer=open_slave(r.slave);
    assert(write(in,"S",1)==1);
    char c; struct pollfd p={observer,POLLIN,0};
    assert(poll(&p,1,10000)==1 && read(observer,&c,1)==1 && c=='Q' && !hup_within(observer,0));
    assert(write(in,"F",1)==1);
    int rc=exit_code(o);
    if (rc) printf("positive owner exit %d\n",rc);
    assert(!rc && hup_within(observer,2000));
    close(observer); close(out); close(in);
    pass("P5 jobs (root uid, caps dropped): node path gone, mknod, /proc reopen and pidfd_getfd "
         "refused; census clean; confined loan; final close releases");

    char node2[128]; snprintf(node2,sizeof(node2),"%s/control-a",dir); make_node(node2);
    g_node=node2; g_kind=1; g_root=getpid();
    o=start(run_owner,&out,&in);
    assert(read(out,&r,sizeof(r))==(ssize_t)sizeof(r));
    char path[64]; snprintf(path,sizeof(path),"/proc/%d/fd/%d",r.pid,r.anchor);
    int reopened=open(path,O_RDWR|O_NOCTTY|O_CLOEXEC);
    assert(reopened>=0); /* CAP_SYS_PTRACE beats non-dumpable and the unlinked path */
    assert(write(in,"C",1)==1);
    rc=exit_code(o); if (rc) printf("control owner A exit %d\n",rc);
    assert(!rc); close(reopened); close(out); close(in);
    pass("NEGATIVE CONTROL: a full-capability root reopens through /proc despite unlink and "
         "non-dumpable; the owner census refuses it as a second OFD");

    char node3[128]; snprintf(node3,sizeof(node3),"%s/control-b",dir); make_node(node3);
    g_node=node3;
    o=start(run_owner,&out,&in);
    assert(read(out,&r,sizeof(r))==(ssize_t)sizeof(r));
    char again[128]; snprintf(again,sizeof(again),"%s/control-b-again",dir); make_node(again);
    int second=open(again,O_RDWR|O_NOCTTY|O_CLOEXEC); assert(second>=0); /* CAP_MKNOD */
    assert(write(in,"C",1)==1);
    rc=exit_code(o); if (rc) printf("control owner B exit %d\n",rc);
    assert(!rc); close(second); close(out); close(in);
    pass("NEGATIVE CONTROL: a full-capability root mknods another node of the device and opens a "
         "second OFD; the census matches it by device number, not by inode");

    unlink(again); unlink(node2); unlink(node3);
    assert(!umount(pts) && !rmdir(pts) && !umount(dir) && !rmdir(dir));
    alarm(0);
    printf("PID1 anchor root qualification: %u cases PASS (stand-in node; real endpoint not opened)\n",cases);
    return 0;
}
