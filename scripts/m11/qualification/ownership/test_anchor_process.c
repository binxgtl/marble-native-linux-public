/* Real Linux processes and descriptors with a STAND-IN character device: a /dev/ptmx master is
 * the anchor OFD, and its pty slave is the observer, because the master's release (its last
 * fput, like audio_pkt_release) hangs the slave up. pty masters, like audio_pkt_fops, have no
 * .flush. No real endpoint, driver, ADSP or DMA is touched; D-state is not reproducible here
 * (model only). NEGATIVE CONTROL cases show hazards the adapter cannot prevent by itself; they
 * are integration rules (no CLONE_FILES, no close_range/dup2 over the reserved numbers, no PID1
 * self-exec, no SCM_RIGHTS of the endpoint), not adapter behaviour. */
#define _GNU_SOURCE
#include "m11_anchor_owner.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
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
static const char *standin;
static int slave=-1;

static bool hup_within(int fd, int ms) {
    struct pollfd p={fd,POLLIN,0}; int rc;
    do { rc=poll(&p,1,ms); } while (rc<0 && errno==EINTR);
    assert(rc>=0);
    return rc>0 && (p.revents & (POLLHUP|POLLERR));
}
static bool hung_up(void) { return hup_within(slave,0); }
static char from_slave(void) {
    struct pollfd p={slave,POLLIN,0}; int rc;
    do { rc=poll(&p,1,3000); } while (rc<0 && errno==EINTR);
    assert(rc==1 && (p.revents & POLLIN));
    char c; assert(read(slave,&c,1)==1); return c;
}
static int raw_slave(int s) {
    struct termios t; assert(!tcgetattr(s,&t)); cfmakeraw(&t); assert(!tcsetattr(s,TCSANOW,&t));
    return s;
}
static int open_slave_by_name(const char *name) {
    int s=open(name,O_RDWR|O_NOCTTY|O_NONBLOCK|O_CLOEXEC); assert(s>=0);
    return raw_slave(s);
}
static int open_slave(int master) {
    assert(!grantpt(master) && !unlockpt(master));
    const char *name=ptsname(master); assert(name);
    return open_slave_by_name(name);
}
/* Oracle for the stand-in only: the slave is hung up once the master OFD was released. */
static int slave_oracle(void *v) { (void)v; return hung_up() ? 1 : 0; }
static int bind_standin(m11_pid1_anchor *a, m11_anchor_linux *l, int census_root) {
    m11_anchor_ops ops; struct stat st;
    assert(!m11_anchor_linux_ops(l,standin,census_root,&ops) && !stat(standin,&st));
    memset(a,0,sizeof(*a));
    int rc=m11_anchor_bind(a,&ops,NULL,&evidence,getpid(),(uint64_t)st.st_rdev);
    if (a->state!=M11_ANCHOR_HELD) return rc;
    if (slave>=0) close(slave);
    slave=open_slave(a->anchor_fd);
    assert(!hung_up());
    return rc;
}
/* Harness only: this process is not global init, so a RETAINED or latched anchor is dropped
 * here between scenarios (the census would otherwise see its OFD as another holder). */
static void end_scenario(m11_pid1_anchor *a) {
    if (a->anchor_fd>=0) close(a->anchor_fd);
    if (a->guard_fd>=0) close(a->guard_fd);
    a->anchor_fd=a->guard_fd=-1;
}
static void reaped(pid_t pid) {
    int status; pid_t rc;
    do { rc=waitpid(pid,&status,0); } while (rc<0 && errno==EINTR);
    assert(rc==pid);
}
static int exit_code(pid_t pid) {
    int status; pid_t rc;
    do { rc=waitpid(pid,&status,0); } while (rc<0 && errno==EINTR);
    assert(rc==pid);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128+WTERMSIG(status);
}
/* Records, after each close the adapter performs, whether the observer was hung up. */
static int (*real_close)(void *, int);
static bool hup_after[4]; static unsigned closes;
static int observed_close(void *v, int fd) {
    int rc=real_close(v,fd);
    if (closes<4) hup_after[closes]=hung_up();
    closes++;
    return rc;
}
static bool kcmp_available(int fd) { return syscall(SYS_kcmp,getpid(),getpid(),0,fd,fd)==0; }

/* ---------------------------------- worker bodies ---------------------------------- */
static int send_q(int fd, void *arg) { (void)arg; return write(fd,"Q",1)==1 ? 0 : 1; }
static int stall(int fd, void *arg) {
    (void)fd; (void)arg;
    for (;;) if (pause()<0 && errno!=EINTR) return 1; /* SIGKILL ends it */
}
/* Only stdio, the borrowed fd and the kept report pipe may be open. */
static int hygiene(int fd, void *arg) {
    int report=*(const int *)arg;
    for (int n=0;n<4096;n++) {
        if (n<=2 || n==fd || n==report) continue;
        if (fcntl(n,F_GETFD)>=0) return 1;
    }
    return write(report,"H",1)==1 && write(fd,"H",1)==1 ? 0 : 1;
}
static bool denied(long rc, int want) { return rc==-1 && errno==want; }
/* Every route to a second OFD, an exported/hidden reference, a new process or KernelSU's fd is
 * refused by the worker's seccomp filter; I/O on the borrowed fd keeps working. */
static int confined(int fd, void *arg) {
    (void)arg;
    if (!denied(open("/dev/null",O_RDONLY|O_CLOEXEC),EPERM)) return 1;   /* world-readable: DAC allows */
    if (!denied(open(standin,O_RDWR|O_NOCTTY|O_CLOEXEC),EPERM)) return 2; /* a second OFD of the node */
    int sv[2];
    if (socketpair(AF_UNIX,SOCK_DGRAM|SOCK_CLOEXEC,0,sv)) return 3;
    char byte='x'; struct iovec io={&byte,1};
    union { char buf[CMSG_SPACE(sizeof(int))]; struct cmsghdr align; } u;
    struct msghdr m={.msg_iov=&io,.msg_iovlen=1,.msg_control=u.buf,.msg_controllen=sizeof(u.buf)};
    struct cmsghdr *c=CMSG_FIRSTHDR(&m);
    c->cmsg_level=SOL_SOCKET; c->cmsg_type=SCM_RIGHTS; c->cmsg_len=CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c),&fd,sizeof(int));
    if (!denied(sendmsg(sv[0],&m,0),EPERM)) return 4;                     /* no SCM_RIGHTS export */
    if (send(sv[0],"y",1,0)!=1) return 5;                                 /* plain bytes still flow */
    if (!denied(fork(),EPERM)) return 6;                                  /* no CLONE_FILES peer */
    if (!denied(syscall(SYS_clone3,NULL,0),ENOSYS)) return 7;
    char *const argv[]={(char *)"true",NULL};
    if (!denied(execve("/bin/true",argv,environ),EPERM)) return 8;
    if (!denied(syscall(SYS_io_uring_setup,1,NULL),EPERM)) return 9;      /* no fixed-file refs */
    if (!denied(syscall(SYS_pidfd_getfd,-1,0,0),EPERM)) return 10;
    if (!denied(syscall(SYS_ptrace,0,0,0,0),EPERM)) return 11;
    if (!denied(syscall(SYS_reboot,0,0,0,NULL),EPERM)) return 12;         /* KernelSU fd install path */
    return write(fd,"S",1)==1 ? 0 : 13;
}

/* --------------------------- sealed owner (P1-P4, P5 owner part) --------------------------- */
static int sendmsg_rights(int fd) {
    int sv[2];
    if (socketpair(AF_UNIX,SOCK_DGRAM|SOCK_CLOEXEC,0,sv)) return -1;
    char byte='x'; struct iovec io={&byte,1};
    union { char buf[CMSG_SPACE(sizeof(int))]; struct cmsghdr align; } u;
    struct msghdr m={.msg_iov=&io,.msg_iovlen=1,.msg_control=u.buf,.msg_controllen=sizeof(u.buf)};
    struct cmsghdr *c=CMSG_FIRSTHDR(&m);
    c->cmsg_level=SOL_SOCKET; c->cmsg_type=SCM_RIGHTS; c->cmsg_len=CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c),&fd,sizeof(int));
    long rc=sendmsg(sv[0],&m,0); int e=errno;
    close(sv[0]); close(sv[1]); errno=e;
    return (int)rc;
}
/* Run inside the sealed owner. Returns 0 or the number of the first unexpected result. */
static int seal_battery(const m11_pid1_anchor *a) {
    int A=a->anchor_fd, G=a->guard_fd, null=open("/dev/null",O_RDONLY|O_CLOEXEC);
    if (null<0) return 20;
    if (!denied(close(A),EPERM) || !denied(close(G),EPERM)) return 21;              /* P3 */
    if (!denied(dup3(null,A,O_CLOEXEC),EPERM) || !denied(dup3(null,G,0),EPERM) || !denied(dup(A),EPERM)) return 22;
    if (!denied(fcntl(A,F_SETFD,0),EPERM) || !denied(fcntl(G,F_DUPFD_CLOEXEC,700),EPERM) ||
        !denied(fcntl(A,F_DUPFD,700),EPERM) || !denied(fcntl(G,F_SETFL,0),EPERM)) return 23;
    if (fcntl(A,F_GETFD)<0 || fcntl(G,F_GETFL)<0 || dup3(null,700,O_CLOEXEC)!=700 || close(700)) return 24;
    if (!denied(syscall(SYS_close_range,3u,~0u,0u),EPERM) ||
        !denied(syscall(SYS_close_range,(unsigned)A,(unsigned)G,4u),EPERM) ||      /* CLOSE_RANGE_CLOEXEC */
        !denied(syscall(SYS_close_range,(unsigned)G,(unsigned)G,0u),EPERM)) return 25;
    char *const argv[]={(char *)"true",NULL};
    if (!denied(execve("/bin/true",argv,environ),EPERM)) return 26;                 /* P2 */
    if (!denied(syscall(SYS_clone,CLONE_FILES|SIGCHLD,0,0,0,0),EPERM)) return 27;   /* P1 */
    if (!denied(syscall(SYS_clone3,NULL,0),ENOSYS)) return 28;
    pid_t f=fork();                                                                 /* plain fork stays */
    if (f<0) return 29;
    if (!f) _exit(0);
    if (exit_code(f)) return 29;
    if (!denied(sendmsg_rights(A),EPERM)) return 30;                                /* P4 */
    if (!denied(syscall(SYS_io_uring_setup,1,NULL),EPERM)) return 31;
    if (!denied(syscall(SYS_ptrace,0,0,0,0),EPERM)) return 32;
    if (!denied(mknodat(AT_FDCWD,"/tmp/m11-seal-must-not-exist",S_IFCHR|0600,makedev(1,3)),EPERM)) return 33; /* P5 */
    if (prctl(PR_GET_DUMPABLE,0,0,0,0)!=0) return 34;
    close(null);
    return 0;
}
static const char *const job_true[]={"/bin/true",NULL};
static const char *const job_false[]={"/bin/false",NULL};
static const char *const *const owner_jobs[]={job_true,job_false};
static void sealed_owner_scenario(void) {
    int name_pipe[2], go[2]; assert(!pipe2(name_pipe,O_CLOEXEC) && !pipe2(go,O_CLOEXEC));
    pid_t o=fork(); assert(o>=0);
    if (!o) {
        close(name_pipe[0]); close(go[1]);
        m11_spawner sp; /* forked BEFORE the bind: it never holds the endpoint */
        if (m11_spawner_start(&sp,owner_jobs,2,false)) _exit(40);
        m11_pid1_anchor own; m11_anchor_linux ol; m11_anchor_ops oops; struct stat st;
        if (m11_anchor_linux_ops(&ol,standin,getpid(),&oops) || stat(standin,&st)) _exit(41);
        memset(&own,0,sizeof(own));
        if (m11_anchor_bind(&own,&oops,NULL,&evidence,getpid(),(uint64_t)st.st_rdev)) _exit(42);
        if (grantpt(own.anchor_fd) || unlockpt(own.anchor_fd) || !ptsname(own.anchor_fd)) _exit(43);
        char name[128]; snprintf(name,sizeof(name),"%s",ptsname(own.anchor_fd));
        char g;
        if (write(name_pipe[1],name,sizeof(name))!=(ssize_t)sizeof(name) || read(go[0],&g,1)!=1) _exit(44);
        if (m11_anchor_owner_seal(&own,NULL)) _exit(45);
        int rc=seal_battery(&own);
        if (rc) { fprintf(stderr,"seal battery step %d\n",rc); _exit(rc); }
        int status=-1;
        if (m11_spawner_run(&sp,0,NULL,3000,&status) || status) _exit(46);    /* jobs still exec */
        if (m11_spawner_run(&sp,1,NULL,3000,&status) || status!=1) _exit(47);
        m11_worker_end end;
        if (m11_anchor_linux_lend(&own,send_q,NULL,NULL,0,3000,1000,&end) || end!=M11_WORKER_EXIT_OK) _exit(48);
        if (m11_anchor_check(&own) || read(go[0],&g,1)!=1) _exit(49);
        if (m11_anchor_final_close(&own) || own.state!=M11_ANCHOR_OWNER_FDS_DROPPED) _exit(50);
        if (m11_spawner_stop(&sp)) _exit(51);
        _exit(0);
    }
    close(name_pipe[1]); close(go[0]);
    char name[128]; assert(read(name_pipe[0],name,sizeof(name))==(ssize_t)sizeof(name));
    int observer=open_slave_by_name(name);
    assert(write(go[1],"S",1)==1);
    char c; struct pollfd p={observer,POLLIN,0};
    assert(poll(&p,1,5000)==1 && read(observer,&c,1)==1 && c=='Q' && !hup_within(observer,0));
    assert(write(go[1],"F",1)==1);
    int rc=exit_code(o);
    if (rc) printf("sealed owner exit code %d\n",rc);
    assert(!rc && hup_within(observer,2000));
    close(observer); close(name_pipe[0]); close(go[1]);
}

int main(void) {
    alarm(120); /* finite harness bound, not a recovery mechanism */
    setvbuf(stdout,NULL,_IONBF,0); /* keep every PASS line if an assertion aborts */
    struct stat st;
    standin=!lstat("/dev/ptmx",&st) && S_ISCHR(st.st_mode) ? "/dev/ptmx" : "/dev/pts/ptmx";
    m11_anchor_linux l; m11_anchor_ops ops;
    const char *refused[]={"/dev/aud_pasthru_adsp","/dev/msm_audio_ion","/dev/snd/pcmC0D0p","/tmp/endpoint"};
    for (unsigned i=0;i<4;i++) assert(m11_anchor_linux_ops(&l,refused[i],getpid(),&ops)==-EPERM);
    pass("backend refuses the real endpoint, the ION node, PCM nodes and any non-allowlisted path");

    m11_pid1_anchor a;
    assert(!bind_standin(&a,&l,getpid()));
    assert(a.anchor_fd>=M11_ANCHOR_RESERVED_FD && a.guard_fd==a.anchor_fd+1);
    assert((fcntl(a.anchor_fd,F_GETFD) & FD_CLOEXEC) && (fcntl(a.guard_fd,F_GETFD) & FD_CLOEXEC));
    bool kcmp=kcmp_available(a.anchor_fd);
    printf("INFO kcmp(KCMP_FILE) %s on this kernel\n",kcmp ? "available" : "UNAVAILABLE");
    pass("bind on the stand-in: one open, anchor + guard CLOEXEC at reserved numbers, census clean");

    m11_worker_end end;
    assert(!m11_anchor_linux_lend(&a,send_q,NULL,NULL,0,3000,1000,&end) && end==M11_WORKER_EXIT_OK);
    assert(from_slave()=='Q' && !hung_up() && a.state==M11_ANCHOR_HELD);
    pass("forked worker does I/O on the borrowed OFD and exits: non-final close, no release");
    assert(!m11_anchor_linux_lend(&a,stall,NULL,NULL,0,50,3000,&end) && end==M11_WORKER_EXIT_ABNORMAL);
    assert(!hung_up() && (a.latches & M11_ANCHOR_LATCH_WORKER_ABNORMAL) && !m11_anchor_check(&a));
    pass("worker SIGKILLed at the deadline: exit_files() is a non-final close, observer not hung up");

    int report[2]; assert(!pipe2(report,O_CLOEXEC));
    int extra=open("/dev/null",O_RDONLY|O_CLOEXEC); assert(extra>=0); /* PID1 state a worker must not keep */
    assert(!m11_anchor_linux_lend(&a,hygiene,&report[1],&report[1],1,3000,1000,&end) && end==M11_WORKER_EXIT_OK);
    char c; assert(read(report[0],&c,1)==1 && c=='H' && from_slave()=='H');
    close(report[0]); close(report[1]); close(extra);
    pass("worker fd hygiene: only stdio, the borrowed fd and the explicitly kept fd survive");
    assert(!m11_anchor_linux_lend(&a,confined,NULL,NULL,0,3000,1000,&end) && end==M11_WORKER_EXIT_OK);
    assert(from_slave()=='S' && !hung_up());
    pass("worker seccomp: no open, SCM_RIGHTS, fork/clone, exec, io_uring, pidfd_getfd, ptrace or reboot");

    char dir[]="/tmp/m11-anchor-XXXXXX"; assert(mkdtemp(dir));
    char forbidden[64]; snprintf(forbidden,sizeof(forbidden),"%s/node",dir);
    int made=open(forbidden,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600); assert(made>=0); close(made);
    if (geteuid()) {
        assert(!chmod(forbidden,0)); /* non-root: owner without CAP_DAC_OVERRIDE */
        pid_t dac=fork(); assert(dac>=0);
        if (!dac) {
            int other=open(forbidden,O_RDONLY|O_CLOEXEC);
            _exit(other<0 && errno==EACCES && write(a.anchor_fd,"D",1)==1 ? 0 : 1);
        }
        assert(!exit_code(dac) && from_slave()=='D');
        pass("DAC layer: open(2) of a protected node is refused, the inherited fd keeps working");
    } else {
        puts("SKIP DAC-only case as root (the backend worker drops to 65534 and is confined)");
    }
    unlink(forbidden); rmdir(dir);

    pid_t job=fork(); assert(job>=0);
    if (!job) { execl("/bin/true","true",(char *)NULL); _exit(127); }
    reaped(job);
    assert(!m11_anchor_check(&a) && !hung_up());
    pass("fork+exec job: CLOEXEC drops the inherited references at exec; census clean");
    int ready[2]; assert(!pipe2(ready,O_CLOEXEC));
    pid_t child=fork(); assert(child>=0);
    if (!child) { close(ready[0]); char r='R'; (void)!write(ready[1],&r,1); for (;;) pause(); }
    close(ready[1]); assert(read(ready[0],&c,1)==1); close(ready[0]);
    assert(m11_anchor_final_close(&a)==-EBUSY && (a.latches & M11_ANCHOR_LATCH_FOREIGN_HOLDER));
    assert(!kill(child,SIGKILL)); reaped(child);
    assert(m11_anchor_final_close(&a)==-EOWNERDEAD && !hung_up());
    pass("final close refused while a forked child shares the OFD; the refusal stays latched");
    m11_anchor_end how;
    assert(!m11_anchor_end_boot(&a,M11_TERMINAL_RESET_RETAINING_ANCHORS,&how) && how==M11_ANCHOR_END_RETAIN);
    assert(a.state==M11_ANCHOR_RETAINED && !hung_up());
    end_scenario(&a);

    assert(!bind_standin(&a,&l,getpid()));
    assert(!pipe2(ready,O_CLOEXEC));
    pid_t intruder=fork(); assert(intruder>=0);
    if (!intruder) {
        close(ready[0]);
        int second=open(standin,O_RDWR|O_NOCTTY|O_CLOEXEC); /* a second OFD of the same node */
        char r=second>=0 ? 'O' : 'E'; (void)!write(ready[1],&r,1);
        for (;;) pause();
    }
    close(ready[1]); assert(read(ready[0],&c,1)==1 && c=='O'); close(ready[0]);
    int fd=-1;
    assert(m11_anchor_check(&a)==-EBUSY && m11_anchor_lend_begin(&a,&fd)==-EOWNERDEAD);
    if (kcmp) assert(a.latches & M11_ANCHOR_LATCH_SECOND_OFD);
    assert(!kill(intruder,SIGKILL)); reaped(intruder);
    assert(!hung_up());
    pass("second OFD of the node detected (kcmp: as another OFD); its own release does not touch the anchor");
    end_scenario(&a);

    assert(!bind_standin(&a,&l,getpid()));
    char path[64]; snprintf(path,sizeof(path),"/proc/self/fd/%d",a.anchor_fd);
    int reopened=open(path,O_RDWR|O_NOCTTY|O_CLOEXEC); assert(reopened>=0);
    if (kcmp) assert(syscall(SYS_kcmp,getpid(),getpid(),0,a.anchor_fd,reopened)!=0);
    assert(m11_anchor_check(&a)==-EBUSY && (a.latches & M11_ANCHOR_LATCH_FOREIGN_HOLDER));
    close(reopened); assert(!hung_up());
    pass("reopen through /proc/<pid>/fd creates a NEW OFD, even of a path-less node; census refuses it");
    end_scenario(&a);

    if (kcmp) {
        assert(!bind_standin(&a,&l,getpid()));
        /* Same open flags as the backend, so identity AND F_GETFL match: only kcmp differs. */
        int planted=open(standin,O_RDWR|O_NONBLOCK|O_CLOEXEC|O_NOFOLLOW|O_NOCTTY); assert(planted>=0);
        assert(dup3(planted,a.guard_fd,O_CLOEXEC)==a.guard_fd); close(planted);
        assert(m11_anchor_check(&a)==-EBUSY && (a.latches & M11_ANCHOR_LATCH_SECOND_OFD) && !hung_up());
        pass("kcmp census: a second OFD planted at the guard number is refused despite equal identity");
        end_scenario(&a);
    } else {
        puts("SKIP planted second OFD: kcmp unavailable (identity alone cannot see it)");
    }

    assert(!bind_standin(&a,&l,getpid()));
    int null=open("/dev/null",O_RDONLY|O_CLOEXEC); assert(null>=0);
    assert(dup3(null,a.anchor_fd,O_CLOEXEC)==a.anchor_fd);
    assert(m11_anchor_check(&a)==-EBADF && (a.latches & M11_ANCHOR_LATCH_FD_DISCIPLINE) && !hung_up());
    pass("anchor number replaced by another file: identity mismatch latched; guard keeps the OFD");
    assert(dup3(null,a.guard_fd,O_CLOEXEC)==a.guard_fd); close(null);
    assert(hup_within(slave,2000));
    pass("NEGATIVE CONTROL: dup3 over BOTH reserved numbers releases the OFD (integration rule)");
    end_scenario(&a);

    assert(!bind_standin(&a,&l,getpid()));
    long cr=syscall(SYS_close_range,(unsigned)a.anchor_fd,(unsigned)a.guard_fd,0u);
    if (cr==0) {
        assert(hup_within(slave,2000) && m11_anchor_check(&a)==-EBADF);
        pass("NEGATIVE CONTROL: one close_range() over [anchor, guard] releases the OFD (integration rule)");
    } else {
        assert(errno==ENOSYS); puts("SKIP close_range: not provided by this kernel");
    }
    a.anchor_fd=a.guard_fd=-1;

    /* Self-exec: an owner process (not this harness) execs; the observer lives here. */
    int name_pipe[2], go[2]; assert(!pipe2(name_pipe,O_CLOEXEC) && !pipe2(go,O_CLOEXEC));
    pid_t owner=fork(); assert(owner>=0);
    if (!owner) {
        m11_pid1_anchor own; m11_anchor_linux ol; m11_anchor_ops oops;
        if (m11_anchor_linux_ops(&ol,standin,getpid(),&oops) || stat(standin,&st)) _exit(1);
        memset(&own,0,sizeof(own));
        if (m11_anchor_bind(&own,&oops,NULL,&evidence,getpid(),(uint64_t)st.st_rdev)) _exit(2);
        if (grantpt(own.anchor_fd) || unlockpt(own.anchor_fd) || !ptsname(own.anchor_fd)) _exit(3);
        char name[128]; snprintf(name,sizeof(name),"%s",ptsname(own.anchor_fd));
        if (write(name_pipe[1],name,sizeof(name))!=(ssize_t)sizeof(name)) _exit(4);
        char g; if (read(go[0],&g,1)!=1) _exit(5);
        execl("/bin/sleep","sleep","5",(char *)NULL); /* stays alive: only exec drops the fds */
        _exit(6);
    }
    close(name_pipe[1]); close(go[0]);
    char name[128]; assert(read(name_pipe[0],name,sizeof(name))==(ssize_t)sizeof(name));
    int observer=open(name,O_RDWR|O_NOCTTY|O_NONBLOCK|O_CLOEXEC); assert(observer>=0);
    assert(!hup_within(observer,0));
    assert(write(go[1],"X",1)==1);
    assert(hup_within(observer,3000) && !kill(owner,0)); /* released while the exec'ed image lives */
    assert(!kill(owner,SIGKILL)); reaped(owner);
    close(observer); close(name_pipe[0]); close(go[1]);
    pass("NEGATIVE CONTROL: an owner self-exec drops both FD_CLOEXEC references (integration rule)");

    /* CLONE_FILES: the child shares the owner's fd table. */
    assert(!bind_standin(&a,&l,getpid()));
    assert(!m11_anchor_lend_begin(&a,&fd));
    pid_t shared=(pid_t)syscall(SYS_clone,CLONE_FILES|SIGCHLD,0,0,0,0); assert(shared>=0);
    if (!shared) _exit(m11_anchor_worker_accept(&a,fd)==-EPERM ? 0 : 1);
    int accepted=exit_code(shared);
    assert(!m11_anchor_lend_abort(&a) || !kcmp);
    if (kcmp) {
        assert(!accepted && !m11_anchor_check(&a) && !hung_up());
        pass("CLONE_FILES worker refused by kcmp(KCMP_FILES) before it can touch the shared table");
    } else {
        assert(m11_anchor_check(&a)==-EBADF && !hung_up());
        pass("CLONE_FILES worker without kcmp: its guard close trips FD_DISCIPLINE, the anchor holds");
    }
    end_scenario(&a);
    assert(!bind_standin(&a,&l,getpid()));
    shared=(pid_t)syscall(SYS_clone,CLONE_FILES|SIGCHLD,0,0,0,0); assert(shared>=0);
    if (!shared) _exit(close(a.anchor_fd) || close(a.guard_fd)); /* a careless "close my copy" */
    assert(!exit_code(shared) && hup_within(slave,2000));
    pass("NEGATIVE CONTROL: a CLONE_FILES child closing its numbers releases the OFD (integration rule)");
    a.anchor_fd=a.guard_fd=-1;

    assert(!bind_standin(&a,&l,getpid()));
    int sv[2]; assert(!socketpair(AF_UNIX,SOCK_DGRAM|SOCK_CLOEXEC,0,sv));
    char byte='x'; struct iovec io={&byte,1};
    union { char buf[CMSG_SPACE(sizeof(int))]; struct cmsghdr align; } u;
    struct msghdr m={.msg_iov=&io,.msg_iovlen=1,.msg_control=u.buf,.msg_controllen=sizeof(u.buf)};
    struct cmsghdr *cm=CMSG_FIRSTHDR(&m);
    cm->cmsg_level=SOL_SOCKET; cm->cmsg_type=SCM_RIGHTS; cm->cmsg_len=CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cm),&a.anchor_fd,sizeof(int));
    assert(sendmsg(sv[0],&m,0)==1);          /* queued, never received: in flight */
    assert(!m11_anchor_check(&a));           /* every fd table looks clean */
    a.ops.release_oracle=slave_oracle;
    assert(!m11_anchor_final_close(&a) && a.state==M11_ANCHOR_OWNER_FDS_DROPPED);
    assert(a.release==M11_RELEASE_NOT_OBSERVED && (a.latches & M11_ANCHOR_LATCH_HIDDEN_REFERENCE) && !hung_up());
    assert(m11_anchor_end_boot(&a,M11_TERMINAL_ORDERLY_SHUTDOWN,&how)==-EPROTO && how==M11_ANCHOR_END_RETAIN);
    close(sv[0]); close(sv[1]);
    assert(hup_within(slave,2000));
    pass("SCM_RIGHTS in flight: owner fds dropped is not release; oracle refutes it, reboot refused");

    assert(!bind_standin(&a,&l,getpid()));
    assert(!m11_anchor_linux_lend(&a,send_q,NULL,NULL,0,3000,1000,&end) && from_slave()=='Q');
    real_close=a.ops.close_fd; closes=0;
    a.ops.close_fd=observed_close; a.ops.release_oracle=slave_oracle;
    assert(!m11_anchor_final_close(&a) && a.state==M11_ANCHOR_OWNER_FDS_DROPPED && closes==2);
    assert(!hup_after[0] && hup_after[1] && a.release==M11_RELEASE_OBSERVED);
    assert(!m11_anchor_end_boot(&a,M11_TERMINAL_ORDERLY_SHUTDOWN,&how) && how==M11_ANCHOR_END_REBOOT);
    pass("final close as sole holder: release observed after the second close, not the first");

    sealed_owner_scenario();
    pass("sealed owner: close/dup/fcntl/close_range over the reserved numbers, exec, CLONE_FILES, "
         "SCM_RIGHTS, io_uring, ptrace and mknod refused; jobs run through the pre-bind spawner; "
         "a confined loan works; the final close_range releases");

    if (geteuid()) {
        int rc=bind_standin(&a,&l,0);
        assert(rc<0 && a.state==M11_ANCHOR_HELD && (a.latches & M11_ANCHOR_LATCH_CENSUS_ERROR));
        assert(m11_anchor_lend_begin(&a,&fd)==-EOWNERDEAD && m11_anchor_final_close(&a)==-EOWNERDEAD);
        pass("whole-system census as non-root cannot read every fd table: fails closed");
        end_scenario(&a);
    } else {
        puts("SKIP whole-system census fail-closed case: running as root");
    }
    alarm(0);
    printf("PID1 anchor process qualification: %u cases PASS (stand-in node; real endpoint not opened)\n",cases);
    return 0;
}
