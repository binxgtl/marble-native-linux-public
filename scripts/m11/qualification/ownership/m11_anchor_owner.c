#define _GNU_SOURCE
#include "m11_anchor_owner.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#if defined(__x86_64__)
#define OWNER_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define OWNER_ARCH AUDIT_ARCH_AARCH64
#else
#error "owner seal is defined for x86_64 and aarch64 only"
#endif

/* ------------------------------------ the seal ------------------------------------ */
#define SEAL_MAX 160u
struct prog { struct sock_filter f[SEAL_MAX]; unsigned n; bool overflow; };
static void put(struct prog *p, struct sock_filter x) {
    if (p->n<SEAL_MAX) p->f[p->n++]=x; else p->overflow=true;
}
#define STMT(c,k) put(p,(struct sock_filter)BPF_STMT((c),(k)))
#define JUMP(c,k,t,f) put(p,(struct sock_filter)BPF_JUMP((c),(k),(t),(f)))
#define RET_DENY (SECCOMP_RET_ERRNO|(EPERM&SECCOMP_RET_DATA))
static uint32_t arg_lo(unsigned i) { return (uint32_t)(offsetof(struct seccomp_data,args)+8u*i); } /* little endian */
/* Every block is entered with the syscall number in the accumulator and ends in a return,
 * so a block that does not match is skipped whole. */
static void deny(struct prog *p, uint32_t nr, uint32_t err) {
    JUMP(BPF_JMP|BPF_JEQ|BPF_K,nr,0,1);
    STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|(err&SECCOMP_RET_DATA));
}
static void reserved_arg(struct prog *p, uint32_t nr, unsigned i, uint32_t a, uint32_t g) {
    JUMP(BPF_JMP|BPF_JEQ|BPF_K,nr,0,5);
    STMT(BPF_LD|BPF_W|BPF_ABS,arg_lo(i));
    JUMP(BPF_JMP|BPF_JEQ|BPF_K,a,2,0);
    JUMP(BPF_JMP|BPF_JEQ|BPF_K,g,1,0);
    STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW);
    STMT(BPF_RET|BPF_K,RET_DENY);
}
static void build(struct prog *p, uint32_t a, uint32_t g) {
    STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,arch));
    JUMP(BPF_JMP|BPF_JEQ|BPF_K,OWNER_ARCH,1,0);
    STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS);
    STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr));
#if defined(__x86_64__)
    JUMP(BPF_JMP|BPF_JGE|BPF_K,0x40000000u,0,1); /* x32 ABI aliases */
    STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS);
    deny(p,__NR_mknod,EPERM);
    reserved_arg(p,__NR_dup2,1,a,g);
#endif
    /* P2 */
    deny(p,__NR_execve,EPERM); deny(p,__NR_execveat,EPERM);
    /* P4 */
    deny(p,__NR_sendmsg,EPERM); deny(p,__NR_sendmmsg,EPERM);
    deny(p,__NR_io_uring_setup,EPERM); deny(p,__NR_io_uring_enter,EPERM); deny(p,__NR_io_uring_register,EPERM);
    deny(p,__NR_pidfd_getfd,EPERM); deny(p,__NR_ptrace,EPERM);
    deny(p,__NR_process_vm_readv,EPERM); deny(p,__NR_process_vm_writev,EPERM);
    /* P5 (the owner itself) */
    deny(p,__NR_mknodat,EPERM); deny(p,__NR_open_by_handle_at,EPERM);
    /* P1: clone3 hides its flags in memory; glibc falls back to clone on ENOSYS. */
    deny(p,__NR_clone3,ENOSYS);
    JUMP(BPF_JMP|BPF_JEQ|BPF_K,__NR_clone,0,4);
    STMT(BPF_LD|BPF_W|BPF_ABS,arg_lo(0));
    JUMP(BPF_JMP|BPF_JSET|BPF_K,CLONE_FILES|CLONE_THREAD,1,0);
    STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW);
    STMT(BPF_RET|BPF_K,RET_DENY);
    /* P3 */
    reserved_arg(p,__NR_close,0,a,g);
    reserved_arg(p,__NR_dup,0,a,g);
    reserved_arg(p,__NR_dup3,1,a,g);
    JUMP(BPF_JMP|BPF_JEQ|BPF_K,__NR_fcntl,0,10);
    STMT(BPF_LD|BPF_W|BPF_ABS,arg_lo(0));
    JUMP(BPF_JMP|BPF_JEQ|BPF_K,a,1,0);
    JUMP(BPF_JMP|BPF_JEQ|BPF_K,g,0,5);
    STMT(BPF_LD|BPF_W|BPF_ABS,arg_lo(1));
    JUMP(BPF_JMP|BPF_JEQ|BPF_K,F_DUPFD,4,0);
    JUMP(BPF_JMP|BPF_JEQ|BPF_K,F_DUPFD_CLOEXEC,3,0);
    JUMP(BPF_JMP|BPF_JEQ|BPF_K,F_SETFD,2,0);
    JUMP(BPF_JMP|BPF_JEQ|BPF_K,F_SETFL,1,0);
    STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW);
    STMT(BPF_RET|BPF_K,RET_DENY);
    /* The only permitted close of the reserved numbers: close_range(anchor, guard, 0). */
    JUMP(BPF_JMP|BPF_JEQ|BPF_K,__NR_close_range,0,8);
    STMT(BPF_LD|BPF_W|BPF_ABS,arg_lo(0));
    JUMP(BPF_JMP|BPF_JEQ|BPF_K,a,0,5);
    STMT(BPF_LD|BPF_W|BPF_ABS,arg_lo(1));
    JUMP(BPF_JMP|BPF_JEQ|BPF_K,g,0,3);
    STMT(BPF_LD|BPF_W|BPF_ABS,arg_lo(2));
    JUMP(BPF_JMP|BPF_JEQ|BPF_K,0,0,1);
    STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW);
    STMT(BPF_RET|BPF_K,RET_DENY);
    STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW);
}
int m11_anchor_owner_filter(int anchor_fd, int guard_fd) {
    static struct prog p;
    memset(&p,0,sizeof(p));
    if (anchor_fd<0 || guard_fd!=anchor_fd+1) return -EINVAL;
    build(&p,(uint32_t)anchor_fd,(uint32_t)guard_fd);
    if (p.overflow) return -E2BIG;
    struct sock_fprog fp={(unsigned short)p.n,p.f};
    if (prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)) return -errno;
    return prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&fp,0,0) ? -errno : 0;
}
static int close_pair(void *ctx, int anchor_fd, int guard_fd) {
    (void)ctx;
    return syscall(SYS_close_range,(unsigned)anchor_fd,(unsigned)guard_fd,0u) ? -errno : 0;
}
int m11_anchor_owner_seal(m11_pid1_anchor *a, const char *node) {
    if (!a || a->state!=M11_ANCHOR_HELD || (a->latches & M11_ANCHOR_LATCH_REFUSE) ||
        a->guard_fd!=a->anchor_fd+1 || a->ops.close_pair) return -EINVAL;
    if (node && !*node) return -EINVAL;
    if (!a->ops.self_pid || a->ops.self_pid(a->ops.ctx)!=a->owner_pid) return -EPERM;
    int rc=0;
    if (node && unlink(node)) return -errno; /* P5: no path left to a second OFD */
    if (prctl(PR_SET_DUMPABLE,0,0,0,0)) return -errno; /* P5: no same-uid /proc reopen */
    if ((rc=m11_anchor_owner_filter(a->anchor_fd,a->guard_fd))) return rc; /* owner seal filter */
    a->ops.close_pair=close_pair;
    return rc ? rc : m11_anchor_check(a);
}

/* ----------------------------------- the spawner ----------------------------------- */
#define SPAWN_ARG 160u
struct request { uint32_t index, deadline_ms, flags; char arg[SPAWN_ARG]; };
struct reply { int32_t rc, status; };
int m11_anchor_owner_drop_job_caps(void) {
    static const int caps[]={CAP_MKNOD,CAP_SYS_PTRACE,CAP_DAC_READ_SEARCH};
    for (unsigned i=0;i<3;i++) if (prctl(PR_CAPBSET_DROP,caps[i],0,0,0)) return -errno;
    if (prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_CLEAR_ALL,0,0,0)) return -errno;
    struct __user_cap_header_struct h={_LINUX_CAPABILITY_VERSION_3,0};
    struct __user_cap_data_struct d[2];
    if (syscall(SYS_capget,&h,d)) return -errno;
    for (unsigned i=0;i<3;i++) {
        uint32_t bit=1u<<(caps[i]%32); unsigned w=(unsigned)caps[i]/32;
        d[w].effective&=~bit; d[w].permitted&=~bit; d[w].inheritable&=~bit;
    }
    return syscall(SYS_capset,&h,d) ? -errno : 0;
}
static int now_ms(uint64_t *t) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC,&ts)) return -1;
    *t=(uint64_t)ts.tv_sec*1000u+(uint64_t)ts.tv_nsec/1000000u; return 0;
}
static int reap(pid_t pid, unsigned ms, int *status) {
    uint64_t t, until;
    if (now_ms(&t)) return 0;
    until=t+ms;
    for (;;) {
        int st; pid_t rc=waitpid(pid,&st,WNOHANG);
        if (rc==pid) { *status=WIFEXITED(st) ? WEXITSTATUS(st) : 128+WTERMSIG(st); return 1; }
        if (rc<0 && errno!=EINTR) return 0;
        if (now_ms(&t) || t>=until) return 0;
        (void)poll(NULL,0,2);
    }
}
static int run_one(const char *const *argv, const char *arg, unsigned ms, unsigned flags, int *status, bool *stuck) {
    const char *full[34]; unsigned n=0;
    while (n<32 && argv[n]) { full[n]=argv[n]; n++; }
    if (!n || argv[n]) return -E2BIG;
    if (arg) full[n++]=arg;
    full[n]=NULL;
    pid_t pid=fork();
    if (pid<0) return -errno;
    if (!pid) {
        /* stdin/stdout on /dev/null, stderr kept for diagnostics, nothing else inherited. */
        int null=open("/dev/null",O_RDWR|O_CLOEXEC);
        if (null<0 || dup2(null,0)<0 || dup2(null,1)<0) _exit(126);
        if (m11_anchor_linux_close_unlisted(-1,NULL,0)) _exit(126);
        char *const env[]={NULL};
        execve(full[0],(char *const *)full,env);
        _exit(127);
    }
    if (reap(pid,ms,status)) return 0;
    if (flags & M11_SPAWN_NO_KILL) { *stuck=true; return -EINPROGRESS; } /* left running, never killed */
    (void)kill(pid,SIGKILL);
    if (reap(pid,1000,status)) return -ETIMEDOUT;
    *stuck=true; /* a D-state job: never start another one */
    return -EINPROGRESS;
}
static void serve(int sock, const char *const *const *commands, unsigned count) {
    bool stuck=false;
    for (;;) {
        struct request q; ssize_t got=recv(sock,&q,sizeof(q),0);
        if (got==0) _exit(0);
        if (got!=(ssize_t)sizeof(q)) _exit(3);
        struct reply r={0,0}; int status=0;
        if (stuck) r.rc=-EBUSY;
        else if (q.index>=count || !memchr(q.arg,0,sizeof(q.arg))) r.rc=-EINVAL;
        else r.rc=run_one(commands[q.index],q.arg[0] ? q.arg : NULL,q.deadline_ms,q.flags,&status,&stuck);
        r.status=status;
        if (send(sock,&r,sizeof(r),MSG_NOSIGNAL)!=(ssize_t)sizeof(r)) _exit(4);
    }
}
int m11_spawner_start(m11_spawner *s, const char *const *const *commands, unsigned count, bool require_drop) {
    if (!s || !commands || !count) return -EINVAL;
    *s=(m11_spawner){-1,-1,false};
    bool root=geteuid()==0;
    if (require_drop && !root) return -EPERM;
    int sv[2], ready[2];
    if (socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,sv)) return -errno;
    if (pipe2(ready,O_CLOEXEC)) { int e=errno; close(sv[0]); close(sv[1]); return -e; }
    pid_t pid=fork();
    if (pid<0) { int e=errno; close(sv[0]); close(sv[1]); close(ready[0]); close(ready[1]); return -e; }
    if (!pid) {
        close(sv[0]); close(ready[0]);
        char ok=1;
        if (root && m11_anchor_owner_drop_job_caps()) ok=0; /* P5: job capabilities */
        /* Close every inherited fd BEFORE reporting ready: the owner's census of this process
         * must not race its closes (a vanishing fd is an inconclusive census). */
        if (m11_anchor_linux_close_unlisted(sv[1],&ready[1],1)) ok=0;
        if (write(ready[1],&ok,1)!=1 || !ok) _exit(2);
        close(ready[1]);
        serve(sv[1],commands,count);
        _exit(0);
    }
    close(sv[1]); close(ready[1]);
    char ok=0, extra; ssize_t got, eof;
    do { got=read(ready[0],&ok,1); } while (got<0 && errno==EINTR);
    /* Then EOF: the child has closed its last inherited fd (ready[1]) and its fd table is
     * final, so a census of it cannot race a close. */
    do { eof=read(ready[0],&extra,1); } while (eof<0 && errno==EINTR);
    close(ready[0]);
    if (got!=1 || !ok || eof!=0) {
        close(sv[0]); (void)kill(pid,SIGKILL); (void)waitpid(pid,NULL,0); return -EPERM;
    }
    *s=(m11_spawner){sv[0],pid,root};
    return 0;
}
int m11_spawner_run(m11_spawner *s, unsigned index, const char *arg, unsigned deadline_ms, int *status) {
    return m11_spawner_run_flags(s,index,arg,deadline_ms,0,status);
}
int m11_spawner_run_flags(m11_spawner *s, unsigned index, const char *arg, unsigned deadline_ms,
                          unsigned flags, int *status) {
    if (!s || s->sock<0 || !status) return -EINVAL;
    struct request q={index,deadline_ms,flags,{0}};
    if (arg) {
        size_t len=strlen(arg);
        if (len>=sizeof(q.arg)) return -E2BIG;
        memcpy(q.arg,arg,len);
    }
    if (send(s->sock,&q,sizeof(q),MSG_NOSIGNAL)!=(ssize_t)sizeof(q)) return -EIO;
    struct pollfd p={s->sock,POLLIN,0}; int rc;
    do { rc=poll(&p,1,(int)(deadline_ms+3000u)); } while (rc<0 && errno==EINTR);
    if (rc!=1) return -EINPROGRESS; /* the spawner itself did not answer */
    struct reply r;
    if (recv(s->sock,&r,sizeof(r),0)!=(ssize_t)sizeof(r)) return -EIO;
    *status=r.status;
    return r.rc;
}
int m11_spawner_stop(m11_spawner *s) {
    if (!s || s->sock<0) return -EINVAL;
    close(s->sock); s->sock=-1;
    int status=0;
    if (reap(s->pid,3000,&status)) return status ? -EIO : 0;
    (void)kill(s->pid,SIGKILL); (void)reap(s->pid,1000,&status);
    return -ETIMEDOUT;
}
