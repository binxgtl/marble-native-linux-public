#define _GNU_SOURCE
#include "m11_anchor_linux.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <sys/syscall.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#if defined(M11_ANCHOR_NATIVE_ION) && !defined(M11_ANCHOR_NATIVE)
#error "M11_ANCHOR_NATIVE_ION extends the native integration build only"
#endif
#define MAX_PROCESSES 4096u
#define MAX_FDS 4096u
static const char *const stand_ins[]={"/dev/ptmx","/dev/pts/ptmx","/dev/null"};

static int lx_self(void *v) { (void)v; return (int)getpid(); }
static int lx_open(void *v) {
    const m11_anchor_linux *l=v;
    /* Same flags as the native GPR worker's lx_open, plus O_NOCTTY for the pty stand-in. */
    int fd=open(l->path,O_RDWR|O_NONBLOCK|O_CLOEXEC|O_NOFOLLOW|O_NOCTTY);
    return fd<0 ? -errno : fd;
}
static int lx_identify(void *v, int fd, m11_anchor_id *id) {
    (void)v; struct stat st;
    if (fstat(fd,&st)) return -errno;
    *id=(m11_anchor_id){(uint64_t)st.st_dev,(uint64_t)st.st_ino,(uint64_t)st.st_rdev,(uint32_t)(st.st_mode & S_IFMT)};
    return 0;
}
static int lx_dup(void *v, int fd, int min) { (void)v; int r=fcntl(fd,F_DUPFD_CLOEXEC,min); return r<0 ? -errno : r; }
static int lx_fd_flags(void *v, int fd) { (void)v; int r=fcntl(fd,F_GETFD); return r<0 ? -errno : r; }
static int lx_status(void *v, int fd) { (void)v; int r=fcntl(fd,F_GETFL); return r<0 ? -errno : r; }
static int lx_close(void *v, int fd) { (void)v; return close(fd) ? -errno : 0; } /* never retried */
#define M11_KCMP_FILE 0  /* include/uapi/linux/kcmp.h */
#define M11_KCMP_FILES 2
static int lx_same_ofd(void *v, int pa, int fa, int pb, int fb) {
    (void)v;
    long r=syscall(SYS_kcmp,(pid_t)pa,(pid_t)pb,M11_KCMP_FILE,(unsigned long)fa,(unsigned long)fb);
    if (r<0) return -errno;
    return r==0 ? 1 : 0; /* 1/2 order unequal objects; 3 = not comparable */
}
int m11_anchor_linux_fd_table_shared(void) {
    long r=syscall(SYS_kcmp,getpid(),getppid(),M11_KCMP_FILES,0ul,0ul);
    if (r<0) return -errno;
    return r==0;
}
static int lx_table_shared(void *v) { (void)v; return m11_anchor_linux_fd_table_shared(); }

static int numeric(const char *s) {
    if (!*s) return 0;
    for (;*s;s++) if (*s<'0' || *s>'9') return 0;
    return 1;
}
static int parent_of(int pid) {
    char path[64], b[4096]; snprintf(path,sizeof(path),"/proc/%d/stat",pid);
    int fd=open(path,O_RDONLY|O_CLOEXEC); if (fd<0) return -1;
    ssize_t n=read(fd,b,sizeof(b)-1); close(fd);
    if (n<=0) return -1;
    b[n]=0; char *c=strrchr(b,')'); int ppid;
    if (!c || sscanf(c+1," %*c %d",&ppid)!=1) return -1;
    return ppid;
}
/* Test scope: the census root and its descendants. Unknown ancestry is included (fail closed). */
static int in_scope(int pid, int root) {
    for (unsigned depth=0; depth<64 && pid>0; depth++) {
        if (pid==root) return 1;
        pid=parent_of(pid);
        if (pid<0) return 1;
    }
    return 0;
}
/* A character device is one driver object whatever node reaches it: every node with the same
 * device number is a holder (a second node made with mknod opens a second OFD of the driver). */
static int same_node(const struct stat *st, const m11_anchor_id *want) {
    if ((uint32_t)(st->st_mode & S_IFMT)!=want->type) return 0;
    if (want->type==S_IFCHR) return (uint64_t)st->st_rdev==want->rdev; /* census by device number */
    return (uint64_t)st->st_dev==want->dev && (uint64_t)st->st_ino==want->ino && (uint64_t)st->st_rdev==want->rdev;
}
static int lx_holders(void *v, const m11_anchor_id *want, m11_anchor_holder *out, unsigned cap, unsigned *n) {
    const m11_anchor_linux *l=v; *n=0;
    DIR *proc=opendir("/proc"); if (!proc) return -errno;
    int rc=0; unsigned processes=0; struct dirent *e;
    for (;;) {
        errno=0; e=readdir(proc);
        if (!e) { if (errno) rc=-errno; break; }
        if (!numeric(e->d_name)) continue;
        if (++processes>MAX_PROCESSES) { rc=-E2BIG; break; }
        int pid=atoi(e->d_name);
        if (l->census_root>0 && !in_scope(pid,l->census_root)) continue;
        char path[64]; snprintf(path,sizeof(path),"/proc/%d/fd",pid);
        DIR *fds=opendir(path);
        if (!fds) {
            if (errno==ENOENT) continue; /* exited: holds nothing */
            rc=-errno; break;            /* unreadable: cannot exclude a holder */
        }
        unsigned count=0; struct dirent *f;
        for (;;) {
            errno=0; f=readdir(fds);
            if (!f) { if (errno) rc=-errno; break; }
            if (!numeric(f->d_name)) continue;
            if (++count>MAX_FDS) { rc=-E2BIG; break; }
            char item[384]; struct stat st; /* "/proc/%d/fd" + "/" + NAME_MAX */
            snprintf(item,sizeof(item),"%s/%s",path,f->d_name);
            /* A racing close is inconclusive: reject, never skip (as the native census does). */
            if (stat(item,&st)) { rc=errno==ENOENT ? -EAGAIN : -errno; break; }
            if (!same_node(&st,want)) continue;
            if (*n==cap) { rc=-E2BIG; break; }
            out[(*n)++]=(m11_anchor_holder){pid,atoi(f->d_name)};
        }
        closedir(fds);
        if (rc) break;
    }
    closedir(proc);
    return rc;
}
/* A stand-in is one of the fixed paths, or a private node (e.g. made by a root test with
 * mknod) whose device number is the pty multiplexer (5:2) or null (1:3). Never a path that
 * names the real endpoint, the ION node or an ALSA node, whatever it points at. */
static int standin(const char *path) {
#if defined(M11_ANCHOR_NATIVE)
    if (!strcmp(path,"/dev/aud_pasthru_adsp")) return 1; /* the integration build's one real node */
#endif
#if defined(M11_ANCHOR_NATIVE_ION)
    if (!strcmp(path,"/dev/msm_audio_ion")) return 1; /* R2 build: the ION node, never its CMA twin */
#endif
    if (strstr(path,"aud_pasthru") || strstr(path,"msm_audio_ion") || strstr(path,"/snd/")) return 0;
    for (unsigned i=0;i<sizeof(stand_ins)/sizeof(*stand_ins);i++) if (!strcmp(path,stand_ins[i])) return 1;
    struct stat st;
    return !lstat(path,&st) && S_ISCHR(st.st_mode) &&
           (st.st_rdev==makedev(5,2) || st.st_rdev==makedev(1,3));
}
int m11_anchor_linux_ops(m11_anchor_linux *l, const char *path, int census_root, m11_anchor_ops *out) {
    if (!l || !path || !out || census_root<0) return -EINVAL;
    if (!standin(path)) return -EPERM; /* in particular never /dev/aud_pasthru_adsp */
    *l=(m11_anchor_linux){path,census_root};
    /* No release oracle: the backend cannot observe a driver release. */
    *out=(m11_anchor_ops){l,lx_self,lx_open,lx_identify,lx_dup,lx_fd_flags,lx_status,lx_close,lx_holders,
                          lx_same_ofd,lx_table_shared,NULL,NULL};
    return 0;
}

static int now_ms(uint64_t *t) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC,&ts)) return -1;
    *t=(uint64_t)ts.tv_sec*1000u+(uint64_t)ts.tv_nsec/1000000u; return 0;
}
/* Same sequence as the native audio runtime's drop_privileges(): only when root. */
int m11_anchor_linux_drop_privileges(void) {
    if (prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0) || prctl(PR_SET_KEEPCAPS,0,0,0,0) ||
        prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_CLEAR_ALL,0,0,0)) return -1;
    for (int cap=0;cap<64;cap++) {
        int present=prctl(PR_CAPBSET_READ,cap,0,0,0);
        if (present<0) { if (errno==EINVAL) break; return -1; }
        if (prctl(PR_CAPBSET_DROP,cap,0,0,0)) return -1;
    }
    return setgroups(0,0) || setresgid(65534,65534,65534) || setresuid(65534,65534,65534) ? -1 : 0;
}
static int kept(int fd, int borrowed, const int *keep, unsigned nkeep) {
    if (fd<=2 || fd==borrowed) return 1;
    for (unsigned i=0;i<nkeep;i++) if (keep[i]==fd) return 1;
    return 0;
}
/* Worker fd hygiene: snapshot /proc/self/fd, then close every fd not explicitly kept. */
int m11_anchor_linux_close_unlisted(int borrowed, const int *keep, unsigned nkeep) {
    static int fds[MAX_FDS];
    unsigned n=0;
    DIR *d=opendir("/proc/self/fd"); if (!d) return -1;
    int self=dirfd(d), rc=0; struct dirent *e;
    for (;;) {
        errno=0; e=readdir(d);
        if (!e) { if (errno) rc=-1; break; }
        if (!numeric(e->d_name)) continue;
        int fd=atoi(e->d_name);
        if (fd==self || kept(fd,borrowed,keep,nkeep)) continue;
        if (n==MAX_FDS) { rc=-1; break; }
        fds[n++]=fd;
    }
    closedir(d);
    for (unsigned i=0;i<n;i++) if (close(fds[i])) rc=-1;
    return rc;
}
/* The worker keeps stdio, the borrowed fd, its guard copy when a sealed owner's inherited
 * filter refused to close it, and at most 16 explicitly kept fds. */
int m11_anchor_linux_worker_hygiene(int borrowed, int guard, const int *keep, unsigned nkeep) {
    int kept_fds[17]; unsigned nk=0;
    if (nkeep>16 || (nkeep && !keep)) return -1;
    for (unsigned i=0;i<nkeep;i++) kept_fds[nk++]=keep[i];
    kept_fds[nk++]=guard;
    return m11_anchor_linux_close_unlisted(borrowed,kept_fds,nk);
}
#if defined(__x86_64__)
#define M11_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define M11_AUDIT_ARCH AUDIT_ARCH_AARCH64
#else
#error "worker confinement is defined for x86_64 and aarch64 only"
#endif
#define M11_DENY(nr, err) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(nr),0,1), BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|((err)&SECCOMP_RET_DATA))
/* Denylist, not allowlist: the libc and sanitizer runtimes vary. It removes every route the
 * worker has to a second OFD (open/mknod), to an exported or hidden reference (SCM_RIGHTS,
 * io_uring, pidfd_getfd), to a new image or process (exec, fork/clone: no CLONE_FILES peer),
 * to another process (ptrace, process_vm_*), and to KernelSU's fd (installed by a kprobe on
 * reboot(2) in KernelSU-Next v3.3.0 and v3.4.0). */
int m11_anchor_linux_confine(void) {
    struct sock_filter f[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,arch)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,M11_AUDIT_ARCH,1,0),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
#if defined(__x86_64__)
        BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K,0x40000000u,0,1), /* x32 ABI aliases */
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS),
        M11_DENY(__NR_open,EPERM), M11_DENY(__NR_creat,EPERM), M11_DENY(__NR_mknod,EPERM),
        M11_DENY(__NR_fork,EPERM), M11_DENY(__NR_vfork,EPERM),
#endif
        M11_DENY(__NR_openat,EPERM), M11_DENY(__NR_openat2,EPERM), M11_DENY(__NR_open_by_handle_at,EPERM),
        M11_DENY(__NR_mknodat,EPERM), M11_DENY(__NR_execve,EPERM), M11_DENY(__NR_execveat,EPERM),
        M11_DENY(__NR_sendmsg,EPERM), M11_DENY(__NR_sendmmsg,EPERM), M11_DENY(__NR_pidfd_getfd,EPERM),
        M11_DENY(__NR_io_uring_setup,EPERM), M11_DENY(__NR_io_uring_enter,EPERM),
        M11_DENY(__NR_io_uring_register,EPERM), M11_DENY(__NR_clone,EPERM), M11_DENY(__NR_clone3,ENOSYS),
        M11_DENY(__NR_ptrace,EPERM), M11_DENY(__NR_process_vm_readv,EPERM),
        M11_DENY(__NR_process_vm_writev,EPERM), M11_DENY(__NR_reboot,EPERM),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog={(unsigned short)(sizeof(f)/sizeof(*f)),f};
    if (prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)) return -1;
    return prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&prog,0,0) ? -1 : 0;
}
static int reap(int pid, unsigned ms, int *status) {
    uint64_t t, until;
    if (now_ms(&t)) return 0;
    until=t+ms;
    for (;;) {
        int rc=waitpid(pid,status,WNOHANG);
        if (rc==pid) return 1;
        if (rc<0 && errno!=EINTR) return 0;
        if (now_ms(&t) || t>=until) return 0;
        (void)poll(NULL,0,2);
    }
}
int m11_anchor_linux_lend(m11_pid1_anchor *a, m11_anchor_work work, void *arg, const int *keep, unsigned nkeep,
                          unsigned deadline_ms, unsigned grace_ms, m11_worker_end *end) {
    if (!a || !work || !end || (nkeep && !keep)) return -EINVAL;
    *end=M11_WORKER_UNRESOLVED;
    int fd, rc=m11_anchor_lend_begin(a,&fd);
    if (rc) return rc;
    pid_t pid=fork(); /* a separate fd table: never clone(CLONE_FILES) */
    if (pid<0) { rc=-errno; (void)m11_anchor_lend_abort(a); return rc; }
    if (!pid) {
        if (m11_anchor_worker_accept(a,fd)) _exit(M11_WORKER_EXIT_ACCEPT);
        if (m11_anchor_linux_worker_hygiene(fd,a->guard_fd,keep,nkeep)) _exit(M11_WORKER_EXIT_HYGIENE); /* worker fd hygiene */
        if (geteuid()==0 && m11_anchor_linux_drop_privileges()) _exit(M11_WORKER_EXIT_PRIVILEGE);
        if (m11_anchor_linux_confine()) _exit(M11_WORKER_EXIT_CONFINE); /* worker seccomp confinement */
        _exit(work(fd,arg) ? M11_WORKER_EXIT_WORK : 0);
    }
    if ((rc=m11_anchor_lend_started(a,pid))) return rc; /* cannot happen for a fresh child */
    int status=0;
    if (reap(pid,deadline_ms,&status)) {
        *end=WIFEXITED(status) && !WEXITSTATUS(status) ? M11_WORKER_EXIT_OK : M11_WORKER_EXIT_ABNORMAL;
    } else {
        (void)kill(pid,SIGKILL); /* cannot end a D-state syscall; then the loan stays open */
        *end=reap(pid,grace_ms,&status) ? M11_WORKER_EXIT_ABNORMAL : M11_WORKER_UNRESOLVED;
    }
    return m11_anchor_lend_end(a,*end);
}
