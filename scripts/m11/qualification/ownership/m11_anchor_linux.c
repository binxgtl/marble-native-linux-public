#define _GNU_SOURCE
#include "m11_anchor_linux.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

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
            if ((uint64_t)st.st_dev!=want->dev || (uint64_t)st.st_ino!=want->ino ||
                (uint64_t)st.st_rdev!=want->rdev || (uint32_t)(st.st_mode & S_IFMT)!=want->type) continue;
            if (*n==cap) { rc=-E2BIG; break; }
            out[(*n)++]=(m11_anchor_holder){pid,atoi(f->d_name)};
        }
        closedir(fds);
        if (rc) break;
    }
    closedir(proc);
    return rc;
}
int m11_anchor_linux_ops(m11_anchor_linux *l, const char *path, int census_root, m11_anchor_ops *out) {
    if (!l || !path || !out || census_root<0) return -EINVAL;
    int allowed=0;
    for (unsigned i=0;i<sizeof(stand_ins)/sizeof(*stand_ins);i++) if (!strcmp(path,stand_ins[i])) allowed=1;
    if (!allowed) return -EPERM; /* in particular never /dev/aud_pasthru_adsp */
    *l=(m11_anchor_linux){path,census_root};
    *out=(m11_anchor_ops){l,lx_self,lx_open,lx_identify,lx_dup,lx_fd_flags,lx_status,lx_close,lx_holders};
    return 0;
}

static int now_ms(uint64_t *t) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC,&ts)) return -1;
    *t=(uint64_t)ts.tv_sec*1000u+(uint64_t)ts.tv_nsec/1000000u; return 0;
}
/* Same sequence as the native audio runtime's drop_privileges(): only when root. */
static int drop_privileges(void) {
    if (prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0) || prctl(PR_SET_KEEPCAPS,0,0,0,0) ||
        prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_CLEAR_ALL,0,0,0)) return -1;
    for (int cap=0;cap<64;cap++) {
        int present=prctl(PR_CAPBSET_READ,cap,0,0,0);
        if (present<0) { if (errno==EINVAL) break; return -1; }
        if (prctl(PR_CAPBSET_DROP,cap,0,0,0)) return -1;
    }
    return setgroups(0,0) || setresgid(65534,65534,65534) || setresuid(65534,65534,65534) ? -1 : 0;
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
int m11_anchor_linux_lend(m11_pid1_anchor *a, m11_anchor_work work, void *arg, unsigned deadline_ms,
                          unsigned grace_ms, m11_worker_end *end) {
    if (!a || !work || !end) return -EINVAL;
    *end=M11_WORKER_UNRESOLVED;
    int fd, rc=m11_anchor_lend_begin(a,&fd);
    if (rc) return rc;
    pid_t pid=fork();
    if (pid<0) { rc=-errno; (void)m11_anchor_lend_abort(a); return rc; }
    if (!pid) {
        /* Worker: accept (validates, drops the guard copy), lose the right to open, work. */
        if (m11_anchor_worker_accept(a,fd)) _exit(90);
        if (geteuid()==0 && drop_privileges()) _exit(91);
        _exit(work(fd,arg) ? 92 : 0);
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
