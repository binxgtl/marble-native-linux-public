#define _GNU_SOURCE
#include "anchor_kernel_model.h"
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>

static km_proc *proc_at(km_kernel *k, int i) {
    return i>=0 && i<KM_PROCS && k->procs[i].alive ? &k->procs[i] : NULL;
}
static int new_file(km_kernel *k, bool endpoint, int opener) {
    for (int i=0;i<KM_FILES;i++) if (!k->files[i].used) {
        k->files[i]=(km_file){.used=true,.endpoint=endpoint,.refs=1,
                              .status_flags=O_RDWR|O_NONBLOCK,.opener_pid=opener};
        return i;
    }
    return -1;
}
static void fput(km_kernel *k, int f) {
    km_file *file=&k->files[f];
    if (!file->refs || file->released) return;
    if (--file->refs) return;
    file->released=true;
    if (file->endpoint) { k->endpoint_releases++; k->last_released_file=f; }
}
static void filp_close(km_kernel *k, int f) {
    if (k->files[f].endpoint && k->endpoint_has_flush) k->endpoint_flushes++;
    fput(k,f);
}
static int lowest_free(const km_proc *p, int min) {
    for (int fd=min<0?0:min; fd<KM_FDS; fd++) if (!p->fd[fd]) return fd;
    return -EMFILE;
}
void km_init(km_kernel *k, bool flush) {
    memset(k,0,sizeof(*k));
    k->endpoint_has_flush=flush; k->last_released_file=-1; k->next_pid=2;
    km_proc *init=&k->procs[0];
    init->alive=true; init->privileged=true; init->pid=1;
    int console=new_file(k,false,1);
    for (int fd=0;fd<3;fd++) { init->fd[fd]=(short)(console+1); if (fd) k->files[console].refs++; }
}
int km_fork(km_kernel *k, int parent) {
    km_proc *p=proc_at(k,parent);
    if (!p || p->dstate) return -1;
    for (int i=1;i<KM_PROCS;i++) if (!k->procs[i].alive) {
        km_proc *c=&k->procs[i];
        *c=*p; c->pid=k->next_pid++; c->ppid=p->pid; c->dstate=false;
        for (int fd=0;fd<KM_FDS;fd++) if (c->fd[fd]) k->files[c->fd[fd]-1].refs++; /* dup_fd */
        return i;
    }
    return -1;
}
void km_exec(km_kernel *k, int i) {
    km_proc *p=proc_at(k,i);
    if (!p || p->dstate) return;
    for (int fd=0;fd<KM_FDS;fd++) if (p->fd[fd] && p->cloexec[fd]) {
        int f=p->fd[fd]-1; p->fd[fd]=0; p->cloexec[fd]=false; filp_close(k,f);
    }
}
void km_exit(km_kernel *k, int i) {
    km_proc *p=proc_at(k,i);
    if (!p) return;
    if (p->pid==1) { k->panicked=true; return; } /* panic before exit_files(): nothing closed */
    for (int fd=0;fd<KM_FDS;fd++) if (p->fd[fd]) {
        int f=p->fd[fd]-1; p->fd[fd]=0; p->cloexec[fd]=false; filp_close(k,f);
    }
    p->alive=false;
}
bool km_kill(km_kernel *k, int i) {
    km_proc *p=proc_at(k,i);
    if (!p || p->pid==1) return false;
    if (p->dstate) return false; /* SIGKILL cannot end an uninterruptible syscall */
    km_exit(k,i); return true;
}
int km_open(km_kernel *k, int i, bool endpoint) {
    km_proc *p=proc_at(k,i);
    if (!p) return -ESRCH;
    if (endpoint && !p->privileged) return -EACCES; /* root 0600 node, no CAP_DAC_OVERRIDE */
    int fd=lowest_free(p,3);
    if (fd<0) return fd;
    int f=new_file(k,endpoint,p->pid);
    if (f<0) return -ENFILE;
    if (endpoint) k->endpoint_opens++;
    p->fd[fd]=(short)(f+1); p->cloexec[fd]=true;
    return fd;
}
int km_close(km_kernel *k, int i, int fd) {
    km_proc *p=proc_at(k,i);
    if (!p || fd<0 || fd>=KM_FDS || !p->fd[fd]) return -EBADF;
    int f=p->fd[fd]-1; p->fd[fd]=0; p->cloexec[fd]=false; /* number consumed first */
    filp_close(k,f);
    return 0;
}
int km_dup_min(km_kernel *k, int i, int fd, int min) {
    km_proc *p=proc_at(k,i);
    if (!p || fd<0 || fd>=KM_FDS || !p->fd[fd]) return -EBADF;
    if (k->fail_dup) return -EMFILE;
    int to=lowest_free(p,min);
    if (to<0) return to;
    p->fd[to]=p->fd[fd]; p->cloexec[to]=true; k->files[p->fd[fd]-1].refs++;
    return to;
}
int km_dup2(km_kernel *k, int i, int oldfd, int newfd) {
    km_proc *p=proc_at(k,i);
    if (!p || oldfd<0 || oldfd>=KM_FDS || !p->fd[oldfd] || newfd<0 || newfd>=KM_FDS) return -EBADF;
    if (oldfd==newfd) return newfd;
    if (p->fd[newfd]) km_close(k,i,newfd);
    p->fd[newfd]=p->fd[oldfd]; p->cloexec[newfd]=false; k->files[p->fd[oldfd]-1].refs++;
    return newfd;
}
void km_set_cloexec(km_kernel *k, int i, int fd, bool on) {
    km_proc *p=proc_at(k,i);
    if (p && fd>=0 && fd<KM_FDS && p->fd[fd]) p->cloexec[fd]=on;
}
int km_file_of(const km_kernel *k, int i, int fd) {
    if (i<0 || i>=KM_PROCS || !k->procs[i].alive || fd<0 || fd>=KM_FDS) return -1;
    return k->procs[i].fd[fd]-1;
}
unsigned km_refs_of(const km_kernel *k, int f) { return f>=0 && f<KM_FILES ? k->files[f].refs : 0; }
bool km_foreign_endpoint_ofd(const km_kernel *k, int file) {
    for (int f=0;f<KM_FILES;f++)
        if (f!=file && k->files[f].used && k->files[f].endpoint && !k->files[f].released) return true;
    return false;
}

/* ------------------------------ injected adapter ops ------------------------------ */
static int ops_self(void *v) { km_kernel *k=v; return k->procs[k->current].pid; }
static int ops_open(void *v) { km_kernel *k=v; return km_open(k,k->current,true); }
static void identity(const km_kernel *k, int f, m11_anchor_id *id) {
    if (k->files[f].endpoint) *id=(m11_anchor_id){.dev=5,.ino=77,.rdev=KM_ENDPOINT_RDEV,.type=S_IFCHR};
    else *id=(m11_anchor_id){.dev=1,.ino=1000u+(unsigned)f,.rdev=0,.type=S_IFREG};
}
static int ops_identify(void *v, int fd, m11_anchor_id *id) {
    km_kernel *k=v; int f=km_file_of(k,k->current,fd);
    if (f<0) return -EBADF;
    identity(k,f,id); return 0;
}
static int ops_dup(void *v, int fd, int min) { km_kernel *k=v; return km_dup_min(k,k->current,fd,min); }
static int ops_fd_flags(void *v, int fd) {
    km_kernel *k=v; if (km_file_of(k,k->current,fd)<0) return -EBADF;
    return k->procs[k->current].cloexec[fd] ? FD_CLOEXEC : 0;
}
static int ops_status(void *v, int fd) {
    km_kernel *k=v; int f=km_file_of(k,k->current,fd);
    return f<0 ? -EBADF : k->files[f].status_flags;
}
static int ops_close(void *v, int fd) { km_kernel *k=v; return km_close(k,k->current,fd); }
static int ops_holders(void *v, const m11_anchor_id *want, m11_anchor_holder *out, unsigned cap, unsigned *n) {
    km_kernel *k=v; *n=0;
    if (k->fail_holders) return -EIO;
    for (int i=0;i<KM_PROCS;i++) {
        const km_proc *p=&k->procs[i];
        if (!p->alive) continue;
        for (int fd=0;fd<KM_FDS;fd++) {
            if (!p->fd[fd]) continue;
            m11_anchor_id id; identity(k,p->fd[fd]-1,&id);
            if (id.dev!=want->dev || id.ino!=want->ino || id.rdev!=want->rdev || id.type!=want->type) continue;
            if (*n==cap) return -E2BIG;
            out[(*n)++]=(m11_anchor_holder){p->pid,fd};
        }
    }
    return 0;
}
m11_anchor_ops km_ops(km_kernel *k) {
    return (m11_anchor_ops){k,ops_self,ops_open,ops_identify,ops_dup,ops_fd_flags,ops_status,ops_close,ops_holders};
}
