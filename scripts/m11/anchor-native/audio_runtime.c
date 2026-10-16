/* Native anchor integration of runtime/audio_runtime.c (which stays byte-identical: frozen
 * manifests pin it). Census: PID1 holds the endpoint only as the anchor pair; the pre-bind
 * spawner is the one admitted non-helper. Admission checks the sealed anchor. */
#define _GNU_SOURCE
#include "audio_runtime_internal.h"
#include "anchor_native.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <linux/magic.h>
#include <linux/qrtr.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MAX_PROCESSES 512u
#define MAX_FDS 1024u
struct helper { pid_t pid; unsigned long long start; dev_t dev; ino_t ino; };
struct m11_audio_runtime {
    struct m11_audio_status status;
    pid_t parent;
    dev_t device;
    int lease, qrtr, down[2], down_latched;
    uint64_t last_pump;
    struct helper helpers[2];
    m11_pid1_anchor *anchor;          /* sealed PID1 anchor (NULL before the bind) */
    pid_t spawner; unsigned long long spawner_start;
    /* R2: msm_audio_ion (PID1's ION anchor) and msm_audio_ion_cma (never opened, no node). */
    dev_t ion, ion_cma;
    m11_pid1_anchor *ion_anchor;
};
static struct m11_audio_runtime runtime;
static int attempted; /* Never reset, even after a failed acquire. */
static const char *const helper_path[]={"/sbin/m11-pd-mapper","/sbin/m11-kmsg-relay"};
static int ns(uint64_t *v) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC,&t)) return -1;
    *v=(uint64_t)t.tv_sec*1000000000u+(uint64_t)t.tv_nsec; return 0;
}
static int valid(const struct m11_audio_runtime *r) {
    return r==&runtime && r->status.acquired && r->parent==getpid();
}
static int text(const char *path, char *b, size_t cap) {
    int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if (fd<0) return -1;
    ssize_t n=read(fd,b,cap-1); int e=close(fd);
    if (n<=0 || n==(ssize_t)cap-1 || e) return -1;
    b[n]=0; return 0;
}
struct process { pid_t ppid; unsigned long flags; unsigned long long start; char state; };
static int process(pid_t pid, struct process *p) {
    char path[80], b[4096]; snprintf(path,sizeof(path),"/proc/%ld/stat",(long)pid);
    if (text(path,b,sizeof(b))) return -1;
    char *c=strrchr(b,')'); if (!c || c[1]!=' ') return -1;
    c+=2; char *save=0, *s=strtok_r(c," ",&save);
    memset(p,0,sizeof(*p));
    for (unsigned field=3;field<=22;field++,s=strtok_r(0," ",&save)) {
        if (!s) return -1;
        if (field==3) p->state=s[0];
        if (field==4) p->ppid=(pid_t)strtol(s,0,10);
        if (field==9) p->flags=strtoul(s,0,10);
        if (field==22) p->start=strtoull(s,0,10);
    }
    return 0; /* Early PID1/kthreadd may legitimately start at jiffy0. */
}
static int numeric(const char *s) {
    if (!*s) return 0;
    for (;*s;s++) if (*s<'0' || *s>'9') return 0;
    return 1;
}
static int single_thread(pid_t pid) {
    char path[80]; snprintf(path,sizeof(path),"/proc/%ld/task",(long)pid);
    DIR *d=opendir(path); if (!d) return 0;
    unsigned count=0; struct dirent *e;
    errno=0;
    while ((e=readdir(d))) if (numeric(e->d_name)) count++;
    int error=errno; closedir(d); return !error && count==1;
}
static int no_device_fds(pid_t pid, dev_t device) {
    char path[80], item[384]; snprintf(path,sizeof(path),"/proc/%ld/fd",(long)pid);
    DIR *d=opendir(path); if (!d) return 0;
    unsigned count=0; int ok=1; struct dirent *e;
    for (;;) {
        errno=0; e=readdir(d); if (!e) { if (errno) ok=0; break; }
        if (!numeric(e->d_name)) continue;
        if (++count>MAX_FDS) { ok=0; break; }
        snprintf(item,sizeof(item),"%s/%s",path,e->d_name);
        struct stat st;
        /* A racing helper fd close is inconclusive; reject instead of skipping. */
        if (stat(item,&st) || (S_ISCHR(st.st_mode) && st.st_rdev==device)) { ok=0; break; }
    }
    closedir(d); return ok;
}
/* R2: no endpoint, ION or ION-CMA descriptor (the ION devices once bound). */
static int no_audio_fds(const struct m11_audio_runtime *r, pid_t pid) {
    return no_device_fds(pid,r->device) && (!r->ion || no_device_fds(pid,r->ion)) &&
        (!r->ion_cma || no_device_fds(pid,r->ion_cma));
}
static int sandbox_status(const char *b) {
    /* Exact uid/gid and no ambient/permitted/effective/bounding privilege. */
    const char *required[]={"\nUid:\t65534\t65534\t65534\t65534\n",
        "\nGid:\t65534\t65534\t65534\t65534\n", "\nNoNewPrivs:\t1\n",
        "\nCapInh:\t0000000000000000\n", "\nCapPrm:\t0000000000000000\n",
        "\nCapEff:\t0000000000000000\n", "\nCapBnd:\t0000000000000000\n",
        "\nCapAmb:\t0000000000000000\n"};
    for (unsigned i=0;i<sizeof(required)/sizeof(*required);i++) if (!strstr(b,required[i])) return 0;
    const char *g=strstr(b,"\nGroups:"); if (!g) return 0;
    for (g+=8;*g && *g!='\n';g++) if (*g!=' ' && *g!='\t') return 0;
    return *g=='\n';
}
static int sandboxed(pid_t pid) {
    char path[80], b[8192]; snprintf(path,sizeof(path),"/proc/%ld/status",(long)pid);
    return !text(path,b,sizeof(b)) && sandbox_status(b);
}
static int helper_ok(struct m11_audio_runtime *r, unsigned role) {
    struct helper *h=&r->helpers[role]; struct process p; struct stat a,b;
    char path[80]; snprintf(path,sizeof(path),"/proc/%ld/exe",(long)h->pid);
    return h->pid>1 && !process(h->pid,&p) && p.ppid==r->parent && p.start==h->start &&
        p.state!='Z' && p.state!='X' && !stat(path,&a) && !lstat(helper_path[role],&b) &&
        S_ISREG(b.st_mode) && b.st_uid==0 && !(b.st_mode&022) &&
        a.st_dev==h->dev && a.st_ino==h->ino && b.st_dev==h->dev && b.st_ino==h->ino &&
        sandboxed(h->pid) && single_thread(h->pid) && no_audio_fds(r,h->pid);
}
static int initial_pid_status(const char *b) {
    /* ACK omits NSpid AND both pid namespace entries with CONFIG_PID_NS=n.
     * Missing status alone is not permission to admit a container/partial view.
     * census() independently requires real procfs and PID2 PF_KTHREAD/ppid0. */
    const char *line=b, *found=NULL;
    while (*line) {
        const char *end=strchr(line,'\n');
        if (!end) return 0;
        if (!strncmp(line,"NSpid:",6)) {
            if (found || (size_t)(end-line)!=8 || memcmp(line,"NSpid:\t1",8)) return 0;
            found=line;
        }
        line=end+1;
    }
    if (found) return 1;
    struct stat st;
    if (lstat("/proc/1/ns",&st) || !S_ISDIR(st.st_mode)) return 0;
    const char *paths[]={"/proc/1/ns/pid","/proc/1/ns/pid_for_children"};
    for (unsigned i=0;i<sizeof(paths)/sizeof(*paths);i++) {
        if (!lstat(paths[i],&st) || errno!=ENOENT) return 0;
    }
    return 1;
}
int m11_census_pid1_endpoint(const int *fds, const unsigned long long *rdevs, unsigned n,
                             unsigned long long rdev, int anchor_fd, int guard_fd) {
    bool anchor_seen=false, guard_seen=false;
    for (unsigned i=0;i<n;i++) {
        if (rdevs[i]!=rdev) continue;
        if (anchor_fd>=0 && fds[i]==anchor_fd && !anchor_seen) anchor_seen=true;
        else if (anchor_fd>=0 && fds[i]==guard_fd && !guard_seen) guard_seen=true;
        else return -1; /* any other endpoint fd in PID1: a second reference or a second OFD */
    }
    return anchor_fd<0 || (anchor_seen && guard_seen) ? 0 : -1;
}
/* PID1's character-device fds by device number, judged by the pure rule above. */
static int pid1_endpoint_fds_ok(const struct m11_audio_runtime *r) {
    int fds[MAX_FDS]; unsigned long long rdevs[MAX_FDS]; unsigned n=0;
    DIR *d=opendir("/proc/1/fd"); if (!d) return 0;
    int ok=1; struct dirent *e; char item[384];
    for (;;) {
        errno=0; e=readdir(d); if (!e) { if (errno) ok=0; break; }
        if (!numeric(e->d_name)) continue;
        if (n==MAX_FDS) { ok=0; break; }
        snprintf(item,sizeof(item),"/proc/1/fd/%s",e->d_name);
        struct stat st;
        if (stat(item,&st)) { ok=0; break; } /* a racing close is inconclusive: reject */
        if (!S_ISCHR(st.st_mode)) continue;
        fds[n]=(int)strtol(e->d_name,0,10); rdevs[n]=(unsigned long long)st.st_rdev; n++;
    }
    closedir(d);
    if (!ok || !r->device) return ok && !r->device;
    const m11_pid1_anchor *a=r->anchor, *i=r->ion_anchor;
    if (m11_census_pid1_endpoint(fds,rdevs,n,(unsigned long long)r->device,
                                 a ? a->anchor_fd : -1, a ? a->guard_fd : -1)) return 0;
    /* R2: the same rule for the ION device (exactly the ION anchor pair once attached, none
     * before) and for its CMA twin (never any). */
    if (r->ion && m11_census_pid1_endpoint(fds,rdevs,n,(unsigned long long)r->ion,
                                           i ? i->anchor_fd : -1, i ? i->guard_fd : -1)) return 0;
    if (r->ion_cma && m11_census_pid1_endpoint(fds,rdevs,n,(unsigned long long)r->ion_cma,-1,-1)) return 0;
    return 1;
}
/* The spawner: PID1's direct child, unchanged since attach, one thread, no endpoint fd. */
static int spawner_ok(const struct m11_audio_runtime *r) {
    struct process p;
    return r->spawner>1 && !process(r->spawner,&p) && p.ppid==r->parent && p.start==r->spawner_start &&
        p.state!='Z' && p.state!='X' && single_thread(r->spawner) && no_audio_fds(r,r->spawner);
}
static int census(struct m11_audio_runtime *r, int initial) {
    if (getpid()!=1 || geteuid()!=0 || !single_thread(1) || !pid1_endpoint_fds_ok(r)) return -1;
    /* Bootstrap must repair closed stdio first (Run2's proven failure class). */
    for (int fd=0;fd<3;fd++) if (fcntl(fd,F_GETFD)<0) return -1;
    char b[8192]; if (text("/proc/1/status",b,sizeof(b)) || !initial_pid_status(b)) return -1;
    struct statfs fs; if (statfs("/proc",&fs) || fs.f_type!=PROC_SUPER_MAGIC) return -1;
    /* NSpid1 alone also matches a container PID1. Require the initial namespace
     * kthreadd at PID2; no user process name/empty cmdline substitutes for it. */
    struct process kthreadd;
    if (process(2,&kthreadd) || !(kthreadd.flags&0x00200000u) || kthreadd.ppid) return -1;
    DIR *d=opendir("/proc"); if (!d) return -1;
    unsigned count=0; int rc=0; struct dirent *e;
    for (;;) {
        errno=0; e=readdir(d); if (!e) { if (errno) rc=-1; break; }
        if (!numeric(e->d_name)) continue;
        if (++count>MAX_PROCESSES) { rc=-1; break; }
        pid_t pid=(pid_t)strtol(e->d_name,0,10); if (pid==1) continue;
        struct process p; if (process(pid,&p)) { rc=-1; break; }
        if (p.flags&0x00200000u) continue; /* PF_KTHREAD, not empty cmdline. */
        int known=0;
        if (!initial) for (unsigned i=0;i<2;i++) if (r->helpers[i].pid==pid && helper_ok(r,i)) known=1;
        if (!initial && r->spawner && pid==r->spawner && spawner_ok(r)) known=1;
        if (!known) { rc=-1; break; }
    }
    closedir(d);
    if (!initial) for (unsigned i=0;i<2;i++) if (r->helpers[i].pid && !helper_ok(r,i)) rc=-1;
    return rc;
}
static void invalidate(struct m11_audio_runtime *r, enum m11_pd_fault why) {
    m11_pd_fail(&r->status.pd,why); r->status.poisoned=1;
    if (!r->down_latched) {
        r->down_latched=1;
        /* Closing the only writer latches HUP; no buffer space or consumption
         * needed. Worker closes its inherited writer before doing any I/O. */
        if (r->down[1]>=0) { close(r->down[1]); r->down[1]=-1; }
    }
}
static struct m11_audio_runtime *acquire(dev_t device) {
    if (attempted) return 0;
    attempted=1;
    memset(&runtime,0,sizeof(runtime)); runtime.parent=getpid(); runtime.device=device;
    runtime.lease=runtime.qrtr=runtime.down[0]=runtime.down[1]=-1;
    if (census(&runtime,1)) return 0;
    struct statfs fs; struct stat st;
    int directory=open("/run",O_DIRECTORY|O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if (directory<0) return 0;
    int ok=!fstatfs(directory,&fs) && fs.f_type==TMPFS_MAGIC && !fstat(directory,&st) &&
        st.st_uid==0 && !(st.st_mode&022);
    if (ok) runtime.lease=openat(directory,"m11-audio-owner.lock",O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    close(directory);
    if (runtime.lease<0) return 0;
    /* Marker lifetime is the boot, not this process's successful close. */
    if (flock(runtime.lease,LOCK_EX|LOCK_NB) || pipe2(runtime.down,O_NONBLOCK|O_CLOEXEC)) return 0;
    runtime.status.acquired=1; runtime.status.resources_quiescent=1;
    runtime.status.owner_pid=runtime.parent; runtime.status.endpoint_device=(uint64_t)device;
    return &runtime;
}
struct m11_audio_runtime *m11_audio_acquire(dev_t device) {
    if (!device) { attempted=1; return 0; }
    return acquire(device);
}
struct m11_audio_runtime *m11_audio_acquire_boot(void) { return acquire(0); }
int m11_audio_bind_endpoint(struct m11_audio_runtime *r, dev_t device) {
    if (!valid(r) || r->device || r->status.retired || !device || !major(device) || minor(device) ||
        r->status.pd_started || r->status.admitted || r->status.poisoned) return -1;
    char path[128], b[4096]; struct stat st; struct statfs fs;
    snprintf(path,sizeof(path),"/sys/dev/char/%u:%u/uevent",major(device),minor(device));
    if (statfs("/sys",&fs) || fs.f_type!=SYSFS_MAGIC || text(path,b,sizeof(b)) ||
        !strstr(b,"DEVNAME=aud_pasthru_adsp\n") ||
        lstat("/dev/aud_pasthru_adsp",&st) || !S_ISCHR(st.st_mode) || st.st_rdev!=device ||
        st.st_uid || st.st_gid || (st.st_mode&0777)!=0600 || st.st_nlink!=1) {
        invalidate(r,M11_PD_IO); return -1;
    }
    r->device=device; r->status.endpoint_device=(uint64_t)device;
    if (census(r,0)) { invalidate(r,M11_PD_IO); return -1; }
    return 0;
}
/* R2: like the endpoint bind, for /dev/msm_audio_ion (made by PID1, root 0600, one link); the CMA
 * twin is identified through sysfs only and must have no node at all. After the endpoint bind and
 * before PDR start; both device numbers then enter every census. */
static int sysfs_devname(dev_t device, const char *line) {
    char path[128], b[4096];
    snprintf(path,sizeof(path),"/sys/dev/char/%u:%u/uevent",major(device),minor(device));
    return !text(path,b,sizeof(b)) && strstr(b,line);
}
int m11_audio_bind_ion(struct m11_audio_runtime *r, dev_t ion, dev_t ion_cma) {
    if (!valid(r) || !r->device || r->ion || r->status.retired || !ion || !ion_cma || ion==ion_cma ||
        ion==r->device || ion_cma==r->device || r->status.pd_started || r->status.admitted ||
        r->status.poisoned || r->anchor) return -1;
    struct stat st; struct statfs fs;
    if (statfs("/sys",&fs) || fs.f_type!=SYSFS_MAGIC ||
        !sysfs_devname(ion,"DEVNAME=msm_audio_ion\n") || !sysfs_devname(ion_cma,"DEVNAME=msm_audio_ion_cma\n") ||
        lstat("/dev/msm_audio_ion",&st) || !S_ISCHR(st.st_mode) || st.st_rdev!=ion ||
        st.st_uid || st.st_gid || (st.st_mode&0777)!=0600 || st.st_nlink!=1 ||
        !lstat("/dev/msm_audio_ion_cma",&st) || errno!=ENOENT) {
        invalidate(r,M11_PD_IO); return -1;
    }
    r->ion=ion; r->ion_cma=ion_cma;
    if (census(r,0)) { invalidate(r,M11_PD_IO); return -1; }
    return 0;
}
int m11_audio_enroll(struct m11_audio_runtime *r, pid_t pid, enum m11_audio_helper role) {
    if (!valid(r) || r->status.pd_started || r->status.poisoned || role>M11_AUDIO_LOGGER ||
        (int)role<0 || pid<=1 || r->helpers[role].pid) return -1;
    struct process p; struct stat st; char path[80];
    snprintf(path,sizeof(path),"/proc/%ld/exe",(long)pid);
    if (process(pid,&p) || stat(path,&st)) return -1;
    struct helper *h=&r->helpers[role]; h->pid=pid; h->start=p.start; h->dev=st.st_dev; h->ino=st.st_ino;
    if (!helper_ok(r,(unsigned)role)) { memset(h,0,sizeof(*h)); invalidate(r,M11_PD_IO); return -1; }
    r->status.helper_pid[role]=pid; r->status.helper_start[role]=h->start;
    r->status.helper_inode[role]=(uint64_t)h->ino; r->status.helper_device[role]=(uint64_t)h->dev;
    return 0;
}
static int drop_privileges(void) {
    if (prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0) || prctl(PR_SET_KEEPCAPS,0,0,0,0) ||
        prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_CLEAR_ALL,0,0,0)) return -1;
    for (int cap=0;cap<64;cap++) {
        int present=prctl(PR_CAPBSET_READ,cap,0,0,0);
        if (present<0) { if (errno==EINVAL) break; return -1; }
        if (prctl(PR_CAPBSET_DROP,cap,0,0,0)) return -1;
    }
    return setgroups(0,0) || setresgid(65534,65534,65534) || setresuid(65534,65534,65534)?-1:0;
}
static int close_helper_fds(int image, int error_fd) {
    DIR *d=opendir("/proc/self/fd"); if (!d) return -1;
    int own=dirfd(d), rc=0; unsigned count=0; struct dirent *e;
    for (;;) {
        errno=0; e=readdir(d); if (!e) { if (errno) rc=-1; break; }
        if (!numeric(e->d_name)) continue;
        if (++count>MAX_FDS) { rc=-1; break; }
        int fd=(int)strtol(e->d_name,0,10);
        if (fd>2 && fd!=own && fd!=image && fd!=error_fd && close(fd)) { rc=-1; break; }
    }
    closedir(d); return rc;
}
pid_t m11_audio_spawn_helper(struct m11_audio_runtime *r, enum m11_audio_helper role, int log_fd) {
    if (!valid(r) || r->status.pd_started || r->status.poisoned || (int)role<0 || role>M11_AUDIO_LOGGER ||
        r->helpers[role].pid || census(r,0)) return -1;
    struct stat st; struct statfs fs;
    int flags=fcntl(log_fd,F_GETFL);
    if (flags<0 || (flags&O_ACCMODE)==O_RDONLY || fstat(log_fd,&st) || !S_ISREG(st.st_mode) ||
        fstatfs(log_fd,&fs) || fs.f_type!=TMPFS_MAGIC) return -1;
    int image=open(helper_path[role],O_RDONLY|O_CLOEXEC|O_NOFOLLOW), ep[2]={-1,-1};
    unsigned char magic[4];
    if (image<0 || fstat(image,&st) || !S_ISREG(st.st_mode) || st.st_uid || (st.st_mode&022) ||
        !(st.st_mode&0111) || pread(image,magic,4,0)!=4 || memcmp(magic,"\177ELF",4) || pipe2(ep,O_CLOEXEC|O_NONBLOCK)) {
        if (image>=0) close(image);
        invalidate(r,M11_PD_IO); return -1;
    }
    /* Duplicate above stdio so redirection cannot overwrite our own inputs. */
    int exe=fcntl(image,F_DUPFD_CLOEXEC,3), log=fcntl(log_fd,F_DUPFD_CLOEXEC,3);
    close(image);
    if (exe<0 || log<0) {
        if (exe>=0) close(exe);
        if (log>=0) close(log);
        close(ep[0]); close(ep[1]); invalidate(r,M11_PD_IO); return -1;
    }
    pid_t pid=fork();
    if (!pid) {
        close(ep[0]);
        int nullfd=open("/dev/null",O_RDONLY|O_NOFOLLOW);
        int failed=nullfd<0 || dup2(nullfd,0)<0 || dup2(log,1)<0 || dup2(log,2)<0;
        if (!failed) failed=close_helper_fds(exe,ep[1]) || drop_privileges();
        if (!failed) {
            char *const mapper[]={ (char *)helper_path[role],"--serve",0 };
            char *const logger[]={ (char *)helper_path[role],0 };
            char *const env[]={0};
            fexecve(exe,role==M11_AUDIO_LOCATOR?mapper:logger,env);
        }
        unsigned char failure=1;
        /* Best effort: the child must fail even if its error pipe is full. */
        ssize_t reported=write(ep[1],&failure,1);
        (void)reported;
        _exit(127);
    }
    close(ep[1]); close(exe); close(log);
    if (pid<0) { close(ep[0]); invalidate(r,M11_PD_IO); return -1; }
    uint64_t now, until=0; int success=0;
    if (!ns(&now)) until=now+500000000ULL;
    while (until && !ns(&now) && now<until) {
        unsigned char error; ssize_t got=read(ep[0],&error,1);
        if (!got) { success=1; break; }
        if (got>0 || (got<0 && errno!=EAGAIN && errno!=EINTR)) break;
        struct pollfd p={ep[0],POLLIN,0}; (void)poll(&p,1,5);
    }
    close(ep[0]);
    if (success && !m11_audio_enroll(r,pid,role)) return pid;
    invalidate(r,M11_PD_IO); (void)kill(pid,SIGKILL);
    until=0; if (!ns(&now)) until=now+100000000ULL;
    for (;;) {
        int status; pid_t got=waitpid(pid,&status,WNOHANG);
        if (got==pid) break;
        if (got<0 || !until || ns(&now) || now>=until) { r->status.unresolved_worker=pid; break; }
        (void)poll(0,0,1);
    }
    return -1;
}
static int send_qrtr(void *ctx, uint32_t node, uint32_t port, const void *b, size_t n) {
    struct m11_audio_runtime *r=ctx;
    struct sockaddr_qrtr a={.sq_family=AF_QIPCRTR,.sq_node=node,.sq_port=port};
    /* qrtr_sendmsg refuses every flag but MSG_DONTWAIT with -EINVAL (pinned ACK
     * net/qrtr/af_qrtr.c:893; same check in the shipped qrtr.ko). The frozen runtime also
     * passed MSG_NOSIGNAL, so no PDR packet could ever be sent (Run22 pre-hardware audit). */
    ssize_t sent=sendto(r->qrtr,b,n,MSG_DONTWAIT,(struct sockaddr *)&a,sizeof(a));
    return sent==(ssize_t)n?0:sent<0?-errno:-EMSGSIZE;
}
static int pump(struct m11_audio_runtime *r, int cleanup) {
    uint64_t now;
    if (ns(&now)) { invalidate(r,M11_PD_CLOCK); return -1; }
    /* A paused/dead monitor cannot silently renew its previous UP observation. */
    if (!cleanup && r->last_pump && (now<r->last_pump || now-r->last_pump>250000000ULL))
        invalidate(r,M11_PD_DEADLINE);
    r->last_pump=now;
    (void)m11_pd_tick(&r->status.pd,now);
    for (unsigned i=0;i<16;i++) {
        unsigned char b[M11_PD_WIRE_MAX]; struct sockaddr_qrtr a;
        socklen_t len=sizeof(a); memset(&a,0,sizeof(a));
        ssize_t n=recvfrom(r->qrtr,b,sizeof(b),MSG_DONTWAIT|MSG_TRUNC,(struct sockaddr *)&a,&len);
        if (n<0 && errno==EAGAIN) {
            if (r->status.pd.invalid) invalidate(r,r->status.pd.fault);
            return r->status.pd.invalid?-1:0;
        }
        if (n<=0 || n>(ssize_t)sizeof(b) || len!=sizeof(a) || a.sq_family!=AF_QIPCRTR || ns(&now)) {
            invalidate(r,M11_PD_IO); return -1;
        }
        if (m11_pd_receive(&r->status.pd,a.sq_node,a.sq_port,b,(size_t)n,now)) {
            invalidate(r,r->status.pd.fault); return -1;
        }
    }
    invalidate(r,M11_PD_OVERFLOW); return -1; /* Flood cannot keep UP indefinitely. */
}
int m11_audio_start_pd(struct m11_audio_runtime *r, unsigned int budget_ms) {
    if (!valid(r) || r->status.pd_started || r->status.poisoned || !budget_ms || budget_ms>5000 ||
        !r->helpers[M11_AUDIO_LOCATOR].pid || census(r,0)) return -1;
    r->status.pd_started=1;
    r->qrtr=socket(AF_QIPCRTR,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);
    /* qrtr_bind() refuses any sq_node other than the socket's own node (pinned ACK
     * net/qrtr/af_qrtr.c:816; qrtr_create sets it to qrtr_local_nid, :1261). Run21 bound node 0
     * and got -EINVAL: read the own address first, then bind port 0 (assigned) on that node. */
    struct sockaddr_qrtr a; socklen_t len=sizeof(a); uint64_t now=0; memset(&a,0,sizeof(a));
    int ok=r->qrtr>=0 && !getsockname(r->qrtr,(struct sockaddr *)&a,&len) && len==sizeof(a) &&
        a.sq_family==AF_QIPCRTR;
    if (ok) {
        a.sq_port=0; len=sizeof(a);
        ok=!bind(r->qrtr,(struct sockaddr *)&a,sizeof(a)) &&
           !getsockname(r->qrtr,(struct sockaddr *)&a,&len) && len==sizeof(a) &&
           a.sq_family==AF_QIPCRTR && a.sq_port && !ns(&now);
    }
    if (!ok) { invalidate(r,M11_PD_IO); return -1; }
    uint64_t until=now+(uint64_t)budget_ms*1000000u;
    /* Includes startup + maximum4s query + cleanup headroom; fixed one-shot. */
    if (m11_pd_begin(&r->status.pd,a.sq_node,a.sq_port,now,now+10000000000ULL,send_qrtr,r)) {
        invalidate(r,r->status.pd.fault); return -1;
    }
    while (!m11_audio_pump(r)) {
        if (ns(&now) || now>=until) break;
        if (r->status.pd.phase==M11_PD_READY) return 0;
        struct pollfd p={r->qrtr,POLLIN,0};
        if (poll(&p,1,10)<0 && errno!=EINTR) break;
    }
    invalidate(r,r->status.pd.invalid?r->status.pd.fault:M11_PD_DEADLINE); return -1;
}
int m11_audio_pump(struct m11_audio_runtime *r) {
    if (!valid(r) || !r->status.pd_started || r->status.retired || r->qrtr<0) return -1;
    for (unsigned i=0;i<2;i++) if (r->helpers[i].pid) {
        struct process p;
        if (process(r->helpers[i].pid,&p) || p.start!=r->helpers[i].start || p.ppid!=r->parent || p.state=='Z' || p.state=='X') {
            invalidate(r,M11_PD_IO); return -1;
        }
    }
    return pump(r,0);
}
int m11_audio_admit(struct m11_gpr_session *s) {
    struct m11_audio_runtime *r=s?s->runtime:0;
    if (!valid(r) || !r->device || r->status.admitted || r->status.retired || r->status.poisoned ||
        s->consumed || s->expected_device!=r->device) return -1;
    r->status.admitted=1; /* failed admission also consumes this boot's attempt */
    memcpy(r->status.capture_nonce,s->capture_nonce,16); memcpy(r->status.image_sha256,s->image_sha256,32);
    r->status.token=s->token;
    if (census(r,0) || m11_audio_pump(r) || r->status.pd.phase!=M11_PD_READY) {
        invalidate(r,M11_PD_IO); return -1;
    }
    if (ns(&r->status.census_ns)) { invalidate(r,M11_PD_CLOCK); return -1; }
    /* The seal unlinked the node: admission rests on the sealed anchor, whose census (by device
     * number, with kcmp) refuses any other holder or OFD of the endpoint. */
    if (!r->anchor || !r->anchor->ops.close_pair || m11_anchor_check(r->anchor) ||
        r->anchor->id.rdev!=(uint64_t)r->device) {
        invalidate(r,M11_PD_IO); return -1;
    }
    /* R2: a bound ION device is admitted only as PID1's sealed ION anchor (no other holder). */
    if (r->ion && (!r->ion_anchor || !r->ion_anchor->ops.close_pair || m11_anchor_check(r->ion_anchor) ||
                   r->ion_anchor->id.rdev!=(uint64_t)r->ion)) {
        invalidate(r,M11_PD_IO); return -1;
    }
    s->exclusive_native_owner=1; s->service_down_fd=r->down[0];
    r->status.resources_quiescent=0; r->status.pd.resources_busy=1;
    return 0;
}
int m11_audio_control(struct m11_gpr_session const *s) {
    struct m11_audio_runtime *r=s->runtime;
    if (!r) return 0; /* only internal injected supervisor tests use no runtime */
    if (r!=&runtime || !r->status.acquired) return -1;
    if (getpid()!=r->parent) return 0; /* child observes latched pipe only */
    if (m11_audio_pump(r)) return 1;
    if (r->status.pd.phase!=M11_PD_READY) { invalidate(r,M11_PD_NOT_UP); return 1; }
    return 0;
}
void m11_audio_child_detach(struct m11_gpr_session const *s) {
    struct m11_audio_runtime *r=s->runtime;
    if (!r || r!=&runtime || getpid()==r->parent) return;
    if (r->qrtr>=0) { close(r->qrtr); r->qrtr=-1; }
    if (r->down[1]>=0) { close(r->down[1]); r->down[1]=-1; }
    /* Keep lease fd until exit: parent close cannot unlock a surviving worker. */
}
void m11_audio_finish(struct m11_gpr_session *s, const struct m11_gpr_result *out) {
    struct m11_audio_runtime *r=s->runtime;
    if (!valid(r) || !r->status.admitted) return;
    r->status.finished=1; r->status.unresolved_worker=out->unresolved_worker;
    /* An unreaped worker may still hold a reference: never quiescent. With the sealed PID1
     * anchor, a reaped borrower's exit (any code, any signal, before or after its I/O) is a
     * non-final close: PID1 still holds the OFD and releases it once, at final close, after
     * its own census. The query outcome stays failed (RED); the resources are quiescent.
     * Without an anchor the original explicit-close proof is still required. */
    bool anchored=r->anchor && r->anchor->ops.close_pair;
    if (!out->worker_reaped || out->unresolved_worker) { invalidate(r,M11_PD_UNRESOLVED); return; }
    if (!anchored && (!out->worker_exit_ok || !out->close_returned || !out->close_ok || !out->ipc_complete)) {
        invalidate(r,M11_PD_UNRESOLVED); return;
    }
    r->status.resources_quiescent=1;
    if (m11_pd_resources_released(&r->status.pd)) invalidate(r,r->status.pd.fault);
}
int m11_audio_retire(struct m11_audio_runtime *r) {
    if (!valid(r) || r->status.retired || !r->status.resources_quiescent || r->status.unresolved_worker) return -1;
    r->status.retired=1;
    /* Revoke permission first, even if unregister subsequently fails. */
    if (r->down[1]>=0) { close(r->down[1]); r->down[1]=-1; }
    r->down_latched=1;
    /* Nothing ever reached the name service or the PD (PDR never started, no socket, or no
     * packet accepted): nothing to unregister. Close the socket only. This also covers
     * m11_pd_begin never having run, where m11_pd_stop would call the NULL send hook (Run21:
     * PID1 SIGSEGV at address 0). */
    int sent_any=0;
    for (unsigned i=0;i<r->status.pd.count;i++)
        if (r->status.pd.records[i].tx && r->status.pd.records[i].rc==0) sent_any=1;
    if (!r->status.pd_started || r->qrtr<0 || !r->status.pd.send || !sent_any) {
        int cr=r->qrtr>=0 ? close(r->qrtr) : 0; r->qrtr=-1;
        r->status.notifier_cleanup_complete=cr==0;
        return cr==0?0:-1;
    }
    uint64_t now; if (ns(&now)) return -1; uint64_t until=now+2000000000ULL;
    int rc=-1;
    while (!ns(&now) && now<until) {
        int step=m11_pd_stop(&r->status.pd,now,until);
        if (step<=0) { rc=step; break; }
        (void)pump(r,1);
        struct pollfd p={r->qrtr,POLLIN,0};
        if (poll(&p,1,10)<0 && errno!=EINTR) break;
    }
    int cr=close(r->qrtr); r->qrtr=-1;
    r->status.notifier_cleanup_complete=rc==0 && cr==0 && r->status.pd.lookup_removed;
    if (!r->status.notifier_cleanup_complete) r->status.poisoned=1;
    /* Retain lease marker and descriptor until native boot ends. */
    return r->status.notifier_cleanup_complete?0:-1;
}
int m11_audio_attach_spawner(struct m11_audio_runtime *r, pid_t spawner) {
    struct process p;
    if (!valid(r) || r->spawner || r->device || r->status.pd_started || spawner<=1 ||
        process(spawner,&p) || p.ppid!=r->parent) return -1;
    r->spawner=spawner; r->spawner_start=p.start;
    if (!spawner_ok(r)) { r->spawner=0; invalidate(r,M11_PD_IO); return -1; }
    return 0;
}
int m11_audio_attach_anchors(struct m11_audio_runtime *r, m11_pid1_anchor *a, m11_pid1_anchor *ion) {
    /* After a qualified PDR UP and before admission: the anchor replaces the worker's open. With
     * a bound ION device both sealed anchors are attached together (each census needs both). */
    if (!valid(r) || r->anchor || !r->device || !r->status.pd_started || r->status.admitted ||
        r->status.retired || r->status.poisoned || !a || a->state!=M11_ANCHOR_HELD ||
        !a->ops.close_pair || a->id.rdev!=(uint64_t)r->device) return -1;
    if (!r->ion != !ion) return -1;
    if (ion && (ion==a || ion->state!=M11_ANCHOR_HELD || !ion->ops.close_pair ||
                ion->id.rdev!=(uint64_t)r->ion)) return -1;
    r->anchor=a; r->ion_anchor=ion;
    if (census(r,0)) { invalidate(r,M11_PD_IO); return -1; }
    return 0;
}
int m11_audio_attach_anchor(struct m11_audio_runtime *r, m11_pid1_anchor *a) {
    return m11_audio_attach_anchors(r,a,NULL);
}
int m11_audio_snapshot(const struct m11_audio_runtime *r, struct m11_audio_status *out) {
    if (!valid(r) || !out) return -1;
    *out=r->status; out->pd.context=0; out->pd.send=0; return 0;
}
