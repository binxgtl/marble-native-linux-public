/* PDR start/retire regression (Run21 hardware failure), synthetic procfs/sysfs/QRTR fixtures.
 * Build with -DRUNTIME_ORIGINAL to reproduce the Run21 crash on the frozen runtime. */
#ifdef RUNTIME_ORIGINAL
#include "../runtime/audio_runtime.c"
#else
#include "audio_runtime.c"
#endif
#include <assert.h>
#include "../runtime/gpr_native.h"
static int fail_mode, listed, dir_index[8], ready, unreg_reply;
static uint64_t fixture_now;
static char current_path[256];
static int fd_mode[3];
pid_t __wrap_getpid(void) { return 1; }
uid_t __wrap_geteuid(void) { return 0; }
int __wrap_open(const char *path, int flags, ...) {
    (void)flags;
    snprintf(current_path,sizeof(current_path),"%s",path);
    if (!strcmp(path,"/run")) return 901;
    return 900;
}
int __wrap_openat(int fd, const char *path, int flags, ...) {
    assert(fd==901 && !strcmp(path,"m11-audio-owner.lock") && (flags&O_EXCL)); return 902;
}
int __wrap_close(int fd) { (void)fd; return 0; }
ssize_t __wrap_read(int fd, void *out, size_t cap) {
    assert(fd==900); char b[4096]="";
    if (strlen(current_path)>=5 && !strcmp(current_path+strlen(current_path)-5,"/stat")) {
        int pid=atoi(current_path+6);
        unsigned flags=pid==2?0x00200000:0;
        if (fail_mode==2 && pid==2) flags=0;
        snprintf(b,sizeof(b),"%d (task with spaces) S %d 0 0 0 0 %u 0 0 0 0 0 0 0 0 0 0 0 0 123\n",pid,pid==2?0:1,flags);
    } else if (!strcmp(current_path,"/proc/1/status")) {
        strcpy(b,fail_mode==1?"Name:\tinit\nNSpid:\t1\t1\n":"Name:\tinit\nNSpid:\t1\n");
    } else if (strstr(current_path,"/status")) {
        snprintf(b,sizeof(b),"Name:\thelper\nUid:\t65534\t65534\t65534\t65534\nGid:\t65534\t65534\t65534\t65534\nGroups:\t\nNoNewPrivs:\t1\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t000000000000000%d\nCapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\n",fail_mode==5?1:0);
    } else if (strstr(current_path,"/uevent")) {
        strcpy(b,fail_mode==6?"DEVNAME=wrong\n":"MAJOR=240\nMINOR=0\nDEVNAME=aud_pasthru_adsp\n");
    } else assert(0);
    size_t n=strlen(b); assert(n<cap); memcpy(out,b,n); return (ssize_t)n;
}
int __wrap_statfs(const char *path, struct statfs *st) {
    memset(st,0,sizeof(*st)); st->f_type=!strcmp(path,"/proc")?PROC_SUPER_MAGIC:SYSFS_MAGIC; return 0;
}
int __wrap_fstatfs(int fd, struct statfs *st) { assert(fd==901); memset(st,0,sizeof(*st)); st->f_type=TMPFS_MAGIC; return 0; }
int __wrap_fstat(int fd, struct stat *st) { assert(fd==901); memset(st,0,sizeof(*st)); st->st_mode=S_IFDIR|0755; return 0; }
int __wrap_flock(int fd, int op) { assert(fd==902 && (op&LOCK_NB)); return 0; }
int __wrap_fcntl(int fd, int op, ...) {
    assert(fd>=0 && fd<3 && op==F_GETFD); return fd_mode[fd]?-1:0;
}
DIR *__wrap_opendir(const char *path) {
    unsigned id;
    if (!strcmp(path,"/proc")) id=1;
    else if (strstr(path,"/task")) id=2;
    else if (strstr(path,"/fd")) id=3;
    else { assert(0); id=0; }
    dir_index[id]=0; return (DIR *)(uintptr_t)id;
}
struct dirent *__wrap_readdir(DIR *d) {
    static struct dirent e; unsigned id=(unsigned)(uintptr_t)d; int index=dir_index[id]++;
    memset(&e,0,sizeof(e));
    if (id==2) { if (index) return NULL; strcpy(e.d_name,"1"); }
    else if (id==3) { if (index) return NULL; strcpy(e.d_name,"0"); }
    else {
        const char *names[]={"1","2","100","101","999"};
        int count=listed?4:2; if (fail_mode==3) count++;
        if (index>=count) return NULL;
        strcpy(e.d_name,index==count-1 && fail_mode==3?"999":names[index]);
    }
    return &e;
}
int __wrap_closedir(DIR *d) { (void)d; return 0; }
int __wrap_stat(const char *path, struct stat *st) {
    memset(st,0,sizeof(*st)); st->st_mode=S_IFREG|0755; st->st_dev=1; st->st_ino=strstr(path,"/101/")?101:100;
    if (strstr(path,"/fd/") && fail_mode==4) { st->st_mode=S_IFCHR|0600; st->st_rdev=makedev(240,0); }
    return 0;
}
int __wrap_lstat(const char *path, struct stat *st) {
    memset(st,0,sizeof(*st));
    if (!strcmp(path,"/dev/aud_pasthru_adsp")) {
        st->st_mode=S_IFCHR|0600; st->st_nlink=1; st->st_rdev=makedev(240,0); st->st_uid=fail_mode==7?65534:0;
    } else { st->st_mode=S_IFREG|0755; st->st_dev=1; st->st_ino=strstr(path,"kmsg")?101:100; }
    return 0;
}
int __wrap_pipe2(int fds[2], int flags) { (void)flags; fds[0]=903; fds[1]=904; return 0; }
/* QRTR socket model of pinned ACK net/qrtr/af_qrtr.c: a new socket's own address is
 * {qrtr_local_nid, port 0} (:1261-1262); bind() refuses any other node (:816) and assigns a
 * port for port 0. Never a real socket. */
#define LOCAL_NID 1u
#define ASSIGNED_PORT 0x4001u
static unsigned bound_port, bind_calls, bind_node, sends, first_cmd, first_port, force_bind_fail;
int __wrap_socket(int domain, int type, int protocol) {
    assert(domain==AF_QIPCRTR && (type&SOCK_DGRAM) && !protocol); bound_port=0; return 905;
}
int __wrap_bind(int fd, const struct sockaddr *addr, socklen_t len) {
    const struct sockaddr_qrtr *a=(const void *)addr;
    assert(fd==905 && len==sizeof(*a) && a->sq_family==AF_QIPCRTR);
    bind_calls++; bind_node=a->sq_node;
    if (force_bind_fail || a->sq_node!=LOCAL_NID) { errno=EINVAL; return -1; }
    bound_port=a->sq_port?a->sq_port:ASSIGNED_PORT; return 0;
}
int __wrap_getsockname(int fd, struct sockaddr *addr, socklen_t *len) {
    struct sockaddr_qrtr *a=(void *)addr; assert(fd==905 && *len>=sizeof(*a));
    memset(a,0,sizeof(*a)); a->sq_family=AF_QIPCRTR; a->sq_node=LOCAL_NID; a->sq_port=bound_port;
    *len=sizeof(*a); return 0;
}
ssize_t __wrap_recvfrom(int fd, void *b, size_t cap, int flags, struct sockaddr *addr, socklen_t *len) {
    (void)fd; (void)b; (void)cap; (void)flags; (void)addr; (void)len; errno=EAGAIN; return -1;
}
ssize_t __wrap_sendto(int fd, const void *b, size_t n, int flags, const struct sockaddr *addr, socklen_t len) {
    const struct sockaddr_qrtr *a=(const void *)addr; const unsigned char *p=b;
    assert(fd==905 && len==sizeof(*a) && n>=4); (void)flags;
    if (!sends++) { first_cmd=(unsigned)p[0]|(unsigned)p[1]<<8|(unsigned)p[2]<<16|(unsigned)p[3]<<24; first_port=a->sq_port; }
    return (ssize_t)n;
}
static void setup(void) {
    attempted=fail_mode=listed=ready=unreg_reply=0;
    memset(fd_mode,0,sizeof(fd_mode)); memset(&runtime,0,sizeof(runtime));
    bound_port=bind_calls=bind_node=sends=first_cmd=first_port=force_bind_fail=0;
    assert(!ns(&fixture_now));
}
static void owner(void) {
    setup(); assert(m11_audio_acquire_boot()==&runtime);
    assert(!m11_audio_enroll(&runtime,100,M11_AUDIO_LOCATOR));
    assert(!m11_audio_enroll(&runtime,101,M11_AUDIO_LOGGER)); listed=1;
    assert(!m11_audio_bind_endpoint(&runtime,makedev(240,0)));
}
int main(void) {
    setvbuf(stdout,NULL,_IONBF,0);
    owner();
    int rc=m11_audio_start_pd(&runtime,50); /* no PDR peer answers: a bounded failure */
#ifdef RUNTIME_ORIGINAL
    /* The frozen runtime binds node 0: refused, before m11_pd_begin (Run21 journal state). */
    assert(rc==-1 && bind_calls==1 && bind_node==0 && !sends);
    assert(runtime.status.pd_started && runtime.status.poisoned && runtime.status.pd.phase==M11_PD_INVALID &&
           runtime.status.pd.fault==M11_PD_IO && !runtime.status.pd.send && runtime.qrtr==905);
    puts("REPRO Run21: bind(sq_node=0) refused, pd_started=1 poisoned=1 phase=4 fault=5 send=NULL; retire next");
    (void)m11_audio_retire(&runtime); /* expected: SIGSEGV through the NULL send hook */
    puts("UNEXPECTED: retire returned");
    return 0;
#else
    /* Fixed: bind on the socket's own node; m11_pd_begin ran and sent the lookup to the
     * control port; the start still fails cleanly when no peer answers. */
    assert(rc==-1 && bind_calls==1 && bind_node==LOCAL_NID && runtime.status.pd.send &&
           runtime.status.pd.local_node==LOCAL_NID && runtime.status.pd.local_port==ASSIGNED_PORT);
    assert(sends>=1 && first_cmd==10 && first_port==QRTR_PORT_CTRL);
    assert(!m11_audio_retire(&runtime) && runtime.status.notifier_cleanup_complete && runtime.qrtr<0);
    puts("PASS PDR start binds the socket's own QRTR node and sends the locator lookup; retire after a begun start unregisters");
    /* A start that fails before m11_pd_begin leaves send NULL: retire must only close. */
    owner(); force_bind_fail=1;
    assert(m11_audio_start_pd(&runtime,50)==-1 && !runtime.status.pd.send && runtime.qrtr==905 && !sends);
    assert(!m11_audio_retire(&runtime) && runtime.status.notifier_cleanup_complete && runtime.qrtr<0 && !sends);
    puts("PASS retire after a PDR start that never began closes the socket only (no NULL send; Run21 crash fixed)");
    return 0;
#endif
}
