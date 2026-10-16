/* End-to-end PDR start -> READY -> finish -> retire over a kernel-rule QRTR model (Run22
 * pre-hardware audit F1-F3). Synthetic procfs/sysfs fixtures as test-pdr.c. No device. */
#include "audio_runtime.c"
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
/* AF_QIPCRTR model of pinned ACK net/qrtr/af_qrtr.c and net/qrtr/ns.c (b97c62c4), plus a
 * scripted name service and audio-PD servreg responder. The model refuses what the kernel
 * refuses: bind() to a node other than the socket's own (:816), any send flag but
 * MSG_DONTWAIT (:893), control packets not addressed to {own node, CTRL}, QMI packets not
 * addressed to the announced server. Never a real socket. */
#define LOCAL_NID 1u
#define ASSIGNED_PORT 0x4001u
#define SERVER_NODE 5u
#define SERVER_PORT 100u
#define CTRL_PORT 0xfffffffeu
#define SVC_INSTANCE ((M11_PD_INSTANCE << 8) | 1u)
enum { SRV_ANNOUNCE=1, SRV_REFUSE_SEND=2 };
static unsigned srv_flags, bound_port, sends_ok, sends_refused, lookups, del_lookups, registers, unregisters, acks;
struct dgram { uint32_t node, port; size_t n; unsigned char b[M11_PD_WIRE_MAX]; };
static struct dgram queue[32]; static unsigned q_head, q_tail;
static void le32(unsigned char *p, uint32_t v) { p[0]=(unsigned char)v; p[1]=(unsigned char)(v>>8); p[2]=(unsigned char)(v>>16); p[3]=(unsigned char)(v>>24); }
static void le16(unsigned char *p, uint16_t v) { p[0]=(unsigned char)v; p[1]=(unsigned char)(v>>8); }
static uint32_t rd32(const unsigned char *p) { return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24; }
static uint16_t rd16(const unsigned char *p) { return (uint16_t)(p[0]|p[1]<<8); }
static void enqueue(uint32_t node, uint32_t port, const unsigned char *b, size_t n) {
    assert(q_tail-q_head<32 && n<=M11_PD_WIRE_MAX);
    struct dgram *d=&queue[q_tail++%32]; d->node=node; d->port=port; d->n=n; memcpy(d->b,b,n);
}
static void ns_record(uint32_t cmd, uint32_t svc, uint32_t inst, uint32_t node, uint32_t port) {
    unsigned char b[20]; le32(b,cmd); le32(b+4,svc); le32(b+8,inst); le32(b+12,node); le32(b+16,port);
    enqueue(LOCAL_NID,CTRL_PORT,b,20);
}
static size_t put_tlv(unsigned char *b, size_t at, unsigned char t, const void *v, uint16_t n) {
    b[at]=t; le16(b+at+1,n); memcpy(b+at+3,v,n); return at+3+n;
}
/* QMI response: type 2, txn, msg id, length, result TLV (u16 result + u16 error = 0). */
static void qmi_response(uint16_t id, uint16_t txn, int with_state, uint32_t state) {
    unsigned char b[64]={0}, result[4]={0}, st[4]; size_t n=7;
    n=put_tlv(b,n,2,result,4);
    if (with_state) { le32(st,state); n=put_tlv(b,n,16,st,4); }
    b[0]=2; le16(b+1,txn); le16(b+3,id); le16(b+5,(uint16_t)(n-7));
    enqueue(SERVER_NODE,SERVER_PORT,b,n);
}
static void indication(uint32_t state, uint16_t txn) {
    unsigned char b[64]={0}, st[4], t[2]; size_t n=7;
    le32(st,state); le16(t,txn);
    n=put_tlv(b,n,1,st,4); n=put_tlv(b,n,2,M11_PD_PATH,(uint16_t)(sizeof(M11_PD_PATH)-1)); n=put_tlv(b,n,3,t,2);
    b[0]=4; le16(b+1,0); le16(b+3,0x22); le16(b+5,(uint16_t)(n-7));
    enqueue(SERVER_NODE,SERVER_PORT,b,n);
}
int __wrap_socket(int domain, int type, int protocol) {
    assert(domain==AF_QIPCRTR && (type&SOCK_DGRAM) && !protocol); bound_port=0; return 905;
}
int __wrap_bind(int fd, const struct sockaddr *addr, socklen_t len) {
    const struct sockaddr_qrtr *a=(const void *)addr;
    assert(fd==905 && len==sizeof(*a) && a->sq_family==AF_QIPCRTR);
    if (a->sq_node!=LOCAL_NID) { errno=EINVAL; return -1; }
    bound_port=a->sq_port?a->sq_port:ASSIGNED_PORT; return 0;
}
int __wrap_getsockname(int fd, struct sockaddr *addr, socklen_t *len) {
    struct sockaddr_qrtr *a=(void *)addr; assert(fd==905 && *len>=sizeof(*a));
    memset(a,0,sizeof(*a)); a->sq_family=AF_QIPCRTR; a->sq_node=LOCAL_NID; a->sq_port=bound_port;
    *len=sizeof(*a); return 0;
}
ssize_t __wrap_sendto(int fd, const void *buf, size_t n, int flags, const struct sockaddr *addr, socklen_t len) {
    const struct sockaddr_qrtr *a=(const void *)addr; const unsigned char *b=buf;
    if (fd!=905 || !addr || len!=sizeof(*a) || a->sq_family!=AF_QIPCRTR || !bound_port) { errno=EINVAL; return -1; }
    if (flags & ~MSG_DONTWAIT) { errno=EINVAL; return -1; } /* af_qrtr.c:893 */
    if (srv_flags & SRV_REFUSE_SEND) { sends_refused++; errno=EPERM; return -1; }
    if (a->sq_port==CTRL_PORT) {
        if (a->sq_node!=LOCAL_NID || n!=20) { errno=EINVAL; return -1; } /* ns.c: own node only */
        uint32_t cmd=rd32(b);
        assert(rd32(b+4)==0x42 && rd32(b+8)==SVC_INSTANCE);
        if (cmd==10) {
            lookups++;
            if (srv_flags & SRV_ANNOUNCE) ns_record(4,0x42,SVC_INSTANCE,SERVER_NODE,SERVER_PORT);
            ns_record(4,0,0,0,0); /* end of the lookup listing */
        } else if (cmd==11) {
            assert(rd32(b+12)==LOCAL_NID && rd32(b+16)==bound_port); del_lookups++;
        } else { errno=EINVAL; return -1; }
        sends_ok++; return (ssize_t)n;
    }
    if (a->sq_node!=SERVER_NODE || a->sq_port!=SERVER_PORT || n<7 || rd16(b+5)!=n-7 || b[0]!=0) { errno=EINVAL; return -1; }
    uint16_t txn=rd16(b+1), id=rd16(b+3);
    if (id==0x20) {
        assert(b[7]==1 && rd16(b+8)==1); /* TLV 1: enable */
        if (b[10]) { registers++; qmi_response(0x20,txn,1,M11_PD_UP); }
        else { unregisters++; qmi_response(0x20,txn,0,0); }
    } else if (id==0x23) { acks++; qmi_response(0x23,txn,0,0); }
    else { errno=EINVAL; return -1; }
    sends_ok++; return (ssize_t)n;
}
ssize_t __wrap_recvfrom(int fd, void *b, size_t cap, int flags, struct sockaddr *addr, socklen_t *len) {
    assert(fd==905 && (flags&MSG_DONTWAIT));
    if (q_head==q_tail) { errno=EAGAIN; return -1; }
    struct dgram *d=&queue[q_head++%32];
    size_t n=d->n<cap?d->n:cap; memcpy(b,d->b,n);
    struct sockaddr_qrtr *a=(void *)addr; memset(a,0,sizeof(*a));
    a->sq_family=AF_QIPCRTR; a->sq_node=d->node; a->sq_port=d->port; *len=sizeof(*a);
    return (ssize_t)n;
}
static int fake_close_pair(void *ctx, int a, int g) { (void)ctx; (void)a; (void)g; return 0; }
static m11_pid1_anchor fake_anchor;
static void dump(void) {
    const struct m11_pd *p=&runtime.status.pd;
    printf("STATE phase=%d fault=%d invalid=%d peer=%d node=%u port=%u registered=%d register_txn=%u ack_txn=%u "
           "ack_deferred=%d count=%u poisoned=%d pd_started=%d qrtr=%d bound_port=%u sends_ok=%u refused=%u "
           "lookups=%u registers=%u unregisters=%u acks=%u q=%u/%u\n",
           (int)p->phase,(int)p->fault,p->invalid,p->peer,p->node,p->port,p->registered,(unsigned)p->register_txn,
           (unsigned)p->ack_txn,p->ack_deferred,p->count,runtime.status.poisoned,runtime.status.pd_started,runtime.qrtr,
           bound_port,sends_ok,sends_refused,lookups,registers,unregisters,acks,q_head,q_tail);
    for (unsigned i=0;i<p->count && i<12;i++)
        printf("  record %u tx=%u node=%u port=%u size=%u rc=%d first=%02x\n",i,p->records[i].tx,p->records[i].node,
               p->records[i].port,p->records[i].size,p->records[i].rc,p->records[i].size?p->records[i].bytes[0]:0);
}
#define CHECK(cond, what) do { if (!(cond)) { printf("FAIL %s: %s (line %d)\n", what, #cond, __LINE__); dump(); abort(); } } while (0)
static void owner(unsigned flags) {
    attempted=fail_mode=listed=ready=unreg_reply=0;
    memset(fd_mode,0,sizeof(fd_mode)); memset(&runtime,0,sizeof(runtime));
    srv_flags=flags; bound_port=sends_ok=sends_refused=lookups=del_lookups=registers=unregisters=acks=0; q_head=q_tail=0;
    assert(!ns(&fixture_now));
    assert(m11_audio_acquire_boot()==&runtime);
    assert(!m11_audio_enroll(&runtime,100,M11_AUDIO_LOCATOR));
    assert(!m11_audio_enroll(&runtime,101,M11_AUDIO_LOGGER)); listed=1;
    assert(!m11_audio_bind_endpoint(&runtime,makedev(240,0)));
}
/* What m11_audio_admit establishes, without the sealed anchor it would check. */
static void admitted(void) {
    memset(&fake_anchor,0,sizeof(fake_anchor)); fake_anchor.ops.close_pair=fake_close_pair;
    runtime.anchor=&fake_anchor; runtime.status.admitted=1;
    runtime.status.resources_quiescent=0; runtime.status.pd.resources_busy=1;
}
static struct m11_gpr_session session(void) {
    struct m11_gpr_session s; memset(&s,0,sizeof(s)); s.runtime=&runtime; s.expected_device=makedev(240,0); return s;
}
int main(void) {
    setvbuf(stdout,NULL,_IONBF,0);
    /* 1. happy path: READY, clean worker, full unregister. */
    owner(SRV_ANNOUNCE);
    CHECK(!m11_audio_start_pd(&runtime,2000), "happy start");
    CHECK(runtime.status.pd.phase==M11_PD_READY && lookups==1 && registers==1 && !runtime.status.poisoned, "happy ready");
    admitted();
    struct m11_gpr_session s=session();
    struct m11_gpr_result clean={.worker_reaped=1,.worker_exit_ok=1,.close_returned=1,.close_ok=1,.ipc_complete=1};
    m11_audio_finish(&s,&clean);
    CHECK(runtime.status.resources_quiescent && !runtime.status.pd.resources_busy, "happy finish");
    CHECK(!m11_audio_retire(&runtime) && runtime.status.notifier_cleanup_complete && unregisters==1 && del_lookups==1 &&
          runtime.status.pd.phase==M11_PD_STOPPED && runtime.qrtr<0, "happy retire");
    puts("PASS e2e happy: lookup -> NEW_SERVER -> register(UP) -> READY; clean finish; unregister + DEL_LOOKUP; retire 0");
    /* 2. worker killed at its deadline under the sealed anchor: quiescent, retire completes (RED, not a hold). */
    owner(SRV_ANNOUNCE);
    CHECK(!m11_audio_start_pd(&runtime,2000), "worker timeout start");
    admitted(); s=session();
    struct m11_gpr_result killed={.worker_reaped=1};
    m11_audio_finish(&s,&killed);
    CHECK(runtime.status.resources_quiescent && !runtime.status.unresolved_worker, "worker timeout quiescent under the anchor");
    CHECK(!m11_audio_retire(&runtime) && runtime.status.notifier_cleanup_complete && unregisters==1, "worker timeout retire");
    puts("PASS e2e worker timeout: a reaped borrower is quiescent under the anchor; retire completes (RED, not a hold)");
    /* 3. unresolved worker: never quiescent, retire refuses and sends nothing. */
    owner(SRV_ANNOUNCE);
    CHECK(!m11_audio_start_pd(&runtime,2000), "unresolved start");
    admitted(); s=session();
    struct m11_gpr_result stuck={.unresolved_worker=4242};
    unsigned before=sends_ok;
    m11_audio_finish(&s,&stuck);
    CHECK(!runtime.status.resources_quiescent && runtime.status.unresolved_worker==4242, "unresolved not quiescent");
    CHECK(m11_audio_retire(&runtime)==-1 && sends_ok==before, "unresolved retire refused");
    puts("PASS e2e unresolved worker: not quiescent; retire refuses and sends nothing (hold, resources retained)");
    /* 4. no server announced: start fails (not UP), retire sends DEL_LOOKUP and completes (CYAN, no hold). */
    owner(0);
    CHECK(m11_audio_start_pd(&runtime,100)==-1 && lookups==1 && !registers && runtime.status.poisoned, "no server start");
    CHECK(!m11_audio_retire(&runtime) && del_lookups==1 && !unregisters && runtime.status.notifier_cleanup_complete, "no server retire");
    puts("PASS e2e no server: start not UP; retire removes the lookup and completes (CYAN path, no hold)");
    /* 5. every send refused: nothing accepted, retire closes only and never sends again. */
    owner(SRV_ANNOUNCE|SRV_REFUSE_SEND);
    CHECK(m11_audio_start_pd(&runtime,100)==-1 && sends_refused==1 && !sends_ok, "refused start");
    unsigned refused=sends_refused;
    CHECK(!m11_audio_retire(&runtime) && sends_refused==refused && runtime.status.notifier_cleanup_complete && runtime.qrtr<0, "refused retire");
    puts("PASS e2e send refused: start fails before anything is accepted; retire closes only (no further send)");
    /* 6. state DOWN after READY: control invalidates the query (RED); retire still completes. */
    owner(SRV_ANNOUNCE);
    CHECK(!m11_audio_start_pd(&runtime,2000), "indication start");
    s=session();
    indication(M11_PD_DOWN,7);
    CHECK(m11_audio_control(&s)!=0 && runtime.status.pd.phase==M11_PD_INVALID && runtime.status.pd.fault==M11_PD_NOT_UP && acks==1, "indication down");
    CHECK(!m11_audio_retire(&runtime) && unregisters==1 && del_lookups==1 && runtime.status.notifier_cleanup_complete, "indication retire");
    puts("PASS e2e indication DOWN after READY: query invalidated (RED); indication ACKed; retire completes");
    /* 7. the model enforces the kernel flags rule the frozen runtime violated. */
    owner(SRV_ANNOUNCE); bound_port=ASSIGNED_PORT;
    struct sockaddr_qrtr a={.sq_family=AF_QIPCRTR,.sq_node=LOCAL_NID,.sq_port=CTRL_PORT};
    unsigned char probe[20]={0};
    errno=0;
    CHECK(__wrap_sendto(905,probe,sizeof(probe),MSG_DONTWAIT|MSG_NOSIGNAL,(struct sockaddr *)&a,sizeof(a))==-1 && errno==EINVAL, "flags rule");
    puts("PASS e2e model refuses MSG_DONTWAIT|MSG_NOSIGNAL with EINVAL (af_qrtr.c:893)");
    puts("PDR end-to-end model qualification: 7 cases PASS (kernel-rule QRTR + scripted name service/servreg; synthetic only)");
    return 0;
}
