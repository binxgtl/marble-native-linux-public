/* SPDX-License-Identifier: GPL-2.0-only
 * Native Linux adapter; launched only by a trusted PID1 supervisor.
 * No path opens, filesystem writes, sysfs trigger, RF or calibration logic.
 */
#define _GNU_SOURCE
#include "cnssd.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/qrtr.h>
/* Only the stable SHA256_CTX primitive is needed. OpenSSL3's one-shot SHA256
 * routes through EVP_Q_digest and pulls providers/DNS/dlopen into static PID1
 * payloads. Request the 1.1 API declarations without relaxing compiler checks. */
#define OPENSSL_API_COMPAT 0x10100000L
#include <openssl/sha.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static unsigned char *hash256(const unsigned char *bytes,size_t size,unsigned char digest[32]) {
    SHA256_CTX ctx;
    if(!SHA256_Init(&ctx) || !SHA256_Update(&ctx,bytes,size) || !SHA256_Final(digest,&ctx))return NULL;
    return digest;
}

static int immutable_fd(int fd,size_t size) {
    struct stat st;
    int flags=fcntl(fd,F_GETFL),seals=fcntl(fd,F_GET_SEALS);
    const int required=F_SEAL_SEAL|F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_WRITE;
    if(!size || flags<0 || seals<0 ||
       (flags&O_ACCMODE)!=O_RDONLY || (seals&required)!=required || fstat(fd,&st) ||
       !S_ISREG(st.st_mode) || st.st_size<0 || (uint64_t)st.st_size!=size)return -EINVAL;
    return 0;
}
int m12_cnssd_seed_fd(int fd,size_t size,const unsigned char hash[32],int origin_fd,
                     const unsigned char origin[32],unsigned char *ram,size_t cap) {
    if(!ram || !cap || cap>M12_CALDB_MAX || !hash || !origin)return -EINVAL;
    memset(ram,0,cap);
    if(!size || size>cap || fd==origin_fd ||
       immutable_fd(fd,size))return -EINVAL;
    /* The provenance record is itself an immutable, content-addressed RAM
     * object. Exact schema binds source kind, device, logical name, size/hash.
     * It remains a trusted-parent assertion, not proof of factory authenticity. */
    char hex[65],expected[256],actual[256];
    for(unsigned i=0;i<32;i++)(void)snprintf(hex+i*2,3,"%02x",hash[i]);
    int len=snprintf(expected,sizeof(expected),"M12-CALDB-SEED-v1\nsource=stock-read-only-snapshot\ndevice=marble\nname=wlfw_cal_db.bin\nsize=%zu\nsha256=%s\n",size,hex);
    if(len<=0 || (size_t)len>=sizeof(expected) || immutable_fd(origin_fd,(size_t)len))return -EINVAL;
    ssize_t got;
    do { got=pread(origin_fd,actual,(size_t)len,0); } while(got<0 && errno==EINTR);
    unsigned char digest[32];
    if(got!=len || memcmp(actual,expected,(size_t)len) ||
       !hash256((unsigned char *)actual,(size_t)len,digest) || memcmp(digest,origin,32))return -EBADMSG;
    size_t off=0;
    while(off<size) {
        ssize_t n=pread(fd,ram+off,size-off,(off_t)off);
        if(n<0 && errno==EINTR)continue;
        if(n<=0) { memset(ram,0,cap);return n<0?-errno:-EIO; }
        off+=(size_t)n;
    }
    if(!hash256(ram,size,digest) || memcmp(digest,hash,32)) {
        memset(ram,0,cap);return -EBADMSG;
    }
    return 0;
}
struct linux_io {
    int qrtr,supervisor,supervisor_dead,seed_fd,origin_fd;
    size_t seed_size;
    unsigned char hash[32],origin[32];
};
static uint64_t monotonic(void *ctx) {
    (void)ctx;struct timespec ts;
    if(clock_gettime(CLOCK_MONOTONIC,&ts))return 0;
    return (uint64_t)ts.tv_sec*1000+(uint64_t)ts.tv_nsec/1000000+1;
}
static int tx(void *ctx,uint32_t node,uint32_t port,const void *bytes,size_t size) {
    struct linux_io *l=ctx;
    struct sockaddr_qrtr to={.sq_family=AF_QIPCRTR,.sq_node=node,.sq_port=port};
    /* ACK 5.10 qrtr_sendmsg rejects every flag except MSG_DONTWAIT with
     * -EINVAL, before routing even NEW_LOOKUP. MSG_NOSIGNAL is appropriate
     * for the separate UNIX supervision socket, not this QRTR datagram. */
    ssize_t rc=sendto(l->qrtr,bytes,size,MSG_DONTWAIT,(void *)&to,sizeof(to));
    return rc<0?-errno:(size_t)rc==size?0:-EIO;
}
static int record(void *ctx,const struct m12_owner_record *r) {
    struct linux_io *l=ctx;
    ssize_t n=send(l->supervisor,r,sizeof(*r),MSG_DONTWAIT|MSG_NOSIGNAL);
    return n<0?-errno:(size_t)n==sizeof(*r)?0:-EIO;
}
static int seed(void *ctx,unsigned char *ram,size_t cap,size_t *n,
                unsigned char hash[32],unsigned char origin[32]) {
    struct linux_io *l=ctx;
    if(l->seed_fd<0)return 0;
    int rc=m12_cnssd_seed_fd(l->seed_fd,l->seed_size,l->hash,l->origin_fd,l->origin,ram,cap);
    if(rc)return rc;
    *n=l->seed_size;memcpy(hash,l->hash,32);memcpy(origin,l->origin,32);return 1;
}
static int wait_input(void *ctx,unsigned ms,int faulted,struct m12_input *in) {
    struct linux_io *l=ctx;
    struct pollfd f[2]={{.fd=l->supervisor_dead?-1:l->supervisor,.events=POLLIN},
                      {.fd=faulted?-1:l->qrtr,.events=POLLIN}};
    int n=poll(f,2,(int)ms);
    if(n<0)return errno==EINTR?0:-errno;
    if(!n)return 0;
    /* Supervision first; no queued QRTR data can starve a retirement denial. */
    if(f[0].revents) {
        if(f[0].revents&POLLIN) {
            ssize_t got=recv(l->supervisor,&in->stop,sizeof(in->stop),MSG_DONTWAIT|MSG_TRUNC);
            if(got==(ssize_t)sizeof(in->stop)) { in->kind=M12_INPUT_STOP;return 1; }
            if(got<0 && (errno==EINTR || errno==EAGAIN))return 0;
            if(got>0)return -EMSGSIZE;
        }
        l->supervisor_dead=1;return -EPIPE; /* Subsequent poll sleeps; keep owner. */
    }
    if(f[1].revents&POLLIN) {
        struct sockaddr_qrtr from={0};socklen_t len=sizeof(from);
        ssize_t got=recvfrom(l->qrtr,in->bytes,sizeof(in->bytes),MSG_DONTWAIT|MSG_TRUNC,
                             (void *)&from,&len);
        if(got<0)return (errno==EINTR || errno==EAGAIN)?0:-errno;
        if((size_t)got>sizeof(in->bytes) || !got || len!=sizeof(from) ||
           from.sq_family!=AF_QIPCRTR)return -EMSGSIZE;
        in->kind=M12_INPUT_QRTR;in->node=from.sq_node;in->port=from.sq_port;
        in->size=(size_t)got;return 1;
    }
    if(f[1].revents)return -ENOTCONN;
    return 0;
}
static int number(const char *s,int *out) {
    char *end;errno=0;long v=strtol(s,&end,10);
    if(errno || !*s || *end || v<3 || v>1024)return -1;
    *out=(int)v;return 0;
}
static int digest(const char *s,unsigned char out[32]) {
    if(strlen(s)!=64)return -1;
    for(unsigned i=0;i<32;i++) {
        unsigned v=0;
        for(unsigned j=0;j<2;j++) {
            unsigned c=(unsigned char)s[i*2+j];
            if(c>='0' && c<='9')c-='0';else if(c>='a' && c<='f')c=c-'a'+10;else return -1;
            v=v*16+c;
        }
        out[i]=(unsigned char)v;
    }
    return 0;
}
#ifndef M12_CNSSD_NO_MAIN
int main(int argc,char **argv) {
    /* argv: supervisor-fd [seed-fd size content-sha256 source-evidence-fd source-evidence-sha256]
     * No daemonization/reconnect/retry. PID1 owns stop proof and child reaping.
     * This guard prevents an accidental CLI invocation from opening QRTR. */
    if(getppid()!=1 || geteuid()!=0 || (argc!=2 && argc!=7))return 2;
    struct linux_io l={.qrtr=-1,.supervisor=-1,.seed_fd=-1,.origin_fd=-1};
    if(number(argv[1],&l.supervisor))return 2;
    struct ucred cred;socklen_t len=sizeof(cred);int type=0;socklen_t tlen=sizeof(type);
    if(getsockopt(l.supervisor,SOL_SOCKET,SO_PEERCRED,&cred,&len) ||
       len!=sizeof(cred) || cred.pid!=1 || cred.uid!=0 ||
       getsockopt(l.supervisor,SOL_SOCKET,SO_TYPE,&type,&tlen) || type!=SOCK_SEQPACKET)return 2;
    if(argc==7) {
        char *end;errno=0;unsigned long n=strtoul(argv[3],&end,10);
        if(errno || !*argv[3] || *end || !n || n>M12_CALDB_MAX ||
           number(argv[2],&l.seed_fd) || l.seed_fd==l.supervisor ||
           number(argv[5],&l.origin_fd) || l.origin_fd==l.supervisor || l.origin_fd==l.seed_fd ||
           digest(argv[4],l.hash) || digest(argv[6],l.origin))return 2;
        l.seed_size=(size_t)n;
    }
    (void)signal(SIGTERM,SIG_IGN);(void)signal(SIGINT,SIG_IGN);
    l.qrtr=socket(AF_QIPCRTR,SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK,0);
    if(l.qrtr<0)return 3; /* No registration attempted. */
    /* An unconnected QRTR socket's local node is available via getsockname;
     * bind port 0 allocates the ephemeral port on that local node. */
    struct sockaddr_qrtr local={0};len=sizeof(local);
    if(getsockname(l.qrtr,(void *)&local,&len) || len!=sizeof(local) || local.sq_family!=AF_QIPCRTR ||
       bind(l.qrtr,(void *)&local,sizeof(local))) { close(l.qrtr);return 3; }
    unsigned char *ram=calloc(1,M12_CALDB_MAX);
    if(!ram) { close(l.qrtr);return 3; }
    struct m12_daemon state;
    struct m12_daemon_io io={&l,monotonic,wait_input,tx,record,seed};
    int rc=m12_cnssd_run(&state,&io,local.sq_node,ram,M12_CALDB_MAX);
    /* Event loop returns only after explicit retirement or pre-TX invalid
     * arguments/clock. No timeout/parent EOF drops a registered owner. */
    memset(ram,0,M12_CALDB_MAX);free(ram);close(l.qrtr);
    if(l.seed_fd>=0)close(l.seed_fd);
    if(l.origin_fd>=0)close(l.origin_fd);
    close(l.supervisor);return rc?1:0;
}
#endif
