/* One packet transaction; callbacks run only inside the contained I/O worker. */
#include "gpr_native_internal.h"
#include <errno.h>
#include <limits.h>
#include <string.h>

static uint32_t word(const unsigned char *p) {
    return (uint32_t)p[0] | (uint32_t)p[1]<<8 | (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24;
}
static void put(unsigned char *p, uint32_t v) {
    p[0]=(unsigned char)v; p[1]=(unsigned char)(v>>8);
    p[2]=(unsigned char)(v>>16); p[3]=(unsigned char)(v>>24);
}
struct transaction {
    const struct m11_gpr_io *io;
    uint64_t now, deadline;
    enum m11_gpr_outcome outcome;
    int recording_failed;
};
static int guard(struct transaction *t) {
    uint64_t n;
    /* Sample after the syscall even when DOWN/cancel wins classification. */
    if (t->io->now(t->io->context,&n) || n<t->now) {
        t->outcome=M11_GPR_IO_ERROR; return 0;
    }
    t->now=n;
    int c=t->io->control(t->io->context);
    if (c) {
        t->outcome=c==1 ? M11_GPR_SERVICE_DOWN : c==2 ? M11_GPR_CANCELLED : M11_GPR_IO_ERROR;
        return 0;
    }
    if (n>=t->deadline) { t->outcome=M11_GPR_TIMEOUT; return 0; }
    return 1;
}
static int record(struct transaction *t, enum m11_gpr_stage stage, int64_t rc,
                  const unsigned char *packet, size_t size) {
    struct m11_gpr_event e;
    memset(&e,0,sizeof(e));
    e.stage=stage; e.outcome=t->outcome; e.rc=rc; e.monotonic_ns=t->now;
    e.size=(uint32_t)size;
    if (packet && size) memcpy(e.packet,packet,size);
    if (t->io->record(t->io->context,&e)) {
        t->outcome=M11_GPR_IO_ERROR; t->recording_failed=1; return 0;
    }
    return 1;
}
static enum m11_gpr_outcome response(const unsigned char *p, size_t n, uint32_t token) {
    if (n<24 || n>M11_GPR_MAX || word(p)!=((uint32_t)n<<8 | 0x60u) ||
        p[4]!=3 || p[5]!=2 || p[6] || p[7] || word(p+8)!=1 ||
        word(p+12)!=M11_GPR_SOURCE_PORT || word(p+16)!=token)
        return M11_GPR_PROTOCOL_ERROR;
    if (word(p+20)==M11_GPR_SPF_RESPONSE && n==28) {
        uint32_t state=word(p+24);
        return state==1 ? M11_GPR_SPF_READY : state==0 ? M11_GPR_SPF_NOT_READY : M11_GPR_PROTOCOL_ERROR;
    }
    if (word(p+20)==M11_GPR_BASIC_RESPONSE && n==32 && word(p+24)==M11_GPR_GET_SPF && word(p+28))
        return M11_GPR_FIRMWARE_REJECTED;
    /* A basic status0 does not substitute for the typed state response. */
    return M11_GPR_PROTOCOL_ERROR;
}
void m11_gpr_worker(const struct m11_gpr_io *io, uint32_t token, uint64_t start, uint64_t deadline) {
    struct transaction t={io,start,deadline,M11_GPR_INVALID,0};
    unsigned char tx[24]={0}, rx[M11_GPR_MAX];
    int fd=-1;
    int64_t rc;
    if (!token || deadline<=start || !guard(&t)) goto done;
    if (!record(&t,M11_GPR_BEGIN,0,0,0)) goto done;
    if (!guard(&t)) goto done; /* diagnostic callback may consume the budget */
    rc=io->open(io->context);
    /* Preserve the returned descriptor even when the post-open guard expires. */
    if (rc>=0 && rc<=INT_MAX) fd=(int)rc;
    if (!guard(&t)) { record(&t,M11_GPR_OPEN,rc,0,0); goto close_fd; }
    if (fd<0) t.outcome=M11_GPR_OPEN_FAILED;
    if (!record(&t,M11_GPR_OPEN,rc,0,0) || fd<0) goto close_fd;
    if (!guard(&t)) goto close_fd; /* observe may delay even a preflight read */
    rc=io->read(io->context,fd,rx,sizeof(rx));
    if (!guard(&t)) { record(&t,M11_GPR_PREFLIGHT,rc,0,0); goto close_fd; }
    if (rc!=-EAGAIN) t.outcome=rc>=0 ? M11_GPR_DIRTY_QUEUE : rc==-ENETRESET ? M11_GPR_SERVICE_DOWN : M11_GPR_RX_FAILED;
    if (!record(&t,M11_GPR_PREFLIGHT,rc,rx,rc>0 && rc<=M11_GPR_MAX?(size_t)rc:0) || rc!=-EAGAIN) goto close_fd;
    put(tx,(24u<<8)|0x60u); tx[4]=2; tx[5]=3;
    put(tx+8,M11_GPR_SOURCE_PORT); put(tx+12,1); put(tx+16,token); put(tx+20,M11_GPR_GET_SPF);
    if (!guard(&t) || !record(&t,M11_GPR_TX_BEGIN,0,tx,sizeof(tx))) goto close_fd;
    if (!guard(&t)) goto close_fd; /* never TX after a slow diagnostic callback */
    rc=io->write(io->context,fd,tx,sizeof(tx)); /* Exactly once; never write a suffix or retry EINTR. */
    if (!guard(&t)) { record(&t,M11_GPR_TX_RETURN,rc,tx,sizeof(tx)); goto close_fd; }
    if (rc!=(int64_t)sizeof(tx)) t.outcome=rc==-ENETRESET ? M11_GPR_SERVICE_DOWN : rc<0 ? M11_GPR_TX_FAILED : M11_GPR_TX_INCOMPLETE;
    if (!record(&t,M11_GPR_TX_RETURN,rc,tx,sizeof(tx)) || rc!=(int64_t)sizeof(tx)) goto close_fd;
    for (;;) {
        if (!guard(&t)) break;
        /* Nonblocking read first also accepts a response queued during write. */
        rc=io->read(io->context,fd,rx,sizeof(rx));
        if (!guard(&t)) { record(&t,M11_GPR_RX_RETURN,rc,rx,rc>0 && rc<=M11_GPR_MAX?(size_t)rc:0); break; }
        if (rc!=-EAGAIN && rc!=-EINTR) {
            t.outcome=rc==-ENETRESET ? M11_GPR_SERVICE_DOWN : rc<=0 ? M11_GPR_RX_FAILED :
                rc>M11_GPR_MAX ? M11_GPR_PROTOCOL_ERROR : response(rx,(size_t)rc,token);
            record(&t,M11_GPR_RX_RETURN,rc,rx,rc>0 && rc<=M11_GPR_MAX?(size_t)rc:0);
            break;
        }
        unsigned int ms=(unsigned int)((t.deadline-t.now+999999u)/1000000u);
        if (ms>50) ms=50;
        rc=io->wait(io->context,fd,ms);
        if (rc<0 && rc!=-EINTR) { t.outcome=rc==-ENETRESET?M11_GPR_SERVICE_DOWN:M11_GPR_IO_ERROR; break; }
    }
close_fd:
    if (fd>=0) {
        /* Close may affect global APM/ION state and may block. Supervisor owns containment. */
        record(&t,M11_GPR_CLOSE_BEGIN,0,0,0);
        rc=io->close(io->context,fd); /* No retry: EINTR can already consume the fd. */
        enum m11_gpr_outcome primary=t.outcome;
        if (!guard(&t)) primary=t.outcome;
        t.outcome=primary;
        if (rc && (primary==M11_GPR_SPF_READY || primary==M11_GPR_SPF_NOT_READY)) t.outcome=M11_GPR_CLOSE_FAILED;
        record(&t,M11_GPR_CLOSE_RETURN,rc,0,0);
    }
done:
    if (!t.recording_failed) record(&t,M11_GPR_DONE,0,0,0);
}
