/* SPDX-License-Identifier: GPL-2.0-only */
#include "cnssd.h"
#include <errno.h>
#include <limits.h>
#include <linux/qrtr.h>
#include <string.h>

_Static_assert(sizeof(struct qrtr_ctrl_pkt)==20,"QRTR control wire layout");

static uint32_t le32(const unsigned char *b) {
    return (uint32_t)b[0]|(uint32_t)b[1]<<8|(uint32_t)b[2]<<16|(uint32_t)b[3]<<24;
}
static void put32(unsigned char *b,uint32_t v) {
    for(unsigned i=0;i<4;i++)b[i]=(unsigned char)(v>>(8*i));
}
static int evidence(struct m12_daemon *s,const struct m12_daemon_io *io,unsigned event,int rc) {
    struct m12_owner_record r={0};
    r.magic=M12_OWNER_MAGIC;r.version=M12_OWNER_VERSION;r.sequence=++s->sequence;
    r.event=event;r.phase=s->db.phase;r.node=s->db.node;r.port=s->db.port;
    r.size=s->db.size;r.rc=rc;r.qmi_result=s->db.qmi_result;r.qmi_error=s->db.qmi_error;
    r.seed_verified=s->seed_verified;r.ram_valid=s->db.ram_valid;
    r.transaction=s->db.txn;r.waiting_message=s->db.waiting_msg;
    r.segment=s->db.segment;r.offset=s->db.offset;r.driver_status=s->db.driver_status;
    memcpy(r.seed_sha256,s->seed_sha256,32);memcpy(r.source_evidence_sha256,s->source_evidence_sha256,32);
    return io->record(io->ctx,&r);
}
static void poison(struct m12_daemon *s,const struct m12_daemon_io *io,int rc) {
    if(s->poisoned)return;
    s->poisoned=1;s->error=rc;
    m12_caldb_disconnect(&s->db); /* Invalidates all RAM, never persists it. */
    (void)evidence(s,io,M12_POISON,rc);
}
static int emit(struct m12_daemon *s,const struct m12_daemon_io *io,
                uint32_t node,uint32_t port,const void *bytes,size_t n) {
    int rc=evidence(s,io,M12_TX,0);
    if(!rc)rc=io->send(io->ctx,node,port,bytes,n);
    if(rc)poison(s,io,rc); /* No retransmit after short, EAGAIN or uncertain TX. */
    return rc;
}
static int control(struct m12_daemon *s,const struct m12_input *in) {
    /* Linux 5.10 net/qrtr/ns.c lookup_notify(NULL) emits an all-zero
     * NEW_SERVER body after the initial census. Control origin is local NS. */
    if(in->node!=s->local_node)return -EACCES;
    if(in->size!=20)return -EPROTO;
    uint32_t cmd=le32(in->bytes),svc=le32(in->bytes+4),inst=le32(in->bytes+8);
    uint32_t node=le32(in->bytes+12),port=le32(in->bytes+16);
    if(cmd==4 && !svc && !inst && !node && !port) {
        if(s->discovered)return -EPROTO;
        if(s->census!=1)return -ENOENT;
        s->discovered=1;return 1;
    }
    if(cmd==4 || cmd==5) {
        if(svc!=M12_CNSS_SERVICE || inst!=(M12_CNSS_INSTANCE<<8|M12_CNSS_VERSION))return -EPROTO;
        if(node!=s->local_node || !port || port==QRTR_PORT_CTRL ||
           port==QRTR_NODE_BCAST)return -EACCES;
        if(cmd==5)return -ENOTCONN;
        if(s->census || s->discovered)return -EADDRINUSE; /* No endpoint substitution. */
        s->peer_port=port;s->census=1;return 0;
    }
    if(cmd==3 && svc==s->local_node)return -ENOTCONN; /* BYE client.node */
    if(cmd==6 && svc==s->local_node && inst==s->peer_port)return -ENOTCONN;
    /* Other local client deaths/resume notifications do not identify owner. */
    if(cmd==6 || cmd==7)return 0;
    return -EPROTO;
}
int m12_cnssd_run(struct m12_daemon *s,const struct m12_daemon_io *io,
                 uint32_t local,unsigned char *ram,size_t cap) {
    if(!s || !io || !io->now || !io->wait || !io->send || !io->record || !io->seed ||
       !ram || !cap || cap>M12_CALDB_MAX)return -EINVAL;
    memset(s,0,sizeof(*s));memset(ram,0,cap);s->local_node=local;
    s->db.ram=ram;s->db.capacity=cap;
    uint64_t now=io->now(io->ctx),last=now;
    if(!now || UINT64_MAX-now<5000)return -EINVAL;
    s->discovery_deadline=now+5000;
    unsigned char lookup[20]={0};put32(lookup,10);put32(lookup+4,M12_CNSS_SERVICE);
    put32(lookup+8,M12_CNSS_VERSION|M12_CNSS_INSTANCE<<8);
    if(evidence(s,io,M12_DISCOVERY,0))poison(s,io,-EPIPE);
    /* Local namespace socket, not the broadcast NODE sentinel used as a port. */
    if(!s->poisoned)(void)emit(s,io,local,QRTR_PORT_CTRL,lookup,sizeof(lookup));
    for(;;) {
        struct m12_input in={0};
        now=io->now(io->ctx);
        if(!now || now<last)poison(s,io,-EINVAL);
        last=now;
        if(!s->poisoned) {
            if(!s->discovered && now>=s->discovery_deadline)poison(s,io,-ETIMEDOUT);
            else if(s->discovered) {
                int rc=m12_caldb_tick(&s->db,now);if(rc)poison(s,io,rc);
            }
        }
        int rc=io->wait(io->ctx,100,s->poisoned,&in);
        if(rc<0) { poison(s,io,rc);continue; }
        if(!rc)continue;
        if(in.kind==M12_INPUT_STOP) {
            const struct m12_owner_stop *p=&in.stop;
            if(p->magic!=M12_OWNER_MAGIC || p->version!=M12_OWNER_VERSION ||
               p->qca_retired!=1 || p->cnss_retired!=1 || p->unresolved_child!=0 ||
               p->transfer_pending!=0 || s->db.waiting_msg || s->db.pending_upload ||
               s->db.phase==M12_DB_DOWNLOAD || s->db.phase==M12_DB_UPLOAD) {
                if(evidence(s,io,M12_STOP_DENIED,-EBUSY))poison(s,io,-EPIPE);
                continue;
            }
            m12_caldb_disconnect(&s->db);
            rc=evidence(s,io,M12_RETIRED,s->error);
            /* No final receipt => not a clean retirement, never fake success. */
            return s->error?s->error:rc;
        }
        if(s->poisoned)continue;
        if(in.kind!=M12_INPUT_QRTR) { poison(s,io,-EPROTO);continue; }
        if(evidence(s,io,M12_RX,0)) { poison(s,io,-EPIPE);continue; }
        now=io->now(io->ctx);
        if(!now || now<last || (!s->discovered && now>=s->discovery_deadline)) {
            poison(s,io,!now || now<last?-EINVAL:-ETIMEDOUT);continue;
        }
        struct m12_caldb_packet out={0};
        if(in.port==QRTR_PORT_CTRL) {
            rc=control(s,&in);
            if(rc==1)rc=m12_caldb_begin(&s->db,ram,cap,local,s->peer_port,now,&out);
        } else {
            if(!s->discovered)rc=-EPROTO;
            else {
                enum m12_caldb_phase before=s->db.phase;
                rc=m12_caldb_receive(&s->db,in.node,in.port,in.bytes,in.size,now,&out);
                if(!rc && before==M12_DB_SETUP && m12_caldb_owned(&s->db)) {
                    size_t n=0;
                    rc=io->seed(io->ctx,ram,cap,&n,s->seed_sha256,s->source_evidence_sha256);
                    if(rc==1) {
                        rc=m12_caldb_seed(&s->db,ram,n);if(!rc)s->seed_verified=1;
                    }
                    if(!rc)rc=evidence(s,io,M12_READY,0);
                }
            }
        }
        if(rc) { poison(s,io,rc);continue; }
        if(out.size)(void)emit(s,io,s->db.node,s->db.port,out.bytes,out.size);
        /* Publish post-ACK state even when a completed transfer emits no TX.
         * Parent must not infer idle/retirement from the pre-processing RX. */
        if(!s->poisoned && evidence(s,io,M12_STATE,0))poison(s,io,-EPIPE);
    }
}
