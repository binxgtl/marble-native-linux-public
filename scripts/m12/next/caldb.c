/* SPDX-License-Identifier: GPL-2.0-only */
#include "caldb.h"
#include <errno.h>
#include <limits.h>
#include <string.h>

struct field { const unsigned char *p; size_t n; };
static uint16_t u16(const unsigned char *p) { return (uint16_t)(p[0]|p[1]<<8); }
static uint32_t u32(const unsigned char *p) {
    return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;
}
static void put16(unsigned char *p,uint16_t v) { p[0]=(unsigned char)v;p[1]=(unsigned char)(v>>8); }
static void put32(unsigned char *p,uint32_t v) {
    for(unsigned i=0;i<4;i++)p[i]=(unsigned char)(v>>(8*i));
}
static int fail(struct m12_caldb *s,int rc) {
    s->error=rc;s->phase=M12_DB_FAILED;s->ram_valid=0;
    s->pending_upload=0;s->waiting_msg=0;s->deadline=0;s->file_deadline=0;
    /* Discard partial/old bytes on failure. Nothing ever goes to a filesystem. */
    if(s->ram && s->capacity)memset(s->ram,0,s->capacity);
    s->size=0;
    return rc;
}
static void tlv(struct m12_caldb_packet *p,unsigned char id,const void *b,uint16_t n) {
    p->bytes[p->size]=id;put16(p->bytes+p->size+1,n);
    memcpy(p->bytes+p->size+3,b,n);p->size+=3u+n;
}
static void word(struct m12_caldb_packet *p,unsigned char id,uint32_t v) {
    unsigned char b[4];put32(b,v);tlv(p,id,b,4);
}
static int request(struct m12_caldb *s,struct m12_caldb_packet *p,
                   uint16_t msg,uint64_t now) {
    if(!now || UINT64_MAX-now<5000 || s->txn==UINT16_MAX)return fail(s,-EOVERFLOW);
    p->size=7;p->bytes[0]=0;put16(p->bytes+1,++s->txn);put16(p->bytes+3,msg);
    s->waiting_msg=msg;s->deadline=now+5000;
    return 0;
}
static int finish(struct m12_caldb_packet *p) {
    if(p->size<7 || p->size-7>UINT16_MAX)return -EOVERFLOW;
    put16(p->bytes+5,(uint16_t)(p->size-7));return 0;
}
static int fields(const unsigned char *b,size_t n,struct field f[17],uint32_t *mask) {
    memset(f,0,17*sizeof(*f));*mask=0;
    for(size_t off=0;off<n;) {
        if(n-off<3)return -EPROTO;
        unsigned id=b[off];size_t len=u16(b+off+1);off+=3;
        if(id>16 || !id || (*mask&(1u<<id)) || len>n-off)return -EPROTO;
        f[id].p=b+off;f[id].n=len;*mask|=1u<<id;off+=len;
    }
    return 0;
}
int m12_caldb_tick(struct m12_caldb *s,uint64_t now) {
    if(s->phase==M12_DB_FAILED)return s->error;
    if(!now || now<s->last_tick)return fail(s,-EINVAL);
    s->last_tick=now;
    if((s->deadline && now>=s->deadline) ||
       (s->file_deadline && now>=s->file_deadline))return fail(s,-ETIMEDOUT);
    return 0;
}
void m12_caldb_disconnect(struct m12_caldb *s) { (void)fail(s,-ENOTCONN); }
int m12_caldb_owned(const struct m12_caldb *s) {
    return s->registered && s->setup_ack && s->phase==M12_DB_IDLE && !s->error;
}
int m12_caldb_seed(struct m12_caldb *s,const unsigned char *data,size_t n) {
    if(!m12_caldb_owned(s) || !data || !n || n>s->capacity)return fail(s,-EINVAL);
    memmove(s->ram,data,n);s->size=(uint32_t)n;s->ram_valid=1;
    return 0;
}
int m12_caldb_begin(struct m12_caldb *s,unsigned char *ram,size_t cap,
                   uint32_t node,uint32_t port,uint64_t now,struct m12_caldb_packet *p) {
    memset(s,0,sizeof(*s));p->size=0;
    if(!ram || !cap || cap>M12_CALDB_MAX || !port)return fail(s,-EINVAL);
    s->ram=ram;s->capacity=cap;s->node=node;s->port=port;
    memset(ram,0,cap);s->phase=M12_DB_REGISTER;s->last_tick=now;
    int rc=request(s,p,6,now);if(rc)return rc;
    word(p,0x10,1); /* Mandatory optional flag supplied: daemon client ID1. */
    return finish(p);
}
static int name_ok(struct field f) {
    static const char name[]="wlfw_cal_db.bin";
    /* Top-level QMI_STRING is bare bytes, no embedded length or trailing NUL. */
    return f.n==sizeof(name)-1 && !memcmp(f.p,name,sizeof(name)-1);
}
static int download(struct m12_caldb *s,uint64_t now,struct m12_caldb_packet *p) {
    uint32_t remaining=s->size-s->offset;
    uint16_t chunk=(uint16_t)(remaining>M12_CALDB_SEGMENT?M12_CALDB_SEGMENT:remaining);
    int rc=request(s,p,3,now);if(rc)return rc;
    word(p,1,s->file_id);word(p,2,s->size);
    unsigned char end=chunk==remaining;tlv(p,3,&end,1);word(p,4,s->segment);
    unsigned char data[M12_CALDB_SEGMENT+2];put16(data,chunk);
    memcpy(data+2,s->ram+s->offset,chunk);tlv(p,5,data,(uint16_t)(chunk+2));
    return finish(p);
}
static int upload(struct m12_caldb *s,uint64_t now,struct m12_caldb_packet *p) {
    int rc=request(s,p,5,now);if(rc)return rc;
    word(p,1,s->file_id);word(p,2,s->segment);return finish(p);
}
int m12_caldb_receive(struct m12_caldb *s,uint32_t node,uint32_t port,
                     const unsigned char *b,size_t n,uint64_t now,struct m12_caldb_packet *p) {
    p->size=0;
    int rc=m12_caldb_tick(s,now);if(rc)return rc;
    if(node!=s->node || port!=s->port)return fail(s,-EACCES);
    if(!b || n<7 || n>M12_CALDB_WIRE || u16(b+5)!=n-7)return fail(s,-EPROTO);
    struct field f[17];uint32_t mask;
    if(fields(b+7,n-7,f,&mask))return fail(s,-EPROTO);
    unsigned kind=b[0];uint16_t txn=u16(b+1),msg=u16(b+3);
    if(kind==4) {
        /* Serial file service; reject interleaved transfers and indications
         * during startup. QMI indication transaction IDs have no request role. */
        if(!m12_caldb_owned(s) || (msg!=2 && msg!=4) || !name_ok(f[1]) ||
           f[2].n!=4 || mask!=(msg==2?6u:14u) || (msg==4 && f[3].n!=4))return fail(s,-EPROTO);
        s->file_id=u32(f[2].p);s->segment=0;s->offset=0;
        if(UINT64_MAX-now<9000)return fail(s,-EOVERFLOW);
        s->file_deadline=now+9000; /* Kernel file transaction allowance is10s. */
        if(msg==2) {
            /* Never invent an empty factory calibration or advertise a seed
             * we have not received. Missing RAM CalDB is a hard blocker. */
            if(!s->ram_valid || !s->size)return fail(s,-ENODATA);
            s->phase=M12_DB_DOWNLOAD;return download(s,now,p);
        }
        s->total=u32(f[3].p);
        if(!s->total || s->total>s->capacity)return fail(s,-EFBIG);
        s->phase=M12_DB_UPLOAD;s->pending_upload=1;s->ram_valid=0;s->size=0;
        memset(s->ram,0,s->capacity);return upload(s,now,p);
    }
    if(kind!=2 || !s->waiting_msg || msg!=s->waiting_msg || txn!=s->txn ||
       f[2].n!=4)return fail(s,-EPROTO);
    s->qmi_result=u16(f[2].p);s->qmi_error=u16(f[2].p+2);
    if(s->qmi_result || s->qmi_error)return fail(s,-EREMOTEIO);
    s->waiting_msg=0;s->deadline=0;
    switch(s->phase) {
    case M12_DB_REGISTER:
        if(msg!=6 || mask!=4u)return fail(s,-EPROTO);
        s->registered=1;s->phase=M12_DB_SETUP;
        if(request(s,p,1,now))return s->error;
        {
            unsigned char zero=0;tlv(p,1,&zero,1);tlv(p,2,&zero,1);word(p,3,0);
            /* No DMS MAC provision, no trace override, no available-file claim. */
        }
        return finish(p);
    case M12_DB_SETUP:
        if(msg!=1 || mask!=12u || f[3].n!=8)return fail(s,-EPROTO);
        s->driver_status=(uint64_t)u32(f[3].p)|(uint64_t)u32(f[3].p+4)<<32;
        /* The matched server leaves driver_status zero: NEVER CBC readiness. */
        s->setup_ack=1;s->phase=M12_DB_IDLE;return 0;
    case M12_DB_DOWNLOAD:
        if(msg!=3 || mask!=28u || f[3].n!=4 || f[4].n!=4 ||
           u32(f[3].p)!=s->file_id || u32(f[4].p)!=s->segment+1)return fail(s,-EPROTO);
        {
            uint32_t left=s->size-s->offset;
            s->offset+=left>M12_CALDB_SEGMENT?M12_CALDB_SEGMENT:left;s->segment++;
        }
        if(s->offset<s->size)return download(s,now,p);
        s->phase=M12_DB_IDLE;s->file_deadline=0;return 0;
    case M12_DB_UPLOAD:
        if(msg!=5 || mask!=124u || f[3].n!=4 || f[4].n!=1 || f[5].n!=4 || f[6].n<2 ||
           u32(f[3].p)!=s->file_id || u32(f[5].p)!=s->segment || f[4].p[0]>1)return fail(s,-EPROTO);
        {
            uint32_t len=u16(f[6].p),left=s->total-s->offset;
            uint32_t expected=left>M12_CALDB_SEGMENT?M12_CALDB_SEGMENT:left;
            if(len!=expected || f[6].n!=len+2 || f[4].p[0]!=(len==left))return fail(s,-EPROTO);
            memcpy(s->ram+s->offset,f[6].p+2,len);s->offset+=len;s->segment++;
            if(s->offset<s->total)return upload(s,now,p);
        }
        s->size=s->total;s->ram_valid=1;s->pending_upload=0;
        s->phase=M12_DB_IDLE;s->file_deadline=0;return 0;
    default:return fail(s,-EPROTO);
    }
}
