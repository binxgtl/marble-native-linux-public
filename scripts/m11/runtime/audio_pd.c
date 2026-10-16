/* Minimal strict SERVREG v1 codec. Protocol references and stock applicability:
 * docs/m11-audio-pd-ownership.md. Independently written; no vendor code copied. */
#include "audio_pd.h"
#include <string.h>

#define CTRL 0xfffffffeu
#define INSTANCE ((M11_PD_INSTANCE << 8) | 1u)
static uint16_t u16(const unsigned char *p) { return (uint16_t)(p[0] | (unsigned)p[1]<<8); }
static uint32_t u32(const unsigned char *p) { return (uint32_t)u16(p) | (uint32_t)u16(p+2)<<16; }
static void p16(unsigned char *p, uint16_t n) { p[0]=(unsigned char)n; p[1]=(unsigned char)(n>>8); }
static void p32(unsigned char *p, uint32_t n) { p16(p,(uint16_t)n); p16(p+2,(uint16_t)(n>>16)); }
void m11_pd_fail(struct m11_pd *p, enum m11_pd_fault f) {
    if (!p->invalid) p->fault=f;
    p->invalid=1; p->phase=M11_PD_INVALID;
}
static int bad(struct m11_pd *p, enum m11_pd_fault f) { m11_pd_fail(p,f); return -1; }
static int record(struct m11_pd *p, int tx, uint32_t node, uint32_t port, const void *b, size_t n) {
    if (p->count==M11_PD_RECORDS || n>M11_PD_WIRE_MAX) {
        p->truncated=1; return bad(p,M11_PD_OVERFLOW);
    }
    struct m11_pd_record *r=&p->records[p->count++];
    r->ns=p->now; r->tx=(uint32_t)tx; r->node=node; r->port=port; r->size=(uint32_t)n;
    r->rc=tx?-1:(int)n;
    memcpy(r->bytes,b,n); return 0;
}
static int send_packet(struct m11_pd *p, uint32_t node, uint32_t port, const void *b, size_t n) {
    if (record(p,1,node,port,b,n)) return -1;
    int rc=p->send(p->context,node,port,b,n);
    p->records[p->count-1].rc=rc;
    if (rc) return bad(p,M11_PD_IO);
    return 0;
}
static int lookup(struct m11_pd *p, uint32_t cmd) {
    unsigned char b[20]={0}; p32(b,cmd); p32(b+4,0x42); p32(b+8,INSTANCE);
    if (cmd==11) { p32(b+12,p->local_node); p32(b+16,p->local_port); }
    return send_packet(p,p->local_node,CTRL,b,sizeof(b));
}
static uint16_t txn(struct m11_pd *p) {
    /* Bounded transcript ensures no wrap/reuse is needed. */
    if (!p->next_txn || p->next_txn==65535) { bad(p,M11_PD_OVERFLOW); return 0; }
    return p->next_txn++;
}
static size_t tlv(unsigned char *b, unsigned char t, const void *v, size_t n) {
    b[0]=t; p16(b+1,(uint16_t)n); memcpy(b+3,v,n); return n+3;
}
static int request(struct m11_pd *p, uint16_t id, uint16_t t, unsigned char *b, size_t n) {
    b[0]=0; p16(b+1,t); p16(b+3,id); p16(b+5,(uint16_t)(n-7));
    return send_packet(p,p->node,p->port,b,n);
}
static int registration(struct m11_pd *p, int enable) {
    unsigned char b[M11_PD_WIRE_MAX]={0}, e=(unsigned char)enable;
    size_t n=7; n+=tlv(b+n,1,&e,1); n+=tlv(b+n,2,M11_PD_PATH,sizeof(M11_PD_PATH)-1);
    p->register_txn=txn(p); if (!p->register_txn) return -1;
    p->register_deadline=p->now+2000000000ULL;
    return request(p,0x20,p->register_txn,b,n);
}
static int ack(struct m11_pd *p) {
    unsigned char b[M11_PD_WIRE_MAX]={0}, t[2]; p16(t,p->indication_txn);
    size_t n=7; n+=tlv(b+n,1,M11_PD_PATH,sizeof(M11_PD_PATH)-1); n+=tlv(b+n,2,t,2);
    p->ack_txn=txn(p); if (!p->ack_txn) return -1;
    p->ack_deferred=0; p->ack_deadline=p->now+2000000000ULL;
    return request(p,0x23,p->ack_txn,b,n);
}
int m11_pd_tick(struct m11_pd *p, uint64_t now) {
    if (now<p->now) return bad(p,M11_PD_CLOCK);
    p->now=now;
    if (p->phase==M11_PD_STOPPED) return 0;
    if (now>=p->deadline || (p->register_txn && now>=p->register_deadline) ||
        (p->ack_txn && now>=p->ack_deadline))
        return bad(p,M11_PD_DEADLINE);
    return p->invalid?-1:0;
}
int m11_pd_begin(struct m11_pd *p, uint32_t node, uint32_t port, uint64_t now, uint64_t deadline,
                 int (*send)(void *,uint32_t,uint32_t,const void *,size_t), void *ctx) {
    memset(p,0,sizeof(*p)); p->phase=M11_PD_DISCOVERY; p->now=now; p->deadline=deadline;
    p->local_node=node; p->local_port=port; p->next_txn=1; p->send=send; p->context=ctx;
    if (!send || !port || port>=CTRL || deadline<=now || deadline-now>10000000000ULL)
        return bad(p,M11_PD_MALFORMED);
    return lookup(p,10);
}
struct value { const unsigned char *b; size_t n; };
/* Reject duplicate/unknown TLVs, truncation and trailing bytes. Strings in
 * top-level QMI_STRING TLVs have no inner length or terminating NUL. */
static int values(const unsigned char *b, size_t n, struct value v[256]) {
    memset(v,0,256*sizeof(*v));
    for (size_t pos=7;pos<n;) {
        if (n-pos<3) return -1;
        unsigned t=b[pos]; size_t len=u16(b+pos+1); pos+=3;
        if (v[t].b || len>n-pos) return -1;
        v[t].b=b+pos; v[t].n=len; pos+=len;
    }
    return 0;
}
static int only(const struct value v[256], unsigned a, unsigned b, unsigned c) {
    for (unsigned i=0;i<256;i++) if (v[i].b && i!=a && i!=b && i!=c) return 0;
    return 1;
}
static int result_ok(const struct value *v) { return v->b && v->n==4 && !u32(v->b); }
static int path_ok(const struct value *v) {
    return v->b && v->n==sizeof(M11_PD_PATH)-1 && !memcmp(v->b,M11_PD_PATH,v->n);
}
static int valid_state(uint32_t s) {
    return s==M11_PD_UP || s==M11_PD_DOWN || s==0x2fffffff || s==0x7fffffff;
}
static void state(struct m11_pd *p, uint32_t s) {
    p->state=s;
    if (s!=M11_PD_UP && (p->ever_ready || p->resources_busy)) m11_pd_fail(p,M11_PD_NOT_UP);
    if (!p->invalid && !p->stopping && p->registered && !p->register_txn && !p->ack_txn && !p->ack_deferred) {
        p->phase=s==M11_PD_UP?M11_PD_READY:M11_PD_WAIT_UP;
        if (p->phase==M11_PD_READY) p->ever_ready=1;
    }
}
int m11_pd_receive(struct m11_pd *p, uint32_t node, uint32_t port, const void *data, size_t n, uint64_t now) {
    const unsigned char *b=data;
    /* An invalidated session can still ACK cleanup/unregister, never regain UP. */
    if (now<p->now) return bad(p,M11_PD_CLOCK);
    if (now>=p->deadline || (p->register_txn && now>=p->register_deadline) ||
        (p->ack_txn && now>=p->ack_deadline))
        return bad(p,M11_PD_DEADLINE);
    p->now=now;
    if (!data) return bad(p,M11_PD_MALFORMED);
    if (record(p,0,node,port,b,n)) return -1;
    if (port==CTRL) {
        if (node!=p->local_node || n!=20) return bad(p,M11_PD_MALFORMED);
        uint32_t cmd=u32(b), service=u32(b+4), inst=u32(b+8), peer=u32(b+12), pp=u32(b+16);
        if (cmd==4 && !service && !inst && !peer && !pp) return 0; /* lookup end */
        if ((cmd==4 || cmd==5) && service==0x42 && inst==INSTANCE && peer!=p->local_node && pp && pp<CTRL) {
            if (cmd==5) return bad(p,M11_PD_PEER_LOST);
            if (p->peer) return peer==p->node && pp==p->port?0:bad(p,M11_PD_PEER_LOST);
            if (p->invalid || p->stopping) return -1;
            p->peer=1; p->node=peer; p->port=pp; p->phase=M11_PD_REGISTERING;
            return registration(p,1);
        }
        /* BYE/DEL_CLIENT/unknown control: loss cannot be interpreted as UP. */
        return bad(p,M11_PD_PEER_LOST);
    }
    if (!p->peer || node!=p->node || port!=p->port || n<7 || n>M11_PD_WIRE_MAX || u16(b+5)!=n-7)
        return bad(p,M11_PD_MALFORMED);
    struct value v[256];
    if (values(b,n,v)) return bad(p,M11_PD_MALFORMED);
    uint16_t id=u16(b+3), t=u16(b+1);
    if (b[0]==2 && id==0x20 && t && t==p->register_txn) {
        if (!only(v,2,16,2) || !result_ok(&v[2])) return bad(p,M11_PD_MALFORMED);
        p->register_txn=0;
        if (p->unregister_sent) { p->unregister_ok=1; p->registered=0; return 0; }
        if (!v[16].b || v[16].n!=4 || !valid_state(u32(v[16].b))) return bad(p,M11_PD_MALFORMED);
        p->registered=1;
        /* Indication wins over a delayed registration snapshot. */
        state(p,p->saw_indication?p->indication_state:u32(v[16].b)); return 0;
    }
    if (b[0]==4 && id==0x22) {
        if (!only(v,1,2,3) || !v[1].b || v[1].n!=4 || !path_ok(&v[2]) ||
            !v[3].b || v[3].n!=2 || !valid_state(u32(v[1].b)) || p->ack_txn || p->ack_deferred || p->unregister_ok)
            return bad(p,M11_PD_MALFORMED);
        p->saw_indication=1; p->indication_txn=u16(v[3].b); p->indication_state=u32(v[1].b);
        p->ack_deferred=1; state(p,p->indication_state);
        if (!p->invalid) p->phase=M11_PD_WAIT_UP; /* UP waits for ACK response. */
        if (p->resources_busy && p->indication_state!=M11_PD_UP) return 0;
        return ack(p);
    }
    if (b[0]==2 && id==0x23 && t && t==p->ack_txn) {
        if (!only(v,2,2,2) || !result_ok(&v[2])) return bad(p,M11_PD_MALFORMED);
        p->ack_txn=0; state(p,p->indication_state); return 0;
    }
    return bad(p,M11_PD_MALFORMED);
}
int m11_pd_resources_released(struct m11_pd *p) {
    p->resources_busy=0;
    return p->ack_deferred?ack(p):0;
}
int m11_pd_stop(struct m11_pd *p, uint64_t now, uint64_t deadline) {
    if (p->phase==M11_PD_STOPPED) return 0;
    if (p->resources_busy) return bad(p,M11_PD_UNRESOLVED);
    if (now<p->now || deadline<=now || deadline-now>2000000000ULL) return bad(p,M11_PD_CLOCK);
    p->stopping=1; p->now=now; p->deadline=deadline;
    if (p->ack_deferred && ack(p)) return -1;
    if (p->ack_txn || p->register_txn) return 1; /* caller pumps until deadline */
    if (p->peer && !p->unregister_sent) {
        p->unregister_sent=1; p->phase=M11_PD_UNREGISTERING;
        return registration(p,0)?-1:1;
    }
    if (p->peer && !p->unregister_ok) return 1;
    if (lookup(p,11)) return -1;
    p->lookup_removed=1; p->phase=M11_PD_STOPPED; return 0;
}
