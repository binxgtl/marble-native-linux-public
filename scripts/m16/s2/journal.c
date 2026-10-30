/* SPDX-License-Identifier: GPL-2.0-only */
#include "journal.h"
#include <errno.h>
#include <string.h>
typedef unsigned long ulong;
#include "../../m11/anchor-native/p4/sha256.h"

static const char magic[8]={'M','1','6','J','1',0,0,0};

static void put16(unsigned char *p,uint16_t v) { p[0]=(unsigned char)v;p[1]=(unsigned char)(v>>8); }
void m16_put32(unsigned char *p,uint32_t v) { for(unsigned i=0;i<4;i++)p[i]=(unsigned char)(v>>(8*i)); }
void m16_put64(unsigned char *p,uint64_t v) { for(unsigned i=0;i<8;i++)p[i]=(unsigned char)(v>>(8*i)); }
static int nibble(char c) {
 if(c>='0'&&c<='9')return c-'0';
 if(c>='a'&&c<='f')return c-'a'+10;
 return -1;
}
void m16_hex(const unsigned char *p,size_t n,char *out) {
 static const char digits[]="0123456789abcdef";
 for(size_t i=0;i<n;i++){out[2*i]=digits[p[i]>>4];out[2*i+1]=digits[p[i]&15];}
}
/* Bytes 88..95 are always zero; the host requires that. */
static void encode(const struct m16_record *r,unsigned char out[M16_RECORD_SIZE]) {
 memset(out,0,M16_RECORD_SIZE);
 m16_put32(out,r->seq);put16(out+4,r->type);put16(out+6,r->length);
 m16_put64(out+8,r->boot_ns);m16_put64(out+16,r->mono_ns);
 memcpy(out+24,r->payload,M16_PAYLOAD);
 memcpy(out+M16_BODY_SIZE,r->chain,32);
}
static void link_hash(const unsigned char prev[32],const unsigned char body[M16_BODY_SIZE],unsigned char out[32]) {
 Sha256 s;char hex[65];
 sha_init(&s);sha_update(&s,(const char *)prev,32);sha_update(&s,(const char *)body,M16_BODY_SIZE);sha_hex(s,hex);
 for(unsigned i=0;i<32;i++)out[i]=(unsigned char)(nibble(hex[2*i])<<4|nibble(hex[2*i+1]));
}
static uint64_t gap(const struct m16_clock *c) { return c->boot_ns>c->mono_ns?c->boot_ns-c->mono_ns:0; }
int m16_clock_valid(const struct m16_clock *c) {
 return c&&c->boot_ns&&c->mono_ns&&c->boot_ns+M16_JITTER_NS>=c->mono_ns;
}
int m16_journal_init(struct m16_journal *j,struct m16_record *storage,uint32_t capacity,const unsigned char nonce[16]) {
 if(!j||!storage||!nonce||capacity<=M16_RESERVED)return -EINVAL;
 memset(j,0,sizeof(*j));
 memset(storage,0,(size_t)capacity*sizeof(*storage));
 j->records=storage;j->capacity=capacity;j->state=M16_J_OPEN;
 memcpy(j->nonce,nonce,16);
 /* The first link is bound to this run, so records cannot move between runs. */
 unsigned char seed[32]={0},body[M16_BODY_SIZE]={0};
 memcpy(seed,nonce,16);
 link_hash(seed,body,j->head);
 return 0;
}
static int ordered(const struct m16_journal *j,const struct m16_clock *c) {
 if(!m16_clock_valid(c))return 0;
 if(!j->have_clock)return 1;
 if(c->boot_ns<j->last_boot||c->mono_ns<j->last_mono)return 0;
 const struct m16_clock last={j->last_boot,j->last_mono};
 /* BOOTTIME minus MONOTONIC only grows, by sleep. Allow for the two-read pair. */
 return gap(c)+M16_JITTER_NS>=gap(&last);
}
static void write_record(struct m16_journal *j,enum m16_event type,const struct m16_clock *c,const void *payload,size_t n) {
 struct m16_record *r=&j->records[j->count];
 unsigned char body[M16_RECORD_SIZE];
 r->seq=j->count;r->type=(uint16_t)type;r->length=(uint16_t)n;
 r->boot_ns=c->boot_ns;r->mono_ns=c->mono_ns;
 memset(r->payload,0,M16_PAYLOAD);
 if(n)memcpy(r->payload,payload,n);
 memset(r->chain,0,32);
 encode(r,body);
 link_hash(j->head,body,r->chain);
 memcpy(j->head,r->chain,32);
 j->count++;j->last_boot=c->boot_ns;j->last_mono=c->mono_ns;j->have_clock=1;
}
int m16_journal_append(struct m16_journal *j,enum m16_event type,const struct m16_clock *c,const void *payload,size_t n) {
 if(!j||!c||type<M16_EV_OPEN||type>=M16_EV_LIMIT||type==M16_EV_SEAL||type==M16_EV_FAIL)return -EINVAL;
 if(n>M16_PAYLOAD||(n&&!payload))return -EINVAL;
 if(j->state!=M16_J_OPEN)return -EPERM;
 if(!ordered(j,c))return -ERANGE;
 if(j->count>=j->capacity-(type==M16_EV_CLEANUP?1u:M16_RESERVED))return -ENOSPC;
 write_record(j,type,c,payload,n);
 return 0;
}
int m16_journal_fail(struct m16_journal *j,uint32_t reason,int32_t error,uint32_t state) {
 if(!j)return -EINVAL;
 if(j->state!=M16_J_OPEN)return -EPERM;
 if(!j->have_clock)return -ENODATA;
 if(j->count>=j->capacity-2)return -ENOSPC;
 const struct m16_clock last={j->last_boot,j->last_mono};
 unsigned char p[12];
 m16_put32(p,reason);m16_put32(p+4,(uint32_t)error);m16_put32(p+8,state);
 write_record(j,M16_EV_FAIL,&last,p,sizeof(p));
 return 0;
}
int m16_journal_seal(struct m16_journal *j) {
 if(!j)return -EINVAL;
 if(j->state!=M16_J_OPEN)return -EPERM;
 if(!j->have_clock)return -ENODATA;
 if(j->count>=j->capacity)return -ENOSPC;
 const struct m16_clock last={j->last_boot,j->last_mono};
 unsigned char p[8];
 m16_put32(p,j->count);m16_put32(p+4,j->capacity);
 write_record(j,M16_EV_SEAL,&last,p,sizeof(p));
 j->state=M16_J_SEALED;
 return 0;
}
uint64_t m16_journal_wire_size(const struct m16_journal *j) {
 return j?M16_HEADER_SIZE+(uint64_t)j->count*M16_RECORD_SIZE:0;
}
static void header(const struct m16_journal *j,unsigned char *h) {
 memset(h,0,M16_HEADER_SIZE);
 memcpy(h,magic,sizeof(magic));
 m16_put32(h+8,M16_RECORD_SIZE);m16_put32(h+12,j->count);m16_put32(h+16,j->capacity);
 memcpy(h+20,j->nonce,16);memcpy(h+36,j->head,32);
}
int m16_journal_export(struct m16_journal *j,m16_sink sink,void *arg) {
 if(!j||!sink)return -1;
 if(j->state!=M16_J_SEALED&&j->state!=M16_J_ACKED)return -1;
 uint64_t total=m16_journal_wire_size(j),off=j->export_offset;
 if(off>=total)return 1;
 unsigned char block[M16_RECORD_SIZE];
 size_t have;uint64_t at;
 if(off<M16_HEADER_SIZE){header(j,block);have=M16_HEADER_SIZE;at=off;}
 else {
  uint64_t index=(off-M16_HEADER_SIZE)/M16_RECORD_SIZE;
  encode(&j->records[index],block);have=M16_RECORD_SIZE;at=(off-M16_HEADER_SIZE)%M16_RECORD_SIZE;
 }
 errno=0;
 ssize_t n=sink(arg,block+at,have-(size_t)at);
 if(n<0)return errno==EAGAIN||errno==EINTR?0:-1;
 if((size_t)n>have-(size_t)at)return -1;
 j->export_offset=off+(uint64_t)n;
 return j->export_offset>=total;
}
void m16_journal_rewind(struct m16_journal *j) { if(j)j->export_offset=0; }
int m16_journal_ack(struct m16_journal *j,const char hex[M16_ACK_HEX]) {
 if(!j||!hex)return -EINVAL;
 if(j->state!=M16_J_SEALED)return -EPERM;
 if(j->export_offset<m16_journal_wire_size(j))return -EPERM; /* cannot verify what was not sent */
 unsigned char want[32];
 for(unsigned i=0;i<32;i++){
  int a=nibble(hex[2*i]),b=nibble(hex[2*i+1]);
  if(a<0||b<0){j->ack_failures++;return -EBADMSG;}
  want[i]=(unsigned char)(a<<4|b);
 }
 if(memcmp(want,j->head,32)){j->ack_failures++;return -EBADMSG;}
 j->state=M16_J_ACKED;
 return 0;
}
int m16_journal_release(struct m16_journal *j) {
 if(!j)return -EINVAL;
 if(j->state!=M16_J_ACKED)return -EBUSY;
 memset(j->records,0,(size_t)j->capacity*sizeof(*j->records));
 j->count=0;j->state=M16_J_RELEASED;
 return 0;
}
