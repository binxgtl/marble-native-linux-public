/* SPDX-License-Identifier: GPL-2.0-only */
#include "escrow.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
typedef unsigned long ulong;
#include "../../m11/anchor-native/p4/sha256.h"
#define CHUNK 1024u
#define OWNERS 16u
struct blob { unsigned char *p; size_t n,cap; char hash[65]; };
struct cursor { unsigned phase,file; size_t off,used; uint64_t sequence; };
struct owner { uint64_t id; int reaped,status; };
struct m15 {
 enum m15_state state; const char *error; uint64_t now,until;
 struct blob files[M15_FILES]; struct owner owners[OWNERS]; unsigned count;
 int frozen,census_active; unsigned char nonce[16]; char noncehex[33],binding[65];
 char manifest[1024],manifest_hash[65],transfer_hash[65],final[256];
 size_t manifest_n,final_n; uint64_t frames,bytes,accepted;
 struct cursor cursor; Sha256 accepted_hash;
};
static const char terminal[]="{\"schema\":\"M15O3-supervisor\",\"reaped\":true,\"raw_status\":0,\"errno\":0,\"control_permitted\":false}\n";
static void hex(Sha256 s,char out[65]) { sha_hex(s,out);out[64]=0; }
static void hash(const void *p,size_t n,char out[65]) { Sha256 s;sha_init(&s);sha_update(&s,p,n);hex(s,out); }
void m15_poison(struct m15 *s,const char *reason) {
 if(s && s->state!=M15_HOLD){s->error=reason;s->state=M15_HOLD;}
}
static int fail(struct m15 *s,const char *reason) { m15_poison(s,reason);return -1; }
static int clock_ok(struct m15 *s,uint64_t now) {
 if(!s || s->state==M15_HOLD)return -1;
 if(now<s->now)return fail(s,"clock-regression");
 s->now=now;
 if(s->state!=M15_RECOVERED && now>=s->until)return fail(s,"deadline");
 return 0;
}
static int state_ok(struct m15 *s,enum m15_state state,uint64_t now) {
 if(clock_ok(s,now))return -1;
 return s->state==state?0:fail(s,"state-order");
}
static int set_state(struct m15 *s,enum m15_state state,uint64_t now,uint64_t budget) {
 if(UINT64_MAX-now<budget)return fail(s,"clock-overflow");
 s->state=state;s->until=now+budget;return 0;
}
static int append(struct m15 *s,unsigned file,const void *p,size_t n) {
 struct blob *b=&s->files[file];
 if(n>b->cap-b->n)return fail(s,"ram-exhausted");
 if(n)memcpy(b->p+b->n,p,n);
 b->n+=n;return 0;
}
static int event(struct m15 *s,const char *name,uint64_t id,int status,uint64_t now) {
 char b[160];int n=snprintf(b,sizeof(b),"%llu %s %llu %d\n",(unsigned long long)now,name,(unsigned long long)id,status);
 if(n<0 || (size_t)n>=sizeof(b))return fail(s,"event-overflow");
 return append(s,M15_JOURNAL,b,(size_t)n);
}
struct m15 *m15_create(const unsigned char nonce[16],const void *metadata,size_t n,
                       struct m15_limits l,uint64_t now) {
 if(!nonce || !metadata || !n || n>8192 || !l.raw || !l.error || !l.journal || !l.kernel || l.total>16u*1024*1024)return NULL;
 size_t caps[M15_FILES]={l.raw,l.error,l.journal,n,256,l.kernel};
 size_t sum=sizeof(struct m15);
 for(unsigned i=0;i<M15_FILES;i++){if(caps[i]>l.total || sum>l.total-caps[i])return NULL;sum+=caps[i];}
 unsigned nonzero=0;for(unsigned i=0;i<16;i++)nonzero|=nonce[i];if(!nonzero)return NULL;
 struct m15 *s=calloc(1,sizeof(*s));if(!s)return NULL;
 for(unsigned i=0;i<M15_FILES;i++) {
  s->files[i].cap=caps[i];s->files[i].p=malloc(caps[i]);
  if(!s->files[i].p){m15_destroy(s);return NULL;}
 }
 memcpy(s->nonce,nonce,16);const char *digits="0123456789abcdef";
 for(unsigned i=0;i<16;i++){s->noncehex[2*i]=digits[nonce[i]>>4];s->noncehex[2*i+1]=digits[nonce[i]&15];}
 s->noncehex[32]=0;hash(metadata,n,s->binding);s->now=now;
 if(append(s,M15_METADATA,metadata,n) || set_state(s,M15_PC,now,300000) || event(s,"PC_WAIT",0,0,now)){m15_destroy(s);return NULL;}
 return s;
}
int m15_ownership_clear(const struct m15 *s) {
 if(!s || s->census_active)return 0;
 for(unsigned i=0;i<s->count;i++)if(!s->owners[i].reaped)return 0;
 return 1;
}
void m15_destroy(struct m15 *s) {
 if(!s)return;
 if(!m15_ownership_clear(s)){m15_poison(s,"release-unresolved-owner");return;}
 for(unsigned i=0;i<M15_FILES;i++)free(s->files[i].p);
 free(s);
}
enum m15_state m15_state(const struct m15 *s) { return s?s->state:M15_HOLD; }
const char *m15_error(const struct m15 *s) { return s?s->error:"allocation"; }
void m15_binding(const struct m15 *s,char out[65]) { memcpy(out,s->binding,65); }
static int receipt(struct m15 *s,const void *p,size_t n,const char *expected) {
 size_t wanted=strlen(expected);
 return p && n==wanted && !memcmp(p,expected,n)?0:fail(s,"receipt-mismatch");
}
int m15_pc_receipt(struct m15 *s,const void *p,size_t n,uint64_t now) {
 if(state_ok(s,M15_PC,now))return -1;
 char b[160];snprintf(b,sizeof(b),"M15PC1 %s %s\n",s->noncehex,s->binding);
 if(receipt(s,p,n,b) || event(s,"PC_ACK",0,0,now))return -1;
 return set_state(s,M15_ISOLATE,now,10000);
}
int m15_isolated(struct m15 *s,int reaped,int unbound,uint64_t now) {
 if(state_ok(s,M15_ISOLATE,now))return -1;
 if(reaped!=1 || unbound!=1)return fail(s,"isolation-unproven");
 if(event(s,"ISOLATED",0,0,now))return -1;
 return set_state(s,M15_WALL,now,300000);
}
int m15_wall(struct m15 *s,int absent,int wall,uint64_t now) {
 if(state_ok(s,M15_WALL,now))return -1;
 if(absent!=1 || wall!=1)return fail(s,"connector-contract");
 if(event(s,"COLLECT",0,0,now))return -1;
 return set_state(s,M15_COLLECT,now,100000);
}
int m15_owner_add(struct m15 *s,uint64_t id,uint64_t now) {
 if(state_ok(s,M15_COLLECT,now))return -1;
 if(!id || s->count==OWNERS)return fail(s,"owner-limit");
 for(unsigned i=0;i<s->count;i++)if(s->owners[i].id==id)return fail(s,"duplicate-owner");
 s->owners[s->count++]=(struct owner){id,0,0};return event(s,"OWN",id,0,now);
}
int m15_census_begin(struct m15 *s) {
 if(!s || s->state!=M15_COLLECT || s->count || s->census_active)return -1;
 s->census_active=1;return 0;
}
void m15_census_closed(struct m15 *s) { if(s)s->census_active=0; }
int m15_owner_reaped(struct m15 *s,uint64_t id,int raw_wait,uint64_t now) {
 if(!s || s->frozen)return -1;
 /* Reap facts remain recordable after failure; never clear the sticky hold. */
 for(unsigned i=0;i<s->count;i++)if(s->owners[i].id==id && !s->owners[i].reaped) {
  if(!WIFEXITED(raw_wait) && !WIFSIGNALED(raw_wait))return fail(s,"nonterminal-wait");
  s->owners[i].reaped=1;s->owners[i].status=raw_wait;
  return event(s,"REAP",id,raw_wait,now);
 }
 return fail(s,"unknown-or-double-reap");
}
int m15_append(struct m15 *s,enum m15_file file,const void *p,size_t n) {
 if(!s || s->frozen || s->state!=M15_COLLECT)return -1;
 if(file!=M15_RAW && file!=M15_STDERR && file!=M15_KERNEL)return fail(s,"file-contract");
 if(n && !p)return fail(s,"null-bytes");
 return append(s,(unsigned)file,p,n);
}
static int next(const struct m15 *s,struct cursor *c,char temp[128],const void **p,size_t *n) {
 if(c->phase==4)return 0;
 if(c->phase==0){*p=s->manifest;*n=s->manifest_n;return 1;}
 while(c->file<M15_FILES && c->off==s->files[c->file].n){c->file++;c->off=0;}
 if(c->file==M15_FILES)c->phase=3;
 if(c->phase==3){*p=s->final;*n=s->final_n;return 1;}
 size_t left=s->files[c->file].n-c->off;if(left>CHUNK)left=CHUNK;
 if(c->phase==1){int k=snprintf(temp,128,"D %llu %u %zu %zu\n",(unsigned long long)c->sequence,c->file,c->off,left);if(k<0 || k>=128)return -1;*p=temp;*n=(size_t)k;}
 else {*p=s->files[c->file].p+c->off;*n=left;}
 return 1;
}
static void advance(const struct m15 *s,struct cursor *c,size_t n) {
 c->used=0;
 if(c->phase==0)c->phase=1;
 else if(c->phase==1)c->phase=2;
 else if(c->phase==2){c->off+=n;c->sequence++;c->phase=1;}
 else if(c->phase==3){c->phase=4;c->file=M15_FILES;}
 (void)s;
}
static void transfer_hash(Sha256 digest,uint64_t frames,uint64_t bytes,const char *manifest,char out[65]) {
 char suffix[192];int n=snprintf(suffix,sizeof(suffix),"M15E1 FINAL\nframes=%llu bytes=%llu manifest=%s\n",(unsigned long long)frames,(unsigned long long)bytes,manifest);
 sha_update(&digest,suffix,(ulong)n);hex(digest,out);
}
int m15_finish(struct m15 *s,int wait_status,int census_closed,uint64_t now) {
 if(state_ok(s,M15_COLLECT,now))return -1;
 if(!s->count || !m15_ownership_clear(s) || census_closed!=1)return fail(s,"ownership-unresolved");
 if(wait_status!=s->owners[0].status)return fail(s,"collector-wait-mismatch");
 for(unsigned i=0;i<s->count;i++)if(s->owners[i].status!=0)return fail(s,"descendant-failure");
 if(!WIFEXITED(wait_status) || WEXITSTATUS(wait_status)!=0 || s->files[M15_STDERR].n)return fail(s,"collector-failure");
 struct blob *raw=&s->files[M15_RAW];size_t tail=sizeof(terminal)-1;
 if(raw->n<tail || memcmp(raw->p+raw->n-tail,terminal,tail))return fail(s,"incomplete-supervisor-receipt");
 if(event(s,"FREEZE",0,wait_status,now))return -1;
 char status[128];int k=snprintf(status,sizeof(status),"wait_status=%d\ntracked=%u\nreaped=%u\ncensus_closed=1\n",wait_status,s->count,s->count);
 if(append(s,M15_STATUS,status,(size_t)k))return -1;
 int used=snprintf(s->manifest,sizeof(s->manifest),"M15E1 %s %s %u\n",s->noncehex,s->binding,M15_FILES);
 for(unsigned i=0;i<M15_FILES;i++){
  hash(s->files[i].p,s->files[i].n,s->files[i].hash);
  k=snprintf(s->manifest+used,sizeof(s->manifest)-(size_t)used,"I %u %zu %s\n",i,s->files[i].n,s->files[i].hash);
  if(k<0 || (size_t)k>=sizeof(s->manifest)-(size_t)used)return fail(s,"manifest-overflow");
  used+=k;
 }
 memcpy(s->manifest+used,"END\n",4);s->manifest_n=(size_t)used+4;
 hash(s->manifest,s->manifest_n,s->manifest_hash);
 struct cursor c={0};Sha256 digest;sha_init(&digest);
 while(c.phase!=3){char t[128];const void *p;size_t n;
  if(next(s,&c,t,&p,&n)<0)return fail(s,"serialization");
  if(c.phase==3)break;
  sha_update(&digest,p,n);s->bytes+=n;advance(s,&c,n);
 }
 s->frames=c.sequence;transfer_hash(digest,s->frames,s->bytes,s->manifest_hash,s->transfer_hash);
 k=snprintf(s->final,sizeof(s->final),"F %llu %llu %s %s\n",(unsigned long long)s->frames,(unsigned long long)s->bytes,s->manifest_hash,s->transfer_hash);
 s->final_n=(size_t)k;s->frozen=1;sha_init(&s->accepted_hash);
 return set_state(s,M15_RECONNECT,now,300000);
}
int m15_reconnect(struct m15 *s,int pc,uint64_t now) {
 if(state_ok(s,M15_RECONNECT,now))return -1;
 if(pc!=1)return fail(s,"reconnect-failed");
 return set_state(s,M15_EXPORT,now,300000);
}
int m15_export_step(struct m15 *s,m15_sink sink,void *arg,uint64_t now) {
 if(state_ok(s,M15_EXPORT,now))return -1;
 if(!sink)return fail(s,"missing-nonblocking-sink");
 char t[128];const void *p;size_t n;
 if(next(s,&s->cursor,t,&p,&n)<=0 || s->cursor.used>=n)return fail(s,"export-cursor");
 size_t remaining=n-s->cursor.used;
 errno=0;ssize_t sent=sink(arg,(const char *)p+s->cursor.used,remaining);
 if(sent<0 && (errno==EINTR || errno==EAGAIN))return 0;
 if(sent<=0 || (size_t)sent>remaining)return fail(s,"export-write-failed");
 if(s->cursor.phase!=3)sha_update(&s->accepted_hash,(const char *)p+s->cursor.used,(ulong)sent);
 s->accepted+=(uint64_t)sent;s->cursor.used+=(size_t)sent;
 if(s->cursor.used==n)advance(s,&s->cursor,n);
 if(s->cursor.phase==4){
  char digest[65];transfer_hash(s->accepted_hash,s->frames,s->bytes,s->manifest_hash,digest);
  if(strcmp(digest,s->transfer_hash))return fail(s,"accepted-bytes-mismatch");
  if(set_state(s,M15_ACK,now,30000))return -1;
  return 1;
 }
 return 0;
}
int m15_host_ack(struct m15 *s,const void *p,size_t n,uint64_t now) {
 if(state_ok(s,M15_ACK,now))return -1;
 char b[256];snprintf(b,sizeof(b),"M15ACK1 %s %s %s\n",s->noncehex,s->manifest_hash,s->transfer_hash);
 if(receipt(s,p,n,b))return -1;
 if(!m15_ownership_clear(s))return fail(s,"ownership-after-export");
 return set_state(s,M15_RECOVERED,now,0);
}
int m15_tick(struct m15 *s,uint64_t now) { return clock_ok(s,now); }
const unsigned char *m15_evidence(const struct m15 *s,enum m15_file file,size_t *n) {
 if(!s || (unsigned)file>=M15_FILES)return NULL;
 *n=s->files[file].n;return s->files[file].p;
}
uint64_t m15_accepted_bytes(const struct m15 *s) { return s?s->accepted:0; }
