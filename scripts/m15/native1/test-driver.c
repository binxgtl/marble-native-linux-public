/* SPDX-License-Identifier: GPL-2.0-only */
/* TEST ONLY: synthetic paths/connector events. Not a native PID1 or USB opener. */
#define _GNU_SOURCE
#include "escrow.h"
#include "supervise.h"
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
struct bytes { unsigned char *p;size_t n; };
static struct bytes load(const char *path) {
 FILE *f=fopen(path,"rb");assert(f);assert(!fseek(f,0,SEEK_END));long n=ftell(f);assert(n>=0 && n<2000000);rewind(f);
 unsigned char *p=malloc((size_t)n+1);assert(p);assert(fread(p,1,(size_t)n,f)==(size_t)n);assert(!fclose(f));return (struct bytes){p,(size_t)n};
}
struct sink { FILE *out;const char *mode;unsigned calls; };
static ssize_t sink(void *arg,const void *p,size_t n) {
 struct sink *s=arg;s->calls++;
 if(!strcmp(s->mode,"disconnect") || (!strcmp(s->mode,"short-fail") && s->calls>4)){errno=EIO;return -1;}
 if(!strcmp(s->mode,"zero-write"))return 0;
 if(!strcmp(s->mode,"overreported-write"))return (ssize_t)n+1;
 if(!strcmp(s->mode,"eintr") && s->calls==1){errno=EINTR;return -1;}
 if(!strcmp(s->mode,"eagain") && s->calls==1){errno=EAGAIN;return -1;}
 if((!strcmp(s->mode,"short") || !strcmp(s->mode,"short-fail")) && n>3)n=3;
 if(!strcmp(s->mode,"stall")){errno=EAGAIN;return -1;}
 size_t done=fwrite(p,1,n,s->out);return done?(ssize_t)done:-1;
}
struct childargs { const char *mode,*observer,*fixture;const struct bytes *raw; };
static void child(void *arg) {
 struct childargs *a=arg;
 if(!strcmp(a->mode,"process") || !strcmp(a->mode,"closed-stdio")) {
  execl(a->observer,"observer","--fixture-root",a->fixture,"--samples","3","--interval-ms","1000","--deadline-ms","90000",(char *)NULL);_exit(127);
 }
 if(!strcmp(a->mode,"worker-crash")){assert(write(1,"prefix\n",7)==7);raise(SIGKILL);_exit(128);}
 if(!strcmp(a->mode,"getter-block")){assert(write(1,"read_begin fixture\n",19)==19);for(;;)pause();}
 assert(!strcmp(a->mode,"orphan-process"));
 pid_t p=fork();assert(p>=0);
 if(!p){assert(setsid()>0);for(;;)pause();}
 assert(write(1,a->raw->p,a->raw->n)==(ssize_t)a->raw->n);_exit(0);
}
int main(int argc,char **argv) {
 assert(argc==7 || argc==9);
 const char *mode=argv[1];struct bytes raw=load(argv[2]),meta=load(argv[3]);
 struct m15_limits limits={131072,8192,16384,4096,300000};
 if(!strcmp(mode,"tiny-journal"))limits.journal=60;
 unsigned char nonce[16];for(unsigned i=0;i<16;i++)nonce[i]=(unsigned char)(i+1);
 struct m15 *s=m15_create(nonce,meta.p,meta.n,limits,0);assert(s);
 char binding[65],pc[160];m15_binding(s,binding);
 int n=snprintf(pc,sizeof(pc),"M15PC1 0102030405060708090a0b0c0d0e0f10 %s\n",binding);
 uint64_t now=1;
 if(!strcmp(mode,"missing-pc")){m15_tick(s,300000);goto output;}
 if(!strcmp(mode,"bad-pc"))pc[8]='f';
 if(m15_pc_receipt(s,pc,(size_t)n,now++))goto output;
 if(!strcmp(mode,"pc-replay")){m15_pc_receipt(s,pc,(size_t)n,now++);goto output;}
 if(m15_isolated(s,1,strcmp(mode,"bad-unbind")!=0,now++))goto output;
 if(m15_wall(s,strcmp(mode,"pc-present")!=0,1,now++))goto output;
 struct m15_process_result r={0};
 if(!strcmp(mode,"ambient-child")) {
  pid_t ambient=fork();assert(ambient>=0);if(!ambient)for(;;)pause();
  assert(m15_supervise(s,child,NULL,100,now,&r)==-1);
  assert(kill(ambient,SIGKILL)==0);int waited;assert(waitpid(ambient,&waited,0)==ambient);
  goto output;
 }
 if(!strcmp(mode,"process") || !strcmp(mode,"closed-stdio") || !strcmp(mode,"worker-crash") || !strcmp(mode,"getter-block") || !strcmp(mode,"orphan-process")) {
  assert(argc==9);struct childargs args={mode,argv[7],argv[8],&raw};
  if(!strcmp(mode,"closed-stdio")){close(0);close(1);close(2);}
  int rc=m15_supervise(s,child,&args,!strcmp(mode,"getter-block")?25u:5000u,now,&r);
  now+=r.elapsed_ms+1;
  if(rc || m15_finish(s,r.raw_wait,r.census_closed,now++))goto export_if_ready;
 } else {
  if(m15_owner_add(s,1001,now++))goto resolve;
  if(!strcmp(mode,"ram-exhausted")){
   assert(!m15_append(s,M15_RAW,raw.p,512));
   unsigned char *p=calloc(1,limits.raw);assert(p);m15_append(s,M15_RAW,p,limits.raw);free(p);goto resolve;
  }
  if(!strcmp(mode,"kernel-overflow")){char p[4097]={0};m15_append(s,M15_KERNEL,p,sizeof(p));goto resolve;}
  if(m15_append(s,M15_RAW,raw.p,raw.n))goto resolve;
  if(!strcmp(mode,"stderr")){m15_append(s,M15_STDERR,"error\n",6);}
  if(!strcmp(mode,"orphan-owner")){m15_owner_add(s,1002,now++);m15_owner_reaped(s,1001,0,now++);m15_finish(s,0,0,now++);goto resolve;}
  if(!strcmp(mode,"blocked-owner")){m15_tick(s,100004);goto resolve;}
  if(!strcmp(mode,"nonterminal-wait")){m15_owner_reaped(s,1001,0x137f,now++);goto resolve;}
  if(m15_owner_reaped(s,1001,!strcmp(mode,"exit-error")?256:0,now++))goto resolve;
  if(!strcmp(mode,"double-reap")){m15_owner_reaped(s,1001,0,now++);goto output;}
  if(m15_finish(s,!strcmp(mode,"exit-error")?256:0,1,now++))goto output;
 }
export_if_ready:
 if(m15_state(s)!=M15_RECONNECT)goto output;
 if(!strcmp(mode,"frozen-append")){assert(m15_append(s,M15_RAW,"x",1)==-1);}
 if(!strcmp(mode,"frozen-corrupt")){size_t len;unsigned char *p=(unsigned char *)m15_evidence(s,M15_RAW,&len);assert(len);p[0]^=1;}
 if(!strcmp(mode,"reconnect-timeout")){m15_tick(s,now+300000);goto output;}
 if(m15_reconnect(s,strcmp(mode,"reconnect-failed")!=0,now++))goto output;
 {
  FILE *f=fopen(argv[4],"wb");assert(f);struct sink target={f,mode,0};int rc=0;
  while(m15_state(s)==M15_EXPORT && target.calls<100000){rc=m15_export_step(s,sink,&target,now++);if(rc)break;}
  assert(!fclose(f));
  if(!strcmp(mode,"stall"))m15_tick(s,now+300000);
  if(!strcmp(mode,"ack-timeout") && m15_state(s)==M15_ACK)m15_tick(s,now+30000);
  if(strcmp(argv[5],"-") && m15_state(s)==M15_ACK){struct bytes ack=load(argv[5]);m15_host_ack(s,ack.p,ack.n,now++);free(ack.p);}
 }
 goto output;
resolve:
 /* Test teardown only: explicit terminal facts after the assertion state was
  * poisoned. Never clear the hold or claim kernel hardware quiescence. */
 if(!m15_ownership_clear(s)){
  m15_owner_reaped(s,1001,SIGKILL,now++);
  if(!strcmp(mode,"orphan-owner"))m15_owner_reaped(s,1002,SIGKILL,now++);
 }
output:
 {
  FILE *f=fopen(argv[6],"wb");assert(f);size_t bytes=0;
  const unsigned char *p=m15_evidence(s,M15_RAW,&bytes);assert(p);
  fprintf(f,"{\"state\":%d,\"error\":\"%s\",\"raw_bytes\":%zu,\"ownership_clear\":%s,\"sink_accepted_bytes\":%llu,\"control_permitted\":false,\"device_safety\":\"UNKNOWN\",\"sealed_baseline\":false}\n",
          m15_state(s),m15_error(s)?m15_error(s):"",bytes,m15_ownership_clear(s)?"true":"false",(unsigned long long)m15_accepted_bytes(s));
  assert(!fclose(f));
  char path[4096];assert(snprintf(path,sizeof(path),"%s.raw",argv[6])<(int)sizeof(path));f=fopen(path,"wb");assert(f);
  assert(fwrite(p,1,bytes,f)==bytes);assert(!fclose(f));
 }
 assert(m15_ownership_clear(s));m15_destroy(s);free(raw.p);free(meta.p);return 0;
}
