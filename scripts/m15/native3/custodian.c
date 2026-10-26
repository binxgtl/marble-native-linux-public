/* SPDX-License-Identifier: GPL-2.0-only */
/* OFFLINE fixture integration only. No device paths, charger or reboot APIs. */
#define _GNU_SOURCE
#include "../native1/escrow.h"
#include "../native1/supervise.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static const char noncehex[]="0102030405060708090a0b0c0d0e0f10"; /* fixture ONLY */
static uint64_t now(void) {struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))_exit(125);return (uint64_t)t.tv_sec*1000+t.tv_nsec/1000000;}
static void held(struct m15 *s) {
 m15_poison(s,"integration-hold");
 /* No destroy, automatic retry, exit or reboot on any failed integration path. */
 const char message[]="HOLD retained; device_safety=UNKNOWN\n";
 ssize_t n=write(2,message,sizeof(message)-1);(void)n;
 for(;;)pause();
}
static void notify(struct m15 *s,const char *p) {
 size_t n=strlen(p);ssize_t k=write(2,p,n);
 if(k<0 || (size_t)k!=n)held(s);
}
static size_t command(struct m15 *s,unsigned seq,char out[512]) {
 char b[640],prefix[80];size_t n=0;
 uint64_t deadline=now()+3000;
 while(now()<deadline && n<sizeof(b)-1) {
  char c;ssize_t k=read(0,&c,1);
  if(k==1){b[n++]=c;if(c=='\n')break;}
  else if(k==0 || (errno!=EAGAIN && errno!=EINTR))held(s);
  else {struct pollfd f={0,POLLIN,0};if(poll(&f,1,10)<0 && errno!=EINTR)held(s);}
 }
 int z=snprintf(prefix,sizeof(prefix),"M15IPC1 %s %u ",noncehex,seq);
 if(!n || b[n-1]!='\n' || n<=(size_t)z || memcmp(b,prefix,(size_t)z) || n-(size_t)z>=512)held(s);
 size_t length=n-(size_t)z;memcpy(out,b+z,length);out[length]=0;return length;
}
struct child {const char *observer,*root;};
static void collect(void *arg) {
 struct child *a=arg;
 execl(a->observer,"observer","--fixture-root",a->root,"--samples","3","--interval-ms","1000","--deadline-ms","90000",(char *)NULL);
 _exit(127);
}
static ssize_t sink(void *arg,const void *p,size_t n){(void)arg;return write(1,p,n);}
int main(int argc,char **argv) {
 if(argc!=5 || strcmp(argv[1],"--offline-fixture"))return 64;
 signal(SIGPIPE,SIG_IGN);
 for(int fd=0;fd<3;fd++){int f=fcntl(fd,F_GETFL);if(f<0 || fcntl(fd,F_SETFL,f|O_NONBLOCK))return 70;}
 static const char meta[]="{\"schema\":\"M15-native-phase1-metadata-v1\",\"synthetic_only\":true,\"launcher\":\"offline-subreaper\",\"evidence_path\":\"ram-escrow-deferred-export\",\"observation_schema\":\"M15O3\",\"power_supply_contract\":\"usb-or-usb-pd-v1\",\"freshness\":\"UNKNOWN\",\"negotiated_contract\":\"UNKNOWN\",\"protection_active\":\"UNKNOWN\",\"sealed_baseline\":false,\"control_permitted\":false}";
 unsigned char nonce[16];for(unsigned i=0;i<16;i++)nonce[i]=(unsigned char)(i+1);
 struct m15 *s=m15_create(nonce,meta,sizeof(meta)-1,(struct m15_limits){2000000,262144,1048576,8388608,16*1024*1024},now());
 if(!s)return 70;
 char binding[65],message[256],cmd[512];m15_binding(s,binding);
 snprintf(message,sizeof(message),"READY %s %s\n",noncehex,binding);notify(s,message);
 size_t n=command(s,0,cmd);if(m15_pc_receipt(s,cmd,n,now()))held(s);
 notify(s,"ISOLATE_BEGIN\n");
 command(s,1,cmd);if(strcmp(cmd,"ISOLATED 1 1\n") || m15_isolated(s,1,1,now()))held(s);
 notify(s,"WALL_WAIT\n");
 command(s,2,cmd);if(strcmp(cmd,"WALL 1 1\n") || m15_wall(s,1,1,now()))held(s);
 notify(s,"COLLECT_BEGIN\n");
 struct child a={argv[2],argv[3]};struct m15_process_result r;
 /* argv[4] is an explicit fixed mode, never a host-controlled command. */
 if(strcmp(argv[4],"collect"))held(s);
 if(m15_supervise(s,collect,&a,10000,now(),&r))held(s);
 notify(s,"COLLECT_RETURNED\n");
 if(m15_finish(s,r.raw_wait,r.census_closed,now()))held(s);
 notify(s,"FROZEN\n");
 command(s,3,cmd);if(strcmp(cmd,"PC 1\n") || m15_reconnect(s,1,now()))held(s);
 while(m15_state(s)==M15_EXPORT){
  if(m15_export_step(s,sink,NULL,now())<0)held(s);
  struct pollfd f={1,POLLOUT,0};if(poll(&f,1,2)<0 && errno!=EINTR)held(s);
 }
 snprintf(message,sizeof(message),"WAIT_ACK %llu\n",(unsigned long long)m15_accepted_bytes(s));notify(s,message);
 n=command(s,4,cmd);if(m15_host_ack(s,cmd,n,now()))held(s);
 notify(s,"RECOVERED evidence_only\n");
 /* The ONLY ordinary disposal path is independently verified ACK + no owners. */
 if(m15_state(s)!=M15_RECOVERED || !m15_ownership_clear(s))held(s);
 m15_destroy(s);return 0;
}
