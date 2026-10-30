/* SPDX-License-Identifier: GPL-2.0-only */
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
#include <sys/random.h>
#include <time.h>
#include <unistd.h>
static char nonce[33];
static uint64_t now(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))_exit(125);return (uint64_t)t.tv_sec*1000+t.tv_nsec/1000000;}
static _Noreturn void hold(struct m15 *s){
 /* First failure, before this poison. PID1 journals it, and the RED QR shows it. */
 char b[128];int z=snprintf(b,sizeof(b),"HOLD retained %s\n",m15_state(s)==M15_HOLD?m15_error(s):"runtime");
 m15_poison(s,"native-runtime-hold");
 ssize_t n=write(2,b,z>0&&(size_t)z<sizeof(b)?(size_t)z:0);(void)n;for(;;)pause();
}
static void notify(struct m15 *s,const char *v){size_t n=strlen(v);if(write(2,v,n)!=(ssize_t)n)hold(s);}
static size_t command(struct m15 *s,unsigned sequence,char out[512]){
 char prefix[80],b[640];size_t at=0;uint64_t until=now()+300000;
 while(now()<until&&at<sizeof(b)-1){
  char c;ssize_t n=read(0,&c,1);
  if(n==1){if(c!='\n'&&(c<32||c>126))hold(s);b[at++]=c;if(c=='\n')break;}
  else if(!n||(errno!=EAGAIN&&errno!=EINTR))hold(s);
  else {struct pollfd p={0,POLLIN,0};if(poll(&p,1,50)<0&&errno!=EINTR)hold(s);}
 }
 int z=snprintf(prefix,sizeof(prefix),"M15IPC1 %s %u ",nonce,sequence);
 if(!at||b[at-1]!='\n'||at<=(size_t)z||at-(size_t)z>=512||memcmp(b,prefix,(size_t)z))hold(s);
 size_t n=at-(size_t)z;memcpy(out,b+z,n);out[n]=0;return n;
}
static const char *observer;
static void collect(void *unused){
 (void)unused;
#ifdef M15_RUNTIME_TEST
 const char *root=getenv("M15_FIXTURE_ROOT");
 if(root){execl(observer,"observer","--fixture-root",root,"--samples","3","--interval-ms","1000","--deadline-ms","90000",(char *)NULL);_exit(127);}
#endif
 execl(observer,"observer","--sysfs","--samples","3","--interval-ms","1000","--deadline-ms","90000",(char *)NULL);_exit(127);
}
static ssize_t sink(void *unused,const void *p,size_t n){(void)unused;return write(1,p,n);}
static int append_file(struct m15 *s,const char *path){
 int fd=open(path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(fd<0)return -1;
 char b[4096];size_t total=0;int failed=0;
 for(;;){ssize_t n=read(fd,b,sizeof(b));if(n<0&&errno==EINTR)continue;if(n<0){failed=1;break;}if(!n)break;
  total+=(size_t)n;if(total>8388608||m15_append(s,M15_KERNEL,b,(size_t)n)){failed=1;break;}}
 if(close(fd))failed=1;
 return failed?-1:0;
}
int main(int argc,char **argv){
 if(argc!=5)return 64;
 observer=argv[2];signal(SIGPIPE,SIG_IGN);
 for(int fd=0;fd<3;fd++){int f=fcntl(fd,F_GETFL);if(f<0||fcntl(fd,F_SETFL,f|O_NONBLOCK))return 70;}
 char meta[8192];int m=open(argv[1],O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(m<0)return 70;
 ssize_t n=read(m,meta,sizeof(meta));int closed=close(m);if(n<=0||n==(ssize_t)sizeof(meta)||closed)return 70;
 unsigned char random[16];if(getrandom(random,sizeof(random),GRND_NONBLOCK)!=16)return 70;
 for(unsigned i=0;i<16;i++)snprintf(nonce+2*i,3,"%02x",random[i]);
 struct m15 *s=m15_create(random,meta,(size_t)n,(struct m15_limits){2000000,262144,1048576,8388608,16*1024*1024},now());if(!s)return 70;
 char binding[65],message[200],cmd[512];m15_binding(s,binding);
 snprintf(message,sizeof(message),"READY %s %s\n",nonce,binding);notify(s,message);
 size_t size=command(s,0,cmd);char admission[200],expected[200];
 snprintf(expected,sizeof(expected),"M15PC1 %s %s\n",nonce,binding);
 if(size>=sizeof(admission)||strcmp(cmd,expected))hold(s);
 memcpy(admission,cmd,size+1);notify(s,"ISOLATE_BEGIN\n");
 command(s,1,cmd);if(strcmp(cmd,"ISOLATED 1 1\n")||m15_pc_receipt(s,admission,size,now())||m15_isolated(s,1,1,now()))hold(s);notify(s,"WALL_WAIT\n");
 command(s,2,cmd);if(strcmp(cmd,"WALL 1 1\n")||m15_wall(s,1,1,now()))hold(s);notify(s,"COLLECT_BEGIN\n");
 struct m15_process_result result;if(m15_supervise(s,collect,NULL,100000,now(),&result))hold(s);
 notify(s,"COLLECT_RETURNED\n");
 command(s,3,cmd);if(strcmp(cmd,"SEAL\n"))hold(s);
 /* PID1 has closed its writer at this barrier. File paths are boot-inventory
  * inputs, never supplied by the host. Original kernel bytes precede journal. */
 if(append_file(s,argv[3]))hold(s);
 const char mark[]="M15_PARENT_JOURNAL\n";
 if(m15_append(s,M15_KERNEL,mark,sizeof(mark)-1)||append_file(s,argv[4]))hold(s);
 if(m15_finish(s,result.raw_wait,result.census_closed,now()))hold(s);
 notify(s,"FROZEN\n");
 command(s,4,cmd);if(strcmp(cmd,"PC 1\n")||m15_reconnect(s,1,now()))hold(s);
 while(m15_state(s)==M15_EXPORT){if(m15_export_step(s,sink,NULL,now())<0)hold(s);struct pollfd p={1,POLLOUT,0};if(poll(&p,1,2)<0&&errno!=EINTR)hold(s);}
 snprintf(message,sizeof(message),"WAIT_ACK %llu\n",(unsigned long long)m15_accepted_bytes(s));notify(s,message);
 size=command(s,5,cmd);if(m15_host_ack(s,cmd,size,now()))hold(s);
 notify(s,"RECOVERED evidence_only\n");for(;;)pause();
}
