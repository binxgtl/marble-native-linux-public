/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include "../native5/ownership.h"
#include "../native5/io.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/statfs.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#ifndef M15_STAGE_BUDGET
#define M15_STAGE_BUDGET 300000
#endif
enum phase { START,HOST,HOST_ACK,BLUE_PENDING,BLUE_WAIT,UNBIND_WAIT,ISOLATE_WAIT,YELLOW_PENDING,WALL_WAIT,COLLECT,SEAL_WAIT,GREEN_PENDING,GREEN_WAIT,GREEN_REMOVED,REBIND_WAIT,RETURN_HOST,CYAN_PENDING,EXPORT,COMPLETE_PENDING,DONE };
static int journal=-1,failed,display_in=-1,tty=-1;static unsigned colors=1;
static struct parent_ledger owners;
static unsigned long long now(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return 0;return (unsigned long long)t.tv_sec*1000+t.tv_nsec/1000000;}
static void record(const char *s){char b[600];int n=snprintf(b,sizeof(b),"%llu %s\n",now(),s);if(n<0||(size_t)n>=sizeof(b)||journal<0||write(journal,b,(size_t)n)!=n)failed=1;}
static void send_line(int fd,const char *s){size_t n=strlen(s);if(fd<0||write(fd,s,n)!=(ssize_t)n)failed=1;}
static void color(const char *s){char b[80];snprintf(b,sizeof(b),"M15COLOR %u %s\n",colors++,s);send_line(display_in,b);record(s);}
static int pipe_high(int p[2]){int r[2];if(pipe2(r,O_CLOEXEC))return -1;p[0]=fcntl(r[0],F_DUPFD_CLOEXEC,10);p[1]=fcntl(r[1],F_DUPFD_CLOEXEC,10);close(r[0]);close(r[1]);return p[0]<0||p[1]<0?-1:0;}
static int nonblock(int fd){int f=fcntl(fd,F_GETFL);return f<0?-1:fcntl(fd,F_SETFL,f|O_NONBLOCK);}
static pid_t launch(char *const a[],int in,int out,int err,int status){pid_t p=fork();if(p)return p;if(dup2(in,0)<0||dup2(out,1)<0||dup2(err,2)<0||(status>=0&&dup2(status,3)<0))_exit(126);execv(a[0],a);_exit(127);}
static void reap(void){int status;pid_t p;while((p=waitpid(-1,&status,WNOHANG))>0){int r=parent_wait(&owners,p,status);(void)r;record("unexpected_child_terminal ownership_retained");failed=1;}}
static int line(int fd,char *b,size_t *at,size_t cap){char c;ssize_t n=read(fd,&c,1);if(n<0&&(errno==EAGAIN||errno==EINTR))return 0;if(n!=1||*at>=cap-1||c=='\r'||(c!='\n'&&(c<32||c>126))){failed=1;return 0;}if(c=='\n'){b[*at]=0;*at=0;return 1;}b[(*at)++]=c;return 0;}
static int opentty(const char *path){int fd=open(path,O_RDWR|O_NOCTTY|O_NONBLOCK|O_CLOEXEC);if(fd<0)return -1;struct termios t;if(tcgetattr(fd,&t)){close(fd);return -1;}cfmakeraw(&t);if(tcsetattr(fd,TCSANOW,&t)){close(fd);return -1;}return fd;}
static int hex(const char *p,size_t n){for(size_t i=0;i<n;i++)if(!((p[i]>='0'&&p[i]<='9')||(p[i]>='a'&&p[i]<='f')))return 0;return !p[n];}
static int snapshot(const char *source,const char *target){int a=open(source,O_RDONLY|O_CLOEXEC),b=open(target,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);if(a<0||b<0)return -1;char buf[4096];size_t total=0;int bad=0;for(;;){ssize_t n=read(a,buf,sizeof(buf));if(n<0&&errno==EINTR)continue;if(n<0){bad=1;break;}if(!n)break;total+=(size_t)n;if(total>1048576||write(b,buf,(size_t)n)!=n){bad=1;break;}}if(fsync(b))bad=1;if(close(a))bad=1;if(close(b))bad=1;return bad?-1:0;}
int main(int argc,char **argv){
 if(getpid()!=1)return 64;
 signal(SIGPIPE,SIG_IGN);signal(SIGCHLD,SIG_DFL);
 if(argc!=2)goto hold;
 const char *run="/run/m15",*cust="/sbin/m15-custodian",*screen="/sbin/m15-display",*conn="/sbin/m15-connector",*obs="/sbin/m15-observe-o3",*port="/dev/ttyGS0",*kmsg="/dev/kmsg";
#ifdef M15_RUNTIME_TEST
 run=getenv("M15_RUN");cust=getenv("M15_CUSTODIAN");screen=getenv("M15_DISPLAY");conn=getenv("M15_CONNECTOR");obs=getenv("M15_OBSERVER");port=getenv("M15_TTY");kmsg=getenv("M15_KMSG");
 if(!run||!cust||!screen||!conn||!obs||!port||!kmsg)goto hold;
#endif
 char jp[512],kp[512],fp[512];
 if(snprintf(jp,sizeof(jp),"%s/pid1.journal",run)>=(int)sizeof(jp)||snprintf(kp,sizeof(kp),"%s/kernel.raw",run)>=(int)sizeof(kp)||snprintf(fp,sizeof(fp),"%s/frozen.journal",run)>=(int)sizeof(fp))goto hold;
 journal=open(jp,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);if(journal<0)goto hold;
#ifndef M15_RUNTIME_TEST
 struct statfs fs;if(fstatfs(journal,&fs)||(unsigned long)fs.f_type!=0x01021994)goto hold;
#endif
 record("NATIVE_RUNTIME O3 unchanged control_permitted=false charger_identity=operator-reported");
 int ki=open(kmsg,O_RDONLY|O_CLOEXEC|O_NONBLOCK),ko=open(kp,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);
 if(ki<0||ko<0)goto hold;
 struct klog kernel={0};size_t journal_size=0;
 int ci[2],co[2],ce[2],di[2],ds[2],xi[2],xo[2];
 if(pipe_high(ci)||pipe_high(co)||pipe_high(ce)||pipe_high(di)||pipe_high(ds)||pipe_high(xi)||pipe_high(xo))goto hold;
 int nullfd=open("/dev/null",O_RDWR|O_CLOEXEC);if(nullfd<0)goto hold;
 char *ca[]={ (char *)cust,argv[1],(char *)obs,kp,fp,NULL};pid_t cp=launch(ca,ci[0],co[1],ce[1],-1);if(cp<0||parent_add(&owners,cp,CUSTODIAN))goto hold;
 char *xa[]={ (char *)conn,NULL};pid_t xp=launch(xa,xi[0],xo[1],journal,-1);if(xp<0||parent_add(&owners,xp,CONNECTOR))goto hold;
 close(ci[0]);close(co[1]);close(ce[1]);close(xi[0]);close(xo[1]);
 if(nonblock(ci[1])||nonblock(co[0])||nonblock(ce[0])||nonblock(xi[1])||nonblock(xo[0])||nonblock(ds[0])||nonblock(di[1]))goto hold;
 char cb[512],hb[512],db[128],xb[128],nonce[33]={0},binding[65]={0},cmd[512],ack[201]={0};
 size_t cat=0,hat=0,dat=0,xat=0,used=0,sent=0;unsigned char pending[65536];
 enum phase phase=START;int cr=0,xr=0,display=0,collected=0,wait_ack=0,ack_received=0,ack_forwarded=0,sealing=0;
 unsigned long long deadline=now()+M15_STAGE_BUDGET;
#ifdef M15_RUNTIME_TEST
 const char *budget=getenv("M15_TEST_BUDGET");if(budget)deadline=now()+strtoul(budget,NULL,10);
#endif
 while(!failed){
  reap();if(failed)break;
  if(!now()||(phase!=DONE&&now()>=deadline)){record("stage_deadline HOLD_not_reboot");break;}
  int drained=0;
  if(ki>=0){
   for(unsigned i=0;i<32;i++){
    unsigned char b[8192];ssize_t n=read(ki,b,sizeof(b));
    if(n<0&&(errno==EAGAIN||errno==EINTR)){drained=errno==EAGAIN;break;}
#ifdef M15_RUNTIME_TEST
    if(n==0){drained=1;break;}
#endif
    if(n<=0||klog_record(&kernel,b,(size_t)n,7*1024*1024)||write(ko,b,(size_t)n)!=n){record("kernel_capture_failure");failed=1;break;}
   }
  }
  if(sealing&&drained){
   /* A final nonblocking drain above reached EAGAIN. The close is our explicit
    * coverage boundary; no claim is made for later GREEN/reconnect kernel logs. */
   if(!kernel.have||fsync(ko)||close(ki)||close(ko)){failed=1;break;}ki=ko=-1;
   record("KERNEL_COVERAGE_END before_freeze");if(fsync(journal)||snapshot(jp,fp)){failed=1;break;}
   snprintf(cmd,sizeof(cmd),"M15IPC1 %s 3 SEAL\n",nonce);send_line(ci[1],cmd);sealing=0;phase=SEAL_WAIT;
  }
  struct pollfd p[5]={{ce[0],POLLIN,0},{xo[0],POLLIN,0},{ds[0],display?POLLIN:0,0},{co[0],sent==used?POLLIN:0,0},{tty,(short)(tty>=0?(POLLIN|(sent<used?POLLOUT:0)):0),0}};
  if(poll(p,5,50)<0){if(errno==EINTR)continue;record("poll_failure");break;}
  if(p[0].revents&&line(ce[0],cb,&cat,sizeof(cb))){
   record(cb);
   if(phase==START&&!cr&&strlen(cb)==103&&sscanf(cb,"READY %32s %64s",nonce,binding)==2&&hex(nonce,32)&&hex(binding,64))cr=1;
   else if(phase==HOST_ACK&&!strcmp(cb,"ISOLATE_BEGIN")){
    char *da[]={ (char *)screen,NULL};pid_t dp=launch(da,di[0],nullfd,journal,ds[1]);if(dp<0||parent_add(&owners,dp,DISPLAY)){failed=1;break;}
    close(di[0]);close(ds[1]);display_in=di[1];display=1;phase=BLUE_PENDING;
   }else if(phase==ISOLATE_WAIT&&!strcmp(cb,"WALL_WAIT")){color("YELLOW");phase=YELLOW_PENDING;}
   else if(phase==COLLECT&&!collected&&!strcmp(cb,"COLLECT_BEGIN"))collected=1;
   else if(phase==COLLECT&&collected==1&&!strcmp(cb,"COLLECT_RETURNED")){collected=2;sealing=1;}
   else if(phase==SEAL_WAIT&&!strcmp(cb,"FROZEN")){color("GREEN");phase=GREEN_PENDING;deadline=now()+M15_STAGE_BUDGET;}
   else if(phase==EXPORT&&!strncmp(cb,"WAIT_ACK ",9))wait_ack=1;
   else if(phase==EXPORT&&ack_forwarded&&!strcmp(cb,"RECOVERED evidence_only")){
    record("PARENT_RECEIPT evidence_recovered=true release_permitted=false");if(fsync(journal)){failed=1;break;}
    int n=snprintf((char *)pending,sizeof(pending),"M15DONE1 %s\n",ack+8);used=(size_t)n;sent=0;color("COMPLETE");phase=COMPLETE_PENDING;
   }else failed=1;
  }
  if(p[1].revents&&line(xo[0],xb,&xat,sizeof(xb))){
   record(xb);
   if(phase==START&&!xr&&!strcmp(xb,"CONNECTOR_READY"))xr=1;
   else if(phase==BLUE_WAIT&&!strcmp(xb,"REMOVED")){send_line(xi[1],"UNBIND\n");phase=UNBIND_WAIT;}
   else if(phase==UNBIND_WAIT&&!strcmp(xb,"UNBOUND")){snprintf(cmd,sizeof(cmd),"M15IPC1 %s 1 ISOLATED 1 1\n",nonce);send_line(ci[1],cmd);phase=ISOLATE_WAIT;}
   else if(phase==WALL_WAIT&&!strcmp(xb,"ATTACHED")){
    record("wall_attachment kernel_reported; identity_and_PC_absence operator_declared");snprintf(cmd,sizeof(cmd),"M15IPC1 %s 2 WALL 1 1\n",nonce);send_line(ci[1],cmd);phase=COLLECT;deadline=now()+100000;
   }else if(phase==GREEN_WAIT&&!strcmp(xb,"REMOVED"))phase=GREEN_REMOVED;
   else if(phase==GREEN_REMOVED&&!strcmp(xb,"ATTACHED")){send_line(xi[1],"BIND\n");phase=REBIND_WAIT;}
   else if(phase==REBIND_WAIT&&!strcmp(xb,"BOUND")){
    tty=opentty(port);if(tty<0){failed=1;break;}
    int n=snprintf((char *)pending,sizeof(pending),"M15RETURN1 %s %s\n",nonce,binding);used=(size_t)n;sent=0;phase=RETURN_HOST;
   }else if(phase!=DONE)failed=1;
  }
  if(phase==START&&cr&&xr){
   tty=opentty(port);if(tty<0){failed=1;break;}
   int n=snprintf((char *)pending,sizeof(pending),"M15NATIVE1 %s %s\n",nonce,binding);used=(size_t)n;sent=0;phase=HOST;
  }
  if(p[2].revents&&line(ds[0],db,&dat,sizeof(db))){
   record(db);
   if(phase==BLUE_PENDING&&!strcmp(db,"M15DISPLAY 0 BLUE committed")){phase=BLUE_WAIT;deadline=now()+M15_STAGE_BUDGET;}
   else if(phase==YELLOW_PENDING&&!strcmp(db,"M15DISPLAY 1 YELLOW mapped"))phase=WALL_WAIT;
   else if(phase==GREEN_PENDING&&!strcmp(db,"M15DISPLAY 2 GREEN mapped"))phase=GREEN_WAIT;
   else if(phase==CYAN_PENDING&&!strcmp(db,"M15DISPLAY 3 CYAN mapped")){snprintf(cmd,sizeof(cmd),"M15IPC1 %s 4 PC 1\n",nonce);send_line(ci[1],cmd);phase=EXPORT;}
   else if(phase==COMPLETE_PENDING&&!strcmp(db,"M15DISPLAY 4 COMPLETE mapped")){record("COMPLETE retain_RAM_ADSP_USB_display");phase=DONE;}
   else failed=1;
  }
  if(p[3].revents&&sent==used){ssize_t n=read(co[0],pending,sizeof(pending));if(n>0&&phase==EXPORT){used=(size_t)n;sent=0;}else if(!n||(n<0&&errno!=EAGAIN&&errno!=EINTR)||n>0)failed=1;}
  if(tty>=0&&p[4].revents&POLLOUT){ssize_t n=write(tty,pending+sent,used-sent);if(n>0)sent+=(size_t)n;else if(!n||(errno!=EAGAIN&&errno!=EINTR))failed=1;}
  if(tty>=0&&phase!=DONE&&p[4].revents&(POLLERR|POLLHUP|POLLNVAL)){record("unexpected_transport_loss");failed=1;}
  if(tty>=0&&phase!=DONE&&p[4].revents&POLLIN&&line(tty,hb,&hat,sizeof(hb))){
   char expected[180];
   if(phase==HOST){snprintf(expected,sizeof(expected),"M15PC1 %s %s",nonce,binding);if(strcmp(hb,expected))failed=1;else{snprintf(cmd,sizeof(cmd),"M15IPC1 %s 0 %.200s\n",nonce,hb);send_line(ci[1],cmd);if(close(tty))failed=1;tty=-1;used=sent=0;phase=HOST_ACK;}}
   else if(phase==RETURN_HOST){snprintf(expected,sizeof(expected),"M15PC2 %s %s",nonce,binding);if(strcmp(hb,expected))failed=1;else{color("CYAN");phase=CYAN_PENDING;deadline=now()+M15_STAGE_BUDGET;}}
   else if(phase==EXPORT&&!ack_received&&strlen(hb)<sizeof(ack)&&!strncmp(hb,"M15ACK1 ",8)){strcpy(ack,hb);ack_received=1;}
   else failed=1;
  }
  if(phase==EXPORT&&ack_received&&wait_ack&&!ack_forwarded&&sent==used){snprintf(cmd,sizeof(cmd),"M15IPC1 %s 5 %s\n",nonce,ack);send_line(ci[1],cmd);ack_forwarded=1;}
  off_t size=lseek(journal,0,SEEK_CUR);if(size<0||(journal_size=(size_t)size)>1048576){failed=1;break;}
 }
hold:
 failed=1;if(display_in>=0)color("RED");record("RED_HOLD retain_no_teardown_no_reboot");for(;;){reap();(void)poll(NULL,0,100);}
}
