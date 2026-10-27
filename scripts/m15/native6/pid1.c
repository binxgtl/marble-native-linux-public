/* SPDX-License-Identifier: GPL-2.0-only */
/* Integrated PC-only transport/display smoke. O3 reads a synthetic fixture,
 * NEVER power_supply on PC. Wall acquisition is not admitted by this entry. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include "../native5/ownership.h"
#ifndef M15_SMOKE_DEADLINE
#define M15_SMOKE_DEADLINE 300000
#endif
static int journal=-1,failed,display_in=-1;static unsigned color_seq=1;
static struct parent_ledger owners;
static unsigned long long ms(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return 0;return (unsigned long long)t.tv_sec*1000+t.tv_nsec/1000000;}
static int nonblock(int fd){int f=fcntl(fd,F_GETFL);return f<0?-1:fcntl(fd,F_SETFL,f|O_NONBLOCK);}
static void record(const char *s){
 char b[512];int n=snprintf(b,sizeof(b),"%llu %s\n",ms(),s);
 if(n<0||(size_t)n>=sizeof(b)||journal<0||write(journal,b,(size_t)n)!=n)failed=1;
}
static void send_line(int fd,const char *s){size_t n=strlen(s);if(fd<0||write(fd,s,n)!=(ssize_t)n)failed=1;}
static void color(const char *name){char b[80];snprintf(b,sizeof(b),"M15COLOR %u %s\n",color_seq++,name);send_line(display_in,b);record(name);}
static int pipe_high(int p[2]){
 int raw[2];if(pipe2(raw,O_CLOEXEC))return -1;
 p[0]=fcntl(raw[0],F_DUPFD_CLOEXEC,10);p[1]=fcntl(raw[1],F_DUPFD_CLOEXEC,10);
 close(raw[0]);close(raw[1]);return p[0]<0||p[1]<0?-1:0;
}
static pid_t launch(char *const argv[],int in,int out,int err,int status){
 pid_t p=fork();if(p)return p;
 if(dup2(in,0)<0||dup2(out,1)<0||dup2(err,2)<0||(status>=0&&dup2(status,3)<0))_exit(126);
 /* All other inherited descriptors are CLOEXEC. fd3 is display status only. */
 execv(argv[0],argv);_exit(127);
}
static void reap(void){int status;pid_t p;while((p=waitpid(-1,&status,WNOHANG))>0){int rc=parent_wait(&owners,p,status);(void)rc;record("child_terminal unexpected; no release");failed=1;}}
static int hex(const char *s,size_t n){for(size_t i=0;i<n;i++)if(!((s[i]>='0'&&s[i]<='9')||(s[i]>='a'&&s[i]<='f')))return 0;return s[n]==0;}
static int line_byte(int fd,char *b,size_t *at,size_t cap){
 char c;ssize_t n=read(fd,&c,1);
 if(n<0&&(errno==EINTR||errno==EAGAIN))return 0;
 if(n!=1||*at>=cap-1||c=='\r'||(c!='\n'&&(c<32||c>126))){failed=1;return 0;}
 if(c=='\n'){b[*at]=0;*at=0;return 1;}b[(*at)++]=c;return 0;
}
int main(int argc,char **argv){
 if(getpid()!=1)return 64;
 signal(SIGPIPE,SIG_IGN);signal(SIGCHLD,SIG_DFL);
 int fixture=argc==8&&!strcmp(argv[1],"--namespace-smoke");
 if(argc!=8||(!fixture&&strcmp(argv[1],"--pc-smoke")))goto hold;
 journal=open(argv[7],O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);
 if(journal<0)goto hold;
 struct statfs fs;if(fstatfs(journal,&fs)||(!fixture&&(unsigned long)fs.f_type!=0x01021994))goto hold;
 record("PC_SMOKE synthetic_O3 transport_only control_permitted=false");
 int tty=open(argv[6],O_RDWR|O_NOCTTY|O_NONBLOCK|O_CLOEXEC);
 if(tty<0)goto hold;
 struct termios term;if(tcgetattr(tty,&term))goto hold;cfmakeraw(&term);
 if(tcsetattr(tty,TCSANOW,&term))goto hold;
 int ci[2],co[2],ce[2],di[2],ds[2];
 if(pipe_high(ci)||pipe_high(co)||pipe_high(ce)||pipe_high(di)||pipe_high(ds))goto hold;
 int nullfd=open("/dev/null",O_RDWR|O_CLOEXEC);if(nullfd<0)goto hold;
 char *cust[]={argv[2],"--offline-fixture",argv[3],argv[4],"collect",NULL};
 pid_t cp=launch(cust,ci[0],co[1],ce[1],-1);if(cp<0||parent_add(&owners,cp,CUSTODIAN))goto hold;
 close(ci[0]);close(co[1]);close(ce[1]);
 if(nonblock(ci[1])||nonblock(co[0])||nonblock(ce[0])||nonblock(ds[0])||nonblock(di[1]))goto hold;
 char cbuf[512],hbuf[512],dbuf[128],nonce[33]={0},binding[65]={0},command[512];
 size_t ca=0,ha=0,da=0;unsigned char pending[65536];size_t used=0,sent=0;
 int phase=0,display_started=0,wait_ack=0,ack_forwarded=0,complete=0,collected=0,ack_pending=0;
 unsigned long long deadline=ms()+M15_SMOKE_DEADLINE;
 while(!failed){
  reap();if(failed)break;
  unsigned long long now=ms();if(!now||(!complete&&now>=deadline)){record("deadline");failed=1;break;}
  struct pollfd p[4]={{ce[0],POLLIN,0},{tty,(short)(POLLIN|(sent<used?POLLOUT:0)),0},{co[0],sent==used?POLLIN:0,0},{ds[0],display_started?POLLIN:0,0}};
  int pr=poll(p,4,50);if(pr<0){if(errno==EINTR)continue;failed=1;break;}
  if(p[0].revents&&(line_byte(ce[0],cbuf,&ca,sizeof(cbuf)))){
   if(phase==0&&sscanf(cbuf,"READY %32s %64s",nonce,binding)==2&&strlen(cbuf)==103&&hex(nonce,32)&&hex(binding,64)){
    int z=snprintf((char *)pending,sizeof(pending),"M15PCSMOKE1 %s %s\n",nonce,binding);used=(size_t)z;sent=0;phase=1;record("custodian_ready");
   }else if(!strcmp(cbuf,"ISOLATE_BEGIN")&&phase==2){
    char *screen[]={argv[5],NULL};pid_t dp=launch(screen,di[0],nullfd,journal,ds[1]);
    if(dp<0||parent_add(&owners,dp,DISPLAY)){failed=1;break;}
    close(di[0]);close(ds[1]);display_in=di[1];display_started=1;phase=3;
   }else if(!strcmp(cbuf,"WALL_WAIT")&&phase==4){
    color("YELLOW");phase=11;
   }else if(phase==5&&collected==0&&!strcmp(cbuf,"COLLECT_BEGIN")){collected=1;record(cbuf);
   }else if(phase==5&&collected==1&&!strcmp(cbuf,"COLLECT_RETURNED")){collected=2;record(cbuf);
   }else if(!strcmp(cbuf,"FROZEN")&&phase==5&&collected==2){color("GREEN");phase=6;
   }else if(!strncmp(cbuf,"WAIT_ACK ",9)&&phase==8){wait_ack=1;record("export_bytes_accepted not delivery");
   }else if(!strcmp(cbuf,"RECOVERED evidence_only")&&phase==8&&ack_forwarded){
    record("PARENT_RECEIPT evidence_recovered=true release_permitted=false");
    if(fsync(journal))failed=1;else{color("COMPLETE");complete=1;phase=9;}
   }else{record("custodian protocol failure");failed=1;}
  }
  if(p[3].revents&&line_byte(ds[0],dbuf,&da,sizeof(dbuf))){
   if(phase==3&&!strcmp(dbuf,"M15DISPLAY 0 BLUE committed")){
    record("BLUE_PC_READY display commit returned; synthetic isolation only");
    snprintf(command,sizeof(command),"M15IPC1 %s 1 ISOLATED 1 1\n",nonce);send_line(ci[1],command);phase=4;
   }else if(phase==11&&!strcmp(dbuf,"M15DISPLAY 1 YELLOW mapped")){
    snprintf(command,sizeof(command),"M15IPC1 %s 2 WALL 1 1\n",nonce);send_line(ci[1],command);phase=5;record("synthetic_fixture_collect; NOT wall attachment");
   }else if(phase==6&&!strcmp(dbuf,"M15DISPLAY 2 GREEN mapped")){color("CYAN");phase=7;
   }else if(phase==7&&!strcmp(dbuf,"M15DISPLAY 3 CYAN mapped")){
    snprintf(command,sizeof(command),"M15IPC1 %s 3 PC 1\n",nonce);send_line(ci[1],command);phase=8;
   }else if(phase==9&&!strcmp(dbuf,"M15DISPLAY 4 COMPLETE mapped")){record("COMPLETE evidence only; retain RAM and devices");phase=10;
   }else{record("display protocol failure");failed=1;}
  }
  if(p[2].revents&&sent==used){
   ssize_t n=read(co[0],pending,sizeof(pending));
   if(n>0&&phase==8){used=(size_t)n;sent=0;}
   else if(n==0||(n<0&&errno!=EAGAIN&&errno!=EINTR)||n>0)failed=1;
  }
  if(p[1].revents&POLLOUT){ssize_t n=write(tty,pending+sent,used-sent);if(n>0)sent+=(size_t)n;else if(n==0||(errno!=EAGAIN&&errno!=EINTR))failed=1;}
  if(p[1].revents&(POLLERR|POLLHUP|POLLNVAL)){record("transport disconnect");failed=1;}
  if(p[1].revents&POLLIN&&line_byte(tty,hbuf,&ha,sizeof(hbuf))){
   if(phase==1){
    char expected[160];snprintf(expected,sizeof(expected),"M15PC1 %s %s",nonce,binding);
    if(strcmp(hbuf,expected))failed=1;
    else{snprintf(command,sizeof(command),"M15IPC1 %s 0 %.200s\n",nonce,hbuf);send_line(ci[1],command);phase=2;record("real_host_admission");}
   }else if(phase==8&&!ack_pending&&!ack_forwarded){
    if(strlen(hbuf)>200||strncmp(hbuf,"M15ACK1 ",8))failed=1;
    else ack_pending=1;
   }else failed=1;
  }
  if(ack_pending&&wait_ack&&!ack_forwarded&&sent==used){
   snprintf(command,sizeof(command),"M15IPC1 %s 4 %.200s\n",nonce,hbuf);send_line(ci[1],command);ack_forwarded=1;
  }
 }
hold:
 failed=1;if(display_in>=0)color("RED");record("RED_HOLD retain; no teardown or reboot");
 for(;;){reap();(void)poll(NULL,0,100);}
}
