/* SPDX-License-Identifier: GPL-2.0-only */
/* Namespace PID1 offline lifecycle harness. Never a boot init. */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
static unsigned long long tick(void){struct timespec t;assert(!clock_gettime(CLOCK_MONOTONIC,&t));return (unsigned long long)t.tv_sec*1000+t.tv_nsec/1000000;}
static void send_byte(int fd,char c){assert(write(fd,&c,1)==1);}
static char receive(int fd){char c;struct pollfd p={fd,POLLIN,0};assert(poll(&p,1,3000)==1);assert(read(fd,&c,1)==1);return c;}
static void custodian(int out,int in,int mode){
 assert(!prctl(PR_SET_CHILD_SUBREAPER,1));
 send_byte(out,'B');assert(receive(in)=='G');
 pid_t worker=fork();assert(worker>=0);
 if(!worker){assert(setsid()>0);if(mode==2){struct timespec t={0,100000000};nanosleep(&t,NULL);}_exit(0);}
 send_byte(out,'W');
 if(mode==2){for(;;)pause();}
 int status;assert(waitpid(worker,&status,0)==worker && status==0);
 assert(waitpid(-1,&status,WNOHANG)==-1 && errno==ECHILD);
 send_byte(out,'F');assert(receive(in)=='A');send_byte(out,'R');
 assert(receive(in)=='L');_exit(0);
}
int main(int argc,char **argv){
 assert(argc==3 && !strcmp(argv[1],"--namespace-fixture") && getpid()==1);
 int mode=atoi(argv[2]);assert(mode>=0 && mode<=5);
 assert(signal(SIGCHLD,SIG_DFL)!=SIG_ERR);assert(signal(SIGPIPE,SIG_IGN)!=SIG_ERR);
 int to[2],from[2];assert(!pipe2(to,O_CLOEXEC)&&!pipe2(from,O_CLOEXEC));
 /* Unrelated logger belongs to PID1, never to the collector ledger. */
 pid_t logger=fork();assert(logger>=0);if(!logger){close(to[0]);close(to[1]);close(from[0]);close(from[1]);_exit(0);}
 pid_t child=fork();assert(child>=0);
 if(!child){close(to[1]);close(from[0]);custodian(from[1],to[0],mode);}
 close(to[0]);close(from[1]);
 int pidfd=(int)syscall(SYS_pidfd_open,child,0);assert(pidfd>=0);
 assert(receive(from[0])=='B');
 int failed=0,recovered=0,released=0,adopted=0,child_reaped=0,logger_reaped=0;
 if(mode==1)failed=1;
 else {
  send_byte(to[1],'G');assert(receive(from[0])=='W');
  if(mode==2)failed=1;
  else {
   assert(receive(from[0])=='F');
   if(mode==3)failed=1;
   else {send_byte(to[1],'A');assert(receive(from[0])=='R');recovered=1;
    if(mode==4 || mode==5)failed=1;
    else { /* Separate parent sidecar before explicit release. */
     puts("PARENT_RECEIPT evidence_recovered=1 control_permitted=0");assert(!fflush(stdout));
     send_byte(to[1],'L');released=1;
    }
   }
  }
 }
 /* Fault injection ONLY: pidfd targets exact child; never numeric-PID recovery. */
 if(failed)assert(!syscall(SYS_pidfd_send_signal,pidfd,SIGKILL,NULL,0));
 unsigned long long until=tick()+3000;int closed=0;
 while(tick()<until){
  int status;pid_t p=waitpid(-1,&status,WNOHANG);
  if(p>0){assert(WIFEXITED(status)||WIFSIGNALED(status));
   if(p==child){child_reaped=1;if(status!=0)failed=1;}
   else if(p==logger){logger_reaped=1;assert(status==0);}
   else {adopted++;failed=1;}
  }else if(p<0){assert(errno==ECHILD);closed=1;break;}
  else {struct timespec t={0,1000000};nanosleep(&t,NULL);}
 }
 assert(closed && child_reaped && logger_reaped);
 assert(mode!=2 || adopted==1);
 assert(mode!=0 || (!failed && recovered && released && !adopted));
 assert(mode==0 || (failed && !released));
 printf("RESULT pid1=1 mode=%d hold=%d recovered=%d released=%d adopted=%d device_safety=UNKNOWN\n",mode,failed,recovered,released,adopted);
 close(pidfd);close(to[1]);close(from[0]);
 /* Fixture completion exits namespace; not production HOLD implementation. */
 return 0;
}
