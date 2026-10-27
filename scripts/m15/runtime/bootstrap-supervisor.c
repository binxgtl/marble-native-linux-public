/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
static unsigned long long now(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return 0;return (unsigned long long)t.tv_sec*1000+t.tv_nsec/1000000;}
int main(void){
 if(getpid()!=1)return 64;
 const char *worker="/m15/bootstrap",*runtime="/sbin/m15-runtime",*meta="/m15/metadata.json";
#ifdef M15_RUNTIME_TEST
 worker=getenv("M15_BOOT_WORKER");runtime=getenv("M15_BOOT_RUNTIME");meta="fixture";
 if(!worker||!runtime)return 64;
#endif
 signal(SIGPIPE,SIG_IGN);signal(SIGCHLD,SIG_DFL);
 pid_t child=fork();if(child<0)goto hold;
 if(!child){
#ifdef M15_RUNTIME_TEST
  execl(worker,worker,(char *)NULL);
#else
  execl("/bin/busybox","busybox","sh",worker,(char *)NULL);
#endif
  _exit(127);
 }
 unsigned long long end=now()+120000;
#ifdef M15_RUNTIME_TEST
 end=now()+1000;
#endif
 dprintf(2,"M15 bootstrap OWN pid=%ld\n",(long)child);
 while(now()&&now()<end){
  int status;pid_t p=waitpid(-1,&status,WNOHANG);
  if(p==child){
   dprintf(2,"M15 bootstrap REAP pid=%ld status=%d\n",(long)p,status);
   if(status)goto hold;
   errno=0;
   if(waitpid(-1,&status,WNOHANG)!=-1||errno!=ECHILD)goto hold;
   dprintf(2,"M15 bootstrap census_closed=1\n");
   execl(runtime,runtime,meta,(char *)NULL);goto hold;
  }
  if(p>0||(p<0&&errno!=EINTR))goto hold;
  (void)poll(NULL,0,10);
 }
hold:
 dprintf(2,"M15 bootstrap HOLD ownership_retained no_kill no_restore no_reboot\n");
 for(;;){int status;pid_t p=waitpid(-1,&status,WNOHANG);if(p>0)dprintf(2,"M15 bootstrap late_REAP pid=%ld status=%d\n",(long)p,status);(void)poll(NULL,0,100);}
}
