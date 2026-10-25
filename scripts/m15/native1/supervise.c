/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include "supervise.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
struct seen { pid_t pid; int reaped; };
static uint64_t ms(void) { struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return 0;return (uint64_t)t.tv_sec*1000+(unsigned long)t.tv_nsec/1000000; }
static int remember(struct m15 *s,struct seen seen[16],unsigned *count,pid_t pid,uint64_t now) {
 for(unsigned i=0;i<*count;i++)if(seen[i].pid==pid)return (int)i;
 if(*count>=16 || m15_owner_add(s,(uint64_t)pid,now))return -1;
 unsigned i=(*count)++;seen[i]=(struct seen){pid,0};return (int)i;
}
static int children(struct m15 *s,struct seen seen[16],unsigned *count,pid_t root,uint64_t now,int terminate) {
 char path[100];snprintf(path,sizeof(path),"/proc/self/task/%ld/children",(long)getpid());
 FILE *f=fopen(path,"r");if(!f)return -1;
 long pid;unsigned visits=0;int ok=0;
 while(fscanf(f,"%ld",&pid)==1) {
  if(++visits>16 || pid<=1){ok=-1;break;}
  if(remember(s,seen,count,(pid_t)pid,now)<0)ok=-1;
  if(pid!=root){m15_poison(s,"unexpected-adopted-worker");ok=-1;}
  if(terminate && kill((pid_t)pid,SIGKILL) && errno!=ESRCH)ok=-1;
 }
 if(ferror(f))ok=-1;
 fclose(f);return ok;
}
int m15_supervise(struct m15 *s,m15_child_fn fn,void *arg,unsigned deadline,
                  uint64_t logical,struct m15_process_result *r) {
 memset(r,0,sizeof(*r));
 int status=0;errno=0;
 if(!fn || !deadline || deadline>100000 || waitpid(-1,&status,WNOHANG)!=-1 || errno!=ECHILD)
  {m15_poison(s,"nonexclusive-process-scope");return -1;}
 int previous=0;
 if(prctl(PR_GET_CHILD_SUBREAPER,&previous) || prctl(PR_SET_CHILD_SUBREAPER,1) || m15_census_begin(s))
  {m15_poison(s,"subreaper-setup");return -1;}
 int pipes[2][2];
 if(pipe2(pipes[0],O_CLOEXEC) || pipe2(pipes[1],O_CLOEXEC))
  {m15_poison(s,"pipe-setup");return -1;}
 pid_t child=fork();
 if(child<0){m15_poison(s,"fork-failure");return -1;}
 if(!child) {
  if(setpgid(0,0) || dup2(pipes[0][1],STDOUT_FILENO)<0 || dup2(pipes[1][1],STDERR_FILENO)<0)_exit(120);
  for(unsigned i=0;i<2;i++){close(pipes[i][0]);close(pipes[i][1]);}
  fn(arg);_exit(121);
 }
 struct seen seen[16];unsigned count=0;
 int broken=remember(s,seen,&count,child,logical)<0;
 for(unsigned i=0;i<2;i++){
  close(pipes[i][1]);
  int flags=fcntl(pipes[i][0],F_GETFL);
  if(flags<0 || fcntl(pipes[i][0],F_SETFL,flags|O_NONBLOCK))broken=1;
 }
 uint64_t start=ms(),stop=0;int eof[2]={0,0},closed=0;
 while(1) {
  uint64_t elapsed=ms()-start,now=logical+elapsed;
  if(children(s,seen,&count,child,now,stop!=0))broken=1;
  if(m15_state(s)==M15_HOLD)broken=1;
  if((broken || elapsed>=deadline) && !stop) {
   r->timeout=elapsed>=deadline;stop=ms();m15_poison(s,r->timeout?"collector-timeout":"collector-supervision");
   if(kill(-child,SIGKILL) && errno!=ESRCH)broken=1;
   for(unsigned i=0;i<count;i++)if(!seen[i].reaped)(void)kill(seen[i].pid,SIGKILL);
  }
  /* Bound each drain; two fds cannot starve deadline or adopted-child census. */
  for(unsigned i=0;i<2;i++)if(!eof[i]) {
   char bytes[4096];ssize_t n=read(pipes[i][0],bytes,sizeof(bytes));
   if(n>0){if(m15_append(s,i==0?M15_RAW:M15_STDERR,bytes,(size_t)n))broken=1;}
   else if(n==0)eof[i]=1;
   else if(errno!=EAGAIN && errno!=EINTR)broken=1;
  }
  /* Exhaust actual terminal wait facts; root exit alone never closes census. */
  for(unsigned visits=0;visits<17;visits++) {
   pid_t pid=waitpid(-1,&status,WNOHANG);
   if(pid>0){
    int i=remember(s,seen,&count,pid,now);
    if(i<0 || seen[i].reaped)broken=1;
    else {seen[i].reaped=1;r->reaped++;if(m15_owner_reaped(s,(uint64_t)pid,status,now))broken=1;}
    if(pid==child)r->raw_wait=status;
   } else {
    if(pid<0 && errno==ECHILD){closed=1;r->census_closed=1;m15_census_closed(s);}
    else if(pid<0 && errno!=EINTR)broken=1;
    break;
   }
  }
  if(closed && eof[0] && eof[1])break;
  if(stop && ms()-stop>=500)break;
  struct pollfd fds[2]={{pipes[0][0],POLLIN,0},{pipes[1][0],POLLIN,0}};
  if(poll(fds,2,2)<0 && errno!=EINTR)broken=1;
 }
 for(unsigned i=0;i<2;i++)close(pipes[i][0]);
 r->tracked=count;
 r->elapsed_ms=ms()-start;
 if(closed)(void)prctl(PR_SET_CHILD_SUBREAPER,previous);
 if(!closed || broken || r->timeout || r->tracked!=r->reaped) {m15_poison(s,"ownership-or-supervision-failed");return -1;}
 return 0;
}
