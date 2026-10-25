/* Real processes/SEQPACKET, no QRTR, files, radio or phone. */
#define _GNU_SOURCE
#include "owner-supervisor.h"
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

enum { CLEAN, EARLY, FINAL_ERROR, TRAILING, OPEN_PEER, EXIT_ERROR, SIGNAL_EXIT,
       BAD_SEQUENCE, DUPLICATE, MISSING, MALFORMED, PRIOR_POISON, PREMATURE_STOP,
       DELAYED_EXIT, WAITPID_ERROR, CASES };
static void put(int fd,struct m12_owner_record *r,size_t n) {
 assert(send(fd,r,n,MSG_NOSIGNAL)==(ssize_t)n);
}
int main(void) {
 for(int mode=0;mode<CASES;mode++) {
  int f[2],sync[2];assert(!socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,f));
  assert(!pipe(sync));pid_t pid=fork();assert(pid>=0);
  if(!pid) {
   close(f[0]);close(sync[1]);
   struct m12_owner_record r={.magic=M12_OWNER_MAGIC,.version=M12_OWNER_VERSION,
    .sequence=1,.event=M12_READY,.phase=M12_DB_IDLE,.node=1,.port=123};
   put(f[1],&r,sizeof(r));struct m12_owner_stop stop;
   assert(recv(f[1],&stop,sizeof(stop),0)==sizeof(stop));
   assert(stop.qca_retired==1 && stop.cnss_retired==1 && !stop.transfer_pending);
   if(mode!=EARLY && mode!=MISSING) {
    r.sequence=mode==BAD_SEQUENCE?3:2;r.event=M12_RETIRED;r.phase=M12_DB_FAILED;
    r.rc=mode==FINAL_ERROR?-EIO:0;
    put(f[1],&r,mode==MALFORMED?sizeof(r)-1:sizeof(r));
    if(mode==TRAILING || mode==DUPLICATE) {
     r.sequence=3;r.event=mode==DUPLICATE?M12_RETIRED:M12_STATE;put(f[1],&r,sizeof(r));
    }
   }
   if(mode==DELAYED_EXIT) {char b;assert(read(sync[0],&b,1)==1);}
   close(sync[0]);close(f[1]);
   if(mode==SIGNAL_EXIT) {raise(SIGKILL);_exit(99);}
   _exit(mode==EXIT_ERROR?1:0);
  }
  close(sync[0]);if(mode!=OPEN_PEER)close(f[1]);
  struct m12_owner_supervisor s={.fd=f[0],.child=pid};
  assert(m12_owner_finish(&s)==-EINVAL && !s.terminal_checked);
  assert(m12_owner_receive(&s,2000)==1);
  assert(m12_owner_stop(&s,0,1,0,0)==-EBUSY);
  assert(m12_owner_stop(&s,1,0,0,0)==-EBUSY);
  assert(m12_owner_stop(&s,1,1,1,0)==-EBUSY);
  assert(m12_owner_stop(&s,1,1,0,1)==-EBUSY);
  assert(!m12_owner_stop(&s,1,1,0,0));
  if(mode==PRIOR_POISON)s.poisoned=1;
  if(mode==PREMATURE_STOP)s.stop_sent=0;
  if(mode==DELAYED_EXIT) {
   assert(m12_owner_receive(&s,2000)==1 && s.final_received);
   assert(!m12_owner_reap(&s) && !s.reaped);assert(m12_owner_finish(&s)==-EINVAL);
   assert(write(sync[1],"x",1)==1);
  }
  /* Deterministic: both record and close queued before drain, no timed sleep. */
  siginfo_t info={0};assert(!waitid(P_PID,pid,&info,WEXITED|WNOWAIT));
  if(mode!=DELAYED_EXIT) {
   int got=m12_owner_receive(&s,0);
   if(mode==EARLY || mode==MISSING)assert(got==-EPIPE && !s.final_received);
   else if(mode==BAD_SEQUENCE || mode==MALFORMED || mode==PREMATURE_STOP)assert(got==-EPROTO && !s.final_received);
   else assert(got==1 && s.final_received);
  }
  if(mode==WAITPID_ERROR) {
   int status;assert(waitpid(pid,&status,0)==pid);
   assert(m12_owner_reap(&s)==-ECHILD && !s.reaped && s.reap_errno==ECHILD);
   assert(m12_owner_finish(&s)==-EINVAL);close(f[0]);close(sync[1]);continue;
  }
  int rc=m12_owner_reap(&s);
  assert(s.reaped && s.reap_errno==0);
  assert((mode==CLEAN || mode==TRAILING || mode==OPEN_PEER || mode==DUPLICATE || mode==DELAYED_EXIT)?rc==1:rc==-ECHILD);
  unsigned calls=s.wait_calls;assert(m12_owner_reap(&s)==-EALREADY && s.wait_calls==calls);
  int done=m12_owner_finish(&s);
  if(mode==CLEAN || mode==DELAYED_EXIT)assert(!done && s.eof_verified && !s.poisoned);
  else if(mode==TRAILING || mode==DUPLICATE)assert(done==-EPROTO && !s.eof_verified && s.poisoned);
  else if(mode==OPEN_PEER)assert(done==-EBUSY && !s.eof_verified && s.poisoned);
  else if(!s.final_received)assert(done==-EINVAL);
  else assert(done==-EPROTO && s.poisoned);
  if(s.terminal_checked)assert(m12_owner_finish(&s)==-EALREADY);
  if(mode==OPEN_PEER)close(f[1]);
  close(f[0]);close(sync[1]);
 }
 puts("Real owner lifecycle: 15 fork/SEQPACKET cases, WNOWAIT ordering, clean final/reap/EOF, early EOF, nonzero final, trailing/duplicate, open peer, nonzero/signal exit, sequence/malformed/missing, prior poison, premature STOP, delayed exit, actual waitpid failure and single reap PASS; no hardware");
}
