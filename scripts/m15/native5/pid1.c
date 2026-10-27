/* SPDX-License-Identifier: GPL-2.0-only */
/* Persistent coordinator entry point, NOT a staged boot init. Backend deployment
 * is intentionally unavailable until display/connector/provenance gates close.
 * There is no success reboot or release path, including after host ACK. */
#define _GNU_SOURCE
#include "coordinator.h"
#include "ownership.h"
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
static uint64_t clock_ms(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return UINT64_MAX;return (uint64_t)t.tv_sec*1000+(uint64_t)t.tv_nsec/1000000;}
int main(int argc,char **argv){
 if(getpid()!=1)return 64;
 signal(SIGPIPE,SIG_IGN);signal(SIGCHLD,SIG_DFL);
 struct coordinator s;coord_init(&s,clock_ms());
 struct parent_ledger owners={0};
 /* No permissive backend fallback. A future integration must replace this
  * explicit gate after qualification, not feed host text as connector facts. */
 int offline=argc==2&&!strcmp(argv[1],"--namespace-hold-test");
 coord_fact(&s,IO_FAILED,0,s.last);
 const char msg[]="M15 RED_HOLD backend_unqualified control_permitted=false\n";
 ssize_t log_rc=write(2,msg,sizeof(msg)-1);(void)log_rc;
 for(;;){
  int status;pid_t p;
  do{p=waitpid(-1,&status,WNOHANG);if(p>0){int result=parent_wait(&owners,p,status);(void)result;}}while(p>0);
  /* Remain alive after ECHILD, failed logging, timeout or clock failure. No
   * module/ADSP/gadget cleanup and no inference of device safety. */
  if(offline){const char receipt[]="PERSISTENT_HOLD no_release no_reboot\n";log_rc=write(1,receipt,sizeof(receipt)-1);(void)log_rc;offline=0;}
  (void)poll(NULL,0,100);
 }
}
