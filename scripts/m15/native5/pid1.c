/* SPDX-License-Identifier: GPL-2.0-only */
/* Persistent coordinator entry point, NOT a staged boot init. Backend deployment
 * is intentionally unavailable until display/connector/provenance gates close.
 * There is no success reboot or release path, including after host ACK. */
#define _GNU_SOURCE
#include "coordinator.h"
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
 /* No permissive backend fallback. A future integration must replace this
  * explicit gate after qualification, not feed host text as connector facts. */
 int offline=argc==2&&!strcmp(argv[1],"--namespace-hold-test");
 coord_fact(&s,IO_FAILED,0,s.last);
 const char msg[]="M15 RED_HOLD backend_unqualified control_permitted=false\n";
 (void)write(2,msg,sizeof(msg)-1);
 for(;;){
  int status;pid_t p;
  do{p=waitpid(-1,&status,WNOHANG);}while(p>0);
  /* Remain alive after ECHILD, failed logging, timeout or clock failure. No
   * module/ADSP/gadget cleanup and no inference of device safety. */
  if(offline){const char receipt[]="PERSISTENT_HOLD no_release no_reboot\n";(void)write(1,receipt,sizeof(receipt)-1);offline=0;}
  (void)poll(NULL,0,100);
 }
}
