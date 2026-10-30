/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include "run.h"
#include <poll.h>
#include <signal.h>
#include <sys/random.h>
#include <sys/wait.h>
#include <unistd.h>

#define NONBLOCKING_RANDOM 0x0004u /* GRND_INSECURE: early boot must not wait for entropy */
#define TAG 0x31u /* Run1; a different value from every earlier test alarm */

static struct m16_linux adapter;
static struct m16_run run={
 .config={.alarm_s=45,.early_s=15,.late_s=5,.resume_margin_s=20,.channel_s=420,.export_s=60,.ack_s=300,.cycle_mode=1},
 .root="",.bootstrap="/m16/bootstrap",.adsp="/m16/adsp",.connector="/sbin/m15-connector",.display="/sbin/m16-display",
 .tty="/dev/ttyGS0",.kmsg="/dev/kmsg",.boot_log="/run/m16/bootstrap.log",.tag=TAG,
 .bootstrap_ms=120000,.settle_ms=20000,.display_ms=20000,.blue_ms=5000,.final_ms=600000,.step_ms=5,.pace_ms=20,.log_ms=180000};
int main(void) {
 if(getpid()!=1)return 64;
 signal(SIGPIPE,SIG_IGN);signal(SIGCHLD,SIG_DFL);
 m16_linux_init(&adapter,"",5000);
 m16_linux_ops(&run.base,&adapter);
 if(getrandom(run.nonce,sizeof(run.nonce),NONBLOCKING_RANDOM)==(ssize_t)sizeof(run.nonce))(void)m16_run_main(&run);
 /* PID1 must never exit, and this runtime has no reboot path. Long-power ends the run. */
 for(;;){
  int status;
  while(waitpid(-1,&status,WNOHANG)>0){}
  (void)poll(NULL,0,100);
 }
}
