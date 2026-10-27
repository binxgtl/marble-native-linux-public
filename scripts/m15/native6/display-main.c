/* SPDX-License-Identifier: GPL-2.0-only */
#include "m9-kms.h"
#include <signal.h>
#include <unistd.h>
int main(void){
 signal(SIGPIPE,SIG_IGN);
 int rc=m9_kms_cpu_checkpoint("/dev/dri/card0",0x000000ff,0);
 (void)rc;
 /* Setup failure cannot prove RED visible; parent observes EOF only if exited,
  * so explicitly report failure then retain process/resources. */
 const char error[]="M15DISPLAY ERROR\n";
 ssize_t n=write(3,error,sizeof(error)-1);(void)n;
 for(;;)pause();
}
