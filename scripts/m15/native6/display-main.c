/* SPDX-License-Identifier: GPL-2.0-only */
#include "display-loop.h"
#include "m9-kms.h"
#include <signal.h>
#include <string.h>
#include <unistd.h>
int main(int argc,char **argv){
 signal(SIGPIPE,SIG_IGN);
 uint32_t first=0x000000ff;
 if(argc==2&&!strcmp(argv[1],"wait")){first=0x00ff00ff;m15_display_ready="M15DISPLAY 0 WAIT committed\n";}
 int rc=m9_kms_cpu_checkpoint("/dev/dri/card0",first,0);
 (void)rc;
 /* Setup failure cannot prove RED visible; parent observes EOF only if exited,
  * so explicitly report failure then retain process/resources. */
 const char error[]="M15DISPLAY ERROR\n";
 ssize_t n=write(3,error,sizeof(error)-1);(void)n;
 for(;;)pause();
}
