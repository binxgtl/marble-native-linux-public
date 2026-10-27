/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
int main(void){
 static const char *const tail[]={"regmap-spmi.ko","qcom-spmi-pmic.ko","pinctrl-spmi-gpio.ko","i2c-msm-geni.ko","qti_battery_charger_main.ko"};
 static const char empty[]="";
 for(unsigned i=0;i<sizeof(tail)/sizeof(tail[0]);i++){
  char path[128];snprintf(path,sizeof(path),"/lib/modules/%s",tail[i]);
  int fd=open(path,O_RDONLY|O_CLOEXEC);if(fd<0){fprintf(stderr,"M15 tail open index=%u errno=%d\n",i,errno);return 1;}
  errno=0;long rc=syscall(SYS_finit_module,fd,empty,0);int error=errno,closed=close(fd);
  fprintf(stderr,"M15 tail index=%u rc=%ld errno=%d close=%d\n",i,rc,error,closed);
  if(rc||closed)return 1;
 }
 return 0;
}
