/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
/* The one module S3 adds to the M8 closure. It needs the SPMI layer from the M8 tail first. */
int main(void){
 static const char empty[]="";
 int fd=open("/lib/modules/rtc-pm8xxx.ko",O_RDONLY|O_CLOEXEC);
 if(fd<0){fprintf(stderr,"M16 rtc open errno=%d\n",errno);return 1;}
 errno=0;long rc=syscall(SYS_finit_module,fd,empty,0);int error=errno,closed=close(fd);
 fprintf(stderr,"M16 rtc rc=%ld errno=%d close=%d\n",rc,error,closed);
 return rc||closed?1:0;
}
