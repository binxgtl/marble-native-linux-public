/* SPDX-License-Identifier: GPL-2.0-only */
/* Linker-only fault injection; not linked into redistributable observer. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
ssize_t __real_read(int,void *,size_t);
ssize_t __real___read_chk(int,void *,size_t,size_t);
ssize_t __real_write(int,const void *,size_t);
ssize_t __wrap_read(int fd,void *buf,size_t size) {
 const char *mode=getenv("M15_TEST_FAULT");
 if(mode && !strcmp(mode,"read-block")) {
  char p[64],target[4096];snprintf(p,sizeof(p),"/proc/self/fd/%d",fd);
  ssize_t n=readlink(p,target,sizeof(target)-1);
  if(n>0){target[n]=0;if(strstr(target,"/battery/type")){fputs("read-block injected\n",stderr);sleep(10);}}
 }
 if(mode && !strcmp(mode,"short-read") && size>1)size=1;
 static int interrupted;
 if(mode && !strcmp(mode,"eintr") && !interrupted++){errno=EINTR;return -1;}
 return __real_read(fd,buf,size);
}
/* Hosted Ubuntu's fortified read may bind to __read_chk instead of read.
 * Keep its bounds check and inject only after the same size contract passes. */
ssize_t __wrap___read_chk(int fd,void *buf,size_t size,size_t available) {
 if(size>available)return __real___read_chk(fd,buf,size,available);
 return __wrap_read(fd,buf,size);
}
ssize_t __wrap_write(int fd,const void *buf,size_t size) {
 const char *mode=getenv("M15_TEST_FAULT");
 if(mode && !strcmp(mode,"short-write") && size>3)size=3;
 if(mode && !strcmp(mode,"output-error") && fd==STDOUT_FILENO){errno=EIO;return -1;}
 return __real_write(fd,buf,size);
}
