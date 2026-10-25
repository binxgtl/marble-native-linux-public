/* SPDX-License-Identifier: GPL-2.0-only */
/* Synthetic fixture faults only; no test control in production observer. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int __real_open(const char *,int,...);
ssize_t __real_read(int,void *,size_t);
ssize_t __real___read_chk(int,void *,size_t,size_t);

static const char *mode(void) { const char *s=getenv("M15_TEST_FAULT");return s?s:""; }
int __wrap_open(const char *path,int flags,...) {
 if(strstr(path,"/qcom-battery/apdo_max") && !strcmp(mode(),"vendor-open-error")) {
  fputs("vendor-open-error injected\n",stderr);errno=EACCES;return -1;
 }
 if(strstr(path,"-partner/")) {
  /* A real unlink between discovery and the observed open, only inside the
   * synthetic fixture tree. Production has neither unlink nor this wrapper. */
  static int removed;
  if(!removed && !strcmp(mode(),"partner-disappear") && strstr(path,"supports_usb_power_delivery")) {
   if(unlink(path))_exit(93);
   removed=1;
   fputs("partner-disappear injected\n",stderr);
  }
 }
 return __real_open(path,flags);
}
ssize_t __wrap_read(int fd,void *buf,size_t size) {
 char link[64],path[4096];snprintf(link,sizeof(link),"/proc/self/fd/%d",fd);
 ssize_t n=readlink(link,path,sizeof(path)-1);
 if(n>0) {
  path[n]=0;
  if(strstr(path,"/qcom-battery/pdo2") && !strcmp(mode(),"vendor-read-error")) {
   fputs("vendor-read-error injected\n",stderr);errno=EIO;return -1;
  }
  if(strstr(path,"-partner/") && !strcmp(mode(),"partner-read-error")) {
   fputs("partner-read-error injected\n",stderr);errno=EIO;return -1;
  }
  if(strstr(path,"/qcom-battery/pdo2") && !strcmp(mode(),"optional-read-block")) {
   fputs("optional-read-block injected\n",stderr);sleep(10);
  }
 }
 if(!strcmp(mode(),"short-read") && size>1)size=1;
 return __real_read(fd,buf,size);
}
ssize_t __wrap___read_chk(int fd,void *buf,size_t size,size_t available) {
 if(size>available)return __real___read_chk(fd,buf,size,available);
 return __wrap_read(fd,buf,size);
}
