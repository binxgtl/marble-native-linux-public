/* One admitted sysfs write, supervised by PID1; no retries or daemonization. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
static int trigger(void) {
 int fd=open("/sys/kernel/cnss/fs_ready",O_WRONLY|O_NOFOLLOW|O_CLOEXEC);
 int e=fd<0?errno:0,rc=fd<0?-e:0;
 printf("M12FS open raw_rc=%d errno=%d\n",fd,e);
 if(fd>=0) {
  ssize_t n=write(fd,"1",1);e=n<0?errno:0;
  printf("M12FS write raw_rc=%ld errno=%d\n",(long)n,e);
  rc=n==1?0:n<0?-e:-EIO;
  int cr=close(fd);e=cr<0?errno:0;
  printf("M12FS close raw_rc=%d errno=%d\n",cr,e);
  if(!rc && cr)rc=-e;
 }
 printf("M12FS final raw_rc=%d errno=%d\n",rc,rc<0?-rc:0);
 return fflush(stdout)?3:rc?2:0;
}
int m12_fs_ready_main(int argc,char **argv) {
 (void)argv;
 if(argc!=1 || getppid()!=1)return 2;
 return trigger();
}
#ifndef M12_RUN5_EMBEDDED
int main(int argc,char **argv){return m12_fs_ready_main(argc,argv);}
#endif
