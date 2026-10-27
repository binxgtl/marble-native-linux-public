/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include "connector.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/netlink.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <time.h>
#include <unistd.h>
#define G "/config/usb_gadget/m15"
#define U "/sys/class/udc/a600000.dwc3"
#define P "/sys/class/typec/port0-partner"
static unsigned long long now(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return 0;return (unsigned long long)t.tv_sec*1000+t.tv_nsec/1000000;}
static int attr(const char *path,char *b,size_t cap){
 int fd=open(path,O_RDONLY|O_CLOEXEC|O_NONBLOCK);if(fd<0)return -1;
 ssize_t n=read(fd,b,cap-1);int error=errno,c=close(fd);errno=error;
 if(n<0||c||n==(ssize_t)cap-1)return -1;
 b[n]=0;while(n>0&&b[n-1]=='\n')b[--n]=0;return 0;
}
static int put(const char *path,const char *v){
 int fd=open(path,O_WRONLY|O_CLOEXEC|O_NONBLOCK);if(fd<0)return -1;
 size_t n=strlen(v);ssize_t k=write(fd,v,n);int error=errno,c=close(fd);errno=error;
 return k==(ssize_t)n&&!c?0:-1;
}
static void message(const char *text){if(dprintf(1,"%s\n",text)<0)_exit(70);}
static int sink_role(void){char b[80];return !attr("/sys/class/typec/port0/power_role",b,sizeof(b))&&(!strcmp(b,"sink")||strstr(b,"[sink]"));}
static int same_port(const char *expected){char real[PATH_MAX];return realpath("/sys/class/typec/port0",real)&&!strcmp(real,expected);}
static int partner_snapshot(int present,const char *port){
 unsigned long long end=now()+5000;
 while(now()<end){
  struct stat st;int rc=lstat(P,&st),error=errno;
  if(rc&&error!=ENOENT)return -1;
  if((rc==0)==present)return same_port(port)&&sink_role()?0:-1;
  /* Device uevents can precede class-link removal/publication. A deadline
   * merely bounds readback polling; it never supplies a missing predicate. */
  (void)poll(NULL,0,10);
 }
 errno=ETIMEDOUT;return -1;
}
static int configured(void){char b[80];return !attr(U "/state",b,sizeof(b))&&!strcmp(b,"configured");}
static int unbind(void){
 char b[128],f[128];
 if(attr(G "/UDC",b,sizeof(b)))return -1;
 if(*b&&put(G "/UDC","none"))return -1;
 if(attr(G "/UDC",b,sizeof(b))||*b)return -1;
 if(!attr(U "/function",f,sizeof(f)))return *f?-1:0;
 /* UDC may have been removed by connector-driven role=none. Only explicit
  * ENOENT plus its own lstat absence is accepted; other getter errors fail. */
 if(errno!=ENOENT)return -1;
 struct stat st;return lstat(U,&st)&&errno==ENOENT?0:-1;
}
static int build(void){
 struct stat st;if(!lstat("/config",&st)||errno!=ENOENT)return -1;
 if(mkdir("/config",0755)||mount("configfs","/config","configfs",MS_NOSUID|MS_NODEV|MS_NOEXEC,NULL)||mkdir(G,0755))return -1;
 const char *paths[]={"idVendor","idProduct","bDeviceClass","bDeviceSubClass","bDeviceProtocol"};
 const char *values[]={"0x1d6b","0x0104","0xef","0x02","0x01"};char path[256];
 for(unsigned i=0;i<5;i++){snprintf(path,sizeof(path),G "/%s",paths[i]);if(put(path,values[i]))return -1;}
 if(mkdir(G "/strings/0x409",0755)||mkdir(G "/configs/c.1",0755)||mkdir(G "/configs/c.1/strings/0x409",0755)||mkdir(G "/functions/acm.usb0",0755))return -1;
 if(put(G "/strings/0x409/manufacturer","marble-native-linux")||put(G "/strings/0x409/product","M15 RAM evidence")||put(G "/strings/0x409/serialnumber","M15RAM")||put(G "/configs/c.1/strings/0x409/configuration","acm")||symlink(G "/functions/acm.usb0",G "/configs/c.1/acm.usb0"))return -1;
 char dev[64],extra;unsigned maj,min;
 if(attr("/sys/class/tty/ttyGS0/dev",dev,sizeof(dev))||sscanf(dev,"%u:%u%c",&maj,&min,&extra)!=2||!maj)return -1;
 return mknod("/dev/ttyGS0",S_IFCHR|0600,makedev(maj,min));
}
int main(void){
 signal(SIGPIPE,SIG_IGN);setvbuf(stdout,NULL,_IONBF,0);
 int fd=socket(AF_NETLINK,SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK,NETLINK_KOBJECT_UEVENT),one=1,size=1048576;
 if(fd<0||setsockopt(fd,SOL_SOCKET,SO_PASSCRED,&one,sizeof(one))||setsockopt(fd,SOL_SOCKET,SO_RCVBUF,&size,sizeof(size)))goto fail;
 {socklen_t n=sizeof(size);if(getsockopt(fd,SOL_SOCKET,SO_RCVBUF,&size,&n)||n!=sizeof(size)||size<262144)goto fail;dprintf(2,"M15 uevent receive buffer=%d\n",size);}
 struct sockaddr_nl local={.nl_family=AF_NETLINK,.nl_groups=1};
 if(bind(fd,(struct sockaddr *)&local,sizeof(local)))goto fail;
 char real[PATH_MAX];if(!realpath("/sys/class/typec/port0",real)||strncmp(real,"/sys/devices/",13))goto fail;
 struct connector s={0};
 if(snprintf(s.partner,sizeof(s.partner),"%s/port0-partner",real+4)>=(int)sizeof(s.partner))goto fail;
 /* Drain subscription startup before the baseline snapshot. Any connector
  * event during this small window fails admission rather than manufacturing it. */
 struct stat st;if(lstat(P,&st)||!sink_role()||build())goto fail;
 s.attached=1;int bound=0,ready=0,pending_bind=1;
 unsigned long long deadline=now()+30000;char command[32];size_t at=0;
 for(;;){
  if(pending_bind){
   if(now()>=deadline)goto fail;
   if(!bound&&!lstat(U,&st)){if(put(G "/UDC","a600000.dwc3"))goto fail;bound=1;}
   if(bound&&configured()&&!lstat(P,&st)&&sink_role()){
    message(ready?"BOUND":"CONNECTOR_READY");ready=1;pending_bind=0;
   }
  }
  struct pollfd p[2]={{fd,POLLIN,0},{0,POLLIN,0}};
  int rc=poll(p,2,100);if(rc<0){if(errno==EINTR)continue;goto fail;}
  if(p[0].revents){
   char bytes[16384],control[CMSG_SPACE(sizeof(struct ucred))];struct sockaddr_nl peer;
   struct iovec iov={bytes,sizeof(bytes)};struct msghdr msg={.msg_name=&peer,.msg_namelen=sizeof(peer),.msg_iov=&iov,.msg_iovlen=1,.msg_control=control,.msg_controllen=sizeof(control)};
   ssize_t n=recvmsg(fd,&msg,0);if(n<0){if(errno==EAGAIN||errno==EINTR)continue;goto fail;}
   int kernel=0;
   for(struct cmsghdr *c=CMSG_FIRSTHDR(&msg);c;c=CMSG_NXTHDR(&msg,c))if(c->cmsg_level==SOL_SOCKET&&c->cmsg_type==SCM_CREDENTIALS&&c->cmsg_len==CMSG_LEN(sizeof(struct ucred))){struct ucred u;memcpy(&u,CMSG_DATA(c),sizeof(u));kernel=u.pid==0&&u.uid==0&&u.gid==0;}
   kernel=kernel&&msg.msg_namelen==sizeof(peer)&&peer.nl_family==AF_NETLINK&&peer.nl_pid==0;
   int event=connector_event(&s,bytes,(size_t)n,kernel,msg.msg_flags&(MSG_TRUNC|MSG_CTRUNC));if(event<0)goto fail;
   if(event==2){if(partner_snapshot(0,real))goto fail;message("REMOVED");}
   if(event==1){if(partner_snapshot(1,real))goto fail;message("ATTACHED");}
  }
  if(p[1].revents){
   char c;ssize_t n=read(0,&c,1);if(n<0&&errno==EINTR)continue;
   if(n!=1||at>=sizeof(command)-1)goto fail;
   if(c!='\n'){if(c<32||c>126)goto fail;command[at++]=c;continue;}
   command[at]=0;at=0;
   if(!strcmp(command,"UNBIND")&&!s.attached&&!pending_bind){if(unbind())goto fail;bound=0;message("UNBOUND");}
   else if(!strcmp(command,"BIND")&&s.attached&&!bound&&!pending_bind){pending_bind=1;deadline=now()+30000;}
   else goto fail;
  }
 }
fail:
 {int saved=errno;dprintf(2,"M15 connector failure errno=%d\n",saved);message("CONNECTOR_FAILED");}
 /* Preserve configfs/ADSP on failure. Parent observes failure and holds. */
 for(;;)pause();
}
