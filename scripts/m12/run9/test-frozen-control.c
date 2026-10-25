/* Execute the immutable Run8 C functions with fixed clock and real AF_UNIX.
 * The fake retains the monitor pathname, just like pinned2.12. */
#define _GNU_SOURCE
#include <time.h>
static int frozen_clock(clockid_t id,struct timespec *t){(void)id;t->tv_sec=42;t->tv_nsec=381000000;return 0;}
#define clock_gettime frozen_clock
static char control_dir[80];
#define WDIR control_dir
#define M12_NETWORK_TEST
#define main frozen_main
#include "../run8/network.c"
#undef main
#undef clock_gettime
#include <assert.h>
static void trace(const char *s,int rc){(void)s;(void)rc;}
int main(void){
 char dir[]="/tmp/m12-frozen-XXXXXX";assert(mkdtemp(dir));strcpy(control_dir,dir);
 int ready[2],witness[2];assert(!pipe(ready)&&!pipe(witness));pid_t child=fork();assert(child>=0);
 if(!child){close(ready[0]);close(witness[0]);int fd=socket(AF_UNIX,SOCK_DGRAM,0);assert(fd>=0);struct sockaddr_un server={.sun_family=AF_UNIX},monitor={0};snprintf(server.sun_path,sizeof(server.sun_path),"%s/teststa",dir);assert(!bind(fd,(void*)&server,sizeof(server)));assert(write(ready[1],"1",1)==1);
  for(;;){char b[128];struct sockaddr_un from;socklen_t n=sizeof(from);ssize_t z=recvfrom(fd,b,sizeof(b)-1,0,(void*)&from,&n);assert(z>0);b[z]=0;if(!strcmp(b,"ATTACH")){monitor=from;assert(sendto(fd,"OK\n",3,0,(void*)&from,n)==3);}else if(!strcmp(b,"SCAN")){assert(sendto(fd,"OK\n",3,0,(void*)&from,n)==3);struct timespec delay={0,200000000};nanosleep(&delay,NULL);int error=0;const char event[]="<3>CTRL-EVENT-SCAN-RESULTS";if(sendto(fd,event,sizeof(event)-1,MSG_DONTWAIT,(void*)&monitor,sizeof(monitor))<0)error=errno;assert(write(witness[1],&error,sizeof(error))==sizeof(error));_exit(0);}else assert(0);}
 }
 close(ready[1]);close(witness[1]);char one;assert(read(ready[0],&one,1)==1);close(ready[0]);m12_test_ops.crumb=trace;
 char path[108];int ev=event_socket("teststa",path,sizeof(path));assert(ev>=0);struct stat initial;assert(!lstat(path,&initial));assert(!command_ok("teststa","SCAN"));
 assert(lstat(path,&initial)<0&&errno==ENOENT);int error;assert(read(witness[0],&error,sizeof(error))==sizeof(error)&&error==ENOENT);close(witness[0]);struct pollfd p={ev,POLLIN,0};assert(poll(&p,1,100)==0);close(ev);int st;assert(waitpid(child,&st,0)==child&&WIFEXITED(st)&&!WEXITSTATUS(st));snprintf(path,sizeof(path),"%s/teststa",dir);assert(!unlink(path)&&!rmdir(dir));
 puts("Frozen Run8 source oracle: fixed same-ms ATTACH/SCAN collision removes monitor pathname; async send ENOENT, no monitor event PASS; no radio");return 0;
}
