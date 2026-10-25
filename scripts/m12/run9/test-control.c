#define _GNU_SOURCE
#include <unistd.h>
#include <errno.h>
#include <time.h>
static int fail_close=-1,fixed_clock;
static int close_fault(int fd){int r=close(fd);if(fd==fail_close){fail_close=-1;errno=EIO;return -1;}return r;}
static int controlled_clock(clockid_t c,struct timespec *t){if(fixed_clock){t->tv_sec=42;t->tv_nsec=381000000;return 0;}return clock_gettime(c,t);}
#define clock_gettime controlled_clock
#define M12_CTRL_CLOSE close_fault
static char control_dir[80];
#define WDIR control_dir
#define M12_NETWORK_TEST
#define main network_program_main
#include "network.c"
#undef main
#undef clock_gettime
#include <assert.h>
static char events[1024][48];static int values[1024],count;
static void trace(const char *s,int rc){assert(count<1024);snprintf(events[count],48,"%s",s);values[count++]=rc;}
static int seen(const char *s,int rc){for(int i=0;i<count;i++)if(!strcmp(events[i],s)&&values[i]==rc)return 1;return 0;}
static const char header[]="bssid / frequency / signal level / flags / ssid\n";
static void reply(int fd,const char *b,size_t n,const struct sockaddr_un *to){assert(sendto(fd,b,n,0,(const void*)to,sizeof(*to))==(ssize_t)n);}
static void event(int fd,const char *text,const struct sockaddr_un *to){reply(fd,text,strlen(text),to);}
static pid_t server(const char *mode){int ready[2];assert(!pipe(ready));pid_t p=fork();assert(p>=0);if(!p){close(ready[0]);int fd=socket(AF_UNIX,SOCK_DGRAM,0);assert(fd>=0);struct sockaddr_un sa={.sun_family=AF_UNIX},monitor={0};snprintf(sa.sun_path,sizeof(sa.sun_path),"%s/teststa",control_dir);assert(!bind(fd,(void*)&sa,sizeof(sa)));assert(write(ready[1],"1",1)==1);close(ready[1]);int attached=0;
  for(;;){char b[128];struct sockaddr_un from={0};socklen_t len=sizeof(from);ssize_t n=recvfrom(fd,b,sizeof(b)-1,0,(void*)&from,&len);assert(n>0);b[n]=0;
   if(!strcmp(b,"ATTACH")){monitor=from;attached=1;event(fd,"OK\n",&from);if(!strcmp(mode,"stale"))event(fd,"<3>CTRL-EVENT-SCAN-RESULTS",&monitor);}
   else if(!strcmp(b,"PING"))event(fd,"PONG\n",&from);
   else if(!strcmp(b,"LEVEL 3"))event(fd,attached&&!strcmp(from.sun_path,monitor.sun_path)?"OK\n":"FAIL\n",&from);
   else if(!strcmp(b,"SCAN")){
    if(!strcmp(mode,"reject")){event(fd,"FAIL-BUSY\n",&from);continue;}
    if(!strcmp(mode,"noack"))continue;
    if(!strcmp(mode,"badack")){event(fd,"unrecognized\n",&from);continue;}
    if(!strcmp(mode,"ordering"))event(fd,"<3>CTRL-EVENT-SCAN-RESULTS",&monitor);
    event(fd,"OK\n",&from);
    if(!strcmp(mode,"exit"))_exit(23);
    if(!strcmp(mode,"lostpath")){assert(!unlink(monitor.sun_path));continue;}
    if(!strcmp(mode,"failed")){event(fd,"<3>CTRL-EVENT-SCAN-FAILED ret=-16",&monitor);continue;}
    if(!strcmp(mode,"malformed")){event(fd,"<3>CTRL-EVENT-SCAN-FAILED ret=oops",&monitor);continue;}
    if(!strcmp(mode,"disconnect")){event(fd,"<3>CTRL-EVENT-TERMINATING - reason=fixture",&monitor);continue;}
    if(!strcmp(mode,"oversize")){char huge[5000];memset(huge,'x',sizeof(huge));reply(fd,huge,sizeof(huge),&monitor);continue;}
    if(!strcmp(mode,"startedflood")){for(unsigned j=0;j<17;j++)event(fd,"<3>CTRL-EVENT-SCAN-STARTED",&monitor);continue;}
    if(!strcmp(mode,"unknown")){char other[600];memset(other,'x',sizeof(other));memcpy(other,"<3>UNRELATED SYNTHETIC_SECRET ",29);reply(fd,other,sizeof(other),&monitor);}
    if(!strcmp(mode,"started")||!strcmp(mode,"noevent")||!strcmp(mode,"detached"))event(fd,"<3>CTRL-EVENT-SCAN-STARTED",&monitor);
    if(!strcmp(mode,"detached")){attached=0;continue;}
    if(strcmp(mode,"noevent")&&strcmp(mode,"ordering"))event(fd,"<3>CTRL-EVENT-SCAN-RESULTS",&monitor);
   }else if(!strcmp(b,"SCAN_RESULTS")){char results[4096];size_t n=strlen(header);memcpy(results,header,n);
    if(!strcmp(mode,"truncated")){memset(results+n,'x',sizeof(results)-n);n=sizeof(results);}
    else if(strcmp(mode,"zero")){const char *row=!strcmp(mode,"absent")?"00:11:22:33:44:55\t2412\t-50\t[WPA2]\tother\n":"00:11:22:33:44:55\t2412\t-50\t[WPA2]\tfixture-net\n";memcpy(results+n,row,strlen(row));n+=strlen(row);}
    reply(fd,results,n,&from);
   }else assert(0);
  }
 }
 close(ready[1]);char b;assert(read(ready[0],&b,1)==1);close(ready[0]);return p;
}
int main(void){
 char temp[]="/tmp/m12-control-XXXXXX";assert(mkdtemp(temp));strcpy(control_dir,temp);m12_test_ops.crumb=trace;
 const char *modes[]={"good","started","failed","reject","noack","badack","noevent","detached","lostpath","exit","zero","absent","truncated","malformed","disconnect","oversize","unknown","stale","ordering","startedflood"};
 const int errors[]={0,0,EBUSY,EBUSY,EAGAIN,EIO,ETIMEDOUT,ENOTCONN,ENOTCONN,ECHILD,ENODATA,ENOENT,EOVERFLOW,EPROTO,ENOTCONN,EMSGSIZE,0,0,0,EOVERFLOW};
 for(unsigned i=0;i<sizeof(modes)/sizeof(*modes);i++){
  count=0;supplicant=(struct m12_supplicant){.pid=server(modes[i]),.event=trace};char monitor[108];int ev=event_socket("teststa",monitor,sizeof(monitor));assert(ev>=0);
  if(!strcmp(modes[i],"stale")){struct pollfd queued={ev,POLLIN,0};assert(poll(&queued,1,1000)==1);}
  uint64_t start=now_ms();
  int r=scan_target("teststa",ev,(const unsigned char*)"fixture-net",11),e=errno;
  assert((r==0)==(errors[i]==0));if(r)assert(e==errors[i]);assert(seen("monitor_health_result",0));
  if(!strcmp(modes[i],"noevent")){assert(now_ms()-start>=25000&&now_ms()-start<28000);assert(seen("monitor_timeout_health",0)&&seen("scan_timeout_started",1));}
  if(!strcmp(modes[i],"detached"))assert(seen("monitor_lost",-ENOTCONN));
  if(!strcmp(modes[i],"lostpath"))assert(seen("monitor_path_error",-ENOENT));
  if(!strcmp(modes[i],"failed"))assert(seen("scan_failed_event",-16)&&now_ms()-start<3000);
  if(!strcmp(modes[i],"exit"))assert(seen("supplicant_exit",23)&&supplicant.reaped);
  if(!strcmp(modes[i],"zero"))assert(seen("scan_zero_aps",1));
  if(!strcmp(modes[i],"absent"))assert(seen("scan_target_absent",1));
  if(!strcmp(modes[i],"truncated"))assert(seen("scan_results_truncated",1));
  if(!errors[i])assert(seen("scan_target_found",1)&&seen("ctrl_distinct",1));
  if(!strcmp(modes[i],"stale"))assert(seen("scan_stale_events",1));
  for(int j=0;j<count;j++)assert(!strstr(events[j],"SYNTHETIC_SECRET"));
  assert(!sup_stop(&supplicant,1000));assert(!ctrl_release(ev));char path[108];snprintf(path,sizeof(path),"%s/teststa",temp);assert(!unlink(path));assert(dir_empty(temp));
 }
 /* Same-ms independent sockets, exhaustion, pre-existing name, failed
  * connect and injected close failure. Only each registered inode is retired. */
 count=0;supplicant=(struct m12_supplicant){.pid=server("good"),.event=trace};char mon[108],local[108];int ev=event_socket("teststa",mon,sizeof(mon));assert(ev>=0);
 fixed_clock=1;
 for(unsigned i=0;i<200;i++){int fd=ctrl_connect("teststa",local,sizeof(local));assert(fd>=0&&strcmp(local,mon));assert(!ctrl_owned(ev));assert(!ctrl_release(fd));assert(!ctrl_owned(ev));}
 fixed_clock=0;
 char occupied[108];snprintf(occupied,sizeof(occupied),"%s/c-%ld-%llu",temp,(long)getpid(),(unsigned long long)ctrl_sequence+1);int other=socket(AF_UNIX,SOCK_DGRAM,0);struct sockaddr_un addr={.sun_family=AF_UNIX};strcpy(addr.sun_path,occupied);assert(!bind(other,(void*)&addr,sizeof(addr)));assert(ctrl_connect("teststa",local,sizeof(local))<0&&errno==EADDRINUSE);struct stat st;assert(!lstat(occupied,&st)&&!ctrl_owned(ev));close(other);assert(!unlink(occupied));
 int fd=ctrl_connect("teststa",local,sizeof(local));assert(fd>=0);fail_close=fd;assert(ctrl_release(fd)<0&&errno==EIO);assert(access(local,F_OK)<0&&errno==ENOENT&&!ctrl_owned(ev));
 fd=ctrl_connect("teststa",local,sizeof(local));assert(fd>=0);assert(!unlink(local));other=socket(AF_UNIX,SOCK_DGRAM,0);strcpy(addr.sun_path,local);assert(!bind(other,(void*)&addr,sizeof(addr)));assert(ctrl_release(fd)<0&&errno==ESTALE);assert(!lstat(local,&st)&&!ctrl_owned(ev));close(other);assert(!unlink(local));
 assert(ctrl_connect("missing",local,sizeof(local))<0&&errno==ENOENT);
 assert(ctrl_connect("teststa",local,2)<0&&errno==ENAMETOOLONG);
 ctrl_sequence=INT_MAX;assert(ctrl_connect("teststa",local,sizeof(local))<0&&errno==EOVERFLOW);
 assert(!ctrl_release(ev));assert(!sup_stop(&supplicant,1000));snprintf(local,sizeof(local),"%s/teststa",temp);assert(!unlink(local)&&dir_empty(temp)&&!rmdir(temp));
 int ret;assert(scan_event_parse("bad",&ret)<0&&errno==EPROTO);assert(scan_event_parse("<3>CTRL-EVENT-SCAN-FAILED ret=2147483648",&ret)<0);unsigned char ssid[32];size_t used;const char *encoded="a\\x20b\\\\c\\\"";assert(!scan_ssid(encoded,strlen(encoded),ssid,&used));assert(used==6&&!memcmp(ssid,"a b\\c\"",6));
 puts("Run9 actual AF_UNIX:20 scan outcome/ordering/privacy/liveness cases; real25s deadline, detached monitor,200 same-ms cycles, bind/connect/close/inode/length/overflow ownership guards PASS; no radio");return 0;
}
