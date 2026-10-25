/* Real AF_UNIX peer tests of the production control path; no radio/device. */
#define M12_NETWORK_TEST
#define M12_DISCONNECT_TIMEOUT_MS 150
#define M12_DISCONNECT_HOLD_MS 150
#define main network_main
#include "network.c"
#undef main
#include <assert.h>
static int testmode;
static void quiet_crumb(const char *s,int rc){(void)s;(void)rc;}
static void peer(int server,int ev){
 int disconnected=0,seen=0;for(;;){
  char b[256];struct sockaddr_un who={0};socklen_t n=sizeof(who);ssize_t z=recvfrom(server,b,sizeof(b)-1,0,(void*)&who,&n);if(z<0)_exit(1);b[z]=0;
  const char *reply=NULL;
  if(!strcmp(b,"DISCONNECT")){
   reply=testmode==1?"FAIL\n":"OK\n";disconnected=1;
   if(sendto(server,reply,strlen(reply),0,(void*)&who,n)!=(ssize_t)strlen(reply))_exit(2);
   if(testmode!=2){const char *e="<3>CTRL-EVENT-DISCONNECTED locally_generated=1";if(send(ev,e,strlen(e),0)!=(ssize_t)strlen(e))_exit(3);}continue;
  }
  if(strcmp(b,"STATUS"))_exit(4);
  if(!disconnected)reply="wpa_state=COMPLETED\nid=0\n";
  else if(testmode==3 || (testmode==4 && ++seen>1))reply="wpa_state=COMPLETED\nid=0\n";
  else if(testmode==5)reply="xwpa_state=DISCONNECTED\nid=0\n";
  else reply="wpa_state=DISCONNECTED\n";
  if(sendto(server,reply,strlen(reply),0,(void*)&who,n)!=(ssize_t)strlen(reply))_exit(5);
 }
}
int main(void){
 char root[]="/tmp/m12-run11-XXXXXX";assert(mkdtemp(root));assert(!chdir(root));assert(!mkdir("m12",0700));assert(!mkdir("m12/wpa",0700));
 m12_test_ops.crumb=quiet_crumb;
 for(testmode=0;testmode<6;testmode++){
  int server=socket(AF_UNIX,SOCK_DGRAM|SOCK_CLOEXEC,0);assert(server>=0);
  struct sockaddr_un a={.sun_family=AF_UNIX};strcpy(a.sun_path,WDIR "/teststa");assert(!bind(server,(void*)&a,sizeof(a)));
  int ev[2];assert(!socketpair(AF_UNIX,SOCK_DGRAM|SOCK_CLOEXEC,0,ev));
  /* An old event must be drained; it cannot replace the new event in mode2. */
  const char stale[]="<3>CTRL-EVENT-DISCONNECTED stale=1";assert(send(ev[1],stale,sizeof(stale)-1,0)==sizeof(stale)-1);
  pid_t p=fork();assert(p>=0);if(!p){close(ev[0]);peer(server,ev[1]);_exit(0);}
  close(ev[1]);int rc=disconnect_phase("teststa",ev[0]);assert(testmode==0?rc==0:rc<0);
  assert(!kill(p,SIGTERM));int st;assert(waitpid(p,&st,0)==p);assert(WIFSIGNALED(st)&&WTERMSIG(st)==SIGTERM);
  close(ev[0]);close(server);assert(!unlink(WDIR "/teststa"));assert(dir_empty(WDIR));
 }
 assert(!rmdir(WDIR));assert(!rmdir("m12"));assert(!chdir("/"));assert(!rmdir(root));
 puts("Run11 actual control peer: disconnect ACK/event/status/dwell PASS; NACK/missing fresh event/still-connected/early-reconnect/prefix-spoof rejected; no hardware");return 0;
}
