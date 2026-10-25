#define _GNU_SOURCE
static char control_dir[80];
#define WDIR control_dir
#define M12_NETWORK_TEST
#define main unused_network_main
#include "network.c"
#undef main
#include <assert.h>
static char events[128][48];static int values[128],count;
static void event(const char *name,int rc){assert(count<128);snprintf(events[count],48,"%s",name);values[count++]=rc;}
static int seen(const char *name,int rc){for(int i=0;i<count;i++)if(!strcmp(events[i],name)&&values[i]==rc)return 1;return 0;}
static int fake(const char *mode,const char *path){
 if(!strcmp(mode,"exit255")){fputs("Failed to read or parse configuration 'SYNTHETIC_SECRET'.\n",stderr);return 255;}
 if(!strcmp(mode,"exit0"))return 0;
 if(!strcmp(mode,"signal")){raise(SIGTERM);return 1;}
 if(!strcmp(mode,"flood")){char b[1024];memset(b,'x',sizeof(b));for(unsigned i=0;i<1024;i++)if(write(2,b,sizeof(b))<0)break;return 0;}
 if(!strcmp(mode,"ignore"))signal(SIGTERM,SIG_IGN);
 if(!strcmp(mode,"socket")||!strcmp(mode,"attachfail")){
  struct timespec t={0,200000000};nanosleep(&t,NULL);
  int fd=socket(AF_UNIX,SOCK_DGRAM,0);assert(fd>=0);struct sockaddr_un a={.sun_family=AF_UNIX};assert(strlen(path)<sizeof(a.sun_path));strcpy(a.sun_path,path);assert(!bind(fd,(void*)&a,sizeof(a)));
  char b[64];struct sockaddr_un client;socklen_t n=sizeof(client);assert(recvfrom(fd,b,sizeof(b),0,(void*)&client,&n)==6);
  const char *reply=!strcmp(mode,"socket")?"OK\n":"FAIL\n";assert(sendto(fd,reply,strlen(reply),0,(void*)&client,n)==(ssize_t)strlen(reply));
 }
 for(;;)pause();
}
int main(int argc,char **argv){
 if(argc==4&&!strcmp(argv[1],"--fake"))return fake(argv[2],argv[3]);
 m12_test_ops.crumb=event;
 char temp[]="/tmp/m12-sup-XXXXXX";assert(mkdtemp(temp));snprintf(control_dir,sizeof(control_dir),"%s",temp);
 char log[128],sock[128];snprintf(log,sizeof(log),"%s/log",temp);snprintf(sock,sizeof(sock),"%s/teststa",temp);
 static const char *modes[]={"exit255","exit0","signal","socket","attachfail","never","ignore","flood"};
 for(unsigned i=0;i<sizeof(modes)/sizeof(*modes);i++){
  struct m12_supplicant s;count=0;char *args[]={argv[0],"--fake",(char*)modes[i],sock,NULL};
  uint64_t begin=sup_ms();assert(sup_spawn(&s,args,log,event)>0);assert(seen("supplicant_exec",0)&&seen("supplicant_spawned",0));
  if(i<3){assert(sup_ctrl_wait(&s,sock,12000)<0&&errno==ECHILD&&s.reaped);assert(sup_ms()-begin<3000);assert(seen("supplicant_exit",i==0?255:i==1?0:143));}
  else if(i==3||i==4){
   assert(!sup_ctrl_wait(&s,sock,12000)&&seen("ctrl_wait_ready",0));
   char local[108]={0};int fd=event_socket("teststa",local,sizeof(local));assert((fd>=0)==(i==3));
   if(fd>=0){assert(!ctrl_release(fd));}else assert(errno==EPROTO);
  }else if(i==5){assert(sup_ctrl_wait(&s,sock,12000)<0&&errno==ETIMEDOUT&&!s.reaped);assert(sup_ms()-begin>=12000&&sup_ms()-begin<15000);assert(seen("ctrl_wait_failed",-ETIMEDOUT));}
  else if(i==6){struct timespec t={0,200000000};nanosleep(&t,NULL);}
  else assert(!sup_wait(&s,3000));
  assert(!sup_stop(&s,100));assert(s.reaped);if(i==6)assert(seen("supplicant_exit",137));
  int st;assert(waitpid(s.pid,&st,WNOHANG)==-1&&errno==ECHILD);assert(!sup_stop(&s,100));
  assert(!sup_diagnostics(&s));assert(access(log,F_OK)<0&&errno==ENOENT);
  if(!i)assert(seen("supplicant_diag_config",1));
  if(i==7)assert(seen("supplicant_diag_capped",1));
  for(int j=0;j<count;j++)assert(!strstr(events[j],"SYNTHETIC_SECRET"));
  unlink(sock);
 }
 /* Real exec receipt: distinguish missing/execution-permission/bad-ELF failures. */
 char bad[128];snprintf(bad,sizeof(bad),"%s/bad",temp);
 for(unsigned i=0;i<3;i++){
  if(i){FILE*f=fopen(bad,"w");assert(f);fputs("not-an-ELF\n",f);fclose(f);assert(!chmod(bad,i==1?0600:0700));}
  count=0;char *a[]={bad,NULL};struct m12_supplicant s;assert(sup_spawn(&s,a,log,event)<0);
  int expected=i==0?ENOENT:i==1?EACCES:ENOEXEC;assert(errno==expected&&seen("supplicant_exec",-expected));
  assert(!sup_wait(&s,3000)&&seen("supplicant_exit",127));assert(!sup_diagnostics(&s));
 }
 unlink(bad);assert(!rmdir(temp));
 puts("Actual fork/exec: exits0/255/signal, exec ENOENT/EACCES/ENOEXEC, real12s alive timeout, socket+ATTACH OK/FAIL, SIGKILL/reap,16KiB cap and secret suppression PASS; no radio");
 return 0;
}
