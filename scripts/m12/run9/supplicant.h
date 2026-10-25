#ifndef M12_SUPPLICANT_H
#define M12_SUPPLICANT_H
/* One owned child, one CLOEXEC receipt, one bounded RAM diagnostic file.
 * Never publish raw supplicant text (even on failure): only fixed categories. */
#include <sys/resource.h>
struct m12_supplicant {
 pid_t pid;
 int reaped, status, log_owned;
 const char *log_path;
 void (*event)(const char *,int);
};
static uint64_t sup_ms(void) {
 struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return 0;
 return (uint64_t)t.tv_sec*1000+(uint64_t)t.tv_nsec/1000000;
}
static void sup_pause(void){struct timespec t={0,20000000};nanosleep(&t,NULL);}
/* 0 alive, 1 reaped, -1 error. Never wait twice for a reaped child. */
static int sup_check(struct m12_supplicant *s) {
 if(s->reaped)return 1;
 int st;pid_t p=waitpid(s->pid,&st,WNOHANG);
 if(p==s->pid){s->reaped=1;s->status=st;
  s->event("supplicant_wait_status",st);
  s->event("supplicant_exit",WIFEXITED(st)?WEXITSTATUS(st):WIFSIGNALED(st)?128+WTERMSIG(st):-EPROTO);
  return 1;
 }
 if(p<0&&errno==EINTR)return 0;
 return p<0?-1:0;
}
static int sup_wait(struct m12_supplicant *s,unsigned ms) {
 uint64_t end=sup_ms()+ms;
 do{int r=sup_check(s);if(r)return r<0?-1:0;sup_pause();}while(sup_ms()<end);
 errno=ETIMEDOUT;return -1;
}
static int sup_stop(struct m12_supplicant *s,unsigned ms) {
 if(s->pid<=0||s->reaped)return 0;
 int r=sup_check(s);if(r)return r<0?-1:0;
 if(kill(s->pid,SIGTERM)&&errno!=ESRCH)return -1;
 if(!sup_wait(s,ms))return 0;
 if(errno!=ETIMEDOUT)return -1;
 if(kill(s->pid,SIGKILL)&&errno!=ESRCH)return -1;
 return sup_wait(s,2000);
}
static void sup_child_error(int fd,int error) {
 const char *b=(const char *)&error;size_t p=0;
 while(p<sizeof(error)){ssize_t n=write(fd,b+p,sizeof(error)-p);if(n<0&&errno==EINTR)continue;if(n<=0)break;p+=(size_t)n;}
 _exit(127);
}
static pid_t sup_spawn(struct m12_supplicant *s,char *const argv[],const char *log_path,void (*event)(const char *,int)) {
 *s=(struct m12_supplicant){.pid=-1,.log_path=log_path,.event=event};
 int log=open(log_path,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);
 if(log<0){event("supplicant_exec",-errno);return -1;}s->log_owned=1;
 if(log<3){int n=fcntl(log,F_DUPFD_CLOEXEC,3);if(n<0){int e=errno;close(log);event("supplicant_exec",-e);errno=e;return -1;}close(log);log=n;}
 int fds[2];if(pipe2(fds,O_CLOEXEC)){int e=errno;close(log);event("supplicant_exec",-e);errno=e;return -1;}
 /* Descriptors0..2 need not already exist in minimal PID1 environments. */
 for(unsigned i=0;i<2;i++)if(fds[i]<3){int n=fcntl(fds[i],F_DUPFD_CLOEXEC,3);if(n<0){int e=errno;close(fds[0]);close(fds[1]);close(log);event("supplicant_exec",-e);errno=e;return -1;}close(fds[i]);fds[i]=n;}
 pid_t p=fork();
 if(p<0){int e=errno;close(fds[0]);close(fds[1]);close(log);event("supplicant_exec",-e);errno=e;return -1;}
 if(!p){
  close(fds[0]);
  struct rlimit limit={16384,16384},core={0,0};
  if(setrlimit(RLIMIT_FSIZE,&limit)||setrlimit(RLIMIT_CORE,&core))sup_child_error(fds[1],errno);
  int input=open("/dev/null",O_RDONLY|O_CLOEXEC);
  if(input<0||dup2(input,0)<0||dup2(log,1)<0||dup2(log,2)<0)sup_child_error(fds[1],errno);
  long max=sysconf(_SC_OPEN_MAX);if(max<0||max>4096)max=4096;
  for(int i=3;i<max;i++)if(i!=fds[1])close(i);
  execv(argv[0],argv);sup_child_error(fds[1],errno);
 }
 s->pid=p;close(fds[1]);close(log);event("supplicant_spawned",0);
 uint64_t end=sup_ms()+3000;int error=0;size_t got=0;int rc=-ETIMEDOUT;
 while(sup_ms()<end){
  struct pollfd pollfd={fds[0],POLLIN,0};int z=poll(&pollfd,1,100);
  if(z<0&&errno==EINTR)continue;
  if(z<0){rc=-errno;break;}
  if(!z)continue;
  ssize_t n=read(fds[0],(char *)&error+got,sizeof(error)-got);
  if(n<0&&errno==EINTR)continue;
  if(n<0){rc=-errno;break;}
  if(!n){rc=got?-EPROTO:0;break;}
  got+=(size_t)n;if(got==sizeof(error)){rc=error>0?-error:-EPROTO;break;}
 }
 close(fds[0]);event("supplicant_exec",rc);
 if(rc){errno=-rc;return -1;}return p;
}
static int sup_ctrl_wait(struct m12_supplicant *s,const char *path,unsigned ms) {
 s->event("ctrl_wait_begin",0);uint64_t end=sup_ms()+ms;
 for(;;){
  int r=sup_check(s);if(r){int e=r>0?ECHILD:errno;s->event("ctrl_wait_failed",-e);errno=e;return -1;}
  struct stat st;
  if(!lstat(path,&st)&&S_ISSOCK(st.st_mode)){s->event("ctrl_wait_ready",0);return 0;}
  if(sup_ms()>=end){s->event("ctrl_wait_failed",-ETIMEDOUT);errno=ETIMEDOUT;return -1;}
  sup_pause();
 }
}
static int sup_diagnostics(struct m12_supplicant *s) {
 if(!s->log_owned)return 0;
 /* Called only after reap: no writer can race file classification/removal. */
 if(s->pid>0&&!s->reaped){errno=EBUSY;return -1;}
 int fd=open(s->log_path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return -1;
 struct stat st;if(fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_uid!=geteuid()||st.st_nlink!=1||(st.st_mode&07777)!=0600||st.st_size>16384){close(fd);errno=EPERM;return -1;}
 char b[16385];size_t p=0;
 for(;;){ssize_t n=read(fd,b+p,16384-p);if(n<0&&errno==EINTR)continue;if(n<0){int e=errno;close(fd);errno=e;return -1;}if(!n)break;p+=(size_t)n;if(p==16384)break;}
 if(close(fd))return -1;
 b[p]=0;
 static const struct {const char *needle,*category;} table[]={
  {"Failed to read or parse configuration", "supplicant_diag_config"},
  {"Failed to initialize driver interface", "supplicant_diag_driver"},
  {"Could not set interface", "supplicant_diag_ifup"},
  {"Failed to initialize control interface", "supplicant_diag_ctrl"},
  {"Failed to initialize wpa_supplicant", "supplicant_diag_init"},
  {"Cannot open RFKILL control device", "supplicant_diag_rfkill"},
  {"l2_packet_init", "supplicant_diag_l2"},
  {"socket(PF_PACKET)", "supplicant_diag_packet"},
  {"Detach monitor that cannot receive messages", "supplicant_diag_monitor_detached"},
  {"CTRL-EVENT-SCAN-FAILED", "supplicant_diag_scan_failed"},
  {"CTRL-EVENT-REGDOM-CHANGE", "supplicant_diag_regdom"}
 };
 for(unsigned i=0;i<sizeof(table)/sizeof(*table);i++)if(strstr(b,table[i].needle))s->event(table[i].category,1);
 s->event("supplicant_diag_bytes",(int)p);s->event("supplicant_diag_capped",p==16384);
 volatile char *wipe=b;for(size_t i=0;i<sizeof(b);i++)wipe[i]=0;
 if(unlink(s->log_path))return -1;
 s->log_owned=0;return 0;
}
#endif
