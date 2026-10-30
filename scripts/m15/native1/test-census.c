/* SPDX-License-Identifier: GPL-2.0-only */
/* Faults on one child's /proc/<pid>/stat, in the production census itself. */
#define _GNU_SOURCE
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
static char target[64];
static int open_error,read_error,target_fd=-1,read_empty;
static const char *read_text;
static int fake_open(const char *path,int flags){
 if(!strcmp(path,target)&&open_error){errno=open_error;return -1;}
 int fd=open(path,flags);
 if(!strcmp(path,target))target_fd=fd;
 return fd;
}
static ssize_t fake_read(int fd,void *b,size_t n){
 if(fd==target_fd){
  if(read_error){errno=read_error;return -1;}
  if(read_empty)return 0;
  if(read_text){size_t k=strlen(read_text);memcpy(b,read_text,k);return (ssize_t)k;}
 }
 return read(fd,b,n);
}
#define open fake_open
#define read fake_read
#include "supervise.c"
#undef open
#undef read
static void clear(void){open_error=read_error=read_empty=0;read_text=NULL;target_fd=-1;}
static void quiet(void *unused){(void)unused;_exit(0);}
static int run(void){long p[16];return child_pids(getpid(),p,16);}
int main(void){
 pid_t child=fork();assert(child>=0);
 if(!child){for(;;)pause();}
 snprintf(target,sizeof(target),"/proc/%ld/stat",(long)child);
 long pids[16];
 clear();assert(child_pids(getpid(),pids,16)==1&&pids[0]==(long)child);
 /* The only skip: the task exited after the listing. */
 static const int gone[]={ENOENT,ESRCH};
 for(unsigned i=0;i<2;i++){
  clear();open_error=gone[i];assert(run()==0);
  clear();read_error=gone[i];assert(run()==0);
 }
 static const int bad[]={EACCES,EIO,EMFILE,ENOMEM,EPERM};
 for(unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);i++){
  clear();open_error=bad[i];assert(run()==-1);
  clear();read_error=bad[i];assert(run()==-1);
 }
 clear();read_empty=1;assert(run()==-1);
 static const char *const broken[]={"no parenthesis at all","12 (x)","12 (x) S","12 (x) S notanumber"};
 for(unsigned i=0;i<sizeof(broken)/sizeof(broken[0]);i++){clear();read_text=broken[i];assert(run()==-1);}
 /* comm may carry spaces and parentheses. */
 char line[128];snprintf(line,sizeof(line),"%ld (a) b) c) S %ld 0 0",(long)child,(long)getpid());
 clear();read_text=line;assert(child_pids(getpid(),pids,16)==1&&pids[0]==(long)child);
 snprintf(line,sizeof(line),"%ld (a) %ld) S 1 0 0",(long)child,(long)getpid());
 clear();read_text=line;assert(run()==0);
 /* A census failure closes both of its users. */
 clear();read_error=EIO;assert(!exclusive());
 struct seen seen[16];unsigned count=0;
 unsigned char nonce[16]={1};
 struct m15 *s=m15_create(nonce,"{}",2,(struct m15_limits){4096,4096,4096,4096,1048576},0);assert(s);
 assert(children(s,seen,&count,child,0,0)==-1);
 struct m15_process_result r;
 assert(m15_supervise(s,quiet,NULL,1000,0,&r)==-1&&!strcmp(m15_error(s),"nonexclusive-process-scope"));
 clear();assert(!kill(child,SIGKILL));int status;assert(waitpid(child,&status,0)==child);
 assert(run()==0&&exclusive());
 puts("PASS census skips only ENOENT and ESRCH; other errors and malformed stat fail closed");
}
