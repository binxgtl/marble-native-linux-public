/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include "linux.h"
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define INTERRUPTS_CAP (512u*1024u)
#define ACTIVE_LIMIT 4096u
#define RTC_IRQ "pm8xxx_rtc_alarm"
#define RTC_NAME "rtc-pm8xxx"
#define RTC_NODE "rtc@6100"

static int full_path(const struct m16_linux *l,const char *rel,char *out,size_t cap) {
 int n=snprintf(out,cap,"%s%s",l->root,rel);
 return n<0||(size_t)n>=cap?-ENAMETOOLONG:0;
}
/* A short read of a whole file. O_NONBLOCK so a stray FIFO cannot stall PID1. */
static int read_text(const struct m16_linux *l,const char *rel,char *b,size_t cap) {
 char path[PATH_MAX];
 int rc=full_path(l,rel,path,sizeof(path));
 if(rc)return rc;
 int fd=open(path,O_RDONLY|O_CLOEXEC|O_NONBLOCK);
 if(fd<0)return -errno;
 size_t have=0;
 for(;;){
  if(have==cap-1){close(fd);return -EOVERFLOW;}
  ssize_t n=read(fd,b+have,cap-1-have);
  if(n<0&&errno==EINTR)continue;
  if(n<0){int error=errno;close(fd);return -error;}
  if(!n)break;
  have+=(size_t)n;
 }
 if(close(fd))return -errno;
 b[have]=0;
 while(have&&(b[have-1]=='\n'||b[have-1]==' '))b[--have]=0;
 return 0;
}
static int write_text(const struct m16_linux *l,const char *rel,const char *text) {
 char path[PATH_MAX];
 int rc=full_path(l,rel,path,sizeof(path));
 if(rc)return rc;
 int fd=open(path,O_WRONLY|O_TRUNC|O_CLOEXEC|O_NONBLOCK);
 if(fd<0)return -errno;
 size_t n=strlen(text);
 ssize_t k=write(fd,text,n);
 int error=errno;
 if(close(fd)&&k==(ssize_t)n)return -errno;
 if(k<0)return -error;
 return (size_t)k==n?0:-EIO;
}
static int parse_u64(const char *s,uint64_t *out) {
 if(!*s||!isdigit((unsigned char)*s))return -EINVAL;
 errno=0;
 char *end;
 unsigned long long v=strtoull(s,&end,10);
 if(errno||*end)return -EINVAL;
 *out=v;
 return 0;
}
static int read_u64(const struct m16_linux *l,const char *rel,uint64_t *out) {
 char b[64];
 int rc=read_text(l,rel,b,sizeof(b));
 return rc?rc:parse_u64(b,out);
}
int m16_has_token(const char *text,const char *token) {
 size_t n=strlen(token);
 for(const char *p=text;*p;){
  while(*p==' ')p++;
  const char *e=p;
  while(*e&&*e!=' ')e++;
  if((size_t)(e-p)==n&&!strncmp(p,token,n))return 1;
  p=e;
 }
 return 0;
}
int m16_parse_mem_sleep(const char *text,uint32_t *selected) {
 if(strstr(text,"[s2idle]"))*selected=M16_MEM_S2IDLE;
 else if(strstr(text,"[deep]"))*selected=M16_MEM_DEEP;
 else return -EINVAL;
 return 0;
}
/* "0-7" or "0-3,6". Anything outside the eight known CPUs is refused, not ignored. */
int m16_parse_cpu_mask(const char *text,uint64_t *mask) {
 uint64_t m=0;
 const char *p=text;
 if(!*p)return -EINVAL;
 for(;;){
  if(!isdigit((unsigned char)*p))return -EINVAL;
  char *e;
  unsigned long a=strtoul(p,&e,10),b=a;
  if(*e=='-'){
   if(!isdigit((unsigned char)e[1]))return -EINVAL;
   b=strtoul(e+1,&e,10);
  }
  if(a>b||b>=M16_CPUS)return -EINVAL;
  for(unsigned long i=a;i<=b;i++)m|=1ull<<i;
  if(!*e)break;
  if(*e!=',')return -EINVAL;
  p=e+1;
 }
 *mask=m;
 return 0;
}
/* One line ending in name, summed across its CPU columns. Zero or two matches fail. */
int m16_parse_interrupts(const char *text,const char *name,uint64_t *total) {
 size_t name_n=strlen(name);
 int found=0;
 uint64_t sum=0;
 for(const char *line=text;*line;){
  const char *end=strchr(line,'\n');
  size_t n=end?(size_t)(end-line):strlen(line);
  while(n&&line[n-1]==' ')n--;
  if(n>name_n&&!strncmp(line+n-name_n,name,name_n)&&line[n-name_n-1]==' '){
   if(found++)return -EEXIST;
   const char *p=memchr(line,':',n);
   if(!p)return -EINVAL;
   p++;
   int columns=0;
   for(;;){
    while(*p==' ')p++;
    if(!isdigit((unsigned char)*p))break;
    char *e;
    errno=0;
    unsigned long long v=strtoull(p,&e,10);
    if(errno)return -EINVAL;
    if(*e!=' ')break; /* a chip name or hwirq that merely starts with a digit */
    sum+=v;columns++;
    p=e;
   }
   if(!columns)return -EINVAL;
  }
  if(!end)break;
  line=end+1;
 }
 if(!found)return -ENOENT;
 *total=sum;
 return 0;
}
static int active_sources(const struct m16_linux *l,uint32_t *active) {
 char path[PATH_MAX];
 int rc=full_path(l,"/sys/class/wakeup",path,sizeof(path));
 if(rc)return rc;
 DIR *d=opendir(path);
 if(!d)return errno==ENOENT?(*active=0,0):-errno;
 uint32_t seen=0,count=0;
 for(struct dirent *e;(e=readdir(d));){
  if(strncmp(e->d_name,"wakeup",6))continue;
  if(++seen>ACTIVE_LIMIT){closedir(d);return -E2BIG;}
  char rel[128];
  uint64_t ms=0;
  if(snprintf(rel,sizeof(rel),"/sys/class/wakeup/%.64s/active_time_ms",e->d_name)>=(int)sizeof(rel)){closedir(d);return -ENAMETOOLONG;}
  rc=read_u64(l,rel,&ms);
  if(rc){closedir(d);return rc;}
  if(ms)count++;
 }
 closedir(d);
 *active=count;
 return 0;
}
static int count_entries(const struct m16_linux *l,const char *rel,uint32_t *out) {
 char path[PATH_MAX];
 int rc=full_path(l,rel,path,sizeof(path));
 if(rc)return rc;
 DIR *d=opendir(path);
 *out=0;
 if(!d)return errno==ENOENT?0:-errno;
 for(struct dirent *e;(e=readdir(d));)if(e->d_name[0]!='.')++*out;
 closedir(d);
 return 0;
}
static int remoteprocs_offline(const struct m16_linux *l,int *offline) {
 char path[PATH_MAX];
 int rc=full_path(l,"/sys/class/remoteproc",path,sizeof(path));
 if(rc)return rc;
 *offline=1;
 DIR *d=opendir(path);
 if(!d)return errno==ENOENT?0:-errno;
 for(struct dirent *e;(e=readdir(d));){
  if(strncmp(e->d_name,"remoteproc",10))continue;
  char rel[128],b[32];
  if(snprintf(rel,sizeof(rel),"/sys/class/remoteproc/%.64s/state",e->d_name)>=(int)sizeof(rel)){closedir(d);return -ENAMETOOLONG;}
  rc=read_text(l,rel,b,sizeof(b));
  if(rc){closedir(d);return rc;}
  if(strcmp(b,"offline"))*offline=0;
 }
 closedir(d);
 return 0;
}
static int linux_clock(void *arg,struct m16_clock *c) {
 (void)arg;
 for(unsigned i=0;i<3;i++){
  struct timespec a,m,b;
  if(clock_gettime(CLOCK_BOOTTIME,&a)||clock_gettime(CLOCK_MONOTONIC,&m)||clock_gettime(CLOCK_BOOTTIME,&b))return -errno;
  uint64_t first=(uint64_t)a.tv_sec*1000000000ull+(uint64_t)a.tv_nsec,second=(uint64_t)b.tv_sec*1000000000ull+(uint64_t)b.tv_nsec;
  /* A wide bracket means something ran or slept between the reads. Sample again. */
  if(second-first<=M16_JITTER_NS){
   c->boot_ns=first;c->mono_ns=(uint64_t)m.tv_sec*1000000000ull+(uint64_t)m.tv_nsec;
   return 0;
  }
 }
 return -EAGAIN;
}
static int linux_preflight(void *arg,struct m16_preflight *p) {
 struct m16_linux *l=arg;
 char b[256];
 int rc=read_text(l,"/sys/power/state",b,sizeof(b));
 if(rc)return rc;
 p->freeze_available=m16_has_token(b,"freeze");
 rc=read_text(l,"/sys/power/mem_sleep",b,sizeof(b));
 if(rc)return rc;
 rc=m16_parse_mem_sleep(b,&p->mem_sleep);
 if(rc)return rc;
 rc=read_text(l,"/sys/class/rtc/rtc0/name",b,sizeof(b));
 if(rc&&rc!=-ENOENT)return rc;
 p->rtc_identity=!rc&&!strncmp(b,RTC_NAME " ",sizeof(RTC_NAME))&&strstr(b,RTC_NODE);
 char path[PATH_MAX];
 rc=full_path(l,"/sys/class/rtc/rtc0/wakealarm",path,sizeof(path));
 if(rc)return rc;
 p->wakealarm_present=!access(path,R_OK|W_OK);
 rc=count_entries(l,"/sys/class/udc",&p->udc_count);
 if(rc)return rc;
 rc=remoteprocs_offline(l,&p->adsp_offline);
 if(rc)return rc;
 return active_sources(l,&p->wake_active);
}
static int linux_alarm_enabled(void *arg,int *enabled) {
 struct m16_linux *l=arg;
 char b[32];
 int rc=read_text(l,"/sys/class/rtc/rtc0/wakealarm",b,sizeof(b));
 if(rc)return rc;
 /* Empty when disabled. "0" is the disarm request itself, never a real alarm time. */
 *enabled=b[0]&&strcmp(b,"0");
 return 0;
}
static int linux_counters(void *arg,struct m16_counters *c,struct m16_idle *i) {
 struct m16_linux *l=arg;
 memset(c,0,sizeof(*c));
 memset(i,0,sizeof(*i));
 int rc=read_u64(l,"/sys/power/suspend_stats/success",&c->success);
 if(!rc)rc=read_u64(l,"/sys/power/suspend_stats/fail",&c->fail);
 if(rc)return rc;
 char b[64];
 rc=read_text(l,"/sys/power/suspend_stats/last_failed_errno",b,sizeof(b));
 if(rc)return rc;
 rc=parse_u64(b[0]=='-'?b+1:b,&c->failed_errno);
 if(rc)return rc;
 char *text=malloc(INTERRUPTS_CAP);
 if(!text)return -ENOMEM;
 rc=read_text(l,"/proc/interrupts",text,INTERRUPTS_CAP);
 if(!rc)rc=m16_parse_interrupts(text,RTC_IRQ,&c->rtc_irq);
 free(text);
 if(rc)return rc;
 int enabled=0;
 rc=linux_alarm_enabled(l,&enabled);
 if(rc)return rc;
 c->alarm_enabled=(uint64_t)enabled;
 uint32_t active=0;
 rc=active_sources(l,&active);
 if(rc)return rc;
 c->wake_active=active;
 rc=read_text(l,"/sys/devices/system/cpu/online",b,sizeof(b));
 if(!rc)rc=m16_parse_cpu_mask(b,&c->cpu_mask);
 if(rc)return rc;
 for(unsigned cpu=0;cpu<M16_CPUS;cpu++){
  if(!(c->cpu_mask>>cpu&1))continue;
  /* WFI has no s2idle directory; a state that exists contributes its count. */
  for(unsigned state=0;state<10;state++){
   char rel[128];
   uint64_t usage=0;
   snprintf(rel,sizeof(rel),"/sys/devices/system/cpu/cpu%u/cpuidle/state%u/s2idle/usage",cpu,state);
   rc=read_u64(l,rel,&usage);
   if(rc==-ENOENT)continue;
   if(rc)return rc;
   i->s2idle_usage[cpu]+=usage;
  }
 }
 return 0;
}
static int linux_alarm_arm(void *arg,uint32_t seconds) {
 char text[32];
 snprintf(text,sizeof(text),"+%u\n",seconds);
 return write_text(arg,"/sys/class/rtc/rtc0/wakealarm",text);
}
static int linux_alarm_clear(void *arg) { return write_text(arg,"/sys/class/rtc/rtc0/wakealarm","0\n"); }
/* Reading wakeup_count sleeps while any wakeup source is held, and S1 saw that
 * last for hours. A child takes the block; PID1 only waits on a bounded poll. */
static int linux_wake_count_read(void *arg,uint32_t *count) {
 struct m16_linux *l=arg;
 char path[PATH_MAX];
 int rc=full_path(l,"/sys/power/wakeup_count",path,sizeof(path));
 if(rc)return rc;
 int p[2];
 if(pipe2(p,O_CLOEXEC))return -errno;
 pid_t pid=fork();
 if(pid<0){int error=errno;close(p[0]);close(p[1]);return -error;}
 if(!pid){
  close(p[0]);
  int fd=open(path,O_RDONLY|O_CLOEXEC);
  char b[32];
  ssize_t n=fd<0?-1:read(fd,b,sizeof(b)-1);
  if(n<=0)_exit(1);
  _exit(write(p[1],b,(size_t)n)==n?0:2);
 }
 close(p[1]);
 struct pollfd w={p[0],POLLIN,0};
 int ready;
 do ready=poll(&w,1,(int)l->wake_count_timeout_ms); while(ready<0&&errno==EINTR);
 char b[32];
 ssize_t n=ready>0?read(p[0],b,sizeof(b)-1):-1;
 int status=0;
 if(ready<=0)kill(pid,SIGKILL);
 while(waitpid(pid,&status,0)<0&&errno==EINTR){}
 close(p[0]);
 if(ready==0)return -ETIMEDOUT;
 if(ready<0||n<=0||!WIFEXITED(status)||WEXITSTATUS(status))return -EIO;
 b[n]=0;
 while(n&&(b[n-1]=='\n'||b[n-1]==' '))b[--n]=0;
 uint64_t v=0;
 rc=parse_u64(b,&v);
 if(rc||v>UINT32_MAX)return -EINVAL;
 *count=(uint32_t)v;
 return 0;
}
static int linux_wake_count_write(void *arg,uint32_t count) {
 char text[32];
 snprintf(text,sizeof(text),"%u\n",count);
 return write_text(arg,"/sys/power/wakeup_count",text);
}
struct writer_result { int64_t rc,error; };
/* "freeze" selects PM_SUSPEND_TO_IDLE without touching mem_sleep, the same state
 * Android reaches by writing "mem" after its vendor script selects s2idle. */
static int linux_writer_start(void *arg) {
 struct m16_linux *l=arg;
 char path[PATH_MAX];
 int rc=full_path(l,l->state_write,path,sizeof(path));
 if(rc)return rc;
 int p[2];
 if(pipe2(p,O_CLOEXEC|O_NONBLOCK))return -errno;
 pid_t pid=fork();
 if(pid<0){int error=errno;close(p[0]);close(p[1]);return -error;}
 if(!pid){
  close(p[0]);
  struct writer_result r={0,0};
  int fd=open(path,O_WRONLY|O_CLOEXEC);
  ssize_t n=fd<0?-1:write(fd,"freeze",6);
  if(n!=6){r.rc=-1;r.error=errno;}
  _exit(write(p[1],&r,sizeof(r))==(ssize_t)sizeof(r)?0:3);
 }
 close(p[1]);
 l->writer_fd=p[0];l->writer_pid=(long)pid;
 return 0;
}
static int linux_writer_poll(void *arg,int64_t *rc,int64_t *error) {
 struct m16_linux *l=arg;
 struct writer_result r;
 ssize_t n=read(l->writer_fd,&r,sizeof(r));
 if(n<0&&(errno==EAGAIN||errno==EINTR))return 0;
 int status=0;
 while(waitpid((pid_t)l->writer_pid,&status,0)<0&&errno==EINTR){}
 close(l->writer_fd);
 l->writer_fd=-1;
 if(n!=(ssize_t)sizeof(r)||!WIFEXITED(status)||WEXITSTATUS(status))return -EPIPE;
 *rc=r.rc;*error=r.error;
 return 1;
}
void m16_linux_init(struct m16_linux *l,const char *root,unsigned wake_count_timeout_ms) {
 l->root=root;l->state_write="/sys/power/state";l->wake_count_timeout_ms=wake_count_timeout_ms;
 l->writer_fd=-1;l->writer_pid=0;
}
void m16_linux_ops(struct m16_ops *ops,struct m16_linux *l) {
 memset(ops,0,sizeof(*ops));
 ops->arg=l;
 ops->clock=linux_clock;ops->preflight=linux_preflight;ops->counters=linux_counters;
 ops->alarm_arm=linux_alarm_arm;ops->alarm_enabled=linux_alarm_enabled;ops->alarm_clear=linux_alarm_clear;
 ops->wake_count_read=linux_wake_count_read;ops->wake_count_write=linux_wake_count_write;
 ops->writer_start=linux_writer_start;ops->writer_poll=linux_writer_poll;
}
