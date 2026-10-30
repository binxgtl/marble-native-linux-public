/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include "run.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
typedef unsigned long ulong;
#include "../../m11/anchor-native/p4/sha256.h"

#define BLUE 0x000000ffu
#define GREEN 0x0000ff00u
#define YELLOW 0x00ffff00u
#define RED 0x00ff0000u
#define LOG_CAP (1024u*1024u)
#define LOG_CHUNK 256u /* unpaced, M15 Run4 lost whole runs of 1536 bytes */
#define RESEND_TRIES 4000u

static struct m16_record records[M16_RUN_RECORDS];
static struct m16_journal journal;
static struct m16_machine machine;
static unsigned char log_bytes[LOG_CAP];

const struct m16_machine *m16_run_machine(void) { return &machine; }
static unsigned long long now_ms(void) {
 struct timespec t;
 if(clock_gettime(CLOCK_MONOTONIC,&t))return 0;
 return (unsigned long long)t.tv_sec*1000+(unsigned long long)t.tv_nsec/1000000;
}
/* One compact record per line; the exported kernel log carries these to the host. */
__attribute__((format(printf,2,3)))
static void diag(const struct m16_run *r,const char *format,...) {
 char b[200];
 int at=snprintf(b,sizeof(b),"<6>M16: ");
 va_list a;
 va_start(a,format);
 int n=vsnprintf(b+at,sizeof(b)-(size_t)at-1,format,a);
 va_end(a);
 if(n<0)return;
 size_t size=(size_t)at+((size_t)n<sizeof(b)-(size_t)at-1?(size_t)n:sizeof(b)-(size_t)at-2);
 b[size++]='\n';
 int fd=open(r->kmsg,O_WRONLY|O_APPEND|O_CLOEXEC);
 if(fd<0)return;
 ssize_t put=write(fd,b,size);
 (void)put;
 close(fd);
}
static pid_t spawn(char *const argv[],int in,int out) {
 pid_t p=fork();
 if(p)return p;
 if(dup2(in,0)<0||dup2(out,1)<0)_exit(126);
 execv(argv[0],argv);
 _exit(127);
}
static pid_t spawn_quiet(char *const argv[]) {
 int null=open("/dev/null",O_RDWR|O_CLOEXEC);
 if(null<0)return -1;
 pid_t p=spawn(argv,null,null);
 close(null);
 return p;
}
static int wait_child(pid_t pid,unsigned ms,int *status) {
 unsigned long long end=now_ms()+ms;
 for(;;){
  pid_t p=waitpid(pid,status,WNOHANG);
  if(p==pid)return 0;
  if(p<0&&errno!=EINTR)return -1;
  if(now_ms()>=end)return -ETIMEDOUT;
  (void)poll(NULL,0,10);
 }
}
static pid_t paint(const struct m16_run *r,uint32_t color,unsigned hold_ms) {
 char c[16],h[16];
 snprintf(c,sizeof(c),"%08x",color);snprintf(h,sizeof(h),"%u",hold_ms);
 char *a[]={(char *)r->display,c,h,NULL};
 return spawn_quiet(a);
}
/* Before the cycle: a failure here is reported through the journal, never by suspending
 * with the panel in an unknown state. A child stuck in the driver is left alone. */
static void show_blue(struct m16_run *r) {
 int status=-1;
 pid_t p=paint(r,BLUE,r->blue_ms);
 int rc=p<0?-1:wait_child(p,r->display_ms,&status);
 r->display_failed=rc||status;
 diag(r,"blue rc=%d status=%d",rc,status);
}
/* Boot leaves transient wakeup sources held. The machine reads them once, so wait first. */
static void settle(const struct m16_run *r) {
 unsigned long long begin=now_ms(),end=begin+r->settle_ms;
 for(;;){
  struct m16_preflight p;
  memset(&p,0,sizeof(p));
  int rc=r->base.preflight(r->base.arg,&p);
  if(rc||!p.wake_active||now_ms()>=end){
   diag(r,"settle rc=%d active=%u ms=%llu",rc,p.wake_active,now_ms()-begin);
   return;
  }
  (void)poll(NULL,0,100);
 }
}
static int file_path(const struct m16_run *r,const char *rel,char *out,size_t cap) {
 int n=snprintf(out,cap,"%s%s",r->root,rel);
 return n<0||(size_t)n>=cap?-ENAMETOOLONG:0;
}
static int read_u64(const struct m16_run *r,const char *rel,uint64_t *value) {
 char path[PATH_MAX],b[32];
 int rc=file_path(r,rel,path,sizeof(path));
 if(rc)return rc;
 int fd=open(path,O_RDONLY|O_CLOEXEC|O_NONBLOCK);
 if(fd<0)return -errno;
 ssize_t n=read(fd,b,sizeof(b)-1);
 int error=errno;
 close(fd);
 if(n<=0)return n?-error:-ENODATA;
 b[n]=0;
 char *end;
 errno=0;
 *value=strtoull(b,&end,10);
 return errno||end==b||(*end&&*end!='\n')?-EINVAL:0;
}
static int write_alarm(const struct m16_run *r,uint64_t value) {
 char path[PATH_MAX],b[32];
 int rc=file_path(r,"/sys/class/rtc/rtc0/wakealarm",path,sizeof(path));
 if(rc)return rc;
 int fd=open(path,O_WRONLY|O_TRUNC|O_CLOEXEC|O_NONBLOCK);
 if(fd<0)return -errno;
 int n=snprintf(b,sizeof(b),"%llu\n",(unsigned long long)value);
 ssize_t put=write(fd,b,(size_t)n);
 int error=errno;
 close(fd);
 return put==n?0:-error;
}
/* After the seal and before ADSP, so it survives a failed channel and any later reset. */
static void write_mark(struct m16_run *r) {
 const struct m16_machine *m=&machine;
 uint64_t now=0,back=0;
 r->mark_code=m16_mark_code(m->verdict,m->failure!=M16_F_NONE,m->cycle.clock_post.boot_ns!=0);
 int rc=read_u64(r,"/sys/class/rtc/rtc0/since_epoch",&now);
 if(!rc)rc=m16_mark_encode(now,r->tag,r->mark_code,&r->mark_value);
 if(!rc)rc=write_alarm(r,r->mark_value);
 if(!rc)rc=read_u64(r,"/sys/class/rtc/rtc0/wakealarm",&back);
 if(!rc&&back!=r->mark_value)rc=-EBADMSG;
 r->mark_rc=rc;
 diag(r,"mark rc=%d value=%llu code=%d now=%llu",rc,(unsigned long long)r->mark_value,(int)r->mark_code,(unsigned long long)now);
}
/* Nonblocking, one byte a call, so a caller can never be held by a silent peer. */
static int read_line(struct m16_run *r,int fd) {
 for(;;){
  char c;
  ssize_t n=read(fd,&c,1);
  if(n<0&&(errno==EAGAIN||errno==EINTR))return 0;
  if(n!=1)return -1;
  if(c=='\n'){r->line[r->line_at]=0;r->line_at=0;return 1;}
  if(c<32||c>126||r->line_at>=sizeof(r->line)-1){r->line_at=0;continue;}
  r->line[r->line_at++]=c;
 }
}
static int open_tty(const struct m16_run *r) {
 int fd=open(r->tty,O_RDWR|O_NOCTTY|O_NONBLOCK|O_CLOEXEC);
 if(fd<0)return -1;
 struct termios t;
 if(tcgetattr(fd,&t)){close(fd);return -1;}
 cfmakeraw(&t);
 if(tcsetattr(fd,TCSANOW,&t)){close(fd);return -1;}
 return fd;
}
static int start_connector(struct m16_run *r) {
 int in[2],out[2];
 if(pipe2(in,O_CLOEXEC))return -1;
 if(pipe2(out,O_CLOEXEC|O_NONBLOCK)){close(in[0]);close(in[1]);return -1;}
 char *a[]={(char *)r->connector,NULL};
 pid_t p=spawn(a,in[0],out[1]);
 close(in[0]);close(out[1]);
 if(p<0){close(in[1]);close(out[0]);return -1;}
 r->connector_in=in[1]; /* stays open: EOF on its stdin is a connector failure */
 r->connector_out=out[0];
 return 0;
}
static int link_step(struct m16_run *r) {
 switch(r->link){
 case M16_LINK_ADSP:{
  int status=0;
  pid_t p=waitpid((pid_t)r->adsp_pid,&status,WNOHANG);
  if(!p||(p<0&&errno==EINTR))return 0;
  diag(r,"adsp pid=%ld status=%d",(long)p,status);
  if(p<0||status||start_connector(r))return -1;
  r->link=M16_LINK_CONNECTOR;
  return 0;
 }
 case M16_LINK_CONNECTOR:{
  int got=read_line(r,r->connector_out);
  if(got<=0)return got;
  diag(r,"connector %.64s",r->line);
  if(strcmp(r->line,"CONNECTOR_READY"))return -1;
  r->tty_fd=open_tty(r);
  if(r->tty_fd<0)return -1;
  r->link=M16_LINK_HOST;
  return 0;
 }
 case M16_LINK_HOST:{
  int got=read_line(r,r->tty_fd);
  if(got<0)return -1;
  if(got&&!strcmp(r->line,M16_HOST_HELLO)){r->link=M16_LINK_READY;return 1;}
  return 0;
 }
 default:
  return 1;
 }
}
static int run_clock(void *a,struct m16_clock *c) { struct m16_run *r=a; return r->base.clock(r->base.arg,c); }
static int run_preflight(void *a,struct m16_preflight *p) {
 struct m16_run *r=a;
 int rc=r->base.preflight(r->base.arg,p);
 /* Recorded as PREFLIGHT_READ -ENODEV: no suspend, and the export says why. */
 return rc?rc:r->display_failed?-ENODEV:0;
}
static int run_counters(void *a,struct m16_counters *c,struct m16_idle *i) { struct m16_run *r=a; return r->base.counters(r->base.arg,c,i); }
static int run_arm(void *a,uint32_t s) { struct m16_run *r=a; return r->base.alarm_arm(r->base.arg,s); }
static int run_enabled(void *a,int *e) { struct m16_run *r=a; return r->base.alarm_enabled(r->base.arg,e); }
static int run_clear(void *a) { struct m16_run *r=a; return r->base.alarm_clear(r->base.arg); }
static int run_count_read(void *a,uint32_t *c) { struct m16_run *r=a; return r->base.wake_count_read(r->base.arg,c); }
static int run_count_write(void *a,uint32_t c) { struct m16_run *r=a; return r->base.wake_count_write(r->base.arg,c); }
static int run_writer_start(void *a) { struct m16_run *r=a; return r->base.writer_start(r->base.arg); }
static int run_writer_poll(void *a,int64_t *rc,int64_t *e) { struct m16_run *r=a; return r->base.writer_poll(r->base.arg,rc,e); }
static int run_channel_start(void *a) {
 struct m16_run *r=a;
 write_mark(r);
 char *argv[]={(char *)r->adsp,NULL};
 pid_t p=spawn_quiet(argv);
 if(p<0)return -1;
 r->adsp_pid=(long)p;r->link=M16_LINK_ADSP;
 return 0;
}
static int run_channel_poll(void *a) { return link_step(a); }
static ssize_t run_sink(void *a,const void *p,size_t n) { struct m16_run *r=a; return write(r->tty_fd,p,n); }
/* The whole wire again, on the host's request. Offsets restart, the bytes are identical. */
static void resend(struct m16_run *r) {
 m16_journal_rewind(&journal);
 for(unsigned i=0;i<RESEND_TRIES;i++){
  int sent=m16_journal_export(&journal,run_sink,r);
  if(sent)return;
  (void)poll(NULL,0,(int)r->pace_ms);
 }
}
static int run_ack_poll(void *a,char hex[M16_ACK_HEX]) {
 struct m16_run *r=a;
 int got=read_line(r,r->tty_fd);
 if(got<=0)return 0; /* a lost link only runs out the deadline, and the journal stays */
 size_t prefix=sizeof(M16_HOST_ACK)-1;
 if(!strncmp(r->line,M16_HOST_ACK,prefix)&&strlen(r->line)==prefix+M16_ACK_HEX){
  memcpy(hex,r->line+prefix,M16_ACK_HEX);
  return 1;
 }
 if(!strcmp(r->line,M16_HOST_RESEND)){diag(r,"resend");resend(r);}
 return 0;
}
static size_t add_text(size_t at,const char *text) {
 size_t n=strlen(text);
 if(n>LOG_CAP-at)return at;
 memcpy(log_bytes+at,text,n);
 return at+n;
}
static size_t add_file(size_t at,const char *path) {
 int fd=open(path,O_RDONLY|O_CLOEXEC|O_NONBLOCK);
 if(fd<0)return at;
 while(at<LOG_CAP){
  /* /dev/kmsg hands out one record a read and wants room for a whole one. */
  size_t room=LOG_CAP-at;
  if(room<8192)break;
  ssize_t n=read(fd,log_bytes+at,room>8192?8192:room);
  if(n<0&&(errno==EINTR||errno==EPIPE))continue;
  if(n<=0)break;
  at+=(size_t)n;
 }
 close(fd);
 return at;
}
static int send_paced(const struct m16_run *r,const unsigned char *p,size_t n,unsigned long long end) {
 for(size_t at=0;at<n;){
  if(now_ms()>=end)return -ETIMEDOUT;
  ssize_t put=write(r->tty_fd,p+at,n-at<LOG_CHUNK?n-at:LOG_CHUNK);
  if(put<0&&errno!=EAGAIN&&errno!=EINTR)return -errno;
  if(put>0)at+=(size_t)put;
  (void)poll(NULL,0,(int)r->pace_ms);
 }
 return 0;
}
/* Diagnostics only, after the ACK: a host that misses this has already got the evidence. */
static void send_log(const struct m16_run *r) {
 size_t size=add_text(0,"M16 bootstrap.log\n");
 size=add_file(size,r->boot_log);
 size=add_text(size,"M16 kernel log\n");
 size=add_file(size,r->kmsg);
 Sha256 s;
 char hash[65]={0},head[200];
 sha_init(&s);sha_update(&s,(const char *)log_bytes,(ulong)size);sha_hex(s,hash);
 int n=snprintf(head,sizeof(head),M16_DEVICE_LOG " %zu %s %d %llu %d\n",size,hash,r->mark_rc,(unsigned long long)r->mark_value,(int)r->mark_code);
 unsigned long long end=now_ms()+r->log_ms;
 int rc=send_paced(r,(const unsigned char *)head,(size_t)n,end);
 if(!rc)rc=send_paced(r,log_bytes,size,end);
 diag(r,"log rc=%d bytes=%zu",rc,size);
}
enum m16_run_end m16_run_main(struct m16_run *r) {
 r->tty_fd=r->connector_in=r->connector_out=-1;r->mark_rc=-ENODATA;r->display_failed=0;
 diag(r,"start tag=%02x",r->tag);
 int status=-1;
 char *argv[]={(char *)r->bootstrap,NULL};
 pid_t p=spawn_quiet(argv);
 int rc=p<0?-1:wait_child(p,r->bootstrap_ms,&status);
 diag(r,"bootstrap rc=%d status=%d",rc,status);
 if(rc||status)return M16_END_BOOTSTRAP;
 show_blue(r);
 settle(r);
 const struct m16_ops ops={.arg=r,.clock=run_clock,.preflight=run_preflight,.counters=run_counters,
  .alarm_arm=run_arm,.alarm_enabled=run_enabled,.alarm_clear=run_clear,.wake_count_read=run_count_read,
  .wake_count_write=run_count_write,.writer_start=run_writer_start,.writer_poll=run_writer_poll,
  .channel_start=run_channel_start,.channel_poll=run_channel_poll,.sink=run_sink,.ack_poll=run_ack_poll};
 if(m16_journal_init(&journal,records,M16_RUN_RECORDS,r->nonce)||m16_machine_init(&machine,&ops,&r->config,&journal)){
  diag(r,"machine init failed");
  return M16_END_HOLD;
 }
 enum m16_outcome outcome;
 for(;;){
  outcome=m16_step(&machine);
  if(outcome!=M16_O_RUNNING)break;
  (void)poll(NULL,0,(int)(machine.state==M16_S_EXPORT?r->pace_ms:r->step_ms));
 }
 diag(r,"machine outcome=%d state=%d failure=%s verdict=%s slept_ms=%llu",(int)outcome,(int)machine.state,
      m16_fail_name(machine.failure),m16_verdict_name(machine.verdict),(unsigned long long)(machine.slept_ns/1000000));
 if(outcome==M16_O_HOLD){
  /* A writer still in the kernel means the transition is unresolved: touch nothing. */
  if(!machine.writer_active)(void)paint(r,RED,r->final_ms);
  return M16_END_HOLD;
 }
 send_log(r);
 (void)paint(r,outcome==M16_O_VERIFIED_PASS?GREEN:YELLOW,r->final_ms);
 return outcome==M16_O_VERIFIED_PASS?M16_END_PASS:M16_END_NOT_PASS;
}
