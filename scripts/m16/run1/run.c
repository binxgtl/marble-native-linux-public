/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include "run.h"
#include <dirent.h>
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
#define WHITE 0x00ffffffu /* flash after each cycle: display came back */
#define CYAN 0x0000ffffu /* operator: swipe the screen */
#define MAGENTA 0x00ff00ffu /* operator: press Volume Up once it goes black */
#define STORAGE_BYTES (1024u*1024u)
#define EV_ABS_TYPE 3u
#define TOUCH_MIN_EVENTS 20
#define LOG_CAP (1024u*1024u)
#define LOG_CHUNK 256u /* unpaced, M15 Run4 lost whole runs of 1536 bytes */
#define RESEND_TRIES 4000u

static struct m16_record records[M16_RUN_CYCLES][M16_RUN_RECORDS];
static struct m16_journal journals[M16_RUN_CYCLES];
static struct m16_machine machines[M16_RUN_CYCLES];
static unsigned char log_bytes[LOG_CAP];

const struct m16_machine *m16_run_machine(unsigned cycle) { return cycle<M16_RUN_CYCLES?&machines[cycle]:NULL; }
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
/* stderr is the boot log: a single attempt needs every line a child prints. */
static pid_t spawn_logged(char *const argv[]) {
 int null=open("/dev/null",O_RDONLY|O_CLOEXEC);
 if(null<0)return -1;
 pid_t p=spawn(argv,null,2);
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
 return spawn_logged(a);
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
/* Boot leaves transient wakeup sources held, and the machine reads them once. The panel
 * disable also reaches touch, whose SPI bus then needs its 250 ms autosuspend: spi_geni
 * refuses suspend until that lapses, which is what stopped Run2. Android never sees this,
 * because it suspends long after the screen goes off. So hold for quiet_ms in any case. */
static void settle(const struct m16_run *r) {
 unsigned long long begin=now_ms(),quiet=begin+r->quiet_ms,end=begin+r->settle_ms;
 for(;;){
  struct m16_preflight p;
  memset(&p,0,sizeof(p));
  int rc=r->base.preflight(r->base.arg,&p);
  unsigned long long now=now_ms();
  if(now>=end||(now>=quiet&&(rc||!p.wake_active))){
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
/* Names, not a count: Run1 could only show that one UDC was there. */
static void log_dir(const struct m16_run *r,const char *rel) {
 char path[PATH_MAX];
 if(file_path(r,rel,path,sizeof(path)))return;
 DIR *d=opendir(path);
 if(!d){diag(r,"dir %s errno=%d",rel,errno);return;}
 for(struct dirent *e;(e=readdir(d));)if(e->d_name[0]!='.')diag(r,"dir %s: %.64s",rel,e->d_name);
 closedir(d);
}
static void log_value(const struct m16_run *r,const char *rel) {
 char path[PATH_MAX],b[64];
 if(file_path(r,rel,path,sizeof(path)))return;
 int fd=open(path,O_RDONLY|O_CLOEXEC|O_NONBLOCK);
 ssize_t n=fd<0?-1:read(fd,b,sizeof(b)-1);
 int error=errno;
 if(fd>=0)close(fd);
 if(n<=0){diag(r,"value %s errno=%d",rel,error);return;}
 while(n&&b[n-1]=='\n')n--;
 b[n]=0;
 diag(r,"value %s: %s",rel,b);
}
/* A stray alarm or a failure must never read as a pass, so PASS needs every step. */
static int cycle_passed(const struct m16_machine *m) { return m->verdict==M16_V_PASS&&!m->failure; }
static enum m16_mark_code summary(const struct m16_run *r) {
 for(unsigned i=0;i<r->cycles&&i<r->rtc_cycles;i++){
  const struct m16_machine *m=&machines[i];
  if(!cycle_passed(m))return m16_mark_code(m->verdict,m->failure!=M16_F_NONE,m->cycle.clock_post.boot_ns!=0);
 }
 return r->all_ok?M16_M_PASS:M16_M_FAILED_AFTER_RESUME;
}
/* After the last seal and before ADSP, so it survives a failed channel and any later reset. */
static void write_mark(struct m16_run *r) {
 uint64_t now=0,back=0;
 r->mark_code=summary(r);
 int rc=read_u64(r,"/sys/class/rtc/rtc0/since_epoch",&now);
 if(!rc)rc=m16_mark_encode(now,r->tag,r->mark_code,&r->mark_value);
 if(!rc)rc=write_alarm(r,r->mark_value);
 if(!rc)rc=read_u64(r,"/sys/class/rtc/rtc0/wakealarm",&back);
 if(!rc&&back!=r->mark_value)rc=-EBADMSG;
 r->mark_rc=rc;
 diag(r,"mark rc=%d value=%llu code=%d now=%llu",rc,(unsigned long long)r->mark_value,(int)r->mark_code,(unsigned long long)now);
}
/* In a child, because a resume that broke UFS leaves the reader in D state. Direct I/O, so
 * the bytes come from the device after this resume and not from the page cache. */
static void storage_child(const struct m16_run *r,int out) {
 void *b=NULL;
 int fd=open(r->block,O_RDONLY|O_CLOEXEC|r->block_flags);
 if(fd<0||posix_memalign(&b,4096,STORAGE_BYTES))_exit(1);
 Sha256 s;
 char hash[65]={0};
 sha_init(&s);
 size_t total=0;
 while(total<STORAGE_BYTES){
  ssize_t n=read(fd,b,STORAGE_BYTES-total);
  if(n<0)_exit(2);
  if(!n)break;
  sha_update(&s,(const char *)b,(ulong)n);
  total+=(size_t)n;
 }
 if(!total)_exit(3);
 sha_hex(s,hash);
 _exit(write(out,hash,64)==64?0:4);
}
static int storage_hash(const struct m16_run *r,char hash[65]) {
 int p[2];
 if(pipe2(p,O_CLOEXEC))return -errno;
 pid_t pid=fork();
 if(pid<0){int error=errno;close(p[0]);close(p[1]);return -error;}
 if(!pid){close(p[0]);storage_child(r,p[1]);}
 close(p[1]);
 int status=-1,rc=wait_child(pid,r->storage_ms,&status);
 ssize_t n=!rc&&!status?read(p[0],hash,64):-1;
 close(p[0]);
 if(rc)return rc;
 if(n!=64)return -EIO;
 hash[64]=0;
 return 0;
}
static int check_storage(struct m16_run *r) {
 char hash[65];
 int rc=storage_hash(r,hash);
 if(!rc&&strcmp(hash,r->baseline))rc=-EBADMSG;
 diag(r,"storage rc=%d",rc);
 return rc;
}
static int check_display(const struct m16_run *r) {
 int status=-1;
 pid_t p=paint(r,WHITE,r->check_ms);
 int rc=p<0?-1:wait_child(p,r->display_ms,&status);
 diag(r,"display rc=%d status=%d",rc,status);
 return rc||status;
}
struct touch_event { unsigned long long sec,usec; unsigned short type,code; int value; };
/* Input needs a finger. Existence of the node, or IRQ activity alone, proves nothing. */
static void touch_window(struct m16_run *r) {
 int fd=open(r->touch,O_RDONLY|O_NONBLOCK|O_CLOEXEC),status=-1;
 pid_t p=paint(r,CYAN,r->touch_ms);
 unsigned long long end=now_ms()+r->touch_ms;
 r->touch_events=0;
 while(fd>=0&&now_ms()<end){
  struct touch_event e[32];
  ssize_t n=read(fd,e,sizeof(e));
  for(ssize_t i=0;i<n/(ssize_t)sizeof(e[0]);i++)if(e[i].type==EV_ABS_TYPE)r->touch_events++;
  (void)poll(NULL,0,20);
 }
 if(fd>=0)close(fd);
 int rc=p<0?-1:wait_child(p,r->display_ms,&status);
 diag(r,"touch open=%d abs_events=%ld display_rc=%d status=%d",fd>=0,r->touch_events,rc,status);
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
 if(pipe2(out,O_CLOEXEC)){close(in[0]);close(in[1]);return -1;}
 /* Only this end: the connector keeps the blocking stdout it had in M15. */
 if(fcntl(out[0],F_SETFL,O_NONBLOCK)){close(in[0]);close(in[1]);close(out[0]);close(out[1]);return -1;}
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
/* One link serves every journal, and it is up before any machine reaches this state. */
static int run_channel_start(void *a) { (void)a; return 0; }
static int run_channel_poll(void *a) { (void)a; return 1; }
static ssize_t run_sink(void *a,const void *p,size_t n) { struct m16_run *r=a; return write(r->tty_fd,p,n); }
/* The whole wire again, on the host's request. Offsets restart, the bytes are identical. */
static void resend(struct m16_run *r) {
 struct m16_journal *j=&journals[r->current];
 m16_journal_rewind(j);
 for(unsigned i=0;i<RESEND_TRIES;i++){
  int sent=m16_journal_export(j,run_sink,r);
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
static const struct m16_ops run_ops={.clock=run_clock,.preflight=run_preflight,.counters=run_counters,
 .alarm_arm=run_arm,.alarm_enabled=run_enabled,.alarm_clear=run_clear,.wake_count_read=run_count_read,
 .wake_count_write=run_count_write,.writer_start=run_writer_start,.writer_poll=run_writer_poll,
 .channel_start=run_channel_start,.channel_poll=run_channel_poll,.sink=run_sink,.ack_poll=run_ack_poll};
/* One machine from its first step to its seal. Below zero means hold. */
static int run_cycle(struct m16_run *r,const struct m16_config *config) {
 settle(r);
 log_value(r,"/sys/bus/platform/devices/990000.spi/power/runtime_status");
 unsigned i=r->cycles;
 unsigned char nonce[16];
 memcpy(nonce,r->nonce,sizeof(nonce));
 nonce[15]^=(unsigned char)(i+1); /* a record cannot move between cycles either */
 struct m16_ops ops=run_ops;
 ops.arg=r;
 if(i>=M16_RUN_CYCLES||m16_journal_init(&journals[i],records[i],M16_RUN_RECORDS,nonce)||m16_machine_init(&machines[i],&ops,config,&journals[i])){
  diag(r,"machine init failed");
  return -1;
 }
 r->cycles=i+1;
 struct m16_machine *m=&machines[i];
 for(;;){
  enum m16_outcome outcome=m16_step(m);
  if(outcome==M16_O_HOLD||m->state==M16_S_HOLD)break;
  if(m->state>=M16_S_CHANNEL)break;
  (void)poll(NULL,0,(int)r->step_ms);
 }
 diag(r,"cycle %u state=%d failure=%s verdict=%s slept_ms=%llu",i,(int)m->state,m16_fail_name(m->failure),
      m16_verdict_name(m->verdict),(unsigned long long)(m->slept_ns/1000000));
 return m->state==M16_S_HOLD?-1:0;
}
/* A writer still in the kernel means the transition is unresolved: touch nothing. */
static enum m16_run_end hold(const struct m16_run *r) {
 if(!r->cycles||!machines[r->cycles-1].writer_active)(void)paint(r,RED,r->final_ms);
 return M16_END_HOLD;
}
/* Every cycle sealed, or the loop stopped at the first one that did not pass. */
static int run_cycles(struct m16_run *r) {
 int good=r->storage_ready;
 for(unsigned i=0;i<r->rtc_cycles;i++){
  if(run_cycle(r,&r->config))return -1;
  if(!cycle_passed(&machines[i])){good=0;r->all_ok=0;return 0;}
  if((r->storage_ready&&check_storage(r))||check_display(r)){r->all_ok=0;return 0;}
 }
 r->key_ok=1;
 if(r->operator_steps){
  touch_window(r);
  if(r->touch_events<TOUCH_MIN_EVENTS)good=0;
  int status=-1;
  pid_t p=paint(r,MAGENTA,r->prompt_ms);
  if(p<0||wait_child(p,r->display_ms,&status)||status)good=0;
  if(run_cycle(r,&r->key_config))return -1;
  const struct m16_machine *m=&machines[r->cycles-1];
  /* The RTC stays armed behind the key, so a missed press still ends the cycle. */
  r->key_ok=m->verdict==M16_V_EARLY_WAKE&&!m->failure&&m->cycle.post.rtc_irq==m->cycle.pre.rtc_irq;
  if((r->storage_ready&&check_storage(r))||check_display(r))good=0;
 }
 r->all_ok=good&&r->key_ok;
 return 0;
}
static int bring_up_link(struct m16_run *r) {
 char *argv[]={(char *)r->adsp,NULL};
 pid_t p=spawn_logged(argv);
 if(p<0)return -1;
 r->adsp_pid=(long)p;r->link=M16_LINK_ADSP;
 unsigned long long end=now_ms()+r->link_ms;
 while(now_ms()<end){
  int rc=link_step(r);
  if(rc)return rc<0?-1:0;
  (void)poll(NULL,0,(int)r->step_ms);
 }
 diag(r,"link deadline");
 return -1;
}
/* Each journal keeps its own chain and its own ACK, in cycle order. */
static int export_cycles(struct m16_run *r) {
 char head[32];
 int n=snprintf(head,sizeof(head),M16_DEVICE_CYCLES " %u\n",r->cycles);
 if(send_paced(r,(const unsigned char *)head,(size_t)n,now_ms()+r->log_ms))return -1;
 for(unsigned i=0;i<r->cycles;i++){
  struct m16_machine *m=&machines[i];
  r->current=i;
  for(;;){
   enum m16_outcome outcome=m16_step(m);
   if(outcome==M16_O_HOLD)return -1;
   if(outcome!=M16_O_RUNNING)break;
   (void)poll(NULL,0,(int)(m->state==M16_S_EXPORT?r->pace_ms:r->step_ms));
  }
 }
 return 0;
}
enum m16_run_end m16_run_main(struct m16_run *r) {
 r->tty_fd=r->connector_in=r->connector_out=-1;r->mark_rc=-ENODATA;r->display_failed=0;r->cycles=0;
 diag(r,"start tag=%02x",r->tag);
 int status=-1;
 char *argv[]={(char *)r->bootstrap,NULL};
 pid_t p=spawn_logged(argv);
 int rc=p<0?-1:wait_child(p,r->bootstrap_ms,&status);
 diag(r,"bootstrap rc=%d status=%d",rc,status);
 if(rc||status)return M16_END_BOOTSTRAP;
 show_blue(r);
 /* Touch registers after bootstrap, so its node can only be made here. */
 char *nodes[]={(char *)r->nodes,NULL};
 status=-1;
 p=spawn_logged(nodes);
 rc=p<0?-1:wait_child(p,r->display_ms,&status);
 diag(r,"nodes rc=%d status=%d",rc,status);
 log_dir(r,"/sys/class/udc");
 log_dir(r,"/sys/devices/system/cpu/cpu0/cpuidle");
 r->storage_ready=!storage_hash(r,r->baseline);
 diag(r,"storage baseline ready=%d",r->storage_ready);
 if(run_cycles(r))return hold(r);
 diag(r,"summary cycles=%u all_ok=%d key_ok=%d touch=%ld storage=%d",r->cycles,r->all_ok,r->key_ok,r->touch_events,r->storage_ready);
 write_mark(r);
 if(bring_up_link(r)||export_cycles(r))return hold(r);
 send_log(r);
 (void)paint(r,r->all_ok?GREEN:YELLOW,r->final_ms);
 return r->all_ok?M16_END_PASS:M16_END_NOT_PASS;
}
