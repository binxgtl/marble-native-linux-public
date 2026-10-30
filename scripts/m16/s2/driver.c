/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include "linux.h"
#include "mark.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* Test harness only: real linux.c against a synthetic tree, with time and the
 * evidence channel replaced. It is never staged into an image. */
struct harness { struct m16_linux adapter; struct m16_ops real; const char *root; uint64_t scale; int wire; };

static int test_path(const struct harness *h,const char *name,char *out,size_t cap) {
 int n=snprintf(out,cap,"%s/test/%s",h->root,name);
 return n<0||(size_t)n>=cap?-1:0;
}
static void touch(const struct harness *h,const char *name) {
 char path[4096];
 if(test_path(h,name,path,sizeof(path)))return;
 int fd=open(path,O_WRONLY|O_CREAT|O_CLOEXEC,0644);
 if(fd>=0)close(fd);
}
static uint64_t gap_ns(const struct harness *h) {
 char path[4096],b[32];
 if(test_path(h,"gap_ns",path,sizeof(path)))return 0;
 int fd=open(path,O_RDONLY|O_CLOEXEC);
 if(fd<0)return 0;
 ssize_t n=read(fd,b,sizeof(b)-1);
 close(fd);
 if(n<=0)return 0;
 b[n]=0;
 return strtoull(b,NULL,10);
}
/* Scaled so a thirty-second alarm costs a CI run milliseconds. */
static int scaled_clock(void *arg,struct m16_clock *c) {
 struct harness *h=arg;
 struct timespec t;
 if(clock_gettime(CLOCK_MONOTONIC,&t))return -errno;
 uint64_t now=((uint64_t)t.tv_sec*1000000000ull+(uint64_t)t.tv_nsec)*h->scale;
 c->mono_ns=now;c->boot_ns=now+gap_ns(h);
 return 0;
}
static int wrap_preflight(void *a,struct m16_preflight *p) { struct harness *h=a; return h->real.preflight(&h->adapter,p); }
static int wrap_counters(void *a,struct m16_counters *c,struct m16_idle *i) { struct harness *h=a; return h->real.counters(&h->adapter,c,i); }
static int wrap_arm(void *a,uint32_t s) { struct harness *h=a; return h->real.alarm_arm(&h->adapter,s); }
static int wrap_enabled(void *a,int *e) { struct harness *h=a; return h->real.alarm_enabled(&h->adapter,e); }
static int wrap_clear(void *a) { struct harness *h=a; return h->real.alarm_clear(&h->adapter); }
static int wrap_count_read(void *a,uint32_t *c) { struct harness *h=a; return h->real.wake_count_read(&h->adapter,c); }
static int wrap_count_write(void *a,uint32_t c) { struct harness *h=a; return h->real.wake_count_write(&h->adapter,c); }
static int wrap_writer_start(void *a) {
 struct harness *h=a;
 int rc=h->real.writer_start(&h->adapter);
 if(!rc)touch(h,"writer_started");
 return rc;
}
static int wrap_writer_poll(void *a,int64_t *rc,int64_t *e) { struct harness *h=a; return h->real.writer_poll(&h->adapter,rc,e); }
static int channel_start(void *a) { (void)a;return 0; }
static int channel_poll(void *a) { (void)a;return 1; }
static ssize_t sink(void *a,const void *p,size_t n) { struct harness *h=a; return write(h->wire,p,n); }
static int ack_poll(void *a,char hex[M16_ACK_HEX]) {
 struct harness *h=a;
 touch(h,"wire_done");
 char path[4096];
 if(test_path(h,"ack",path,sizeof(path)))return -1;
 int fd=open(path,O_RDONLY|O_CLOEXEC);
 if(fd<0)return errno==ENOENT?0:-1;
 ssize_t n=read(fd,hex,M16_ACK_HEX);
 close(fd);
 return n==(ssize_t)M16_ACK_HEX;
}
static int run(int argc,char **argv) {
 if(argc!=6)return 64;
 static struct harness h;
 static struct m16_record records[64];
 static struct m16_journal journal;
 static struct m16_machine machine;
 h.root=argv[2];h.scale=strtoull(argv[4],NULL,10);
 m16_linux_init(&h.adapter,h.root,(unsigned)strtoul(argv[5],NULL,10));
 h.adapter.state_write="/test/state_fifo"; /* labels stay readable, writes can block */
 h.wire=open(argv[3],O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC,0644);
 if(h.wire<0||!h.scale)return 65;
 m16_linux_ops(&h.real,&h.adapter);
 const struct m16_ops ops={.arg=&h,.clock=scaled_clock,.preflight=wrap_preflight,.counters=wrap_counters,
  .alarm_arm=wrap_arm,.alarm_enabled=wrap_enabled,.alarm_clear=wrap_clear,.wake_count_read=wrap_count_read,
  .wake_count_write=wrap_count_write,.writer_start=wrap_writer_start,.writer_poll=wrap_writer_poll,
  .channel_start=channel_start,.channel_poll=channel_poll,.sink=sink,.ack_poll=ack_poll};
 const struct m16_config config={.alarm_s=45,.early_s=15,.late_s=5,.resume_margin_s=20,.channel_s=30,.export_s=600,.ack_s=3000,.cycle_mode=1};
 const unsigned char nonce[16]={0x4d,0x31,0x36,0x53,0x32};
 if(m16_journal_init(&journal,records,64,nonce)||m16_machine_init(&machine,&ops,&config,&journal))return 66;
 enum m16_outcome outcome;
 do {
  outcome=m16_step(&machine);
  if(outcome==M16_O_RUNNING)usleep(200);
 } while(outcome==M16_O_RUNNING);
 printf("{\"outcome\":%d,\"state\":%d,\"failure\":\"%s\",\"failure_error\":%d,\"verdict\":\"%s\",\"slept_ns\":%llu,\"journal\":%d,\"release_rc\":%d}\n",
        (int)outcome,(int)machine.state,m16_fail_name(machine.failure),(int)machine.failure_error,m16_verdict_name(machine.verdict),
        (unsigned long long)machine.slept_ns,(int)journal.state,journal.state==M16_J_ACKED?0:m16_journal_release(&journal));
 return 0;
}
/* One vector per line: fixed field order, written by test.py from vectors.json. */
static int oracle(void) {
 char line[2048];
 while(fgets(line,sizeof(line),stdin)){
  struct m16_cycle c;
  struct m16_expect e;
  memset(&c,0,sizeof(c));
  unsigned long long v[44];
  unsigned n=0;
  char *p=line;
  for(;;){
   char *end;
   errno=0;
   long long s=strtoll(p,&end,10);
   if(end==p)break;
   if(n==44)return 70;
   v[n++]=(unsigned long long)s;
   p=end;
  }
  if(n!=44)return 71;
  unsigned i=0;
  c.clock_pre.boot_ns=v[i++];c.clock_pre.mono_ns=v[i++];c.clock_post.boot_ns=v[i++];c.clock_post.mono_ns=v[i++];
  e.interval_ns=v[i++];e.early_ns=v[i++];e.late_ns=v[i++];
  c.writer_rc=(int64_t)v[i++];c.writer_errno=(int64_t)v[i++];
  uint64_t *const sides[2][8]={
   {&c.pre.success,&c.pre.fail,&c.pre.failed_errno,&c.pre.rtc_irq,&c.pre.alarm_enabled,&c.pre.wake_active,&c.pre.cycle_mode,&c.pre.cpu_mask},
   {&c.post.success,&c.post.fail,&c.post.failed_errno,&c.post.rtc_irq,&c.post.alarm_enabled,&c.post.wake_active,&c.post.cycle_mode,&c.post.cpu_mask}};
  for(unsigned side=0;side<2;side++)for(unsigned k=0;k<8;k++)*sides[side][k]=v[i++];
  for(unsigned k=0;k<2;k++)c.idle_pre.s2idle_usage[k]=v[i++];
  for(unsigned k=2;k<M16_CPUS;k++)c.idle_pre.s2idle_usage[k]=c.idle_pre.s2idle_usage[1];
  for(unsigned k=0;k<2;k++)c.idle_post.s2idle_usage[k]=v[i++];
  for(unsigned k=2;k<M16_CPUS;k++)c.idle_post.s2idle_usage[k]=c.idle_post.s2idle_usage[1];
  uint64_t slept=0;
  enum m16_verdict verdict=m16_judge(&c,&e,&slept);
  printf("%s %llu\n",m16_verdict_name(verdict),(unsigned long long)slept);
 }
 return 0;
}
/* Prints the encoded alarm so the host decoder can be tested against the real encoder. */
static int mark(char **argv) {
 uint64_t alarm=0;
 int rc=m16_mark_encode(strtoull(argv[2],NULL,10),(uint8_t)strtoul(argv[3],NULL,10),(enum m16_mark_code)strtoul(argv[4],NULL,10),&alarm);
 if(rc)return 1;
 printf("%llu\n",(unsigned long long)alarm);
 return 0;
}
int main(int argc,char **argv) {
 setvbuf(stdout,NULL,_IOLBF,0);
 if(argc>=2&&!strcmp(argv[1],"run"))return run(argc,argv);
 if(argc==2&&!strcmp(argv[1],"oracle"))return oracle();
 if(argc==5&&!strcmp(argv[1],"mark"))return mark(argv);
 return 64;
}
