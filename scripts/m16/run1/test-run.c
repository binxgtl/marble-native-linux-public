/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include "run.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Real run.c, machine and linux.c against a synthetic tree. Time is scaled and the sleep
 * gap comes from the fixture. Never staged into an image. */
struct harness { struct m16_linux adapter; struct m16_ops real; const char *root; uint64_t scale; };

static uint64_t gap_ns(const struct harness *h) {
 char path[4096],b[32];
 snprintf(path,sizeof(path),"%s/test/gap_ns",h->root);
 int fd=open(path,O_RDONLY|O_CLOEXEC);
 if(fd<0)return 0;
 ssize_t n=read(fd,b,sizeof(b)-1);
 close(fd);
 if(n<=0)return 0;
 b[n]=0;
 return strtoull(b,NULL,10);
}
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
 char path[4096];
 snprintf(path,sizeof(path),"%s/test/writer_started",h->root);
 int fd=rc?-1:open(path,O_WRONLY|O_CREAT|O_CLOEXEC,0644);
 if(fd>=0)close(fd);
 return rc;
}
static int wrap_writer_poll(void *a,int64_t *rc,int64_t *e) { struct harness *h=a; return h->real.writer_poll(&h->adapter,rc,e); }
static char paths[8][4096];
static const char *under(unsigned slot,const char *root,const char *name) {
 snprintf(paths[slot],sizeof(paths[slot]),"%s/%s",root,name);
 return paths[slot];
}
int main(int argc,char **argv) {
 if(argc!=5)return 64; /* root tty scale channel_s */
 setvbuf(stdout,NULL,_IOLBF,0);
 static struct harness h;
 static struct m16_run r;
 h.root=argv[1];h.scale=strtoull(argv[3],NULL,10);
 m16_linux_init(&h.adapter,h.root,200);
 h.adapter.state_write="/test/state_fifo";
 m16_linux_ops(&h.real,&h.adapter);
 r.base=(struct m16_ops){.arg=&h,.clock=scaled_clock,.preflight=wrap_preflight,.counters=wrap_counters,
  .alarm_arm=wrap_arm,.alarm_enabled=wrap_enabled,.alarm_clear=wrap_clear,.wake_count_read=wrap_count_read,
  .wake_count_write=wrap_count_write,.writer_start=wrap_writer_start,.writer_poll=wrap_writer_poll};
 r.config=(struct m16_config){.alarm_s=45,.early_s=15,.late_s=5,.resume_margin_s=20,.channel_s=(uint32_t)strtoul(argv[4],NULL,10),.export_s=600,.ack_s=600,.cycle_mode=1};
 r.root=h.root;r.tty=argv[2];
 r.bootstrap=under(0,h.root,"test/bootstrap");r.adsp=under(1,h.root,"test/adsp");r.connector=under(2,h.root,"test/connector");
 r.display=under(3,h.root,"test/display");r.kmsg=under(4,h.root,"test/kmsg");r.boot_log=under(5,h.root,"test/boot.log");
 r.tag=0x33;memcpy(r.nonce,"M16RUN1-FIXTURE!",16);
 r.bootstrap_ms=5000;r.quiet_ms=300;r.settle_ms=800;r.display_ms=2000;r.blue_ms=1;r.final_ms=1;r.step_ms=1;r.pace_ms=1;r.log_ms=20000;
 enum m16_run_end end=m16_run_main(&r);
 const struct m16_machine *m=m16_run_machine();
 printf("{\"end\":%d,\"failure\":\"%s\",\"failure_error\":%d,\"verdict\":\"%s\",\"mark_rc\":%d,\"mark_value\":%llu,\"mark_code\":%d,\"writer_active\":%d}\n",
        (int)end,m16_fail_name(m->failure),(int)m->failure_error,m16_verdict_name(m->verdict),r.mark_rc,(unsigned long long)r.mark_value,(int)r.mark_code,m->writer_active);
 return 0;
}
