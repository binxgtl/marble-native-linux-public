/* SPDX-License-Identifier: GPL-2.0-only */
#include "machine.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Deterministic platform: every operation is counted, so "never suspended" and
 * "never touched the RTC again" are asserted from what was called. */
static unsigned checks;
#define CHECK(x) do{checks++;if(!(x)){fprintf(stderr,"FAIL %s:%d %s\n",__FILE__,__LINE__,#x);exit(1);}}while(0)
#define S 1000000000ull

enum op { OP_NONE,OP_CLOCK,OP_PREFLIGHT,OP_COUNTERS,OP_ARM,OP_ALARM_READ,OP_CLEAR,OP_COUNT_READ,OP_COUNT_WRITE,
          OP_WRITER_START,OP_WRITER_POLL,OP_CHANNEL_START,OP_CHANNEL_POLL,OP_SINK,OP_ACK,OP_LIMIT };
struct fake {
 uint64_t boot,mono,step_ns,jump_ns;
 unsigned calls[OP_LIMIT],jump_call,writers;
 int fail_op,fail_rc,fail_nth; /* fail_op fails on its fail_nth call, counting from 1 */
 struct m16_preflight pre;
 struct m16_counters counters;
 struct m16_idle idle;
 int alarm,stale_alarm,armed_readback_zero;
 uint64_t sleep_ns; unsigned writer_polls_until_done,writer_polls;
 int64_t writer_rc,writer_errno;
 int resumed,clock_after_poll_only,clear_keeps_alarm;
 unsigned channel_polls_until_ready,sink_limit,sink_errors,acks_wrong;
 int channel_never,sink_blocked,ack_never;
 uint64_t rtc_delta,success_delta,fail_delta,failed_errno;
 const struct m16_journal *journal;
 unsigned char wire[32768]; size_t wire_used; int wire_done;
};
static int faulted(struct fake *f,enum op op) {
 f->calls[op]++;
 return f->fail_op==(int)op&&(f->fail_nth?f->calls[op]==(unsigned)f->fail_nth:1);
}
static int f_clock(void *a,struct m16_clock *c) {
 struct fake *f=a;
 if(faulted(f,OP_CLOCK))return f->fail_rc;
 f->boot+=f->step_ns;f->mono+=f->step_ns;
 if(f->calls[OP_CLOCK]==f->jump_call){f->boot+=f->jump_ns;f->mono+=f->jump_ns;}
 c->boot_ns=f->boot;c->mono_ns=f->mono;
 return 0;
}
static int f_preflight(void *a,struct m16_preflight *p) {
 struct fake *f=a;
 if(faulted(f,OP_PREFLIGHT))return f->fail_rc;
 *p=f->pre;
 return 0;
}
static int f_counters(void *a,struct m16_counters *c,struct m16_idle *i) {
 struct fake *f=a;
 if(faulted(f,OP_COUNTERS))return f->fail_rc;
 *c=f->counters;*i=f->idle;c->alarm_enabled=(uint64_t)f->alarm;
 return 0;
}
static int f_arm(void *a,uint32_t seconds) {
 struct fake *f=a;
 (void)seconds;
 if(faulted(f,OP_ARM))return f->fail_rc;
 f->alarm=!f->armed_readback_zero;
 return 0;
}
static int f_alarm(void *a,int *enabled) {
 struct fake *f=a;
 if(faulted(f,OP_ALARM_READ))return f->fail_rc;
 *enabled=f->alarm||f->stale_alarm;
 return 0;
}
static int f_clear(void *a) {
 struct fake *f=a;
 if(faulted(f,OP_CLEAR))return f->fail_rc;
 if(!f->clear_keeps_alarm)f->alarm=0;
 return 0;
}
static int f_count_read(void *a,uint32_t *c) {
 struct fake *f=a;
 if(faulted(f,OP_COUNT_READ))return f->fail_rc;
 *c=41;
 return 0;
}
static int f_count_write(void *a,uint32_t c) {
 struct fake *f=a;
 CHECK(c==41);
 return faulted(f,OP_COUNT_WRITE)?f->fail_rc:0;
}
static int f_writer_start(void *a) {
 struct fake *f=a;
 if(faulted(f,OP_WRITER_START))return f->fail_rc;
 f->writers++;
 return 0;
}
static int f_writer_poll(void *a,int64_t *rc,int64_t *error) {
 struct fake *f=a;
 if(faulted(f,OP_WRITER_POLL))return f->fail_rc;
 if(++f->writer_polls<f->writer_polls_until_done)return 0;
 if(!f->resumed){
  /* Sleep lands here, after the machine's clock read for this step. That is the
   * freeze-between-sample-and-poll window a stale post clock would hide. */
  f->resumed=1;
  f->boot+=f->sleep_ns;
  f->counters.success+=f->success_delta;f->counters.fail+=f->fail_delta;
  if(f->fail_delta)f->counters.failed_errno=f->failed_errno;
  f->counters.rtc_irq+=f->rtc_delta;
  if(f->rtc_delta)f->alarm=0;
  for(unsigned i=0;i<M16_CPUS;i++)f->idle.s2idle_usage[i]+=f->success_delta;
 }
 *rc=f->writer_rc;*error=f->writer_errno;
 return 1;
}
static int f_channel_start(void *a) {
 struct fake *f=a;
 return faulted(f,OP_CHANNEL_START)?f->fail_rc:0;
}
static int f_channel_poll(void *a) {
 struct fake *f=a;
 if(faulted(f,OP_CHANNEL_POLL))return f->fail_rc;
 if(f->channel_never)return 0;
 return f->calls[OP_CHANNEL_POLL]>f->channel_polls_until_ready;
}
static ssize_t f_sink(void *a,const void *p,size_t n) {
 struct fake *f=a;
 f->calls[OP_SINK]++;
 if(f->sink_blocked){errno=EAGAIN;return -1;}
 if(f->sink_errors){
  f->sink_errors--;f->wire_used=0;errno=EIO;
  return -1;
 }
 if(f->sink_limit&&n>f->sink_limit)n=f->sink_limit;
 memcpy(f->wire+f->wire_used,p,n);
 f->wire_used+=n;
 return (ssize_t)n;
}
static int f_ack(void *a,char hex[M16_ACK_HEX]) {
 struct fake *f=a;
 if(faulted(f,OP_ACK))return f->fail_rc;
 if(f->ack_never)return 0;
 m16_hex(f->journal->head,32,hex);
 if(f->acks_wrong){f->acks_wrong--;hex[0]=hex[0]=='0'?'1':'0';}
 return 1;
}
static const struct m16_ops ops_template={
 .clock=f_clock,.preflight=f_preflight,.counters=f_counters,.alarm_arm=f_arm,.alarm_enabled=f_alarm,
 .alarm_clear=f_clear,.wake_count_read=f_count_read,.wake_count_write=f_count_write,
 .writer_start=f_writer_start,.writer_poll=f_writer_poll,.channel_start=f_channel_start,
 .channel_poll=f_channel_poll,.sink=f_sink,.ack_poll=f_ack};
static const struct m16_config config={.alarm_s=45,.early_s=15,.late_s=5,.resume_margin_s=20,
 .channel_s=30,.export_s=30,.ack_s=30,.cycle_mode=1};
static const unsigned char nonce[16]={0xa5,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
#define CAPACITY 32u
struct run { struct fake f; struct m16_journal j; struct m16_record r[CAPACITY]; struct m16_machine m; struct m16_ops ops; enum m16_outcome outcome; };

static void healthy(struct fake *f) {
 memset(f,0,sizeof(*f));
 f->boot=100*S;f->mono=100*S-S/2;f->step_ns=S/100;
 f->pre=(struct m16_preflight){.freeze_available=1,.rtc_identity=1,.wakealarm_present=1,.adsp_offline=1,.mem_sleep=M16_MEM_DEEP};
 f->counters.cpu_mask=0xff;
 f->sleep_ns=40*S;f->rtc_delta=1;f->success_delta=1;
 f->writer_polls_until_done=2;
}
static void start(struct run *r,uint32_t capacity) {
 r->ops=ops_template;r->ops.arg=&r->f;
 CHECK(!m16_journal_init(&r->j,r->r,capacity,nonce));
 r->f.journal=&r->j;
 CHECK(!m16_machine_init(&r->m,&r->ops,&config,&r->j));
}
static void drive(struct run *r) {
 unsigned rounds=0;
 do r->outcome=m16_step(&r->m); while(r->outcome==M16_O_RUNNING&&++rounds<100000);
 CHECK(r->outcome!=M16_O_RUNNING);
 /* A terminal machine calls nothing, however often it is stepped. */
 unsigned before[OP_LIMIT];
 memcpy(before,r->f.calls,sizeof(before));
 for(int i=0;i<16;i++)CHECK(m16_step(&r->m)==r->outcome);
 CHECK(!memcmp(before,r->f.calls,sizeof(before)));
}
static unsigned count_type(const struct run *r,enum m16_event t) {
 unsigned n=0;
 for(uint32_t i=0;i<r->j.count;i++)n+=r->r[i].type==t;
 return n;
}
static uint32_t get32(const unsigned char *p) { return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24; }
static uint32_t failure_of(const struct run *r) {
 for(uint32_t i=0;i<r->j.count;i++)if(r->r[i].type==M16_EV_FAIL)return get32(r->r[i].payload);
 return 0;
}
/* Whatever else went wrong: sealed once, intact, and the RTC not left armed by us. */
static void invariants(const struct run *r) {
 CHECK(r->j.state==M16_J_SEALED||r->j.state==M16_J_ACKED||!r->j.count);
 if(r->j.count){
  CHECK(r->r[r->j.count-1].type==M16_EV_SEAL);
  for(uint32_t i=0;i<r->j.count;i++)CHECK(r->r[i].seq==i);
 }
 CHECK(count_type(r,M16_EV_SEAL)<=1&&count_type(r,M16_EV_FAIL)<=1);
 CHECK(r->f.writers<=1&&r->f.calls[OP_ARM]<=1&&r->f.calls[OP_CLEAR]<=1);
}
static void write_wire(const struct run *r,const char *dir,const char *name) {
 char path[512];
 snprintf(path,sizeof(path),"%s/%s.wire",dir,name);
 FILE *f=fopen(path,"wb");
 CHECK(f);
 CHECK(fwrite(r->f.wire,1,r->f.wire_used,f)==r->f.wire_used);
 CHECK(!fclose(f));
}
static struct run *fresh(void) { struct run *r=calloc(1,sizeof(*r));CHECK(r);healthy(&r->f);return r; }

static void test_pass(const char *dir) {
 struct run *r=fresh();
 r->f.sink_limit=61;
 start(r,CAPACITY);drive(r);
 CHECK(r->outcome==M16_O_VERIFIED_PASS&&r->m.verdict==M16_V_PASS&&!r->m.failure);
 CHECK(r->m.state==M16_S_RETAINED&&r->j.state==M16_J_ACKED);
 CHECK(r->m.slept_ns==40*S);
 CHECK(r->f.writers==1&&!r->f.calls[OP_CLEAR]);
 CHECK(count_type(r,M16_EV_FAIL)==0&&count_type(r,M16_EV_VERDICT)==1&&count_type(r,M16_EV_CLEANUP)==1);
 CHECK(r->f.wire_used==m16_journal_wire_size(&r->j));
 /* The machine keeps the evidence even after ACK; release stays a separate decision. */
 CHECK(r->j.count>0&&r->r[0].type==M16_EV_OPEN);
 invariants(r);
 write_wire(r,dir,"pass");
 free(r);
}
/* Regression for the stale sample: sleep happens after the step's clock read. */
static void test_post_clock_is_taken_after_the_writer(void) {
 struct run *r=fresh();
 r->f.writer_polls_until_done=1;
 start(r,CAPACITY);drive(r);
 CHECK(r->m.verdict==M16_V_PASS&&r->m.slept_ns==40*S);
 free(r);
}
static void expect_no_suspend(struct run *r,enum m16_fail why) {
 CHECK(r->m.failure==why);
 CHECK(failure_of(r)==(uint32_t)why);
 CHECK(!r->f.writers);
 CHECK(!r->f.alarm); /* never left armed */
 CHECK(r->outcome==M16_O_VERIFIED_NOT_PASS); /* the failure itself still reaches the host */
 CHECK(r->j.state==M16_J_ACKED);
 invariants(r);
}
static void test_preflight_properties(void) {
 for(unsigned i=0;i<6;i++){
  struct run *r=fresh();
  enum m16_fail why=M16_F_NONE;
  switch(i){
  case 0: r->f.pre.freeze_available=0;why=M16_F_NO_FREEZE;break;
  case 1: r->f.pre.rtc_identity=0;why=M16_F_RTC_IDENTITY;break;
  case 2: r->f.pre.wakealarm_present=0;why=M16_F_NO_WAKEALARM;break;
  case 3: r->f.pre.udc_count=1;why=M16_F_USB_PRESENT;break;
  case 4: r->f.pre.adsp_offline=0;why=M16_F_ADSP_RUNNING;break;
  default: r->f.pre.wake_active=1;why=M16_F_WAKE_ACTIVE;break;
  }
  start(r,CAPACITY);drive(r);
  expect_no_suspend(r,why);
  CHECK(!r->f.calls[OP_ARM]);
  free(r);
 }
 const struct m16_preflight empty={0};
 CHECK(m16_preflight_gate(&empty)==M16_F_NO_FREEZE); /* all-zero is never a pass */
 CHECK(m16_preflight_gate(NULL)==M16_F_PREFLIGHT_READ);
}
static void test_stale_alarm_is_not_ours_to_clear(void) {
 struct run *r=fresh();
 r->f.stale_alarm=1;
 start(r,CAPACITY);drive(r);
 CHECK(r->m.failure==M16_F_ALARM_STALE&&!r->f.calls[OP_ARM]&&!r->f.calls[OP_CLEAR]&&!r->f.writers);
 free(r);
}
static void fail_before_suspend(enum op op,int nth,enum m16_fail why,int armed) {
 struct run *r=fresh();
 r->f.fail_op=(int)op;r->f.fail_rc=-EIO;r->f.fail_nth=nth;
 start(r,CAPACITY);drive(r);
 expect_no_suspend(r,why);
 CHECK(r->f.calls[OP_ARM]==(unsigned)armed);
 free(r);
}
static void test_each_step_before_suspend(void) {
 fail_before_suspend(OP_PREFLIGHT,0,M16_F_PREFLIGHT_READ,0);
 fail_before_suspend(OP_COUNTERS,1,M16_F_COUNTERS,0);
 fail_before_suspend(OP_ALARM_READ,1,M16_F_ALARM_STALE,0);
 fail_before_suspend(OP_ARM,0,M16_F_ALARM_ARM,1);
 fail_before_suspend(OP_COUNT_READ,0,M16_F_WAKE_COUNT_READ,1);
 fail_before_suspend(OP_COUNT_WRITE,0,M16_F_WAKE_COUNT_WRITE,1);
 fail_before_suspend(OP_WRITER_START,0,M16_F_WRITER_START,1);
 /* Armed but readback says no: suspending would have nothing to wake it. */
 struct run *r=fresh();
 r->f.armed_readback_zero=1;
 start(r,CAPACITY);drive(r);
 CHECK(r->m.failure==M16_F_ALARM_READBACK&&!r->f.writers);
 free(r);
}
static void test_entry_too_late(void) {
 struct run *r=fresh();
 r->f.jump_call=3;r->f.jump_ns=30*S; /* the time left to enter is already spent */
 start(r,CAPACITY);drive(r);
 expect_no_suspend(r,M16_F_ENTRY_LATE);
 CHECK(r->f.calls[OP_CLEAR]==1);
 free(r);
}
static void test_writer_never_returns(void) {
 struct run *r=fresh();
 r->f.writer_polls_until_done=~0u;r->f.step_ns=S;
 start(r,CAPACITY);drive(r);
 CHECK(r->outcome==M16_O_HOLD&&r->m.failure==M16_F_WRITER_TIMEOUT&&r->m.state==M16_S_HOLD);
 /* The kernel may still be mid-transition: no RTC write, no USB bring-up. */
 CHECK(!r->f.calls[OP_CLEAR]&&!r->f.calls[OP_CHANNEL_START]);
 CHECK(r->j.state==M16_J_SEALED&&m16_journal_release(&r->j)==-EBUSY);
 invariants(r);
 free(r);
}
static void test_writer_lost(void) {
 struct run *r=fresh();
 r->f.fail_op=OP_WRITER_POLL;r->f.fail_rc=-EPIPE;r->f.fail_nth=1;
 start(r,CAPACITY);drive(r);
 CHECK(r->outcome==M16_O_HOLD&&r->m.failure==M16_F_WRITER_POLL&&!r->f.calls[OP_CHANNEL_START]);
 invariants(r);
 free(r);
}
static void test_kernel_refused(const char *dir) {
 struct run *r=fresh();
 r->f.writer_rc=-1;r->f.writer_errno=EBUSY;r->f.sleep_ns=0;r->f.rtc_delta=0;
 r->f.success_delta=0;r->f.fail_delta=1;r->f.failed_errno=EBUSY;
 start(r,CAPACITY);drive(r);
 CHECK(r->outcome==M16_O_VERIFIED_NOT_PASS&&r->m.verdict==M16_V_ABORTED&&!r->m.failure);
 CHECK(r->f.calls[OP_CLEAR]==1&&!r->f.alarm); /* the alarm never fired, so it is ours */
 invariants(r);
 write_wire(r,dir,"refused");
 free(r);
}
static void verdict_case(uint64_t sleep,uint64_t rtc,uint64_t success,enum m16_verdict want) {
 struct run *r=fresh();
 r->f.sleep_ns=sleep;r->f.rtc_delta=rtc;r->f.success_delta=success;
 start(r,CAPACITY);drive(r);
 CHECK(r->m.verdict==want&&r->outcome==M16_O_VERIFIED_NOT_PASS);
 CHECK(!r->f.alarm);
 invariants(r);
 free(r);
}
static void test_verdicts(void) {
 verdict_case(S/2,0,1,M16_V_NO_SLEEP);
 verdict_case(10*S,1,1,M16_V_EARLY_WAKE);
 verdict_case(60*S,1,1,M16_V_LATE_WAKE);
 verdict_case(40*S,0,1,M16_V_WRONG_WAKE);
 verdict_case(40*S,2,1,M16_V_WRONG_WAKE);
 verdict_case(40*S,1,2,M16_V_INVALID);
 verdict_case(40*S,1,0,M16_V_INVALID);
}
static void test_clock_failure_everywhere(void) {
 for(int nth=1;nth<=8;nth++){
  struct run *r=fresh();
  r->f.fail_op=OP_CLOCK;r->f.fail_rc=-EIO;r->f.fail_nth=nth;
  start(r,CAPACITY);drive(r);
  CHECK(r->outcome!=M16_O_VERIFIED_PASS);
  invariants(r);
  free(r);
 }
}
static void test_clock_failure_while_writer_runs(void) {
 struct run *r=fresh();
 r->f.writer_polls_until_done=~0u;
 r->f.fail_op=OP_CLOCK;r->f.fail_rc=-EIO;r->f.fail_nth=6;
 start(r,CAPACITY);drive(r);
 CHECK(r->outcome==M16_O_HOLD&&r->m.failure==M16_F_CLOCK&&!r->f.calls[OP_CHANNEL_START]&&!r->f.calls[OP_CLEAR]);
 invariants(r);
 free(r);
}
static void test_journal_full_still_records_failure(void) {
 struct run *r=fresh();
 start(r,6);drive(r); /* OPEN, PHASE, COUNTERS_PRE fit; IDLE_PRE does not */
 CHECK(r->m.failure==M16_F_JOURNAL&&!r->f.calls[OP_ARM]&&!r->f.writers);
 CHECK(failure_of(r)==M16_F_JOURNAL&&r->r[r->j.count-1].type==M16_EV_SEAL);
 CHECK(r->outcome==M16_O_VERIFIED_NOT_PASS);
 free(r);
}
static void test_channel_and_export_failures_retain(void) {
 struct run *r=fresh();
 r->f.fail_op=OP_CHANNEL_START;r->f.fail_rc=-EIO;
 start(r,CAPACITY);drive(r);
 CHECK(r->outcome==M16_O_HOLD&&r->m.verdict==M16_V_PASS&&r->j.state==M16_J_SEALED&&m16_journal_release(&r->j)==-EBUSY);
 free(r);
 r=fresh();
 r->f.channel_never=1;r->f.step_ns=S;
 start(r,CAPACITY);drive(r);
 CHECK(r->outcome==M16_O_HOLD&&!r->f.calls[OP_SINK]&&r->j.count);
 free(r);
 r=fresh();
 r->f.sink_blocked=1;r->f.step_ns=S;
 start(r,CAPACITY);drive(r);
 CHECK(r->outcome==M16_O_HOLD&&r->j.state==M16_J_SEALED&&r->j.count);
 free(r);
 r=fresh();
 r->f.sink_errors=3;
 start(r,CAPACITY);drive(r);
 CHECK(r->outcome==M16_O_VERIFIED_PASS&&r->m.export_errors==3); /* restart, nothing lost */
 free(r);
}
static void test_ack(void) {
 struct run *r=fresh();
 r->f.acks_wrong=2;
 start(r,CAPACITY);drive(r);
 CHECK(r->outcome==M16_O_VERIFIED_PASS&&r->j.ack_failures==2);
 free(r);
 r=fresh();
 r->f.ack_never=1;r->f.step_ns=S;
 start(r,CAPACITY);drive(r);
 CHECK(r->outcome==M16_O_HOLD&&r->j.state==M16_J_SEALED&&m16_journal_release(&r->j)==-EBUSY);
 free(r);
 r=fresh();
 r->f.fail_op=OP_ACK;r->f.fail_rc=-EIO;
 start(r,CAPACITY);drive(r);
 CHECK(r->outcome==M16_O_HOLD&&r->j.state==M16_J_SEALED);
 free(r);
}
static void test_alarm_that_will_not_clear(void) {
 struct run *r=fresh();
 r->f.fail_op=OP_COUNT_READ;r->f.fail_rc=-ETIMEDOUT;r->f.clear_keeps_alarm=1;
 start(r,CAPACITY);drive(r);
 CHECK(r->m.failure==M16_F_WAKE_COUNT_READ&&r->f.calls[OP_CLEAR]==1&&!r->f.writers);
 CHECK(count_type(r,M16_EV_CLEANUP)==1); /* recorded, and never retried */
 free(r);
}
static void test_config(void) {
 struct m16_config c=config;
 CHECK(m16_config_valid(&c));
 c.alarm_s=29;CHECK(!m16_config_valid(&c));
 c.alarm_s=301;CHECK(!m16_config_valid(&c));
 c=config;c.early_s=c.alarm_s;CHECK(!m16_config_valid(&c));
 c=config;c.late_s=0;CHECK(!m16_config_valid(&c));
 c=config;c.ack_s=0;CHECK(!m16_config_valid(&c));
 CHECK(!m16_config_valid(NULL));
 struct run *r=fresh();
 r->ops=ops_template;r->ops.writer_start=NULL;
 CHECK(!m16_journal_init(&r->j,r->r,CAPACITY,nonce));
 CHECK(m16_machine_init(&r->m,&r->ops,&config,&r->j)==-EINVAL);
 free(r);
}
int main(int argc,char **argv) {
 if(argc!=2)return 64;
 test_pass(argv[1]);test_post_clock_is_taken_after_the_writer();test_preflight_properties();
 test_stale_alarm_is_not_ours_to_clear();test_each_step_before_suspend();test_entry_too_late();
 test_writer_never_returns();test_writer_lost();test_kernel_refused(argv[1]);test_verdicts();
 test_clock_failure_everywhere();test_clock_failure_while_writer_runs();
 test_journal_full_still_records_failure();test_channel_and_export_failures_retain();test_ack();
 test_alarm_that_will_not_clear();test_config();
 printf("machine: %u checks passed\n",checks);
 return 0;
}
