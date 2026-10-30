/* SPDX-License-Identifier: GPL-2.0-only */
#include "machine.h"
#include <errno.h>
#include <string.h>

#define S_TO_NS 1000000000ull
#define MIN_ALARM_S 30u /* above alarmtimer's two-second refusal and any entry latency */
#define MAX_ALARM_S 300u

const char *m16_fail_name(enum m16_fail f) {
 static const char *const names[M16_F_LIMIT]={
  "NONE","CLOCK","JOURNAL","PREFLIGHT_READ","NO_FREEZE","RTC_IDENTITY","NO_WAKEALARM","USB_PRESENT",
  "ADSP_RUNNING","WAKE_ACTIVE","ALARM_STALE","COUNTERS","ALARM_ARM","ALARM_READBACK","WAKE_COUNT_READ",
  "WAKE_COUNT_WRITE","ENTRY_LATE","WRITER_START","WRITER_POLL","WRITER_TIMEOUT"};
 return (unsigned)f<M16_F_LIMIT?names[f]:"UNKNOWN";
}
int m16_config_valid(const struct m16_config *c) {
 if(!c||c->alarm_s<MIN_ALARM_S||c->alarm_s>MAX_ALARM_S||c->early_s>=c->alarm_s)return 0;
 return c->late_s&&c->resume_margin_s&&c->channel_s&&c->export_s&&c->ack_s;
}
int m16_machine_init(struct m16_machine *m,const struct m16_ops *ops,const struct m16_config *c,struct m16_journal *j) {
 if(!m||!ops||!j||!m16_config_valid(c)||j->state!=M16_J_OPEN||j->count)return -EINVAL;
 if(!ops->clock||!ops->preflight||!ops->counters||!ops->alarm_arm||!ops->alarm_enabled||!ops->alarm_clear)return -EINVAL;
 if(!ops->wake_count_read||!ops->wake_count_write||!ops->writer_start||!ops->writer_poll)return -EINVAL;
 if(!ops->channel_start||!ops->channel_poll||!ops->sink||!ops->ack_poll)return -EINVAL;
 memset(m,0,sizeof(*m));
 m->ops=*ops;m->config=*c;m->journal=j;m->state=M16_S_INIT;m->verdict=M16_V_INVALID;
 return 0;
}
enum m16_fail m16_preflight_gate(const struct m16_preflight *p) {
 if(!p)return M16_F_PREFLIGHT_READ;
 if(!p->freeze_available)return M16_F_NO_FREEZE;
 if(!p->rtc_identity)return M16_F_RTC_IDENTITY;
 if(!p->wakealarm_present)return M16_F_NO_WAKEALARM;
 if(p->udc_count)return M16_F_USB_PRESENT;
 if(!p->adsp_offline)return M16_F_ADSP_RUNNING;
 if(p->wake_active)return M16_F_WAKE_ACTIVE;
 return M16_F_NONE;
}
static void record(struct m16_machine *m,enum m16_event type,const struct m16_clock *c,const void *p,size_t n,enum m16_fail *bad) {
 int rc=m16_journal_append(m->journal,type,c,p,n);
 if(rc&&!*bad)*bad=rc==-ERANGE?M16_F_CLOCK:M16_F_JOURNAL;
}
static void counters_payload(const struct m16_counters *c,unsigned char *p) {
 const uint64_t v[8]={c->success,c->fail,c->failed_errno,c->rtc_irq,c->alarm_enabled,c->wake_active,c->cycle_mode,c->cpu_mask};
 for(unsigned i=0;i<8;i++)m16_put64(p+8*i,v[i]);
}
static void idle_payload(const struct m16_idle *c,unsigned char *p) {
 for(unsigned i=0;i<M16_CPUS;i++)m16_put64(p+8*i,c->s2idle_usage[i]);
}
/* Disarmed at most once, by the path that armed it. Stamped with the last accepted
 * clocks so the record survives even a clock failure. */
static void disarm(struct m16_machine *m) {
 if(!m->armed)return;
 m->armed=0;
 int enabled=-1,got=m->ops.alarm_enabled(m->ops.arg,&enabled),cleared=0;
 if(!got&&enabled){
  cleared=m->ops.alarm_clear(m->ops.arg);
  if(m->ops.alarm_enabled(m->ops.arg,&enabled))enabled=-1;
 }
 const struct m16_clock last={m->journal->last_boot,m->journal->last_mono};
 unsigned char p[12];
 m16_put32(p,(uint32_t)got);m16_put32(p+4,(uint32_t)cleared);m16_put32(p+8,(uint32_t)enabled);
 (void)m16_journal_append(m->journal,M16_EV_CLEANUP,&last,p,sizeof(p));
}
static void finish_record(struct m16_machine *m,enum m16_state next) {
 if(m16_journal_seal(m->journal))next=M16_S_HOLD; /* nothing verifiable to send */
 m->state=next;
}
/* Latches the first cause and keeps the journal intact. A writer still in the
 * kernel means a transition is unresolved, so that path touches nothing else. */
static void fail(struct m16_machine *m,enum m16_fail why,int error) {
 enum m16_state from=m->state;
 m->failure=why;m->failure_error=error;
 (void)m16_journal_fail(m->journal,(uint32_t)why,error,(uint32_t)from);
 if(m->writer_active){finish_record(m,M16_S_HOLD);return;}
 disarm(m);
 finish_record(m,M16_S_CHANNEL);
}
static void step_init(struct m16_machine *m,const struct m16_clock *c) {
 enum m16_fail bad=M16_F_NONE;
 unsigned char p[M16_PAYLOAD]={0};
 m16_put32(p,m->config.alarm_s);m16_put32(p+4,m->config.early_s);m16_put32(p+8,m->config.late_s);
 m16_put64(p+16,m->config.cycle_mode);
 record(m,M16_EV_OPEN,c,p,24,&bad);
 if(bad){fail(m,bad,0);return;}
 struct m16_preflight f;
 memset(&f,0,sizeof(f));
 int rc=m->ops.preflight(m->ops.arg,&f);
 m16_put32(p,M16_P_PREFLIGHT);m16_put32(p+4,f.mem_sleep);m16_put32(p+8,f.udc_count);m16_put32(p+12,f.wake_active);
 record(m,M16_EV_PHASE,c,p,16,&bad);
 if(rc){fail(m,M16_F_PREFLIGHT_READ,rc);return;}
 if(!bad)bad=m16_preflight_gate(&f);
 if(bad){fail(m,bad,0);return;}
 int enabled=1;
 rc=m->ops.alarm_enabled(m->ops.arg,&enabled);
 if(rc||enabled){fail(m,M16_F_ALARM_STALE,rc);return;}
 rc=m->ops.counters(m->ops.arg,&m->cycle.pre,&m->cycle.idle_pre);
 if(rc){fail(m,M16_F_COUNTERS,rc);return;}
 m->cycle.pre.cycle_mode=m->config.cycle_mode;
 counters_payload(&m->cycle.pre,p);record(m,M16_EV_COUNTERS_PRE,c,p,M16_PAYLOAD,&bad);
 idle_payload(&m->cycle.idle_pre,p);record(m,M16_EV_IDLE_PRE,c,p,M16_PAYLOAD,&bad);
 if(bad){fail(m,bad,0);return;}
 m->cycle.clock_pre=*c;
 rc=m->ops.alarm_arm(m->ops.arg,m->config.alarm_s);
 m->armed=1; /* on any return: a failed write may still have reached the RTC */
 int readback=0,got=rc?0:m->ops.alarm_enabled(m->ops.arg,&readback);
 memset(p,0,sizeof(p));
 m16_put32(p,m->config.alarm_s);m16_put32(p+4,(uint32_t)rc);m16_put32(p+8,(uint32_t)readback);
 record(m,M16_EV_ALARM,c,p,12,&bad);
 if(rc){fail(m,M16_F_ALARM_ARM,rc);return;}
 if(got||!readback){fail(m,M16_F_ALARM_READBACK,got);return;}
 if(bad){fail(m,bad,0);return;}
 /* Entering after the alarm would sleep with nothing left to wake it. */
 m->enter_by=c->boot_ns+(uint64_t)(m->config.alarm_s/2)*S_TO_NS;
 m->state=M16_S_ARMED;
}
static void step_armed(struct m16_machine *m,const struct m16_clock *c) {
 enum m16_fail bad=M16_F_NONE;
 uint32_t count=0;
 int got=m->ops.wake_count_read(m->ops.arg,&count),put=got?0:m->ops.wake_count_write(m->ops.arg,count);
 unsigned char p[12];
 m16_put32(p,count);m16_put32(p+4,(uint32_t)got);m16_put32(p+8,(uint32_t)put);
 record(m,M16_EV_WAKE_COUNT,c,p,sizeof(p),&bad);
 if(got){fail(m,M16_F_WAKE_COUNT_READ,got);return;}
 if(put){fail(m,M16_F_WAKE_COUNT_WRITE,put);return;}
 if(bad){fail(m,bad,0);return;}
 m->wake_count=count;
 m->state=M16_S_COUNTED;
}
static void step_counted(struct m16_machine *m,const struct m16_clock *c) {
 enum m16_fail bad=M16_F_NONE;
 if(c->boot_ns>=m->enter_by){fail(m,M16_F_ENTRY_LATE,0);return;}
 unsigned char p[4];
 m16_put32(p,M16_P_SUSPEND_ENTER);
 record(m,M16_EV_PHASE,c,p,sizeof(p),&bad);
 if(bad){fail(m,bad,0);return;}
 int rc=m->ops.writer_start(m->ops.arg);
 if(rc){fail(m,M16_F_WRITER_START,rc);return;}
 m->writer_active=1;
 /* BOOTTIME keeps counting asleep, so this deadline survives the cycle. It can only
  * fire once PID1 is thawed; a kernel that never resumes needs the operator. */
 m->deadline=c->boot_ns+(uint64_t)(m->config.alarm_s+m->config.late_s+m->config.resume_margin_s)*S_TO_NS;
 m->state=M16_S_SUSPENDING;
}
static void step_suspending(struct m16_machine *m,const struct m16_clock *c) {
 enum m16_fail bad=M16_F_NONE;
 int64_t rc=0,error=0;
 int done=m->ops.writer_poll(m->ops.arg,&rc,&error);
 if(done<0){fail(m,M16_F_WRITER_POLL,done);return;}
 if(!done){
  if(c->boot_ns>=m->deadline)fail(m,M16_F_WRITER_TIMEOUT,0);
  return;
 }
 m->writer_active=0;
 /* c was read before the poll, and PID1 may have frozen and thawed between the two.
  * Only a sample taken after the writer returned can stand for the far side. */
 struct m16_clock post={0,0};
 int read_rc=m->ops.clock(m->ops.arg,&post);
 if(read_rc||!m16_clock_valid(&post)){fail(m,M16_F_CLOCK,read_rc);return;}
 unsigned char p[M16_PAYLOAD]={0};
 m16_put64(p,(uint64_t)rc);m16_put64(p+8,(uint64_t)error);
 record(m,M16_EV_WRITER,&post,p,16,&bad);
 m->cycle.writer_rc=rc;m->cycle.writer_errno=error;m->cycle.clock_post=post;
 int got=m->ops.counters(m->ops.arg,&m->cycle.post,&m->cycle.idle_post);
 if(got){fail(m,M16_F_COUNTERS,got);return;}
 m->cycle.post.cycle_mode=m->config.cycle_mode;
 counters_payload(&m->cycle.post,p);record(m,M16_EV_COUNTERS_POST,&post,p,M16_PAYLOAD,&bad);
 idle_payload(&m->cycle.idle_post,p);record(m,M16_EV_IDLE_POST,&post,p,M16_PAYLOAD,&bad);
 const struct m16_expect e={(uint64_t)m->config.alarm_s*S_TO_NS,(uint64_t)m->config.early_s*S_TO_NS,(uint64_t)m->config.late_s*S_TO_NS};
 m->verdict=m16_judge(&m->cycle,&e,&m->slept_ns);
 memset(p,0,sizeof(p));
 m16_put32(p,(uint32_t)m->verdict);m16_put64(p+8,m->slept_ns);
 record(m,M16_EV_VERDICT,&post,p,16,&bad);
 if(bad){fail(m,bad,0);return;}
 disarm(m);
 finish_record(m,M16_S_CHANNEL);
}
static void hold(struct m16_machine *m) { m->state=M16_S_HOLD; }
static void step_tail(struct m16_machine *m,const struct m16_clock *c) {
 switch(m->state){
 case M16_S_CHANNEL:
  if(m->ops.channel_start(m->ops.arg)){hold(m);return;}
  m->deadline=c->boot_ns+(uint64_t)m->config.channel_s*S_TO_NS;
  m->state=M16_S_CHANNEL_WAIT;
  return;
 case M16_S_CHANNEL_WAIT:{
  int ready=m->ops.channel_poll(m->ops.arg);
  if(ready<0||(!ready&&c->boot_ns>=m->deadline)){hold(m);return;}
  if(ready){m->deadline=c->boot_ns+(uint64_t)m->config.export_s*S_TO_NS;m->state=M16_S_EXPORT;}
  return;
 }
 case M16_S_EXPORT:{
  int sent=m16_journal_export(m->journal,m->ops.sink,m->ops.arg);
  if(sent>0){m->deadline=c->boot_ns+(uint64_t)m->config.ack_s*S_TO_NS;m->state=M16_S_ACK;return;}
  if(sent<0){m->export_errors++;m16_journal_rewind(m->journal);}
  if(c->boot_ns>=m->deadline)hold(m);
  return;
 }
 case M16_S_ACK:{
  char hex[M16_ACK_HEX];
  int have=m->ops.ack_poll(m->ops.arg,hex);
  if(have<0){hold(m);return;}
  if(have&&!m16_journal_ack(m->journal,hex)){m->state=M16_S_RETAINED;return;}
  if(c->boot_ns>=m->deadline)hold(m);
  return;
 }
 default:
  return;
 }
}
enum m16_outcome m16_step(struct m16_machine *m) {
 if(!m)return M16_O_HOLD;
 if(m->state==M16_S_RETAINED)return m->verdict==M16_V_PASS&&!m->failure?M16_O_VERIFIED_PASS:M16_O_VERIFIED_NOT_PASS;
 if(m->state==M16_S_HOLD)return M16_O_HOLD;
 struct m16_clock c={0,0};
 int rc=m->ops.clock(m->ops.arg,&c);
 if(rc||!m16_clock_valid(&c)){
  /* Nothing past the seal needs time to stay honest; before it, time is the evidence. */
  if(m->state<M16_S_CHANNEL)fail(m,M16_F_CLOCK,rc);
  else hold(m);
  return M16_O_RUNNING;
 }
 switch(m->state){
 case M16_S_INIT: step_init(m,&c);break;
 case M16_S_ARMED: step_armed(m,&c);break;
 case M16_S_COUNTED: step_counted(m,&c);break;
 case M16_S_SUSPENDING: step_suspending(m,&c);break;
 default: step_tail(m,&c);break;
 }
 return M16_O_RUNNING;
}
