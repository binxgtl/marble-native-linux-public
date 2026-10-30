/* SPDX-License-Identifier: GPL-2.0-only */
#include "oracle.h"

const char *m16_verdict_name(enum m16_verdict v) {
 static const char *const names[M16_V_LIMIT]={"INVALID","PASS","ABORTED","NO_SLEEP","EARLY_WAKE","LATE_WAKE","WRONG_WAKE"};
 return (unsigned)v<M16_V_LIMIT?names[v]:"INVALID";
}
static uint64_t gap(const struct m16_clock *c) { return c->boot_ns>c->mono_ns?c->boot_ns-c->mono_ns:0; }
static int counters_ordered(const struct m16_cycle *c) {
 if(c->post.success<c->pre.success||c->post.fail<c->pre.fail||c->post.rtc_irq<c->pre.rtc_irq)return 0;
 if(c->pre.cycle_mode!=c->post.cycle_mode)return 0;
 if(!c->pre.cpu_mask||c->pre.cpu_mask!=c->post.cpu_mask||c->pre.cpu_mask>>M16_CPUS)return 0;
 for(unsigned i=0;i<M16_CPUS;i++)if(c->idle_post.s2idle_usage[i]<c->idle_pre.s2idle_usage[i])return 0;
 return 1;
}
/* Named by mask, not inferred from zeros: on a first cycle every counter starts
 * at zero, so a present CPU that never idled would otherwise look absent. */
static int all_idled(const struct m16_cycle *c) {
 for(unsigned i=0;i<M16_CPUS;i++)
  if(c->post.cpu_mask>>i&1&&c->idle_post.s2idle_usage[i]<=c->idle_pre.s2idle_usage[i])return 0;
 return 1;
}
enum m16_verdict m16_judge(const struct m16_cycle *c,const struct m16_expect *e,uint64_t *slept_ns) {
 if(slept_ns)*slept_ns=0;
 if(!c||!e||!e->interval_ns||e->early_ns>=e->interval_ns)return M16_V_INVALID;
 if(e->interval_ns>UINT64_MAX-e->late_ns)return M16_V_INVALID;
 if(!m16_clock_valid(&c->clock_pre)||!m16_clock_valid(&c->clock_post))return M16_V_INVALID;
 if(c->clock_post.boot_ns<c->clock_pre.boot_ns||c->clock_post.mono_ns<c->clock_pre.mono_ns)return M16_V_INVALID;
 uint64_t a=gap(&c->clock_pre),b=gap(&c->clock_post);
 if(b+M16_JITTER_NS<a||!counters_ordered(c))return M16_V_INVALID;
 uint64_t slept=b>a?b-a:0,success=c->post.success-c->pre.success,fail=c->post.fail-c->pre.fail;
 if(slept_ns)*slept_ns=slept;
 if(c->writer_rc){
  /* A refusal must look like one: counted as failed, and not asleep. */
  if(!success&&fail==1&&slept<M16_MIN_SLEEP_NS&&c->writer_errno>0&&c->post.failed_errno==(uint64_t)c->writer_errno)return M16_V_ABORTED;
  return M16_V_INVALID;
 }
 if(c->writer_errno||success!=1||fail||c->pre.alarm_enabled||c->post.alarm_enabled>1)return M16_V_INVALID;
 if(slept<M16_MIN_SLEEP_NS)return M16_V_NO_SLEEP;
 if(!all_idled(c))return M16_V_INVALID;
 if(slept<e->interval_ns-e->early_ns)return M16_V_EARLY_WAKE;
 if(slept>e->interval_ns+e->late_ns)return M16_V_LATE_WAKE;
 /* Arrival at the right time is not cause: the alarm must have fired and cleared. */
 if(c->post.rtc_irq-c->pre.rtc_irq!=1||c->post.alarm_enabled)return M16_V_WRONG_WAKE;
 return M16_V_PASS;
}
