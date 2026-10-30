/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef M16_ORACLE_H
#define M16_ORACLE_H
#include "journal.h"

#define M16_CPUS 8u
#define M16_MIN_SLEEP_NS 1000000000ull /* the RTC resolves one second, no finer */

/* Exactly M16_PAYLOAD bytes on the wire. failed_errno is stored as a magnitude;
 * /sys/power/suspend_stats/last_failed_errno prints it negative. */
struct m16_counters {
 uint64_t success,fail,failed_errno,rtc_irq,alarm_enabled,wake_active,cycle_mode,cpu_mask;
};
struct m16_idle { uint64_t s2idle_usage[M16_CPUS]; };
struct m16_cycle {
 struct m16_clock clock_pre,clock_post;
 struct m16_counters pre,post;
 struct m16_idle idle_pre,idle_post;
 int64_t writer_rc,writer_errno;
};
struct m16_expect { uint64_t interval_ns,early_ns,late_ns; };
enum m16_verdict {
 M16_V_INVALID, /* inputs contradict each other: never read as a device result */
 M16_V_PASS,
 M16_V_ABORTED, /* the kernel refused and said so */
 M16_V_NO_SLEEP, /* claimed success, no measurable frozen time */
 M16_V_EARLY_WAKE,
 M16_V_LATE_WAKE,
 M16_V_WRONG_WAKE, /* slept the right time without the RTC interrupt */
 M16_V_LIMIT
};
const char *m16_verdict_name(enum m16_verdict v);
/* Integer arithmetic only, no state. Anything not proven is not PASS. */
enum m16_verdict m16_judge(const struct m16_cycle *c,const struct m16_expect *e,uint64_t *slept_ns);
#endif
