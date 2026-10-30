/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef M16_MACHINE_H
#define M16_MACHINE_H
#include "journal.h"
#include "oracle.h"

/* One RTC-timed s2idle cycle before ADSP and USB exist. Each step is bounded and
 * never blocks: suspend itself runs in a child, so PID1 stays able to record what
 * happened afterwards. Terminal states stop calling every platform operation. */
enum m16_state {
 M16_S_INIT, M16_S_ARMED, M16_S_COUNTED, M16_S_SUSPENDING, M16_S_CHANNEL,
 M16_S_CHANNEL_WAIT, M16_S_EXPORT, M16_S_ACK, M16_S_RETAINED, M16_S_HOLD
};
enum m16_fail {
 M16_F_NONE, M16_F_CLOCK, M16_F_JOURNAL, M16_F_PREFLIGHT_READ, M16_F_NO_FREEZE, M16_F_RTC_IDENTITY,
 M16_F_NO_WAKEALARM, M16_F_USB_PRESENT, M16_F_ADSP_RUNNING, M16_F_WAKE_ACTIVE, M16_F_ALARM_STALE,
 M16_F_COUNTERS, M16_F_ALARM_ARM, M16_F_ALARM_READBACK, M16_F_WAKE_COUNT_READ, M16_F_WAKE_COUNT_WRITE,
 M16_F_ENTRY_LATE, M16_F_WRITER_START, M16_F_WRITER_POLL, M16_F_WRITER_TIMEOUT, M16_F_LIMIT
};
enum m16_phase { M16_P_PREFLIGHT=1, M16_P_SUSPEND_ENTER };
enum m16_outcome { M16_O_RUNNING, M16_O_VERIFIED_PASS, M16_O_VERIFIED_NOT_PASS, M16_O_HOLD };

struct m16_config {
 uint32_t alarm_s,early_s,late_s,resume_margin_s,channel_s,export_s,ack_s;
 uint64_t cycle_mode;
};
/* A true value is a checked property, never a default: see m16_preflight_gate(). */
struct m16_preflight {
 int freeze_available,rtc_identity,wakealarm_present,adsp_offline;
 uint32_t mem_sleep,udc_count,wake_active;
};
enum m16_mem_sleep { M16_MEM_UNKNOWN, M16_MEM_S2IDLE, M16_MEM_DEEP };
struct m16_ops {
 void *arg;
 int (*clock)(void *arg,struct m16_clock *c);
 int (*preflight)(void *arg,struct m16_preflight *p);
 int (*counters)(void *arg,struct m16_counters *c,struct m16_idle *i);
 int (*alarm_arm)(void *arg,uint32_t seconds);
 int (*alarm_enabled)(void *arg,int *enabled);
 int (*alarm_clear)(void *arg);
 int (*wake_count_read)(void *arg,uint32_t *count); /* bounded by the adapter */
 int (*wake_count_write)(void *arg,uint32_t count);
 int (*writer_start)(void *arg);
 int (*writer_poll)(void *arg,int64_t *rc,int64_t *error); /* 0 running, 1 done, <0 lost */
 int (*channel_start)(void *arg);
 int (*channel_poll)(void *arg); /* 0 waiting, 1 ready, <0 failed */
 ssize_t (*sink)(void *arg,const void *p,size_t n);
 int (*ack_poll)(void *arg,char hex[M16_ACK_HEX]); /* 0 none, 1 ready, <0 failed */
};
struct m16_machine {
 struct m16_ops ops; struct m16_config config; struct m16_journal *journal;
 enum m16_state state; enum m16_fail failure; int32_t failure_error;
 enum m16_verdict verdict; uint64_t slept_ns,deadline,enter_by;
 uint32_t wake_count,export_errors;
 int armed,writer_active;
 struct m16_cycle cycle;
};
int m16_config_valid(const struct m16_config *c);
int m16_machine_init(struct m16_machine *m,const struct m16_ops *ops,const struct m16_config *c,struct m16_journal *j);
/* First failed property in a fixed order, or M16_F_NONE. Pure, so it is tested alone. */
enum m16_fail m16_preflight_gate(const struct m16_preflight *p);
enum m16_outcome m16_step(struct m16_machine *m);
const char *m16_fail_name(enum m16_fail f);
#endif
