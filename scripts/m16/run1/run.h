/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef M16_RUN_H
#define M16_RUN_H
#include "../s2/linux.h"
#include "../s2/mark.h"

/* One S3-S7 attempt around the unchanged S2 machine, one machine per cycle. Colour, settling
 * and read-only checks sit between cycles; mark, ADSP, USB and export come after the last
 * seal, so nothing here can change what a journal recorded. No reboot path exists: every
 * ending is a hold. */
#define M16_RUN_RECORDS 64u
#define M16_RUN_CYCLES 6u
#define M16_HOST_HELLO "M16HOST1"
#define M16_HOST_RESEND "M16RESEND1"
#define M16_HOST_ACK "M16ACK1 "
#define M16_DEVICE_CYCLES "M16CYCLES"
#define M16_DEVICE_LOG "M16LOG1"

struct m16_run {
 struct m16_ops base; /* clock and the S2 readers; channel members stay unset */
 struct m16_config config,key_config;
 const char *root,*bootstrap,*nodes,*adsp,*connector,*display,*tty,*kmsg,*boot_log,*block,*touch;
 unsigned char nonce[16];
 uint8_t tag;
 unsigned rtc_cycles;
 int operator_steps; /* touch window and Volume Up cycle after the RTC cycles */
 int block_flags;
 unsigned bootstrap_ms,quiet_ms,settle_ms,display_ms,blue_ms,check_ms,storage_ms,touch_ms,prompt_ms,final_ms,step_ms,pace_ms,link_ms,log_ms;
 /* Filled in by m16_run_main(). */
 unsigned cycles,current;
 int display_failed,mark_rc,tty_fd,connector_in,connector_out,storage_ready,all_ok,key_ok;
 long touch_events;
 uint64_t mark_value;
 enum m16_mark_code mark_code;
 enum { M16_LINK_ADSP, M16_LINK_CONNECTOR, M16_LINK_HOST, M16_LINK_READY } link;
 long adsp_pid;
 char line[128],baseline[65];
 size_t line_at;
};
enum m16_run_end { M16_END_PASS, M16_END_NOT_PASS, M16_END_HOLD, M16_END_BOOTSTRAP };
/* Returns when PID1 has nothing left to do. The caller holds; it must never exit. */
enum m16_run_end m16_run_main(struct m16_run *r);
const struct m16_machine *m16_run_machine(unsigned cycle);
#endif
