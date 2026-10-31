/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef M16_RUN_H
#define M16_RUN_H
#include "../s2/linux.h"
#include "../s2/mark.h"

/* One S3 attempt around the unchanged S2 machine. Colour and settling come before the
 * cycle; mark, ADSP, USB and export come after its seal, so nothing here can change
 * what the journal recorded. No reboot path exists: every ending is a hold. */
#define M16_RUN_RECORDS 64u
#define M16_HOST_HELLO "M16HOST1"
#define M16_HOST_RESEND "M16RESEND1"
#define M16_HOST_ACK "M16ACK1 "
#define M16_DEVICE_LOG "M16LOG1"

struct m16_run {
 struct m16_ops base; /* clock and the S2 readers; channel members stay unset */
 struct m16_config config;
 const char *root,*bootstrap,*adsp,*connector,*display,*tty,*kmsg,*boot_log;
 unsigned char nonce[16];
 uint8_t tag;
 unsigned bootstrap_ms,quiet_ms,settle_ms,display_ms,blue_ms,final_ms,step_ms,pace_ms,log_ms;
 /* Filled in by m16_run_main(). */
 int display_failed,mark_rc,tty_fd,connector_in,connector_out;
 uint64_t mark_value;
 enum m16_mark_code mark_code;
 enum { M16_LINK_ADSP, M16_LINK_CONNECTOR, M16_LINK_HOST, M16_LINK_READY } link;
 long adsp_pid;
 char line[128];
 size_t line_at;
};
enum m16_run_end { M16_END_PASS, M16_END_NOT_PASS, M16_END_HOLD, M16_END_BOOTSTRAP };
/* Returns when PID1 has nothing left to do. The caller holds; it must never exit. */
enum m16_run_end m16_run_main(struct m16_run *r);
const struct m16_machine *m16_run_machine(void);
#endif
