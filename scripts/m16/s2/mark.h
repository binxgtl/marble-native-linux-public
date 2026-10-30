/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef M16_MARK_H
#define M16_MARK_H
#include "oracle.h"

/* A few bits that outlive a reset: the outcome written as the value of an RTC alarm,
 * which Android can read back without any write. Pure encoding, no I/O. A mark that
 * is present proves PID1 ran after the cycle. One that is absent proves nothing. */
#define M16_MARK_HORIZON_S 7200u /* one RTC alarm, so it must outlast the attended run */
#define M16_MARK_SLOT 4096u
#define M16_MARK_MAX_RTC 0xffffffffull /* the PMIC alarm register is 32 bits */

enum m16_mark_code {
 M16_M_NONE, M16_M_PASS, M16_M_ABORTED, M16_M_NO_SLEEP, M16_M_EARLY_WAKE, M16_M_LATE_WAKE,
 M16_M_WRONG_WAKE, M16_M_INVALID, M16_M_FAILED_BEFORE_SUSPEND, M16_M_FAILED_AFTER_RESUME, M16_M_LIMIT
};
enum m16_mark_code m16_mark_code(enum m16_verdict verdict,int failed,int reached_suspend);
/* -EINVAL for a reserved code or tag 0, -ERANGE when the value would not fit the register. */
int m16_mark_encode(uint64_t rtc_now,uint8_t tag,enum m16_mark_code code,uint64_t *alarm);
#endif
