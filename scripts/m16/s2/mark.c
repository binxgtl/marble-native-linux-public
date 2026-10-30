/* SPDX-License-Identifier: GPL-2.0-only */
#include "mark.h"
#include <errno.h>

enum m16_mark_code m16_mark_code(enum m16_verdict verdict,int failed,int reached_suspend) {
 if(failed)return reached_suspend?M16_M_FAILED_AFTER_RESUME:M16_M_FAILED_BEFORE_SUSPEND;
 switch(verdict){
 case M16_V_PASS: return M16_M_PASS;
 case M16_V_ABORTED: return M16_M_ABORTED;
 case M16_V_NO_SLEEP: return M16_M_NO_SLEEP;
 case M16_V_EARLY_WAKE: return M16_M_EARLY_WAKE;
 case M16_V_LATE_WAKE: return M16_M_LATE_WAKE;
 case M16_V_WRONG_WAKE: return M16_M_WRONG_WAKE;
 default: return M16_M_INVALID;
 }
}
/* Low twelve bits carry the run and the outcome; the slot only rounds the alarm down,
 * so it always stays more than an hour ahead of the moment it was set. */
int m16_mark_encode(uint64_t rtc_now,uint8_t tag,enum m16_mark_code code,uint64_t *alarm) {
 if(!alarm||!tag||code<=M16_M_NONE||code>=M16_M_LIMIT)return -EINVAL;
 if(rtc_now>M16_MARK_MAX_RTC-M16_MARK_HORIZON_S)return -ERANGE;
 uint64_t base=(rtc_now+M16_MARK_HORIZON_S)&~(uint64_t)(M16_MARK_SLOT-1);
 *alarm=base|(uint64_t)tag<<4|(uint64_t)code;
 return 0;
}
