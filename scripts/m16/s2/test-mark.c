/* SPDX-License-Identifier: GPL-2.0-only */
#include "mark.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

static unsigned checks;
#define CHECK(x) do{checks++;if(!(x)){fprintf(stderr,"FAIL %s:%d %s\n",__FILE__,__LINE__,#x);exit(1);}}while(0)
#define NOW 80076948ull /* the 1972-style value this RTC really counts from */

static void test_codes(void) {
 CHECK(m16_mark_code(M16_V_PASS,0,1)==M16_M_PASS);
 CHECK(m16_mark_code(M16_V_ABORTED,0,1)==M16_M_ABORTED);
 CHECK(m16_mark_code(M16_V_NO_SLEEP,0,1)==M16_M_NO_SLEEP);
 CHECK(m16_mark_code(M16_V_EARLY_WAKE,0,1)==M16_M_EARLY_WAKE);
 CHECK(m16_mark_code(M16_V_LATE_WAKE,0,1)==M16_M_LATE_WAKE);
 CHECK(m16_mark_code(M16_V_WRONG_WAKE,0,1)==M16_M_WRONG_WAKE);
 CHECK(m16_mark_code(M16_V_INVALID,0,1)==M16_M_INVALID);
 CHECK(m16_mark_code(M16_V_LIMIT,0,1)==M16_M_INVALID); /* never reads as a pass */
 /* A failure outranks any verdict, even a stored PASS. */
 CHECK(m16_mark_code(M16_V_PASS,1,1)==M16_M_FAILED_AFTER_RESUME);
 CHECK(m16_mark_code(M16_V_PASS,1,0)==M16_M_FAILED_BEFORE_SUSPEND);
}
static void test_encoding(void) {
 for(unsigned code=M16_M_PASS;code<M16_M_LIMIT;code++){
  uint64_t a=0;
  CHECK(!m16_mark_encode(NOW,0xa5,code,&a));
  CHECK((a&15)==code&&(a>>4&255)==0xa5);
  CHECK(a>NOW+3600&&a<=NOW+M16_MARK_HORIZON_S+M16_MARK_SLOT);
  CHECK(a<=M16_MARK_MAX_RTC);
 }
 /* Every starting second stays safely in the future. */
 for(uint64_t now=NOW;now<NOW+2*M16_MARK_SLOT;now++){
  uint64_t a=0;
  CHECK(!m16_mark_encode(now,1,M16_M_PASS,&a));
  CHECK(a>now+3000);
 }
}
static void test_rejections(void) {
 uint64_t a=7;
 CHECK(m16_mark_encode(NOW,0,M16_M_PASS,&a)==-EINVAL);
 CHECK(m16_mark_encode(NOW,1,M16_M_NONE,&a)==-EINVAL);
 CHECK(m16_mark_encode(NOW,1,M16_M_LIMIT,&a)==-EINVAL);
 CHECK(m16_mark_encode(NOW,1,M16_M_PASS,NULL)==-EINVAL);
 CHECK(m16_mark_encode(M16_MARK_MAX_RTC,1,M16_M_PASS,&a)==-ERANGE);
 CHECK(m16_mark_encode(M16_MARK_MAX_RTC-M16_MARK_HORIZON_S+1,1,M16_M_PASS,&a)==-ERANGE);
 CHECK(a==7); /* nothing written on refusal */
}
int main(void) {
 test_codes();test_encoding();test_rejections();
 printf("mark: %u checks passed\n",checks);
 return 0;
}
