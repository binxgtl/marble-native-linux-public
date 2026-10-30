/* SPDX-License-Identifier: GPL-2.0-only */
#include "linux.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

static unsigned checks;
#define CHECK(x) do{checks++;if(!(x)){fprintf(stderr,"FAIL %s:%d %s\n",__FILE__,__LINE__,#x);exit(1);}}while(0)

/* Shapes follow the kernel's own output; the numbers are synthetic. */
static const char interrupts[]=
 "           CPU0       CPU1       CPU2       CPU3       CPU4       CPU5       CPU6       CPU7\n"
 "  3:     123456      23456      34567          1          2          3          4          5     GICv3  30 Level     arch_timer\n"
 "260:          4          0          0          1          0          0          0          0  pmic_arb 25164545 Edge      pm8xxx_rtc_alarm\n"
 "282:          0          0          0          0          0          0          0          0   msmgpio  79 Edge      hs_uart_wakeup\n"
 "IPI0:       100        200        300        400        500        600        700        800       Rescheduling interrupts\n"
 "Err:          0\n";

static void test_interrupts(void) {
 uint64_t v=99;
 CHECK(!m16_parse_interrupts(interrupts,"pm8xxx_rtc_alarm",&v)&&v==5);
 CHECK(!m16_parse_interrupts(interrupts,"hs_uart_wakeup",&v)&&!v);
 CHECK(m16_parse_interrupts(interrupts,"no_such_irq",&v)==-ENOENT);
 /* A longer name ending in the wanted text must not match. */
 CHECK(m16_parse_interrupts(" 9: 1 chip x_pm8xxx_rtc_alarm\n","pm8xxx_rtc_alarm",&v)==-ENOENT);
 CHECK(m16_parse_interrupts(" 9: 1 chip pm8xxx_rtc_alarm\n10: 1 chip pm8xxx_rtc_alarm\n","pm8xxx_rtc_alarm",&v)==-EEXIST);
 CHECK(m16_parse_interrupts(" 9: chip pm8xxx_rtc_alarm\n","pm8xxx_rtc_alarm",&v)==-EINVAL);
 CHECK(m16_parse_interrupts("no colon pm8xxx_rtc_alarm\n","pm8xxx_rtc_alarm",&v)==-EINVAL);
 CHECK(!m16_parse_interrupts(" 9: 2 3 0chip pm8xxx_rtc_alarm","pm8xxx_rtc_alarm",&v)&&v==5);
}
static void test_cpu_mask(void) {
 uint64_t m=0;
 CHECK(!m16_parse_cpu_mask("0-7",&m)&&m==0xff);
 CHECK(!m16_parse_cpu_mask("0",&m)&&m==1);
 CHECK(!m16_parse_cpu_mask("0-3,6",&m)&&m==0x4f);
 CHECK(!m16_parse_cpu_mask("1,3,5",&m)&&m==0x2a);
 const char *bad[]={"","8","0-8","3-1","a","0-","0,","0-3,x"," 0"};
 for(unsigned i=0;i<sizeof(bad)/sizeof(*bad);i++)CHECK(m16_parse_cpu_mask(bad[i],&m)==-EINVAL);
}
static void test_mem_sleep(void) {
 uint32_t v=9;
 CHECK(!m16_parse_mem_sleep("[s2idle] deep",&v)&&v==M16_MEM_S2IDLE);
 CHECK(!m16_parse_mem_sleep("s2idle [deep]",&v)&&v==M16_MEM_DEEP);
 CHECK(!m16_parse_mem_sleep("[s2idle]",&v)&&v==M16_MEM_S2IDLE);
 CHECK(m16_parse_mem_sleep("s2idle deep",&v)==-EINVAL);
}
static void test_tokens(void) {
 CHECK(m16_has_token("freeze mem","freeze")&&m16_has_token("freeze mem","mem"));
 CHECK(!m16_has_token("freezer mem","freeze")&&!m16_has_token("","freeze"));
}
int main(void) {
 test_interrupts();test_cpu_mask();test_mem_sleep();test_tokens();
 printf("linux parsers: %u checks passed\n",checks);
 return 0;
}
