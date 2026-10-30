/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef M15_DISPLAY_LOOP_H
#define M15_DISPLAY_LOOP_H
#include <stdint.h>
extern const char *m15_display_ready;
_Noreturn void m15_display_loop(void *,uint32_t);
#endif
