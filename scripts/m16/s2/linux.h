/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef M16_LINUX_H
#define M16_LINUX_H
#include "machine.h"

/* Real procfs and sysfs readers plus the two children that may block. root is ""
 * on a device and a synthetic tree in tests. No role, regulator, power-supply or
 * reboot path exists here, and the only sysfs writes are the three named below:
 * wakealarm, wakeup_count and state. */
struct m16_linux {
 const char *root,*state_write;
 unsigned wake_count_timeout_ms;
 int writer_fd; long writer_pid;
};
void m16_linux_init(struct m16_linux *l,const char *root,unsigned wake_count_timeout_ms);
void m16_linux_ops(struct m16_ops *ops,struct m16_linux *l);
/* Parsers kept separate so their formats are tested against exact kernel output. */
int m16_parse_interrupts(const char *text,const char *name,uint64_t *total);
int m16_parse_cpu_mask(const char *text,uint64_t *mask);
int m16_parse_mem_sleep(const char *text,uint32_t *selected);
int m16_has_token(const char *text,const char *token);
/* True only for dummy_udc.N, the emulator the carrier builds in. Everything else is real USB. */
int m16_udc_is_emulated(const char *name);
#endif
