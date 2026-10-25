/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef M15_SUPERVISE_H
#define M15_SUPERVISE_H
#include "escrow.h"
struct m15_process_result { int raw_wait, census_closed, timeout; unsigned tracked,reaped; uint64_t elapsed_ms; };
typedef void (*m15_child_fn)(void *arg);
/* Exclusive process scope required: no ambient children, threads or concurrent
 * spawners. Establishes subreaper BEFORE fork. Remains subreaper on unresolved
 * ownership. Callback is trusted test/integration code, NOT host-supplied exec. */
int m15_supervise(struct m15 *s,m15_child_fn fn,void *arg,unsigned deadline_ms,
                  uint64_t logical_start,struct m15_process_result *result);
#endif
