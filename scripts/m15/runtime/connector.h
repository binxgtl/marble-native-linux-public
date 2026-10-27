/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef M15_CONNECTOR_H
#define M15_CONNECTOR_H
#include <stddef.h>
#include <stdint.h>
struct connector { uint64_t sequence;int have,attached,failed;char partner[512]; };
/* All multicast messages, not only typec, advance the loss-detection sequence.
 * peer/credential checks are made by recvmsg adapter before this parser. */
int connector_event(struct connector *,const void *,size_t,int kernel_peer,int truncated);
#endif
