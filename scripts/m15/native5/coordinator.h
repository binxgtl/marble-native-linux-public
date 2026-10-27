/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef M15_COORDINATOR_H
#define M15_COORDINATOR_H
#include <stdint.h>
enum stage { START, BLUE, YELLOW_WAIT, YELLOW_CAPTURE, GREEN, CYAN, COMPLETE, RED };
enum fact { INITIALIZED, PC_ADMITTED, PC_DETACHED, WALL_ATTACHED, COLLECTOR_FROZEN,
 PC_RECONNECTED, HOST_ACK, PARENT_RECEIPT, CUSTODIAN_EXIT, COLLECTOR_FAILED, IO_FAILED };
struct coordinator {
 enum stage stage;uint64_t last,deadline;unsigned sequence;
 int initialized,admitted,collector_owned,collector_reaped,census_closed;
 int custodian_owned,custodian_reaped,ack,parent_receipt,escrow_lost;
};
void coord_init(struct coordinator *,uint64_t);
int coord_fact(struct coordinator *,enum fact,unsigned,uint64_t);
int coord_tick(struct coordinator *,uint64_t);
const char *coord_name(enum stage);
/* No teardown/reboot authorization is returned by this API. */
#endif
