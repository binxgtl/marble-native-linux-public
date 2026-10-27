/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef M15_PARENT_OWNERSHIP_H
#define M15_PARENT_OWNERSHIP_H
#include <sys/types.h>
enum role { CUSTODIAN, DISPLAY, CONNECTOR, KMSG };
struct parent_owner {pid_t pid;enum role role;int reaped,status;};
struct parent_ledger {struct parent_owner owners[4];unsigned count;int failed,escrow_lost;};
int parent_add(struct parent_ledger *,pid_t,enum role);
int parent_wait(struct parent_ledger *,pid_t,int);
/* A custodian is expected LIVE at freeze. Parent completion is not collector census. */
int parent_custodian_live(const struct parent_ledger *);
#endif
