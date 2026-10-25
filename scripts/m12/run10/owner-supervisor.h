/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef M12_OWNER_SUPERVISOR_H
#define M12_OWNER_SUPERVISOR_H
#include "../next/cnssd.h"
#include <sys/types.h>
/* PID1 owns launch/socket and evidence forwarding. Final receipt AND reap
 * are required; missing evidence never permits kill/force/retry. */
struct m12_owner_supervisor {
    int fd,poisoned,stop_sent,final_received,reaped,exit_status;
    int reap_errno,terminal_checked,terminal_rc,eof_verified;
    unsigned wait_calls;
    pid_t child;
    uint32_t sequence;
    struct m12_owner_record latest;
};
int m12_owner_receive(struct m12_owner_supervisor *,unsigned timeout_ms);
int m12_owner_stop(struct m12_owner_supervisor *,int qca_retired,int cnss_retired,
                   int unresolved_child,int transfer_pending);
int m12_owner_reap(struct m12_owner_supervisor *);
/* Only after final receipt and successful waitpid: no queued records, EOF,
 * clean final rc and normal exit0. Never relax generic receive EOF handling. */
int m12_owner_finish(struct m12_owner_supervisor *);
#endif
