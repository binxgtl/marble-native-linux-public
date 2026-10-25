/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef M15_ESCROW_H
#define M15_ESCROW_H
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
enum m15_state { M15_PC, M15_ISOLATE, M15_WALL, M15_COLLECT, M15_RECONNECT,
                 M15_EXPORT, M15_ACK, M15_RECOVERED, M15_HOLD };
enum m15_file { M15_RAW, M15_STDERR, M15_JOURNAL, M15_METADATA, M15_STATUS, M15_KERNEL, M15_FILES };
struct m15;
struct m15_limits { size_t raw, error, journal, kernel, total; };
/* Only in-memory core. No module, device, mount, charger, reboot or filesystem API. */
struct m15 *m15_create(const unsigned char nonce[16], const void *metadata,size_t n,
                       struct m15_limits limits,uint64_t now);
void m15_destroy(struct m15 *s); /* refuses release while ownership unresolved */
enum m15_state m15_state(const struct m15 *s);
const char *m15_error(const struct m15 *s);
void m15_binding(const struct m15 *s,char hex[65]);
int m15_pc_receipt(struct m15 *s,const void *p,size_t n,uint64_t now);
int m15_isolated(struct m15 *s,int transmitter_reaped,int unbind_verified,uint64_t now);
int m15_wall(struct m15 *s,int pc_absent,int declared_wall,uint64_t now);
int m15_owner_add(struct m15 *s,uint64_t identity,uint64_t now);
int m15_owner_reaped(struct m15 *s,uint64_t identity,int raw_wait,uint64_t now);
int m15_census_begin(struct m15 *s);
void m15_census_closed(struct m15 *s); /* trusted adapter only after waitpid ECHILD */
int m15_append(struct m15 *s,enum m15_file file,const void *p,size_t n);
int m15_finish(struct m15 *s,int collector_wait,int census_closed,uint64_t now);
int m15_reconnect(struct m15 *s,int pc_configured,uint64_t now);
typedef ssize_t (*m15_sink)(void *arg,const void *p,size_t n);
/* One bounded nonblocking sink call; positive short writes are advanced exactly.
 * No state can call them delivery. Caller must honor the nonblocking contract. */
int m15_export_step(struct m15 *s,m15_sink sink,void *arg,uint64_t now);
int m15_host_ack(struct m15 *s,const void *p,size_t n,uint64_t now);
int m15_tick(struct m15 *s,uint64_t now);
void m15_poison(struct m15 *s,const char *reason);
const unsigned char *m15_evidence(const struct m15 *s,enum m15_file file,size_t *n);
uint64_t m15_accepted_bytes(const struct m15 *s);
int m15_ownership_clear(const struct m15 *s);
/* Cleanup/reboot/device safety is deliberately NOT granted by this API. */
#endif
