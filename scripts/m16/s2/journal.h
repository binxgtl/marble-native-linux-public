/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef M16_JOURNAL_H
#define M16_JOURNAL_H
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* Ordered RAM evidence for one suspend cycle. Fixed caller-owned storage, no
 * allocation and no I/O of its own: the only path out is m16_journal_export(),
 * and nothing is released until the host proves it holds the same chain head. */
#define M16_RECORD_SIZE 128u
#define M16_BODY_SIZE 96u /* hashed part of a record; the chain field follows it */
#define M16_PAYLOAD 64u
#define M16_HEADER_SIZE 96u
#define M16_RESERVED 3u /* one FAIL, one CLEANUP and one SEAL always fit */
#define M16_JITTER_NS 5000000ull /* the pair is two reads, not one atomic sample */
#define M16_ACK_HEX 64u

enum m16_event {
 M16_EV_OPEN=1, M16_EV_PHASE, M16_EV_COUNTERS_PRE, M16_EV_IDLE_PRE, M16_EV_ALARM,
 M16_EV_WAKE_COUNT, M16_EV_WRITER, M16_EV_COUNTERS_POST, M16_EV_IDLE_POST,
 M16_EV_VERDICT, M16_EV_CLEANUP, M16_EV_FAIL, M16_EV_SEAL, M16_EV_LIMIT
};
enum m16_journal_state { M16_J_OPEN, M16_J_SEALED, M16_J_ACKED, M16_J_RELEASED };

struct m16_clock { uint64_t boot_ns,mono_ns; };
struct m16_record { /* little-endian on the wire, fixed size */
 uint32_t seq; uint16_t type,length; uint64_t boot_ns,mono_ns;
 unsigned char payload[M16_PAYLOAD]; unsigned char chain[32];
};
struct m16_journal {
 struct m16_record *records; uint32_t capacity,count;
 unsigned char nonce[16],head[32];
 enum m16_journal_state state;
 uint64_t export_offset,last_boot,last_mono;
 uint32_t ack_failures; int have_clock;
};

int m16_clock_valid(const struct m16_clock *c);
int m16_journal_init(struct m16_journal *j,struct m16_record *storage,uint32_t capacity,const unsigned char nonce[16]);
/* -ERANGE: clocks disagree with the record before. -ENOSPC: only reserved slots
 * remain. -EINVAL: bad call. None of these changes what is already recorded. */
int m16_journal_append(struct m16_journal *j,enum m16_event type,const struct m16_clock *c,const void *payload,size_t n);
/* Keeps working when clocks do not: a failure stamped with the last accepted
 * pair is evidence, a failure that could not be written is not. */
int m16_journal_fail(struct m16_journal *j,uint32_t reason,int32_t error,uint32_t state);
int m16_journal_seal(struct m16_journal *j);
uint64_t m16_journal_wire_size(const struct m16_journal *j);
typedef ssize_t (*m16_sink)(void *arg,const void *p,size_t n);
/* One bounded sink call. Returns 1 complete, 0 progress or retry, -1 sink error.
 * Short writes advance exactly. A sealed journal can be exported any number of times. */
int m16_journal_export(struct m16_journal *j,m16_sink sink,void *arg);
void m16_journal_rewind(struct m16_journal *j);
/* Compares against the chain head. A wrong ACK changes nothing except a counter. */
int m16_journal_ack(struct m16_journal *j,const char hex[M16_ACK_HEX]);
/* Refused unless ACKED. Everything before that keeps the evidence intact. */
int m16_journal_release(struct m16_journal *j);
void m16_hex(const unsigned char *p,size_t n,char *out);
void m16_put32(unsigned char *p,uint32_t v);
void m16_put64(unsigned char *p,uint64_t v);
#endif
