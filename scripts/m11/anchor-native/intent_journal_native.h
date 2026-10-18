/* G7 (docs/m11-custodian-native-integration.md): intent journaling before every TX. Built only in
 * the reviewed M11_CUSTODIAN_NATIVE build; never part of a candidate.
 *
 * A transport wrapper around the native transport (G2/G6). Its write_fn, for every packet:
 *  1. decodes the GPR packet and refuses (-EPERM, nothing written) any opcode outside the
 *     custodian's set: GET_SPF_STATE, SHARED_MEM_MAP/UNMAP_REGIONS, GRAPH_OPEN/PREPARE/START/STOP/
 *     CLOSE, SET_CFG, GET_CFG. APM_CMD_CLOSE_ALL is therefore never sent from userspace;
 *  2. requires the custodian's ledger intent first: a MAP only once dsp_map_attempted is set, an
 *     UNMAP only once dsp_unmap_attempted is set (-EPERM otherwise);
 *  3. appends one record (boot epoch, sequence, opcode, token, client data; for a MAP the dma-buf
 *     fd number, size, pool and flags; for an UNMAP the map handle) to the sink, and transmits only
 *     after the sink accepted it whole (-EIO otherwise, nothing written);
 *  4. then calls the inner write_fn unchanged.
 * Any refusal happens after the engine called write_fn, so the engine records an UNKNOWN TX
 * (WRITE_ERROR) and the region manager keeps the region unresolved: fail closed, never "not sent".
 * The production sink writes each record with one write(2) to an fd (/dev/kmsg: one record per
 * call, a short write is a failure). The journal is evidence, not durable storage: RAM and kmsg do
 * not survive the reset that ends a mapped boot unless something captured them first.
 */
#ifndef M11_INTENT_JOURNAL_NATIVE_H
#define M11_INTENT_JOURNAL_NATIVE_H
#ifndef M11_CUSTODIAN_NATIVE
#error "intent_journal_native requires the reviewed M11_CUSTODIAN_NATIVE build"
#endif
#include "../qualification/ownership/m11_custodian.h"
#include <stddef.h>
#include <stdint.h>

#define M11_INTENT_RECORD_MAX 192u

typedef struct {
    int (*append_fn)(void *user, const char *rec, size_t len); /* 0 = the whole record accepted */
    void *user;
} m11_intent_sink;

typedef struct {
    m11_gpr_transport_t inner;
    const m11_intent_sink *sink;
    const m11_boot_ledger *boot;
    uint32_t seq, journaled, refused, sink_failures;
} m11_intent_link;

/* Wrap `inner` (copied) with the journal. -EINVAL on NULLs or an uninitialized ledger. */
int m11_intent_transport(m11_intent_link *, const m11_gpr_transport_t *inner, const m11_intent_sink *,
                         const m11_boot_ledger *, m11_gpr_transport_t *out);

/* The record for one packet ("<6>M11INTENT ...\n", kmsg level 6). Length, or -EBADMSG for a
 * malformed packet, -EPERM for an opcode outside the set, -ENOSPC if cap is too small. */
int m11_intent_format(char *buf, size_t cap, uint64_t boot_epoch, uint32_t seq,
                      const uint8_t *pkt, size_t len);

/* Production sink over an fd: one write(2) per record (EINTR retried), a short write is -EIO. */
typedef struct { int fd; uint32_t writes; } m11_intent_fd_sink;
int m11_intent_sink_fd(m11_intent_fd_sink *, int fd, m11_intent_sink *out);

#endif
