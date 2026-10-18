/* The composed native custodian runner core (docs/m11-custodian-native-integration.md, criterion 7):
 * G1-G8 wired in one fixed order. Built only in the reviewed M11_CUSTODIAN_NATIVE build; never part
 * of a candidate; no frozen Run source is used or changed (the PID1 entry that binds the real nodes
 * is a later, separate step).
 *
 * The caller (the PID1 entry, or the stand-in harness) supplies the endpoint and ION anchors already
 * bound and sealed together by the owner seal (m11_anchor_owner_seal_pairs), the G4 heap fd, the
 * PD monitor and the journal sink. m11_crunner_start then, in this order and refusing at the first
 * failure:
 *   1. the effective cmdline gate (m11_custodian_cmdline_allowed) gives contract.strict_iommu; a
 *      refused cmdline starts nothing (no pool, no TX, the heap fd untouched);
 *   2. the PD monitor must be UP;
 *   3. the dma-buf pool is built from the heap fd (G5), the heap fd is closed (nothing allocates
 *      after this), and the pool seal is installed over the owner seal's two pairs;
 *   4. the boot ledger is created, the transport is the G6 transport over the endpoint anchor with
 *      the PD monitor, wrapped by the G7 intent journal; the engine opens through it;
 *   5. the region manager runs over the pooled G3 backend with the ION anchor; the custodian (G1)
 *      enrols with the model contract; the PDR loop (G6) is bound;
 *   6. the composed census must pass.
 * The composed census (before and after MAP, UNMAP and close, after idle, and once more in end):
 * both anchors HELD and passing m11_anchor_check (identity, CLOEXEC, holders), the heap device held by
 * nobody (closed in step 3), the dma-buf pool held exactly at its pairs by this process (G5 census),
 * and no descendant of this process holding a pool buffer or the heap device (an unreadable or
 * exiting descendant is inconclusive and fails). A failed census is a foreign holder: it latches for
 * the boot, refuses every later MAP, UNMAP and close (-EOWNERDEAD), and is reported to the custodian
 * as an uncontrolled global cleanup, so the boot's only end becomes RESET_RETAINING_ANCHORS.
 * Every custodian call is followed by m11_pdr_loop_settle. m11_crunner_end hands the boot to the G8
 * terminal with both anchors, the pool and the journal sink. A start that failed before the custodian
 * enrolled has no G8 decision: m11_crunner_end then journals START_FAILED with the failing step and
 * ends through exit_fn without closing anything (fail closed). Start is one-shot per process.
 */
#ifndef M11_CUSTODIAN_RUNNER_NATIVE_H
#define M11_CUSTODIAN_RUNNER_NATIVE_H
#ifndef M11_CUSTODIAN_NATIVE
#error "custodian_runner_native requires the reviewed M11_CUSTODIAN_NATIVE build"
#endif
#include "gpr_transport_native.h"
#include "intent_journal_native.h"
#include "pdr_loop_native.h"
#include "terminal_native.h"

typedef struct {
    m11_pid1_anchor *endpoint, *ion;   /* bound, HELD, sealed together by the owner seal */
    int heap_fd;                       /* the G4 heap fd; closed by start after the pool is built */
    dev_t heap_rdev;                   /* its device number, for the census (nobody may hold it) */
    unsigned pool_count;
    size_t pool_len;
    int pool_base;
    const m11_shmem_native_sys *sys;   /* NULL = libc */
    const m11_pd_monitor *pd;
    const m11_intent_sink *journal;
    m11_terminal_ops terminal_ops;
    const char *cmdline;               /* the effective /proc/cmdline text */
    uint64_t boot_epoch;
    uint32_t timeout_ms, recovery_budget_ms;
    uint16_t src_port;
} m11_crunner_config;

/* census_why bits: which part of the composed census failed (accumulated over the boot) */
#define M11_CRUNNER_CENSUS_ENDPOINT 1u /* endpoint anchor not HELD or its check failed */
#define M11_CRUNNER_CENSUS_ION      2u /* ION anchor not HELD or its check failed */
#define M11_CRUNNER_CENSUS_HEAP     4u /* this process holds the heap device */
#define M11_CRUNNER_CENSUS_POOL     8u /* this process does not hold the pool exactly */
#define M11_CRUNNER_CENSUS_TREE    16u /* a descendant holds a pool buffer or the heap, or is unreadable */

typedef struct {
    m11_crunner_config cfg;
    int stage;                 /* last completed start step (0..6) */
    int started, census_failed; /* started: the custodian is enrolled (step 5 done) */
    unsigned census_why;
    m11_dmabuf_pool pool;
    m11_boot_ledger boot;
    m11_gpr_native_link link;
    m11_gpr_transport_t inner, transport;
    m11_intent_link journal;
    m11_gpr_engine_t eng;
    m11_shmem_native_link shm;
    m11_shmem_backend_t backend;
    m11_shmem_mgr_t mgr;
    m11_custodian cust;
    m11_pdr_loop loop;
    m11_terminal_native term;
} m11_crunner;

/* 0, or a negative errno with the first failing step in *step (1..6 as above). */
int m11_crunner_start(m11_crunner *, const m11_crunner_config *, uint64_t now_ms, int *step);
/* The composed census; 0 or -1 (and the latch). */
int m11_crunner_census(m11_crunner *);
int m11_crunner_map(m11_crunner *, size_t bytes, uint64_t now_ms, unsigned *slot);
int m11_crunner_retire(m11_crunner *, unsigned slot, uint64_t now_ms);
int m11_crunner_idle(m11_crunner *, uint32_t budget_ms, uint64_t now_ms);
int m11_crunner_close(m11_crunner *);
m11_terminal_action m11_crunner_action(m11_crunner *, uint64_t now_ms);
/* The G8 end (does not return unless the terminal refuses: -EBUSY for HOLD/HOLD_RECONCILE). */
int m11_crunner_end(m11_crunner *, uint64_t now_ms);

#endif
