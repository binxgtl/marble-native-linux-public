/* Production P3 (docs/m11-custodian-native-integration.md): the PID1 entry of the native custodian.
 * It composes the P1 long-session PD monitor, the P2 boot sequence, the composed runner (G1-G8) and
 * the G8 terminal with production ops. Built only in the reviewed M11_CUSTODIAN_NATIVE build; never
 * part of a candidate; no frozen Run source is used or changed.
 *
 * m11_entry_run, in this order. Any failure before the runner exists closes nothing and writes a
 * START_FAILED record naming the phase and the end (B4, readiness review): while nothing audio was
 * ever opened (no bind attempted on either anchor, no heap fd) the end is reboot_fn, as Run23
 * rebooted a boot whose PD never came UP; once a bind was attempted, or if reboot_fn returns, the
 * end is exit_fn (retaining). B6: each phase writes one compact "<6>M11ENTRY" record (journal,
 * cmdline verdict with the gate tokens, length and CRC32 but never the text, which carries the
 * device serial; PD READY; boot stage and numbers; runner; session; the first HOLD). A
 * never-mapped boot writes 6 of them plus the G8 record, under the /dev/kmsg per-fd burst of 10:
 *   1. arguments, then PID1 (production), then one-shot per process;
 *   2. the journal sink: one fd (production /dev/kmsg, char 1:11 checked), opened before the
 *      spawner is forked (the spawner closes every fd it inherits);
 *   3. the effective cmdline (/proc/cmdline) must pass m11_custodian_cmdline_allowed before
 *      anything else is opened (the runner checks it again);
 *   4. the P1 monitor: an AF_QIPCRTR socket, the long SERVREG session, READY within the bring-up
 *      budget (<= 10 s); a PD that is not UP opens nothing else;
 *   5. the P2 boot with that monitor (spawner, PD UP, endpoint/ION nodes and binds, CMA twin has no
 *      node, G4 heap node, owner seal);
 *   6. the runner with the boot's anchors and heap fd, the same monitor, the journal sink, the
 *      production terminal ops, and the MAP intent wired to the P1 session's resources-busy latch:
 *      from the first MAP intent a PD DOWN is no longer acknowledged. The latch is never released
 *      in this boot (what an UNMAP ACK proves is UNKNOWN, blocker 2), so a DOWN after any MAP stays
 *      unacknowledged and the PD restart is not let through while the ADSP may reach our pages;
 *   7. the session (session_fn), if any. The production configuration has none: it never maps
 *      (CP2 is BLOCKED; a production session is a CP2 decision, not a P3 one);
 *   8. close, then the G8 end. While the custodian decides HOLD or HOLD_RECONCILE, PID1 waits on the
 *      monitor (m11_crunner_idle, hold_idle_ms per round) and asks again; a PD DOWN, a census
 *      failure or the recovery deadline turns the decision into the retaining end. PID1 never
 *      leaves without a G8 end. B5: the orderly end (never mapped, no MAP intent, census clean,
 *      both final closes done) runs the Run23-style teardown between its record and the reboot:
 *      the PD listener is withdrawn (unregister, DEL_LOOKUP, socket closed), one teardown record
 *      is written (the last one: the seal closes the evidence channel), the typed steps run in order
 *      (P4, Run23's sequence: seal, the relay reaped, logger.done, usb_stop, stop_adsp, pd.stop, the
 *      locator reaped, pd.done, common, the checkpoint, unmount), the spawner is stopped. Any refused
 *      gate or failed step holds (hold_fn): no reboot, no exit, nothing more is run.
 * Run25 readiness R1/D2 (docs/m11-argon-run25-readiness.md): every other end also seals the evidence,
 * as Run23 sealed before every reboot (CYAN included):
 *   - a pre-bind failure (the reboot end) runs the same steps after its START_FAILED record: the PD
 *     listener withdrawn when READY (its socket only closed otherwise), one "phase=teardown fail=1"
 *     record, the steps with the RESULT checkpoint "cyan", the spawner stopped (started first when
 *     the failure came before P2 forked it, which is still before any open); a failed step holds;
 *   - before every retaining exit (a post-bind START_FAILED, the runner's partial start, the G8
 *     retaining end) one "phase=seal" record, then only the first seal_count steps (production: seal,
 *     the relay reaped, logger.done); the anchors stay held and the exit follows whatever they return.
 *   The steps start at most once per boot (Run23: never append past an attempted final digest).
 * Not here: the PID1 environment (mounts, ADSP start, USB, the post-seal jobs the spawner runs) is a
 * precondition, part of a later candidate step. /dev must not be a devtmpfs that already holds the
 * audio nodes: P2 refuses a node that exists.
 */
#ifndef M11_CUSTODIAN_ENTRY_NATIVE_H
#define M11_CUSTODIAN_ENTRY_NATIVE_H
#ifndef M11_CUSTODIAN_NATIVE
#error "custodian_entry_native requires the reviewed M11_CUSTODIAN_NATIVE build"
#endif
#include "custodian_boot_native.h"
#include "custodian_runner_native.h"
#include "pd_session_native.h"

typedef struct m11_entry m11_entry;

/* One B5 teardown step (P4: Run23's whole sequence, helpers included):
 *  JOB    spawner command `index` with argument `arg`, never killed; status 0 required;
 *  CHECK  `arg` must be a regular file reading "1\n" (Run23 logger.done / pd.done);
 *  CREATE marker `arg` made O_EXCL with "1\n" (Run23 pd.stop);
 *  REAP   helper_pids[slot] must exit with status 0 within deadline_ms (never killed; a timeout,
 *         a signal or a non-zero status is a failure);
 *  RESULT spawner command `index` with the boot's result as its argument ("green" after the orderly
 *         end, "cyan" after a pre-bind failure: Run23's checkpoint colours), as JOB otherwise. */
enum { M11_TD_JOB, M11_TD_CHECK, M11_TD_CREATE, M11_TD_REAP, M11_TD_RESULT };
typedef struct { int kind; const char *arg; uint32_t deadline_ms; unsigned index, slot; } m11_entry_job;
#define M11_ENTRY_HELPERS 2u /* P4: 0 the PD locator (m11-pd-mapper), 1 the kmsg relay */

typedef struct {
    m11_boot_config boot;            /* P2 (production: m11_boot_config_default + the control job) */
    const m11_qrtr_sys *qrtr;        /* NULL = m11_qrtr_libc */
    uint32_t pd_ready_budget_ms;     /* 1..10000 */
    const char *cmdline_path;        /* "/proc/cmdline" */
    const char *journal_path;        /* "/dev/kmsg" */
    int journal_require_kmsg;        /* production 1: the journal fd must be char 1:11 */
    int require_pid1;                /* production 1 */
    unsigned pool_count;
    size_t pool_len;
    int pool_base;
    const m11_shmem_native_sys *sys; /* NULL = libc */
    uint32_t timeout_ms, recovery_budget_ms, hold_idle_ms;
    uint16_t src_port;
    uint64_t boot_epoch;             /* 0 = derived at entry (getrandom, else CLOCK_BOOTTIME) */
    m11_terminal_ops terminal_ops;   /* production: m11_terminal_ops_default + hold_fn (pause forever);
                                      * its teardown_fn is ignored: the entry supplies its own */
    /* B5 teardown (orderly never-mapped end only): PD listener retired, one record, then the steps
     * in order, the spawner stopped. Production (P4): Run23's sequence - seal, reap the relay, its
     * logger.done, usb_stop, stop_adsp, pd.stop, reap the locator, its pd.done, common, the green
     * checkpoint, unmount. 0 steps: no teardown (the orderly end reboots after its record). */
    const m11_entry_job *teardown_jobs;
    unsigned teardown_count;
    unsigned seal_count;             /* R1/D2: the leading steps that seal the evidence (production 3:
                                      * seal, the relay reaped, logger.done); 1..teardown_count */
    uint32_t seal_settle_ms;         /* E-1 (docs/m11-argon-pstore-review.md): the least time between
                                      * the last record and the first step, so the relay (10 ms rounds,
                                      * no kmsg read after the seal's logger.stop) ships that record;
                                      * production 100, at most 1000 */
    pid_t helper_pids[M11_ENTRY_HELPERS]; /* P4 environment helpers (0: none; a REAP of it fails) */
    uint32_t pd_retire_budget_ms;    /* 1..2000 */
    const char *proc_root;           /* NULL = "/proc" (runner tree census) */
    int (*session_fn)(void *user, m11_entry *); /* NULL in production: never maps */
    void *session_user;
} m11_entry_config;

/* phases (the last one completed) */
enum { M11_ENTRY_NONE, M11_ENTRY_JOURNAL, M11_ENTRY_CMDLINE, M11_ENTRY_PD_UP, M11_ENTRY_BOOT,
       M11_ENTRY_RUNNER, M11_ENTRY_SESSION, M11_ENTRY_END };

struct m11_entry {
    m11_entry_config cfg;
    int phase, fail_step, fail_rc;
    int journal_fd;
    m11_intent_fd_sink jfd;
    m11_intent_sink sink;
    char cmdline[4096];
    uint64_t boot_epoch;
    m11_pdmon pdmon;
    m11_boot boot;
    m11_crunner runner;
    int session_rc, reboot_rc;
    int teardown_step, teardown_rc;  /* B5: last step reached (0 retire, 1..n steps, n+1 spawner stop) */
    int steps_started;               /* R1/D2: the steps (the seal first) have started in this boot */
    int seal_rc;                     /* D2: the pre-exit seal (0, or the failed step's -errno) */
    const char *result;              /* the RESULT checkpoint argument */
    uint64_t last_record_ms;         /* E-1: when the last entry record was written (0: none) */
    uint64_t settle_ms;              /* E-1: last record to the first step, as observed */
    unsigned hold_rounds;
    unsigned records, record_failures; /* entry records written / refused by the sink */
    char record[M11_INTENT_RECORD_MAX + 96];
};

m11_entry_config m11_entry_config_default(void);
/* B6/B3: the cmdline record body ("allowed=%d len=%zu strict=%s passthrough=%s crc32=%08x"; the gate
 * verdict, the last iommu.strict= / iommu.passthrough= token values sanitized or absent/empty, the
 * length and CRC-32 of the text; never the text). Returns the verdict. The CRC is local evidence only:
 * over a text with one short unknown field (the serial) it can be inverted, so it is never committed
 * or exported. scripts/m11/anchor-native/cmdline_summary.py computes the same body off-device. */
int m11_entry_cmdline_summary(const char *cmdline, char *out, size_t cap);
uint64_t m11_entry_now_ms(void); /* CLOCK_MONOTONIC ms: the clock every phase uses */
/* -EINVAL (bad configuration) and -EPERM (not PID1) touch nothing and do not count as the one call;
 * -EALREADY on any later call. Otherwise it does not return unless exit_fn or reboot_fn returns
 * (-EFAULT): every end goes through exit_fn (retaining) or the G8 orderly reboot. */
int m11_entry_run(m11_entry *, const m11_entry_config *);

#endif
