/* G8 (docs/m11-custodian-native-integration.md): the native end of a custodian boot. Built only in
 * the reviewed M11_CUSTODIAN_NATIVE build; never part of a candidate.
 *
 * m11_terminal_native_end executes the custodian's terminal decision, nothing else:
 *  - HOLD / HOLD_RECONCILE: refused (-EBUSY); nothing is closed and the boot does not end;
 *  - ORDERLY_SHUTDOWN, only when reboot is permitted AND the ledger never attempted a DSP MAP:
 *    first EVERY anchor must be HELD and pass m11_anchor_check, or be legitimately finished
 *    (dropped without close error or hidden reference, or never bound); otherwise nothing is closed
 *    ("anchor_not_held"). Then each held anchor gets its one final close, m11_anchor_end_boot must
 *    say REBOOT for every anchor, a terminal record is written, and reboot_fn runs. A final close
 *    refused after an earlier one succeeded ends as "partial_final_close"; any failing step, or a
 *    reboot_fn that returns, falls through to the reset end below (never a retry);
 *  - RESET_RETAINING_ANCHORS / UNSAFE_LAST_CLOSE_OCCURRED (and every fall-through): no anchor,
 *    pool or heap fd is closed and reboot_fn is never called. Each anchor is marked RETAINED
 *    (m11_anchor_end_boot), the anchors and the dma-buf pool are checked still held (recorded, not
 *    gating), the terminal record is written (a sink failure never blocks the end), and exit_fn
 *    runs: in production PID1 _exit(0)s, the kernel panics before exit_files() and restarts
 *    without device_shutdown(). That path is source-INFERRED (pinned ACK); Run24, which would
 *    observe it, is HARDWARE NO-GO. /proc/sys/kernel/panic is read and recorded: 0 means the panic
 *    never restarts (the device hangs with every anchor still held).
 * The record also states the anchor fds actually still open (from the numbers captured before the
 * first close: the adapter forgets them after a refused close_pair while they stay open) and how
 * many custodian regions still own a dma-buf, and how many of those are sealed pool buffers: a
 * mapped buffer outside the pool is pinned only by its own fd, which nothing seals.
 */
#ifndef M11_TERMINAL_NATIVE_H
#define M11_TERMINAL_NATIVE_H
#ifndef M11_CUSTODIAN_NATIVE
#error "terminal_native requires the reviewed M11_CUSTODIAN_NATIVE build"
#endif
#include "intent_journal_native.h"
#include "dmabuf_pool_native.h"

typedef struct {
    void (*exit_fn)(void *user);   /* production: _exit(0) in PID1; must not return */
    int (*reboot_fn)(void *user);  /* production: reboot(RB_AUTOBOOT); returns only on failure */
    void *user;
    const char *panic_path;        /* production: "/proc/sys/kernel/panic" */
    /* B5 (readiness review): optional teardown between the orderly end's record and reboot_fn, run
     * only on that path (never mapped, every final close done, every anchor ended REBOOT). 0 lets
     * the reboot proceed; any failure calls hold_fn (Run23: a failed teardown step holds, with no
     * reboot and no exit). hold_fn is required whenever teardown_fn is set. */
    int (*teardown_fn)(void *user);
    void (*hold_fn)(void *user);   /* must not return in production */
} m11_terminal_ops;

typedef struct {
    m11_custodian *c;
    m11_pid1_anchor *anchors[2];   /* endpoint, ION */
    unsigned nanchors;
    const m11_dmabuf_pool *pool;   /* NULL: no pool */
    const m11_intent_sink *sink;   /* NULL: no record */
    m11_terminal_ops ops;
    /* Non-NULL: end retaining whatever the custodian decided (HOLD included), with this note. Set by
     * the composed runner after an ownership violation (a failed census): the custodian ledger is
     * left as it is (no fake taint), the end is forced conservative here. */
    const char *force_retain_note;
    /* what the last call did, for the caller's journal and tests */
    m11_terminal_action action;
    int orderly_failed, reboot_failed, sink_failed;
    int teardown_ran, teardown_rc; /* B5: teardown_fn called, and its result */
    unsigned anchors_held;
    unsigned regions, regions_in_pool; /* custodian regions still owning a dma-buf fd; of those, pool buffers */
    int pool_held, panic;          /* panic: INT_MIN when unreadable */
    int saved, saved_fd[2][2];     /* anchor/guard numbers captured before the first close */
    char record[M11_INTENT_RECORD_MAX + 160];
} m11_terminal_native;

/* Production ops: _exit(0), reboot(RB_AUTOBOOT), /proc/sys/kernel/panic. */
m11_terminal_ops m11_terminal_ops_default(void);
/* -EBUSY for HOLD/HOLD_RECONCILE, -EINVAL on bad input; otherwise does not return unless exit_fn
 * returns (then -EFAULT). */
int m11_terminal_native_end(m11_terminal_native *, uint64_t now_ms);

#endif
