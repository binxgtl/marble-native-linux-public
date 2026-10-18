/* G8 (docs/m11-custodian-native-integration.md): the native end of a custodian boot. Built only in
 * the reviewed M11_CUSTODIAN_NATIVE build; never part of a candidate.
 *
 * m11_terminal_native_end executes the custodian's terminal decision, nothing else:
 *  - HOLD / HOLD_RECONCILE: refused (-EBUSY); nothing is closed and the boot does not end;
 *  - ORDERLY_SHUTDOWN, only when reboot is permitted AND the ledger never attempted a DSP MAP:
 *    each held anchor gets its one final close, m11_anchor_end_boot must then say REBOOT for every
 *    anchor, a terminal record is written, and reboot_fn runs. Any failing step, or a reboot_fn
 *    that returns, falls through to the reset end below (never a retry);
 *  - RESET_RETAINING_ANCHORS / UNSAFE_LAST_CLOSE_OCCURRED (and every fall-through): no anchor,
 *    pool or heap fd is closed and reboot_fn is never called. Each anchor is marked RETAINED
 *    (m11_anchor_end_boot), the anchors and the dma-buf pool are checked still held (recorded, not
 *    gating), the terminal record is written (a sink failure never blocks the end), and exit_fn
 *    runs: in production PID1 _exit(0)s, the kernel panics before exit_files() and restarts
 *    without device_shutdown(). That path is source-INFERRED (pinned ACK); Run24, which would
 *    observe it, is HARDWARE NO-GO. /proc/sys/kernel/panic is read and recorded: 0 means the panic
 *    never restarts (the device hangs with every anchor still held).
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
} m11_terminal_ops;

typedef struct {
    m11_custodian *c;
    m11_pid1_anchor *anchors[2];   /* endpoint, ION */
    unsigned nanchors;
    const m11_dmabuf_pool *pool;   /* NULL: no pool */
    const m11_intent_sink *sink;   /* NULL: no record */
    m11_terminal_ops ops;
    /* what the last call did, for the caller's journal and tests */
    m11_terminal_action action;
    int orderly_failed, reboot_failed, sink_failed;
    unsigned anchors_held;
    int pool_held, panic;          /* panic: INT_MIN when unreadable */
    char record[M11_INTENT_RECORD_MAX + 64];
} m11_terminal_native;

/* Production ops: _exit(0), reboot(RB_AUTOBOOT), /proc/sys/kernel/panic. */
m11_terminal_ops m11_terminal_ops_default(void);
/* -EBUSY for HOLD/HOLD_RECONCILE, -EINVAL on bad input; otherwise does not return unless exit_fn
 * returns (then -EFAULT). */
int m11_terminal_native_end(m11_terminal_native *, uint64_t now_ms);

#endif
