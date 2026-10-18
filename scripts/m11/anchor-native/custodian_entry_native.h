/* Production P3 (docs/m11-custodian-native-integration.md): the PID1 entry of the native custodian.
 * It composes the P1 long-session PD monitor, the P2 boot sequence, the composed runner (G1-G8) and
 * the G8 terminal with production ops. Built only in the reviewed M11_CUSTODIAN_NATIVE build; never
 * part of a candidate; no frozen Run source is used or changed.
 *
 * m11_entry_run, in this order; any failure before the runner exists ends the boot through
 * exit_fn without closing anything (a START_FAILED record names the phase):
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
 *      leaves without a G8 end.
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
    m11_terminal_ops terminal_ops;   /* production: m11_terminal_ops_default */
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
    int session_rc;
    unsigned hold_rounds;
    char record[M11_INTENT_RECORD_MAX + 96];
};

m11_entry_config m11_entry_config_default(void);
uint64_t m11_entry_now_ms(void); /* CLOCK_MONOTONIC ms: the clock every phase uses */
/* -EINVAL (bad configuration) and -EPERM (not PID1) touch nothing and do not count as the one call;
 * -EALREADY on any later call. Otherwise it does not return unless exit_fn or reboot_fn returns
 * (-EFAULT): every end goes through exit_fn (retaining) or the G8 orderly reboot. */
int m11_entry_run(m11_entry *, const m11_entry_config *);

#endif
