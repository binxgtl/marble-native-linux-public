#ifndef M11_PID1_ANCHOR_H
#define M11_PID1_ANCHOR_H
/*
 * PID1 ownership adapter for the GPR endpoint (R1). Qualification ONLY: it is not wired to
 * the native runner, the native GPR query worker or the native audio runtime, and its Linux
 * backend refuses the real endpoint path.
 *
 * Mechanism (design and evidence: the M11 PID1 anchor adapter document under docs/):
 *  - PID1 performs the boot's only open(2) of the endpoint and immediately holds TWO
 *    references to that one open file description (OFD): `anchor` and `guard`, both
 *    FD_CLOEXEC, at reserved high fd numbers. No single close(2) in PID1 is a last close.
 *  - A worker never opens. It inherits the anchor OFD by fork(2) (dup_fd() takes a
 *    reference), validates its identity, drops its guard copy, and does I/O on it.
 *  - The shipped audio_pkt_fops has no .flush (static_audio_pkt_fops.py), and pinned ACK
 *    runs f_op->release only on the last fput(). So a worker's close, exec or death (any
 *    signal) is a non-final close that runs no audio_pkt code: no CLOSE_ALL, no ION crash
 *    handler.
 *  - PID1 drops its two fds only in final_close(), only when a census shows them to be the
 *    only VISIBLE holders, and only when the custodian allowed the endpoint close. That is
 *    OWNER_FDS_DROPPED, not "release observed": a reference outside every fd table (an
 *    SCM_RIGHTS message in flight, an io_uring fixed file, a blocked syscall) keeps the OFD
 *    alive, and only an injected oracle can say whether the release ran. Otherwise the boot
 *    ends with the anchor retained (a live terminal hold, or PID1 exit; never a close).
 *  - A worker never closes the borrowed fd: returning the loan is exiting. Under a shared fd
 *    table (CLONE_FILES) an explicit close would close PID1's own number; exit does not.
 * Limits: user-space discipline, not kernel enforcement. A second open(2) creates a second
 * OFD whose own last close runs the global cleanup regardless of this anchor. The census sees
 * fd tables only; with kcmp(KCMP_FILE) it can tell OFDs apart, without it only nodes. Both
 * PID1 references live in one fd table: close_range(), dup2/dup3 onto both numbers, or a
 * PID1 self-exec (both are FD_CLOEXEC) remove them together. Those are integration rules.
 */
/* Two build modes. M11_OWNERSHIP_OFFLINE: qualification against stand-ins (default for every
 * test). M11_ANCHOR_NATIVE: the native integration build (scripts/m11/anchor-native/), which
 * links no custodian and lets the Linux backend name the real endpoint. Neither: refused. */
#if !defined(M11_OWNERSHIP_OFFLINE) && !defined(M11_ANCHOR_NATIVE)
#error "PID1 anchor adapter requires explicitly offline qualification; device integration is BLOCKED"
#endif
#if defined(M11_OWNERSHIP_OFFLINE)
#include "m11_custodian.h"
#else
/* Same names and values as m11_custodian.h (anchor-native/test.sh compares both builds). */
typedef enum {
    M11_TERMINAL_ORDERLY_SHUTDOWN = 0,
    M11_TERMINAL_HOLD,
    M11_TERMINAL_HOLD_RECONCILE,
    M11_TERMINAL_RESET_RETAINING_ANCHORS,
    M11_TERMINAL_UNSAFE_LAST_CLOSE_OCCURRED
} m11_terminal_action;
#include <stdbool.h>
#endif
#include <stdbool.h>
#include <stdint.h>

/* 1: one open, anchor + guard, loans by fork, census, sole-holder final close.
 * 2: OWNER_FDS_DROPPED replaces RELEASED, release oracle and HIDDEN_REFERENCE latch, kcmp
 *    OFD comparison in the census, shared-fd-table refusal in the worker, END_RETAIN.
 * 3: close_pair for a sealed owner; a worker keeps its guard copy when the seal refuses it. */
#define M11_ANCHOR_API_REVISION 3
#define M11_ANCHOR_RESERVED_FD 512
#define M11_ANCHOR_MAX_HOLDERS 16u

typedef struct { uint64_t dev, ino, rdev; uint32_t type; } m11_anchor_id; /* type = st_mode & S_IFMT */
typedef struct { int pid, fd; } m11_anchor_holder;

/* Injected dependencies. Each returns 0/fd or a negative errno. */
typedef struct {
    void *ctx;
    int (*self_pid)(void *ctx);
    int (*open_endpoint)(void *ctx);                       /* bind is the ONLY caller */
    int (*identify)(void *ctx, int fd, m11_anchor_id *out); /* fstat */
    int (*dup_min)(void *ctx, int fd, int min_fd);          /* F_DUPFD_CLOEXEC */
    int (*fd_flags)(void *ctx, int fd);                     /* F_GETFD */
    int (*status_flags)(void *ctx, int fd);                 /* F_GETFL */
    int (*close_fd)(void *ctx, int fd);                     /* never retried */
    /* Every (pid, fd) whose file has this identity. Any unreadable process is an error. */
    int (*holders)(void *ctx, const m11_anchor_id *, m11_anchor_holder *, unsigned cap, unsigned *n);
    /* Optional (NULL or -ENOSYS = unavailable). same_ofd: 1 same open file description,
     * 0 different (kcmp KCMP_FILE). fd_table_shared: 1 when the caller shares its fd table
     * with its parent (kcmp KCMP_FILES). release_oracle: 1 the last-reference consequence is
     * observable now, 0 it is not; no oracle exists for the real endpoint. */
    int (*same_ofd)(void *ctx, int pid_a, int fd_a, int pid_b, int fd_b);
    int (*fd_table_shared)(void *ctx);
    int (*release_oracle)(void *ctx);
    /* Optional: a sealed owner may close the reserved numbers only together, in this one call
     * (close_range(anchor, guard, 0)); every other close/dup/close_range over them is refused. */
    int (*close_pair)(void *ctx, int anchor_fd, int guard_fd);
} m11_anchor_ops;

/* Static facts the adapter cannot observe at run time; each must cite recorded evidence. */
typedef struct {
    bool endpoint_has_no_flush;     /* audio_pkt_fops.flush == NULL in the exact module */
    bool release_on_last_fput_only; /* pinned ACK fput_many()/__fput() */
    bool owner_single_threaded;     /* no thread or CLONE_FILES sharer of PID1's fd table */
} m11_anchor_contract;

/* Ledger events (custodian integration). Any callback may be NULL. */
typedef struct {
    void *ctx;
    void (*worker_lost)(void *ctx);    /* lent worker died abnormally or is unresolved */
    void (*foreign_holder)(void *ctx); /* someone else holds the node, or a hidden reference
                                          holds our OFD: a release at an unknown time */
    void (*anchor_lost)(void *ctx, bool may_have_released);
} m11_anchor_sink;

typedef enum {
    M11_ANCHOR_UNBOUND = 0,
    M11_ANCHOR_HELD,     /* PID1 holds anchor + guard; no worker */
    M11_ANCHOR_LENT,     /* exactly one forked worker shares the anchor OFD */
    M11_ANCHOR_OWNER_FDS_DROPPED, /* terminal: PID1 closed guard and anchor after the policy
                                     checks; says nothing by itself about the driver release */
    M11_ANCHOR_RETAINED, /* terminal: never closed; the boot ends retaining the anchor */
    M11_ANCHOR_FAILED    /* bind failed; any descriptor it obtained is kept, never closed */
} m11_anchor_state;

enum { /* latched for the rest of the boot */
    M11_ANCHOR_LATCH_WORKER_ABNORMAL = 1u,
    M11_ANCHOR_LATCH_WORKER_UNRESOLVED = 2u,
    M11_ANCHOR_LATCH_FOREIGN_HOLDER = 4u,
    M11_ANCHOR_LATCH_FD_DISCIPLINE = 8u, /* anchor/guard missing, replaced or lost FD_CLOEXEC */
    M11_ANCHOR_LATCH_CENSUS_ERROR = 16u,
    M11_ANCHOR_LATCH_CLOSE_ERROR = 32u,
    M11_ANCHOR_LATCH_SECOND_OFD = 64u,   /* kcmp: a holder of the node at ANOTHER OFD */
    M11_ANCHOR_LATCH_HIDDEN_REFERENCE = 128u, /* oracle: owner fds dropped, release not observed */
};
/* Every latch except an abnormal (reaped) worker refuses new loans and the final close. */
#define M11_ANCHOR_LATCH_REFUSE (~(uint32_t)M11_ANCHOR_LATCH_WORKER_ABNORMAL)

typedef enum { M11_WORKER_EXIT_OK, M11_WORKER_EXIT_ABNORMAL, M11_WORKER_UNRESOLVED } m11_worker_end;
/* RETAIN: never close, never reboot(2). A live terminal hold, or PID1 exit (global init
 * panics before exit_files()); which one is an integration decision. */
typedef enum { M11_ANCHOR_END_REBOOT, M11_ANCHOR_END_RETAIN } m11_anchor_end;
typedef enum { M11_RELEASE_UNKNOWN = 0, M11_RELEASE_OBSERVED, M11_RELEASE_NOT_OBSERVED } m11_release_evidence;

typedef struct {
    m11_anchor_ops ops;
    m11_anchor_sink sink;
    m11_anchor_contract contract;
    m11_anchor_state state;
    bool bind_attempted;
    int owner_pid, raw_fd, anchor_fd, guard_fd, status_flags;
    m11_anchor_id id;
    int lent_pid;            /* 0 while a loan is reserved but its fork is not reported */
    uint32_t latches;
    uint32_t opens, lends, final_closes;
    m11_release_evidence release;
} m11_pid1_anchor;

/* One-shot per boot, owner only (self_pid() == owner_pid; production passes 1). Requires a
 * character device with expected_rdev, opened O_RDWR|O_NONBLOCK. Never closes an fd it could
 * not validate: closing an unproven endpoint fd could itself be a last close. */
int m11_anchor_bind(m11_pid1_anchor *, const m11_anchor_ops *, const m11_anchor_sink *,
                    const m11_anchor_contract *, int owner_pid, uint64_t expected_rdev);
/* Owner only: both fds still the bound identity with FD_CLOEXEC; census of holders. */
int m11_anchor_check(m11_pid1_anchor *);
/* Owner only. Reserve the single loan; *fd is the number the forked worker must use. */
int m11_anchor_lend_begin(m11_pid1_anchor *, int *fd);
int m11_anchor_lend_started(m11_pid1_anchor *, int pid);
int m11_anchor_lend_abort(m11_pid1_anchor *); /* fork failed: no worker exists */
/* UNRESOLVED keeps the loan forever: the worker still holds a reference. */
int m11_anchor_lend_end(m11_pid1_anchor *, m11_worker_end);
/* Worker side, after fork (never CLONE_FILES): refuses a shared fd table, validates the
 * borrowed fd, drops the guard copy. Never opens; never closes the borrowed fd. */
int m11_anchor_worker_accept(const m11_pid1_anchor *, int fd);
/* Owner only. The custodian's endpoint close maps here: allowed only when PID1's two fds
 * are the sole VISIBLE holders. Ends in OWNER_FDS_DROPPED; `release` records the oracle. */
int m11_anchor_final_close(m11_pid1_anchor *);
/* How this boot may end, from the custodian decision. HOLD/HOLD_RECONCILE: -EBUSY.
 * REBOOT only for ORDERLY_SHUTDOWN after OWNER_FDS_DROPPED (or nothing opened) with no
 * hidden reference or close error; everything else is RETAIN. */
int m11_anchor_end_boot(m11_pid1_anchor *, m11_terminal_action, m11_anchor_end *);
const char *m11_anchor_state_name(m11_anchor_state);
#endif
