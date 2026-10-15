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
 *  - audio_pkt_release runs only from final_close(), which PID1 may call only when a census
 *    shows its own two fds are the ONLY holders (so that close is the last one), and only
 *    when the custodian allowed the endpoint close. Otherwise the boot ends with the
 *    anchor retained (PID1 exit: panic before exit_files(), no release).
 * Limits: user-space discipline, not kernel enforcement. A second open(2) creates a second
 * OFD whose own last close runs the global cleanup regardless of this anchor; the census
 * can detect another holder of the node but cannot tell OFDs apart.
 */
#ifndef M11_OWNERSHIP_OFFLINE
#error "PID1 anchor adapter requires explicitly offline qualification; device integration is BLOCKED"
#endif
#include "m11_custodian.h"
#include <stdbool.h>
#include <stdint.h>

#define M11_ANCHOR_API_REVISION 1
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
    void (*foreign_holder)(void *ctx); /* someone else holds the node: its own OFD's last close
                                          would run the global cleanup at an unknown time */
    void (*anchor_lost)(void *ctx, bool may_have_released);
} m11_anchor_sink;

typedef enum {
    M11_ANCHOR_UNBOUND = 0,
    M11_ANCHOR_HELD,     /* PID1 holds anchor + guard; no worker */
    M11_ANCHOR_LENT,     /* exactly one forked worker shares the anchor OFD */
    M11_ANCHOR_RELEASED, /* terminal: PID1 performed the single last close */
    M11_ANCHOR_RETAINED, /* terminal: never closed; the boot ends by PID1 exit */
    M11_ANCHOR_FAILED    /* bind failed; any descriptor it obtained is kept, never closed */
} m11_anchor_state;

enum { /* latched for the rest of the boot */
    M11_ANCHOR_LATCH_WORKER_ABNORMAL = 1u,
    M11_ANCHOR_LATCH_WORKER_UNRESOLVED = 2u,
    M11_ANCHOR_LATCH_FOREIGN_HOLDER = 4u,
    M11_ANCHOR_LATCH_FD_DISCIPLINE = 8u, /* anchor/guard missing, replaced or lost FD_CLOEXEC */
    M11_ANCHOR_LATCH_CENSUS_ERROR = 16u,
    M11_ANCHOR_LATCH_CLOSE_ERROR = 32u,
};
/* Every latch except an abnormal (reaped) worker refuses new loans and the final close. */
#define M11_ANCHOR_LATCH_REFUSE (~(uint32_t)M11_ANCHOR_LATCH_WORKER_ABNORMAL)

typedef enum { M11_WORKER_EXIT_OK, M11_WORKER_EXIT_ABNORMAL, M11_WORKER_UNRESOLVED } m11_worker_end;
typedef enum { M11_ANCHOR_END_REBOOT, M11_ANCHOR_END_PID1_EXIT } m11_anchor_end;

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
/* Worker side, after fork: validates the borrowed fd and drops the guard copy. Never opens. */
int m11_anchor_worker_accept(const m11_pid1_anchor *, int fd);
/* Owner only. The custodian's endpoint close maps here: allowed only when PID1's two fds
 * are the sole holders, so the second close is the last fput (audio_pkt_release). */
int m11_anchor_final_close(m11_pid1_anchor *);
/* How this boot may end, from the custodian decision. HOLD/HOLD_RECONCILE: -EBUSY.
 * Anything but a released anchor with ORDERLY_SHUTDOWN ends by PID1 exit, anchor retained. */
int m11_anchor_end_boot(m11_pid1_anchor *, m11_terminal_action, m11_anchor_end *);
const char *m11_anchor_state_name(m11_anchor_state);
#endif
