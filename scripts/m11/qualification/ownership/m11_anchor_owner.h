#ifndef M11_ANCHOR_OWNER_H
#define M11_ANCHOR_OWNER_H
/*
 * Owner-side (PID1) enforcement of the anchor integration rules. Offline qualification ONLY:
 * not wired to the native runner; the Linux backend still refuses the real endpoint path.
 *
 *  P1  no CLONE_FILES or thread peer of the owner      seal: clone(CLONE_FILES|CLONE_THREAD),
 *                                                       clone3 refused
 *  P2  the owner never execs after the bind             seal: execve/execveat refused
 *  P3  nothing closes or replaces a reserved number     seal: close/dup/dup2/dup3 onto it,
 *      except the one final close                       fcntl F_DUPFD, F_DUPFD_CLOEXEC and
 *                                                       F_SETFD on it, and every close_range
 *                                                       except (anchor, guard, 0)
 *  P4  no hidden reference from the owner               seal: sendmsg/sendmmsg, io_uring,
 *                                                       pidfd_getfd, ptrace, process_vm_*
 *  P5  no second opener                                 seal: the node path is unlinked, the
 *                                                       owner is non-dumpable and cannot mknod;
 *                                                       jobs run from a spawner forked BEFORE the
 *                                                       bind (it never holds the endpoint) without
 *                                                       CAP_MKNOD, CAP_SYS_PTRACE and
 *                                                       CAP_DAC_READ_SEARCH
 * The seal is a seccomp filter: irreversible, inherited by every later child of the owner
 * (the worker adds its own), and blind to paths, so P5 for the owner's own open(2) of
 * another path stays code discipline. A CAP_SYS_ADMIN job could still mount a filesystem
 * that already contains a matching node; the native jobs mount none.
 */
#include "m11_anchor_linux.h"

/* After a successful bind (guard == anchor + 1): unlink `node` (NULL keeps it), set
 * PR_SET_DUMPABLE 0 and NO_NEW_PRIVS, install the seal filter keyed to the two numbers, and
 * route the adapter's final close through close_range(anchor, guard, 0). 0 or -errno. */
int m11_anchor_owner_seal(m11_pid1_anchor *, const char *node);
/* The seal's two parts, exposed for tests: install the filter for (anchor, anchor + 1), and
 * remove the three job capabilities from the calling process (root only). */
int m11_anchor_owner_filter(int anchor_fd, int guard_fd);
int m11_anchor_owner_drop_job_caps(void);

typedef struct { int sock, pid; bool dropped; } m11_spawner;
/* Fork the spawner. As root it removes CAP_MKNOD, CAP_SYS_PTRACE and CAP_DAC_READ_SEARCH from
 * its bounding, permitted, effective, inheritable and ambient sets before serving anything;
 * require_drop fails the start when it cannot (non-root). commands[i] is a NULL-terminated
 * argv; the table is copied by fork, so the owner later sends only an index. */
int m11_spawner_start(m11_spawner *, const char *const *const *commands, unsigned count, bool require_drop);
/* Run commands[index] plus `arg` (NULL: none) with an empty environment, stdin/stdout on
 * /dev/null and stderr inherited; wait up to deadline_ms. 0 and *status (exit code, or 128+signal); -ETIMEDOUT when
 * killed at the deadline and reaped; -EINPROGRESS when unresolved (the spawner then refuses
 * further work); other -errno on protocol failure. */
int m11_spawner_run(m11_spawner *, unsigned index, const char *arg, unsigned deadline_ms, int *status);
/* M11_SPAWN_NO_KILL: never kill a job at its deadline (the native runner's rule for control
 * jobs that may be inside a device syscall); report -EINPROGRESS and leave it running. */
#define M11_SPAWN_NO_KILL 1u
int m11_spawner_run_flags(m11_spawner *, unsigned index, const char *arg, unsigned deadline_ms,
                          unsigned flags, int *status);
int m11_spawner_stop(m11_spawner *);
#endif
