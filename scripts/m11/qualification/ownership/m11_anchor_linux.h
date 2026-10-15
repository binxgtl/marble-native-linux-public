#ifndef M11_ANCHOR_LINUX_H
#define M11_ANCHOR_LINUX_H
/*
 * Offline Linux backend for the PID1 anchor: real fork/exec/exit/fd semantics, but bound to an
 * allowlisted STAND-IN character device only (/dev/ptmx, /dev/pts/ptmx, /dev/null). It refuses
 * every other path, including /dev/aud_pasthru_adsp and /dev/msm_audio_ion. Connecting it to the
 * real endpoint needs a separate review; it is not an integration.
 */
#include "m11_pid1_anchor.h"

typedef struct {
    const char *path;
    int census_root; /* >0: that process and its descendants only (tests); 0: every process,
                        and any unreadable process makes the census fail closed */
} m11_anchor_linux;

int m11_anchor_linux_ops(m11_anchor_linux *, const char *path, int census_root, m11_anchor_ops *out);
/* Runs in the forked worker on the borrowed fd; nonzero = failure. Must not open the node. */
typedef int (*m11_anchor_work)(int fd, void *arg);
/* Reserve the loan, fork, let the worker accept the fd (and drop privileges when running as
 * root), wait up to deadline_ms, SIGKILL, wait up to grace_ms, and end the loan. Returns the
 * adapter's lend_end() result; *end says how the worker ended. */
int m11_anchor_linux_lend(m11_pid1_anchor *, m11_anchor_work, void *arg, unsigned deadline_ms,
                          unsigned grace_ms, m11_worker_end *end);
#endif
