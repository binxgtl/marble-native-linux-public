#ifndef M11_ANCHOR_LINUX_H
#define M11_ANCHOR_LINUX_H
/*
 * Linux backend for the PID1 anchor: real fork/exec/exit/fd semantics. In the offline build
 * it is bound to STAND-IN character devices only (/dev/ptmx, /dev/pts/ptmx, /dev/null, or a
 * private c 5:2 / c 1:3 node) and refuses every other path, including /dev/aud_pasthru_adsp and
 * /dev/msm_audio_ion. Only the native integration build (M11_ANCHOR_NATIVE) also admits the
 * exact path /dev/aud_pasthru_adsp; ION and ALSA paths stay refused in both builds. The R2
 * build (M11_ANCHOR_NATIVE plus M11_ANCHOR_NATIVE_ION) also admits /dev/msm_audio_ion for the
 * PID1 ION anchor; /dev/msm_audio_ion_cma and ALSA paths stay refused in every build.
 */
#include "m11_pid1_anchor.h"

typedef struct {
    const char *path;
    int census_root; /* >0: that process and its descendants only (tests); 0: every process,
                        and any unreadable process makes the census fail closed */
} m11_anchor_linux;

int m11_anchor_linux_ops(m11_anchor_linux *, const char *path, int census_root, m11_anchor_ops *out);
/* Runs in the forked, confined worker on the borrowed fd; nonzero = failure. It must not
 * close the borrowed fd (returning the loan is exiting). */
typedef int (*m11_anchor_work)(int fd, void *arg);
/* Reserve the loan and fork (never CLONE_FILES). The worker refuses a shared fd table,
 * accepts the fd, closes every inherited fd except stdio, the borrowed fd and `keep`, drops
 * privileges when root, then sets NO_NEW_PRIVS and a seccomp denylist (no open, mknod, exec,
 * sendmsg/SCM_RIGHTS, io_uring, pidfd_getfd, fork/clone, ptrace, process_vm_*, reboot)
 * before running `work`. The parent waits up to deadline_ms, SIGKILLs, waits up to grace_ms
 * and ends the loan. Returns the adapter's lend_end() result; *end says how it ended. */
int m11_anchor_linux_lend(m11_pid1_anchor *, m11_anchor_work, void *arg, const int *keep, unsigned nkeep,
                          unsigned deadline_ms, unsigned grace_ms, m11_worker_end *end);
/* kcmp(KCMP_FILES) of the caller and its parent: 1 shared, 0 not, negative errno unknown. */
int m11_anchor_linux_fd_table_shared(void);
/* Worker steps, exposed for tests: close every fd except stdio, `borrowed` and `keep`; set
 * NO_NEW_PRIVS and install the seccomp denylist. 0 on success. */
int m11_anchor_linux_close_unlisted(int borrowed, const int *keep, unsigned nkeep);
int m11_anchor_linux_worker_hygiene(int borrowed, int guard, const int *keep, unsigned nkeep);
/* uid/gid 65534, no supplementary groups or capabilities, NO_NEW_PRIVS (root only). */
int m11_anchor_linux_drop_privileges(void);
int m11_anchor_linux_confine(void);
/* Worker exit codes, for tests. */
enum { M11_WORKER_EXIT_ACCEPT = 90, M11_WORKER_EXIT_PRIVILEGE = 91, M11_WORKER_EXIT_WORK = 92,
       M11_WORKER_EXIT_HYGIENE = 94, M11_WORKER_EXIT_CONFINE = 95 };
#endif
