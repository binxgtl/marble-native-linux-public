#ifndef M11_ANCHOR_KERNEL_MODEL_H
#define M11_ANCHOR_KERNEL_MODEL_H
/*
 * Synthetic model of the pinned-ACK file lifetime rules the PID1 anchor relies on. Not a
 * kernel and not the driver. Modelled from pinned ACK b97c62c4:
 *   fork        dup_fd() takes a reference to every open file (fs/file.c:381)
 *   exec        do_close_on_exec() -> filp_close() for FD_CLOEXEC fds (fs/file.c:851)
 *   exit        exit_files() -> close_files() -> filp_close() (fs/file.c:408-428); global
 *               init panics before exit_files() (kernel/exit.c), so PID1 closes nothing
 *   close(2)    pick_file() consumes the number, then filp_close() (fs/file.c:691-699)
 *   filp_close  f_op->flush if present, then fput() (fs/open.c:1317-1335)
 *   fput        f_op->release only when the count reaches 0 (fs/file_table.c:280,335-337)
 * The endpoint file models audio_pkt_fops (static_audio_pkt_fops.py: no flush; release =
 * drain RX + CLOSE_ALL + global ION crash handler). endpoint_has_flush=true is a
 * counterfactual driver used only to show which precondition the anchor needs.
 */
#include "m11_pid1_anchor.h"

#define KM_PROCS 24
#define KM_FDS 600
#define KM_FILES 64
#define KM_ENDPOINT_RDEV 0x1ff00000ull /* synthetic devno */

typedef struct {
    bool used, endpoint, released;
    unsigned refs;
    int status_flags, opener_pid;
} km_file;
typedef struct {
    bool alive, dstate, privileged;
    int pid, ppid;
    short fd[KM_FDS]; /* file index + 1; 0 = free */
    bool cloexec[KM_FDS];
} km_proc;
typedef struct {
    km_file files[KM_FILES];
    km_proc procs[KM_PROCS];
    bool endpoint_has_flush, panicked;
    unsigned endpoint_opens;
    unsigned endpoint_releases; /* audio_pkt_release ran: CLOSE_ALL + global ION cleanup */
    unsigned endpoint_flushes;  /* driver code run by a NON-final close (counterfactual) */
    int last_released_file;
    int current;                /* process the injected ops act as */
    int next_pid;
    bool fail_holders, fail_dup;
} km_kernel;

void km_init(km_kernel *, bool endpoint_has_flush); /* process 0 = PID1, privileged */
int km_fork(km_kernel *, int parent);               /* child index, or -1 */
void km_exec(km_kernel *, int proc);
void km_exit(km_kernel *, int proc);
bool km_kill(km_kernel *, int proc);                /* false: D-state, still holds its fds */
int km_open(km_kernel *, int proc, bool endpoint);  /* fd, or -EACCES for an unprivileged endpoint open */
int km_close(km_kernel *, int proc, int fd);
int km_dup_min(km_kernel *, int proc, int fd, int min_fd);
int km_dup2(km_kernel *, int proc, int oldfd, int newfd);
void km_set_cloexec(km_kernel *, int proc, int fd, bool on);
int km_file_of(const km_kernel *, int proc, int fd);
unsigned km_refs_of(const km_kernel *, int file);
/* Live processes (other than PID1) that hold any reference to an endpoint OFD other than `file`. */
bool km_foreign_endpoint_ofd(const km_kernel *, int file);
m11_anchor_ops km_ops(km_kernel *);
#endif
