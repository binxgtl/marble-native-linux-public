/* Dedicated native PID1 engineering API; deliberately refuses stock Android.
 * Single thread, one query per boot, no ownership reset/retry API. */
#ifndef M11_AUDIO_RUNTIME_H
#define M11_AUDIO_RUNTIME_H
#include "audio_pd.h"
#include <sys/types.h>
struct m11_audio_runtime;
enum m11_audio_helper { M11_AUDIO_LOCATOR, M11_AUDIO_LOGGER };
struct m11_audio_status {
    int acquired, pd_started, admitted, finished, poisoned, retired;
    int resources_quiescent, notifier_cleanup_complete;
    pid_t unresolved_worker;
    pid_t owner_pid, helper_pid[2];
    uint64_t helper_start[2], helper_inode[2], helper_device[2];
    uint64_t endpoint_device, census_ns;
    unsigned char capture_nonce[16], image_sha256[32];
    uint32_t token;
    int permits_playback; /* always zero */
    struct m11_pd pd; /* bounded raw wire transcript; callbacks cleared in copy */
};
/* Must run in PID1 before starting ANY other userspace process; requires procfs,
 * initial PID namespace, tmpfs /run and root. The O_EXCL lease is never unlinked.
 * expected_device comes from validated current cdev sysfs metadata, not a
 * guessed/static major. Requires valid descriptors0/1/2 before acquisition. */
struct m11_audio_runtime *m11_audio_acquire(dev_t expected_device);
/* Candidate PID1 may acquire before ADSP creates its dynamic cdev. No endpoint
 * I/O is admitted until bind validates current sysfs/procfs and the RAM node. */
struct m11_audio_runtime *m11_audio_acquire_boot(void);
int m11_audio_bind_endpoint(struct m11_audio_runtime *, dev_t expected_device);
/* Optional trusted helpers only. Direct children, fixed executable inode,
 * uid/gid65534, no supplementary groups/capabilities, NoNewPrivs=1. Launcher
 * must sandbox them BEFORE enrollment and provision only their RAM paths.
 * Unknown processes/threads/fds deny endpoint admission. */
int m11_audio_enroll(struct m11_audio_runtime *, pid_t, enum m11_audio_helper);
/* Preferred helper creation: fixed executable/argv, empty environment, drop all
 * capabilities/groups, uid/gid65534 and NoNewPrivs before exec. log_fd must be
 * a caller-owned writable regular file on tmpfs. No arbitrary helper command.
 * Caller provisions helper RAM directories/device read permissions beforehand.
 * Failure poisons ownership; unresolved helper PID is reported in snapshot. */
pid_t m11_audio_spawn_helper(struct m11_audio_runtime *, enum m11_audio_helper, int log_fd);
/* Active QRTR lookup + QMI listener registration, up to5000ms. NOT rproc boot.
 * Pinned instance74/path audio_pd; locator stays alive until ADSP later stops. */
int m11_audio_start_pd(struct m11_audio_runtime *, unsigned int budget_ms);
/* Must be pumped by PID1 while idle; query supervisor pumps automatically.
 * Every accepted session is terminal on DOWN/loss/error; never reconnects. */
int m11_audio_pump(struct m11_audio_runtime *);
/* After explicit endpoint close and normal worker reap, ACK deferred DOWN and
 * unregister listener, then remove lookup. Bounded2s; never stops ADSP/mapper.
 * Unresolved close/worker denies teardown, retains owner lease, no false ACK. */
int m11_audio_retire(struct m11_audio_runtime *);
int m11_audio_snapshot(const struct m11_audio_runtime *, struct m11_audio_status *);
/* Complete bounded JSON or -1/empty output; no file/USB I/O. Qualification
 * stays UNKNOWN and permissions false, even when every software gate passes. */
int m11_audio_status_encode(const struct m11_audio_status *, char *, size_t);
#endif
