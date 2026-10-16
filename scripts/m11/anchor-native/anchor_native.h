/* Native integration hooks of the PID1 endpoint anchor (R1, rules P1-P5). Engineering source:
 * not a candidate, not staged, not hardware-qualified. Built only with M11_ANCHOR_NATIVE. */
#ifndef M11_ANCHOR_NATIVE_H
#define M11_ANCHOR_NATIVE_H
#include "audio_runtime.h"
#include "gpr_native.h"
#include "m11_anchor_owner.h"

/* GPR layer: every query borrows this anchor (fork loan) instead of opening the endpoint.
 * `keep` lists extra fds the confined worker keeps (the runner's kmsg diagnostic fd). Without
 * an attached anchor every query is refused. */
int m11_gpr_anchor_attach(m11_pid1_anchor *, const int *keep, unsigned nkeep);
/* Raw wait status of the last reaped query worker (journaled by the runner), -1 if none. */
int m11_gpr_last_worker_status(void);

/* Runtime census: PID1 may hold the endpoint only at the anchor's two numbers, and the
 * pre-bind spawner (root, capability-reduced, never holding the endpoint) is the one
 * admitted non-helper process. Admission checks the sealed anchor instead of the node path,
 * which the seal unlinks. */
int m11_audio_attach_spawner(struct m11_audio_runtime *, pid_t spawner);
int m11_audio_attach_anchor(struct m11_audio_runtime *, m11_pid1_anchor *);

/* R2 (docs/m11-r2-ion-ownership.md): /dev/msm_audio_ion gets the endpoint's treatment. PID1
 * makes its node after the endpoint bind (bind_ion checks sysfs DEVNAME, a root 0600 node with
 * one link, and that msm_audio_ion_cma has NO node); every census then also requires that PID1
 * holds the ION device only as its ION anchor pair (none before the attach), that the CMA twin
 * has no holder at all, and that helpers and the spawner hold neither. Both sealed anchors are
 * attached together; admission checks both. */
int m11_audio_bind_ion(struct m11_audio_runtime *, dev_t ion, dev_t ion_cma);
int m11_audio_attach_anchors(struct m11_audio_runtime *, m11_pid1_anchor *endpoint, m11_pid1_anchor *ion);
/* GPR layer: the query worker inherits PID1's fd table by fork; before its fd hygiene it drops
 * the ION anchor pair with the one close the inherited seal permits for it,
 * close_range(anchor, guard, 0). PID1 still holds both, so this is never a last close, and
 * the worker then holds no ION reference. */
int m11_gpr_anchor_attach_ion(const m11_pid1_anchor *);

/* Pure census rule, exposed for tests: the endpoint fds (device number `rdev`) that PID1
 * holds must be exactly {anchor_fd, guard_fd} when an anchor is attached (anchor_fd >= 0), and
 * none otherwise. `fds`/`rdevs` describe PID1's character-device fds. 0 allowed, -1 refused. */
int m11_census_pid1_endpoint(const int *fds, const unsigned long long *rdevs, unsigned n,
                             unsigned long long rdev, int anchor_fd, int guard_fd);
#endif
