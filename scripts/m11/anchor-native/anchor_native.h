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

/* Runtime census: PID1 may hold the endpoint only at the anchor's two numbers, and the
 * pre-bind spawner (root, capability-reduced, never holding the endpoint) is the one
 * admitted non-helper process. Admission checks the sealed anchor instead of the node path,
 * which the seal unlinks. */
int m11_audio_attach_spawner(struct m11_audio_runtime *, pid_t spawner);
int m11_audio_attach_anchor(struct m11_audio_runtime *, m11_pid1_anchor *);

/* Pure census rule, exposed for tests: the endpoint fds (device number `rdev`) that PID1
 * holds must be exactly {anchor_fd, guard_fd} when an anchor is attached (anchor_fd >= 0), and
 * none otherwise. `fds`/`rdevs` describe PID1's character-device fds. 0 allowed, -1 refused. */
int m11_census_pid1_endpoint(const int *fds, const unsigned long long *rdevs, unsigned n,
                             unsigned long long rdev, int anchor_fd, int guard_fd);
#endif
