/* P4 item 1 (docs/m11-argon-p4-assembly.md): the PID1 environment phase that runs before the P3
 * entry, reproducing the Run23 runner's pre-owned path (the frozen Run23 runner is unchanged).
 * Built only in the reviewed M11_CUSTODIAN_NATIVE build; never part of a candidate by itself.
 *
 * m11_p4_env_run, in Run23's order, stopping at the first failure (the caller holds, as Run23 did:
 * nothing audio has been opened, but the ADSP, USB or the amplifiers may be in an unknown state):
 *   1. the prepare job (Run23: /m11/prepare, 90 s; it loads the closure, qcom_dma_heaps included);
 *   2. the control journal job (10 s);
 *   3. the helper log: a new regular file (O_EXCL, 0600), on tmpfs in production;
 *   4. the PD locator helper (Run23: /sbin/m11-pd-mapper --serve), its ready marker (5 s), then
 *      the control probe job (6 s);
 *   5. the kmsg relay helper (Run23: /sbin/m11-kmsg-relay), the helper log closed, its ready
 *      marker (5 s);
 *   6. the control start job (ADSP, 40 s), then usb_start (40 s);
 *   7. the amplifier gate job (60 s); its result marker must read "switches-disabled\n";
 *   8. the endpoint's kernel metadata within 30 s, then ION's and its CMA twin's within 5 s
 *      (read-only: P2 makes the nodes later, as Run23 polled before its binds).
 * Jobs are fork/exec of the shell with the script and one argument, never killed (a job past its
 * deadline is left running and the phase fails: the boot holds, as Run23 did). Helpers are checked
 * images (regular, executable ELF; root-owned and not group/other writable in production), started
 * with stdin on /dev/null, stdout/stderr on the helper log, no other fd, and (production) every
 * capability dropped, no new privileges, uid/gid 65534. Their pids go to the entry's teardown
 * (helper_pids: 0 locator, 1 relay). One compact "<5>M11P4" kmsg record per step, each through its
 * own open (no per-fd rate limit), best effort.
 */
#ifndef M11_P4_ENV_NATIVE_H
#define M11_P4_ENV_NATIVE_H
#ifndef M11_CUSTODIAN_NATIVE
#error "p4_env_native requires the reviewed M11_CUSTODIAN_NATIVE build"
#endif
#include "custodian_boot_native.h"
#include <stdint.h>
#include <sys/types.h>

typedef struct {
    const char *shell, *shell_argv0, *shell_arg; /* production "/bin/busybox", "busybox", "sh" */
    const char *prepare, *control;               /* "/m11/prepare", "/m11/control" */
    const char *helper_log;                      /* "/run/m11/helpers.log" */
    int helper_log_tmpfs;                        /* production 1 */
    const char *locator, *relay;                 /* "/sbin/m11-pd-mapper", "/sbin/m11-kmsg-relay" */
    int helper_images_root;                      /* production 1: root-owned, not g/o writable */
    int drop_helpers;                            /* production 1 */
    const char *locator_ready, *relay_ready;     /* "/run/m11/pd.endpoint", ".../logger.ready" */
    const char *amp_result;                      /* "/run/m11/amp-gate.result" */
    const char *kmsg;                            /* "/dev/kmsg"; NULL: no records */
    const m11_boot_config *boot;                 /* the metadata rules P2 applies */
    uint32_t prepare_ms, journal_ms, marker_ms, probe_ms, start_ms, usb_ms, amp_ms, endpoint_ms, ion_ms;
} m11_p4_env_config;

typedef struct {
    int step;              /* last completed step (0..8) */
    pid_t locator, relay;  /* the helpers (0 until started) */
    dev_t endpoint, ion, ion_cma;
} m11_p4_env;

m11_p4_env_config m11_p4_env_config_default(const m11_boot_config *boot);
/* 0, or a negative errno with the failing step in *step (1..8). One call per process. */
int m11_p4_env_run(m11_p4_env *, const m11_p4_env_config *, int *step);

#endif
