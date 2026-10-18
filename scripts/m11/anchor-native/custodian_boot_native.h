/* Production P2 (docs/m11-custodian-native-integration.md): the PID1 boot sequence that hands the
 * composed runner its sealed anchors and heap fd. Built only in the reviewed M11_CUSTODIAN_NATIVE
 * build; never part of a candidate; the frozen Run sources are not used or changed.
 *
 * m11_boot_run, in this order, refusing at the first failure:
 *   1. the spawner is forked before any node exists or any device is opened (it never holds one;
 *      post-seal jobs run there);
 *   2. the PD must be UP (the G6 monitor pumps 1) before the endpoint's only open;
 *   3. endpoint: metadata from the kernel only (class dev "MAJ:MIN\n", minor 0 in production, the
 *      number's uevent DEVNAME, exactly one matching /proc/devices major), a root 0600 node made
 *      where none exists, then the anchor bind (identity, holders, the guard pair);
 *   4. ION: the same, and its CMA twin must have metadata but NO node;
 *   5. the system-heap node (G4: made, opened once, removed);
 *   6. the owner seal over both pairs, which unlinks both nodes; no audio node is left.
 * A failure never closes an anchor already bound (its release is the terminal's decision) and never
 * leaves a node behind: a node that was made is unlinked whether or not its bind happened.
 * `stage` is the last completed step; the caller ends a failed boot through the retaining path.
 */
#ifndef M11_CUSTODIAN_BOOT_NATIVE_H
#define M11_CUSTODIAN_BOOT_NATIVE_H
#ifndef M11_CUSTODIAN_NATIVE
#error "custodian_boot_native requires the reviewed M11_CUSTODIAN_NATIVE build"
#endif
#include "gpr_transport_native.h"
#include "heap_node_native.h"
#include "m11_anchor_owner.h"

typedef struct {
    const char *class_name;   /* <sys>/class/<class>/<class>/dev */
    const char *devname;      /* uevent DEVNAME and /proc/devices name */
    const char *node;         /* the /dev node PID1 makes (never made for the CMA twin) */
    int require_minor0;       /* production 1 (one cdev per class, minor 0) */
} m11_boot_cdev;

typedef struct {
    const char *sys;              /* "/sys" */
    const char *proc_devices;     /* "/proc/devices" */
    m11_boot_cdev endpoint, ion, ion_cma;
    m11_heap_node_paths heap;
    int require_root;             /* nodes root:root 0600 (production 1) */
    int census_root;              /* 0 production (every process); >0 tests (that process tree) */
    const char *const *const *spawner_commands;
    unsigned spawner_count;
    int spawner_require_drop;     /* production 1 */
} m11_boot_config;

m11_boot_config m11_boot_config_default(void);

typedef struct {
    int stage;                    /* 0..6 */
    m11_spawner spawner;
    m11_anchor_linux endpoint_backend, ion_backend;
    m11_pid1_anchor endpoint, ion;
    m11_heap_node heap;
    dev_t endpoint_rdev, ion_rdev, ion_cma_rdev;
} m11_boot;

/* Kernel metadata of one character device (step 3/4 rules). 0 and *out, or a negative errno. */
int m11_boot_cdev_meta(const m11_boot_config *, const m11_boot_cdev *, dev_t *out);
/* The sequence. 0, or a negative errno with the failing step in *step (1..6). */
int m11_boot_run(m11_boot *, const m11_boot_config *, const m11_pd_monitor *pd, uint64_t now_ms, int *step);

#endif
