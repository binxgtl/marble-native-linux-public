/* G4 (docs/m11-custodian-native-integration.md): PID1's /dev/dma_heap/system node for the G3
 * shmem backend. Built only in the reviewed M11_CUSTODIAN_NATIVE build; never part of a candidate.
 *
 * Rules (the endpoint and ION nodes' treatment, applied to the system heap):
 *  - metadata only from the kernel: <sys>/class/dma_heap/system/dev gives MAJ:MIN, the same
 *    number's <sys>/dev/char/MAJ:MIN/uevent must name DEVNAME=dma_heap/system, and /proc/devices
 *    must list exactly one "dma_heap" major, equal to MAJ (the minor is per heap, not assumed 0);
 *  - the node is made by PID1 before the seal (the seal refuses mknod), only where no node exists:
 *    a root 0600 character node with one link and the expected number, in a real directory;
 *  - it is opened once per process (one-shot latch; a second attempt is refused even after a
 *    failure), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NOCTTY, and the open file must be the inode
 *    just made; the node, and the directory if PID1 made it, are removed before success;
 *  - any failure removes whatever this call made and holds no fd;
 *  - census: PID1 holds the heap device only at the one heap fd (none before the open); any other
 *    process holds it nowhere.
 * The heap fd has no seal pair: dma-heap release has no DSP-side effect (each dma-buf keeps its own
 * file reference), so an early close costs allocation only, never backing already handed out.
 */
#ifndef M11_HEAP_NODE_NATIVE_H
#define M11_HEAP_NODE_NATIVE_H
#ifndef M11_CUSTODIAN_NATIVE
#error "heap_node_native requires the reviewed M11_CUSTODIAN_NATIVE build"
#endif
#include <sys/types.h>

typedef struct {
    const char *sys;            /* "/sys" */
    const char *proc_devices;   /* "/proc/devices" */
    const char *dev_dir;        /* "/dev/dma_heap" */
    const char *node;           /* "/dev/dma_heap/system" */
    int require_kernel_fs;      /* sys on sysfs, proc_devices on procfs (production 1) */
    int require_root;           /* node and directory owned by uid/gid 0 (production 1) */
} m11_heap_node_paths;

/* The production paths, with both requirements set. */
m11_heap_node_paths m11_heap_node_paths_default(void);

typedef struct {
    int fd;          /* -1 unless held */
    dev_t rdev;
    pid_t owner_pid;
} m11_heap_node;

/* Kernel metadata for the system heap. 0 and *out set, or a negative errno. */
int m11_heap_meta(const m11_heap_node_paths *, dev_t *out);
/* One-shot: make, verify, open and remove the node. 0 with out->fd held, or a negative errno
 * with out->fd == -1 and nothing left behind. */
int m11_heap_node_open(const m11_heap_node_paths *, dev_t rdev, m11_heap_node *out);

/* Pure census rule: among `n` character-device fds of PID1 (`fds`, `rdevs`), those with device
 * number `rdev` must be exactly {heap_fd} when heap_fd >= 0, and none otherwise. 0 allowed, -1. */
int m11_census_pid1_heap(const int *fds, const unsigned long long *rdevs, unsigned n,
                         unsigned long long rdev, int heap_fd);
/* The rule applied to /proc/<pid>/fd: heap_fd = the one fd `pid` may hold (-1: none). -1 also on
 * any scan error (a racing close is inconclusive). */
int m11_heap_census_pid(pid_t pid, dev_t rdev, int heap_fd);

#endif
