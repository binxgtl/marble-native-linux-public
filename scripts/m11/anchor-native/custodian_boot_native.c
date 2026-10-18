/* Production P2 PID1 boot sequence — see custodian_boot_native.h. */
#define _GNU_SOURCE
#include "custodian_boot_native.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#define FAIL(n, rc) do { if (step) *step = (n); return (rc); } while (0)

static int boot_started_once;

static const m11_anchor_contract evidence = {.endpoint_has_no_flush = true,
    .release_on_last_fput_only = true, .owner_single_threaded = true};

m11_boot_config m11_boot_config_default(void) {
    return (m11_boot_config){
        .sys = "/sys", .proc_devices = "/proc/devices",
        .endpoint = {"aud_pasthru_adsp", "aud_pasthru_adsp", "/dev/aud_pasthru_adsp", 1},
        .ion = {"msm_audio_ion", "msm_audio_ion", "/dev/msm_audio_ion", 1},
        .ion_cma = {"msm_audio_ion_cma", "msm_audio_ion_cma", "/dev/msm_audio_ion_cma", 1},
        .heap = m11_heap_node_paths_default(), .require_root = 1, .census_root = 0,
        .spawner_commands = NULL, .spawner_count = 0, .spawner_require_drop = 1};
}

static int read_text(const char *path, char *b, size_t cap) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -errno;
    size_t n = 0;
    for (;;) {
        if (n + 1 >= cap) { close(fd); return -EFBIG; }
        ssize_t r = read(fd, b + n, cap - 1 - n);
        if (r < 0) { if (errno == EINTR) continue; int e = -errno; close(fd); return e; }
        if (r == 0) break;
        n += (size_t)r;
    }
    close(fd);
    b[n] = 0;
    return 0;
}

int m11_boot_cdev_meta(const m11_boot_config *c, const m11_boot_cdev *d, dev_t *out) {
    if (!c || !d || !out || !d->class_name || !d->devname) return -EINVAL;
    *out = 0;
    char path[512], b[4096], canon[32], line[160];
    unsigned maj, min;
    int rc;
    snprintf(path, sizeof path, "%s/class/%s/%s/dev", c->sys, d->class_name, d->class_name);
    if ((rc = read_text(path, b, sizeof b))) return rc;
    if (sscanf(b, "%u:%u", &maj, &min) != 2 || !maj || (d->require_minor0 && min)) return -ENODEV;
    snprintf(canon, sizeof canon, "%u:%u\n", maj, min);
    if (strcmp(b, canon)) return -ENODEV;                        /* exactly "MAJ:MIN\n" */
    snprintf(path, sizeof path, "%s/dev/char/%u:%u/uevent", c->sys, maj, min);
    if ((rc = read_text(path, b, sizeof b))) return rc;
    char nl[sizeof line + 2];
    snprintf(line, sizeof line, "DEVNAME=%s\n", d->devname);
    snprintf(nl, sizeof nl, "\n%s", line);
    if (strncmp(b, line, strlen(line)) && !strstr(b, nl)) return -ENODEV; /* the number names this device */
    if ((rc = read_text(c->proc_devices, b, sizeof b))) return rc;
    int in_char = 0, found = 0;
    for (char *l = b; *l;) {
        char *e = strchr(l, '\n');
        if (e) *e = 0;
        if (!strcmp(l, "Character devices:")) in_char = 1;
        else if (!*l || !strcmp(l, "Block devices:")) in_char = 0;
        else { unsigned m; char name[128];
               if (in_char && sscanf(l, "%u %127s", &m, name) == 2 && !strcmp(name, d->devname)) found += m == maj ? 1 : 100; }
        if (!e) break;
        l = e + 1;
    }
    if (found != 1) return -ENODEV;                              /* exactly one, and with this major */
    *out = makedev(maj, min);
    return 0;
}

/* A node only where none exists, then verified as made: char, the number, 0600, one link, root. */
static int make_node(const m11_boot_config *c, const char *node, dev_t rdev) {
    struct stat st;
    if (!lstat(node, &st)) return -EEXIST;
    if (errno != ENOENT) return -errno;
    if (mknod(node, S_IFCHR | 0600, rdev)) return -errno;
    if (lstat(node, &st) || !S_ISCHR(st.st_mode) || st.st_rdev != rdev || (st.st_mode & 07777) != 0600 ||
        st.st_nlink != 1 || (c->require_root && (st.st_uid || st.st_gid))) { (void)unlink(node); return -EIO; }
    return 0;
}

static int bind_anchor(const m11_boot_config *c, const char *node, dev_t rdev, m11_anchor_linux *be, m11_pid1_anchor *a) {
    m11_anchor_ops ops;
    int rc = m11_anchor_linux_ops(be, node, c->census_root, &ops);
    if (rc) return rc;
    int owner = c->census_root > 0 ? c->census_root : getpid();
    return m11_anchor_bind(a, &ops, NULL, &evidence, owner, (uint64_t)rdev);
}

int m11_boot_run(m11_boot *b, const m11_boot_config *c, const m11_pd_monitor *pd, uint64_t now_ms, int *step) {
    if (step) *step = 0;
    if (!b || !c || !pd || !pd->pump_fn || !c->endpoint.node || !c->ion.node || !c->ion_cma.node) return -EINVAL;
    /* One boot sequence per process: a second call must never wipe a struct that may hold the
     * spawner, bound or sealed anchors and the heap fd, whether or not the first call finished. */
    if (boot_started_once) return -EALREADY;
    boot_started_once = 1;
    memset(b, 0, sizeof *b);
    b->heap.fd = -1;
    int rc;
    /* 1. the spawner before any node or open */
    if ((rc = m11_spawner_start(&b->spawner, c->spawner_commands, c->spawner_count, c->spawner_require_drop != 0)))
        FAIL(1, rc);
    b->stage = 1;
    /* 2. the PD UP before the endpoint's only open */
    if (pd->pump_fn(pd->user, now_ms) != 1) FAIL(2, -ENETRESET);
    b->stage = 2;
    /* 3. endpoint */
    if ((rc = m11_boot_cdev_meta(c, &c->endpoint, &b->endpoint_rdev))) FAIL(3, rc);
    if ((rc = make_node(c, c->endpoint.node, b->endpoint_rdev))) FAIL(3, rc);
    if ((rc = bind_anchor(c, c->endpoint.node, b->endpoint_rdev, &b->endpoint_backend, &b->endpoint))) {
        (void)unlink(c->endpoint.node); /* nothing bound: no path may stay for a second opener */
        FAIL(3, rc);
    }
    b->stage = 3;
    /* 4. ION; its CMA twin must have metadata and no node */
    struct stat st;
    if ((rc = m11_boot_cdev_meta(c, &c->ion, &b->ion_rdev)) || (rc = m11_boot_cdev_meta(c, &c->ion_cma, &b->ion_cma_rdev)) ||
        (rc = b->ion_rdev == b->ion_cma_rdev || b->ion_rdev == b->endpoint_rdev || b->ion_cma_rdev == b->endpoint_rdev ? -ENODEV : 0) ||
        (rc = !lstat(c->ion_cma.node, &st) ? -EEXIST : errno == ENOENT ? 0 : -errno)) {
        (void)unlink(c->endpoint.node);
        FAIL(4, rc);
    }
    if ((rc = make_node(c, c->ion.node, b->ion_rdev))) { (void)unlink(c->endpoint.node); FAIL(4, rc); }
    if ((rc = bind_anchor(c, c->ion.node, b->ion_rdev, &b->ion_backend, &b->ion))) {
        (void)unlink(c->ion.node); (void)unlink(c->endpoint.node);
        FAIL(4, rc);
    }
    b->stage = 4;
    /* 5. the system-heap node (G4), before the seal refuses mknod */
    dev_t heap_rdev;
    if ((rc = m11_heap_meta(&c->heap, &heap_rdev)) || (rc = m11_heap_node_open(&c->heap, heap_rdev, &b->heap))) {
        (void)unlink(c->ion.node); (void)unlink(c->endpoint.node); /* nodes go; the anchors stay held */
        FAIL(5, rc);
    }
    b->stage = 5;
    /* 6. the owner seal over both pairs; it unlinks both nodes */
    m11_pid1_anchor *both[2] = {&b->endpoint, &b->ion};
    const char *const nodes[2] = {c->endpoint.node, c->ion.node};
    if ((rc = m11_anchor_owner_seal_pairs(both, nodes, 2))) {
        (void)unlink(c->ion.node); (void)unlink(c->endpoint.node);
        FAIL(6, rc);
    }
    if (!lstat(c->endpoint.node, &st) || !lstat(c->ion.node, &st)) FAIL(6, -EIO);
    b->stage = 6;
    return 0;
}
