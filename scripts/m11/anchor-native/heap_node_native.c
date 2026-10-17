/* G4 PID1 system-heap node — see heap_node_native.h. */
#define _GNU_SOURCE
#include "heap_node_native.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#define HEAP_DEVNAME "DEVNAME=dma_heap/system\n"
#define MAX_SCAN_FDS 1024

m11_heap_node_paths m11_heap_node_paths_default(void) {
    return (m11_heap_node_paths){.sys = "/sys", .proc_devices = "/proc/devices",
                                 .dev_dir = "/dev/dma_heap", .node = "/dev/dma_heap/system",
                                 .require_kernel_fs = 1, .require_root = 1};
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

static int fs_is(const char *path, unsigned long magic) {
    struct statfs fs;
    return !statfs(path, &fs) && (unsigned long)fs.f_type == magic;
}

/* Exactly one "dma_heap" line in the "Character devices:" section, and its major. */
static int dma_heap_major(const char *b, unsigned *out) {
    int in_char = 0, found = 0;
    for (const char *line = b; *line;) {
        const char *end = strchr(line, '\n');
        size_t len = end ? (size_t)(end - line) : strlen(line);
        char l[160];
        if (len >= sizeof l) return -ENODEV;
        memcpy(l, line, len); l[len] = 0;
        if (!strcmp(l, "Character devices:")) in_char = 1;
        else if (!len || !strcmp(l, "Block devices:")) in_char = 0;
        else {
            unsigned m; char name[128];
            if (sscanf(l, "%u %127s", &m, name) == 2 && !strcmp(name, "dma_heap")) {
                if (!in_char) return -ENODEV;
                found++; *out = m;
            }
        }
        if (!end) break;
        line = end + 1;
    }
    return found == 1 ? 0 : -ENODEV;
}

int m11_heap_meta(const m11_heap_node_paths *p, dev_t *out) {
    if (!p || !out || !p->sys || !p->proc_devices) return -EINVAL;
    *out = 0;
    if (p->require_kernel_fs && (!fs_is(p->sys, SYSFS_MAGIC) || !fs_is(p->proc_devices, PROC_SUPER_MAGIC)))
        return -EPERM;
    char path[512], b[4096], canon[32];
    unsigned maj, min, pmaj;
    int rc;
    snprintf(path, sizeof path, "%s/class/dma_heap/system/dev", p->sys);
    if ((rc = read_text(path, b, sizeof b))) return rc;
    if (sscanf(b, "%u:%u", &maj, &min) != 2 || !maj) return -ENODEV;
    snprintf(canon, sizeof canon, "%u:%u\n", maj, min);
    if (strcmp(b, canon)) return -ENODEV;   /* exactly "MAJ:MIN\n" */
    snprintf(path, sizeof path, "%s/dev/char/%u:%u/uevent", p->sys, maj, min);
    if ((rc = read_text(path, b, sizeof b))) return rc;
    if (strncmp(b, HEAP_DEVNAME, sizeof HEAP_DEVNAME - 1) && !strstr(b, "\n" HEAP_DEVNAME))
        return -ENODEV;
    if ((rc = read_text(p->proc_devices, b, sizeof b))) return rc;
    if ((rc = dma_heap_major(b, &pmaj))) return rc;
    if (pmaj != maj) return -ENODEV;
    *out = makedev(maj, min);
    return 0;
}

static int heap_attempted;

int m11_heap_node_open(const m11_heap_node_paths *p, dev_t rdev, m11_heap_node *out) {
    if (!out) return -EINVAL;
    *out = (m11_heap_node){.fd = -1, .rdev = 0, .owner_pid = 0};
    if (!p || !p->dev_dir || !p->node || !major(rdev)) return -EINVAL;
    if (heap_attempted) return -EALREADY;
    heap_attempted = 1;

    int fd = -1, made = 0, created = 0, rc;
    struct stat ln, dir, of;
    if (!lstat(p->node, &ln)) return -EEXIST;
    if (errno != ENOENT) return -errno;
    if (lstat(p->dev_dir, &dir)) {
        if (errno != ENOENT) return -errno;
        if (mkdir(p->dev_dir, 0700)) return -errno;
        created = 1;
        if (lstat(p->dev_dir, &dir)) { rc = -errno; goto fail; }
    }
    if (!S_ISDIR(dir.st_mode)) { rc = -ENOTDIR; goto fail; }
    if ((dir.st_mode & 022) || (p->require_root && (dir.st_uid || dir.st_gid))) { rc = -EPERM; goto fail; }
    if (mknod(p->node, S_IFCHR | 0600, rdev)) { rc = -errno; goto fail; }
    made = 1;
    if (lstat(p->node, &ln)) { rc = -errno; goto fail; }
    if (!S_ISCHR(ln.st_mode) || ln.st_rdev != rdev || (ln.st_mode & 07777) != 0600 || ln.st_nlink != 1 ||
        (p->require_root && (ln.st_uid || ln.st_gid))) { rc = -EIO; goto fail; }
    fd = open(p->node, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NOCTTY);
    if (fd < 0) { rc = -errno; goto fail; }
    if (fstat(fd, &of) || !S_ISCHR(of.st_mode) || of.st_rdev != rdev ||
        of.st_dev != ln.st_dev || of.st_ino != ln.st_ino) { rc = -EIO; goto fail; }
    if (unlink(p->node)) { rc = -errno; goto fail; }
    made = 0;
    if (!lstat(p->node, &ln) || errno != ENOENT) { rc = -EIO; goto fail; }
    if (created) {
        if (rmdir(p->dev_dir)) { rc = -errno; goto fail; }
        created = 0;
    }
    *out = (m11_heap_node){.fd = fd, .rdev = rdev, .owner_pid = getpid()};
    return 0;
fail:
    if (fd >= 0) close(fd);
    if (made) (void)unlink(p->node);
    if (created) (void)rmdir(p->dev_dir);
    return rc;
}

int m11_census_pid1_heap(const int *fds, const unsigned long long *rdevs, unsigned n,
                         unsigned long long rdev, int heap_fd) {
    int seen = 0;
    for (unsigned i = 0; i < n; i++) {
        if (rdevs[i] != rdev) continue;
        if (heap_fd >= 0 && fds[i] == heap_fd && !seen) seen = 1;
        else return -1;   /* a second heap fd, a repeated number, or one before the open */
    }
    return heap_fd < 0 || seen ? 0 : -1;
}

int m11_heap_census_pid(pid_t pid, dev_t rdev, int heap_fd) {
    int fds[MAX_SCAN_FDS];
    unsigned long long rdevs[MAX_SCAN_FDS];
    char path[64], item[96];
    snprintf(path, sizeof path, "/proc/%ld/fd", (long)pid);
    DIR *d = opendir(path);
    if (!d) return -1;
    unsigned n = 0;
    int ok = 1;
    for (;;) {
        errno = 0;
        struct dirent *e = readdir(d);
        if (!e) { if (errno) ok = 0; break; }
        char *end;
        long v = strtol(e->d_name, &end, 10);
        if (e->d_name[0] < '0' || e->d_name[0] > '9' || *end || v < 0) continue;
        if (n == MAX_SCAN_FDS) { ok = 0; break; }
        snprintf(item, sizeof item, "%s/%s", path, e->d_name);
        struct stat st;
        if (stat(item, &st)) { ok = 0; break; } /* a racing close is inconclusive: reject */
        if (!S_ISCHR(st.st_mode)) continue;
        fds[n] = (int)v; rdevs[n] = (unsigned long long)st.st_rdev; n++;
    }
    closedir(d);
    if (!ok) return -1;
    return m11_census_pid1_heap(fds, rdevs, n, (unsigned long long)rdev, heap_fd);
}
