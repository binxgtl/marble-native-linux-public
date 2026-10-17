/* G4 stand-in test: the system-heap node module over a fake sysfs/procfs tree and a scratch /dev
 * directory. Unprivileged it covers metadata, the census rule and scan, and every refusal; as root
 * (sudo in CI) it makes a real character node carrying /dev/full's number as the heap stand-in.
 * Every open runs in a fresh child: the open is one-shot per process. No dma-heap driver. */
#ifndef M11_CUSTODIAN_NATIVE
#error "test-heap-node-native.c builds only with M11_CUSTODIAN_NATIVE"
#endif
#define _GNU_SOURCE
#include "heap_node_native.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <unistd.h>

static char base[256], root[300];
static m11_heap_node_paths P;
static char p_sys[400], p_proc[400], p_dir[400], p_node[400], p_dev[400];

static void put(const char *rel, const char *text) {
    char path[512], dir[512];
    snprintf(path, sizeof path, "%s/%s", root, rel);
    snprintf(dir, sizeof dir, "%s", path);
    for (char *s = dir + strlen(root) + 1; (s = strchr(s, '/')); s++) { *s = 0; (void)mkdir(dir, 0755); *s = '/'; }
    if (!text) { assert(unlink(path) == 0 || errno == ENOENT); return; }
    FILE *f = fopen(path, "w"); assert(f);
    assert(fputs(text, f) >= 0 && fclose(f) == 0);
}
static int rm_one(const char *path, const struct stat *st, int flag, struct FTW *ftw) {
    (void)st; (void)flag; (void)ftw; return remove(path);
}
#define GOOD_DEV "1:7\n"
#define GOOD_UEVENT "MAJOR=1\nMINOR=7\nDEVNAME=dma_heap/system\n"
static const char XDEV[] = "XDEVNAME=dma_heap/system\n"; /* a prefixed key, not DEVNAME */
#define GOOD_PROC "Character devices:\n  1 mem\n  1 dma_heap\n 10 misc\n\nBlock devices:\n  7 loop\n"
static void fresh(void) {
    static unsigned seq;
    if (root[0]) (void)nftw(root, rm_one, 16, FTW_DEPTH | FTW_PHYS);
    snprintf(root, sizeof root, "%s/t%ld-%u", base, (long)getpid(), seq++); /* children too */
    assert(mkdir(root, 0700) == 0 && chmod(root, 0700) == 0);
    put("sys/class/dma_heap/system/dev", GOOD_DEV);
    put("sys/dev/char/1:7/uevent", GOOD_UEVENT);
    put("proc_devices", GOOD_PROC);
    snprintf(p_sys, sizeof p_sys, "%s/sys", root);
    snprintf(p_proc, sizeof p_proc, "%s/proc_devices", root);
    snprintf(p_dev, sizeof p_dev, "%s/dev", root);
    snprintf(p_dir, sizeof p_dir, "%s/dev/dma_heap", root);
    snprintf(p_node, sizeof p_node, "%s/dev/dma_heap/system", root);
    assert(mkdir(p_dev, 0755) == 0 && chmod(p_dev, 0755) == 0);
    P = (m11_heap_node_paths){.sys = p_sys, .proc_devices = p_proc, .dev_dir = p_dir, .node = p_node,
                              .require_kernel_fs = 0, .require_root = 0};
}
static int meta_rc(void) { dev_t d; return m11_heap_meta(&P, &d); }
static int meta_with_dev(const char *t) { fresh(); put("sys/class/dma_heap/system/dev", t); return meta_rc(); }
static int meta_with_uevent(const char *t) { fresh(); put("sys/dev/char/1:7/uevent", t); return meta_rc(); }
static int meta_with_proc(const char *t) { fresh(); put("proc_devices", t); return meta_rc(); }
static int absent(const char *path) { struct stat st; return lstat(path, &st) && errno == ENOENT; }

/* Run one case in a child (the open is one-shot per process); an assertion there aborts here too. */
static void in_child(void (*fn)(void)) {
    pid_t c = fork(); assert(c >= 0);
    if (c == 0) { fn(); _exit(0); }
    int st; assert(waitpid(c, &st, 0) == c);
    if (WIFSIGNALED(st) && WTERMSIG(st) == SIGABRT) abort();
    assert(WIFEXITED(st) && WEXITSTATUS(st) == 0);
}

static dev_t full_rdev(void) { struct stat st; assert(stat("/dev/full", &st) == 0 && S_ISCHR(st.st_mode)); return st.st_rdev; }

/* ---- open cases ---- */
static void case_existing_node(void) {
    m11_heap_node h;
    fresh(); assert(mkdir(p_dir, 0700) == 0); put("dev/dma_heap/system", "keep");
    assert(m11_heap_node_open(&P, full_rdev(), &h) == -EEXIST && h.fd == -1);
    struct stat st; assert(lstat(p_node, &st) == 0 && S_ISREG(st.st_mode) && st.st_size == 4);
}
static void case_symlinked_dir(void) {
    m11_heap_node h; char target[512];
    fresh(); snprintf(target, sizeof target, "%s/elsewhere", root);
    assert(mkdir(target, 0700) == 0 && symlink(target, p_dir) == 0);
    assert(m11_heap_node_open(&P, full_rdev(), &h) == -ENOTDIR && h.fd == -1);
    char inside[600]; snprintf(inside, sizeof inside, "%s/system", target);
    assert(absent(inside));
}
static void case_world_writable_dir(void) {
    m11_heap_node h;
    fresh(); assert(mkdir(p_dir, 0700) == 0 && chmod(p_dir, 0777) == 0);
    assert(m11_heap_node_open(&P, full_rdev(), &h) == -EPERM);
    assert(absent(p_node) && !absent(p_dir));
}
static void case_bad_args(void) {
    m11_heap_node h;
    fresh();
    assert(m11_heap_node_open(NULL, full_rdev(), &h) == -EINVAL && h.fd == -1);
    assert(m11_heap_node_open(&P, full_rdev(), NULL) == -EINVAL);
    assert(m11_heap_node_open(&P, makedev(0, 7), &h) == -EINVAL);
}
static void case_one_shot_after_failure(void) {
    m11_heap_node h;
    fresh(); assert(mkdir(p_dir, 0700) == 0); put("dev/dma_heap/system", "keep");
    assert(m11_heap_node_open(&P, full_rdev(), &h) == -EEXIST);
    put("dev/dma_heap/system", NULL);
    int second = m11_heap_node_open(&P, full_rdev(), &h);
    assert(second == -EALREADY && h.fd == -1 && absent(p_node));
}
static void case_unprivileged_mknod(void) {
    m11_heap_node h;
    fresh();
    assert(m11_heap_node_open(&P, full_rdev(), &h) == -EPERM && h.fd == -1);
    assert(absent(p_node) && absent(p_dir)); /* the directory the call made is gone again */
}
static void case_root_success(void) {
    m11_heap_node h; dev_t full = full_rdev();
    fresh(); P.require_root = 1;
    int rc = m11_heap_node_open(&P, full, &h);
    assert(rc == 0 && h.fd >= 0);
    struct stat st; assert(fstat(h.fd, &st) == 0 && S_ISCHR(st.st_mode) && st.st_rdev == full);
    assert((fcntl(h.fd, F_GETFD) & FD_CLOEXEC) && (fcntl(h.fd, F_GETFL) & O_ACCMODE) == O_RDONLY);
    assert(absent(p_node) && absent(p_dir) && h.owner_pid == getpid() && h.rdev == full);
    assert(m11_heap_census_pid(getpid(), full, h.fd) == 0);
    assert(m11_heap_node_open(&P, full, &h) == -EALREADY);
}
static void case_root_kept_dir(void) {
    m11_heap_node h;
    fresh(); P.require_root = 1; assert(mkdir(p_dir, 0700) == 0);
    assert(m11_heap_node_open(&P, full_rdev(), &h) == 0 && absent(p_node) && !absent(p_dir));
}
static void case_root_foreign_dir(void) {
    m11_heap_node h;
    fresh(); P.require_root = 1; assert(mkdir(p_dir, 0700) == 0 && chown(p_dir, 65534, 65534) == 0);
    assert(m11_heap_node_open(&P, full_rdev(), &h) == -EPERM && absent(p_node));
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    snprintf(base, sizeof base, "%s/m11-heap-XXXXXX", argc > 1 ? argv[1] : "/tmp");
    assert(mkdtemp(base));
    const int as_root = geteuid() == 0;
    dev_t full = full_rdev();

    /* 1. production paths. */
    m11_heap_node_paths d = m11_heap_node_paths_default();
    assert(!strcmp(d.sys, "/sys") && !strcmp(d.proc_devices, "/proc/devices") &&
           !strcmp(d.dev_dir, "/dev/dma_heap") && !strcmp(d.node, "/dev/dma_heap/system") &&
           d.require_kernel_fs == 1 && d.require_root == 1);
    dev_t host = 0; int host_rc = m11_heap_meta(&d, &host);
    printf("INFO host system heap metadata: rc=%d dev=%u:%u (not asserted)\n", host_rc, major(host), minor(host));
    printf("PASS default paths are the kernel's, with kernel-fs and root requirements\n");

    /* 2. metadata accepted. */
    fresh(); dev_t m = 0;
    assert(m11_heap_meta(&P, &m) == 0 && m == makedev(1, 7));
    printf("PASS metadata: exact MAJ:MIN, DEVNAME=dma_heap/system by number, one dma_heap character major\n");

    /* 3. metadata refused. */
    assert(meta_with_dev("0:7\n") == -ENODEV);
    assert(meta_with_dev(" 1:7\n") == -ENODEV);
    assert(meta_with_dev("1:7") == -ENODEV);
    assert(meta_with_uevent("MAJOR=1\nMINOR=7\nDEVNAME=dma_heap/qcom,system\n") == -ENODEV);
    assert(meta_with_uevent(XDEV) == -ENODEV);
    assert(meta_with_proc("Character devices:\n  1 dma_heap\n  1 dma_heap\n") == -ENODEV);
    assert(meta_with_proc("Character devices:\n  2 dma_heap\n") == -ENODEV);
    assert(meta_with_proc("Character devices:\n  1 mem\n\nBlock devices:\n  1 dma_heap\n") == -ENODEV);
    assert(meta_with_uevent(NULL) == -ENOENT);
    fresh(); P.require_kernel_fs = 1;
    assert(meta_rc() == -EPERM);
    printf("PASS metadata refused: zero major, padded or unterminated number, wrong or prefixed DEVNAME, "
           "duplicate/mismatched/block-only major, missing file, non-kernel filesystems\n");

    /* 4. census rule. */
    const unsigned long long H = 77, O = 78;
    int f1[] = {5}, f2[] = {5, 6}, f3[] = {5, 5}, f4[] = {5, 9};
    unsigned long long r1[] = {H}, r2[] = {H, H}, r4[] = {H, O};
    assert(m11_census_pid1_heap(f1, r1, 0, H, -1) == 0);
    assert(m11_census_pid1_heap(f1, r1, 1, H, -1) == -1);
    assert(m11_census_pid1_heap(f1, r1, 1, H, 5) == 0);
    assert(m11_census_pid1_heap(f2, r2, 2, H, 5) == -1);
    assert(m11_census_pid1_heap(f3, r2, 2, H, 5) == -1);
    assert(m11_census_pid1_heap(f1, r1, 0, H, 5) == -1);
    assert(m11_census_pid1_heap(f4, r4, 2, H, 5) == 0);
    printf("PASS census rule: exactly the heap fd once opened, none before\n");

    /* 5. census scan of /proc/<pid>/fd. */
    int x = open("/dev/full", O_RDONLY | O_CLOEXEC); assert(x >= 0);
    assert(m11_heap_census_pid(getpid(), full, x) == 0);
    assert(m11_heap_census_pid(getpid(), full, -1) == -1);
    int y = dup(x); assert(y >= 0);
    assert(m11_heap_census_pid(getpid(), full, x) == -1);
    close(y);
    int go[2], ack[2]; assert(pipe(go) == 0 && pipe(ack) == 0);
    pid_t c = fork(); assert(c >= 0);
    if (c == 0) { char b; if (read(go[0], &b, 1) != 1) _exit(1); close(x); _exit(write(ack[1], "k", 1) == 1 ? 0 : 1); }
    assert(m11_heap_census_pid(c, full, -1) == -1);   /* the child inherited the heap fd */
    char b; assert(write(go[1], "g", 1) == 1 && read(ack[0], &b, 1) == 1);
    assert(m11_heap_census_pid(c, full, -1) == 0);
    int st; assert(waitpid(c, &st, 0) == c && WIFEXITED(st) && WEXITSTATUS(st) == 0);
    close(x);
    printf("PASS census scan of /proc/<pid>/fd: self and a child holder\n");

    /* 6. refusals; 7. one-shot. */
    in_child(case_existing_node);
    in_child(case_symlinked_dir);
    in_child(case_world_writable_dir);
    in_child(case_bad_args);
    printf("PASS open refused: existing node, symlinked or world-writable directory, bad arguments; nothing made\n");
    in_child(case_one_shot_after_failure);
    printf("PASS open is one-shot: a second attempt is refused after a failure\n");

    if (!as_root) {
        in_child(case_unprivileged_mknod);
        printf("PASS unprivileged mknod fails cleanly: the directory the call made is removed\n");
    } else {
        in_child(case_root_success);
        printf("PASS root: node made, verified, opened O_RDONLY|O_CLOEXEC and removed with the directory it made; "
               "census holds exactly the heap fd; one-shot after success\n");
        in_child(case_root_kept_dir);
        in_child(case_root_foreign_dir);
        printf("PASS root: a pre-existing root directory is kept; a non-root directory is refused\n");
    }
    if (root[0]) (void)nftw(root, rm_one, 16, FTW_DEPTH | FTW_PHYS);
    (void)nftw(base, rm_one, 16, FTW_DEPTH | FTW_PHYS);
    printf("PASS G4 heap node (%s sections)\n", as_root ? "root" : "unprivileged");
    return 0;
}
