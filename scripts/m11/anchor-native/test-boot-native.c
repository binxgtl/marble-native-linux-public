/* Production P2 stand-in test: the PID1 boot sequence over a fake sysfs/procfs tree and a scratch /dev.
 * Stand-ins: the endpoint is the pty multiplexer's number (5:2), ION is null's (1:3), its CMA twin
 * zero's (1:5), the system heap full's (1:7); node names avoid the real device names (the Linux
 * anchor backend admits a private node only by its stand-in number). Unprivileged: metadata rules.
 * As root (sudo in CI): every refusal, then a full boot handed to the composed runner, which starts
 * (census over the spawner included) and ends orderly. Each root case runs in a child. No device. */
#ifndef M11_CUSTODIAN_NATIVE
#error "test-boot-native.c builds only with M11_CUSTODIAN_NATIVE"
#endif
#define _GNU_SOURCE
#include "custodian_boot_native.h"
#include "custodian_runner_native.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static char base[256], root[320];
static int in_case; /* set in a root case child, which has its own mount namespace */
static m11_boot_config C;
static char p_sys[400], p_proc[400], p_ep[400], p_ion[400], p_cma[400], p_hdir[400], p_hnode[400], p_dev[400];

static void put(const char *rel, const char *text) {
    char path[600], dir[600];
    snprintf(path, sizeof path, "%s/%s", root, rel);
    snprintf(dir, sizeof dir, "%s", path);
    for (char *s = dir + strlen(root) + 1; (s = strchr(s, '/')); s++) { *s = 0; (void)mkdir(dir, 0755); *s = '/'; }
    FILE *f = fopen(path, "w"); assert(f && fputs(text, f) >= 0 && fclose(f) == 0);
}
static const char *PROC_OK = "Character devices:\n  1 msm_audio_ion\n  1 msm_audio_ion_cma\n  1 dma_heap\n  5 aud_pasthru_adsp\n\nBlock devices:\n  7 loop\n";
static void tree(const char *ep_devname, const char *proc) {
    static unsigned seq;
    snprintf(root, sizeof root, "%s/t%ld-%u", base, (long)getpid(), seq++);
    assert(mkdir(root, 0700) == 0);
    put("sys/class/aud_pasthru_adsp/aud_pasthru_adsp/dev", "5:2\n");
    char ue[160]; snprintf(ue, sizeof ue, "MAJOR=5\nMINOR=2\nDEVNAME=%s\n", ep_devname);
    put("sys/dev/char/5:2/uevent", ue);
    put("sys/class/msm_audio_ion/msm_audio_ion/dev", "1:3\n");
    put("sys/dev/char/1:3/uevent", "MAJOR=1\nMINOR=3\nDEVNAME=msm_audio_ion\n");
    put("sys/class/msm_audio_ion_cma/msm_audio_ion_cma/dev", "1:5\n");
    put("sys/dev/char/1:5/uevent", "MAJOR=1\nMINOR=5\nDEVNAME=msm_audio_ion_cma\n");
    put("sys/class/dma_heap/system/dev", "1:7\n");
    put("sys/dev/char/1:7/uevent", "MAJOR=1\nMINOR=7\nDEVNAME=dma_heap/system\n");
    put("proc_devices", proc);
    snprintf(p_sys, sizeof p_sys, "%s/sys", root); snprintf(p_proc, sizeof p_proc, "%s/proc_devices", root);
    snprintf(p_dev, sizeof p_dev, "%s/dev", root); assert(mkdir(p_dev, 0755) == 0 && chmod(p_dev, 0755) == 0);
    if (in_case && geteuid() == 0) {
        /* A pty multiplexer node opens only next to a devpts "pts" (the kernel looks it up beside
         * the node); bind the real one in this case's private mount namespace. */
        char pts[460]; snprintf(pts, sizeof pts, "%s/pts", p_dev);
        assert(mkdir(pts, 0755) == 0 && mount("/dev/pts", pts, NULL, MS_BIND, NULL) == 0);
    }
    snprintf(p_ep, sizeof p_ep, "%s/dev/ep_node", root); snprintf(p_ion, sizeof p_ion, "%s/dev/ion_node", root);
    snprintf(p_cma, sizeof p_cma, "%s/dev/cma_node", root);
    snprintf(p_hdir, sizeof p_hdir, "%s/dev/heap", root); snprintf(p_hnode, sizeof p_hnode, "%s/dev/heap/system", root);
    static const char *const job[] = {"/bin/true", NULL};
    static const char *const *const jobs[] = {job};
    C = (m11_boot_config){.sys = p_sys, .proc_devices = p_proc,
        .endpoint = {"aud_pasthru_adsp", "aud_pasthru_adsp", p_ep, 0}, .ion = {"msm_audio_ion", "msm_audio_ion", p_ion, 0},
        .ion_cma = {"msm_audio_ion_cma", "msm_audio_ion_cma", p_cma, 0},
        .heap = {.sys = p_sys, .proc_devices = p_proc, .dev_dir = p_hdir, .node = p_hnode, .require_kernel_fs = 0, .require_root = 1},
        .require_root = 1, .census_root = getpid(), .spawner_commands = jobs, .spawner_count = 1, .spawner_require_drop = geteuid() == 0};
}
static int absent(const char *p) { struct stat st; return lstat(p, &st) && errno == ENOENT; }

/* ---- PD monitor stand-in ---- */
static int pd_state = 1, pd_pipe[2] = {-1, -1};
static int pump(void *u, uint64_t now) { (void)u; (void)now; return pd_state; }
static m11_pd_monitor pdm;
static void pd_init(int up) { pd_state = up; if (pd_pipe[0] < 0) assert(pipe2(pd_pipe, O_CLOEXEC) == 0); pdm = (m11_pd_monitor){pd_pipe[0], pump, NULL}; }

static void stdio_off_null(void) {
    for (int fd = 0; fd < 3; fd++) {
        struct stat st;
        if (fstat(fd, &st) || !S_ISCHR(st.st_mode) || st.st_rdev != makedev(1, 3)) continue;
        int p[2]; assert(!pipe(p)); assert(dup2(fd == 0 ? p[0] : p[1], fd) == fd); close(p[0]); close(p[1]);
    }
}
static uint64_t ms(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return (uint64_t)t.tv_sec * 1000u + (uint64_t)t.tv_nsec / 1000000u; }
static int report_fd = -1;
static void say(const char *s) { (void)!write(report_fd, s, strlen(s)); }

/* ---- root cases ---- */
static m11_boot B;
static void boot_report(int rc, int step) {
    char b[400];
    snprintf(b, sizeof b, "BOOT rc=%d step=%d stage=%d ep=%s ion=%s ep_node=%d ion_node=%d cma_node=%d heap_fd=%d heap_dir=%d sealed=%d spawner=%d\n",
             rc, step, B.stage, m11_anchor_state_name(B.endpoint.state), m11_anchor_state_name(B.ion.state),
             !absent(p_ep), !absent(p_ion), !absent(p_cma), B.heap.fd >= 0, !absent(p_hdir),
             B.endpoint.ops.close_pair != NULL && B.ion.ops.close_pair != NULL, B.spawner.pid > 0);
    say(b);
}
static void c_pd_down(void) { tree("aud_pasthru_adsp", PROC_OK); pd_init(0); int step; int rc = m11_boot_run(&B, &C, &pdm, ms(), &step); boot_report(rc, step); _exit(0); }
static void c_node_exists(void) {
    tree("aud_pasthru_adsp", PROC_OK); pd_init(1); put("dev/ep_node", "keep");
    int step; int rc = m11_boot_run(&B, &C, &pdm, ms(), &step); boot_report(rc, step);
    struct stat st; char b[64]; snprintf(b, sizeof b, "KEPT regular=%d\n", !lstat(p_ep, &st) && S_ISREG(st.st_mode)); say(b);
    _exit(0);
}
static void c_devname(void) { tree("something_else", PROC_OK); pd_init(1); int step; int rc = m11_boot_run(&B, &C, &pdm, ms(), &step); boot_report(rc, step); _exit(0); }
static void c_cma_node(void) {
    tree("aud_pasthru_adsp", PROC_OK); pd_init(1);
    assert(mknod(p_cma, S_IFCHR | 0600, makedev(1, 5)) == 0);
    int step; int rc = m11_boot_run(&B, &C, &pdm, ms(), &step); boot_report(rc, step); _exit(0);
}
static void c_heap_missing(void) {
    tree("aud_pasthru_adsp", "Character devices:\n  1 msm_audio_ion\n  1 msm_audio_ion_cma\n  5 aud_pasthru_adsp\n\n"); pd_init(1);
    int step; int rc = m11_boot_run(&B, &C, &pdm, ms(), &step); boot_report(rc, step); _exit(0);
}

/* the full boot, handed to the composed runner */
static int fx_heap = -1, fx_ion = -1;
static int fx_ioctl(int fd, unsigned long req, void *arg) {
    if (req == M11_DMA_HEAP_IOCTL_ALLOC) {
        m11_dma_heap_allocation_data *d = arg;
        if (fd != fx_heap) { errno = EBADF; return -1; }
        int m = memfd_create("m11-boot", MFD_CLOEXEC);
        if (m < 0 || ftruncate(m, (off_t)d->len)) return -1;
        d->fd = (uint32_t)m; return 0;
    }
    if (req == M11_MSM_AUDIO_ION_MAP_PHYS || req == M11_MSM_AUDIO_ION_UNMAP) return fd == fx_ion ? 0 : (errno = EBADF, -1);
    errno = ENOTTY; return -1;
}
static int fx_munmap(void *a, size_t l) { return munmap(a, l); }
static const m11_shmem_native_sys fx_sys = {fx_ioctl, mmap, fx_munmap, close};
static int sink_append(void *u, const char *rec, size_t n) { (void)u; (void)rec; (void)n; return 0; }
static const m11_intent_sink sink = {sink_append, NULL};
static m11_crunner R;
static void t_exit(void *u) { (void)u; char b[160]; snprintf(b, sizeof b, "END exit why=%u\n", R.census_why); say(b); _exit(42); }
static int t_reboot(void *u) {
    (void)u; char b[200];
    snprintf(b, sizeof b, "END reboot ep_fd_open=%d ion_fd_open=%d\n", fcntl(512, F_GETFD) != -1, fcntl(514, F_GETFD) != -1);
    say(b); _exit(43);
}
static void c_full(void) {
    tree("aud_pasthru_adsp", PROC_OK); pd_init(1);
    int step; int rc = m11_boot_run(&B, &C, &pdm, ms(), &step); boot_report(rc, step);
    if (rc) _exit(0);
    fx_heap = B.heap.fd; fx_ion = B.ion.anchor_fd;
    m11_crunner_config cc = {.endpoint = &B.endpoint, .ion = &B.ion, .heap_fd = B.heap.fd, .heap_rdev = B.heap.rdev,
        .pool_count = 2, .pool_len = 4096, .pool_base = 200, .sys = &fx_sys, .pd = &pdm, .journal = &sink,
        .terminal_ops = {.exit_fn = t_exit, .reboot_fn = t_reboot, .user = NULL, .panic_path = "/nonexistent-m11/panic"},
        .cmdline = "iommu.strict=1", .boot_epoch = 21, .timeout_ms = 300, .recovery_budget_ms = 2000, .src_port = 0x0100u};
    rc = m11_crunner_start(&R, &cc, ms(), &step);
    char b[160]; snprintf(b, sizeof b, "START rc=%d step=%d why=%u heap_open=%d\n", rc, step, R.census_why, fcntl(B.heap.fd, F_GETFD) != -1);
    say(b);
    if (rc) _exit(0);
    assert(m11_crunner_close(&R) == 0);
    (void)m11_crunner_end(&R, ms());
    _exit(99);
}

static int run(void (*fn)(void), char *rep, size_t cap) {
    int p[2]; assert(pipe(p) == 0);
    fflush(stdout);
    pid_t c = fork(); assert(c >= 0);
    if (c == 0) {
        close(p[0]); report_fd = p[1]; stdio_off_null();
        /* each root case in its own mount namespace: its bind mounts vanish with it */
        if (geteuid() == 0) assert(unshare(CLONE_NEWNS) == 0 && mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == 0);
        in_case = 1;
        fn(); _exit(98);
    }
    close(p[1]);
    size_t have = 0; ssize_t n;
    while (have + 1 < cap && (n = read(p[0], rep + have, cap - 1 - have)) > 0) have += (size_t)n;
    rep[have] = 0; close(p[0]);
    int st; assert(waitpid(c, &st, 0) == c);
    if (WIFSIGNALED(st) && WTERMSIG(st) == SIGABRT) abort();
    return WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
}
static int rm_one(const char *p, const struct stat *s, int f, struct FTW *w) { (void)s; (void)f; (void)w; return remove(p); }

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGPIPE, SIG_IGN);
    snprintf(base, sizeof base, "%s/m11-boot-XXXXXX", argc > 1 ? argv[1] : "/tmp");
    assert(mkdtemp(base));

    /* production defaults */
    m11_boot_config d = m11_boot_config_default();
    assert(!strcmp(d.endpoint.node, "/dev/aud_pasthru_adsp") && !strcmp(d.ion.node, "/dev/msm_audio_ion") &&
           !strcmp(d.ion_cma.node, "/dev/msm_audio_ion_cma") && d.endpoint.require_minor0 && d.ion.require_minor0 &&
           d.require_root && d.census_root == 0 && d.spawner_require_drop && !strcmp(d.sys, "/sys"));
    printf("PASS default config: the real node paths, minor 0, root nodes, the whole-system census, a capability-dropped spawner\n");

    /* metadata rules (unprivileged) */
    tree("aud_pasthru_adsp", PROC_OK);
    dev_t r;
    assert(m11_boot_cdev_meta(&C, &C.endpoint, &r) == 0 && r == makedev(5, 2));
    m11_boot_cdev strict = C.endpoint; strict.require_minor0 = 1;
    assert(m11_boot_cdev_meta(&C, &strict, &r) == -ENODEV);              /* production: minor 0 only */
    tree("something_else", PROC_OK);
    int devname_rc = m11_boot_cdev_meta(&C, &C.endpoint, &r);
    assert(devname_rc == -ENODEV);
    tree("aud_pasthru_adsp", "Character devices:\n  5 aud_pasthru_adsp\n  6 aud_pasthru_adsp\n");
    assert(m11_boot_cdev_meta(&C, &C.endpoint, &r) == -ENODEV);         /* two majors with the name */
    tree("aud_pasthru_adsp", "Character devices:\n  6 aud_pasthru_adsp\n");
    assert(m11_boot_cdev_meta(&C, &C.endpoint, &r) == -ENODEV);         /* another major */
    tree("aud_pasthru_adsp", "Character devices:\n\nBlock devices:\n  5 aud_pasthru_adsp\n");
    assert(m11_boot_cdev_meta(&C, &C.endpoint, &r) == -ENODEV);         /* a block device */
    printf("PASS boot metadata: exact MAJ:MIN (minor 0 in production), DEVNAME by number, exactly one matching character major\n");

    if (geteuid() != 0) {
        printf("SKIP root cases (mknod, anchor binds, seals): not root\n");
        (void)nftw(base, rm_one, 16, FTW_DEPTH | FTW_PHYS);
        printf("PASS production P2 boot sequence (unprivileged sections)\n");
        return 0;
    }
    char rep[2048]; int st;
    st = run(c_pd_down, rep, sizeof rep); printf("INFO st=%d %s", st, rep);
    assert(st == 0 && strstr(rep, "BOOT rc=-102 step=2 stage=1 ep=UNBOUND ion=UNBOUND ep_node=0 ion_node=0 cma_node=0 heap_fd=0 heap_dir=0 sealed=0 spawner=1"));
    printf("PASS boot refused while the PD is not UP: the spawner exists, no node, nothing opened\n");

    st = run(c_node_exists, rep, sizeof rep); printf("INFO st=%d %s", st, rep);
    assert(st == 0 && strstr(rep, "BOOT rc=-17 step=3 stage=2 ep=UNBOUND") && strstr(rep, "KEPT regular=1"));
    printf("PASS boot refused where an endpoint node already exists: it is left untouched, nothing bound\n");

    st = run(c_devname, rep, sizeof rep); printf("INFO st=%d %s", st, rep);
    assert(st == 0 && strstr(rep, "BOOT rc=-19 step=3 stage=2 ep=UNBOUND ion=UNBOUND ep_node=0"));
    printf("PASS boot refused when the number's DEVNAME is not the endpoint: no node made\n");

    st = run(c_cma_node, rep, sizeof rep); printf("INFO st=%d %s", st, rep);
    assert(st == 0 && strstr(rep, "BOOT rc=-17 step=4 stage=3 ep=HELD ion=UNBOUND ep_node=0 ion_node=0 cma_node=1"));
    printf("PASS boot refused when the ION CMA twin has a node: the endpoint stays held, its node removed, no ION node\n");

    st = run(c_heap_missing, rep, sizeof rep); printf("INFO st=%d %s", st, rep);
    assert(st == 0 && strstr(rep, "BOOT rc=-19 step=5 stage=4 ep=HELD ion=HELD ep_node=0 ion_node=0 cma_node=0 heap_fd=0 heap_dir=0 sealed=0"));
    printf("PASS boot refused without a system heap: both anchors stay held, both nodes removed, no heap node\n");

    st = run(c_full, rep, sizeof rep); printf("INFO st=%d %s", st, rep);
    assert(strstr(rep, "BOOT rc=0 step=0 stage=6 ep=HELD ion=HELD ep_node=0 ion_node=0 cma_node=0 heap_fd=1 heap_dir=0 sealed=1 spawner=1"));
    assert(strstr(rep, "START rc=0 step=0 why=0 heap_open=0") && st == 43 && strstr(rep, "END reboot ep_fd_open=0 ion_fd_open=0"));
    printf("PASS full boot: spawner, PD UP, both nodes made, bound and sealed (nodes gone), heap opened; the composed runner starts with a clean census (spawner included) and ends orderly\n");

    (void)nftw(base, rm_one, 16, FTW_DEPTH | FTW_PHYS);
    printf("PASS production P2 boot sequence (root sections)\n");
    return 0;
}
