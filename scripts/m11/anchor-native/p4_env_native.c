/* P4 environment phase — see p4_env_native.h. */
#define _GNU_SOURCE
#include "p4_env_native.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <signal.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define FAIL(n, rc) do { if (step) *step = (n); env_record(c, e, (n), "failed", (rc)); return (rc); } while (0)
#ifndef TMPFS_MAGIC
#define TMPFS_MAGIC 0x01021994
#endif

static int env_started_once;

m11_p4_env_config m11_p4_env_config_default(const m11_boot_config *boot) {
    return (m11_p4_env_config){
        .shell = "/bin/busybox", .shell_argv0 = "busybox", .shell_arg = "sh",
        .prepare = "/m11/prepare", .control = "/m11/control",
        .helper_log = "/run/m11/helpers.log", .helper_log_tmpfs = 1,
        .locator = "/sbin/m11-pd-mapper", .relay = "/sbin/m11-kmsg-relay", .helper_images_root = 1, .drop_helpers = 1,
        .locator_ready = "/run/m11/pd.endpoint", .relay_ready = "/run/m11-instrumentation/logger.ready",
        .amp_result = "/run/m11/amp-gate.result", .kmsg = "/dev/kmsg", .boot = boot,
        .prepare_ms = 90000, .journal_ms = 10000, .marker_ms = 5000, .probe_ms = 6000, .start_ms = 40000,
        .usb_ms = 40000, .amp_ms = 60000, .endpoint_ms = 30000, .ion_ms = 5000};
}

static uint64_t mono_ms(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) return 0;
    return (uint64_t)t.tv_sec * 1000u + (uint64_t)t.tv_nsec / 1000000u;
}
static void pause10(void) { (void)poll(NULL, 0, 10); }

/* One compact record per step, each through its own open (Run23 crumb pattern). */
static void env_record(const m11_p4_env_config *c, const m11_p4_env *e, int step, const char *what, int rc) {
    if (!c->kmsg) return;
    char b[160];
    int n = snprintf(b, sizeof b, "<5>M11P4 v=1 env step=%d %s rc=%d locator=%d relay=%d\n", step, what, rc,
                     e->locator > 0, e->relay > 0);
    if (n <= 0 || (size_t)n >= sizeof b) return;
    int fd = open(c->kmsg, O_WRONLY | O_APPEND | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return;
    ssize_t w = write(fd, b, (size_t)n);
    (void)w;
    (void)close(fd);
}

/* A job: the shell with the script and one argument; 0 only for exit status 0 within ms. Never
 * killed: past its deadline it is left running and the phase fails (the boot then holds). */
static int job(const m11_p4_env_config *c, const char *script, const char *arg, uint32_t ms) {
    pid_t p = fork();
    if (p < 0) return -errno;
    if (!p) {
        if (c->shell_arg) execl(c->shell, c->shell_argv0, c->shell_arg, script, arg, (char *)NULL);
        else execl(c->shell, c->shell_argv0, script, arg, (char *)NULL);
        _exit(127);
    }
    uint64_t until = mono_ms() + ms;
    for (;;) {
        int status;
        pid_t got = waitpid(p, &status, WNOHANG);
        if (got == p) return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -ECHILD;
        if (got < 0 && errno != EINTR) return -errno;
        if (mono_ms() >= until) return -ETIMEDOUT;
        pause10();
    }
}

static int wait_marker(const char *path, uint32_t ms) {
    uint64_t until = mono_ms() + ms;
    struct stat st;
    do {
        if (!lstat(path, &st)) return S_ISREG(st.st_mode) ? 0 : -EINVAL;
        pause10();
    } while (mono_ms() < until);
    return -ETIMEDOUT;
}

static int read_small(const char *path, char *b, size_t cap) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -errno;
    ssize_t n = read(fd, b, cap - 1);
    int cr = close(fd);
    if (n < 0 || (size_t)n == cap - 1 || cr) return -EIO;
    b[n] = 0;
    return 0;
}

static int drop_privileges(void) {
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) || prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0) ||
        prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)) return -1;
    for (int cap = 0; cap < 64; cap++) {
        int present = prctl(PR_CAPBSET_READ, cap, 0, 0, 0);
        if (present < 0) { if (errno == EINVAL) break; return -1; }
        if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0)) return -1;
    }
    return setgroups(0, NULL) || setresgid(65534, 65534, 65534) || setresuid(65534, 65534, 65534) ? -1 : 0;
}

/* A helper: a checked image started with only stdio (stdin /dev/null, stdout/stderr the log);
 * exec failure is reported through a CLOEXEC pipe within 500 ms. The pid, or a negative errno. */
static pid_t helper(const m11_p4_env_config *c, const char *path, int serve, int log_fd) {
    struct stat st;
    unsigned char magic[4];
    int image = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (image < 0) return -errno;
    if (fstat(image, &st) || !S_ISREG(st.st_mode) || !(st.st_mode & 0111) || pread(image, magic, 4, 0) != 4 ||
        memcmp(magic, "\177ELF", 4) || (c->helper_images_root && (st.st_uid || (st.st_mode & 022)))) {
        close(image);
        return -EPERM;
    }
    int ep[2];
    if (pipe2(ep, O_CLOEXEC | O_NONBLOCK)) { int e = -errno; close(image); return e; }
    pid_t pid = fork();
    if (pid < 0) { int e = -errno; close(image); close(ep[0]); close(ep[1]); return e; }
    if (!pid) {
        close(ep[0]);
        int nullfd = open("/dev/null", O_RDONLY | O_NOFOLLOW);
        int failed = nullfd < 0 || dup2(nullfd, 0) < 0 || dup2(log_fd, 1) < 0 || dup2(log_fd, 2) < 0;
        /* keep only stdio, the image and the error pipe (both CLOEXEC) */
        int keep_lo = image < ep[1] ? image : ep[1], keep_hi = image < ep[1] ? ep[1] : image;
        if (!failed && keep_lo > 3) failed = syscall(SYS_close_range, 3u, (unsigned)keep_lo - 1u, 0u) != 0;
        if (!failed && keep_hi > keep_lo + 1) failed = syscall(SYS_close_range, (unsigned)keep_lo + 1u, (unsigned)keep_hi - 1u, 0u) != 0;
        if (!failed) failed = syscall(SYS_close_range, (unsigned)keep_hi + 1u, ~0u, 0u) != 0;
        if (!failed && c->drop_helpers) failed = drop_privileges();
        if (!failed) {
            char *const with_serve[] = {(char *)path, (char *)"--serve", NULL};
            char *const plain[] = {(char *)path, NULL};
            char *const env[] = {NULL};
            fexecve(image, serve ? with_serve : plain, env);
        }
        unsigned char failure = 1;
        ssize_t w = write(ep[1], &failure, 1);
        (void)w;
        _exit(127);
    }
    close(ep[1]); close(image);
    uint64_t until = mono_ms() + 500;
    int ok = 0;
    for (;;) {
        unsigned char err;
        ssize_t got = read(ep[0], &err, 1);
        if (got == 0) { ok = 1; break; }               /* exec closed the pipe */
        if (got > 0 || (errno != EAGAIN && errno != EINTR)) break;
        if (mono_ms() >= until) break;
        struct pollfd p = {ep[0], POLLIN, 0};
        (void)poll(&p, 1, 5);
    }
    close(ep[0]);
    if (ok) return pid;
    (void)kill(pid, SIGKILL); /* it never ran the helper: an exec that failed */
    (void)waitpid(pid, NULL, 0);
    return -ENOEXEC;
}

static int meta_wait(const m11_p4_env_config *c, const m11_boot_cdev *d, uint32_t ms, dev_t *out) {
    uint64_t until = mono_ms() + ms;
    int rc;
    do {
        if (!(rc = m11_boot_cdev_meta(c->boot, d, out))) return 0;
        pause10();
    } while (mono_ms() < until);
    return rc;
}

int m11_p4_env_run(m11_p4_env *e, const m11_p4_env_config *c, int *step) {
    if (step) *step = 0;
    if (!e || !c || !c->shell || !c->shell_argv0 || !c->prepare || !c->control || !c->helper_log || !c->locator ||
        !c->relay || !c->locator_ready || !c->relay_ready || !c->amp_result || !c->boot) return -EINVAL;
    if (env_started_once) return -EALREADY;
    env_started_once = 1;
    memset(e, 0, sizeof *e);
    int rc;
    /* 1-2. prepare, journal */
    if ((rc = job(c, c->prepare, NULL, c->prepare_ms))) FAIL(1, rc);
    e->step = 1; env_record(c, e, 1, "prepare", 0);
    if ((rc = job(c, c->control, "journal", c->journal_ms))) FAIL(2, rc);
    e->step = 2; env_record(c, e, 2, "journal", 0);
    /* 3. the helper log */
    int log_fd = open(c->helper_log, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (log_fd < 0) FAIL(3, -errno);
    struct stat st; struct statfs fs;
    if (fstat(log_fd, &st) || !S_ISREG(st.st_mode) || (c->helper_log_tmpfs && (fstatfs(log_fd, &fs) || fs.f_type != TMPFS_MAGIC))) {
        close(log_fd);
        FAIL(3, -EPERM);
    }
    e->step = 3;
    /* 4. the PD locator, its marker, the probe */
    pid_t p = helper(c, c->locator, 1, log_fd);
    if (p < 0) { close(log_fd); FAIL(4, (int)p); }
    e->locator = p;
    if ((rc = wait_marker(c->locator_ready, c->marker_ms)) || (rc = job(c, c->control, "probe", c->probe_ms))) {
        close(log_fd);
        FAIL(4, rc);
    }
    e->step = 4; env_record(c, e, 4, "locator", 0);
    /* 5. the kmsg relay, the log closed, its marker */
    p = helper(c, c->relay, 0, log_fd);
    int cr = close(log_fd);
    if (p < 0) FAIL(5, (int)p);
    e->relay = p;
    if (cr) FAIL(5, -EIO);
    if ((rc = wait_marker(c->relay_ready, c->marker_ms))) FAIL(5, rc);
    e->step = 5; env_record(c, e, 5, "relay", 0);
    /* 6. ADSP start, then USB */
    if ((rc = job(c, c->control, "start", c->start_ms)) || (rc = job(c, c->control, "usb_start", c->usb_ms))) FAIL(6, rc);
    e->step = 6; env_record(c, e, 6, "adsp_usb", 0);
    /* 7. the amplifier gate: switches read back disabled */
    char result[64];
    if ((rc = job(c, c->control, "amp_gate", c->amp_ms))) FAIL(7, rc);
    if ((rc = read_small(c->amp_result, result, sizeof result))) FAIL(7, rc);
    if (strcmp(result, "switches-disabled\n")) FAIL(7, -EPERM);
    e->step = 7; env_record(c, e, 7, "amp_gate", 0);
    /* 8. kernel metadata for the endpoint, then ION and its CMA twin (read-only; P2 makes the nodes) */
    if ((rc = meta_wait(c, &c->boot->endpoint, c->endpoint_ms, &e->endpoint))) FAIL(8, rc);
    if ((rc = meta_wait(c, &c->boot->ion, c->ion_ms, &e->ion)) || (rc = meta_wait(c, &c->boot->ion_cma, c->ion_ms, &e->ion_cma)))
        FAIL(8, rc);
    e->step = 8; env_record(c, e, 8, "metadata", 0);
    return 0;
}
