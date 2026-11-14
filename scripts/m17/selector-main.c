/* M17 selector on the phone: the operations selector.h runs (docs/m17-g4.md). PID 1 in boot_a's ramdisk, with the stock
 * first stage at /init.stock. Its log goes to the kernel's, where Android's logd keeps it. */
#define _GNU_SOURCE
#include "kms.h"
#include "menu.h"
#include "modules.h"
#include "select.h"
#include "selector.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#ifndef M17_NATIVE_BUILD
#define M17_NATIVE_BUILD 0 /* G4: Volume Down shows that Ubuntu is not in this build, and goes to Android */
#endif
#define LIST "/m17/modules.list"
#define CARD_WAIT_MS 15000u
#define KEYS_WAIT_MS 5000u

struct ctx {
    int kmsg;
    char **argv, **envp;
    struct m17_kms kms;
    int frame; /* the buffer on the panel */
    uint64_t opened_ms;
};

static void klog(void *user, const char *line) {
    struct ctx *c = user;
    if (c->kmsg < 0) return;
    char text[320];
    int n = snprintf(text, sizeof text, "<6>%s\n", line);
    if (n > 0) (void)!write(c->kmsg, text, (size_t)(n < (int)sizeof text ? n : (int)sizeof text - 1));
}

static int first_error(int rc, int now) {
    return rc ? rc : now;
}

static int mount_early(void *user) {
    struct ctx *c = user;
    int rc = 0;
    rc = first_error(rc, mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) ? -errno : 0);
    rc = first_error(rc, mount("sysfs", "/sys", "sysfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) ? -errno : 0);
    rc = first_error(rc, mount("tmpfs", "/dev", "tmpfs", MS_NOSUID, "mode=0755,size=1m") ? -errno : 0);
    rc = first_error(rc, mknod("/dev/kmsg", S_IFCHR | 0600, makedev(1, 11)) ? -errno : 0);
    rc = first_error(rc, mknod("/dev/null", S_IFCHR | 0666, makedev(1, 3)) ? -errno : 0);
    c->kmsg = open("/dev/kmsg", O_WRONLY | O_CLOEXEC);
    return rc;
}

static int read_file(const char *path, char *buf, unsigned room) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -errno;
    size_t at = 0;
    for (;;) {
        ssize_t n = read(fd, buf + at, room - 1 - at);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        at += (size_t)n;
        if (at == room - 1) break;
    }
    close(fd);
    buf[at] = 0;
    return 0;
}

static int read_cmdline(void *user, char *buf, unsigned room) {
    (void)user;
    return read_file("/proc/cmdline", buf, room);
}

static int read_bootconfig(void *user, char *buf, unsigned room) {
    (void)user;
    return read_file("/proc/bootconfig", buf, room);
}

static int finit(const char *path, const char *params) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -errno;
    int rc = syscall(SYS_finit_module, fd, params, 0) ? -errno : 0;
    close(fd);
    return rc;
}

static struct ctx *log_ctx;
static void module_log(const char *line) {
    klog(log_ctx, line);
}

static int load_modules(void *user, const char *cmdline) {
    static char list[16384];
    struct ctx *c = user;
    if (read_file(LIST, list, sizeof list)) {
        klog(c, "M17SEL modules list-missing");
        return 1;
    }
    log_ctx = c;
    struct m17_modules m = {.dir = "/lib/modules", .cmdline = cmdline, .load = finit, .log = module_log};
    unsigned loaded, already;
    uint64_t t = m17_monotonic_ms();
    int failed = m17_load_modules(&m, list, &loaded, &already);
    char line[128];
    snprintf(line, sizeof line, "M17SEL modules loaded=%u already=%u failed=%d ms=%llu", loaded, already, failed,
             (unsigned long long)(m17_monotonic_ms() - t));
    klog(c, line);
    return failed;
}

static int wait_card(void *user) {
    struct ctx *c = user;
    uint64_t end = m17_monotonic_ms() + CARD_WAIT_MS;
    char link[PATH_MAX], devno[32];
    for (;;) {
        ssize_t n = readlink("/sys/class/drm/card0/device", link, sizeof link - 1);
        if (n > 0) {
            link[n] = 0;
            const char *want = "ae00000.qcom,mdss_mdp";
            size_t len = strlen(link), wl = strlen(want);
            if (len >= wl && !strcmp(link + len - wl, want)) break;
        }
        if (m17_monotonic_ms() >= end) {
            klog(c, "M17SEL card timeout");
            return -1;
        }
        (void)poll(NULL, 0, 20);
    }
    unsigned maj, min;
    if (read_file("/sys/class/drm/card0/dev", devno, sizeof devno) || sscanf(devno, "%u:%u", &maj, &min) != 2) return -1;
    if (mkdir("/dev/dri", 0755) && errno != EEXIST) return -1;
    if (mknod("/dev/dri/card0", S_IFCHR | 0600, makedev(maj, min)) && errno != EEXIST) return -1;
    return 0;
}

static int wait_keys(void *user) {
    struct ctx *c = user;
    uint64_t end = m17_monotonic_ms() + KEYS_WAIT_MS;
    char up[16], down[16];
    while (m17_key_find("/sys", M17_UP_DEVICE, M17_KEY_VOLUMEUP, up) || m17_key_find("/sys", M17_DOWN_DEVICE, M17_KEY_VOLUMEDOWN, down)) {
        if (m17_monotonic_ms() >= end) {
            klog(c, "M17SEL keys timeout");
            return -1;
        }
        (void)poll(NULL, 0, 20);
    }
    return m17_key_node("/sys", "/dev", up) || m17_key_node("/sys", "/dev", down) ? -1 : 0;
}

static int show(struct ctx *c, unsigned left_ms) {
    int next = c->kms.committed ? !c->frame : 0;
    uint32_t pitch;
    uint32_t *pixels = m17_kms_pixels(&c->kms, next, &pitch);
    m17_menu_draw(pixels, pitch, left_ms, M17_WINDOW_MS, M17_NATIVE_BUILD);
    if (m17_kms_show(&c->kms, next)) return -1;
    c->frame = next;
    return 0;
}

static int menu_open(void *user) {
    struct ctx *c = user;
    if (m17_kms_open(&c->kms, "/dev/dri/card0")) {
        klog(c, "M17SEL menu open-failed");
        return -1;
    }
    if (show(c, M17_WINDOW_MS)) {
        klog(c, "M17SEL menu first-frame-failed");
        (void)m17_kms_close(&c->kms);
        return -1;
    }
    c->opened_ms = m17_monotonic_ms();
    return 0;
}

static int menu_frame(void *user, unsigned seconds_left) {
    struct ctx *c = user;
    /* The first call is the opening: that frame is already up. */
    if (seconds_left * 1000u >= M17_WINDOW_MS) return 0;
    return show(c, seconds_left * 1000u);
}

static enum m17_choice window(void *user, struct m17_window *w) {
    struct m17_loop l = {.sys_root = "/sys", .dev_root = "/dev", .window_ms = M17_WINDOW_MS, .require_chr = 1,
                         .now_ms = m17_monotonic_ms, .menu = menu_frame, .user = user};
    return m17_run_window(&l, w);
}

static int menu_close(void *user) {
    struct ctx *c = user;
    return m17_kms_close(&c->kms);
}

static int unmount_early(void *user) {
    (void)user;
    int rc = 0;
    rc = first_error(rc, umount2("/dev", MNT_DETACH) ? -errno : 0);
    rc = first_error(rc, umount2("/sys", MNT_DETACH) ? -errno : 0);
    rc = first_error(rc, umount2("/proc", MNT_DETACH) ? -errno : 0);
    return rc;
}

static int exec_android(void *user) {
    struct ctx *c = user;
    execve("/init.stock", c->argv, c->envp);
    int e = errno;
    char line[64];
    snprintf(line, sizeof line, "M17SEL exec-failed errno=%d", e);
    klog(c, line);
    return -e;
}

int main(int argc, char **argv, char **envp) {
    (void)argc;
    if (getpid() != 1) return 64;
    static struct ctx c = {.kmsg = -1};
    c.argv = argv;
    c.envp = envp;
    struct m17_selector_ops ops = {
        .user = &c, .log = klog, .mount_early = mount_early, .read_cmdline = read_cmdline, .read_bootconfig = read_bootconfig,
        .load_modules = load_modules, .wait_card = wait_card, .wait_keys = wait_keys, .menu_open = menu_open, .window = window,
        .menu_close = menu_close, .unmount_early = unmount_early, .exec_android = exec_android, .run_native = NULL,
    };
    struct m17_selector_result r;
    (void)m17_selector_run(&ops, &r);
    /* /init.stock could not run: PID 1 exits, the kernel panics and restarts the phone, which ABL boots again. */
    return 1;
}
