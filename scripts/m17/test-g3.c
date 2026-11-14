/* M17 G3: K1-keys on synthetic sysfs trees and FIFOs standing in for evdev nodes, with a stand-in module loader.
 * Volume Down's device appears late, as qcom-pon creates it. No device. Run under ASan/UBSan too (test.sh). */
#define _GNU_SOURCE
#include "g3.h"
#include "select.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/input.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int failures;
#define CHECK(cond)                                                                                                    \
    do {                                                                                                               \
        if (!(cond)) {                                                                                                 \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond);                                   \
            failures++;                                                                                                \
        }                                                                                                              \
    } while (0)

static char base[256], sys_root[300], dev_root[300];

static void mkdirs(const char *path) {
    char dir[512];
    snprintf(dir, sizeof dir, "%s", path);
    for (char *p = dir + 1; *p; p++)
        if (*p == '/') {
            *p = 0;
            mkdir(dir, 0755);
            *p = '/';
        }
}

static void put(const char *rel, const char *text) {
    char path[512];
    snprintf(path, sizeof path, "%s/%s", base, rel);
    mkdirs(path);
    char tmp[600];
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    FILE *f = fopen(tmp, "w");
    assert(f);
    fputs(text, f);
    fclose(f);
    assert(!rename(tmp, path));
}

#define CAP_UP "8000000000000 0\n"
#define CAP_DOWN "4000000000000 0\n"
#define CAP_POWER "10000000000000 0\n" /* bit 116: bit 52 of word 1 */

/* A device: its node first, its name last, so a finder never sees a name without a node. */
static void device(const char *event, const char *name, const char *caps) {
    char rel[256], path[512];
    snprintf(path, sizeof path, "%s/dev/input/%s", base, event);
    mkdirs(path);
    unlink(path);
    assert(!mkfifo(path, 0600));
    snprintf(rel, sizeof rel, "sys/class/input/%s/dev", event);
    put(rel, "13:66\n");
    snprintf(rel, sizeof rel, "sys/class/input/%s/device/capabilities/key", event);
    put(rel, caps);
    snprintf(rel, sizeof rel, "sys/class/input/%s/device/name", event);
    put(rel, name);
}

static void world(void) {
    char cmd[300];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", base);
    assert(!system(cmd));
    mkdir(base, 0755);
    put("sys/class/input/event9/device/name", "goodix_ts\n");
    put("sys/class/input/event9/device/capabilities/key", "0\n");
}

/* The stand-in loader: the modules asked for, in order, and qcom-pon's result. */
static char loaded[256];
static int pon_rc;
static int load(const char *path) {
    const char *name = strrchr(path, '/') ? strrchr(path, '/') + 1 : path;
    strncat(loaded, name, sizeof loaded - strlen(loaded) - 2);
    strcat(loaded, ",");
    return strcmp(name, "qcom-pon.ko") ? 0 : pon_rc;
}

static struct input_event key(unsigned code, int value) {
    struct input_event e;
    memset(&e, 0, sizeof e);
    e.type = EV_KEY;
    e.code = (unsigned short)code;
    e.value = value;
    return e;
}

/* A child that makes a device after appear_ms (0: already made), then writes events after delay_ms once the reader
 * opened the node, and stays. partial: 1, five bytes instead; 2, the events and, 100 ms later, five bytes. */
static pid_t feeder(const char *event, const char *name, const char *caps, unsigned appear_ms, unsigned delay_ms, const struct input_event *evs,
                    size_t count, int partial) {
    if (!appear_ms) device(event, name, caps);
    pid_t pid = fork();
    assert(pid >= 0);
    if (pid) return pid;
    alarm(15);
    if (appear_ms) {
        usleep(appear_ms * 1000u);
        device(event, name, caps);
    }
    char path[512];
    snprintf(path, sizeof path, "%s/dev/input/%s", base, event);
    int fd = open(path, O_WRONLY);
    if (fd < 0) _exit(70);
    usleep(delay_ms * 1000u);
    if (partial != 1 && count && write(fd, evs, count * sizeof *evs) != (ssize_t)(count * sizeof *evs)) _exit(72);
    if (partial == 2) usleep(100000);
    if (partial && write(fd, "\1\2\3\4\5", 5) != 5) _exit(71);
    for (;;) pause();
}

static void reap(pid_t pid) {
    if (pid > 0) {
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
    }
}

static char out_text[16384];

static int run(struct m17_g3_result *r, unsigned up_wait, unsigned down_wait, unsigned window, unsigned select_ms, uint64_t *elapsed) {
    FILE *out = tmpfile();
    assert(out);
    loaded[0] = 0;
    struct m17_g3 g = {.sys_root = sys_root, .dev_root = dev_root, .modules_dir = "/lib/modules", .make_nodes = 0, .require_chr = 0,
                       .load = load, .now_ms = m17_monotonic_ms, .up_wait_ms = up_wait, .down_wait_ms = down_wait, .window_ms = window,
                       .settle_ms = 300, .poll_ms = 10, .select_ms = select_ms, .out = out};
    uint64_t t0 = m17_monotonic_ms();
    int rc = m17_g3_run(&g, r);
    if (elapsed) *elapsed = m17_monotonic_ms() - t0;
    rewind(out);
    size_t n = fread(out_text, 1, sizeof out_text - 1, out);
    out_text[n] = 0;
    fclose(out);
    return rc;
}

static const struct input_event UP[] = {{.type = EV_KEY, .code = M17_KEY_VOLUMEUP, .value = 1}, {.type = EV_SYN},
                                        {.type = EV_KEY, .code = M17_KEY_VOLUMEUP, .value = 2},
                                        {.type = EV_KEY, .code = M17_KEY_VOLUMEUP, .value = 0}, {.type = EV_SYN}};
static const struct input_event DOWN[] = {{.type = EV_KEY, .code = M17_KEY_VOLUMEDOWN, .value = 1}, {.type = EV_SYN},
                                          {.type = EV_KEY, .code = M17_KEY_VOLUMEDOWN, .value = 0}, {.type = EV_SYN}};

int main(void) {
    snprintf(base, sizeof base, "%s/m17-g3-%d", getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp", (int)getpid());
    snprintf(sys_root, sizeof sys_root, "%s/sys", base);
    snprintf(dev_root, sizeof dev_root, "%s/dev", base);
    struct m17_g3_result r;
    uint64_t elapsed;

    /* Both keys, Volume Down's device appearing after qcom-pon: keys_ok, the modules in order, an early end, and the
     * selector's view of Volume Up first: Android. */
    world();
    pid_t up = feeder("event0", "gpio-keys\n", CAP_UP, 0, 100, UP, 5, 0);
    pid_t down = feeder("event4", "pmic_resin\n", CAP_DOWN, 700, 500, DOWN, 4, 0);
    pon_rc = 0;
    CHECK(run(&r, 500, 3000, 6000, 3000, &elapsed) == 0 && r.keys_ok == 1);
    CHECK(!strcmp(loaded, "reboot-mode.ko,qcom-pon.ko,"));
    CHECK(r.up_found && r.down_found && !r.power_found && r.up_ready_ms >= 0 && r.up_ready_ms < 100);
    CHECK(r.down_ready_ms >= 600 && r.down_ready_ms < 2500);
    CHECK(r.up_press == 1 && r.up_release == 1 && r.down_press == 1 && r.down_release == 1 && r.events == 5 && !r.read_error);
    CHECK(r.choice == M17_ANDROID && r.why == M17_WHY_VOLUME_UP);
    CHECK(elapsed < 4500);
    CHECK(strstr(out_text, "M17 G3 devices up=event0 ") && strstr(out_text, " down=event4 ") && strstr(out_text, " power=none"));
    CHECK(strstr(out_text, "M17 G3 event down key=114 value=1 at_ms="));
    CHECK(strstr(out_text, " up=1/1 down=1/1 power=0/0 events=5 read_error=0 selector=android/volume-up keys_ok=1\n"));
    reap(up);
    reap(down);

    /* Volume Down first: the selector would have chosen native. A power key is recorded, never required. */
    world();
    struct input_event power[] = {key(M17_KEY_POWER, 1), key(M17_KEY_POWER, 0)};
    pid_t pw = feeder("event5", "pmic_pwrkey\n", CAP_POWER, 0, 50, power, 2, 0);
    up = feeder("event0", "gpio-keys\n", CAP_UP, 0, 700, UP, 5, 0);
    struct input_event foreign[] = {key(M17_KEY_VOLUMEUP, 1), key(M17_KEY_VOLUMEDOWN, 1), key(M17_KEY_VOLUMEDOWN, 0)};
    down = feeder("event4", "pmic_resin\n", CAP_DOWN, 0, 100, foreign, 3, 0);
    CHECK(run(&r, 500, 3000, 6000, 3000, NULL) == 0 && r.keys_ok == 1 && r.choice == M17_NATIVE && r.why == M17_WHY_VOLUME_DOWN);
    CHECK(r.down_press == 1 && r.up_press == 1);
    CHECK(r.power_found && r.power_press == 1 && r.power_release == 1 && strstr(out_text, " power=event5"));
    reap(pw);
    reap(up);
    reap(down);

    /* Volume Down never appears: not ok, after its wait, and Volume Up still recorded. */
    world();
    up = feeder("event0", "gpio-keys\n", CAP_UP, 0, 50, UP, 5, 0);
    CHECK(run(&r, 500, 300, 800, 3000, &elapsed) == 1 && !r.keys_ok && !r.down_found && r.down_ready_ms == -1 && r.up_press == 1);
    CHECK(strstr(out_text, " down=none down_ready_ms=-1 ") && strstr(out_text, "keys_ok=0\n"));
    reap(up);

    /* qcom-pon fails to load: recorded, and nothing appears. */
    world();
    pon_rc = -ENOENT;
    up = feeder("event0", "gpio-keys\n", CAP_UP, 0, 50, UP, 5, 0);
    CHECK(run(&r, 500, 300, 600, 3000, NULL) == 1 && r.pon_rc == -ENOENT && strstr(out_text, "M17 G3 load qcom-pon.ko rc=-2"));
    pon_rc = 0;
    reap(up);

    /* Volume Up missing. */
    world();
    down = feeder("event4", "pmic_resin\n", CAP_DOWN, 0, 50, DOWN, 4, 0);
    CHECK(run(&r, 200, 1000, 600, 3000, NULL) == 1 && !r.up_found && r.up_ready_ms == -1 && r.down_press == 1 && !r.keys_ok);
    reap(down);

    /* Presses without releases. */
    world();
    struct input_event up_press[] = {key(M17_KEY_VOLUMEUP, 1)}, down_press[] = {key(M17_KEY_VOLUMEDOWN, 1)};
    up = feeder("event0", "gpio-keys\n", CAP_UP, 0, 50, up_press, 1, 0);
    down = feeder("event4", "pmic_resin\n", CAP_DOWN, 0, 50, DOWN, 4, 0);
    CHECK(run(&r, 500, 1000, 700, 3000, NULL) == 1 && r.up_press == 1 && !r.up_release && r.down_release == 1 && !r.keys_ok);
    reap(up);
    reap(down);
    world();
    up = feeder("event0", "gpio-keys\n", CAP_UP, 0, 50, UP, 5, 0);
    down = feeder("event4", "pmic_resin\n", CAP_DOWN, 0, 50, down_press, 1, 0);
    CHECK(run(&r, 500, 1000, 700, 3000, NULL) == 1 && r.up_release == 1 && r.down_press == 1 && !r.down_release && !r.keys_ok);
    reap(up);
    reap(down);

    /* A broken event: a read error, and not ok. */
    world();
    up = feeder("event0", "gpio-keys\n", CAP_UP, 0, 50, UP, 5, 0);
    down = feeder("event4", "pmic_resin\n", CAP_DOWN, 0, 50, DOWN, 4, 2);
    CHECK(run(&r, 500, 1000, 1500, 3000, NULL) == 1 && r.read_error && r.down_release == 1 && r.up_release == 1 && !r.keys_ok &&
          strstr(out_text, "M17 G3 read-error down"));
    reap(up);
    reap(down);
    /* Dropped events: a read error too. */
    world();
    struct input_event dropped[] = {{.type = EV_SYN, .code = SYN_DROPPED}, key(M17_KEY_VOLUMEDOWN, 1), key(M17_KEY_VOLUMEDOWN, 0)};
    up = feeder("event0", "gpio-keys\n", CAP_UP, 0, 50, UP, 5, 0);
    down = feeder("event4", "pmic_resin\n", CAP_DOWN, 0, 50, dropped, 3, 0);
    CHECK(run(&r, 500, 1000, 800, 3000, NULL) == 1 && r.read_error && !r.down_press && !r.keys_ok);
    reap(up);
    reap(down);

    /* The selector's window passes before any key: its view is the timeout. */
    world();
    up = feeder("event0", "gpio-keys\n", CAP_UP, 0, 600, UP, 5, 0);
    down = feeder("event4", "pmic_resin\n", CAP_DOWN, 0, 400, DOWN, 4, 0);
    CHECK(run(&r, 500, 1000, 3000, 200, NULL) == 0 && r.keys_ok && r.choice == M17_ANDROID && r.why == M17_WHY_TIMEOUT);
    reap(up);
    reap(down);

    /* Two devices of Volume Down's name: ambiguous, not found. */
    world();
    device("event4", "pmic_resin\n", CAP_DOWN);
    device("event6", "pmic_resin\n", CAP_DOWN);
    up = feeder("event0", "gpio-keys\n", CAP_UP, 0, 50, UP, 5, 0);
    CHECK(run(&r, 500, 200, 400, 3000, NULL) == 1 && !r.down_found && strstr(out_text, "M17 G3 ambiguous pmic_resin"));
    reap(up);

    /* No key at all: it ends at once, without waiting out the window. */
    world();
    CHECK(run(&r, 100, 100, 5000, 3000, &elapsed) == 1 && elapsed < 1500 && !r.up_found && !r.down_found);

    char cmd[300];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", base);
    if (system(cmd)) failures++;
    if (failures) {
        fprintf(stderr, "M17 G3 tests: %d failed\n", failures);
        return 1;
    }
    printf("M17 G3 tests PASS\n");
    return 0;
}
