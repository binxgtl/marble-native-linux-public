/* M17 G1: the selector core on synthetic boot modes, synthetic sysfs trees and FIFOs standing in for evdev nodes.
 * No device. Run under ASan/UBSan too (test.sh). */
#define _GNU_SOURCE
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

/* ---- The boot mode ---- */

static void test_normal_boot(void) {
    struct {
        const char *cmdline, *bootconfig;
        int normal;
    } cases[] = {
        {NULL, NULL, 1},
        {"console=ttyMSM0 androidboot.mode=normal quiet", NULL, 1},
        {"androidboot.mode=charger", NULL, 0},
        {"androidboot.mode=ffbm-00", NULL, 0},
        {"androidboot.mode=\"normal\"", NULL, 1},
        {"androidboot.mode=", NULL, 0},
        {"androidboot.alarmboot=true", NULL, 0},
        {"androidboot.alarmboot=1", NULL, 0},
        {"androidboot.alarmboot=yes", NULL, 0},
        {"androidboot.alarmboot=false androidboot.mode=normal", NULL, 1},
        {"androidboot.alarmboot=0", NULL, 1},
        {"xandroidboot.mode=charger androidboot.modex=charger", NULL, 1},
        {"a=\"b c androidboot.mode=charger\" androidboot.mode=normal", NULL, 1},
        {NULL, "androidboot.mode = \"charger\"\n", 0},
        {NULL, "androidboot.mode = \"normal\"\nandroidboot.alarmboot = \"true\"\n", 0},
        {NULL, "  androidboot.mode=\"normal\"  \n\tandroidboot.serialconsole = \"0\"\n", 1},
        {NULL, "androidboot.mode = \"normal\", \"charger\"\n", 0},
        {NULL, "androidboot.mode = normal", 1},
        {"androidboot.mode=normal", "androidboot.mode = \"charger\"\n", 0},
        {"androidboot.mode=charger", "androidboot.mode = \"normal\"\n", 0},
        {"", "", 1},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        int got = m17_normal_boot(cases[i].cmdline, cases[i].bootconfig);
        if (got != cases[i].normal) fprintf(stderr, "normal_boot case %zu: got %d\n", i, got);
        CHECK(got == cases[i].normal);
    }
}

/* ---- The window ---- */

static void test_window(void) {
    struct m17_window w;
    m17_window_open(&w, 1000, 10000, 0);
    CHECK(w.choice == M17_UNDECIDED && m17_window_left_ms(&w, 1000) == 10000 && m17_window_left_ms(&w, 12000) == 0);
    CHECK(m17_window_key(&w, M17_KEY_VOLUMEDOWN, 1) == M17_NATIVE && w.why == M17_WHY_VOLUME_DOWN);
    /* A choice is final. */
    CHECK(m17_window_key(&w, M17_KEY_VOLUMEUP, 1) == M17_NATIVE && m17_window_tick(&w, 99999) == M17_NATIVE);
    CHECK(m17_window_fail(&w, M17_WHY_READ_ERROR) == M17_NATIVE && w.why == M17_WHY_VOLUME_DOWN);

    m17_window_open(&w, 0, 10000, 0);
    CHECK(m17_window_key(&w, M17_KEY_VOLUMEUP, 1) == M17_ANDROID && w.why == M17_WHY_VOLUME_UP);
    CHECK(m17_window_key(&w, M17_KEY_VOLUMEDOWN, 1) == M17_ANDROID);

    /* A held key's repeats and its release choose nothing; a later press does. */
    m17_window_open(&w, 0, 10000, 0);
    CHECK(m17_window_key(&w, M17_KEY_VOLUMEDOWN, 2) == M17_UNDECIDED);
    CHECK(m17_window_key(&w, M17_KEY_VOLUMEDOWN, 0) == M17_UNDECIDED);
    CHECK(m17_window_key(&w, M17_KEY_VOLUMEUP, 2) == M17_UNDECIDED);
    CHECK(m17_window_key(&w, 116, 1) == M17_UNDECIDED && m17_window_key(&w, 0, 1) == M17_UNDECIDED);
    CHECK(m17_window_key(&w, M17_KEY_VOLUMEDOWN, 7) == M17_UNDECIDED && m17_window_key(&w, M17_KEY_VOLUMEDOWN, -1) == M17_UNDECIDED);
    CHECK(m17_window_tick(&w, 9999) == M17_UNDECIDED);
    CHECK(m17_window_key(&w, M17_KEY_VOLUMEDOWN, 1) == M17_NATIVE);

    /* Volume Up held at the window's opening: Volume Down then means both. */
    m17_window_open(&w, 0, 10000, 1);
    CHECK(m17_window_key(&w, M17_KEY_VOLUMEDOWN, 1) == M17_ANDROID && w.why == M17_WHY_BOTH);
    /* ... unless Volume Up was released first. */
    m17_window_open(&w, 0, 10000, 1);
    CHECK(m17_window_key(&w, M17_KEY_VOLUMEUP, 0) == M17_UNDECIDED);
    CHECK(m17_window_key(&w, M17_KEY_VOLUMEDOWN, 1) == M17_NATIVE);

    /* The deadline. */
    m17_window_open(&w, 500, 10000, 0);
    CHECK(m17_window_tick(&w, 10499) == M17_UNDECIDED);
    CHECK(m17_window_tick(&w, 10500) == M17_ANDROID && w.why == M17_WHY_TIMEOUT);
    CHECK(m17_window_key(&w, M17_KEY_VOLUMEDOWN, 1) == M17_ANDROID);

    m17_window_open(&w, 0, 10000, 0);
    CHECK(m17_window_fail(&w, M17_WHY_NO_MENU) == M17_ANDROID && w.why == M17_WHY_NO_MENU);

    CHECK(!strcmp(m17_choice_name(M17_NATIVE), "native") && !strcmp(m17_choice_name(M17_ANDROID), "android") &&
          !strcmp(m17_choice_name(M17_UNDECIDED), "undecided"));
    CHECK(!strcmp(m17_reason_name(M17_WHY_BOTH), "both") && !strcmp(m17_reason_name(M17_WHY_TIMEOUT), "timeout") &&
          !strcmp(m17_reason_name(M17_WHY_READ_ERROR), "read-error") && !strcmp(m17_reason_name(M17_WHY_NO_KEYS), "no-keys"));
}

/* ---- Synthetic trees ---- */

static char base[256];

static void put(const char *rel, const char *text) {
    char path[512], dir[512];
    snprintf(path, sizeof path, "%s/%s", base, rel);
    snprintf(dir, sizeof dir, "%s", path);
    for (char *p = dir + strlen(base) + 1; *p; p++)
        if (*p == '/') {
            *p = 0;
            mkdir(dir, 0755);
            *p = '/';
        }
    FILE *f = fopen(path, "w");
    assert(f);
    fputs(text, f);
    fclose(f);
}

static void fifo(const char *rel) {
    char path[512];
    snprintf(path, sizeof path, "%s/%s", base, rel);
    char dir[512];
    snprintf(dir, sizeof dir, "%s/dev/input", base);
    mkdir(dir, 0755);
    unlink(path);
    assert(!mkfifo(path, 0600));
}

/* Bit 115 is bit 51 of word 1; bit 114 bit 50. */
#define CAP_UP "8000000000000 0\n"
#define CAP_DOWN "4000000000000 0\n"

static void device(const char *event, const char *name, const char *caps) {
    char rel[256];
    snprintf(rel, sizeof rel, "sys/class/input/%s/device/name", event);
    put(rel, name);
    snprintf(rel, sizeof rel, "sys/class/input/%s/device/capabilities/key", event);
    put(rel, caps);
    snprintf(rel, sizeof rel, "sys/class/input/%s/dev", event);
    put(rel, "13:65\n");
    snprintf(rel, sizeof rel, "dev/input/%s", event);
    fifo(rel);
}

static void world(void) {
    char cmd[300];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", base);
    assert(!system(cmd));
    mkdir(base, 0755);
    put("sys/class/input/mouse0/device/name", "gpio-keys\n");
    put("sys/class/input/input3/name", "gpio-keys\n");
    device("event0", "gpio-keys\n", CAP_UP);
    device("event12", "pmic_resin\n", CAP_DOWN);
    device("event2", "goodix_ts\n", "0\n");
}

static char sys_root[300], dev_root[300];

static void test_key_open(void) {
    struct m17_key_dev k;
    world();
    CHECK(m17_key_open(sys_root, dev_root, M17_UP_DEVICE, M17_KEY_VOLUMEUP, 0, &k) == 0 && k.fd >= 0 && k.code == M17_KEY_VOLUMEUP);
    CHECK(strstr(k.node, "/input/event0") && !strstr(k.node, "event0/"));
    close(k.fd);
    CHECK(m17_key_open(sys_root, dev_root, M17_DOWN_DEVICE, M17_KEY_VOLUMEDOWN, 0, &k) == 0 && strstr(k.node, "/input/event12"));
    close(k.fd);
    /* The name is exact, and the key must be the device's own. */
    CHECK(m17_key_open(sys_root, dev_root, "gpio-key", M17_KEY_VOLUMEUP, 0, &k) == -ENOENT && k.fd == -1);
    CHECK(m17_key_open(sys_root, dev_root, M17_UP_DEVICE, M17_KEY_VOLUMEDOWN, 0, &k) == -ENOENT);
    CHECK(m17_key_open(sys_root, dev_root, "goodix_ts", 0, 0, &k) == -ENOENT);
    /* A FIFO is no character device. */
    CHECK(m17_key_open(sys_root, dev_root, M17_UP_DEVICE, M17_KEY_VOLUMEUP, 1, &k) == -ENODEV && k.fd == -1);
    /* Two devices of the name with the key: ambiguous. */
    device("event7", "gpio-keys\n", "ffffffffffffffff ffffffffffffffff\n");
    CHECK(m17_key_open(sys_root, dev_root, M17_UP_DEVICE, M17_KEY_VOLUMEUP, 0, &k) == -EEXIST);
    /* Malformed bitmaps count as no key. */
    const char *bad[] = {"zz 0\n", "\n", "8000000000000\n", "8000000000000x 0\n", "1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1\n"};
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        world();
        put("sys/class/input/event0/device/capabilities/key", bad[i]);
        CHECK(m17_key_open(sys_root, dev_root, M17_UP_DEVICE, M17_KEY_VOLUMEUP, 0, &k) == -ENOENT);
    }
    /* The node missing. */
    world();
    char path[512];
    snprintf(path, sizeof path, "%s/dev/input/event0", base);
    unlink(path);
    CHECK(m17_key_open(sys_root, dev_root, M17_UP_DEVICE, M17_KEY_VOLUMEUP, 0, &k) == -ENOENT);
    /* No input class at all. */
    CHECK(m17_key_open("/nonexistent-m17", dev_root, M17_UP_DEVICE, M17_KEY_VOLUMEUP, 0, &k) == -ENOENT);
}

/* ---- The loop against FIFOs ---- */

static unsigned menu_calls, menu_fail_at;
static int menu(void *user, unsigned seconds) {
    (void)user;
    (void)seconds;
    menu_calls++;
    return menu_fail_at && menu_calls >= menu_fail_at ? -1 : 0;
}

enum feed { FEED_EVENTS, FEED_CLOSE, FEED_PARTIAL };

/* A writer on one FIFO: after delay_ms, the events, then held open (or closed, or a broken event). */
static pid_t writer(const char *event, unsigned delay_ms, const struct input_event *evs, size_t count, enum feed mode) {
    pid_t pid = fork();
    assert(pid >= 0);
    if (pid) return pid;
    alarm(10);
    char path[512];
    snprintf(path, sizeof path, "%s/dev/input/%s", base, event);
    int fd = open(path, O_WRONLY);
    if (fd < 0) _exit(70);
    usleep(delay_ms * 1000u);
    if (mode == FEED_PARTIAL) {
        if (write(fd, "\1\2\3\4\5", 5) != 5) _exit(71);
    } else if (count && write(fd, evs, count * sizeof *evs) != (ssize_t)(count * sizeof *evs)) {
        _exit(72);
    }
    if (mode == FEED_CLOSE) close(fd);
    for (;;) pause();
}

static void reap(pid_t pid) {
    if (pid > 0) {
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
    }
}

static struct input_event key(unsigned code, int value) {
    struct input_event e;
    memset(&e, 0, sizeof e);
    e.type = EV_KEY;
    e.code = (unsigned short)code;
    e.value = value;
    return e;
}

static struct input_event syn(unsigned code) {
    struct input_event e;
    memset(&e, 0, sizeof e);
    e.type = EV_SYN;
    e.code = (unsigned short)code;
    return e;
}

static enum m17_choice run(unsigned window_ms, struct m17_window *w, uint64_t *elapsed) {
    struct m17_loop l = {.sys_root = sys_root, .dev_root = dev_root, .window_ms = window_ms, .now_ms = m17_monotonic_ms, .menu = menu};
    uint64_t t0 = m17_monotonic_ms();
    enum m17_choice c = m17_run_window(&l, w);
    if (elapsed) *elapsed = m17_monotonic_ms() - t0;
    return c;
}

static void test_loop(void) {
    struct m17_window w;
    uint64_t elapsed;

    /* Volume Down pressed: native, soon after the press. */
    world();
    menu_calls = menu_fail_at = 0;
    struct input_event down[] = {key(M17_KEY_VOLUMEDOWN, 1), syn(SYN_REPORT)};
    pid_t p = writer("event12", 150, down, 2, FEED_EVENTS);
    CHECK(run(3000, &w, &elapsed) == M17_NATIVE && w.why == M17_WHY_VOLUME_DOWN && menu_calls >= 1 && elapsed < 1500);
    reap(p);

    /* Volume Up pressed: Android. */
    world();
    struct input_event up[] = {key(M17_KEY_VOLUMEUP, 1), syn(SYN_REPORT)};
    p = writer("event0", 100, up, 2, FEED_EVENTS);
    CHECK(run(3000, &w, NULL) == M17_ANDROID && w.why == M17_WHY_VOLUME_UP);
    reap(p);

    /* Nothing: Android when the window ends, not before, with a countdown each second. */
    world();
    menu_calls = 0;
    CHECK(run(2300, &w, &elapsed) == M17_ANDROID && w.why == M17_WHY_TIMEOUT && elapsed >= 2300 && elapsed < 2900);
    CHECK(menu_calls >= 3 && menu_calls <= 4);

    /* Repeats, a release, and another key's code on the Volume Down device: nothing chosen. */
    world();
    struct input_event noise[] = {key(M17_KEY_VOLUMEDOWN, 2), key(M17_KEY_VOLUMEDOWN, 0), key(M17_KEY_VOLUMEUP, 1), syn(SYN_REPORT)};
    p = writer("event12", 50, noise, 4, FEED_EVENTS);
    CHECK(run(600, &w, NULL) == M17_ANDROID && w.why == M17_WHY_TIMEOUT);
    reap(p);

    /* Volume Down released, then pressed: native. */
    world();
    struct input_event again[] = {key(M17_KEY_VOLUMEDOWN, 0), syn(SYN_REPORT), key(M17_KEY_VOLUMEDOWN, 1), syn(SYN_REPORT)};
    p = writer("event12", 50, again, 4, FEED_EVENTS);
    CHECK(run(3000, &w, NULL) == M17_NATIVE);
    reap(p);

    /* A key device missing: Android, and no menu shown. */
    world();
    menu_calls = 0;
    char path[512];
    snprintf(path, sizeof path, "%s/sys/class/input/event12/device/name", base);
    unlink(path);
    CHECK(run(3000, &w, &elapsed) == M17_ANDROID && w.why == M17_WHY_NO_KEYS && menu_calls == 0 && elapsed < 500);

    /* The menu fails at once, or at its second update. */
    world();
    menu_calls = 0;
    menu_fail_at = 1;
    CHECK(run(3000, &w, &elapsed) == M17_ANDROID && w.why == M17_WHY_NO_MENU && elapsed < 500);
    world();
    menu_calls = 0;
    menu_fail_at = 2;
    CHECK(run(3000, &w, &elapsed) == M17_ANDROID && w.why == M17_WHY_NO_MENU && elapsed < 1600);
    menu_fail_at = 0;

    /* A device that closes, a broken event and dropped events: Android. */
    world();
    p = writer("event12", 50, NULL, 0, FEED_CLOSE);
    CHECK(run(3000, &w, &elapsed) == M17_ANDROID && w.why == M17_WHY_READ_ERROR && elapsed < 1500);
    reap(p);
    world();
    p = writer("event0", 50, NULL, 0, FEED_PARTIAL);
    CHECK(run(3000, &w, &elapsed) == M17_ANDROID && w.why == M17_WHY_READ_ERROR && elapsed < 1500);
    reap(p);
    world();
    struct input_event dropped[] = {syn(SYN_DROPPED), key(M17_KEY_VOLUMEDOWN, 1)};
    p = writer("event12", 50, dropped, 2, FEED_EVENTS);
    CHECK(run(3000, &w, NULL) == M17_ANDROID && w.why == M17_WHY_READ_ERROR);
    reap(p);
}

int main(void) {
    snprintf(base, sizeof base, "%s/m17-select-%d", getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp", (int)getpid());
    snprintf(sys_root, sizeof sys_root, "%s/sys", base);
    snprintf(dev_root, sizeof dev_root, "%s/dev", base);
    test_normal_boot();
    test_window();
    test_key_open();
    test_loop();
    char cmd[300];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", base);
    if (system(cmd)) failures++;
    if (failures) {
        fprintf(stderr, "M17 selector tests: %d failed\n", failures);
        return 1;
    }
    printf("M17 selector tests PASS\n");
    return 0;
}
