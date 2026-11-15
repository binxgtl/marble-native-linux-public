/* M17 selector core: the boot mode, the window's state machine, the keys by name, and the window's loop
 * (select.h, docs/m17-dual-boot-selector.md). */
#define _GNU_SOURCE
#include "select.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/input.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <time.h>
#include <unistd.h>

const char *m17_choice_name(enum m17_choice choice) {
    switch (choice) {
    case M17_ANDROID: return "android";
    case M17_NATIVE: return "native";
    default: return "undecided";
    }
}

const char *m17_reason_name(enum m17_reason why) {
    switch (why) {
    case M17_WHY_MODE: return "mode";
    case M17_WHY_NO_KEYS: return "no-keys";
    case M17_WHY_NO_MENU: return "no-menu";
    case M17_WHY_TIMEOUT: return "timeout";
    case M17_WHY_VOLUME_UP: return "volume-up";
    case M17_WHY_VOLUME_DOWN: return "volume-down";
    case M17_WHY_BOTH: return "both";
    case M17_WHY_READ_ERROR: return "read-error";
    default: return "none";
    }
}

/* ---- The boot mode ---- */

/* The value of one key=value, without one pair of surrounding quotes. */
static void unquote(const char **v, size_t *n) {
    if (*n >= 2 && (*v)[0] == '"' && (*v)[*n - 1] == '"') {
        (*v)++;
        *n -= 2;
    }
}

static int is(const char *v, size_t n, const char *want) {
    return strlen(want) == n && !memcmp(v, want, n);
}

/* 0 when this key=value makes the boot not normal: androidboot.mode other than "normal", or androidboot.alarmboot
 * other than "false" or "0". Anything unexpected in either counts against a normal boot. */
static int pair_normal(const char *k, size_t kn, const char *v, size_t vn) {
    unquote(&v, &vn);
    if (is(k, kn, "androidboot.mode")) return is(v, vn, "normal");
    if (is(k, kn, "androidboot.alarmboot")) return is(v, vn, "false") || is(v, vn, "0");
    return 1;
}

/* The command line: words split by blanks outside double quotes. */
static int cmdline_normal(const char *s) {
    while (*s) {
        while (*s && isspace((unsigned char)*s)) s++;
        const char *start = s;
        int quoted = 0;
        while (*s && (quoted || !isspace((unsigned char)*s))) {
            if (*s == '"') quoted = !quoted;
            s++;
        }
        if (s == start) break;
        const char *eq = memchr(start, '=', (size_t)(s - start));
        if (eq && !pair_normal(start, (size_t)(eq - start), eq + 1, (size_t)(s - eq - 1))) return 0;
    }
    return 1;
}

/* The bootconfig: one "key = value" a line, blanks around both. */
static int bootconfig_normal(const char *s) {
    while (*s) {
        const char *end = strchr(s, '\n');
        if (!end) end = s + strlen(s);
        const char *eq = memchr(s, '=', (size_t)(end - s));
        if (eq) {
            const char *k = s, *ke = eq, *v = eq + 1, *ve = end;
            while (k < ke && isspace((unsigned char)*k)) k++;
            while (ke > k && isspace((unsigned char)ke[-1])) ke--;
            while (v < ve && isspace((unsigned char)*v)) v++;
            while (ve > v && isspace((unsigned char)ve[-1])) ve--;
            if (!pair_normal(k, (size_t)(ke - k), v, (size_t)(ve - v))) return 0;
        }
        s = *end ? end + 1 : end;
    }
    return 1;
}

int m17_normal_boot(const char *cmdline, const char *bootconfig) {
    return (!cmdline || cmdline_normal(cmdline)) && (!bootconfig || bootconfig_normal(bootconfig));
}

/* ---- The window ---- */

void m17_window_open(struct m17_window *w, uint64_t now_ms, unsigned window_ms, int up_held) {
    w->deadline_ms = now_ms + window_ms;
    w->up_down = up_held ? 1 : 0;
    w->choice = M17_UNDECIDED;
    w->why = M17_WHY_NONE;
}

static enum m17_choice decide(struct m17_window *w, enum m17_choice choice, enum m17_reason why) {
    if (w->choice == M17_UNDECIDED) {
        w->choice = choice;
        w->why = why;
    }
    return w->choice;
}

enum m17_choice m17_window_key(struct m17_window *w, unsigned code, int value) {
    if (w->choice != M17_UNDECIDED || (value != 0 && value != 1)) return w->choice;
    if (code == M17_KEY_VOLUMEUP) {
        w->up_down = value;
        if (value) return decide(w, M17_ANDROID, M17_WHY_VOLUME_UP);
    } else if (code == M17_KEY_VOLUMEDOWN && value == 1) {
        return w->up_down ? decide(w, M17_ANDROID, M17_WHY_BOTH) : decide(w, M17_NATIVE, M17_WHY_VOLUME_DOWN);
    }
    return w->choice;
}

enum m17_choice m17_window_tick(struct m17_window *w, uint64_t now_ms) {
    if (w->choice == M17_UNDECIDED && now_ms >= w->deadline_ms) return decide(w, M17_ANDROID, M17_WHY_TIMEOUT);
    return w->choice;
}

enum m17_choice m17_window_fail(struct m17_window *w, enum m17_reason why) {
    return decide(w, M17_ANDROID, why);
}

unsigned m17_window_left_ms(const struct m17_window *w, uint64_t now_ms) {
    return now_ms >= w->deadline_ms ? 0u : (unsigned)(w->deadline_ms - now_ms);
}

/* ---- The keys, by name ---- */

static int read_text(const char *path, char *buf, size_t room) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -errno;
    ssize_t n;
    do n = read(fd, buf, room - 1); while (n < 0 && errno == EINTR);
    int e = errno;
    close(fd);
    if (n < 0) return -e;
    buf[n] = 0;
    buf[strcspn(buf, "\n")] = 0;
    return 0;
}

/* sysfs's key bitmap: 64-bit hex words, the most significant first. 1 when `code` is set, 0 when not or malformed. */
static int bitmap_has(const char *text, unsigned code) {
    unsigned long long words[16];
    unsigned count = 0;
    const char *s = text;
    while (*s) {
        while (*s == ' ') s++;
        if (!*s) break;
        if (count == 16 || !isxdigit((unsigned char)*s)) return 0;
        char *end;
        errno = 0;
        words[count++] = strtoull(s, &end, 16);
        if (errno || (*end && *end != ' ')) return 0;
        s = end;
    }
    unsigned index = code / 64u;
    if (!count || index >= count) return 0;
    return (int)((words[count - 1u - index] >> (code % 64u)) & 1u);
}

static int event_entry(const char *name) {
    if (strncmp(name, "event", 5) || !name[5]) return 0;
    for (const char *p = name + 5; *p; p++)
        if (!isdigit((unsigned char)*p)) return 0;
    return strlen(name) < 16;
}

int m17_key_find(const char *sys_root, const char *name, unsigned code, char found[16]) {
    char dir[PATH_MAX], path[PATH_MAX], text[512];
    found[0] = 0;
    if (snprintf(dir, sizeof dir, "%s/class/input", sys_root) >= (int)sizeof dir) return -ENAMETOOLONG;
    DIR *d = opendir(dir);
    if (!d) return -errno;
    unsigned matches = 0;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (!event_entry(e->d_name)) continue;
        if (snprintf(path, sizeof path, "%s/%s/device/name", dir, e->d_name) >= (int)sizeof path || read_text(path, text, sizeof text) ||
            strcmp(text, name))
            continue;
        if (snprintf(path, sizeof path, "%s/%s/device/capabilities/key", dir, e->d_name) >= (int)sizeof path ||
            read_text(path, text, sizeof text) || !bitmap_has(text, code))
            continue;
        if (!matches++) memcpy(found, e->d_name, strlen(e->d_name) + 1); /* event_entry: under 16 bytes */
    }
    closedir(d);
    if (!matches) {
        found[0] = 0;
        return -ENOENT;
    }
    if (matches > 1) return -EEXIST;
    return 0;
}

/* The event node's device number, from <sys_root>/class/input/<event>/dev. */
static int event_number(const char *sys_root, const char *event, unsigned *maj, unsigned *min) {
    char path[PATH_MAX], text[64];
    if (snprintf(path, sizeof path, "%s/class/input/%s/dev", sys_root, event) >= (int)sizeof path || read_text(path, text, sizeof text) ||
        sscanf(text, "%u:%u", maj, min) != 2)
        return -ENODEV;
    return 0;
}

int m17_key_node(const char *sys_root, const char *dev_root, const char *event) {
    unsigned maj, min;
    char path[PATH_MAX];
    if (event_number(sys_root, event, &maj, &min)) return -ENODEV;
    if (snprintf(path, sizeof path, "%s/input", dev_root) >= (int)sizeof path) return -ENAMETOOLONG;
    if (mkdir(path, 0755) && errno != EEXIST) return -errno;
    if (snprintf(path, sizeof path, "%s/input/%s", dev_root, event) >= (int)sizeof path) return -ENAMETOOLONG;
    if (mknod(path, S_IFCHR | 0600, makedev(maj, min)) && errno != EEXIST) return -errno;
    return 0;
}

int m17_key_open(const char *sys_root, const char *dev_root, const char *name, unsigned code, int require_chr, struct m17_key_dev *out) {
    out->fd = -1;
    out->code = code;
    out->node[0] = 0;
    char found[16];
    int rc = m17_key_find(sys_root, name, code, found);
    if (rc) return rc;
    unsigned want_major = 0, want_minor = 0;
    if (require_chr && event_number(sys_root, found, &want_major, &want_minor)) return -ENODEV;
    if (snprintf(out->node, sizeof out->node, "%s/input/%s", dev_root, found) >= (int)sizeof out->node) return -ENAMETOOLONG;
    int fd = open(out->node, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return -errno;
    struct stat st;
    if (require_chr && (fstat(fd, &st) || !S_ISCHR(st.st_mode) || major(st.st_rdev) != want_major || minor(st.st_rdev) != want_minor)) {
        close(fd);
        return -ENODEV;
    }
    out->fd = fd;
    return 0;
}

/* ---- The loop ---- */

uint64_t m17_monotonic_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

/* Volume Up already down when the window opens. Unknown (the query fails) counts as up. */
static int key_down_now(int fd, unsigned code) {
    unsigned long bits[KEY_MAX / (8 * sizeof(unsigned long)) + 1];
    memset(bits, 0, sizeof bits);
    if (ioctl(fd, EVIOCGKEY(sizeof bits), bits) < 0) return 0;
    return (int)((bits[code / (8 * sizeof(unsigned long))] >> (code % (8 * sizeof(unsigned long)))) & 1u);
}

/* Every event waiting on one key device. Only that device's own key counts. 0, or -1 on a failure. */
static int drain(struct m17_window *w, const struct m17_key_dev *k) {
    for (;;) {
        struct input_event ev[16];
        ssize_t n = read(k->fd, ev, sizeof ev);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) return errno == EAGAIN ? 0 : -1;
        if (n == 0 || n % (ssize_t)sizeof ev[0]) return -1;
        for (size_t i = 0; i < (size_t)n / sizeof ev[0]; i++) {
            if (ev[i].type == EV_SYN && ev[i].code == SYN_DROPPED) return -1;
            if (ev[i].type == EV_KEY && ev[i].code == k->code && m17_window_key(w, k->code, ev[i].value) != M17_UNDECIDED) return 0;
        }
    }
}

enum m17_choice m17_run_window(const struct m17_loop *l, struct m17_window *w) {
    struct m17_key_dev up = {.fd = -1}, down = {.fd = -1};
    m17_window_open(w, l->now_ms(), l->window_ms, 0);
    if (m17_key_open(l->sys_root, l->dev_root, M17_UP_DEVICE, M17_KEY_VOLUMEUP, l->require_chr, &up) ||
        m17_key_open(l->sys_root, l->dev_root, M17_DOWN_DEVICE, M17_KEY_VOLUMEDOWN, l->require_chr, &down)) {
        m17_window_fail(w, M17_WHY_NO_KEYS);
        goto out;
    }
    unsigned shown = (l->window_ms + 999u) / 1000u;
    if (l->menu && l->menu(l->user, shown) < 0) {
        m17_window_fail(w, M17_WHY_NO_MENU);
        goto out;
    }
    m17_window_open(w, l->now_ms(), l->window_ms, key_down_now(up.fd, M17_KEY_VOLUMEUP));
    while (w->choice == M17_UNDECIDED) {
        uint64_t now = l->now_ms();
        if (m17_window_tick(w, now) != M17_UNDECIDED) break;
        unsigned left = m17_window_left_ms(w, now), seconds = (left + 999u) / 1000u;
        if (seconds != shown) {
            shown = seconds;
            if (l->menu && l->menu(l->user, seconds) < 0) {
                m17_window_fail(w, M17_WHY_NO_MENU);
                break;
            }
        }
        /* Wake at the next whole second for the countdown, and at the deadline. */
        unsigned wait = left % 1000u ? left % 1000u : 1000u;
        struct pollfd p[2] = {{.fd = up.fd, .events = POLLIN}, {.fd = down.fd, .events = POLLIN}};
        int n = poll(p, 2, (int)(wait < left ? wait : left));
        if (n < 0) {
            if (errno == EINTR) continue;
            m17_window_fail(w, M17_WHY_READ_ERROR);
            break;
        }
        const struct m17_key_dev *keys[2] = {&up, &down};
        for (int i = 0; i < 2 && w->choice == M17_UNDECIDED; i++) {
            if ((p[i].revents & POLLIN) && drain(w, keys[i])) m17_window_fail(w, M17_WHY_READ_ERROR);
            else if (!(p[i].revents & POLLIN) && (p[i].revents & (POLLERR | POLLHUP | POLLNVAL))) m17_window_fail(w, M17_WHY_READ_ERROR);
        }
    }
out:
    if (up.fd >= 0) close(up.fd);
    if (down.fd >= 0) close(down.fd);
    return w->choice;
}
