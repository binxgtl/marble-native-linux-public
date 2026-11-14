/* M17 G3 K1-keys (g3.h, docs/m17-g3.md). */
#define _GNU_SOURCE
#include "g3.h"
#include "select.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/input.h>
#include <poll.h>
#include <stdarg.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

__attribute__((format(printf, 2, 3))) static void say(const struct m17_g3 *g, const char *format, ...) {
    va_list a;
    va_start(a, format);
    vfprintf(g->out, format, a);
    va_end(a);
    fputc('\n', g->out);
    fflush(g->out);
}

/* Milliseconds from now until the one device of the name with the key appears, or -1 after `ms`. */
static long long wait_device(const struct m17_g3 *g, const char *name, unsigned code, unsigned ms, char event[16]) {
    uint64_t start = g->now_ms();
    for (;;) {
        int rc = m17_key_find(g->sys_root, name, code, event);
        uint64_t now = g->now_ms();
        if (rc == 0) return (long long)(now - start);
        event[0] = 0;
        if (rc == -EEXIST) {
            say(g, "M17 G3 ambiguous %s", name);
            return -1;
        }
        if (now - start >= ms) return -1;
        (void)poll(NULL, 0, (int)g->poll_ms);
    }
}

static int load_module(const struct m17_g3 *g, const char *name) {
    char path[PATH_MAX];
    if (snprintf(path, sizeof path, "%s/%s", g->modules_dir, name) >= (int)sizeof path) return -ENAMETOOLONG;
    int rc = g->load(path);
    say(g, "M17 G3 load %s rc=%d", name, rc);
    return rc;
}

struct key {
    const char *label;
    struct m17_key_dev dev;
    unsigned *press, *release;
};

/* Opens a found device, its node made first on the phone. */
static int open_key(const struct m17_g3 *g, struct key *k, const char *name, unsigned code, const char *event) {
    k->dev.fd = -1;
    if (!event[0]) return -ENOENT;
    if (g->make_nodes) {
        int rc = m17_key_node(g->sys_root, g->dev_root, event);
        if (rc) {
            say(g, "M17 G3 node %s %s rc=%d", k->label, event, rc);
            return rc;
        }
    }
    int rc = m17_key_open(g->sys_root, g->dev_root, name, code, g->require_chr, &k->dev);
    say(g, "M17 G3 open %s %s rc=%d", k->label, event, rc);
    return rc;
}

/* Every event waiting on one key. 0, or -1 on a read failure or dropped events. */
static int read_key(const struct m17_g3 *g, struct key *k, struct m17_window *w, uint64_t opened, struct m17_g3_result *r, uint64_t *last) {
    for (;;) {
        struct input_event ev[16];
        ssize_t n = read(k->dev.fd, ev, sizeof ev);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) return errno == EAGAIN ? 0 : -1;
        if (n == 0 || n % (ssize_t)sizeof ev[0]) return -1;
        uint64_t now = g->now_ms();
        for (size_t i = 0; i < (size_t)n / sizeof ev[0]; i++) {
            if (ev[i].type == EV_SYN && ev[i].code == SYN_DROPPED) return -1;
            if (ev[i].type != EV_KEY || ev[i].code != k->dev.code) continue;
            say(g, "M17 G3 event %s key=%u value=%d at_ms=%llu", k->label, k->dev.code, ev[i].value, (unsigned long long)(now - opened));
            r->events++;
            if (ev[i].value == 1) (*k->press)++;
            if (ev[i].value == 0) (*k->release)++;
            (void)m17_window_tick(w, now);
            (void)m17_window_key(w, k->dev.code, ev[i].value);
            *last = now;
        }
    }
}

static int up_down_now(int fd) {
    unsigned long bits[KEY_MAX / (8 * sizeof(unsigned long)) + 1];
    memset(bits, 0, sizeof bits);
    if (fd < 0 || ioctl(fd, EVIOCGKEY(sizeof bits), bits) < 0) return 0;
    return (int)((bits[M17_KEY_VOLUMEUP / (8 * sizeof(unsigned long))] >> (M17_KEY_VOLUMEUP % (8 * sizeof(unsigned long)))) & 1u);
}

int m17_g3_run(const struct m17_g3 *g, struct m17_g3_result *r) {
    memset(r, 0, sizeof *r);
    r->choice = M17_UNDECIDED;
    char up_event[16] = "", down_event[16] = "", power_event[16] = "";
    r->up_ready_ms = wait_device(g, M17_UP_DEVICE, M17_KEY_VOLUMEUP, g->up_wait_ms, up_event);
    r->reboot_mode_rc = load_module(g, "reboot-mode.ko");
    r->pon_rc = load_module(g, "qcom-pon.ko");
    r->down_ready_ms = wait_device(g, M17_DOWN_DEVICE, M17_KEY_VOLUMEDOWN, g->down_wait_ms, down_event);
    r->power_ready_ms = wait_device(g, M17_POWER_DEVICE, M17_KEY_POWER, 0, power_event);
    say(g, "M17 G3 devices up=%s up_ready_ms=%lld down=%s down_ready_ms=%lld power=%s", up_event[0] ? up_event : "none", r->up_ready_ms,
        down_event[0] ? down_event : "none", r->down_ready_ms, power_event[0] ? power_event : "none");

    struct key keys[3] = {
        {.label = "up", .press = &r->up_press, .release = &r->up_release},
        {.label = "down", .press = &r->down_press, .release = &r->down_release},
        {.label = "power", .press = &r->power_press, .release = &r->power_release},
    };
    r->up_found = !open_key(g, &keys[0], M17_UP_DEVICE, M17_KEY_VOLUMEUP, up_event);
    r->down_found = !open_key(g, &keys[1], M17_DOWN_DEVICE, M17_KEY_VOLUMEDOWN, down_event);
    r->power_found = !open_key(g, &keys[2], M17_POWER_DEVICE, M17_KEY_POWER, power_event);

    struct m17_window w;
    uint64_t opened = g->now_ms(), end = opened + g->window_ms, last = 0;
    m17_window_open(&w, opened, g->select_ms, up_down_now(keys[0].dev.fd));
    say(g, "M17 G3 window open ms=%u", g->window_ms);
    for (;;) {
        uint64_t now = g->now_ms();
        if (now >= end) break;
        if (r->up_press && r->up_release && r->down_press && r->down_release && now >= last + g->settle_ms) break;
        struct pollfd p[3];
        int which[3], count = 0;
        for (int i = 0; i < 3; i++)
            if (keys[i].dev.fd >= 0) {
                p[count] = (struct pollfd){.fd = keys[i].dev.fd, .events = POLLIN};
                which[count++] = i;
            }
        if (!count) break; /* no key at all: nothing to wait for */
        uint64_t left = end - now;
        int n = poll(p, (nfds_t)count, (int)(left < 100 ? left : 100));
        if (n < 0 && errno != EINTR) {
            r->read_error = 1;
            break;
        }
        for (int j = 0; j < count && n > 0; j++) {
            struct key *k = &keys[which[j]];
            int failed = (p[j].revents & POLLIN) ? read_key(g, k, &w, opened, r, &last) : (p[j].revents & (POLLERR | POLLHUP | POLLNVAL)) ? -1 : 0;
            if (failed) {
                say(g, "M17 G3 read-error %s", k->label);
                r->read_error = 1;
                close(k->dev.fd);
                k->dev.fd = -1;
            }
        }
    }
    (void)m17_window_tick(&w, g->now_ms());
    r->choice = w.choice;
    r->why = w.why;
    for (int i = 0; i < 3; i++)
        if (keys[i].dev.fd >= 0) close(keys[i].dev.fd);
    r->keys_ok = r->up_found && r->down_found && r->up_press && r->up_release && r->down_press && r->down_release && !r->read_error;
    say(g,
        "M17 G3 keys up_ready_ms=%lld down_ready_ms=%lld power_ready_ms=%lld reboot_mode_rc=%d pon_rc=%d up=%u/%u down=%u/%u power=%u/%u "
        "events=%u read_error=%d selector=%s/%s keys_ok=%d",
        r->up_ready_ms, r->down_ready_ms, r->power_ready_ms, r->reboot_mode_rc, r->pon_rc, r->up_press, r->up_release, r->down_press,
        r->down_release, r->power_press, r->power_release, r->events, r->read_error, m17_choice_name((enum m17_choice)r->choice),
        m17_reason_name((enum m17_reason)r->why), r->keys_ok);
    return r->keys_ok ? 0 : 1;
}
