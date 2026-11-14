/* M17 G5: the volume keys in the Ubuntu session (volkeys.h). */
#define _GNU_SOURCE
#include "volkeys.h"

#include "cmd.h"
#include "select.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/input.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define LOG_LIMIT (256 * 1024)

static enum m17_vk_action step_for(unsigned code)
{
    return code == M17_KEY_VOLUMEUP ? M17_VK_UP : M17_VK_DOWN;
}

void m17_vk_reset(struct m17_vk *v)
{
    v->up = v->down = 0;
    v->pending = v->held = 0;
    v->chord = 0;
    v->due_ms = 0;
}

void m17_vk_init(struct m17_vk *v, unsigned grace_ms, unsigned delay_ms, unsigned repeat_ms)
{
    v->grace_ms = grace_ms;
    v->delay_ms = delay_ms;
    v->repeat_ms = repeat_ms;
    m17_vk_reset(v);
}

enum m17_vk_action m17_vk_key(struct m17_vk *v, unsigned code, int value, uint64_t now_ms)
{
    if ((code != M17_KEY_VOLUMEUP && code != M17_KEY_VOLUMEDOWN) || (value != 0 && value != 1))
        return M17_VK_NONE;
    int *state = code == M17_KEY_VOLUMEUP ? &v->up : &v->down;
    int other = code == M17_KEY_VOLUMEUP ? v->down : v->up;
    if (value == 1) {
        if (*state)
            return M17_VK_NONE;
        *state = 1;
        if (v->chord)
            return M17_VK_NONE;
        if (other) {
            v->chord = 1;
            v->pending = v->held = 0;
            v->due_ms = 0;
            return M17_VK_SHOT;
        }
        v->pending = code;
        v->held = 0;
        v->due_ms = now_ms + v->grace_ms;
        return M17_VK_NONE;
    }
    if (!*state)
        return M17_VK_NONE;
    *state = 0;
    if (v->chord) {
        if (!v->up && !v->down)
            v->chord = 0;
        return M17_VK_NONE;
    }
    if (v->pending == code) {
        v->pending = 0;
        v->due_ms = 0;
        return step_for(code);
    }
    if (v->held == code) {
        v->held = 0;
        v->due_ms = 0;
    }
    return M17_VK_NONE;
}

enum m17_vk_action m17_vk_tick(struct m17_vk *v, uint64_t now_ms)
{
    if (v->chord || !v->due_ms || now_ms < v->due_ms)
        return M17_VK_NONE;
    if (v->pending) {
        unsigned code = v->pending;
        v->pending = 0;
        v->held = code;
        v->due_ms = now_ms + v->delay_ms;
        return step_for(code);
    }
    if (v->held) {
        v->due_ms = now_ms + v->repeat_ms;
        return step_for(v->held);
    }
    v->due_ms = 0;
    return M17_VK_NONE;
}

uint64_t m17_vk_due(const struct m17_vk *v)
{
    return v->chord ? 0 : v->due_ms;
}

int m17_vk_volume(int now, enum m17_vk_action action)
{
    if (now < 0)
        now = 0;
    int next = action == M17_VK_UP ? (now / 5 + 1) * 5 : action == M17_VK_DOWN ? ((now + 4) / 5 - 1) * 5 : now;
    return next < 0 ? 0 : next > 100 ? 100 : next;
}

int m17_vk_parse_volume(const char *text)
{
    const char *percent = strchr(text, '%');
    if (!percent)
        return -1;
    const char *digits = percent;
    while (digits > text && digits[-1] >= '0' && digits[-1] <= '9')
        digits--;
    if (digits == percent || percent - digits > 3)
        return -1;
    int value = 0;
    for (; digits < percent; digits++)
        value = value * 10 + (*digits - '0');
    return value;
}

/* The daemon. */

static uint64_t boot_ms(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_BOOTTIME, &t))
        return 0;
    return (uint64_t)t.tv_sec * 1000u + (uint64_t)t.tv_nsec / 1000000u;
}

__attribute__((format(printf, 2, 3))) static void note(const struct m17_volkeys *k, const char *format, ...)
{
    char line[200];
    va_list a;
    va_start(a, format);
    int n = vsnprintf(line, sizeof(line), format, a);
    va_end(a);
    if (n < 0)
        return;
    if ((size_t)n >= sizeof(line))
        n = (int)sizeof(line) - 1;
    char text[320];
    uint64_t now = boot_ms();
    snprintf(text, sizeof(text), "%llu.%03llu %s\n", (unsigned long long)(now / 1000), (unsigned long long)(now % 1000), line);
    (void)m17_append(k->log, text, LOG_LIMIT);
    int fd = open(k->kmsg, O_WRONLY | O_CLOEXEC);
    if (fd >= 0) {
        char record[260];
        int r = snprintf(record, sizeof(record), "<6>M17KEYS %s\n", line);
        (void)!write(fd, record, (size_t)(r < (int)sizeof(record) ? r : (int)sizeof(record) - 1));
        close(fd);
    }
}

static void volume(const struct m17_volkeys *k, enum m17_vk_action action)
{
    char out[1024];
    const char *get[] = {k->pactl, "get-sink-volume", "@DEFAULT_SINK@", NULL};
    int rc = m17_run(get, k->pulse_env, out, sizeof(out), k->command_ms);
    int now = rc ? -1 : m17_vk_parse_volume(out);
    if (now < 0) {
        note(k, "%s volume=unknown rc=%d", action == M17_VK_UP ? "up" : "down", rc);
        return;
    }
    int next = m17_vk_volume(now, action);
    char level[16];
    snprintf(level, sizeof(level), "%d%%", next);
    if (action == M17_VK_UP) {
        const char *unmute[] = {k->pactl, "set-sink-mute", "@DEFAULT_SINK@", "0", NULL};
        (void)m17_run(unmute, k->pulse_env, out, sizeof(out), k->command_ms);
    }
    const char *set[] = {k->pactl, "set-sink-volume", "@DEFAULT_SINK@", level, NULL};
    rc = m17_run(set, k->pulse_env, out, sizeof(out), k->command_ms);
    note(k, "%s volume=%d->%d rc=%d", action == M17_VK_UP ? "up" : "down", now, next, rc);
}

static pid_t shoot(const struct m17_volkeys *k, pid_t running)
{
    if (running > 0 && waitpid(running, NULL, WNOHANG) == 0) {
        note(k, "shot skipped: the last one still runs");
        return running;
    }
    if (mkdir(k->shots, 0755) && errno != EEXIST) {
        note(k, "shot directory errno=%d", errno);
        return -1;
    }
    pid_t pid = fork();
    if (pid == 0) {
        int null = open("/dev/null", O_RDWR | O_CLOEXEC);
        if (null < 0 || dup2(null, 0) < 0 || dup2(null, 1) < 0 || dup2(null, 2) < 0)
            _exit(126);
        /* The session's bus, when the session left its address (gpu-session writes it). */
        static char bus[512];
        const char *env[24];
        unsigned count = 0;
        for (; k->x_env[count] && count < 22; count++)
            env[count] = k->x_env[count];
        int fd = open(k->session_bus, O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            static const char head[] = "DBUS_SESSION_BUS_ADDRESS=";
            memcpy(bus, head, sizeof(head) - 1);
            ssize_t got = read(fd, bus + sizeof(head) - 1, sizeof(bus) - sizeof(head));
            if (got > 0) {
                bus[sizeof(head) - 1 + (size_t)got] = 0;
                bus[strcspn(bus, "\n")] = 0;
                env[count++] = bus;
            }
        }
        env[count] = NULL;
        const char *argv[] = {k->shooter, "-f", "-s", k->shots, NULL};
        execve(argv[0], (char *const *)argv, (char *const *)env);
        _exit(127);
    }
    note(k, "shot pid=%d", (int)pid);
    return pid;
}

static int open_key(const struct m17_volkeys *k, const char *name, unsigned code, struct m17_key_dev *dev)
{
    char event[16];
    int rc = m17_key_find(k->sys, name, code, event);
    if (!rc && k->make_nodes)
        rc = m17_key_node(k->sys, k->dev, event);
    if (!rc)
        rc = m17_key_open(k->sys, k->dev, name, code, k->make_nodes, dev);
    return rc;
}

int m17_volkeys_main(const struct m17_volkeys *k)
{
    signal(SIGPIPE, SIG_IGN);
    if (mkdir(k->dev, 0700) && errno != EEXIST)
        return 1;
    struct m17_key_dev up = {.fd = -1}, down = {.fd = -1};
    uint64_t end = boot_ms() + k->find_ms;
    int rc_up = -1, rc_down = -1;
    for (;;) {
        if (up.fd < 0)
            rc_up = open_key(k, M17_UP_DEVICE, M17_KEY_VOLUMEUP, &up);
        if (down.fd < 0)
            rc_down = open_key(k, M17_DOWN_DEVICE, M17_KEY_VOLUMEDOWN, &down);
        if (up.fd >= 0 && down.fd >= 0)
            break;
        if (boot_ms() >= end) {
            note(k, "keys missing up=%d down=%d", rc_up, rc_down);
            if (up.fd >= 0)
                close(up.fd);
            if (down.fd >= 0)
                close(down.fd);
            return 1;
        }
        (void)poll(NULL, 0, 200);
    }
    note(k, "ready up=%s down=%s", strrchr(up.node, '/') + 1, strrchr(down.node, '/') + 1);
    struct m17_vk v;
    m17_vk_init(&v, 120, 400, 150);
    pid_t shooter = -1;
    for (;;) {
        uint64_t now = boot_ms(), due = m17_vk_due(&v);
        int timeout = due ? (due > now ? (int)(due - now) : 0) : 1000;
        struct pollfd p[2] = {{.fd = up.fd, .events = POLLIN}, {.fd = down.fd, .events = POLLIN}};
        int ready = poll(p, 2, timeout);
        if (ready < 0 && errno != EINTR)
            break;
        int lost = 0;
        for (int i = 0; i < 2 && ready > 0; i++) {
            if (!p[i].revents)
                continue;
            struct input_event events[16];
            ssize_t got = read(p[i].fd, events, sizeof(events));
            if (got < 0 && (errno == EAGAIN || errno == EINTR))
                continue;
            if (got <= 0 || got % (ssize_t)sizeof(events[0])) {
                lost = 1;
                continue;
            }
            for (size_t e = 0; e < (size_t)got / sizeof(events[0]); e++) {
                if (events[e].type == EV_SYN && events[e].code == SYN_DROPPED) {
                    m17_vk_reset(&v);
                    continue;
                }
                if (events[e].type != EV_KEY)
                    continue;
                enum m17_vk_action action = m17_vk_key(&v, events[e].code, events[e].value, boot_ms());
                if (action == M17_VK_SHOT)
                    shooter = shoot(k, shooter);
                else if (action != M17_VK_NONE)
                    volume(k, action);
            }
        }
        if (lost)
            break;
        enum m17_vk_action action = m17_vk_tick(&v, boot_ms());
        if (action != M17_VK_NONE)
            volume(k, action);
        while (waitpid(-1, NULL, WNOHANG) > 0) {
        }
    }
    note(k, "keys lost");
    close(up.fd);
    close(down.fd);
    return 1;
}
