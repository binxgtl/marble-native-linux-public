/* The R2 reporter. systemd starts it early; it waits for the boot to settle, gathers the
 * evidence, judges it, sends it over the serial line with a hash, then paints the verdict.
 * It only reads: systemd's state, the journal, the kernel log, /proc and /sys. */
#define _GNU_SOURCE
#include "r2.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../unlock/core.h"

#define REPORT_CAP (1536u * 1024u) /* about two minutes at the proven pace */
#define JOURNAL_CAP (768u * 1024u)
#define KERNEL_CAP (384u * 1024u)
#define SECTION_CAP (64u * 1024u)
#define GREEN "0000ff00"
#define YELLOW "00ffff00"

static unsigned char report[REPORT_CAP];
static size_t used;

static void add(const void *data, size_t size)
{
    if (size > REPORT_CAP - used)
        size = REPORT_CAP - used;
    memcpy(report + used, data, size);
    used += size;
}

__attribute__((format(printf, 1, 2)))
static void addf(const char *format, ...)
{
    char text[512];
    va_list arguments;
    va_start(arguments, format);
    int n = vsnprintf(text, sizeof(text), format, arguments);
    va_end(arguments);
    if (n > 0)
        add(text, (size_t)n < sizeof(text) ? (size_t)n : sizeof(text) - 1);
}

/* Runs argv with stdout and stderr into out, keeping at most cap bytes and draining the rest. env, when
 * set, adds NAME=value strings in the child only. Returns the wait status, or -1 when it could not run or
 * overran ms and was killed. */
static int capture_env(char *const argv[], const char *const env[], unsigned char *out, size_t cap, size_t *taken, unsigned ms)
{
    int pipe_fd[2];
    *taken = 0;
    if (pipe2(pipe_fd, O_CLOEXEC))
        return -1;
    pid_t pid = fork();
    if (pid == 0) {
        int null = open("/dev/null", O_RDONLY);
        if (null < 0 || dup2(null, 0) < 0 || dup2(pipe_fd[1], 1) < 0 || dup2(pipe_fd[1], 2) < 0)
            _exit(126);
        for (unsigned i = 0; env && env[i]; i++)
            if (putenv((char *)env[i]))
                _exit(126);
        execv(argv[0], argv);
        _exit(127);
    }
    close(pipe_fd[1]);
    if (pid < 0 || fcntl(pipe_fd[0], F_SETFL, O_NONBLOCK)) {
        close(pipe_fd[0]);
        if (pid > 0) {
            (void)kill(pid, SIGKILL);
            (void)waitpid(pid, NULL, 0);
        }
        return -1;
    }
    unsigned long long end = m19_now_ms() + ms;
    int open_pipe = 1, exited = 0, status = -1;
    while (open_pipe || !exited) {
        if (m19_now_ms() >= end) {
            if (!exited) {
                (void)kill(pid, SIGKILL);
                /* A child stuck in the kernel, as a GPU call can be, cannot die at once. Wait a while, never forever. */
                for (unsigned i = 0; i < 200 && waitpid(pid, NULL, WNOHANG) == 0; i++)
                    (void)poll(NULL, 0, 10);
            }
            status = -1;
            break;
        }
        if (open_pipe) {
            struct pollfd p = {pipe_fd[0], POLLIN, 0};
            (void)poll(&p, 1, 10);
            unsigned char chunk[4096];
            ssize_t n = read(pipe_fd[0], chunk, sizeof(chunk));
            if (n > 0) {
                size_t keep = (size_t)n < cap - *taken ? (size_t)n : cap - *taken;
                memcpy(out + *taken, chunk, keep);
                *taken += keep;
            } else if (n == 0 || (errno != EAGAIN && errno != EINTR)) {
                open_pipe = 0;
            }
        } else {
            (void)poll(NULL, 0, 10);
        }
        if (!exited && waitpid(pid, &status, WNOHANG) == pid)
            exited = 1;
    }
    close(pipe_fd[0]);
    return status;
}

static int capture(char *const argv[], unsigned char *out, size_t cap, size_t *taken, unsigned ms)
{
    return capture_env(argv, NULL, out, cap, taken, ms);
}

/* A section of the report: the environment it adds and the command line, then what it printed, then its
 * status. *start and *length, when wanted, say where the output sits in the report. */
static int section_env(char *const argv[], const char *const env[], size_t cap, unsigned ms, size_t *start, size_t *length)
{
    addf("M19 $");
    for (unsigned i = 0; env && env[i]; i++)
        addf(" %s", env[i]);
    for (unsigned i = 0; argv[i]; i++)
        addf(" %s", argv[i]);
    addf("\n");
    size_t room = REPORT_CAP - used, limit = cap < room ? cap : room, taken = 0;
    if (start)
        *start = used;
    int status = capture_env(argv, env, report + used, limit, &taken, ms);
    used += taken;
    if (length)
        *length = taken;
    if (taken == limit)
        addf("\nM19 output truncated at %zu bytes", limit);
    addf("\nM19 status %d\n", status);
    return status;
}

static int section(char *const argv[], size_t cap, unsigned ms)
{
    return section_env(argv, NULL, cap, ms, NULL, NULL);
}

static size_t add_file(const char *path, size_t cap)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    size_t start = used;
    if (fd < 0) {
        addf("M19 cannot open %s errno=%d\n", path, errno);
        return 0;
    }
    while (used - start < cap && used < REPORT_CAP) {
        /* /dev/kmsg hands out one record a read and wants room for a whole one. */
        size_t room = REPORT_CAP - used;
        if (room < 8192 || cap - (used - start) < 8192)
            break;
        ssize_t n = read(fd, report + used, 8192);
        if (n < 0 && (errno == EINTR || errno == EPIPE))
            continue;
        if (n <= 0)
            break;
        used += (size_t)n;
    }
    close(fd);
    return used - start;
}

/* A text file without its lines that hold drop, kept until the first line that would pass cap bytes; then how
 * many lines were left out, and whether the cap cut it.
 * R4b's and R4d's Xorg logs lost the GPU phase to a flood of one touch message. */
static long add_file_without(const char *path, size_t cap, const char *drop)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        addf("M19 cannot open %s errno=%d\n", path, errno);
        return -1;
    }
    static char piece[16384];
    size_t have = 0, start = used, size = strlen(drop);
    long dropped = 0;
    int full = 0;
    for (;;) {
        ssize_t n = read(fd, piece + have, sizeof(piece) - have);
        if (n < 0 && errno == EINTR)
            continue;
        int end = n <= 0;
        if (!end)
            have += (size_t)n;
        size_t at = 0;
        while (at < have) {
            char *newline = memchr(piece + at, '\n', have - at);
            /* A whole line; at the end, what is left; a line longer than the piece goes in pieces. */
            size_t line = newline ? (size_t)(newline - (piece + at)) + 1 : ((end || (!at && have == sizeof(piece))) ? have - at : 0);
            if (!line)
                break;
            if (memmem(piece + at, line, drop, size))
                dropped++;
            else if (!full && used - start + line <= cap)
                add(piece + at, line);
            else
                full = 1;
            at += line;
        }
        memmove(piece, piece + at, have - at);
        have -= at;
        if (end)
            break;
    }
    close(fd);
    addf("M19 left out %ld lines holding \"%s\"%s\n", dropped, drop, full ? ", cut at the cap" : "");
    return dropped;
}

static void first_word(const unsigned char *text, size_t size, char *word, size_t room)
{
    size_t n = 0;
    while (n < size && n < room - 1 && ((text[n] >= 'a' && text[n] <= 'z') || text[n] == '-'))
        n++;
    if (n == 0 || (n < size && text[n] != '\n')) {
        snprintf(word, room, "invalid");
        return;
    }
    memcpy(word, text, n);
    word[n] = 0;
}

static int settled(const char *state)
{
    return !strcmp(state, "running") || !strcmp(state, "degraded") || !strcmp(state, "maintenance") || !strcmp(state, "stopping") ||
           !strcmp(state, "offline");
}

static int read_small(const char *path, char *text, size_t room)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    ssize_t n = read(fd, text, room - 1);
    close(fd);
    if (n < 0)
        return -1;
    text[n] = 0;
    return 0;
}

/* Zero writes, sectors written and discards, and the read-only flag, for one disk or partition. */
static int block_entry(const char *directory, const char *name, int *ro_ok)
{
    char path[1100], text[512], flag[16];
    snprintf(path, sizeof(path), "%s/stat", directory);
    if (read_small(path, text, sizeof(text))) {
        addf("M19 R2 block %s stat unreadable\n", name);
        return 0;
    }
    unsigned long long field[17] = {0};
    int count = 0;
    char *cursor = text;
    while (count < 17) {
        char *end;
        errno = 0;
        unsigned long long value = strtoull(cursor, &end, 10);
        if (end == cursor || errno)
            break;
        field[count++] = value;
        cursor = end;
    }
    snprintf(path, sizeof(path), "%s/ro", directory);
    int ro = !read_small(path, flag, sizeof(flag)) && !strcmp(flag, "1\n");
    addf("M19 R2 block %s writes=%llu sectors=%llu discards=%llu discarded=%llu ro=%d\n", name, field[4], field[6], field[11], field[13], ro);
    if (!ro)
        *ro_ok = 0;
    return count >= 7 && !field[4] && !field[6] && !field[11] && !field[13];
}

/* Every sd disk and dm device, and every partition of an sd disk, must be unwritten and read-only. */
static void check_blocks(const char *block, int *writes_ok, int *ro_ok)
{
    DIR *directory = opendir(block);
    int disks = 0;
    *writes_ok = *ro_ok = 1;
    if (!directory) {
        *writes_ok = *ro_ok = 0;
        addf("M19 R2 no %s\n", block);
        return;
    }
    struct dirent *entry;
    while ((entry = readdir(directory))) {
        const char *name = entry->d_name;
        int disk = !strncmp(name, "sd", 2);
        if (!disk && strncmp(name, "dm-", 3))
            continue;
        char path[1024];
        snprintf(path, sizeof(path), "%s/%s", block, name);
        if (!block_entry(path, name, ro_ok))
            *writes_ok = 0;
        if (!disk)
            continue;
        disks++;
        DIR *parts = opendir(path);
        if (!parts) {
            *ro_ok = 0;
            continue;
        }
        struct dirent *part;
        while ((part = readdir(parts))) {
            if (strncmp(part->d_name, name, strlen(name)) || !part->d_name[strlen(name)])
                continue;
            char inner[1300], flag[16];
            snprintf(inner, sizeof(inner), "%s/%s/ro", path, part->d_name);
            if (read_small(inner, flag, sizeof(flag)) || strcmp(flag, "1\n")) {
                addf("M19 R2 partition %s writable\n", part->d_name);
                *ro_ok = 0;
            }
        }
        closedir(parts);
    }
    closedir(directory);
    if (!disks) {
        addf("M19 R2 no disk\n");
        *writes_ok = 0;
    }
}

static const char *const rw_allowed[] = {"tmpfs", "proc", "sysfs", "devpts", "cgroup", "cgroup2", "securityfs", "debugfs", "tracefs", "configfs",
                                         "selinuxfs", "pstore", "bpf", "mqueue", "hugetlbfs", "fusectl", "binfmt_misc", "ramfs", "functionfs",
                                         "efivarfs", "autofs", "rpc_pipefs", "nsfs", NULL};

static int starts_ro(const char *options)
{
    return !strncmp(options, "ro", 2) && (options[2] == ',' || options[2] == 0);
}

/* Any filesystem that is not RAM or a kernel view must be read-only at the mount and the
 * superblock, and / must be the f2fs root. */
static int check_mounts(const char *mountinfo)
{
    FILE *file = fopen(mountinfo, "re");
    if (!file) {
        addf("M19 R2 cannot open %s\n", mountinfo);
        return 0;
    }
    char line[4096];
    int ok = 1, root = 0, lines = 0;
    while (fgets(line, sizeof(line), file)) {
        char *field[32];
        int count = 0, separator = -1;
        for (char *token = strtok(line, " \n"); token && count < 32; token = strtok(NULL, " \n")) {
            if (separator < 0 && !strcmp(token, "-"))
                separator = count;
            field[count++] = token;
        }
        if (separator < 6 || count < separator + 4) {
            ok = 0;
            continue;
        }
        lines++;
        const char *point = field[4], *options = field[5], *type = field[separator + 1], *super = field[separator + 3];
        int allowed = 0;
        for (unsigned i = 0; rw_allowed[i]; i++)
            allowed |= !strcmp(type, rw_allowed[i]);
        if (!strcmp(point, "/"))
            root = !strcmp(type, "f2fs") && starts_ro(options) && starts_ro(super);
        if (allowed)
            continue;
        if (!starts_ro(options) || !starts_ro(super)) {
            addf("M19 R2 writable mount %s %s\n", point, type);
            ok = 0;
        }
    }
    fclose(file);
    if (!root)
        addf("M19 R2 root is not the read-only f2fs bind\n");
    return ok && root && lines > 0;
}

/* DRM_IOCTL_WAIT_VBLANK, from include/uapi/drm/drm.h: stable ABI, defined here so no libdrm is needed. */
union m19_wait_vblank {
    struct { uint32_t type, sequence; unsigned long signal; } request;
    struct { uint32_t type, sequence; long sec, usec; } reply;
};
#define M19_WAIT_VBLANK _IOWR('d', 0x3a, union m19_wait_vblank)
#define M19_VBLANK_RELATIVE 0x1u
#define M19_VBLANK_HIGH_CRTC_SHIFT 1
#define M19_VBLANK_FRAMES 60u

int m19_vblank_rate(const char *card, double *hz)
{
    int fd = open(card, O_RDWR | O_CLOEXEC);
    if (fd < 0)
        return -1;
    for (unsigned crtc = 0; crtc < 2; crtc++) {
        union m19_wait_vblank v;
        memset(&v, 0, sizeof(v));
        v.request.type = M19_VBLANK_RELATIVE | (crtc << M19_VBLANK_HIGH_CRTC_SHIFT);
        v.request.sequence = 1;
        if (ioctl(fd, M19_WAIT_VBLANK, &v))
            continue;
        uint32_t first = v.reply.sequence;
        double start = (double)v.reply.sec + (double)v.reply.usec / 1e6;
        memset(&v, 0, sizeof(v));
        v.request.type = M19_VBLANK_RELATIVE | (crtc << M19_VBLANK_HIGH_CRTC_SHIFT);
        v.request.sequence = M19_VBLANK_FRAMES;
        if (ioctl(fd, M19_WAIT_VBLANK, &v))
            continue;
        double stop = (double)v.reply.sec + (double)v.reply.usec / 1e6;
        if (v.reply.sequence > first && stop > start) {
            *hz = (double)(v.reply.sequence - first) / (stop - start);
            close(fd);
            return (int)crtc;
        }
    }
    close(fd);
    return -1;
}

struct desktop {
    int x_ok, session_ok, mode_ok, vblank_ok, touch_ok, touch_device, events, crtc;
    long irq_delta;
    double xrandr_hz, vblank_hz;
    char mode[48];
};

static int run_quiet(const struct m19_report *c, char *const argv[], unsigned char *out, size_t cap, size_t *taken)
{
    size_t ignored;
    return capture(argv, out, cap, taken ? taken : &ignored, c->command_ms);
}

static int x_alive(const struct m19_report *c)
{
    unsigned char out[256];
    char *argv[] = {(char *)c->xdpyinfo, "-queryExtensions", NULL};
    return run_quiet(c, argv, out, sizeof(out), NULL) == 0;
}

/* The three XFCE pieces a desktop needs, found by comm in /proc. */
static int session_alive(const struct m19_report *c)
{
    static const char *const want[] = {"xfwm4", "xfce4-panel", "xfdesktop"};
    int seen[3] = {0, 0, 0};
    DIR *directory = opendir(c->proc);
    if (!directory)
        return 0;
    struct dirent *entry;
    while ((entry = readdir(directory))) {
        if (entry->d_name[0] < '1' || entry->d_name[0] > '9')
            continue;
        char path[512], comm[32];
        snprintf(path, sizeof(path), "%s/%s/comm", c->proc, entry->d_name);
        if (read_small(path, comm, sizeof(comm)))
            continue;
        comm[strcspn(comm, "\n")] = 0;
        for (unsigned i = 0; i < 3; i++)
            seen[i] |= !strcmp(comm, want[i]);
    }
    closedir(directory);
    return seen[0] && seen[1] && seen[2];
}

/* The current mode of xrandr's first connected output: the line whose rate carries '*'. */
static void xrandr_mode(const struct m19_report *c, struct desktop *d)
{
    static char out[16384];
    size_t taken = 0;
    char *argv[] = {(char *)c->xrandr, "--query", NULL};
    d->xrandr_hz = 0;
    snprintf(d->mode, sizeof(d->mode), "none");
    if (run_quiet(c, argv, (unsigned char *)out, sizeof(out) - 1, &taken))
        return;
    out[taken] = 0;
    for (char *line = strtok(out, "\n"); line; line = strtok(NULL, "\n")) {
        if (line[0] != ' ' || !strchr(line, '*'))
            continue;
        char name[48] = "";
        if (sscanf(line, " %47s", name) != 1)
            continue;
        for (char *token = line + strspn(line, " ") + strlen(name); *token;) {
            char *end;
            double rate = strtod(token, &end);
            if (end == token) {
                token++;
                continue;
            }
            if (*end == '*') {
                d->xrandr_hz = rate;
                snprintf(d->mode, sizeof(d->mode), "%s", name);
                return;
            }
            token = end;
        }
    }
}

/* Interrupts counted on every CPU for the line whose name is the touch device's. */
static long touch_irqs(const struct m19_report *c)
{
    FILE *file = fopen(c->interrupts, "re");
    if (!file)
        return -1;
    char line[4096];
    long total = -1;
    size_t name = strlen(c->touch_name);
    while (fgets(line, sizeof(line), file)) {
        size_t n = strcspn(line, "\n");
        line[n] = 0;
        if (n <= name || strcmp(line + n - name, c->touch_name) || line[n - name - 1] != ' ')
            continue;
        char *cursor = strchr(line, ':');
        if (!cursor)
            continue;
        total = 0;
        for (cursor++;;) {
            char *end;
            long value = strtol(cursor, &end, 10);
            if (end == cursor)
                break;
            total += value;
            cursor = end;
        }
        break;
    }
    fclose(file);
    return total;
}

static int count_text(const char *text, const char *needle)
{
    int count = 0;
    for (const char *at = text; (at = strstr(at, needle)); at += strlen(needle))
        count++;
    return count;
}

static void desktop_phase(const struct m19_report *c, int tty, struct desktop *d)
{
    memset(d, 0, sizeof(*d));
    d->crtc = -1;
    unsigned long long start = m19_now_ms(), end = start + c->x_wait_ms, beat = start + c->beat_ms;
    while (!(d->x_ok = x_alive(c)) && m19_now_ms() < end) {
        if (m19_now_ms() >= beat) {
            (void)m19_wire_line(tty, c->pace_ms, M19_DEVICE_BEAT " T12-desktop %llu x", (m19_now_ms() - start) / 1000);
            beat = m19_now_ms() + c->beat_ms;
        }
        (void)poll(NULL, 0, (int)c->poll_ms);
    }
    end = m19_now_ms() + c->session_wait_ms;
    while (d->x_ok && !(d->session_ok = session_alive(c)) && m19_now_ms() < end) {
        if (m19_now_ms() >= beat) {
            (void)m19_wire_line(tty, c->pace_ms, M19_DEVICE_BEAT " T12-desktop %llu session", (m19_now_ms() - start) / 1000);
            beat = m19_now_ms() + c->beat_ms;
        }
        (void)poll(NULL, 0, (int)c->poll_ms);
    }
    (void)m19_wire_line(tty, c->pace_ms, M19_DEVICE_STEP " T12-desktop %s %d %d", d->x_ok && d->session_ok ? "OK" : "FAIL", d->x_ok,
                        d->session_ok);
    if (!d->x_ok)
        return;
    xrandr_mode(c, d);
    d->mode_ok = d->xrandr_hz > c->want_hz - 1.0 && d->xrandr_hz < c->want_hz + 1.0;
    d->crtc = m19_vblank_rate(c->card, &d->vblank_hz);
    d->vblank_ok = d->crtc >= 0 && d->vblank_hz > c->want_hz * 0.96 && d->vblank_hz < c->want_hz * 1.04;

    static char list[8192], events[65536];
    size_t taken = 0;
    char *names[] = {(char *)c->xinput, "list", "--name-only", NULL};
    if (!run_quiet(c, names, (unsigned char *)list, sizeof(list) - 1, &taken)) {
        list[taken] = 0;
        for (char *line = strtok(list, "\n"); line; line = strtok(NULL, "\n"))
            d->touch_device |= !strcmp(line, c->touch_name);
    }
    /* The operator touches the screen in this window. Events are counted twice: by the
     * touch controller's interrupt line and by X itself. */
    long before = touch_irqs(c);
    (void)m19_wire_line(tty, c->pace_ms, M19_DEVICE_STEP " T12-touch START %u", c->touch_ms / 1000);
    char *watch[] = {(char *)c->xinput, "test-xi2", "--root", NULL};
    taken = 0;
    (void)capture(watch, (unsigned char *)events, sizeof(events) - 1, &taken, c->touch_ms);
    events[taken] = 0;
    long after = touch_irqs(c);
    d->irq_delta = before >= 0 && after >= 0 ? after - before : -1;
    /* (R4h) Updates and motion too: a swipe begun before the window gives no begin event. */
    d->events = count_text(events, "(TouchBegin)") + count_text(events, "(RawTouchBegin)") + count_text(events, "(ButtonPress)") +
                count_text(events, "(RawButtonPress)") + count_text(events, "(TouchUpdate)") + count_text(events, "(RawTouchUpdate)") +
                count_text(events, "(Motion)") + count_text(events, "(RawMotion)");
    d->touch_ok = d->touch_device && d->irq_delta > 0 && d->events > 0;
    (void)m19_wire_line(tty, c->pace_ms, M19_DEVICE_STEP " T12-touch END %ld %d", d->irq_delta, d->events);
}

/* R4e: one view of the screen. Who composites, whether xfwm4 has Mesa's GL mapped, what the CRTC scans out
 * and how often that changes, and what the X server holds for the whole screen. */
struct view {
    long owner, fb, fbs, changes, pitch, nonblack, mean;
    int owner_ok, gl, crtc_ok, root_ok;
};

struct gpu {
    int node, probe, vk, cube, gl, gears, egl, glamor_init, glamor_on, xorg_unit, glamor_ok, flip_ok, copy_ok, compositor_ok, vblank_ok, scanout_ok,
        on_rc, off_rc;
    long cube_ms, glmark2, copy_done, copies, flip_done, flips, late, composited_done, composited_copies, composited_flips;
    double cube_fps, gears_fps, xorg_cpu, copy_msc, copy_us, flip_msc, flip_us, gears_full_fps, wait_seq, wait_us, event_seq, event_us,
        composited_msc, composited_cube_fps;
    struct view view[3];
    char model[64], probe_device[96], device[96], renderer[160], egl_renderer[160], profile[16], glamor_renderer[160], copy_renderer[160];
};
static const char *const view_names[3] = {"session", "on", "off"};

/* A whole small file as text; -1 when it cannot be read. */
static long file_text(const char *path, char *text, size_t room)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    size_t n = 0;
    for (;;) {
        ssize_t got = read(fd, text + n, room - 1 - n);
        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0)
            break;
        n += (size_t)got;
        if (n == room - 1)
            break;
    }
    close(fd);
    text[n] = 0;
    return (long)n;
}

/* The summary line of one Present probe run: completions, copies, flips, MSCs and microseconds per frame. */
static void present_line(const char *text, const char *mode, long *done, long *copies, long *flips, double *msc, double *us)
{
    char key[32];
    snprintf(key, sizeof(key), "M19 PRESENT %s frames=", mode);
    const char *at = strstr(text, key);
    long frames, skips, others;
    *done = *copies = *flips = -1;
    *msc = *us = -1.0;
    if (at && sscanf(at + strlen(key), "%ld done=%ld copies=%ld flips=%ld skips=%ld others=%ld msc_per_frame=%lf us_per_frame=%lf", &frames, done,
                     copies, flips, &skips, &others, msc, us) != 8)
        *done = *copies = *flips = -1;
}

/* The FPS that glxgears reported last, or 0 when it reported no frames. */
static double gears_fps(char *text)
{
    double last = 0;
    for (char *line = strtok(text, "\n"); line; line = strtok(NULL, "\n")) {
        int count;
        double seconds, fps;
        if (sscanf(line, "%d frames in %lf seconds = %lf FPS", &count, &seconds, &fps) == 3 && count > 0)
            last = fps;
    }
    return last;
}

/* The pid of the first process named name, or -1. */
static long pid_of(const struct m19_report *c, const char *name)
{
    DIR *directory = opendir(c->proc);
    long pid = -1;
    if (!directory)
        return -1;
    struct dirent *entry;
    while (pid < 0 && (entry = readdir(directory))) {
        if (entry->d_name[0] < '1' || entry->d_name[0] > '9')
            continue;
        char path[512], comm[32];
        snprintf(path, sizeof(path), "%s/%s/comm", c->proc, entry->d_name);
        if (read_small(path, comm, sizeof(comm)))
            continue;
        comm[strcspn(comm, "\n")] = 0;
        if (!strcmp(comm, name))
            pid = strtol(entry->d_name, NULL, 10);
    }
    closedir(directory);
    return pid;
}

/* CPU time the X server has used, in clock ticks: utime and stime of the process named Xorg. */
static long xorg_ticks(const struct m19_report *c)
{
    long pid = pid_of(c, "Xorg");
    char path[512], fields[1024];
    snprintf(path, sizeof(path), "%s/%ld/stat", c->proc, pid);
    const char *after = pid < 0 || read_small(path, fields, sizeof(fields)) ? NULL : strrchr(fields, ')');
    unsigned long user, system;
    /* After the command: state, then fields 4 to 13, then utime and stime. */
    if (after && sscanf(after + 1, " %*c %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %lu %lu", &user, &system) == 2)
        return (long)(user + system);
    return -1;
}

/* Whether a file holds any of the needles, each shorter than 64 bytes: 1, 0, or -1 when it cannot be read.
 * It is read in pieces, so a process's maps of any size fit. */
static int file_holds(const char *path, const char *const needles[])
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    static char piece[65536 + 64];
    size_t keep = 0;
    int found = 0;
    while (!found) {
        ssize_t n = read(fd, piece + keep, 65536);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        size_t have = keep + (size_t)n;
        for (unsigned i = 0; needles[i]; i++)
            found |= memmem(piece, have, needles[i], strlen(needles[i])) != NULL;
        keep = have < 63 ? have : 63;
        memmove(piece, piece + have - keep, keep);
    }
    close(fd);
    return found;
}

/* Whether xfwm4 composites with Mesa's GL: libglvnd's GLX or EGL vendor library, or Mesa's driver, in its maps. */
static int xfwm4_gl(const struct m19_report *c)
{
    static const char *const mesa[] = {"libGLX_mesa", "libEGL_mesa", "libgallium", NULL};
    long pid = pid_of(c, "xfwm4");
    char path[512];
    snprintf(path, sizeof(path), "%s/%ld/maps", c->proc, pid);
    return pid < 0 ? -1 : file_holds(path, mesa);
}

/* A copy of a section's output, as text. */
static char *section_text(size_t start, size_t length)
{
    static char text[SECTION_CAP + 1];
    size_t n = length < SECTION_CAP ? length : SECTION_CAP;
    memcpy(text, report + start, n);
    text[n] = 0;
    return text;
}

/* The value after key on the first line holding it, past any spaces, '=' and ':'. */
static void line_value(const char *text, const char *key, char *value, size_t room)
{
    const char *at = strstr(text, key);
    value[0] = 0;
    if (!at)
        return;
    at += strlen(key);
    at += strspn(at, " \t=:");
    size_t n = strcspn(at, "\r\n");
    if (n >= room)
        n = room - 1;
    memcpy(value, at, n);
    value[n] = 0;
}

/* One token for the verdict line: no spaces and no '='. */
static const char *token(char *text)
{
    if (!text[0])
        return "none";
    for (char *at = text; *at; at++)
        if (*at == ' ' || *at == '\t' || *at == '=')
            *at = '_';
    return text;
}

/* An Adreno, by Turnip or freedreno, and never a CPU renderer. */
static int adreno_named(const char *name)
{
    return (strstr(name, "Adreno") || strstr(name, "Turnip") || strstr(name, "FD7")) && !strstr(name, "llvmpipe") && !strstr(name, "softpipe") &&
           !strstr(name, "lavapipe");
}

/* The compositing manager's selection owner, as the probe reads it: 0 when nothing composites, -1 when
 * unreadable. Quiet: nothing goes into the report. */
static long owner_now(const struct m19_report *c)
{
    char *argv[] = {(char *)c->present_probe, "compositor", NULL};
    unsigned char out[256];
    size_t taken = 0;
    int status = capture(argv, out, sizeof(out) - 1, &taken, c->command_ms);
    out[taken] = 0;
    const char *at = strstr((const char *)out, "M19 PRESENT compositor owner=");
    unsigned long owner = 0;
    return status == 0 && at && sscanf(at, "M19 PRESENT compositor owner=%lx", &owner) == 1 ? (long)owner : -1;
}

/* Waits up to compose_ms for a compositing manager to come (want) or go (!want), then a fifth of that for
 * xfwm4 to draw what it now draws. */
static void wait_owner(const struct m19_report *c, int want)
{
    unsigned long long end = m19_now_ms() + c->compose_ms;
    long owner;
    while (((owner = owner_now(c)) < 0 || (owner != 0) != want) && m19_now_ms() < end)
        (void)poll(NULL, 0, 100);
    (void)poll(NULL, 0, (int)(c->compose_ms / 5));
}

/* One view of the screen: xfwm4's settings, the selection's owner, xfwm4's GL, the framebuffers the CRTC
 * scans out, and the root window's pixels. Each reading is -1 when it failed. */
static void observe(const struct m19_report *c, unsigned which, struct view *v)
{
    size_t start = 0, length = 0;
    addf("M19 view %s\n", view_names[which]);
    char *show[] = {(char *)c->shell, (char *)c->compositor_script, "show", NULL};
    (void)section(show, SECTION_CAP / 16, c->command_ms);
    char *owner[] = {(char *)c->present_probe, "compositor", NULL};
    int status = section_env(owner, NULL, SECTION_CAP / 16, c->command_ms, &start, &length);
    const char *at = strstr(section_text(start, length), "M19 PRESENT compositor owner=");
    unsigned long id = 0;
    v->owner_ok = status == 0 && at && sscanf(at, "M19 PRESENT compositor owner=%lx", &id) == 1;
    v->owner = v->owner_ok ? (long)id : -1;
    v->gl = xfwm4_gl(c);
    char samples[16];
    snprintf(samples, sizeof(samples), "%u", c->crtc_samples);
    char *crtc[] = {(char *)c->present_probe, "crtc", samples, (char *)c->card, NULL};
    status = section_env(crtc, NULL, SECTION_CAP / 16, c->command_ms, &start, &length);
    at = strstr(section_text(start, length), "M19 PRESENT crtc id=");
    v->crtc_ok = status == 0 && at &&
                 sscanf(at, "M19 PRESENT crtc id=%*u mode=%*s refresh=%*u fb=%ld fbs=%ld changes=%ld samples=%*d pitch=%ld", &v->fb, &v->fbs,
                        &v->changes, &v->pitch) == 4;
    if (!v->crtc_ok)
        v->fb = v->fbs = v->changes = v->pitch = -1;
    char *root[] = {(char *)c->present_probe, "root", NULL};
    status = section_env(root, NULL, SECTION_CAP / 16, c->command_ms, &start, &length);
    at = strstr(section_text(start, length), "M19 PRESENT root width=");
    v->root_ok = status == 0 && at && sscanf(at, "M19 PRESENT root width=%*u height=%*u nonblack=%ld mean=%ld", &v->nonblack, &v->mean) == 2;
    if (!v->root_ok)
        v->nonblack = v->mean = -1;
}

/* The kernel's vblank line from the probe; every value is -1 when it is missing. */
static int vblank_line(const char *text, struct gpu *g)
{
    const char *at = strstr(text, "M19 PRESENT vblank frames=");
    long frames;
    double wall;
    if (at && sscanf(at, "M19 PRESENT vblank frames=%ld wait_seq=%lf wait_us=%lf event_seq=%lf event_us=%lf event_wall_us=%lf late=%ld", &frames,
                     &g->wait_seq, &g->wait_us, &g->event_seq, &g->event_us, &wall, &g->late) == 7)
        return 1;
    g->wait_seq = g->wait_us = g->event_seq = g->event_us = -1.0;
    g->late = -1;
    return 0;
}

/* The GPU, after the desktop and touch checks so they run exactly as in R3. The probe fills a buffer on
 * the GPU and checks every word; vkcube and glxgears draw on the GPU and show the frames on the X desktop. */
static void gpu_phase(const struct m19_report *c, int tty, struct gpu *g)
{
    size_t start = 0, length = 0;
    memset(g, 0, sizeof(*g));
    (void)m19_wire_line(tty, c->pace_ms, M19_DEVICE_STEP " T12-gpu START");
    struct stat node;
    g->node = !stat(c->kgsl_node, &node) && S_ISCHR(node.st_mode);
    if (read_small(c->kgsl_model, g->model, sizeof(g->model)))
        snprintf(g->model, sizeof(g->model), "unreadable");
    g->model[strcspn(g->model, "\n")] = 0;

    if (c->glamor) {
        /* What the X server and the session got: glamor's own log lines, its unit, the session's profile. */
        static char xlog[512 * 1024];
        if (file_text(c->xorg_logs[0], xlog, sizeof(xlog)) >= 0) {
            g->glamor_init = strstr(xlog, "glamor initialized") != NULL;
            line_value(xlog, "glamor X acceleration enabled on", g->glamor_renderer, sizeof(g->glamor_renderer));
            g->glamor_on = g->glamor_renderer[0] != 0;
        }
        unsigned char out[64];
        size_t taken = 0;
        char *active[] = {(char *)c->systemctl, "is-active", (char *)c->xorg_unit, NULL};
        g->xorg_unit = capture(active, out, sizeof(out), &taken, c->command_ms) == 0 && taken >= 6 && !memcmp(out, "active", 6);
        if (read_small(c->gpu_profile, g->profile, sizeof(g->profile)))
            snprintf(g->profile, sizeof(g->profile), "none");
        g->profile[strcspn(g->profile, "\n")] = 0;
        g->glamor_ok = g->glamor_init && g->glamor_on && adreno_named(g->glamor_renderer) && g->xorg_unit && !strcmp(g->profile, "dri3");
    }

    char *probe[] = {(char *)c->gpu_probe, "vulkan", NULL};
    int status = section_env(probe, c->vk_env, SECTION_CAP / 4, c->gpu_ms, &start, &length);
    char *text = section_text(start, length);
    line_value(text, "M19 GPU vulkan device=", g->probe_device, sizeof(g->probe_device));
    g->probe = status == 0 && strstr(text, "M19 GPU vulkan fill ok") != NULL && adreno_named(g->probe_device);

    char *summary[] = {(char *)c->vulkaninfo, "--summary", NULL};
    status = section_env(summary, c->vk_env, SECTION_CAP, c->gpu_ms, &start, &length);
    text = section_text(start, length);
    line_value(text, "deviceName", g->device, sizeof(g->device));
    g->vk = status == 0 && strstr(text, "DRIVER_ID_MESA_TURNIP") != NULL && adreno_named(g->device);

    char frames[16];
    snprintf(frames, sizeof(frames), "%u", c->cube_frames);
    char *cube[] = {(char *)c->vkcube, "--c", frames, NULL};
    unsigned long long began = m19_now_ms();
    status = section_env(cube, c->vk_env, SECTION_CAP / 4, c->gpu_ms, NULL, NULL);
    g->cube_ms = (long)(m19_now_ms() - began);
    g->cube = status == 0;
    g->cube_fps = g->cube && g->cube_ms > 0 ? c->cube_frames * 1000.0 / (double)g->cube_ms : 0;

    char *info[] = {(char *)c->glxinfo, "-B", NULL};
    status = section_env(info, c->gl_env, SECTION_CAP / 4, c->gpu_ms, &start, &length);
    line_value(section_text(start, length), "OpenGL renderer string", g->renderer, sizeof(g->renderer));
    /* With glamor, GL must be freedreno itself through DRI3, not zink copying through the CPU. */
    g->gl = status == 0 && adreno_named(g->renderer) && !(c->glamor && strstr(g->renderer, "zink"));

    /* glxgears runs until its window closes: the time limit ends it, and its FPS lines are the result.
     * The X server's CPU time meanwhile says whether frames reach it through the CPU. */
    char *gears[] = {(char *)c->glxgears, NULL};
    long ticks = xorg_ticks(c);
    unsigned long long gears_start = m19_now_ms();
    (void)section_env(gears, c->gl_env, SECTION_CAP / 4, c->gears_ms, &start, &length);
    long ticks_after = xorg_ticks(c);
    unsigned long long gears_ms = m19_now_ms() - gears_start;
    long hz = sysconf(_SC_CLK_TCK);
    g->xorg_cpu = ticks >= 0 && ticks_after >= ticks && gears_ms && hz > 0 ? (double)(ticks_after - ticks) * 100000.0 / ((double)hz * (double)gears_ms)
                                                                           : -1.0;
    g->gears_fps = gears_fps(section_text(start, length));
    g->gears = g->gears_fps > 0;

    if (c->present_probe) {
        /* Page flips: the probe, with no Mesa in the way, then glxgears covering the screen. A flip run
         * passes when nearly every completion was a flip and each took one vblank. */
        char frames_text[16];
        snprintf(frames_text, sizeof(frames_text), "%u", c->present_frames);
        char *copy[] = {(char *)c->present_probe, "copy", frames_text, NULL};
        status = section_env(copy, NULL, SECTION_CAP / 8, c->gpu_ms, &start, &length);
        long ignored;
        present_line(section_text(start, length), "copy", &g->copy_done, &ignored, &ignored, &g->copy_msc, &g->copy_us);
        /* (R4h) A windowed copy completes on the vblank it asks for: one vblank a frame, at the panel's rate. */
        g->copy_ok = status == 0 && g->copy_done == (long)c->present_frames && g->copy_msc > 0 && g->copy_msc <= 1.10;
        char *flip[] = {(char *)c->present_probe, "flip", frames_text, NULL};
        status = section_env(flip, NULL, SECTION_CAP / 8, c->gpu_ms, &start, &length);
        long flip_copies;
        present_line(section_text(start, length), "flip", &g->flip_done, &flip_copies, &g->flips, &g->flip_msc, &g->flip_us);
        g->flip_ok = status == 0 && g->flip_done == (long)c->present_frames && g->flips * 10 >= (long)c->present_frames * 9 && g->flip_msc > 0 &&
                     g->flip_msc <= 1.10;
        char *full[] = {(char *)c->glxgears, "-fullscreen", NULL};
        (void)section_env(full, c->gl_env, SECTION_CAP / 4, c->gears_ms, &start, &length);
        g->gears_full_fps = gears_fps(section_text(start, length));
        if (c->compositor_script) {
            /* R4e. The kernel's vblanks on card0, without X, to place Present's two vblanks a frame. */
            char vblank_frames[16];
            snprintf(vblank_frames, sizeof(vblank_frames), "%u", c->vblank_frames);
            char *vblank[] = {(char *)c->present_probe, "vblank", vblank_frames, (char *)c->card, NULL};
            status = section_env(vblank, NULL, SECTION_CAP / 16, c->gpu_ms, &start, &length);
            g->vblank_ok = vblank_line(section_text(start, length), g) && status == 0;
            /* The screen as the session left it, then with R4d's compositor on, then with compositing off. */
            observe(c, 0, &g->view[0]);
            char *on[] = {(char *)c->shell, (char *)c->compositor_script, "on", NULL};
            g->on_rc = section(on, SECTION_CAP / 16, c->command_ms);
            wait_owner(c, 1);
            observe(c, 1, &g->view[1]);
            /* Composited, as R4d ran them: the probe's two windows and vkcube. */
            long ignored, done;
            double us, msc;
            (void)section_env(copy, NULL, SECTION_CAP / 8, c->gpu_ms, &start, &length);
            present_line(section_text(start, length), "copy", &g->composited_done, &g->composited_copies, &ignored, &g->composited_msc, &us);
            (void)section_env(flip, NULL, SECTION_CAP / 8, c->gpu_ms, &start, &length);
            present_line(section_text(start, length), "flip", &done, &ignored, &g->composited_flips, &msc, &us);
            began = m19_now_ms();
            status = section_env(cube, c->vk_env, SECTION_CAP / 4, c->gpu_ms, NULL, NULL);
            unsigned long long composited_ms = m19_now_ms() - began;
            g->composited_cube_fps = status == 0 && composited_ms ? c->cube_frames * 1000.0 / (double)composited_ms : 0;
            char *off[] = {(char *)c->shell, (char *)c->compositor_script, "off", NULL};
            g->off_rc = section(off, SECTION_CAP / 16, c->command_ms);
            wait_owner(c, 0);
            observe(c, 2, &g->view[2]);
            g->compositor_ok = g->on_rc == 0 && g->off_rc == 0 && g->view[0].owner_ok && g->view[1].owner > 0 && g->view[2].owner == 0;
            g->scanout_ok = 1;
            for (unsigned i = 0; i < 3; i++)
                g->scanout_ok = g->scanout_ok && g->view[i].crtc_ok && g->view[i].root_ok;
        }
    }

    /* A broader GL load, and GL through the copy profile for comparison. Recorded, not judged. */
    g->glmark2 = -1;
    if (c->glmark2) {
        char *mark[] = {(char *)c->glmark2, "-b", "build:duration=2.0", "-b", "texture:duration=2.0", "-b", "shading:duration=2.0", NULL};
        status = section_env(mark, c->gl_env, SECTION_CAP / 4, c->gpu_ms, &start, &length);
        char score[32];
        line_value(section_text(start, length), "glmark2 Score", score, sizeof(score));
        if (status == 0 && score[0])
            g->glmark2 = strtol(score, NULL, 10);
    }
    if (c->copy_env) {
        status = section_env(info, c->copy_env, SECTION_CAP / 4, c->gpu_ms, &start, &length);
        line_value(section_text(start, length), "OpenGL renderer string", g->copy_renderer, sizeof(g->copy_renderer));
    }

    /* freedreno itself on KGSL, without X: the driver a GPU X server needs. Recorded, not judged. */
    char *egl[] = {(char *)c->eglinfo, "-B", "-p", "surfaceless", NULL};
    status = section_env(egl, c->egl_env, SECTION_CAP / 4, c->gpu_ms, &start, &length);
    line_value(section_text(start, length), "renderer", g->egl_renderer, sizeof(g->egl_renderer));
    g->egl = status == 0 && adreno_named(g->egl_renderer);
    (void)m19_wire_line(tty, c->pace_ms, M19_DEVICE_STEP " T12-gpu END %d %d %d %d %d %d %d %d %d %d %d %d %d", g->node, g->probe, g->vk, g->cube,
                        g->gl, g->gears, g->egl, g->glamor_ok, g->flip_ok, g->compositor_ok, g->vblank_ok, g->scanout_ok, g->copy_ok);
}

static void desktop_sections(const struct m19_report *c)
{
    char *verbose[] = {(char *)c->xrandr, "--verbose", NULL};
    char *inputs[] = {(char *)c->xinput, "list", NULL};
    char *display[] = {(char *)c->xdpyinfo, NULL};
    char *processes[] = {(char *)c->ps, "-eo", "pid,comm,pcpu,rss", "--sort=-pcpu", NULL};
    (void)section(verbose, SECTION_CAP, c->command_ms);
    (void)section(inputs, SECTION_CAP, c->command_ms);
    (void)section(display, SECTION_CAP / 4, c->command_ms);
    (void)section(processes, SECTION_CAP / 4, c->command_ms);
    for (unsigned i = 0; i < 2; i++) {
        addf("M19 %s\n", c->xorg_logs[i]);
        (void)add_file_without(c->xorg_logs[i], 2 * SECTION_CAP, "overflowing for touch");
    }
    addf("M19 %s\n", c->interrupts);
    (void)add_file(c->interrupts, SECTION_CAP);
}

static int read_long(const char *path, long *value)
{
    char text[64], *end;
    if (read_small(path, text, sizeof(text)))
        return -1;
    errno = 0;
    long parsed = strtol(text, &end, 10);
    if (end == text || errno)
        return -1;
    *value = parsed;
    return 0;
}

/* The hottest thermal zone in thousandths of a degree, and how many zones answered. */
static long hottest_zone(const char *thermal, int *zones)
{
    long hottest = LONG_MIN;
    *zones = 0;
    DIR *directory = opendir(thermal);
    if (!directory)
        return hottest;
    struct dirent *entry;
    while ((entry = readdir(directory))) {
        if (strncmp(entry->d_name, "thermal_zone", 12))
            continue;
        char path[512];
        long value;
        snprintf(path, sizeof(path), "%s/%s/temp", thermal, entry->d_name);
        if (read_long(path, &value) || value <= -40000 || value >= 200000)
            continue;
        (*zones)++;
        if (value > hottest)
            hottest = value;
    }
    closedir(directory);
    return hottest;
}

static int cpu_times(const char *stat, unsigned long long *busy, unsigned long long *total)
{
    FILE *file = fopen(stat, "re");
    char line[512];
    if (!file)
        return -1;
    char *got = fgets(line, sizeof(line), file);
    fclose(file);
    if (!got || strncmp(line, "cpu ", 4))
        return -1;
    unsigned long long field[10] = {0}, sum = 0;
    char *cursor = line + 4;
    for (unsigned i = 0; i < 10; i++) {
        char *end;
        field[i] = strtoull(cursor, &end, 10);
        if (end == cursor)
            break;
        sum += field[i];
        cursor = end;
    }
    *total = sum;
    *busy = sum - field[3] - field[4]; /* idle and iowait */
    return 0;
}

__attribute__((format(printf, 2, 3)))
static void kmsg_note(const char *kmsg, const char *format, ...)
{
    char text[240];
    int at = snprintf(text, sizeof(text), "<4>M19: ");
    va_list arguments;
    va_start(arguments, format);
    int n = vsnprintf(text + at, sizeof(text) - (size_t)at - 1, format, arguments);
    va_end(arguments);
    if (n < 0)
        return;
    size_t size = (size_t)at + ((size_t)n < sizeof(text) - (size_t)at - 1 ? (size_t)n : sizeof(text) - (size_t)at - 2);
    text[size++] = '\n';
    int fd = open(kmsg, O_WRONLY | O_APPEND | O_CLOEXEC);
    if (fd < 0)
        return;
    ssize_t put = write(fd, text, size);
    (void)put;
    close(fd);
}

int m19_guard_main(const struct m19_guard *g)
{
    unsigned long long start = m19_now_ms(), busy_since = 0, note = start, last_busy = 0, last_total = 0;
    int have_sample = !cpu_times(g->stat, &last_busy, &last_total);
    kmsg_note(g->kmsg, "guard start battery_limit=%ld zone_limit=%ld busy_limit=%u busy_ms=%u session_ms=%u", g->battery_limit, g->zone_limit,
              g->busy_limit, g->busy_ms, g->session_ms);
    for (;;) {
        (void)poll(NULL, 0, (int)g->period_ms);
        unsigned long long now = m19_now_ms(), busy = 0, total = 0;
        long battery = LONG_MIN;
        int zones = 0;
        (void)read_long(g->battery_temp, &battery);
        long zone = hottest_zone(g->thermal, &zones);
        unsigned percent = 0;
        if (!cpu_times(g->stat, &busy, &total)) {
            if (have_sample && total > last_total && busy >= last_busy)
                percent = (unsigned)((busy - last_busy) * 100 / (total - last_total));
            last_busy = busy;
            last_total = total;
            have_sample = 1;
        }
        if (percent >= g->busy_limit) {
            if (!busy_since)
                busy_since = now;
        } else {
            busy_since = 0;
        }
        const char *reason = NULL;
        if (battery != LONG_MIN && battery >= g->battery_limit)
            reason = "battery";
        else if (zone != LONG_MIN && zone >= g->zone_limit)
            reason = "zone";
        else if (busy_since && now - busy_since >= g->busy_ms)
            reason = "cpu";
        else if (now - start >= g->session_ms)
            reason = "time";
        if (now >= note || reason) {
            kmsg_note(g->kmsg, "guard battery=%ld zones=%d zone=%ld busy=%u elapsed=%llu", battery == LONG_MIN ? -1 : battery, zones,
                      zone == LONG_MIN ? -1 : zone, percent, (now - start) / 1000);
            note = now + g->note_ms;
        }
        if (reason) {
            kmsg_note(g->kmsg, "guard trip reason=%s, stopping the desktop", reason);
            int fd = open(g->marker, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
            if (fd >= 0) {
                ssize_t put = write(fd, reason, strlen(reason));
                (void)put;
                close(fd);
            }
            unsigned char out[1024];
            size_t taken;
            char *stop[] = {(char *)g->systemctl, "stop", (char *)g->units[0], (char *)g->units[1], (char *)g->units[2], NULL};
            int status = capture(stop, out, sizeof(out), &taken, g->command_ms);
            char *kill_units[] = {(char *)g->systemctl, "kill", "--signal=SIGKILL", (char *)g->units[0], (char *)g->units[1],
                                  (char *)g->units[2], NULL};
            if (status)
                (void)capture(kill_units, out, sizeof(out), &taken, g->command_ms);
            kmsg_note(g->kmsg, "guard stopped the desktop status=%d", status);
            char hold[16];
            snprintf(hold, sizeof(hold), "%u", g->final_ms);
            char *argv[] = {(char *)g->display, YELLOW, hold, NULL};
            execv(g->display, argv);
            return 70;
        }
        if (g->run_ms && now - start >= g->run_ms)
            return 0;
    }
}

static void paint(const struct m19_report *c, int all_ok)
{
    char hold[16];
    snprintf(hold, sizeof(hold), "%u", c->final_ms);
    char *argv[] = {(char *)c->display, all_ok ? GREEN : YELLOW, hold, NULL};
    execv(c->display, argv);
}

int m19_report_main(const struct m19_report *c)
{
    unsigned long long start = m19_now_ms();
    int tty = -1;
    while ((tty = m19_wire_open(c->tty)) < 0 && m19_now_ms() < start + c->tty_wait_ms)
        (void)poll(NULL, 0, 100);
    (void)m19_wire_line(tty, c->pace_ms, M19_DEVICE_STEP " T11-systemd START");

    char state[32] = "unknown";
    char *running[] = {(char *)c->systemctl, "is-system-running", NULL};
    unsigned long long end = start + c->settle_ms, beat = start + c->beat_ms;
    for (;;) {
        unsigned char out[128];
        size_t taken = 0;
        (void)capture(running, out, sizeof(out), &taken, c->command_ms);
        first_word(out, taken, state, sizeof(state));
        unsigned long long now = m19_now_ms();
        if (settled(state) || now >= end)
            break;
        if (now >= beat) {
            (void)m19_wire_line(tty, c->pace_ms, M19_DEVICE_BEAT " T11-systemd %llu %s", (now - start) / 1000, state);
            beat = now + c->beat_ms;
        }
        (void)poll(NULL, 0, (int)c->poll_ms);
    }
    addf("M19 R2 report\nM19 R2 state %s after %llu ms\n", state, m19_now_ms() - start);
    struct desktop d;
    struct gpu g;
    memset(&d, 0, sizeof(d));
    memset(&g, 0, sizeof(g));
    if (c->desktop) {
        /* X clients find the server here; Xorg runs without an authority file. */
        setenv("DISPLAY", ":0", 1);
        desktop_phase(c, tty, &d);
        if (c->gpu && d.x_ok)
            gpu_phase(c, tty, &g);
    }

    char exe[256];
    ssize_t n = readlink(c->proc1_exe, exe, sizeof(exe) - 1);
    exe[n > 0 ? n : 0] = 0;
    int init_ok = n > 0 && !strcmp(exe, c->expected_init);
    addf("M19 R2 pid1 %s\n", n > 0 ? exe : "unreadable");
    int state_ok = !strcmp(state, "running") || !strcmp(state, "degraded");

    char *active[] = {(char *)c->systemctl, "is-active", "basic.target", "multi-user.target", NULL};
    int targets_ok = section(active, SECTION_CAP, c->command_ms) == 0;
    char *failed[] = {(char *)c->systemctl, "--failed", "--no-legend", "--plain", "--no-pager", NULL};
    char *jobs[] = {(char *)c->systemctl, "list-jobs", "--no-legend", "--plain", "--no-pager", NULL};
    char *boot_time[] = {(char *)c->analyze, "time", NULL};
    char *blame[] = {(char *)c->analyze, "blame", "--no-pager", NULL};
    char *version[] = {(char *)c->systemctl, "--version", NULL};
    char *units[] = {(char *)c->systemctl, "list-units", "--all", "--no-legend", "--plain", "--no-pager", NULL};
    (void)section(failed, SECTION_CAP, c->command_ms);
    (void)section(jobs, SECTION_CAP, c->command_ms);
    (void)section(boot_time, SECTION_CAP, c->command_ms);
    (void)section(blame, SECTION_CAP, c->command_ms);
    (void)section(version, SECTION_CAP, c->command_ms);
    (void)section(units, SECTION_CAP, c->command_ms);

    int writes_ok, ro_ok;
    check_blocks(c->block, &writes_ok, &ro_ok);
    addf("M19 mountinfo\n");
    (void)add_file(c->mountinfo, SECTION_CAP);
    int mounts_ok = check_mounts(c->mountinfo);

    addf("M19 kernel log\n");
    size_t kernel = used;
    (void)add_file(c->kmsg, KERNEL_CAP);
    int write_warning = memmem(report + kernel, used - kernel, M19_WRITE_WARNING, sizeof(M19_WRITE_WARNING) - 1) != NULL;
    char *journal[] = {(char *)c->journalctl, "-b", "-o", "short-monotonic", "--no-pager", "-q", NULL};
    (void)section(journal, JOURNAL_CAP, c->command_ms);

    int desktop_ok = 1;
    if (c->desktop) {
        desktop_sections(c);
        /* The guard must be running and must not have tripped. The sensors it reads go into the evidence. */
        char *guard[] = {(char *)c->systemctl, "is-active", (char *)c->guard_unit, NULL};
        int guard_active = section(guard, SECTION_CAP / 16, c->command_ms) == 0, tripped = !access(c->guard_marker, F_OK);
        long battery = LONG_MIN;
        int zones = 0;
        (void)read_long(c->battery_temp, &battery);
        long hottest = hottest_zone(c->thermal, &zones);
        int guard_ok = guard_active && !tripped;
        desktop_ok = d.x_ok && d.session_ok && d.mode_ok && d.vblank_ok && d.touch_ok && guard_ok;
        addf("M19 R3 desktop x=%d session=%d mode=%s xrandr_hz=%.2f mode_ok=%d crtc=%d vblank_hz=%.2f vblank_ok=%d touch_device=%d "
             "touch_irqs=%ld touch_events=%d touch_ok=%d guard=%d tripped=%d battery=%ld zones=%d hottest=%ld\n", d.x_ok, d.session_ok, d.mode,
             d.xrandr_hz, d.mode_ok, d.crtc, d.vblank_hz, d.vblank_ok, d.touch_device, d.irq_delta, d.events, d.touch_ok, guard_ok, tripped,
             battery == LONG_MIN ? -1 : battery, zones, hottest == LONG_MIN ? -1 : hottest);
    }
    int gpu_ok = 1;
    if (c->gpu) {
        /* Page flips and the composited runs are recorded, not judged: R4e measures where they fail. */
        gpu_ok = g.node && g.probe && g.vk && g.cube && g.gl && g.gears && (!c->glamor || g.glamor_ok) &&
                 (!c->compositor_script || (g.compositor_ok && g.vblank_ok && g.scanout_ok)) && (!c->judge_copy || g.copy_ok);
        /* Three lines, each well inside addf's buffer however long the names run. */
        addf("M19 R4 gpu node=%d probe=%d vk=%d cube=%d cube_ms=%ld cube_fps=%.1f gl=%d gears=%d gears_fps=%.1f egl=%d gpu_ok=%d\n", g.node, g.probe,
             g.vk, g.cube, g.cube_ms, g.cube_fps, g.gl, g.gears, g.gears_fps, g.egl, gpu_ok);
        addf("M19 R4 gpu-names model=%s probe_device=%s device=%s\n", token(g.model), token(g.probe_device), token(g.device));
        addf("M19 R4 gpu-renderers renderer=%s egl_renderer=%s\n", token(g.renderer), token(g.egl_renderer));
        if (c->glamor) {
            addf("M19 R4 glamor initialized=%d enabled=%d unit=%d profile=%s xorg_cpu=%.1f glmark2=%ld glamor_ok=%d\n", g.glamor_init, g.glamor_on,
                 g.xorg_unit, token(g.profile), g.xorg_cpu, g.glmark2, g.glamor_ok);
            addf("M19 R4 glamor-renderers glamor_renderer=%s copy_renderer=%s\n", token(g.glamor_renderer), token(g.copy_renderer));
        }
        if (c->present_probe)
            addf("M19 R4 present copy_done=%ld copy_msc=%.2f copy_us=%.0f flip_done=%ld flips=%ld flip_msc=%.2f flip_us=%.0f gears_full_fps=%.1f "
                 "flip_ok=%d copy_ok=%d\n", g.copy_done, g.copy_msc, g.copy_us, g.flip_done, g.flips, g.flip_msc, g.flip_us, g.gears_full_fps, g.flip_ok,
                 g.copy_ok);
        if (c->compositor_script) {
            addf("M19 R4 vblank wait_seq=%.2f wait_us=%.0f event_seq=%.2f event_us=%.0f late=%ld vblank_ok=%d\n", g.wait_seq, g.wait_us, g.event_seq,
                 g.event_us, g.late, g.vblank_ok);
            addf("M19 R4 compositor on_rc=%d off_rc=%d composited_done=%ld composited_copies=%ld composited_flips=%ld composited_msc=%.2f "
                 "composited_cube_fps=%.1f compositor_ok=%d scanout_ok=%d\n", g.on_rc, g.off_rc, g.composited_done, g.composited_copies,
                 g.composited_flips, g.composited_msc, g.composited_cube_fps, g.compositor_ok, g.scanout_ok);
            for (unsigned i = 0; i < 3; i++)
                addf("M19 R4 view %s owner=%ld gl=%d fb=%ld fbs=%ld changes=%ld pitch=%ld nonblack=%ld mean=%ld\n", view_names[i], g.view[i].owner,
                     g.view[i].gl, g.view[i].fb, g.view[i].fbs, g.view[i].changes, g.view[i].pitch, g.view[i].nonblack, g.view[i].mean);
        }
    }
    int all_ok = init_ok && state_ok && targets_ok && writes_ok && ro_ok && mounts_ok && !write_warning && desktop_ok && gpu_ok;
    addf("M19 R2 verdict init=%d state=%s targets=%d writes=%d read_only=%d mounts=%d write_warning=%d all_ok=%d\n", init_ok, state, targets_ok,
         writes_ok, ro_ok, mounts_ok, write_warning, all_ok);

    uint8_t digest[32];
    char hash[65];
    m19_sha256(report, used, digest);
    for (int i = 0; i < 32; i++)
        snprintf(hash + i * 2, 3, "%02x", digest[i]);
    (void)m19_wire_line(tty, c->pace_ms, M19_DEVICE_STEP " T11-systemd %s %d 0", all_ok ? "OK" : "FAIL", all_ok ? 0 : -1);
    unsigned long long log_end = m19_now_ms() + c->log_ms;
    if (!m19_wire_line(tty, c->pace_ms, M19_DEVICE_LOG " %zu %s %d %d", used, hash, all_ok, write_warning))
        (void)m19_wire_put(tty, report, used, c->pace_ms, log_end);
    if (tty >= 0)
        close(tty);
    /* A running X server owns the panel: leave the desktop on it. */
    if (c->desktop && d.x_ok)
        return 0;
    paint(c, all_ok);
    return 70;
}
