/* The R2 reporter. systemd starts it early; it waits for the boot to settle, gathers the
 * evidence, judges it, sends it over the serial line with a hash, then paints the verdict.
 * It only reads: systemd's state, the journal, the kernel log, /proc and /sys. R8's T12-persist is
 * the one exception: one small file in the tree, when persist_path is set. */
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
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>

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

/* R8: one disk's, partition's or dm device's counters and read-only flag; 0 when both read. */
struct counts {
    unsigned long long writes, sectors, discards, discarded;
    int ro;
};

static int block_counts(const char *directory, struct counts *n)
{
    char path[1400], text[512], flag[16];
    memset(n, 0, sizeof(*n));
    snprintf(path, sizeof(path), "%s/stat", directory);
    if (read_small(path, text, sizeof(text)))
        return -1;
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
    if (count < 7 || read_small(path, flag, sizeof(flag)))
        return -1;
    n->writes = field[4];
    n->sectors = field[6];
    n->discards = field[11];
    n->discarded = field[13];
    n->ro = !strcmp(flag, "1\n");
    return 0;
}

static int counts_zero(const struct counts *n)
{
    return !n->writes && !n->sectors && !n->discards && !n->discarded;
}

static void counts_line(const char *name, const char *role, const struct counts *n)
{
    addf("M19 R8 block %s %s writes=%llu sectors=%llu discards=%llu discarded=%llu ro=%d\n", name, role, n->writes, n->sectors, n->discards,
         n->discarded, n->ro);
}

/* The value of key in a uevent file, or "". */
static void uevent_value(const char *path, const char *key, char *value, size_t room)
{
    char text[2048];
    size_t length = strlen(key);
    value[0] = 0;
    if (read_small(path, text, sizeof(text)))
        return;
    for (char *line = text; line && *line;) {
        char *next = strchr(line, '\n');
        if (next)
            *next++ = 0;
        if (!strncmp(line, key, length) && line[length] == '=') {
            snprintf(value, room, "%s", line + length + 1);
            return;
        }
        line = next;
    }
}

static int is_partition_of(const char *part, const char *disk)
{
    size_t length = strlen(disk);
    return !strncmp(part, disk, length) && part[length];
}

/* R8: /data is read-write. Only the data partition (data_part) and the dm device made from it (data_dm) are writable
 * and may count writes; the disk holding the partition may count them too, read-only itself, while every other
 * partition on it counts none. Every other disk, partition and dm device is read-only and unwritten, as in R2. The
 * data table has no discard, so none may count on the data path. */
static void check_blocks_rw(const struct m19_report *c, int *writes_ok, int *ro_ok)
{
    DIR *directory = opendir(c->block);
    int disks = 0, data_parts = 0, data_dms = 0;
    *writes_ok = *ro_ok = 1;
    if (!directory) {
        *writes_ok = *ro_ok = 0;
        addf("M19 R2 no %s\n", c->block);
        return;
    }
    struct dirent *entry;
    while ((entry = readdir(directory))) {
        const char *name = entry->d_name;
        int disk = !strncmp(name, "sd", 2);
        if (!disk && strncmp(name, "dm-", 3))
            continue;
        char path[1024];
        struct counts n;
        snprintf(path, sizeof(path), "%s/%s", c->block, name);
        if (block_counts(path, &n)) {
            addf("M19 R8 block %s unreadable\n", name);
            *writes_ok = *ro_ok = 0;
            continue;
        }
        if (!disk) {
            char inner[1100], dm[128];
            snprintf(inner, sizeof(inner), "%s/dm/name", path);
            if (read_small(inner, dm, sizeof(dm)))
                dm[0] = 0;
            dm[strcspn(dm, "\n")] = 0;
            int data = dm[0] && !strcmp(dm, c->data_dm);
            counts_line(name, data ? "data" : "other", &n);
            if (data) {
                data_dms++;
                if (n.ro)
                    *ro_ok = 0;
                if (n.discards || n.discarded)
                    *writes_ok = 0;
            } else {
                if (!n.ro)
                    *ro_ok = 0;
                if (!counts_zero(&n))
                    *writes_ok = 0;
            }
            continue;
        }
        disks++;
        DIR *parts = opendir(path);
        if (!parts) {
            *ro_ok = 0;
            continue;
        }
        /* The partitions first: which one holds /data, and every other one read-only. */
        char data[256] = "";
        struct dirent *part;
        while ((part = readdir(parts))) {
            if (!is_partition_of(part->d_name, name))
                continue;
            char inner[1300], partname[64], flag[16];
            snprintf(inner, sizeof(inner), "%s/%s/uevent", path, part->d_name);
            uevent_value(inner, "PARTNAME", partname, sizeof(partname));
            if (partname[0] && !strcmp(partname, c->data_part)) {
                data_parts++;
                snprintf(data, sizeof(data), "%s", part->d_name);
                continue;
            }
            snprintf(inner, sizeof(inner), "%s/%s/ro", path, part->d_name);
            if (read_small(inner, flag, sizeof(flag)) || strcmp(flag, "1\n")) {
                addf("M19 R2 partition %s writable\n", part->d_name);
                *ro_ok = 0;
            }
        }
        counts_line(name, data[0] ? "data-disk" : "disk", &n);
        if (!n.ro)
            *ro_ok = 0;
        if (!data[0]) {
            if (!counts_zero(&n))
                *writes_ok = 0;
            closedir(parts);
            continue;
        }
        if (n.discards || n.discarded)
            *writes_ok = 0;
        /* Then the data disk's partitions' own counters: the data partition's, and any other that counts. */
        rewinddir(parts);
        while ((part = readdir(parts))) {
            if (!is_partition_of(part->d_name, name))
                continue;
            char inner[1300];
            struct counts p;
            snprintf(inner, sizeof(inner), "%s/%s", path, part->d_name);
            if (block_counts(inner, &p)) {
                addf("M19 R8 block %s unreadable\n", part->d_name);
                *writes_ok = *ro_ok = 0;
                continue;
            }
            if (!strcmp(part->d_name, data)) {
                counts_line(part->d_name, "data", &p);
                if (p.ro)
                    *ro_ok = 0;
                if (p.discards || p.discarded)
                    *writes_ok = 0;
            } else if (!counts_zero(&p)) {
                counts_line(part->d_name, "other", &p);
                *writes_ok = 0;
            }
        }
        closedir(parts);
    }
    closedir(directory);
    if (!disks) {
        addf("M19 R2 no disk\n");
        *writes_ok = 0;
    }
    if (data_parts != 1 || data_dms != 1) {
        addf("M19 R8 data devices partitions=%d dm=%d\n", data_parts, data_dms);
        *writes_ok = *ro_ok = 0;
    }
}

static const char *const rw_allowed[] = {"tmpfs", "proc", "sysfs", "devpts", "cgroup", "cgroup2", "securityfs", "debugfs", "tracefs", "configfs",
                                         "selinuxfs", "pstore", "bpf", "mqueue", "hugetlbfs", "fusectl", "binfmt_misc", "ramfs", "functionfs",
                                         "efivarfs", "autofs", "rpc_pipefs", "nsfs", NULL};

static int starts_ro(const char *options)
{
    return !strncmp(options, "ro", 2) && (options[2] == ',' || options[2] == 0);
}

static int starts_rw(const char *options)
{
    return !strncmp(options, "rw", 2) && (options[2] == ',' || options[2] == 0);
}

/* Any filesystem that is not RAM or a kernel view must be read-only at the mount and the
 * superblock, and / must be the f2fs root. R8 (data_rw): / is the f2fs root read-write, and every other
 * mount of a disk filesystem is read-only at the mount; an f2fs one shares /'s superblock. */
static int check_mounts(const char *mountinfo, int data_rw)
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
        if (!strcmp(point, "/") && data_rw) {
            root = !strcmp(type, "f2fs") && starts_rw(options) && starts_rw(super);
            continue;
        }
        if (!strcmp(point, "/"))
            root = !strcmp(type, "f2fs") && starts_ro(options) && starts_ro(super);
        if (allowed)
            continue;
        if (!starts_ro(options) || !(starts_ro(super) || (data_rw && !strcmp(type, "f2fs")))) {
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
    /* R6 */
    int width, height, landscape_ok;
    char rotation[16];
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

/* R6: the first connected output's screen geometry and rotation, as xrandr prints them:
 * "DSI-1 connected primary 2400x1080+0+0 right (normal left inverted right x axis y axis) 69mm x 154mm". */
static void xrandr_turn(const struct m19_report *c, struct desktop *d)
{
    static char out[16384];
    size_t taken = 0;
    char *argv[] = {(char *)c->xrandr, "--query", NULL};
    d->width = d->height = 0;
    snprintf(d->rotation, sizeof(d->rotation), "none");
    if (run_quiet(c, argv, (unsigned char *)out, sizeof(out) - 1, &taken))
        return;
    out[taken] = 0;
    for (char *line = out; line && *line;) {
        char *next = strchr(line, '\n');
        if (next)
            *next++ = 0;
        char *at = strstr(line, " connected ");
        if (at && line[0] != ' ') {
            at += strlen(" connected ");
            if (!strncmp(at, "primary ", 8))
                at += 8;
            int w, h, x, y, used = 0;
            if (sscanf(at, "%dx%d+%d+%d %n", &w, &h, &x, &y, &used) == 4 && used) {
                d->width = w;
                d->height = h;
                char word[16] = "";
                if (at[used] == '(' || sscanf(at + used, "%15s", word) != 1)
                    snprintf(d->rotation, sizeof(d->rotation), "normal");
                else
                    snprintf(d->rotation, sizeof(d->rotation), "%s", word);
            }
            return;
        }
        line = next;
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
    if (c->rotation) {
        xrandr_turn(c, d);
        d->landscape_ok = !strcmp(d->rotation, c->rotation) && d->width > d->height && d->height > 0;
    }
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

#define M19_SHOWS_MAX 8

struct gpu {
    int node, probe, vk, cube, gl, gears, egl, glamor_init, glamor_on, xorg_unit, glamor_ok, flip_ok, copy_ok, compositor_ok, vblank_ok, scanout_ok,
        on_rc, off_rc, show_ran, show_visible, shows_ok, late_ok;
    long show_nonblack[M19_SHOWS_MAX], show_mean[M19_SHOWS_MAX];
    long xread_cpu, xread_pixmap, xread_window, gpu_cpu, chain_cpu, chain_pixmap, chain_window;
    long xlate_cpu, xlate_pixmap, xlate_window, chainlate_cpu, chainlate_pixmap, chainlate_window;
    char dmabuf_renderer[64];
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

/* The number after name= on the first line holding key, or -1. */
static long field(const char *text, const char *key, const char *name)
{
    const char *line = strstr(text, key);
    if (!line)
        return -1;
    size_t n = strcspn(line, "\n");
    char pattern[32];
    snprintf(pattern, sizeof(pattern), " %s=", name);
    const char *at = strstr(line, pattern);
    if (!at || at >= line + n)
        return -1;
    char *end;
    long value = strtol(at + strlen(pattern), &end, 10);
    return end == at + strlen(pattern) ? -1 : value;
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
        /* R4i. What glxgears covering the screen shows through each path, read off the screen while it runs:
         * the share of pixels that are not black, in thousandths. */
        for (unsigned i = 0; i < c->show_count && i < M19_SHOWS_MAX; i++) {
            char script[1024];
            snprintf(script, sizeof(script), "%s -fullscreen & gears=$!; sleep %u; %s root; kill $gears; wait $gears; exit 0", c->glxgears,
                     c->show_seconds, c->present_probe);
            char *argv[] = {(char *)c->shell, "-c", script, NULL};
            addf("M19 show %s\n", c->shows[i].name);
            status = section_env(argv, c->shows[i].env, SECTION_CAP / 8, c->gpu_ms, &start, &length);
            const char *at = strstr(section_text(start, length), "M19 PRESENT root width=");
            g->show_nonblack[i] = g->show_mean[i] = -1;
            if (status == 0 && at &&
                sscanf(at, "M19 PRESENT root width=%*u height=%*u nonblack=%ld mean=%ld", &g->show_nonblack[i], &g->show_mean[i]) == 2) {
                g->show_ran++;
                g->show_visible += g->show_nonblack[i] >= 5;
            } else {
                g->show_nonblack[i] = g->show_mean[i] = -1;
            }
        }
        g->shows_ok = g->show_ran == (int)c->show_count && (!c->judge_dri3 || g->show_visible == (int)c->show_count);
        if (c->dmabuf_heap) {
            /* R4j. Which side loses a program's frame: the X server reading a dma-buf the CPU filled, the GPU
             * writing one the CPU reads, and the GPU's handed to the X server. Recorded, not judged. */
            char *xread[] = {(char *)c->present_probe, "xread", (char *)c->dmabuf_heap, NULL};
            (void)section_env(xread, NULL, SECTION_CAP / 16, c->gpu_ms, &start, &length);
            text = section_text(start, length);
            g->xread_cpu = field(text, "M19 PRESENT xread cpu=", "cpu");
            g->xread_pixmap = field(text, "M19 PRESENT xread pixmap=", "pixmap");
            g->xread_window = field(text, "M19 PRESENT xread pixmap=", "window");
            char *gpuwrite[] = {(char *)c->present_probe, "gpuwrite", NULL};
            (void)section_env(gpuwrite, c->dmabuf_env, SECTION_CAP / 16, c->gpu_ms, &start, &length);
            text = section_text(start, length);
            g->gpu_cpu = field(text, "M19 PRESENT gpuwrite renderer=", "cpu");
            const char *at = strstr(text, "M19 PRESENT gpuwrite renderer=");
            if (!at || sscanf(at, "M19 PRESENT gpuwrite renderer=%63s", g->dmabuf_renderer) != 1)
                snprintf(g->dmabuf_renderer, sizeof(g->dmabuf_renderer), "none");
            char *chain[] = {(char *)c->present_probe, "chain", NULL};
            (void)section_env(chain, c->dmabuf_env, SECTION_CAP / 16, c->gpu_ms, &start, &length);
            text = section_text(start, length);
            g->chain_cpu = field(text, "M19 PRESENT chain renderer=", "cpu");
            g->chain_pixmap = field(text, "M19 PRESENT chain pixmap=", "pixmap");
            g->chain_window = field(text, "M19 PRESENT chain pixmap=", "window");
            /* R4k. The same two, written after the X server imported the buffer, as a program draws into its back
             * buffer after handing it over: by the CPU, then by freedreno. Recorded, not judged. */
            char *xlate[] = {(char *)c->present_probe, "xlate", (char *)c->dmabuf_heap, NULL};
            (void)section_env(xlate, NULL, SECTION_CAP / 16, c->gpu_ms, &start, &length);
            text = section_text(start, length);
            g->xlate_cpu = field(text, "M19 PRESENT xlate cpu=", "cpu");
            g->xlate_pixmap = field(text, "M19 PRESENT xlate pixmap=", "pixmap");
            g->xlate_window = field(text, "M19 PRESENT xlate pixmap=", "window");
            char *chainlate[] = {(char *)c->present_probe, "chainlate", NULL};
            (void)section_env(chainlate, c->dmabuf_env, SECTION_CAP / 16, c->gpu_ms, &start, &length);
            text = section_text(start, length);
            g->chainlate_cpu = field(text, "M19 PRESENT chainlate renderer=", "cpu");
            g->chainlate_pixmap = field(text, "M19 PRESENT chainlate pixmap=", "pixmap");
            g->chainlate_window = field(text, "M19 PRESENT chainlate pixmap=", "window");
            g->late_ok = g->xlate_pixmap >= 990 && g->xlate_window >= 990 && g->chainlate_pixmap >= 990 && g->chainlate_window >= 990;
            /* R4l. Where the X server's view goes stale, and the least KGSL cache maintenance that makes a late
             * write visible: each operation alone and timed, a second import, a delayed read. Recorded in the log
             * as the probe prints them, not judged. */
            char *probe = (char *)c->present_probe, *heap = (char *)c->dmabuf_heap, *kgsl = (char *)c->kgsl_node;
            char *const r4l[][6] = {
                {probe, "kgslsync", heap, kgsl, NULL, NULL},
                {probe, "xsync", heap, kgsl, "obj-clean", NULL},
                {probe, "xsync", heap, kgsl, "cache-clean", NULL},
                {probe, "xsync", heap, kgsl, "obj-flush", NULL},
                {probe, "xagain", heap, NULL, NULL, NULL},
                {probe, "xwait", heap, NULL, NULL, NULL},
                {probe, "chainsync", kgsl, "obj-flush", NULL, NULL},
                {probe, "chainsync", kgsl, "cache-flush", NULL, NULL},
                {probe, "chainagain", NULL, NULL, NULL, NULL},
            };
            for (unsigned i = 0; i < sizeof(r4l) / sizeof(r4l[0]); i++)
                (void)section_env(r4l[i], !strncmp(r4l[i][1], "chain", 5) ? c->dmabuf_env : NULL, SECTION_CAP / 16, c->gpu_ms, &start, &length);
            /* R4m. Which layer keeps an import's stale view: the probe's own Mesa without X, glamor's calls
             * repeated in the probe on card0, Turnip's own import, and the X server importing again once the
             * first pixmap is freed. Recorded in the log as printed, not judged. */
            char *card = (char *)c->card, *gpu = (char *)c->gpu_probe;
            char *const r4m[][5] = {
                {probe, "glimport", heap, NULL, NULL},
                {probe, "gbmimport", heap, card, NULL},
                {gpu, "dmabuf", heap, NULL, NULL},
                {probe, "xreimport", heap, NULL, NULL},
            };
            const char *const *const r4m_env[] = {c->dmabuf_env, c->dmabuf_env, c->vk_env, NULL};
            for (unsigned i = 0; i < sizeof(r4m) / sizeof(r4m[0]); i++)
                (void)section_env(r4m[i], r4m_env[i], SECTION_CAP / 16, c->gpu_ms, &start, &length);
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
    (void)m19_wire_line(tty, c->pace_ms, M19_DEVICE_STEP " T12-gpu END %d %d %d %d %d %d %d %d %d %d %d %d %d %d", g->node, g->probe, g->vk,
                        g->cube, g->gl, g->gears, g->egl, g->glamor_ok, g->flip_ok, g->compositor_ok, g->vblank_ok, g->scanout_ok, g->copy_ok,
                        g->shows_ok);
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

struct audio {
    int card, control, playback, capture, snd_nodes, audio_ok;
};

struct speaker {
    int unit_rc, report_seen, report_valid, holder_alive, holder_fds, private_clean, speaker_ok;
    long ok, pid, entry_phase, fail_step, rc, session_rc, spk_stage, spk_fail_step;
    long regions_mapped, re_verified, re0_q12, re1_q12, volume_level, duration_ms, pcm_bytes;
    long buffers_sent, buffers_done, bytes_played, amp_on, amp_off_verified, teardown_rc, pdr_seen;
    long census_rc, census_why, ctl_writes, ctl_readbacks, resources_busy, ack_deferred;
    long terminal_action, anchors_held, anchor_fds_open, pool_held, regions_in_pool, unmap_attempted;
    char plan_sha[80];
};

static int is_digits_only(const char *s)
{
    if (!s || !*s)
        return 0;
    for (; *s; s++)
        if (*s < '0' || *s > '9')
            return 0;
    return 1;
}

static int is_hex64(const char *s)
{
    if (!s)
        return 0;
    size_t n = 0;
    for (; s[n]; n++)
        if (!((s[n] >= '0' && s[n] <= '9') || (s[n] >= 'a' && s[n] <= 'f')))
            return 0;
    return n == 64;
}

/* R5b: walk /dev/snd recursively when present, logging every entry for diagnostics. Dangling symlinks
 * (such as udev's by-path rule when no /dev/snd/controlC* exists) hold no device node; any character,
 * block, regular, FIFO, socket, top-level non-directory, live symlink target or unreadable directory counts. */
static int scan_snd(const char *path, int depth)
{
    if (!path || !*path || depth > 8)
        return 1;
    struct stat st;
    if (lstat(path, &st) != 0) {
        if (errno == ENOENT)
            return 0;
        addf("M19 snd-entry %s lstat_errno=%d\n", path, errno);
        return 1;
    }
    addf("M19 snd-entry %s mode=%o\n", path, (unsigned)st.st_mode);
    if (depth == 0 && !S_ISDIR(st.st_mode))
        return 1;
    if (S_ISLNK(st.st_mode)) {
        struct stat target;
        if (stat(path, &target) == 0)
            return 1;
        return errno == ENOENT ? 0 : 1;
    }
    if (!S_ISDIR(st.st_mode))
        return 1;
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return 1;
    DIR *dir = fdopendir(fd);
    if (!dir) {
        close(fd);
        return 1;
    }
    int count = 0;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(dir);
        if (!entry) {
            if (errno != 0)
                count++;
            break;
        }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;
        char child[1400];
        int n = snprintf(child, sizeof(child), "%s/%s", path, entry->d_name);
        if (n <= 0 || (size_t)n >= sizeof(child))
            count++;
        else
            count += scan_snd(child, depth + 1);
    }
    closedir(dir);
    return count;
}

static void speaker_init(struct speaker *sp)
{
    memset(sp, 0, sizeof(*sp));
    sp->unit_rc = -1;
    long *fields[] = {
        &sp->ok, &sp->pid, &sp->entry_phase, &sp->fail_step, &sp->rc, &sp->session_rc,
        &sp->spk_stage, &sp->spk_fail_step, &sp->regions_mapped, &sp->re_verified,
        &sp->re0_q12, &sp->re1_q12, &sp->volume_level, &sp->duration_ms, &sp->pcm_bytes,
        &sp->buffers_sent, &sp->buffers_done, &sp->bytes_played, &sp->amp_on,
        &sp->amp_off_verified, &sp->teardown_rc, &sp->pdr_seen, &sp->census_rc,
        &sp->census_why, &sp->ctl_writes, &sp->ctl_readbacks, &sp->resources_busy,
        &sp->ack_deferred, &sp->terminal_action, &sp->anchors_held, &sp->anchor_fds_open,
        &sp->pool_held, &sp->regions_in_pool, &sp->unmap_attempted,
    };
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++)
        *fields[i] = LONG_MIN;
}

static int parse_speaker_report(char *text, struct speaker *sp)
{
    struct spk_key { const char *name; long *slot; };
    const struct spk_key keys[] = {
        {"ok", &sp->ok},
        {"pid", &sp->pid},
        {"entry_phase", &sp->entry_phase},
        {"fail_step", &sp->fail_step},
        {"rc", &sp->rc},
        {"session_rc", &sp->session_rc},
        {"spk_stage", &sp->spk_stage},
        {"spk_fail_step", &sp->spk_fail_step},
        {"regions_mapped", &sp->regions_mapped},
        {"re_verified", &sp->re_verified},
        {"re0_q12", &sp->re0_q12},
        {"re1_q12", &sp->re1_q12},
        {"volume_level", &sp->volume_level},
        {"duration_ms", &sp->duration_ms},
        {"pcm_bytes", &sp->pcm_bytes},
        {"buffers_sent", &sp->buffers_sent},
        {"buffers_done", &sp->buffers_done},
        {"bytes_played", &sp->bytes_played},
        {"amp_on", &sp->amp_on},
        {"amp_off_verified", &sp->amp_off_verified},
        {"teardown_rc", &sp->teardown_rc},
        {"pdr_seen", &sp->pdr_seen},
        {"census_rc", &sp->census_rc},
        {"census_why", &sp->census_why},
        {"ctl_writes", &sp->ctl_writes},
        {"ctl_readbacks", &sp->ctl_readbacks},
        {"resources_busy", &sp->resources_busy},
        {"ack_deferred", &sp->ack_deferred},
        {"terminal_action", &sp->terminal_action},
        {"anchors_held", &sp->anchors_held},
        {"anchor_fds_open", &sp->anchor_fds_open},
        {"pool_held", &sp->pool_held},
        {"regions_in_pool", &sp->regions_in_pool},
        {"unmap_attempted", &sp->unmap_attempted},
    };
    int seen_sha = 0;
    for (char *line = strtok(text, "\n"); line; line = strtok(NULL, "\n")) {
        char *eq = strchr(line, '=');
        if (!eq || eq == line)
            return 0;
        *eq = 0;
        const char *val = eq + 1;
        if (!strcmp(line, "plan_sha256")) {
            if (seen_sha || strlen(val) >= sizeof(sp->plan_sha))
                return 0;
            snprintf(sp->plan_sha, sizeof(sp->plan_sha), "%s", val);
            seen_sha = 1;
            continue;
        }
        int matched = 0;
        for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
            if (strcmp(line, keys[i].name))
                continue;
            if (*keys[i].slot != LONG_MIN || !*val)
                return 0;
            char *end = NULL;
            errno = 0;
            long parsed = strtol(val, &end, 10);
            if (end == val || *end != 0 || errno || parsed == LONG_MIN)
                return 0;
            *keys[i].slot = parsed;
            matched = 1;
            break;
        }
        if (!matched)
            return 0;
    }
    return seen_sha;
}

static void check_speaker_holder(const struct m19_report *c, struct speaker *sp)
{
    if (!c->proc || sp->pid <= 1)
        return;
    char path[1024], stat_line[1024];
    snprintf(path, sizeof(path), "%s/%ld/stat", c->proc, sp->pid);
    if (!read_small(path, stat_line, sizeof(stat_line))) {
        const char *after = strrchr(stat_line, ')');
        char pstate = 0;
        if (after && sscanf(after + 1, " %c", &pstate) == 1)
            sp->holder_alive = pstate != 'Z' && pstate != 'X' && pstate != 'x';
    }
    snprintf(path, sizeof(path), "%s/%ld/fd", c->proc, sp->pid);
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        sp->holder_alive = 0;
        return;
    }
    DIR *dir = fdopendir(fd);
    if (!dir) {
        close(fd);
        sp->holder_alive = 0;
        return;
    }
    int fds = 0;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(dir);
        if (!entry) {
            if (errno != 0)
                fds = -1;
            break;
        }
        if (!is_digits_only(entry->d_name))
            continue;
        char item[1400];
        struct stat st;
        int n = snprintf(item, sizeof(item), "%s/%s", path, entry->d_name);
        if (n <= 0 || (size_t)n >= sizeof(item) || lstat(item, &st) != 0) {
            fds = -1;
            break;
        }
        fds++;
    }
    closedir(dir);
    sp->holder_fds = fds;
}

/* R5b: start marble-speaker.service once in T12-audio, wait for its atomic speaker.report, and verify
 * every Run31 gate, the live retaining holder in /proc, and absence of private audio nodes in /dev. */
static void speaker_phase(const struct m19_report *c, int tty, struct speaker *sp)
{
    speaker_init(sp);
    (void)m19_wire_line(tty, c->pace_ms, M19_DEVICE_STEP " T12-audio START");
    char *start_argv[] = {(char *)c->systemctl, "start", (char *)c->speaker_unit, NULL};
    sp->unit_rc = section(start_argv, SECTION_CAP / 16, c->command_ms);

    unsigned long long began = m19_now_ms(), deadline = began + c->speaker_ms, beat = began + c->beat_ms;
    unsigned wait_step = c->poll_ms && c->poll_ms < 50 ? c->poll_ms : 50;
    for (;;) {
        struct stat st;
        if (c->speaker_report && lstat(c->speaker_report, &st) == 0 && S_ISREG(st.st_mode) && st.st_size > 0) {
            sp->report_seen = 1;
            break;
        }
        unsigned long long now = m19_now_ms();
        if (sp->unit_rc != 0 || now >= deadline)
            break;
        if (c->beat_ms && now >= beat) {
            (void)m19_wire_line(tty, c->pace_ms, M19_DEVICE_BEAT " T12-audio %llu wait", (now - began) / 1000);
            beat = now + c->beat_ms;
        }
        (void)poll(NULL, 0, (int)wait_step);
    }

    if (sp->report_seen) {
        char raw[4096];
        if (file_text(c->speaker_report, raw, sizeof(raw)) > 0)
            sp->report_valid = parse_speaker_report(raw, sp);
    }
    check_speaker_holder(c, sp);

    sp->private_clean = 1;
    for (unsigned i = 0; i < sizeof(c->speaker_clean) / sizeof(c->speaker_clean[0]); i++) {
        if (!c->speaker_clean[i])
            continue;
        struct stat st;
        if (lstat(c->speaker_clean[i], &st) == 0 || errno != ENOENT) {
            addf("M19 R5 speaker-dirty %s\n", c->speaker_clean[i]);
            sp->private_clean = 0;
        }
    }

    sp->speaker_ok =
        sp->unit_rc == 0 &&
        sp->report_seen &&
        sp->report_valid &&
        sp->ok == 1 &&
        sp->pid > 1 &&
        sp->entry_phase == 7 &&
        sp->fail_step == 0 &&
        sp->rc == 0 &&
        sp->session_rc == 0 &&
        sp->spk_stage == 22 &&
        sp->spk_fail_step == 0 &&
        sp->regions_mapped == 2 &&
        sp->re_verified == 1 &&
        sp->re0_q12 > 0 &&
        sp->re1_q12 > 0 &&
        sp->volume_level > 0 && sp->volume_level <= 8 &&
        sp->duration_ms > 0 && sp->duration_ms <= 5000 &&
        sp->pcm_bytes > 0 &&
        sp->buffers_sent >= 1 &&
        sp->buffers_done == sp->buffers_sent &&
        sp->bytes_played == sp->pcm_bytes &&
        sp->amp_on == 1 &&
        sp->amp_off_verified == 1 &&
        sp->teardown_rc == 0 &&
        sp->pdr_seen == 0 &&
        sp->census_rc == 0 &&
        sp->census_why == 0 &&
        sp->resources_busy == 1 &&
        sp->terminal_action == 3 &&
        sp->anchors_held == 2 &&
        sp->anchor_fds_open == 4 &&
        sp->pool_held == 1 &&
        sp->regions_in_pool == 2 &&
        sp->unmap_attempted == 0 &&
        is_hex64(sp->plan_sha) &&
        sp->holder_alive &&
        sp->holder_fds >= 8 &&
        sp->private_clean;

    (void)m19_wire_line(tty, c->pace_ms, M19_DEVICE_STEP " T12-audio %s %d %ld %ld %d %d",
                        sp->speaker_ok ? "OK" : "FAIL", sp->speaker_ok,
                        sp->spk_stage == LONG_MIN ? -1L : sp->spk_stage,
                        sp->bytes_played == LONG_MIN ? -1L : sp->bytes_played,
                        sp->holder_alive, sp->holder_fds);
}

/* R5a/R5b: Run12's registration as the session sees it, read-only. The card by name and its index, its control
 * device in sysfs, a playback and a capture PCM, and zero sound device nodes in /dev/snd. */
static void audio_phase(const struct m19_report *c, struct audio *a, const struct speaker *sp)
{
    char text[8192], path[1100];
    a->card = -1;
    if (!read_small(c->asound_cards, text, sizeof(text)))
        for (char *line = strtok(text, "\n"); line; line = strtok(NULL, "\n")) {
            int index, used = 0;
            if (sscanf(line, " %d [%n", &index, &used) == 1 && used && index >= 0 && strstr(line, c->audio_card) && a->card < 0)
                a->card = index;
        }
    if (a->card >= 0) {
        char number[64];
        unsigned major = 0, minor = 0;
        char extra;
        snprintf(path, sizeof(path), "%s/controlC%d/dev", c->sound_class, a->card);
        a->control = !read_small(path, number, sizeof(number)) && sscanf(number, "%u:%u%c", &major, &minor, &extra) >= 2 && major > 0;
        if (!read_small(c->asound_pcm, text, sizeof(text))) {
            char prefix[16];
            snprintf(prefix, sizeof(prefix), "%02d-", a->card);
            for (char *line = strtok(text, "\n"); line; line = strtok(NULL, "\n"))
                if (!strncmp(line, prefix, strlen(prefix))) {
                    a->playback |= strstr(line, "playback") != NULL;
                    a->capture |= strstr(line, "capture") != NULL;
                }
        }
    }
    a->snd_nodes = scan_snd(c->snd_dev, 0);
    a->audio_ok = a->card >= 0 && a->control && a->playback && a->capture && !a->snd_nodes && (!c->speaker_unit || sp->speaker_ok);
}

/* ------------------------------------------------------------------ R6 -------------------------------------------- */

/* The value of key in "key=value" lines, matched at a line's start; LONG_MIN when absent or not a number. */
static long kv_long(const char *text, const char *key)
{
    size_t n = strlen(key);
    for (const char *line = text; line && *line; line = strchr(line, '\n') ? strchr(line, '\n') + 1 : NULL) {
        if (strncmp(line, key, n) || line[n] != '=')
            continue;
        char *end;
        errno = 0;
        long value = strtol(line + n + 1, &end, 10);
        return end == line + n + 1 || errno || (*end && *end != '\n') ? LONG_MIN : value;
    }
    return LONG_MIN;
}

static void kv_text(const char *text, const char *key, char *value, size_t room)
{
    size_t n = strlen(key);
    value[0] = 0;
    for (const char *line = text; line && *line; line = strchr(line, '\n') ? strchr(line, '\n') + 1 : NULL) {
        if (strncmp(line, key, n) || line[n] != '=')
            continue;
        size_t length = strcspn(line + n + 1, "\n");
        if (length >= room)
            length = room - 1;
        memcpy(value, line + n + 1, length);
        value[length] = 0;
        return;
    }
}

struct wifi {
    int ready, connected, route, ping, dns, wifi_ok;
    long waited_ms;
    char result[96], iface[32];
};

/* The default route's gateway on iface, from /proc/net/route. */
static int gateway_of(const struct m19_report *c, const char *iface, struct in_addr *gateway)
{
    char text[8192];
    if (read_small(c->route, text, sizeof(text)))
        return 0;
    for (char *line = strtok(text, "\n"); line; line = strtok(NULL, "\n")) {
        char name[32];
        unsigned destination, via, flags;
        if (sscanf(line, "%31s %x %x %x", name, &destination, &via, &flags) != 4 || strcmp(name, iface))
            continue;
        if (destination == 0 && (flags & 0x3) == 0x3 && via) {
            gateway->s_addr = via; /* already in network order, as the kernel prints it */
            return 1;
        }
    }
    return 0;
}

static uint16_t icmp_sum(const void *data, size_t size)
{
    const uint8_t *p = data;
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < size; i += 2)
        sum += (uint32_t)(p[i] << 8 | p[i + 1]);
    if (size & 1)
        sum += (uint32_t)p[size - 1] << 8;
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return htons((uint16_t)~sum);
}

/* Up to three ICMP echoes to the gateway through iface; 1 at the first reply. The tree has no ping(8). */
static int gateway_ping(const char *iface, struct in_addr gateway)
{
    int fd = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMP);
    if (fd < 0)
        return 0;
    (void)setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, iface, (socklen_t)strlen(iface) + 1);
    struct sockaddr_in to = {.sin_family = AF_INET, .sin_addr = gateway};
    uint16_t id = (uint16_t)(getpid() & 0xffff);
    int ok = 0;
    for (uint16_t seq = 1; seq <= 3 && !ok; seq++) {
        struct {
            struct icmphdr h;
            char data[32];
        } ping;
        memset(&ping, 0, sizeof(ping));
        ping.h.type = ICMP_ECHO;
        ping.h.un.echo.id = htons(id);
        ping.h.un.echo.sequence = htons(seq);
        memcpy(ping.data, "M19 R6 gateway", 14);
        ping.h.checksum = icmp_sum(&ping, sizeof(ping));
        if (sendto(fd, &ping, sizeof(ping), 0, (struct sockaddr *)&to, sizeof(to)) != (ssize_t)sizeof(ping))
            continue;
        unsigned long long end = m19_now_ms() + 2000;
        while (!ok && m19_now_ms() < end) {
            struct pollfd p = {fd, POLLIN, 0};
            if (poll(&p, 1, 100) <= 0)
                continue;
            unsigned char packet[256];
            struct sockaddr_in from;
            socklen_t length = sizeof(from);
            ssize_t n = recvfrom(fd, packet, sizeof(packet), 0, (struct sockaddr *)&from, &length);
            if (n < (ssize_t)sizeof(struct iphdr))
                continue;
            size_t header = (size_t)(packet[0] & 0x0f) * 4;
            if (n < (ssize_t)(header + sizeof(struct icmphdr)) || from.sin_addr.s_addr != gateway.s_addr)
                continue;
            const struct icmphdr *reply = (const void *)(packet + header);
            ok = reply->type == ICMP_ECHOREPLY && ntohs(reply->un.echo.id) == id && ntohs(reply->un.echo.sequence) == seq;
        }
    }
    close(fd);
    return ok;
}

/* R6: T12-wifi. m19-wifi's result, NetworkManager's state for that interface, the default route through it and
 * its gateway's echo. No network name, address or credential is printed. */
static void wifi_phase(const struct m19_report *c, int tty, struct wifi *w)
{
    memset(w, 0, sizeof(*w));
    snprintf(w->result, sizeof(w->result), "none");
    (void)m19_wire_line(tty, c->pace_ms, M19_DEVICE_STEP " T12-wifi START");
    unsigned long long start = m19_now_ms(), end = start + c->wifi_ms, beat = start + c->beat_ms;
    for (;;) {
        char text[128];
        if (!read_small(c->wifi_result, text, sizeof(text))) {
            text[strcspn(text, "\n")] = 0;
            snprintf(w->result, sizeof(w->result), "%.95s", text);
            w->ready = !strncmp(text, "ready ", 6) && text[6];
            if (w->ready)
                snprintf(w->iface, sizeof(w->iface), "%.31s", text + 6);
        }
        if (w->ready && !w->connected) {
            static char out[8192];
            size_t taken = 0;
            char *argv[] = {(char *)c->nmcli, "-t", "-f", "DEVICE,TYPE,STATE", "device", NULL};
            if (!run_quiet(c, argv, (unsigned char *)out, sizeof(out) - 1, &taken)) {
                out[taken] = 0;
                char want[64];
                snprintf(want, sizeof(want), "%s:wifi:connected", w->iface);
                for (char *line = strtok(out, "\n"); line; line = strtok(NULL, "\n"))
                    w->connected |= !strcmp(line, want);
            }
        }
        unsigned long long now = m19_now_ms();
        if (w->connected || now >= end || (!w->ready && strcmp(w->result, "none") && strncmp(w->result, "ready", 5)))
            break;
        if (now >= beat) {
            (void)m19_wire_line(tty, c->pace_ms, M19_DEVICE_BEAT " T12-wifi %llu %d", (now - start) / 1000, w->ready);
            beat = now + c->beat_ms;
        }
        (void)poll(NULL, 0, 1000);
    }
    w->waited_ms = (long)(m19_now_ms() - start);
    struct in_addr gateway = {0};
    if (w->connected) {
        /* DHCP may still be settling when NetworkManager says connected: give the route ten seconds. */
        for (unsigned i = 0; i < 20 && !(w->route = gateway_of(c, w->iface, &gateway)); i++)
            (void)poll(NULL, 0, 500);
    }
    if (w->route)
        w->ping = gateway_ping(w->iface, gateway);
    if (w->route && c->getent && c->dns_name) {
        unsigned char out[512];
        size_t taken = 0;
        char *argv[] = {(char *)c->getent, "hosts", (char *)c->dns_name, NULL};
        w->dns = capture(argv, out, sizeof(out), &taken, c->command_ms) == 0;
    }
    w->wifi_ok = w->ready && w->connected && w->route && w->ping;
    (void)m19_wire_line(tty, c->pace_ms, M19_DEVICE_STEP " T12-wifi %s %d %d %d %d", w->wifi_ok ? "OK" : "FAIL", w->ready, w->connected,
                        w->route, w->ping);
}

/* R7: T12-ce. The keypad (ce_unit) takes the owner's PIN once and hands it to the broker in the TEE island; the keypad
 * records the broker's one status line in ce_result. Judged by that status and by Android's own storage: ce_entry has
 * its real name in ce_android only once the CE key is in. Counts only: no entry name is printed. */
struct ce {
    int unit_rc, result_seen, status_ok, entry_seen, entries, ce_ok;
    long waited_ms;
    char status[32];
};

static void ce_status(const char *text, char *status, size_t room)
{
    static const char head[] = "M19_CE status=";
    status[0] = 0;
    if (strncmp(text, head, sizeof(head) - 1))
        return;
    const char *word = text + sizeof(head) - 1;
    size_t length = strcspn(word, " \n");
    for (size_t i = 0; i < length; i++)
        if (!((word[i] >= 'A' && word[i] <= 'Z') || word[i] == '_'))
            return;
    if (length && length < room) {
        memcpy(status, word, length);
        status[length] = 0;
    }
}

static void ce_phase(const struct m19_report *c, int tty, struct ce *e)
{
    memset(e, 0, sizeof(*e));
    e->unit_rc = -1;
    e->entries = -1;
    (void)m19_wire_line(tty, c->pace_ms, M19_DEVICE_STEP " T12-ce START");
    char *start_argv[] = {(char *)c->systemctl, "start", (char *)c->ce_unit, NULL};
    e->unit_rc = section(start_argv, SECTION_CAP / 16, c->command_ms);
    static char text[512];
    unsigned long long began = m19_now_ms(), deadline = began + c->ce_ms, beat = began + c->beat_ms;
    for (;;) {
        if (file_text(c->ce_result, text, sizeof(text)) > 0) {
            e->result_seen = 1;
            break;
        }
        unsigned long long now = m19_now_ms();
        if (e->unit_rc != 0 || now >= deadline)
            break;
        if (c->beat_ms && now >= beat) {
            (void)m19_wire_line(tty, c->pace_ms, M19_DEVICE_BEAT " T12-ce %llu wait", (now - began) / 1000);
            beat = now + c->beat_ms;
        }
        (void)poll(NULL, 0, 200);
    }
    e->waited_ms = (long)(m19_now_ms() - began);
    if (e->result_seen)
        ce_status(text, e->status, sizeof(e->status));
    e->status_ok = !strcmp(e->status, "OK");
    DIR *directory = opendir(c->ce_android);
    if (directory) {
        e->entries = 0;
        for (struct dirent *entry; (entry = readdir(directory));) {
            if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
                continue;
            e->entries++;
            e->entry_seen |= !strcmp(entry->d_name, c->ce_entry);
        }
        closedir(directory);
    }
    e->ce_ok = e->status_ok && e->entry_seen;
    (void)m19_wire_line(tty, c->pace_ms, M19_DEVICE_STEP " T12-ce %s %s %d %d", e->ce_ok ? "OK" : "FAIL", e->status[0] ? e->status : "none",
                        e->entry_seen, e->entries);
}

/* R8: T12-battery. upower must be running (the session's power manager and panel start it), show the battery at
 * the percentage the kernel reads, within two points, in a known state, and the power manager must run. */
struct battery {
    int unit_active, capacity, upower_pct, pm_running, battery_ok;
    char status[24], state[24];
};

static void battery_phase(const struct m19_report *c, int tty, struct battery *b)
{
    memset(b, 0, sizeof(*b));
    b->capacity = b->upower_pct = -1;
    (void)m19_wire_line(tty, c->pace_ms, M19_DEVICE_STEP " T12-battery START");
    char *active[] = {(char *)c->systemctl, "is-active", (char *)c->battery_unit, NULL};
    b->unit_active = section(active, SECTION_CAP / 16, c->command_ms) == 0;
    char path[600], value[32];
    long number;
    snprintf(path, sizeof(path), "%s/capacity", c->battery_dir);
    if (!read_long(path, &number) && number >= 0 && number <= 100)
        b->capacity = (int)number;
    snprintf(path, sizeof(path), "%s/status", c->battery_dir);
    if (!read_small(path, b->status, sizeof(b->status)))
        b->status[strcspn(b->status, "\n")] = 0;
    char *info[] = {(char *)c->upower, "-i", (char *)c->upower_device, NULL};
    size_t start = 0, length = 0;
    if (section_env(info, NULL, SECTION_CAP / 8, c->command_ms, &start, &length) == 0) {
        char *text = section_text(start, length);
        line_value(text, "percentage:", value, sizeof(value));
        char *end;
        errno = 0;
        number = strtol(value, &end, 10);
        if (end != value && !errno && *end == '%' && number >= 0 && number <= 100)
            b->upower_pct = (int)number;
        line_value(text, "state:", b->state, sizeof(b->state));
    }
    b->pm_running = pid_of(c, c->battery_pm) > 0;
    int near = b->capacity >= 0 && b->upower_pct >= 0 && abs(b->capacity - b->upower_pct) <= 2;
    int known = b->state[0] && strcmp(b->state, "unknown");
    b->battery_ok = b->unit_active && near && known && b->pm_running;
    (void)m19_wire_line(tty, c->pace_ms, M19_DEVICE_STEP " T12-battery %s %d %d %s %d", b->battery_ok ? "OK" : "FAIL", b->capacity, b->upower_pct,
                        token(b->state), b->pm_running);
}

/* R8: T12-persist. This boot's id goes to persist_path in the tree through a temporary name, the file and its
 * directory each synced, and is read back. Android's check after the run reads the same file from /data. */
struct persist {
    int had, on_disk, written, synced, read_back, persist_ok;
    char id[40];
};

static void persist_phase(const struct m19_report *c, int tty, struct persist *p)
{
    memset(p, 0, sizeof(*p));
    (void)m19_wire_line(tty, c->pace_ms, M19_DEVICE_STEP " T12-persist START");
    char text[64], directory[512], temporary[600], line[64], back[64];
    if (!read_small(c->boot_id, text, sizeof(text))) {
        text[strcspn(text, "\n")] = 0;
        if (strlen(text) == 36 && strspn(text, "0123456789abcdef-") == 36)
            memcpy(p->id, text, 37);
    }
    snprintf(directory, sizeof(directory), "%s", c->persist_path);
    char *slash = strrchr(directory, '/');
    if (p->id[0] && slash && slash != directory) {
        *slash = 0;
        p->had = !access(c->persist_path, F_OK);
        if (mkdir(directory, 0755) && errno != EEXIST)
            directory[0] = 0;
        struct statfs fs;
        p->on_disk = directory[0] && !statfs(directory, &fs) && (unsigned long)fs.f_type == c->persist_fs;
        int length = snprintf(line, sizeof(line), "M19 R8 %s\n", p->id);
        snprintf(temporary, sizeof(temporary), "%s.new", c->persist_path);
        int fd = p->on_disk ? open(temporary, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0644) : -1;
        if (fd >= 0) {
            p->written = write(fd, line, (size_t)length) == length;
            p->synced = !fsync(fd);
            close(fd);
        }
        if (p->written && p->synced && !rename(temporary, c->persist_path)) {
            int dfd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            p->synced = dfd >= 0 && !fsync(dfd);
            if (dfd >= 0)
                close(dfd);
        } else {
            p->synced = 0;
        }
        p->read_back = p->synced && !read_small(c->persist_path, back, sizeof(back)) && !strcmp(back, line);
    }
    p->persist_ok = p->on_disk && p->written && p->synced && p->read_back;
    (void)m19_wire_line(tty, c->pace_ms, M19_DEVICE_STEP " T12-persist %s %d %d %d %d", p->persist_ok ? "OK" : "FAIL", p->on_disk, p->written,
                        p->synced, p->read_back);
}

/* R8: T12-media, once the CE key is in. media_view must be a read-only mount listing what ce_android lists, and the
 * first JPEG or PNG a bounded walk meets must start with its format's bytes. No name is printed. */
struct media {
    int mounted_ro, entries, same, walked, kind_ok, media_ok;
    char kind[8];
};

/* 1 for a JPEG or PNG that reads as one, 0 for one that does not, -1 for any other file. */
static int media_magic(const char *path, char *kind, size_t room)
{
    const char *dot = strrchr(path, '/');
    dot = strrchr(dot ? dot : path, '.');
    int jpeg = dot && (!strcasecmp(dot, ".jpg") || !strcasecmp(dot, ".jpeg")), png = dot && !strcasecmp(dot, ".png");
    if (!jpeg && !png)
        return -1;
    snprintf(kind, room, "%s", jpeg ? "jpeg" : "png");
    unsigned char head[8];
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0)
        return 0;
    ssize_t n = read(fd, head, sizeof(head));
    close(fd);
    if (jpeg)
        return n >= 3 && head[0] == 0xff && head[1] == 0xd8 && head[2] == 0xff;
    return n == 8 && !memcmp(head, "\x89PNG\r\n\x1a\n", 8);
}

static int media_walk(const char *directory, unsigned depth, unsigned *budget, char *kind, size_t room)
{
    DIR *dir = opendir(directory);
    if (!dir)
        return -1;
    int result = -1;
    struct dirent *entry;
    while (result < 0 && *budget && (entry = readdir(dir))) {
        if (entry->d_name[0] == '.')
            continue;
        (*budget)--;
        char path[4096];
        struct stat st;
        if (snprintf(path, sizeof(path), "%s/%s", directory, entry->d_name) >= (int)sizeof(path) || lstat(path, &st))
            continue;
        if (S_ISREG(st.st_mode))
            result = media_magic(path, kind, room);
        else if (S_ISDIR(st.st_mode) && depth > 1)
            result = media_walk(path, depth - 1, budget, kind, room);
    }
    closedir(dir);
    return result;
}

static int mounted_ro(const char *mountinfo, const char *point)
{
    FILE *file = fopen(mountinfo, "re");
    if (!file)
        return 0;
    char line[4096];
    int found = 0, ro = 1;
    while (fgets(line, sizeof(line), file)) {
        char *field[8];
        int count = 0;
        for (char *token = strtok(line, " \n"); token && count < 8; token = strtok(NULL, " \n"))
            field[count++] = token;
        if (count < 6 || strcmp(field[4], point))
            continue;
        found = 1;
        ro &= starts_ro(field[5]);
    }
    fclose(file);
    return found && ro;
}

static int count_entries(const char *path)
{
    DIR *directory = opendir(path);
    if (!directory)
        return -1;
    int entries = 0;
    for (struct dirent *entry; (entry = readdir(directory));)
        entries += strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..");
    closedir(directory);
    return entries;
}

static void media_phase(const struct m19_report *c, int tty, int ce_entries, struct media *m)
{
    memset(m, 0, sizeof(*m));
    snprintf(m->kind, sizeof(m->kind), "none");
    (void)m19_wire_line(tty, c->pace_ms, M19_DEVICE_STEP " T12-media START");
    m->mounted_ro = mounted_ro(c->mountinfo, c->media_view);
    m->entries = count_entries(c->media_view);
    m->same = m->entries >= 0 && m->entries == ce_entries;
    unsigned budget = c->media_walk;
    int found = media_walk(c->media_view, c->media_depth, &budget, m->kind, sizeof(m->kind));
    m->walked = (int)(c->media_walk - budget);
    m->kind_ok = found == 1;
    m->media_ok = m->mounted_ro && m->same && m->kind_ok;
    (void)m19_wire_line(tty, c->pace_ms, M19_DEVICE_STEP " T12-media %s %d %d %s", m->media_ok ? "OK" : "FAIL", m->mounted_ro, m->entries,
                        m->kind);
}

struct sink {
    int unit_rc, report_seen, streaming, chord_ok, holder_alive, holder_fds, private_clean, held_empty, pulse_unit_rc, pulse_sink,
        pulse_default, tone_rc;
    int amp_off_before, tone_loud, tone_peaks, amp_on_seen, amp_idle_off, sink_ok;
    long pid, regions, re_verified, re0, re1, played, pcm, pdr_seen, unmap_attempted, volume_level;
    long loud_before, loud_after, enables_before, enables_after, disables_before, disables_after, peak_in, peak_out, underruns;
    char state[16], plan_sha[80];
};

/* R6b: Run31's private directory while the sink streams. Its backend unlinks each node as it opens it and removes the
 * directory only at release, which a streaming sink does not reach: an empty directory, 0700, owned by uid. A link,
 * another shape or mode, another owner or any entry in it is dirty. */
static int held_dir_empty(const char *path, unsigned uid)
{
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return 0;
    struct stat st;
    if (fstat(fd, &st) || st.st_uid != uid || (st.st_mode & 07777) != 0700) {
        close(fd);
        return 0;
    }
    DIR *directory = fdopendir(fd);
    if (!directory) {
        close(fd);
        return 0;
    }
    int entries = 0;
    for (struct dirent *entry; (entry = readdir(directory));)
        entries += strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..");
    closedir(directory);
    return entries == 0;
}

static int sink_status_now(const struct m19_report *c, char *text, size_t room)
{
    return file_text(c->sink_status, text, room) > 0;
}

/* Run1 of the tone file: one second of a full-scale 1 kHz tone, 48 kHz stereo s16le, so the sink's -10 dB and its
 * clamp are what keep it at -10 dBFS. */
static int write_tone(const char *path)
{
    static int16_t pcm[48000 * 2];
    for (unsigned i = 0; i < 48000; i++) {
        /* a sine from a 48-step table of a quarter wave would do; the integer form avoids libm */
        unsigned phase = i % 48;
        static const int16_t quarter[13] = {0, 4277, 8481, 12539, 16383, 19947, 23170, 25996, 28377, 30273, 31650, 32487, 32767};
        int16_t v = phase <= 12 ? quarter[phase] : phase <= 24 ? quarter[24 - phase] : phase <= 36 ? (int16_t)-quarter[phase - 24] : (int16_t)-quarter[48 - phase];
        pcm[2 * i] = pcm[2 * i + 1] = v;
    }
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0644);
    if (fd < 0)
        return 0;
    ssize_t n = write(fd, pcm, sizeof(pcm));
    return !close(fd) && n == (ssize_t)sizeof(pcm);
}

/* R6: T12-audio for the sound server. The chord (Run31's gates, as R5b judged them) and the switch to the stream,
 * then (R6b) PulseAudio started, then a tone through PulseAudio's default sink, which must be marble_speaker. */
static void sink_phase(const struct m19_report *c, int tty, struct sink *k)
{
    memset(k, 0, sizeof(*k));
    k->unit_rc = -1;
    snprintf(k->state, sizeof(k->state), "none");
    (void)m19_wire_line(tty, c->pace_ms, M19_DEVICE_STEP " T12-audio START");
    char *start_argv[] = {(char *)c->systemctl, "start", (char *)c->sink_unit, NULL};
    k->unit_rc = section(start_argv, SECTION_CAP / 16, c->command_ms);
    static char text[8192];
    unsigned long long began = m19_now_ms(), deadline = began + c->sink_ms, beat = began + c->beat_ms;
    for (;;) {
        if (file_text(c->sink_report, text, sizeof(text)) > 0) {
            k->report_seen = 1;
            kv_text(text, "state", k->state, sizeof(k->state));
            if (strcmp(k->state, "pre"))
                break;
        }
        unsigned long long now = m19_now_ms();
        if (k->unit_rc != 0 || now >= deadline)
            break;
        if (c->beat_ms && now >= beat) {
            (void)m19_wire_line(tty, c->pace_ms, M19_DEVICE_BEAT " T12-audio %llu wait", (now - began) / 1000);
            beat = now + c->beat_ms;
        }
        (void)poll(NULL, 0, 50);
    }
    if (k->report_seen) {
        k->streaming = kv_long(text, "streaming") == 1 && !strcmp(k->state, "streaming");
        k->chord_ok = kv_long(text, "chord_ok") == 1;
        k->pid = kv_long(text, "pid");
        k->regions = kv_long(text, "regions_mapped");
        k->re_verified = kv_long(text, "re_verified");
        k->re0 = kv_long(text, "re0_q12");
        k->re1 = kv_long(text, "re1_q12");
        k->played = kv_long(text, "bytes_played");
        k->pcm = kv_long(text, "pcm_bytes");
        k->pdr_seen = kv_long(text, "pdr_seen");
        k->unmap_attempted = kv_long(text, "unmap_attempted");
        k->volume_level = kv_long(text, "volume_level");
        kv_text(text, "plan_sha256", k->plan_sha, sizeof(k->plan_sha));
    }
    struct speaker holder;
    speaker_init(&holder);
    holder.pid = k->pid;
    check_speaker_holder(c, &holder);
    k->holder_alive = holder.holder_alive;
    k->holder_fds = holder.holder_fds;
    k->private_clean = 1;
    for (unsigned i = 0; i < sizeof(c->speaker_clean) / sizeof(c->speaker_clean[0]); i++) {
        struct stat st;
        const char *path = c->speaker_clean[i];
        if (!path || (lstat(path, &st) != 0 && errno == ENOENT))
            continue;
        if (k->streaming && c->held_dir && !strcmp(path, c->held_dir) && held_dir_empty(path, c->held_uid)) {
            addf("M19 R6 sink-held %s empty\n", path);
            k->held_empty = 1;
            continue;
        }
        addf("M19 R6 sink-dirty %s\n", path);
        k->private_clean = 0;
    }
    /* R6b: PulseAudio, started here once the sink streams (nothing in the session starts it for root); then the pipe
     * sink exists and is the default. */
    k->pulse_unit_rc = -1;
    if (k->streaming && c->pulse_unit) {
        char *pulse_argv[] = {(char *)c->systemctl, "start", (char *)c->pulse_unit, NULL};
        k->pulse_unit_rc = section(pulse_argv, SECTION_CAP / 16, c->command_ms);
    }
    unsigned long long pulse_end = m19_now_ms() + c->sink_ms;
    while (k->streaming && !k->pulse_sink && m19_now_ms() < pulse_end) {
        static char out[8192];
        size_t taken = 0;
        char *argv[] = {(char *)c->pactl, "list", "short", "sinks", NULL};
        if (!capture_env(argv, c->pulse_env, (unsigned char *)out, sizeof(out) - 1, &taken, c->command_ms)) {
            out[taken] = 0;
            k->pulse_sink = strstr(out, c->sink_name) != NULL;
        }
        if (!k->pulse_sink)
            (void)poll(NULL, 0, 1000);
    }
    if (k->pulse_sink) {
        char out[256];
        size_t taken = 0;
        char *argv[] = {(char *)c->pactl, "get-default-sink", NULL};
        if (!capture_env(argv, c->pulse_env, (unsigned char *)out, sizeof(out) - 1, &taken, c->command_ms)) {
            out[taken] = 0;
            out[strcspn(out, "\n")] = 0;
            k->pulse_default = !strcmp(out, c->sink_name);
        }
    }
    char status[1024] = "";
    /* The tone goes to the sink by name, so the default sink (what desktop programs use) is a gate of its own. */
    if (k->pulse_sink && write_tone(c->tone_path)) {
        /* The chord's silence first switches the amplifier off; the tone must switch it on again. */
        unsigned long long off_end = m19_now_ms() + c->idle_wait_ms;
        while (m19_now_ms() < off_end && !(sink_status_now(c, status, sizeof(status)) && kv_long(status, "amp_on") == 0))
            (void)poll(NULL, 0, 200);
        k->amp_off_before = sink_status_now(c, status, sizeof(status)) && kv_long(status, "amp_on") == 0;
        k->loud_before = kv_long(status, "bytes_loud");
        k->enables_before = kv_long(status, "amp_enables");
        k->disables_before = kv_long(status, "amp_disables");
        char device[96];
        snprintf(device, sizeof(device), "--device=%.80s", c->sink_name);
        char *argv[] = {(char *)c->pacat, "--playback", "--raw", "--format=s16le", "--rate=48000", "--channels=2", "--latency-msec=100", device,
                        (char *)c->tone_path, NULL};
        size_t ignored;
        unsigned char out[1024];
        k->tone_rc = capture_env(argv, c->pulse_env, out, sizeof(out), &ignored, c->tone_ms);
        (void)poll(NULL, 0, 1500);
        if (sink_status_now(c, status, sizeof(status))) {
            k->loud_after = kv_long(status, "bytes_loud");
            k->enables_after = kv_long(status, "amp_enables");
            k->peak_in = kv_long(status, "peak_in");
            k->peak_out = kv_long(status, "peak_out");
            k->underruns = kv_long(status, "underruns");
        }
        k->tone_loud = k->loud_after != LONG_MIN && k->loud_before != LONG_MIN && k->loud_after - k->loud_before >= 172800; /* 90 % */
        k->tone_peaks = k->peak_in >= 30000 && k->peak_out >= 9000 && k->peak_out <= 10362;
        k->amp_on_seen = k->enables_after != LONG_MIN && k->enables_before != LONG_MIN && k->enables_after > k->enables_before;
        unsigned long long idle_end = m19_now_ms() + c->idle_wait_ms;
        while (m19_now_ms() < idle_end) {
            if (sink_status_now(c, status, sizeof(status)) && kv_long(status, "amp_on") == 0 && kv_long(status, "amp_disables") > k->disables_before)
                break;
            (void)poll(NULL, 0, 200);
        }
        k->disables_after = kv_long(status, "amp_disables");
        k->amp_idle_off = kv_long(status, "amp_on") == 0 && k->disables_after != LONG_MIN && k->disables_after > k->disables_before;
    }
    k->sink_ok = k->unit_rc == 0 && k->report_seen && k->streaming && k->chord_ok && k->regions == 2 && k->re_verified == 1 && k->re0 > 0 &&
                 k->re1 > 0 && k->pcm > 0 && k->played == k->pcm && k->pdr_seen == 0 && k->unmap_attempted == 0 && k->volume_level > 0 &&
                 k->volume_level <= 8 && is_hex64(k->plan_sha) && k->holder_alive && k->holder_fds >= 8 && k->private_clean &&
                 (!c->pulse_unit || k->pulse_unit_rc == 0) &&
                 k->pulse_sink && k->pulse_default && k->tone_rc == 0 && k->amp_off_before && k->tone_loud && k->tone_peaks &&
                 k->amp_on_seen && k->amp_idle_off;
    (void)m19_wire_line(tty, c->pace_ms, M19_DEVICE_STEP " T12-audio %s %d %d %d %d %d", k->sink_ok ? "OK" : "FAIL", k->chord_ok,
                        k->streaming, k->tone_loud, k->tone_peaks, k->amp_idle_off);
}

/* The bytes of the profile's network name, as NetworkManager's keyfile holds them: a byte list such as 97;98;99; */
static size_t profile_ssid(const char *path, unsigned char *ssid, size_t room)
{
    char text[4096], value[512];
    if (!path || read_small(path, text, sizeof(text)))
        return 0;
    kv_text(text, "ssid", value, sizeof(value));
    size_t n = 0;
    for (char *at = value; *at && n < room;) {
        char *end;
        unsigned long byte = strtoul(at, &end, 10);
        if (end == at || *end != ';' || byte > 255)
            return 0;
        ssid[n++] = (unsigned char)byte;
        at = end + 1;
    }
    explicit_bzero(text, sizeof(text));
    return n;
}

static int is_hexdigit(int ch)
{
    return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
}

/* R6: blanks, in place, the profile's SSID, every MAC address and every dotted IPv4 address in the report. */
static void redact(const struct m19_report *c, unsigned *ssids, unsigned *macs, unsigned *addresses)
{
    unsigned char ssid[32];
    size_t length = profile_ssid(c->nm_profile, ssid, sizeof(ssid));
    *ssids = *macs = *addresses = 0;
    if (length >= 2)
        for (unsigned char *at = report; (at = memmem(at, used - (size_t)(at - report), ssid, length)); at += length) {
            memset(at, '*', length);
            (*ssids)++;
        }
    explicit_bzero(ssid, sizeof(ssid));
    for (size_t i = 0; i + 17 <= used; i++) {
        unsigned char *p = report + i;
        int mac = (i == 0 || (!is_hexdigit(p[-1]) && p[-1] != ':')) && (i + 17 == used || (!is_hexdigit(p[17]) && p[17] != ':'));
        for (unsigned j = 0; mac && j < 17; j++)
            mac = j % 3 == 2 ? p[j] == ':' : is_hexdigit(p[j]);
        if (mac) {
            for (unsigned j = 0; j < 17; j++)
                if (j % 3 != 2)
                    p[j] = 'x';
            (*macs)++;
            i += 16;
        }
    }
    for (size_t i = 0; i < used; i++) {
        if (report[i] < '0' || report[i] > '9' || (i && ((report[i - 1] >= '0' && report[i - 1] <= '9') || report[i - 1] == '.')))
            continue;
        size_t j = i;
        int parts = 0, ok = 1;
        while (ok && parts < 4) {
            size_t digits = 0;
            while (j < used && report[j] >= '0' && report[j] <= '9' && digits < 4) {
                j++;
                digits++;
            }
            ok = digits >= 1 && digits <= 3;
            parts++;
            if (ok && parts < 4) {
                ok = j < used && report[j] == '.';
                j++;
            }
        }
        if (!ok || parts != 4 || (j < used && ((report[j] >= '0' && report[j] <= '9') || report[j] == '.')))
            continue;
        for (size_t k = i; k < j; k++)
            if (report[k] != '.')
                report[k] = 'x';
        (*addresses)++;
        i = j;
    }
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
    struct speaker sp;
    memset(&d, 0, sizeof(d));
    memset(&g, 0, sizeof(g));
    speaker_init(&sp);
    if (c->desktop) {
        /* X clients find the server here; Xorg runs without an authority file. */
        setenv("DISPLAY", ":0", 1);
        desktop_phase(c, tty, &d);
        if (c->gpu && d.x_ok)
            gpu_phase(c, tty, &g);
    }
    if (c->audio && c->speaker_unit && (!c->desktop || d.x_ok))
        speaker_phase(c, tty, &sp);
    /* R6: Wi-Fi, then the sound server, after the desktop and the GPU. */
    struct wifi w;
    struct sink k;
    memset(&w, 0, sizeof(w));
    memset(&k, 0, sizeof(k));
    if (c->wifi)
        wifi_phase(c, tty, &w);
    if (c->audio && c->sink_unit && (!c->desktop || d.x_ok))
        sink_phase(c, tty, &k);
    /* R8: the battery on the panel and this boot's id kept in the tree, before the PIN. */
    struct battery b;
    struct persist p;
    memset(&b, 0, sizeof(b));
    memset(&p, 0, sizeof(p));
    if (c->upower && (!c->desktop || d.x_ok))
        battery_phase(c, tty, &b);
    if (c->persist_path)
        persist_phase(c, tty, &p);
    /* R7: the owner's PIN, last, once everything else is judged. */
    struct ce e;
    memset(&e, 0, sizeof(e));
    if (c->ce && (!c->desktop || d.x_ok))
        ce_phase(c, tty, &e);
    /* R8: the owner's storage where the file manager lists it, once its names and contents decrypt. */
    struct media m;
    memset(&m, 0, sizeof(m));
    snprintf(m.kind, sizeof(m.kind), "none");
    if (c->media_view && e.ce_ok)
        media_phase(c, tty, e.entries, &m);

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
    if (c->data_rw)
        check_blocks_rw(c, &writes_ok, &ro_ok);
    else
        check_blocks(c->block, &writes_ok, &ro_ok);
    addf("M19 mountinfo\n");
    (void)add_file(c->mountinfo, SECTION_CAP);
    int mounts_ok = check_mounts(c->mountinfo, (int)c->data_rw);

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
        desktop_ok = d.x_ok && d.session_ok && d.mode_ok && d.vblank_ok && d.touch_ok && guard_ok && (!c->rotation || d.landscape_ok);
        addf("M19 R3 desktop x=%d session=%d mode=%s xrandr_hz=%.2f mode_ok=%d crtc=%d vblank_hz=%.2f vblank_ok=%d touch_device=%d "
             "touch_irqs=%ld touch_events=%d touch_ok=%d guard=%d tripped=%d battery=%ld zones=%d hottest=%ld\n", d.x_ok, d.session_ok, d.mode,
             d.xrandr_hz, d.mode_ok, d.crtc, d.vblank_hz, d.vblank_ok, d.touch_device, d.irq_delta, d.events, d.touch_ok, guard_ok, tripped,
             battery == LONG_MIN ? -1 : battery, zones, hottest == LONG_MIN ? -1 : hottest);
        if (c->rotation)
            addf("M19 R6 landscape rotation=%s screen=%dx%d landscape_ok=%d\n", d.rotation, d.width, d.height, d.landscape_ok);
    }
    int gpu_ok = 1;
    if (c->gpu) {
        /* Page flips and the composited runs are recorded, not judged: R4e measures where they fail. */
        gpu_ok = g.node && g.probe && g.vk && g.cube && g.gl && g.gears && (!c->glamor || g.glamor_ok) &&
                 (!c->compositor_script || (g.compositor_ok && g.vblank_ok && g.scanout_ok)) && (!c->judge_copy || g.copy_ok) &&
                 (!c->show_count || g.shows_ok) && (!c->judge_dri3 || (c->dmabuf_heap && g.late_ok));
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
        if (c->dmabuf_heap)
            addf("M19 R4 dmabuf xread_cpu=%ld xread_pixmap=%ld xread_window=%ld gpu_cpu=%ld chain_cpu=%ld chain_pixmap=%ld chain_window=%ld "
                 "dmabuf_renderer=%s\n", g.xread_cpu, g.xread_pixmap, g.xread_window, g.gpu_cpu, g.chain_cpu, g.chain_pixmap, g.chain_window,
                 g.dmabuf_renderer);
        if (c->dmabuf_heap)
            addf("M19 R4 late xlate_cpu=%ld xlate_pixmap=%ld xlate_window=%ld chainlate_cpu=%ld chainlate_pixmap=%ld chainlate_window=%ld "
                 "late_ok=%d\n", g.xlate_cpu, g.xlate_pixmap, g.xlate_window, g.chainlate_cpu, g.chainlate_pixmap, g.chainlate_window, g.late_ok);
        if (c->show_count) {
            addf("M19 R4 shows ran=%d of=%u visible=%d shows_ok=%d\n", g.show_ran, c->show_count, g.show_visible, g.shows_ok);
            for (unsigned i = 0; i < c->show_count && i < M19_SHOWS_MAX; i++)
                addf("M19 R4 show %s nonblack=%ld mean=%ld\n", c->shows[i].name, g.show_nonblack[i], g.show_mean[i]);
        }
    }
    int audio_ok = 1;
    if (c->audio) {
        struct audio a;
        memset(&a, 0, sizeof(a));
        audio_phase(c, &a, &sp);
        audio_ok = a.audio_ok;
        addf("M19 R5 audio card=%d control=%d playback=%d capture=%d snd_nodes=%d audio_ok=%d\n", a.card, a.control, a.playback, a.capture,
             a.snd_nodes, a.audio_ok);
        if (c->speaker_unit) {
            addf("M19 R5 speaker unit_rc=%d report_seen=%d valid=%d ok=%ld pid=%ld stage=%ld played=%ld pcm=%ld re=%ld/%ld/%ld "
                 "amp=%ld/%ld holder_alive=%d holder_fds=%d private_clean=%d speaker_ok=%d\n",
                 sp.unit_rc, sp.report_seen, sp.report_valid,
                 sp.ok == LONG_MIN ? -1L : sp.ok, sp.pid == LONG_MIN ? -1L : sp.pid,
                 sp.spk_stage == LONG_MIN ? -1L : sp.spk_stage,
                 sp.bytes_played == LONG_MIN ? -1L : sp.bytes_played,
                 sp.pcm_bytes == LONG_MIN ? -1L : sp.pcm_bytes,
                 sp.re_verified == LONG_MIN ? -1L : sp.re_verified,
                 sp.re0_q12 == LONG_MIN ? -1L : sp.re0_q12,
                 sp.re1_q12 == LONG_MIN ? -1L : sp.re1_q12,
                 sp.amp_on == LONG_MIN ? -1L : sp.amp_on,
                 sp.amp_off_verified == LONG_MIN ? -1L : sp.amp_off_verified,
                 sp.holder_alive, sp.holder_fds, sp.private_clean, sp.speaker_ok);
            if (c->speaker_report) {
                addf("M19 speaker report\n");
                (void)add_file(c->speaker_report, SECTION_CAP / 4);
            }
        }
        if (c->sink_unit) {
            audio_ok = audio_ok && k.sink_ok;
            addf("M19 R6 sink unit_rc=%d report_seen=%d state=%s streaming=%d chord_ok=%d pid=%ld played=%ld pcm=%ld re=%ld/%ld/%ld "
                 "regions=%ld volume=%ld holder_alive=%d holder_fds=%d private_clean=%d held_empty=%d pulse_unit_rc=%d pulse_sink=%d "
                 "pulse_default=%d tone_rc=%d "
                 "amp_off_before=%d loud=%ld enables=%ld disables=%ld peak_in=%ld peak_out=%ld underruns=%ld tone_loud=%d tone_peaks=%d "
                 "amp_on_seen=%d amp_idle_off=%d sink_ok=%d\n",
                 k.unit_rc, k.report_seen, k.state, k.streaming, k.chord_ok, k.pid, k.played, k.pcm, k.re_verified, k.re0, k.re1, k.regions,
                 k.volume_level, k.holder_alive, k.holder_fds, k.private_clean, k.held_empty, k.pulse_unit_rc, k.pulse_sink, k.pulse_default,
                 k.tone_rc, k.amp_off_before,
                 k.loud_after == LONG_MIN || k.loud_before == LONG_MIN ? -1L : k.loud_after - k.loud_before,
                 k.enables_after == LONG_MIN || k.enables_before == LONG_MIN ? -1L : k.enables_after - k.enables_before,
                 k.disables_after == LONG_MIN || k.disables_before == LONG_MIN ? -1L : k.disables_after - k.disables_before, k.peak_in,
                 k.peak_out, k.underruns, k.tone_loud, k.tone_peaks, k.amp_on_seen, k.amp_idle_off, k.sink_ok);
            addf("M19 sink report\n");
            (void)add_file(c->sink_report, SECTION_CAP / 4);
            addf("M19 sink status\n");
            (void)add_file(c->sink_status, SECTION_CAP / 8);
        }
        addf("M19 asound cards\n");
        (void)add_file(c->asound_cards, SECTION_CAP);
        addf("M19 asound pcm\n");
        (void)add_file(c->asound_pcm, SECTION_CAP);
    }
    int wifi_ok = 1;
    if (c->wifi) {
        wifi_ok = w.wifi_ok;
        addf("M19 R6 wifi result=%s ready=%d iface=%s connected=%d route=%d ping=%d dns=%d waited_ms=%ld wifi_ok=%d\n", token(w.result), w.ready,
             w.iface[0] ? w.iface : "none", w.connected, w.route, w.ping, w.dns, w.waited_ms, w.wifi_ok);
        addf("M19 wifi report\n");
        (void)add_file(c->wifi_report, SECTION_CAP / 8);
    }
    int ce_ok = 1;
    if (c->ce) {
        ce_ok = e.ce_ok;
        addf("M19 R7 ce unit_rc=%d result_seen=%d status=%s entry_seen=%d entries=%d waited_ms=%ld ce_ok=%d\n", e.unit_rc, e.result_seen,
             e.status[0] ? e.status : "none", e.entry_seen, e.entries, e.waited_ms, e.ce_ok);
    }
    int battery_ok = 1, persist_ok = 1, media_ok = 1;
    if (c->upower) {
        battery_ok = b.battery_ok;
        addf("M19 R8 battery unit=%d capacity=%d status=%s upower=%d state=%s pm=%d battery_ok=%d\n", b.unit_active, b.capacity, token(b.status),
             b.upower_pct, token(b.state), b.pm_running, b.battery_ok);
    }
    if (c->persist_path) {
        persist_ok = p.persist_ok;
        addf("M19 R8 persist had=%d on_disk=%d written=%d synced=%d read_back=%d id=%s persist_ok=%d\n", p.had, p.on_disk, p.written, p.synced,
             p.read_back, p.id[0] ? p.id : "none", p.persist_ok);
    }
    if (c->media_view) {
        media_ok = m.media_ok;
        addf("M19 R8 media mounted_ro=%d entries=%d same=%d walked=%d kind=%s media_ok=%d\n", m.mounted_ro, m.entries, m.same, m.walked, m.kind,
             m.media_ok);
    }
    int all_ok = init_ok && state_ok && targets_ok && writes_ok && ro_ok && mounts_ok && !write_warning && desktop_ok && gpu_ok && audio_ok &&
                 wifi_ok && ce_ok && battery_ok && persist_ok && media_ok;
    addf("M19 R2 verdict init=%d state=%s targets=%d writes=%d read_only=%d mounts=%d write_warning=%d all_ok=%d\n", init_ok, state, targets_ok,
         writes_ok, ro_ok, mounts_ok, write_warning, all_ok);

    if (c->wifi) {
        /* Network names and addresses stay on the phone: the journal and the kernel log may hold them. */
        unsigned ssids, macs, addresses;
        redact(c, &ssids, &macs, &addresses);
        addf("M19 R6 redacted ssid=%u mac=%u ipv4=%u\n", ssids, macs, addresses);
    }
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
