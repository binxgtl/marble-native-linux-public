/* The R2 reporter. systemd starts it early; it waits for the boot to settle, gathers the
 * evidence, judges it, sends it over the serial line with a hash, then paints the verdict.
 * It only reads: systemd's state, the journal, the kernel log, /proc and /sys. */
#define _GNU_SOURCE
#include "r2.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
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

/* Runs argv with stdout and stderr into out, keeping at most cap bytes and draining the rest.
 * Returns the wait status, or -1 when it could not run or overran ms and was killed. */
static int capture(char *const argv[], unsigned char *out, size_t cap, size_t *taken, unsigned ms)
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
                (void)waitpid(pid, NULL, 0);
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

/* A section of the report: the command line, then what it printed, then its status. */
static int section(char *const argv[], size_t cap, unsigned ms)
{
    addf("M19 $");
    for (unsigned i = 0; argv[i]; i++)
        addf(" %s", argv[i]);
    addf("\n");
    size_t room = REPORT_CAP - used, limit = cap < room ? cap : room, taken = 0;
    int status = capture(argv, report + used, limit, &taken, ms);
    used += taken;
    if (taken == limit)
        addf("\nM19 output truncated at %zu bytes", limit);
    addf("\nM19 status %d\n", status);
    return status;
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

    int all_ok = init_ok && state_ok && targets_ok && writes_ok && ro_ok && mounts_ok && !write_warning;
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
    paint(c, all_ok);
    return 70;
}
