#define _GNU_SOURCE
#include "shutdown-trace.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define PF_KTHREAD 0x00200000u /* Linux 5.10 include/linux/sched.h */
#define SCAN_LIMIT 2048
#define PROCESS_LIMIT 64
#define SCAN_BUDGET_NS 25000000L

/* Read PID, state and comm together so a task that exits cannot leave mixed fields. */
static int process_stat(int proc, long pid, char *name, char *state)
{
    char path[32], data[512];
    snprintf(path, sizeof path, "%ld/stat", pid);
    int fd = openat(proc, path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return -1;
    ssize_t length = read(fd, data, sizeof data - 1);
    close(fd);
    if (length <= 0)
        return -1;
    data[length] = '\0';
    /* comm may itself contain spaces, parentheses or line breaks. */
    const char *start = strchr(data, '(');
    const char *end = strrchr(data, ')');
    unsigned flags;
    if (!start || !end || end <= start || end - start > 16 ||
        sscanf(end + 1, " %c %*s %*s %*s %*s %*s %u", state, &flags) != 2)
        return -1;
    if ((flags & PF_KTHREAD) || strchr("ZXx", *state))
        return 0;
    if (!strchr("RSDTtKWPI", *state))
        return -1;
    while (++start < end) {
        const char c = *start;
        *name++ = ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                   (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') ? c : '_';
    }
    *name = '\0';
    return 1;
}

int m18_shutdown_snapshot(const char *proc, const char *log, pid_t spinner)
{
    struct timespec start, now;
    if (clock_gettime(CLOCK_BOOTTIME, &start) < 0)
        return -errno;
    DIR *dir = opendir(proc);
    if (!dir)
        return -errno;

    char rows[PROCESS_LIMIT * 32] = "";
    size_t used = 0;
    unsigned scanned = 0, count = 0, skipped = 0;
    int limited = 0, scan_error = 0;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(dir);
        if (!entry) {
            scan_error = errno;
            break;
        }
        if (++scanned > SCAN_LIMIT || count == PROCESS_LIMIT ||
            clock_gettime(CLOCK_BOOTTIME, &now) < 0 ||
            (now.tv_sec - start.tv_sec) * 1000000000L + now.tv_nsec - start.tv_nsec >= SCAN_BUDGET_NS) {
            limited = 1;
            break;
        }
        if (entry->d_name[0] < '1' || entry->d_name[0] > '9')
            continue;
        char *end;
        long pid = strtol(entry->d_name, &end, 10);
        if (*end || pid > INT_MAX || pid <= 1 || pid == spinner)
            continue;
        char name[16], state;
        int status = process_stat(dirfd(dir), pid, name, &state);
        if (status < 0)
            skipped++;
        if (status <= 0)
            continue;
        int n = snprintf(rows + used, sizeof rows - used, " %ld:%c:%s", pid, state, name);
        used += (size_t)n;
        count++;
    }
    closedir(dir);

    char line[sizeof rows + 128];
    int size = snprintf(line, sizeof line, "%lld.%02ld M18 procs count=%u skipped=%u limited=%d error=%d%.*s\n",
                        (long long)start.tv_sec, start.tv_nsec / 10000000, count, skipped, limited,
                        scan_error, (int)used, rows);
    int fd = open(log, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0600);
    if (fd < 0)
        return -errno;
    struct stat st;
    int rc = fstat(fd, &st) < 0 ? -errno : 0;
    if (!rc && !S_ISREG(st.st_mode))
        rc = -EINVAL;
    if (!rc && write(fd, line, (size_t)size) != size)
        rc = -EIO;
    if (close(fd) < 0 && !rc)
        rc = -errno;
    return rc;
}
