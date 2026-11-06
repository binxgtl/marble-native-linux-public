/* The hand-off. Every user process except PID 1 is killed and reaped, the Android chroot is
 * detached, and PID 1 moves the root T9 built onto / and execs systemd. Nothing here writes a
 * block device: the only mounts it touches are /tee, which it detaches, and /newroot, which it moves. */
#define _GNU_SOURCE
#include "r2.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define PF_KTHREAD_FLAG 0x00200000ul

int m19_stat_is_kthread(const char *line)
{
    /* comm may hold spaces and parentheses, so the fields resume after the last ')'. */
    const char *at = strrchr(line, ')');
    if (!at)
        return -1;
    at++;
    for (int field = 3; field <= 9; field++) {
        while (*at == ' ')
            at++;
        if (*at < '0' && *at != '-')
            return -1;
        if (field == 9) {
            char *end;
            errno = 0;
            unsigned long flags = strtoul(at, &end, 10);
            if (errno || end == at || (*end != ' ' && *end != '\n' && *end))
                return -1;
            return !!(flags & PF_KTHREAD_FLAG);
        }
        while (*at && *at != ' ')
            at++;
    }
    return -1;
}

int m19_sweep(const struct m19_handoff *h, int kill_them)
{
    DIR *directory = opendir(h->proc);
    if (!directory)
        return -1;
    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(directory))) {
        char *end;
        errno = 0;
        long pid = strtol(entry->d_name, &end, 10);
        if (errno || end == entry->d_name || *end || pid <= 1 || pid == (long)h->self)
            continue;
        char path[512], line[1024];
        snprintf(path, sizeof(path), "%s/%ld/stat", h->proc, pid);
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            if (errno != ENOENT && errno != ESRCH)
                count++; /* unreadable is never assumed harmless */
            continue;
        }
        ssize_t n = read(fd, line, sizeof(line) - 1);
        int error = errno;
        close(fd);
        if (n <= 0) {
            if (!(n < 0 && error == ESRCH))
                count++;
            continue;
        }
        line[n] = 0;
        if (m19_stat_is_kthread(line) == 1)
            continue;
        count++;
        if (kill_them)
            (void)h->signal((pid_t)pid, SIGKILL);
    }
    closedir(directory);
    return count;
}

__attribute__((format(printf, 2, 3)))
static void note(const struct m19_handoff *h, const char *format, ...)
{
    char text[200];
    int at = snprintf(text, sizeof(text), "<6>M19: ");
    va_list arguments;
    va_start(arguments, format);
    int n = vsnprintf(text + at, sizeof(text) - (size_t)at - 1, format, arguments);
    va_end(arguments);
    if (n < 0)
        return;
    size_t size = (size_t)at + ((size_t)n < sizeof(text) - (size_t)at - 1 ? (size_t)n : sizeof(text) - (size_t)at - 2);
    text[size++] = '\n';
    int fd = open(h->kmsg, O_WRONLY | O_APPEND | O_CLOEXEC);
    if (fd < 0)
        return;
    ssize_t put = write(fd, text, size);
    (void)put;
    close(fd);
}

static int fail(int tty, const struct m19_handoff *h, const char *reason, long value)
{
    note(h, "handoff failed %s %ld", reason, value);
    (void)m19_wire_line(tty, h->pace_ms, M19_DEVICE_STEP " T10-handoff FAIL %s %ld", reason, value);
    return -1;
}

static void reap(void)
{
    while (waitpid(-1, NULL, WNOHANG) > 0) {
    }
}

int m19_handoff(int tty, const struct m19_handoff *h, int *moved)
{
    *moved = 0;
    (void)m19_wire_line(tty, h->pace_ms, M19_DEVICE_STEP " T10-handoff START");
    /* Android init, its services, the connector and the display all go. The gadget, ADSP and
     * the dm table live in the kernel and stay. */
    unsigned long long end = m19_now_ms() + h->settle_ms;
    int left;
    for (;;) {
        left = m19_sweep(h, 1);
        reap();
        if (left == 0 || m19_now_ms() >= end)
            break;
        (void)poll(NULL, 0, (int)h->poll_ms);
    }
    reap();
    left = m19_sweep(h, 0);
    note(h, "handoff survivors=%d", left);
    if (left)
        return fail(tty, h, "survivors", left);
    if (umount2(h->android, MNT_DETACH))
        return fail(tty, h, "android-detach", errno);
    struct stat parent, root;
    char path[512];
    snprintf(path, sizeof(path), "%s/..", h->newroot);
    if (stat(path, &parent) || stat(h->newroot, &root) || parent.st_dev == root.st_dev)
        return fail(tty, h, "newroot-not-mounted", errno);
    snprintf(path, sizeof(path), "%s%s", h->newroot, h->init);
    if (access(path, X_OK))
        return fail(tty, h, "init", errno);
    if (chdir(h->newroot))
        return fail(tty, h, "chdir", errno);
    if (mount(".", "/", NULL, MS_MOVE, NULL))
        return fail(tty, h, "move", errno);
    *moved = 1;
    if (chroot(".") || chdir("/"))
        return fail(tty, h, "chroot", errno);
    int null = open("/dev/null", O_RDWR);
    if (null < 0 || dup2(null, 0) < 0 || dup2(null, 1) < 0 || dup2(null, 2) < 0)
        return fail(tty, h, "stdio", errno);
    if (null > 2)
        close(null);
    note(h, "handoff exec %s", h->init);
    /* The last line PID 1 sends. The tty closes on exec; systemd's reporter opens it again. */
    (void)m19_wire_line(tty, h->pace_ms, M19_DEVICE_STEP " T10-handoff OK 0 0");
    char *argv[] = {(char *)h->init, NULL};
    char *envp[] = {"HOME=/", "TERM=linux", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", NULL};
    execve(h->init, argv, envp);
    return fail(tty, h, "exec", errno);
}
