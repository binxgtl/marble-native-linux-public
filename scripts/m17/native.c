/* M17 G5: PID 1 on the native path without the PC (native.h, docs/m17-g5.md). M19 R1's runtime (scripts/m19/run1/r1.c),
 * with the USB link, the connector and the host's lines taken out; spawning, waiting, painting and the owned unlock
 * step are R1's own logic. */
#define _GNU_SOURCE
#include "native.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define BLUE 0x000000ffu
#define GREEN 0x0000ff00u
#define YELLOW 0x00ffff00u
#define RED 0x00ff0000u
#define LOG_CAP (4u * 1024u * 1024u)
#define HEAD_CAP (16u * 1024u)
#define BOOT_LOG_CAP (512u * 1024u)
#define LOGCAT_RESERVE (768u * 1024u)
#define REAP_MS 2000u

static char log_bytes[LOG_CAP];

static unsigned long long now_ms(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t))
        return 0;
    return (unsigned long long)t.tv_sec * 1000 + (unsigned long long)t.tv_nsec / 1000000;
}

__attribute__((format(printf, 2, 3))) static void diag(const struct m17_native *n, const char *format, ...)
{
    char text[200];
    int at = snprintf(text, sizeof(text), "<6>M17NAT ");
    va_list arguments;
    va_start(arguments, format);
    int k = vsnprintf(text + at, sizeof(text) - (size_t)at - 1, format, arguments);
    va_end(arguments);
    if (k < 0)
        return;
    size_t size = (size_t)at + ((size_t)k < sizeof(text) - (size_t)at - 1 ? (size_t)k : sizeof(text) - (size_t)at - 2);
    text[size++] = '\n';
    int fd = open(n->kmsg, O_WRONLY | O_APPEND | O_CLOEXEC);
    if (fd < 0)
        return;
    ssize_t put = write(fd, text, size);
    (void)put;
    close(fd);
}

static pid_t spawn(char *const argv[], int in, int out)
{
    pid_t pid = fork();
    if (pid)
        return pid;
    if (dup2(in, 0) < 0 || dup2(out, 1) < 0)
        _exit(126);
    execv(argv[0], argv);
    _exit(127);
}

/* stderr is the boot log: one boot without a PC needs every line a child prints. */
static pid_t spawn_logged(char *const argv[])
{
    int null = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (null < 0)
        return -1;
    pid_t pid = spawn(argv, null, 2);
    close(null);
    return pid;
}

static int wait_child(pid_t pid, unsigned ms, int *status)
{
    unsigned long long end = now_ms() + ms;
    for (;;) {
        pid_t got = waitpid(pid, status, WNOHANG);
        if (got == pid)
            return 0;
        if (got < 0 && errno != EINTR)
            return -1;
        if (now_ms() >= end)
            return -ETIMEDOUT;
        (void)poll(NULL, 0, 10);
    }
}

static pid_t paint(const struct m17_native *n, uint32_t color, unsigned hold_ms)
{
    char colour[16], hold[16];
    snprintf(colour, sizeof(colour), "%08x", color);
    snprintf(hold, sizeof(hold), "%u", hold_ms);
    char *argv[] = {(char *)n->display, colour, hold, NULL};
    return spawn_logged(argv);
}

static void show_blue(struct m17_native *n)
{
    int status = -1;
    pid_t pid = paint(n, BLUE, n->blue_ms);
    int rc = pid < 0 ? -1 : wait_child(pid, n->display_ms, &status);
    diag(n, "blue rc=%d status=%d", rc, status);
}

/* R1's: only the unlock step owns a private group, and its descendants inherit it. */
static pid_t spawn_owned(char *const argv[])
{
    if (prctl(PR_SET_CHILD_SUBREAPER, 1))
        return -1;
    pid_t parent = getpid(), pid = fork();
    if (pid == 0) {
        if (setpgid(0, 0) || prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != parent)
            _exit(126);
        int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (fd < 0 || dup2(fd, 0) < 0 || dup2(2, 1) < 0)
            _exit(126);
        close(fd);
        execv(argv[0], argv);
        _exit(127);
    }
    if (pid > 0 && setpgid(pid, pid) && errno != EACCES)
        (void)kill(pid, SIGKILL);
    return pid;
}

/* R1's: never advance if the step's group cannot be shown gone. */
static int retire_owned(pid_t pid, int *status, int *reaped, int cancel)
{
    int abnormal = cancel, signal_error = 0;
    if (cancel && kill(-pid, SIGKILL) && errno != ESRCH)
        signal_error = 1;
    unsigned long long end = now_ms() + REAP_MS;
    for (;;) {
        if (now_ms() >= end)
            return -1;
        int child_status;
        pid_t got = waitpid(-pid, &child_status, WNOHANG);
        if (got > 0) {
            if (got == pid) {
                *status = child_status;
                *reaped = 1;
            } else {
                abnormal = 1;
            }
            continue;
        }
        if (got < 0 && errno != EINTR && errno != ECHILD)
            return -1;
        if (got < 0 && errno == ECHILD && *reaped && kill(-pid, 0) < 0 && errno == ESRCH)
            return signal_error ? -1 : abnormal;
        if (!cancel) {
            cancel = abnormal = 1;
            if (kill(-pid, SIGKILL) && errno != ESRCH)
                signal_error = 1;
        }
        (void)poll(NULL, 0, 10);
    }
}

static int run_step(struct m17_native *n, unsigned index)
{
    const struct m19_step *step = &n->steps[index];
    char *argv[] = {(char *)step->path, NULL};
    int status = -1;
    diag(n, "step %s START", step->name);
    int owned = !!(step->flags & M19_STEP_OWNED), reaped = 0;
    pid_t pid = owned ? spawn_owned(argv) : spawn_logged(argv);
    if (pid < 0) {
        n->results[index] = -1;
        diag(n, "step %s spawn failed", step->name);
        return -1;
    }
    n->ran[index] = 1;
    unsigned long long start = now_ms(), end = start + step->ms;
    int rc;
    for (;;) {
        pid_t got = waitpid(pid, &status, WNOHANG);
        if (got == pid) {
            reaped = 1;
            rc = status ? -1 : 0;
            break;
        }
        if (got < 0 && errno != EINTR) {
            rc = -1;
            break;
        }
        if (now_ms() >= end) {
            rc = -ETIMEDOUT;
            break;
        }
        (void)poll(NULL, 0, 10);
    }
    if (owned) {
        int retired = retire_owned(pid, &status, &reaped, !reaped);
        n->ownership_unresolved = retired < 0;
        if (retired || !reaped)
            rc = rc ? rc : -ECHILD;
        diag(n, "owner step=%s reaped=%d retired=%d remote=UNKNOWN", step->name, reaped, retired);
    }
    n->results[index] = rc;
    n->step_ms[index] = now_ms() - start;
    diag(n, "step %s %s rc=%d status=%d ms=%llu", step->name, rc ? "FAIL" : "OK", rc, status, n->step_ms[index]);
    return rc;
}

static void run_steps(struct m17_native *n)
{
    int stopped = 0;
    n->all_ok = 1;
    for (unsigned i = 0; i < n->step_count && i < M19_STEPS_MAX; i++) {
        if (n->ownership_unresolved) {
            n->all_ok = 0;
            break;
        }
        const struct m19_step *step = &n->steps[i];
        if (stopped && !(step->flags & M19_STEP_ALWAYS))
            continue;
        if (run_step(n, i) && (step->flags & M19_STEP_REQUIRED)) {
            n->all_ok = 0;
            stopped = 1;
        }
    }
    if (n->step_count > M19_STEPS_MAX)
        n->all_ok = 0;
}

static int hex_digit(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

/* xx:xx:xx:xx:xx:xx or xx-xx-xx-xx-xx-xx, one separator throughout. */
static void blank_macs(char *line, size_t size)
{
    for (size_t i = 0; i + 17 <= size; i++) {
        char separator = line[i + 2];
        int mac = separator == ':' || separator == '-';
        for (int k = 0; k < 17 && mac; k++)
            mac = k % 3 == 2 ? line[i + k] == separator : hex_digit(line[i + k]);
        if (!mac)
            continue;
        for (int k = 0; k < 17; k++)
            if (k % 3 != 2)
                line[i + k] = 'x';
        i += 16;
    }
}

size_t m17_redact(char *text, size_t size)
{
    static const char command[] = "Kernel command line:", serial[] = "serialno", marker[] = " [redacted]";
    size_t in = 0, out = 0;
    while (in < size) {
        char *line = text + in;
        char *newline = memchr(line, '\n', size - in);
        size_t length = newline ? (size_t)(newline - line) : size - in, keep = length;
        char *hit = memmem(line, length, command, sizeof(command) - 1);
        if (hit)
            keep = (size_t)(hit - line) + sizeof(command) - 1;
        else if ((hit = memmem(line, length, serial, sizeof(serial) - 1)))
            keep = (size_t)(hit - line) + sizeof(serial) - 1;
        memmove(text + out, line, length);
        blank_macs(text + out, keep);
        if (length - keep >= sizeof(marker) - 1) {
            memcpy(text + out + keep, marker, sizeof(marker) - 1);
            out += keep + sizeof(marker) - 1;
        } else {
            memset(text + out + keep, 'x', length - keep);
            out += length;
        }
        in += length;
        if (newline) {
            text[out++] = '\n';
            in++;
        }
    }
    return out;
}

int m17_write_log(const char *dir, const char *name, const void *data, size_t size)
{
    char path[PATH_MAX], temporary[NAME_MAX + 1], older[NAME_MAX + 1];
    size_t name_length = strlen(name);
    if (!dir || dir[0] != '/' || !name_length || name_length > NAME_MAX - 8 || strchr(name, '/') || name[0] == '.' ||
        strlen(dir) >= sizeof(path))
        return -EINVAL;
    snprintf(temporary, sizeof(temporary), ".%s.tmp", name);
    snprintf(older, sizeof(older), "%s.1", name);
    int fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0)
        return -errno;
    for (const char *at = dir;;) {
        while (*at == '/')
            at++;
        if (!*at)
            break;
        size_t length = strcspn(at, "/");
        const char *rest = at + length;
        while (*rest == '/')
            rest++;
        if (length >= sizeof(path) || (length == 1 && at[0] == '.') || (length == 2 && at[0] == '.' && at[1] == '.')) {
            close(fd);
            return -EINVAL;
        }
        char *part = path;
        memcpy(part, at, length);
        part[length] = 0;
        at = rest;
        int next = openat(fd, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0 && errno == ENOENT && !*rest) {
            /* Only the last directory may be made. */
            if (mkdirat(fd, part, 0755) && errno != EEXIST) {
                int error = -errno;
                close(fd);
                return error;
            }
            next = openat(fd, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        }
        int error = next < 0 ? -errno : 0;
        close(fd);
        if (error)
            return error;
        fd = next;
    }
    if (unlinkat(fd, temporary, 0) && errno != ENOENT) {
        int error = -errno;
        close(fd);
        return error;
    }
    int out = openat(fd, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (out < 0) {
        int error = -errno;
        close(fd);
        return error;
    }
    int error = 0;
    for (size_t at = 0; at < size && !error;) {
        ssize_t put = write(out, (const char *)data + at, size - at);
        if (put < 0 && errno != EINTR)
            error = -errno;
        else if (put > 0)
            at += (size_t)put;
    }
    if (!error && fsync(out))
        error = -errno;
    if (close(out) && !error)
        error = -errno;
    if (!error && renameat(fd, name, fd, older) && errno != ENOENT)
        error = -errno;
    if (!error && renameat(fd, temporary, fd, name))
        error = -errno;
    if (!error && fsync(fd))
        error = -errno;
    if (error)
        (void)unlinkat(fd, temporary, 0);
    close(fd);
    return error;
}

static size_t add_text(size_t at, const char *text)
{
    size_t length = strlen(text);
    if (length > LOG_CAP - at)
        return at;
    memcpy(log_bytes + at, text, length);
    return at + length;
}

/* Up to `limit` bytes of path, whole kmsg records at a time: /dev/kmsg hands out one a read and wants room for it. */
static size_t add_file(size_t at, const char *path, size_t limit)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0)
        return add_text(at, "(absent)\n");
    size_t end = limit < LOG_CAP - at ? at + limit : LOG_CAP;
    while (end - at >= 8192) {
        ssize_t got = read(fd, log_bytes + at, 8192);
        if (got < 0 && (errno == EINTR || errno == EPIPE))
            continue;
        if (got <= 0)
            break;
        at += (size_t)got;
    }
    close(fd);
    return at;
}

/* The evidence Android reads after the session: the summary, then the bootstrap's log, the kernel's and the TEE
 * island's logcat, redacted. The kernel log is also R1's check: a write warning means not a PASS. */
static void write_log(struct m17_native *n)
{
    size_t at = HEAD_CAP;
    at = add_text(at, "M17 bootstrap.log\n");
    at = add_file(at, n->boot_log, BOOT_LOG_CAP);
    at = add_text(at, "M17 kernel log\n");
    size_t kernel = at;
    at = add_file(at, n->kmsg, LOG_CAP - at > LOGCAT_RESERVE ? LOG_CAP - at - LOGCAT_RESERVE : 0);
    if (memmem(log_bytes + kernel, at - kernel, M19_WRITE_WARNING, sizeof(M19_WRITE_WARNING) - 1)) {
        n->write_warning = 1;
        n->all_ok = 0;
    }
    at = add_text(at, "M17 logcat\n");
    at = add_file(at, n->logcat, LOG_CAP - at);
    size_t body = m17_redact(log_bytes + HEAD_CAP, at - HEAD_CAP);
    char head[HEAD_CAP];
    size_t used = 0;
    int k = snprintf(head, sizeof(head), "M17 native log v1\nsummary all_ok=%d write_warning=%d adsp_rc=%d ownership_unresolved=%d\n",
                     n->all_ok, n->write_warning, n->adsp_rc, n->ownership_unresolved);
    used = k > 0 ? (size_t)k : 0;
    for (unsigned i = 0; i < n->step_count && i < M19_STEPS_MAX && used < sizeof(head); i++) {
        k = snprintf(head + used, sizeof(head) - used, "step %s ran=%d rc=%d ms=%llu\n", n->steps[i].name, n->ran[i], n->results[i],
                     n->step_ms[i]);
        if (k < 0 || (size_t)k >= sizeof(head) - used)
            break;
        used += (size_t)k;
    }
    memcpy(log_bytes + HEAD_CAP - used, head, used);
    n->log_rc = m17_write_log(n->log_dir, n->log_name, log_bytes + HEAD_CAP - used, used + body);
    diag(n, "log rc=%d bytes=%zu", n->log_rc, used + body);
}

enum m17_native_end m17_native_main(struct m17_native *n)
{
    int status = -1;
    n->all_ok = n->write_warning = n->ownership_unresolved = 0;
    n->adsp_rc = n->log_rc = -1;
    n->adsp_pid = -1;
    memset(n->ran, 0, sizeof(n->ran));
    memset(n->step_ms, 0, sizeof(n->step_ms));
    for (unsigned i = 0; i < M19_STEPS_MAX; i++)
        n->results[i] = -1;
    diag(n, "start");
    char *argv[] = {(char *)n->bootstrap, NULL};
    pid_t pid = spawn_logged(argv);
    int rc = pid < 0 ? -1 : wait_child(pid, n->bootstrap_ms, &status);
    diag(n, "bootstrap rc=%d status=%d", rc, status);
    if (rc || status)
        return M17_END_BOOTSTRAP;
    show_blue(n);
    char *adsp[] = {(char *)n->adsp, NULL};
    status = -1;
    pid = spawn_logged(adsp);
    n->adsp_pid = (long)pid;
    rc = pid < 0 ? -1 : wait_child(pid, n->adsp_ms, &status);
    n->adsp_rc = rc ? rc : status ? -1 : 0;
    diag(n, "adsp rc=%d status=%d", rc, status);
    if (n->adsp_rc) {
        (void)paint(n, RED, n->final_ms);
        return M17_END_ADSP;
    }
    run_steps(n);
    diag(n, "summary all_ok=%d", n->all_ok);
    write_log(n);
    (void)paint(n, n->all_ok ? GREEN : YELLOW, n->final_ms);
    return n->all_ok ? M17_END_PASS : M17_END_NOT_PASS;
}
