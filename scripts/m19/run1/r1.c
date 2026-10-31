/* M19 R1: the link comes up before anything touches the TEE, so a hang still names its step.
 * No reboot path exists, every ending is a hold, and the run stops before switch_root. */
#define _GNU_SOURCE
#include "r1.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include "../unlock/core.h"

#define BLUE 0x000000ffu
#define GREEN 0x0000ff00u
#define YELLOW 0x00ffff00u
#define RED 0x00ff0000u
#define LOG_CAP (2u * 1024u * 1024u)
#define LOG_CHUNK 256u /* unpaced, M15 Run4 lost whole runs of 1536 bytes */
#define LINE_MS 5000u

static unsigned char log_bytes[LOG_CAP];

static unsigned long long now_ms(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t))
        return 0;
    return (unsigned long long)t.tv_sec * 1000 + (unsigned long long)t.tv_nsec / 1000000;
}

__attribute__((format(printf, 2, 3)))
static void diag(const struct m19_run *r, const char *format, ...)
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
    int fd = open(r->kmsg, O_WRONLY | O_APPEND | O_CLOEXEC);
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

/* stderr is the boot log: a single attempt needs every line a child prints. */
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

static pid_t paint(const struct m19_run *r, uint32_t color, unsigned hold_ms)
{
    char colour[16], hold[16];
    snprintf(colour, sizeof(colour), "%08x", color);
    snprintf(hold, sizeof(hold), "%u", hold_ms);
    char *argv[] = {(char *)r->display, colour, hold, NULL};
    return spawn_logged(argv);
}

static void show_blue(struct m19_run *r)
{
    int status = -1;
    pid_t pid = paint(r, BLUE, r->blue_ms);
    int rc = pid < 0 ? -1 : wait_child(pid, r->display_ms, &status);
    diag(r, "blue rc=%d status=%d", rc, status);
}

/* Nonblocking, one byte a call, so a caller can never be held by a silent peer. */
static int read_line(struct m19_run *r, int fd)
{
    for (;;) {
        char c;
        ssize_t n = read(fd, &c, 1);
        if (n < 0 && (errno == EAGAIN || errno == EINTR))
            return 0;
        if (n != 1)
            return -1;
        if (c == '\n') {
            r->line[r->line_at] = 0;
            r->line_at = 0;
            return 1;
        }
        if (c < 32 || c > 126 || r->line_at >= sizeof(r->line) - 1) {
            r->line_at = 0;
            continue;
        }
        r->line[r->line_at++] = c;
    }
}

static int open_tty(const struct m19_run *r)
{
    int fd = open(r->tty, O_RDWR | O_NOCTTY | O_NONBLOCK | O_CLOEXEC);
    struct termios t;
    if (fd < 0)
        return -1;
    if (tcgetattr(fd, &t)) {
        close(fd);
        return -1;
    }
    cfmakeraw(&t);
    if (tcsetattr(fd, TCSANOW, &t)) {
        close(fd);
        return -1;
    }
    return fd;
}

static int start_connector(struct m19_run *r)
{
    int in[2], out[2];
    if (pipe2(in, O_CLOEXEC))
        return -1;
    if (pipe2(out, O_CLOEXEC)) {
        close(in[0]);
        close(in[1]);
        return -1;
    }
    /* Only this end: the connector keeps the blocking stdout it had in M15. */
    if (fcntl(out[0], F_SETFL, O_NONBLOCK)) {
        close(in[0]);
        close(in[1]);
        close(out[0]);
        close(out[1]);
        return -1;
    }
    char *argv[] = {(char *)r->connector, NULL};
    pid_t pid = spawn(argv, in[0], out[1]);
    close(in[0]);
    close(out[1]);
    if (pid < 0) {
        close(in[1]);
        close(out[0]);
        return -1;
    }
    r->connector_in = in[1]; /* stays open: EOF on its stdin is a connector failure */
    r->connector_out = out[0];
    return 0;
}

static int bring_up_link(struct m19_run *r)
{
    enum { ADSP, CONNECTOR, HOST } phase = ADSP;
    char *argv[] = {(char *)r->adsp, NULL};
    pid_t pid = spawn_logged(argv);
    if (pid < 0)
        return -1;
    r->adsp_pid = (long)pid;
    unsigned long long end = now_ms() + r->link_ms;
    while (now_ms() < end) {
        if (phase == ADSP) {
            int status = 0;
            pid_t got = waitpid(pid, &status, WNOHANG);
            if (got > 0 || (got < 0 && errno != EINTR)) {
                diag(r, "adsp pid=%ld status=%d", (long)got, status);
                if (got < 0 || status || start_connector(r))
                    return -1;
                phase = CONNECTOR;
            }
        } else if (phase == CONNECTOR) {
            int got = read_line(r, r->connector_out);
            if (got < 0)
                return -1;
            if (got) {
                diag(r, "connector %.64s", r->line);
                if (strcmp(r->line, "CONNECTOR_READY"))
                    return -1;
                r->tty_fd = open_tty(r);
                if (r->tty_fd < 0)
                    return -1;
                phase = HOST;
            }
        } else {
            int got = read_line(r, r->tty_fd);
            if (got < 0)
                return -1;
            if (got && !strcmp(r->line, M19_HOST_HELLO))
                return 0;
        }
        (void)poll(NULL, 0, (int)r->poll_ms);
    }
    diag(r, "link deadline");
    return -1;
}

static int send_paced(const struct m19_run *r, const unsigned char *data, size_t size, unsigned long long end)
{
    for (size_t at = 0; at < size;) {
        if (now_ms() >= end)
            return -ETIMEDOUT;
        ssize_t put = write(r->tty_fd, data + at, size - at < LOG_CHUNK ? size - at : LOG_CHUNK);
        if (put < 0 && errno != EAGAIN && errno != EINTR)
            return -errno;
        if (put > 0)
            at += (size_t)put;
        (void)poll(NULL, 0, (int)r->pace_ms);
    }
    return 0;
}

__attribute__((format(printf, 2, 3)))
static int send_line(const struct m19_run *r, const char *format, ...)
{
    char text[128];
    va_list arguments;
    va_start(arguments, format);
    int n = vsnprintf(text, sizeof(text) - 1, format, arguments);
    va_end(arguments);
    if (n < 0 || (size_t)n >= sizeof(text) - 1)
        return -EMSGSIZE;
    text[n++] = '\n';
    return send_paced(r, (const unsigned char *)text, (size_t)n, now_ms() + LINE_MS);
}

/* A child stuck in a driver is left alone: its step fails and the export still runs. */
static int run_step(struct m19_run *r, unsigned index)
{
    const struct m19_step *step = &r->steps[index];
    char *argv[] = {(char *)step->path, NULL};
    int status = -1;
    if (send_line(r, M19_DEVICE_STEP " %s START", step->name)) {
        r->link_lost = 1;
        return -1;
    }
    pid_t pid = spawn_logged(argv);
    if (pid < 0)
        return -1;
    r->ran[index] = 1;
    unsigned long long start = now_ms(), end = start + step->ms, beat = start + r->beat_ms;
    int rc;
    for (;;) {
        pid_t got = waitpid(pid, &status, WNOHANG);
        if (got == pid) {
            rc = status ? -1 : 0;
            break;
        }
        if (got < 0 && errno != EINTR) {
            rc = -1;
            break;
        }
        unsigned long long now = now_ms();
        if (now >= end) {
            rc = -ETIMEDOUT;
            break;
        }
        if (now >= beat) {
            (void)send_line(r, M19_DEVICE_BEAT " %s %llu", step->name, (now - start) / 1000);
            beat = now + r->beat_ms;
        }
        (void)poll(NULL, 0, 10);
    }
    r->results[index] = rc;
    diag(r, "step %s rc=%d status=%d ms=%llu", step->name, rc, status, now_ms() - start);
    if (send_line(r, M19_DEVICE_STEP " %s %s %d %d", step->name, rc ? "FAIL" : "OK", rc, status))
        r->link_lost = 1;
    return rc;
}

static void run_steps(struct m19_run *r)
{
    int stopped = 0;
    r->all_ok = 1;
    for (unsigned i = 0; i < r->step_count && i < M19_STEPS_MAX; i++) {
        const struct m19_step *step = &r->steps[i];
        if ((stopped || r->link_lost) && !(step->flags & M19_STEP_ALWAYS))
            continue;
        if (run_step(r, i) && (step->flags & M19_STEP_REQUIRED)) {
            r->all_ok = 0;
            stopped = 1;
        }
    }
    if (r->link_lost)
        r->all_ok = 0;
}

static size_t add_text(size_t at, const char *text)
{
    size_t n = strlen(text);
    if (n > LOG_CAP - at)
        return at;
    memcpy(log_bytes + at, text, n);
    return at + n;
}

static size_t add_file(size_t at, const char *path)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0)
        return at;
    while (at < LOG_CAP) {
        /* /dev/kmsg hands out one record a read and wants room for a whole one. */
        size_t room = LOG_CAP - at;
        if (room < 8192)
            break;
        ssize_t n = read(fd, log_bytes + at, room > 8192 ? 8192 : room);
        if (n < 0 && (errno == EINTR || errno == EPIPE))
            continue;
        if (n <= 0)
            break;
        at += (size_t)n;
    }
    close(fd);
    return at;
}

static void send_log(struct m19_run *r)
{
    uint8_t digest[32];
    char hash[65], head[200];
    size_t size = add_text(0, "M19 bootstrap.log\n");
    size = add_file(size, r->boot_log);
    size = add_text(size, "M19 kernel log\n");
    size_t kernel = size;
    size = add_file(size, r->kmsg);
    /* On this kernel the block layer only warns about a write to a read-only device. */
    if (memmem(log_bytes + kernel, size - kernel, M19_WRITE_WARNING, sizeof(M19_WRITE_WARNING) - 1)) {
        r->write_warning = 1;
        r->all_ok = 0;
    }
    size = add_text(size, "M19 logcat\n");
    size = add_file(size, r->logcat);
    m19_sha256(log_bytes, size, digest);
    for (int i = 0; i < 32; i++)
        snprintf(hash + i * 2, 3, "%02x", digest[i]);
    int n = snprintf(head, sizeof(head), M19_DEVICE_LOG " %zu %s %d %d\n", size, hash, r->all_ok, r->write_warning);
    unsigned long long end = now_ms() + r->log_ms;
    int rc = send_paced(r, (const unsigned char *)head, (size_t)n, end);
    if (!rc)
        rc = send_paced(r, log_bytes, size, end);
    diag(r, "log rc=%d bytes=%zu", rc, size);
}

enum m19_run_end m19_run_main(struct m19_run *r)
{
    int status = -1;
    r->tty_fd = r->connector_in = r->connector_out = -1;
    r->all_ok = r->write_warning = r->link_lost = 0;
    diag(r, "start");
    char *argv[] = {(char *)r->bootstrap, NULL};
    pid_t pid = spawn_logged(argv);
    int rc = pid < 0 ? -1 : wait_child(pid, r->bootstrap_ms, &status);
    diag(r, "bootstrap rc=%d status=%d", rc, status);
    if (rc || status)
        return M19_END_BOOTSTRAP;
    show_blue(r);
    if (bring_up_link(r)) {
        (void)paint(r, RED, r->final_ms);
        return M19_END_LINK;
    }
    run_steps(r);
    diag(r, "summary all_ok=%d", r->all_ok);
    send_log(r);
    (void)paint(r, r->all_ok ? GREEN : YELLOW, r->final_ms);
    return r->all_ok ? M19_END_PASS : M19_END_NOT_PASS;
}
