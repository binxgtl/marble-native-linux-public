/* The serial line as R1 uses it: raw, nonblocking, 256 bytes a write and a pause between writes. */
#define _GNU_SOURCE
#include "r2.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define CHUNK 256u /* unpaced, M15 Run4 lost whole runs of 1536 bytes */
#define LINE_MS 5000u

unsigned long long m19_now_ms(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t))
        return 0;
    return (unsigned long long)t.tv_sec * 1000 + (unsigned long long)t.tv_nsec / 1000000;
}

int m19_wire_open(const char *tty)
{
    int fd = open(tty, O_RDWR | O_NOCTTY | O_NONBLOCK | O_CLOEXEC);
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

int m19_wire_put(int fd, const void *data, size_t size, unsigned pace_ms, unsigned long long end_ms)
{
    const unsigned char *bytes = data;
    if (fd < 0)
        return -EBADF;
    for (size_t at = 0; at < size;) {
        if (m19_now_ms() >= end_ms)
            return -ETIMEDOUT;
        ssize_t put = write(fd, bytes + at, size - at < CHUNK ? size - at : CHUNK);
        if (put < 0 && errno != EAGAIN && errno != EINTR)
            return -errno;
        if (put > 0)
            at += (size_t)put;
        (void)poll(NULL, 0, (int)pace_ms);
    }
    return 0;
}

int m19_wire_line(int fd, unsigned pace_ms, const char *format, ...)
{
    char text[160];
    va_list arguments;
    va_start(arguments, format);
    int n = vsnprintf(text, sizeof(text) - 1, format, arguments);
    va_end(arguments);
    if (n < 0 || (size_t)n >= sizeof(text) - 1)
        return -EMSGSIZE;
    text[n++] = '\n';
    return m19_wire_put(fd, text, (size_t)n, pace_ms, m19_now_ms() + LINE_MS);
}
