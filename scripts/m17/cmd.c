/* M17 G5: commands and records for the session's helpers (cmd.h). */
#define _GNU_SOURCE
#include "cmd.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

uint64_t m17_cmd_now_ms(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t))
        return 0;
    return (uint64_t)t.tv_sec * 1000u + (uint64_t)t.tv_nsec / 1000000u;
}

int m17_run(const char *const argv[], const char *const env[], char *out, size_t room, unsigned ms)
{
    if (room)
        out[0] = 0;
    int pipe_fd[2];
    if (pipe2(pipe_fd, O_CLOEXEC))
        return -1;
    pid_t pid = fork();
    if (pid == 0) {
        int null = open("/dev/null", O_RDWR | O_CLOEXEC);
        if (null < 0 || dup2(null, 0) < 0 || dup2(pipe_fd[1], 1) < 0 || dup2(null, 2) < 0)
            _exit(126);
        execve(argv[0], (char *const *)argv, env ? (char *const *)env : environ);
        _exit(127);
    }
    close(pipe_fd[1]);
    if (pid < 0) {
        close(pipe_fd[0]);
        return -1;
    }
    size_t used = 0;
    uint64_t end = m17_cmd_now_ms() + ms;
    int timed_out = 0;
    for (;;) {
        uint64_t now = m17_cmd_now_ms();
        if (now >= end) {
            timed_out = 1;
            break;
        }
        struct pollfd p = {.fd = pipe_fd[0], .events = POLLIN};
        int ready = poll(&p, 1, (int)(end - now));
        if (ready < 0 && errno == EINTR)
            continue;
        if (ready <= 0)
            continue;
        char scratch[256];
        int keep = room && used + 1 < room;
        ssize_t got = read(pipe_fd[0], keep ? out + used : scratch, keep ? room - 1 - used : sizeof(scratch));
        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0)
            break;
        if (keep)
            used += (size_t)got;
    }
    close(pipe_fd[0]);
    if (room)
        out[used] = 0;
    if (timed_out)
        (void)kill(pid, SIGKILL);
    int status = 0;
    uint64_t reap_end = m17_cmd_now_ms() + (timed_out ? 2000u : ms + 2000u);
    for (;;) {
        pid_t got = waitpid(pid, &status, WNOHANG);
        if (got == pid)
            break;
        if (got < 0 && errno != EINTR)
            return -1;
        if (m17_cmd_now_ms() >= reap_end) {
            (void)kill(pid, SIGKILL);
            (void)waitpid(pid, &status, 0);
            return -1;
        }
        (void)poll(NULL, 0, 10);
    }
    if (timed_out || !WIFEXITED(status))
        return -1;
    return WEXITSTATUS(status);
}

int m17_append(const char *path, const char *text, size_t limit)
{
    struct stat st;
    if (!lstat(path, &st)) {
        if (!S_ISREG(st.st_mode))
            return -EINVAL;
        if ((size_t)st.st_size >= limit) {
            char older[512];
            if ((size_t)snprintf(older, sizeof(older), "%s.1", path) >= sizeof(older))
                return -ENAMETOOLONG;
            if (rename(path, older))
                return -errno;
        }
    }
    int fd = open(path, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0)
        return -errno;
    int error = 0;
    size_t size = strlen(text);
    for (size_t at = 0; at < size && !error;) {
        ssize_t put = write(fd, text + at, size - at);
        if (put < 0 && errno != EINTR)
            error = -errno;
        else if (put > 0)
            at += (size_t)put;
    }
    if (!error && fsync(fd))
        error = -errno;
    if (close(fd) && !error)
        error = -errno;
    return error;
}

void m17_first_word(const char *text, char *word, size_t room)
{
    size_t at = 0;
    while (*text == ' ' || *text == '\t' || *text == '\n')
        text++;
    while (at + 1 < room) {
        char c = text[at];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-'))
            break;
        word[at] = c;
        at++;
    }
    word[at] = 0;
    if (!at)
        snprintf(word, room, "none");
}
