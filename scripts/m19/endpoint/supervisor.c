/* Endpoint-only supervisor. No key paths or Keystore business methods. */
#define _GNU_SOURCE
#include "endpoint.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#ifndef M19_ENDPOINT_WORK_MS
#define M19_ENDPOINT_WORK_MS 10000
#endif
#ifndef M19_ENDPOINT_REAP_MS
#define M19_ENDPOINT_REAP_MS 2000
#endif
#define MAGIC 0x19314550u
struct packet { uint32_t magic, sequence, final, stage, flags; int32_t status, detail_errno; };
struct channel { int fd; unsigned sequence, stage; };
extern char **environ;
static int output_fd = 1;
static int output_is_socket;
static volatile sig_atomic_t interrupted;
static void stop(int s) { interrupted = s; }
static uint64_t now_ms(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) return 0;
    return (uint64_t)t.tv_sec * 1000 + (unsigned)t.tv_nsec / 1000000;
}
static int has_loader_environment(void) {
    for (char **entry = environ; entry != NULL && *entry != NULL; ++entry) {
        if (strncmp(*entry, "LD_", 3) == 0) return 1;
    }
    return 0;
}
/* Reject inherited descriptors instead of letting the worker inherit caller
 * capabilities. /proc/self/fd is opened before fork; its own fd is the only
 * descriptor above 2 permitted during this bounded census. */
static int inherited_fds_clean(void) {
    DIR *directory = opendir("/proc/self/fd");
    if (directory == NULL) return 0;
    int own_fd = dirfd(directory);
    int clean = own_fd >= 0;
    int read_error = 0;
    unsigned entries = 0;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (entry == NULL) {
            read_error = errno;
            break;
        }
        if (++entries > 16) { clean = 0; break; }
        const char *name = entry->d_name;
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) continue;
        if (name[0] < '0' || name[0] > '9') { clean = 0; break; }
        unsigned long value = 0;
        for (const char *digit = name; *digit; ++digit) {
            if (*digit < '0' || *digit > '9') { value = ULONG_MAX; break; }
            unsigned next = (unsigned)(*digit - '0');
            if (value > (ULONG_MAX - next) / 10) { value = ULONG_MAX; break; }
            value = value * 10 + next;
        }
        if (value == ULONG_MAX || value > INT_MAX ||
            (value >= 3 && value != (unsigned long)own_fd)) {
            clean = 0;
            break;
        }
    }
    if (read_error != 0) clean = 0;
    if (closedir(directory)) clean = 0;
    return clean;
}
static int valid_output_fd(struct stat *st, int *is_socket) {
    int flags = fcntl(1, F_GETFL);
    if (flags < 0 || (flags & O_ACCMODE) == O_RDONLY) return 0;
    if (fstat(1, st)) return 0;
    if (S_ISFIFO(st->st_mode)) { *is_socket = 0; return 1; }
    if (!S_ISSOCK(st->st_mode)) return 0;
    int type = 0;
    socklen_t type_size = sizeof(type);
    if (getsockopt(1, SOL_SOCKET, SO_TYPE, &type, &type_size) || type != SOCK_STREAM) return 0;
    struct sockaddr_storage local, peer;
    socklen_t local_size = sizeof(local), peer_size = sizeof(peer);
    if (getsockname(1, (struct sockaddr *)&local, &local_size) ||
        getpeername(1, (struct sockaddr *)&peer, &peer_size) ||
        local.ss_family != AF_UNIX || peer.ss_family != AF_UNIX) return 0;
    *is_socket = 1;
    return 1;
}
static int open_private_fifo_output(const struct stat *original) {
    int fd = open("/proc/self/fd/1", O_WRONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return -1;
    struct stat reopened;
    int flags = fcntl(fd, F_GETFL);
    if (fstat(fd, &reopened) || !S_ISFIFO(reopened.st_mode) ||
        reopened.st_dev != original->st_dev || reopened.st_ino != original->st_ino ||
        flags < 0 || (flags & O_ACCMODE) == O_RDONLY) {
        close(fd);
        return -1;
    }
    return fd;
}
static int output(const char *bytes, size_t size) {
    uint64_t start = now_ms();
    if (!start) return -1;
    while (size) {
        uint64_t time = now_ms();
        if (!time || time < start || time - start >= 1000) return -1;
        ssize_t n = output_is_socket
            ? send(output_fd, bytes, size, MSG_DONTWAIT | MSG_NOSIGNAL)
            : write(output_fd, bytes, size);
        if (n > 0) { bytes += n; size -= (size_t)n; }
        else if (!n || (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)) return -1;
        else { struct pollfd p = {output_fd, POLLOUT, 0}; (void)poll(&p, 1, 10); }
    }
    return 0;
}
static const char *stage_name(unsigned stage) {
    static const char *const names[] = {"load", "symbols", "lookup", "descriptor", "release"};
    return stage < 5 ? names[stage] : "none";
}
static void progress(enum m19_endpoint_stage stage, unsigned flags, void *opaque) {
    struct channel *c = opaque;
    c->stage = (unsigned)stage;
    struct packet p = {MAGIC, c->sequence++, 0, c->stage, flags, 0, 0};
    if (write(c->fd, &p, sizeof(p)) != (ssize_t)sizeof(p)) _exit(125);
}
static int valid(const struct packet *p, unsigned next, unsigned previous_flags, unsigned last) {
    if (p->magic != MAGIC || p->sequence != next || p->final > 1 || p->stage > 4 ||
        p->flags > 31 || (p->flags & previous_flags) != previous_flags) return 0;
    if (!p->final) {
        static const unsigned expected[] = {0, 1, 3, 7, 7};
        if (p->stage != next || p->stage >= 5 || p->status || p->detail_errno) return 0;
        return p->flags == expected[p->stage] || (p->stage == 4 && p->flags == 15);
    }
    if (!next || p->stage != last || p->status < 0 || p->status > 6) return 0;
    if (!p->status) return next == 5 && p->stage == 4 && previous_flags == 15 &&
        p->flags == 31 && !p->detail_errno;
    if (p->status == 1) return next == 1 && p->flags == 0;
    if (p->status == 2) return next == 2 && p->flags == 1;
    if (p->status == 3) return next == 3 && p->flags == 3;
    return next == 5 && p->stage == 4 && previous_flags == 7 && p->flags == 23;
}
int main(int argc, char **argv) {
    if (has_loader_environment()) return 64;
    if (argc != 2 || strcmp(argv[1], "--check")) return 64;
    struct stat output_stat, st;
    if (!valid_output_fd(&output_stat, &output_is_socket) ||
        fcntl(0, F_GETFD) < 0 || fcntl(2, F_GETFD) < 0 ||
        !inherited_fds_clean()) return 64;
    if (!output_is_socket) {
        output_fd = open_private_fifo_output(&output_stat);
        if (output_fd < 0) return 64;
    }
    signal(SIGPIPE, SIG_IGN); signal(SIGCHLD, SIG_DFL);
    signal(SIGTERM, stop); signal(SIGINT, stop); signal(SIGHUP, stop);
    int fds[2]; if (pipe2(fds, O_NONBLOCK | O_CLOEXEC)) { if (output_fd > 2) close(output_fd); return 70; }
    uint64_t start = now_ms(); if (!start) { close(fds[0]); close(fds[1]); if (output_fd > 2) close(output_fd); return 70; }
    pid_t parent = getpid(), child = fork();
    if (child < 0) { close(fds[0]); close(fds[1]); if (output_fd > 2) close(output_fd); return 70; }
    if (!child) {
        if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) || getppid() != parent) _exit(125);
        close(fds[0]);
        if (output_fd > 2) close(output_fd);
        struct rlimit core = {0, 0};
        if (setrlimit(RLIMIT_CORE, &core) || prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)) _exit(125);
        int sink = open("/dev/null", O_RDWR | O_NOFOLLOW | O_CLOEXEC);
        if (sink < 0 || fstat(sink, &st) || !S_ISCHR(st.st_mode) || st.st_rdev != makedev(1, 3) ||
            dup2(sink, 0) < 0 || dup2(sink, 1) < 0 || dup2(sink, 2) < 0) _exit(125);
        if (sink > 2) close(sink);
        signal(SIGTERM, SIG_DFL); signal(SIGINT, SIG_DFL); signal(SIGHUP, SIG_DFL);
        struct channel c = {fds[1], 0, 0};
        struct m19_endpoint_result r = {0, 0, 0};
        int status = m19_endpoint_check(progress, &c, &r);
        if (status != r.status) _exit(125);
        struct packet p = {MAGIC, c.sequence++, 1, c.stage, r.flags, r.status, r.detail_errno};
        if (write(c.fd, &p, sizeof(p)) != (ssize_t)sizeof(p) || close(c.fd)) _exit(125);
        _exit(status ? 1 : 0);
    }
    close(fds[1]);
    unsigned next = 0, last = 5, flags = 0; int final = 0, status = -1, detail = 0;
    int reaped = 0, eof = 0, raw = -1; size_t used = 0; unsigned char bytes[sizeof(struct packet)];
    uint64_t deadline = start + M19_ENDPOINT_WORK_MS;
    const char *failure = NULL;
    while (!failure) {
        uint64_t time = now_ms();
        if (!time || time < start || time >= deadline) { failure = "TIMEOUT"; break; }
        if (interrupted) { failure = "INTERRUPTED"; break; }
        ssize_t n = read(fds[0], bytes + used, sizeof(bytes) - used);
        if (n > 0) {
            used += (size_t)n; if (used != sizeof(bytes)) continue;
            struct packet p; memcpy(&p, bytes, sizeof(p)); used = 0;
            if (final || !valid(&p, next, flags, last)) { failure = "PROTOCOL"; break; }
            next++; last = p.stage; flags = p.flags;
            if (p.final) {
                final = 1; status = p.status; detail = p.detail_errno;
                deadline = now_ms() + M19_ENDPOINT_REAP_MS;
            } else {
                char line[128];
                int count = snprintf(line, sizeof(line), "M19_ENDPOINT1 event=begin stage=%s flags=%u\n", stage_name(last), flags);
                if (count < 0 || (size_t)count >= sizeof(line) || output(line, (size_t)count)) { failure = "OUTPUT"; break; }
            }
        } else if (!n) eof = 1;
        else if (errno != EAGAIN && errno != EINTR) { failure = "IPC"; break; }
        if (!reaped) {
            pid_t got = waitpid(child, &raw, WNOHANG);
            if (got == child) reaped = 1;
            else if (got < 0 && errno != EINTR) { failure = "WAIT"; break; }
        }
        if (eof && reaped) {
            if (used || !final || !WIFEXITED(raw) || WEXITSTATUS(raw) != (status ? 1 : 0)) failure = "CHILD";
            break;
        }
        struct pollfd p = {fds[0], POLLIN, 0};
        if (poll(&p, 1, 10) < 0 && errno != EINTR) { failure = "POLL"; break; }
    }
    if (failure && !reaped) {
        (void)kill(child, SIGKILL);
        uint64_t stop_at = now_ms() + M19_ENDPOINT_REAP_MS;
        for (unsigned n = 0; n <= M19_ENDPOINT_REAP_MS / 10; n++) {
            uint64_t time = now_ms(); if (!time || time >= stop_at) break;
            pid_t got = waitpid(child, &raw, WNOHANG);
            if (got == child) { reaped = 1; break; }
            if (got < 0 && errno != EINTR) break;
            (void)poll(NULL, 0, 10);
        }
    }
    close(fds[0]);
    int ok = !failure && final && !status && reaped && eof;
    char line[320];
    int count = snprintf(line, sizeof(line),
        "M19_ENDPOINT1 final=%s stage=%s status=%d errno=%d flags=%u reaped=%d raw_wait=%d descriptor=%s key_calls=0 retry=0 r1=0\n",
        ok ? "OK" : failure ? failure : "ERROR", stage_name(last), status, detail, flags, reaped, raw,
        ok ? "android.system.keystore2.IKeystoreService" : "UNVERIFIED");
    int output_failed = count < 0 || (size_t)count >= sizeof(line) || output(line, (size_t)count);
    if (output_fd > 2) close(output_fd);
    if (output_failed) return 1;
    return ok ? 0 : 1;
}
