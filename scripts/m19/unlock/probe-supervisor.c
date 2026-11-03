/* Finite, one-worker metadata probe. A timeout is NOT remote cancellation. */
#define _GNU_SOURCE
#include "probe.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef M19_PROBE_STEP_MS
#define M19_PROBE_STEP_MS 15000
#endif
#ifndef M19_PROBE_TOTAL_MS
#define M19_PROBE_TOTAL_MS 90000
#endif
#ifndef M19_PROBE_REAP_MS
#define M19_PROBE_REAP_MS 2000
#endif
#define MAGIC 0x4d195031u
struct event { uint32_t magic, sequence, stage, upgrade, observed, final; int32_t status, detail; };
struct channel { int fd; uint32_t sequence; };
static volatile sig_atomic_t interrupted;
static void stop(int s) { interrupted = s; }
static unsigned long long now(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) return 0;
    return (unsigned long long)t.tv_sec * 1000 + (unsigned)t.tv_nsec / 1000000;
}
static int nonblock(int fd) {
    int f = fcntl(fd, F_GETFL);
    return f < 0 ? -1 : fcntl(fd, F_SETFL, f | O_NONBLOCK);
}
static int output(const char *b, size_t n) {
    unsigned long long begin = now(), end = begin + 1000;
    if (!begin) return -1;
    while (n) {
        unsigned long long time = now();
        if (!time || time < begin || time >= end) return -1;
        ssize_t k = write(1, b, n);
        if (k > 0) { b += k; n -= (size_t)k; }
        else if (k == 0 || (errno != EINTR && errno != EAGAIN)) return -1;
        else { struct pollfd p = {1, POLLOUT, 0}; (void)poll(&p, 1, 10); }
    }
    return n ? -1 : 0;
}
static void progress(void *opaque, enum m19_probe_stage stage, enum m19_upgrade_fact u, int seen) {
    struct channel *c = opaque;
    struct event e = {MAGIC, c->sequence++, (uint32_t)stage, (uint32_t)u, (uint32_t)seen, 0, 0, 0};
    if (write(c->fd, &e, sizeof(e)) != (ssize_t)sizeof(e)) _exit(125);
}
static const char *stage_name(unsigned stage) {
    static const char *const names[] = {"key_read", "lookup", "security_level", "create", "update", "finish", "ephemeral", "result"};
    return stage < 8 ? names[stage] : "invalid";
}
static const char *upgrade_name(unsigned u) {
    static const char *const names[] = {"NOT_ATTEMPTED", "UNKNOWN", "NONE_OBSERVED", "OBSERVED"};
    return u < 4 ? names[u] : "UNKNOWN";
}
static int consistent(const struct event *e, unsigned prior_fact, unsigned prior_seen, unsigned key_rpc_started) {
    if ((e->upgrade == M19_U_OBSERVED && !e->observed) ||
        (e->upgrade == M19_U_NONE_OBSERVED && e->observed) ||
        (e->upgrade == M19_U_NOT_ATTEMPTED && (e->observed || key_rpc_started))) return 0;
    if (e->final) {
        if (!key_rpc_started) return e->upgrade == M19_U_NOT_ATTEMPTED;
        return e->status ? e->upgrade == M19_U_UNKNOWN : e->upgrade != M19_U_NOT_ATTEMPTED;
    }
    switch (e->stage) {
    case M19_P_READ: case M19_P_LOOKUP: case M19_P_LEVEL:
        return e->upgrade == M19_U_NOT_ATTEMPTED && !e->observed;
    case M19_P_CREATE: return e->upgrade == M19_U_UNKNOWN && !e->observed;
    case M19_P_UPDATE: return e->upgrade == M19_U_NONE_OBSERVED || e->upgrade == M19_U_OBSERVED;
    case M19_P_FINISH: return e->upgrade == prior_fact && e->observed == prior_seen;
    case M19_P_EPHEMERAL: return e->upgrade == M19_U_UNKNOWN && e->observed == prior_seen;
    default: return 0;
    }
}
int m19_probe_supervise(const char *directory, m19_probe_worker worker) {
    struct stat st;
    /* Only a host pipe/socket. A persistent-file redirection is not admitted. */
    if (fstat(1, &st) || (!S_ISFIFO(st.st_mode) && !S_ISSOCK(st.st_mode)) || nonblock(1)) return 64;
    signal(SIGPIPE, SIG_IGN); signal(SIGTERM, stop); signal(SIGINT, stop); signal(SIGHUP, stop);
    signal(SIGCHLD, SIG_DFL);
    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC | O_NONBLOCK)) return 70;
    unsigned long long start = now();
    if (!start) { close(pipefd[0]); close(pipefd[1]); return 70; }
    pid_t parent = getpid();
    pid_t child = fork();
    if (child < 0) { close(pipefd[0]); close(pipefd[1]); return 70; }
    if (!child) {
        /* Arm before key/Binder access; close the fork-to-prctl parent-death race. */
        if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) || getppid() != parent) _exit(125);
        close(pipefd[0]);
        int nullfd = open("/dev/null", O_RDWR | O_CLOEXEC | O_NOFOLLOW);
        struct stat sink;
        if (nullfd < 0 || fstat(nullfd, &sink) || !S_ISCHR(sink.st_mode) || sink.st_rdev != makedev(1, 3) ||
            dup2(nullfd, 0) < 0 || dup2(nullfd, 1) < 0 || dup2(nullfd, 2) < 0) _exit(125);
        if (nullfd > 2) close(nullfd);
        signal(SIGTERM, SIG_DFL); signal(SIGINT, SIG_DFL); signal(SIGHUP, SIG_DFL);
        struct rlimit core = {0, 0};
        if (setrlimit(RLIMIT_CORE, &core) || prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)) _exit(125);
        struct channel c = {pipefd[1], 0};
        progress(&c, M19_P_READ, M19_U_NOT_ATTEMPTED, 0);
        int detail = 0, observed = 0;
        enum m19_upgrade_fact u = M19_U_UNKNOWN;
        int status = worker(directory, progress, &c, &detail, &u, &observed);
        struct event e = {MAGIC, c.sequence++, M19_P_RESULT, (uint32_t)u, (uint32_t)observed, 1, status, detail};
        if (write(c.fd, &e, sizeof(e)) != (ssize_t)sizeof(e) || close(c.fd)) _exit(125);
        _exit(status ? 1 : 0);
    }
    close(pipefd[1]);
    unsigned long long end = start + M19_PROBE_TOTAL_MS, step = start + M19_PROBE_STEP_MS;
    unsigned next = 0, last = M19_P_READ, fact = M19_U_NOT_ATTEMPTED, observed = 0, key_rpc_started = 0;
    int final = 0, status = -1, detail = 0, raw = -1, reaped = 0, eof = 0;
    const char *failure = NULL;
    unsigned char partial[sizeof(struct event)]; size_t used = 0;
    while (!failure) {
        unsigned long long time = now();
        if (!time || time < start || time >= end || time >= step) { failure = "TIMEOUT"; break; }
        if (interrupted) { failure = "INTERRUPTED"; break; }
        ssize_t n = read(pipefd[0], partial + used, sizeof(partial) - used);
        if (n > 0) {
            used += (size_t)n;
            if (used != sizeof(partial)) continue;
            struct event e; memcpy(&e, partial, sizeof(e)); used = 0;
            if (final || e.magic != MAGIC || e.sequence != next++ || e.stage > M19_P_RESULT ||
                e.upgrade > M19_U_OBSERVED || e.observed > 1 || e.final > 1 || e.observed < observed ||
                (!e.final && (e.stage != next - 1 || e.stage >= M19_P_RESULT)) ||
                (e.final && (e.stage != M19_P_RESULT || e.status < 0 || e.status > 12)) ||
                !consistent(&e, fact, observed, key_rpc_started)) {
                failure = "PROTOCOL"; break;
            }
            last = e.stage; fact = e.upgrade; observed = e.observed;
            if (!e.final && e.stage >= M19_P_CREATE) key_rpc_started = 1;
            char text[160];
            int count = snprintf(text, sizeof(text), "M19_PROBE1 event=stage stage=%s upgrade=%s observed=%u\n",
                                 stage_name(last), upgrade_name(fact), observed);
            if (count < 0 || (size_t)count >= sizeof(text) || output(text, (size_t)count)) { failure = "OUTPUT"; break; }
            if (e.final) {
                final = 1; status = e.status; detail = e.detail;
                if (!status && (next != 8 || (fact != M19_U_NONE_OBSERVED && fact != M19_U_OBSERVED))) { failure = "INCOMPLETE"; break; }
                step = now() + M19_PROBE_REAP_MS;
            } else step = now() + M19_PROBE_STEP_MS;
        } else if (!n) eof = 1;
        else if (errno != EINTR && errno != EAGAIN) { failure = "IPC"; break; }
        if (!reaped) {
            pid_t got = waitpid(child, &raw, WNOHANG);
            if (got == child) reaped = 1;
            else if (got < 0 && errno != EINTR) { failure = "WAIT"; break; }
        }
        if (eof && reaped) {
            if (used || !final || !WIFEXITED(raw) || WEXITSTATUS(raw) != (status ? 1 : 0)) failure = "CHILD";
            break;
        }
        struct pollfd p = {pipefd[0], POLLIN, 0};
        if (poll(&p, 1, 10) < 0 && errno != EINTR) { failure = "POLL"; break; }
    }
    if (failure && !reaped) {
        /* Stop this client once. This does not cancel/undo a remote TA operation. */
        (void)kill(child, SIGKILL);
        unsigned long long until = now() + M19_PROBE_REAP_MS;
        for (unsigned ticks = 0; ticks <= M19_PROBE_REAP_MS / 10; ticks++) {
            unsigned long long time = now(); if (!time || time >= until) break;
            pid_t got = waitpid(child, &raw, WNOHANG);
            if (got == child) { reaped = 1; break; }
            if (got < 0 && errno != EINTR) break;
            (void)poll(NULL, 0, 10);
        }
    }
    close(pipefd[0]);
    int ok = !failure && status == 0 && reaped && eof;
    if (!ok && (failure || key_rpc_started || observed)) fact = M19_U_UNKNOWN;
    char receipt[384];
    int count = snprintf(receipt, sizeof(receipt),
        "M19_PROBE1 final=%s stage=%s status=%d detail=%d upgrade=%s upgrade_observed=%u reaped=%d raw_wait=%d remote=%s retry=0 r1=0\n",
        ok ? "OK" : failure ? failure : "ERROR", stage_name(last), status, detail, upgrade_name(fact), observed,
        reaped, raw, failure ? "UNKNOWN" : "RPC_RETURNED_NOT_QUIESCENCE");
    if (count < 0 || (size_t)count >= sizeof(receipt) || output(receipt, (size_t)count)) return 1;
    return ok ? 0 : 1;
}
