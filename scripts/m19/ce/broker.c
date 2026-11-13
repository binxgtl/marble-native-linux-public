/* The CE broker's socket: one connection, one PIN, one attempt (docs/m19-r7.md). */
#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "broker.h"

static const char PREFIX[] = "PIN:";

static struct {
    char message[M19_CE_MESSAGE_MAX + 1];
} __attribute__((aligned(4096))) secret;

int m19_ce_broker_listen(const char *path)
{
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    if (!path || path[0] != '/' || strlen(path) >= sizeof(address.sun_path))
        return -1;
    strcpy(address.sun_path, path);
    int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    mode_t old = umask(0177);
    int bound = bind(fd, (struct sockaddr *)&address, sizeof(address));
    umask(old);
    if (bound || chmod(path, 0600) || listen(fd, 1)) {
        close(fd);
        return -1;
    }
    return fd;
}

static int reply(int fd, char *line, size_t line_size, const char *status, const struct m19_ce_report *report)
{
    int length = snprintf(line, line_size, "M19_CE status=%s detail=%d version=%d timeout=%u", status, report ? report->detail : 0,
                          report ? report->spblob_version : 0, report ? report->gk_timeout_ms : 0);
    if (length < 0 || (size_t)length >= line_size)
        return -1;
    ssize_t sent = send(fd, line, (size_t)length, MSG_NOSIGNAL);
    return sent == length ? 0 : -1;
}

int m19_ce_broker_serve(int listener, int timeout_ms, uid_t peer_uid, m19_ce_attempt attempt, void *context, char *line, size_t line_size)
{
    struct pollfd wait = {.fd = listener, .events = POLLIN};
    int result = -1, client = -1;
    line[0] = 0;
    (void)mlock(&secret, sizeof(secret));
    int ready;
    do
        ready = poll(&wait, 1, timeout_ms);
    while (ready < 0 && errno == EINTR);
    if (ready != 1) {
        snprintf(line, line_size, "M19_CE status=NO_CONNECTION");
        goto out;
    }
    client = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
    if (client < 0) {
        snprintf(line, line_size, "M19_CE status=NO_CONNECTION");
        goto out;
    }
    struct ucred cred;
    socklen_t cred_size = sizeof(cred);
    if (getsockopt(client, SOL_SOCKET, SO_PEERCRED, &cred, &cred_size) || cred_size != sizeof(cred) || cred.uid != peer_uid) {
        (void)reply(client, line, line_size, "PEER", NULL);
        goto out;
    }
    struct timeval limit = {.tv_sec = 30};
    (void)setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &limit, sizeof(limit));
    ssize_t got = recv(client, secret.message, M19_CE_MESSAGE_MAX + 1, MSG_TRUNC);
    if (got <= (ssize_t)(sizeof(PREFIX) - 1) || got > M19_CE_MESSAGE_MAX || memcmp(secret.message, PREFIX, sizeof(PREFIX) - 1)) {
        (void)reply(client, line, line_size, "MESSAGE", NULL);
        goto out;
    }
    size_t pin_size = (size_t)got - (sizeof(PREFIX) - 1);
    struct m19_ce_report report;
    memset(&report, 0, sizeof(report));
    result = attempt(context, secret.message + sizeof(PREFIX) - 1, pin_size, &report);
    m19_wipe(&secret, sizeof(secret));
    (void)reply(client, line, line_size, m19_ce_status_name((enum m19_ce_status)result), &report);
out:
    m19_wipe(&secret, sizeof(secret));
    if (client >= 0)
        close(client);
    return result;
}
