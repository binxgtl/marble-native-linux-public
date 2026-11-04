/* Deliberately hostile synthetic workers, never linked into the Android tool. */
#define m19_endpoint_check hostile_worker
#include "supervisor.c"
#include <stdlib.h>

int hostile_worker(m19_endpoint_progress send, void *context, struct m19_endpoint_result *r) {
    const char *mode = getenv("M19_ENDPOINT_HOSTILE");
    if (!mode) mode = "success";
    *r = (struct m19_endpoint_result){0, 0, 31};
    if (!strcmp(mode, "crash")) _exit(23);
    send(M19_ENDPOINT_STAGE_LOAD, 0, context);
    if (!strcmp(mode, "block")) for (;;) pause();
    if (!strcmp(mode, "incomplete")) _exit(0);
    if (!strcmp(mode, "partial")) {
        struct channel *c = context; unsigned char byte = 1;
        ssize_t n = write(c->fd, &byte, 1); _exit(n == 1 ? 0 : 125);
    }
    if (!strcmp(mode, "skip")) { send(M19_ENDPOINT_STAGE_LOOKUP, 3, context); return 0; }
    if (!strcmp(mode, "duplicate")) { send(M19_ENDPOINT_STAGE_LOAD, 0, context); return 0; }
    if (!strcmp(mode, "false-success")) return 0;
    send(M19_ENDPOINT_STAGE_SYMBOLS, 1, context);
    send(M19_ENDPOINT_STAGE_LOOKUP, 3, context);
    send(M19_ENDPOINT_STAGE_DESCRIPTOR, 7, context);
    if (!strcmp(mode, "missing-release")) return 0;
    send(M19_ENDPOINT_STAGE_RELEASE, !strcmp(mode, "flags-regress") ? 3 :
        (!strcmp(mode, "descriptor-absent") || !strcmp(mode, "invented-descriptor")) ? 7 : 15, context);
    if (!strcmp(mode, "descriptor-absent")) r->flags = 23;
    if (!strcmp(mode, "success-errno")) r->detail_errno = EPROTO;
    if (!strcmp(mode, "wrong-status")) r->status = 7;
    if (!strcmp(mode, "wrong-exit") || !strcmp(mode, "trailing-byte")) {
        struct channel *c = context;
        struct packet p = {MAGIC, c->sequence++, 1, 4, 31, 0, 0};
        if (write(c->fd, &p, sizeof(p)) != (ssize_t)sizeof(p)) _exit(125);
        if (!strcmp(mode, "wrong-exit")) _exit(23);
        unsigned char byte = 1;
        ssize_t n = write(c->fd, &byte, 1); _exit(n == 1 ? 0 : 125);
    }
    return r->status;
}
