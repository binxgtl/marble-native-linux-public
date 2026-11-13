#ifndef M19_CE_BROKER_H
#define M19_CE_BROKER_H

#include <sys/types.h>

#include "ce.h"

#ifdef __cplusplus
extern "C" {
#endif

#define M19_CE_MESSAGE_MAX 64

typedef enum m19_ce_status (*m19_ce_attempt)(void *context, const char *pin, size_t size, struct m19_ce_report *report);

/* A SOCK_SEQPACKET listener at path, mode 0600. An existing path is refused, never replaced. -1 on failure. */
int m19_ce_broker_listen(const char *path);

/* One connection from `peer_uid`, one "PIN:<digits>" message, one attempt, one reply line, then return.
 * Anything else is refused without an attempt. The PIN lives only in a locked static page, wiped on return.
 * Returns the attempt's status, or -1 when no attempt was made. `line` receives the reply. */
int m19_ce_broker_serve(int listener, int timeout_ms, uid_t peer_uid, m19_ce_attempt attempt, void *context, char *line, size_t line_size);

#ifdef __cplusplus
}
#endif

#endif
