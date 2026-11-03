/* Exact supervisor with a deliberately hostile synthetic worker. No Binder. */
#include "probe-supervisor.c"
#include <stdlib.h>
static int worker(const char *mode, m19_probe_progress send, void *context,
                  int *detail, enum m19_upgrade_fact *upgrade, int *observed)
{
    *detail = 0; *upgrade = M19_U_NONE_OBSERVED; *observed = 0;
    if (!strcmp(mode, "crash")) _exit(23);
    if (!strcmp(mode, "block")) for (;;) pause();
    if (!strcmp(mode, "partial")) {
        struct channel *c = context; unsigned char byte = 1;
        (void)write(c->fd, &byte, 1); _exit(0);
    }
    if (!strcmp(mode, "wrong-stage")) { send(context, M19_P_FINISH, M19_U_UNKNOWN, 0); return 1; }
    if (!strcmp(mode, "duplicate")) { send(context, M19_P_READ, M19_U_NOT_ATTEMPTED, 0); return 1; }
    for (unsigned s = M19_P_LOOKUP; s <= M19_P_EPHEMERAL; ++s)
        send(context, (enum m19_probe_stage)s, s < M19_P_CREATE ? M19_U_NOT_ATTEMPTED : M19_U_UNKNOWN, 0);
    return 0;
}
int main(int argc, char **argv)
{
    if (argc != 2) return 64;
    return m19_probe_supervise(argv[1], worker);
}
