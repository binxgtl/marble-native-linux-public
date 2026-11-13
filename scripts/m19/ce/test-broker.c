/* broker.c with a fake attempt: test-broker <socket> <peer uid> <timeout ms>. Prints the reply line and how
 * the attempt was called. Test only. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "broker.h"

static int calls;
static char seen[32];

static enum m19_ce_status fake(void *context, const char *pin, size_t size, struct m19_ce_report *report)
{
    (void)context;
    calls++;
    if (size < sizeof(seen)) {
        memcpy(seen, pin, size);
        seen[size] = 0;
    }
    report->detail = 7;
    report->spblob_version = 3;
    return m19_ce_check_pin(pin, size) ? M19_CE_ARGUMENTS : !strcmp(seen, "482916") ? M19_CE_OK : M19_CE_GK_REJECTED;
}

int main(int argc, char **argv)
{
    if (argc != 4)
        return 64;
    int listener = m19_ce_broker_listen(argv[1]);
    if (listener < 0) {
        printf("BROKER listen failed\n");
        return 1;
    }
    printf("BROKER ready\n");
    fflush(stdout);
    char line[128];
    int result = m19_ce_broker_serve(listener, atoi(argv[3]), (uid_t)atoi(argv[2]), fake, NULL, line, sizeof(line));
    printf("BROKER result=%d calls=%d pin=%s line=%s\n", result, calls, seen[0] ? seen : "-", line);
    return 0;
}
