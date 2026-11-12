/* M19 R6 marble-sink entry (/run/m19/m19-sink). Started once by m19-r6-report.service in T12-audio; refuses PID 1,
 * non-root and arguments; SIGTERM ends the stream as the session guard does (Disable first, then the hold); it never
 * exits once m11_entry_run begins, so the sealed endpoint, ION and dma-buf descriptors stay open until reset.
 */
#ifndef M11_CUSTODIAN_NATIVE
#error "m19 sink-main requires the reviewed M11_CUSTODIAN_NATIVE build"
#endif
#define _GNU_SOURCE /* sigaction under -std=c11 */
#include "sink.h"
#include <signal.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void on_term(int number) {
    (void)number;
    m19_sink_terminate();
}

int main(int argc, char **argv) {
    (void)argv;
    if (argc != 1 || getpid() <= 1 || geteuid() != 0) return 2;
    umask(077);
    struct sigaction act;
    memset(&act, 0, sizeof act);
    act.sa_handler = on_term;
    sigemptyset(&act.sa_mask);
    if (sigaction(SIGTERM, &act, NULL)) return 2;
    struct m19_sink_config cfg = m19_sink_config_default();
    int rc = m19_sink_run(&cfg);
    return rc == 0 ? 0 : 1;
}
