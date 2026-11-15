/* M17 PROBE BEGIN */
/* M17 G5c: M19 R6's sink-main.c (scripts/m19/run6/sink-main.c), byte for byte outside these marked blocks: the
 * speaker protection probe every 2 s while the amplifiers are on, into the tree's /var/lib/m19/m17-aw.log (256 KiB,
 * one older kept), and the stream at unity gain (0 dB, clamp at full scale) under the backstop: a live coil
 * temperature of 45 or more, a live Re outside 3,000 to 12,000 mOhm, ten reference replies in a row while the
 * output reached -20 dBFS (20 s), or a failed probe drops it to M19's -10 dB for the rest of the boot
 * (docs/m17-loudness-plan.md). */
/* M17 PROBE END */
/* M19 R6 marble-sink entry (/run/m19/m19-sink). Started once by m19-r6-report.service in T12-audio; refuses PID 1,
 * non-root and arguments; SIGTERM ends the stream as the session guard does (Disable first, then the hold); it never
 * exits once m11_entry_run begins, so the sealed endpoint, ION and dma-buf descriptors stay open until reset.
 */
#ifndef M11_CUSTODIAN_NATIVE
#error "m19 sink-main requires the reviewed M11_CUSTODIAN_NATIVE build"
#endif
#define _GNU_SOURCE /* sigaction under -std=c11 */
#include "sink.h"
/* M17 PROBE BEGIN */
#include "awprobe.h"
/* M17 PROBE END */
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
/* M17 PROBE BEGIN */
    m17_probe = (struct m17_probe_config){.log = "/var/lib/m19/m17-aw.log", .period_ms = 2000u, .log_limit = 262144u,
                                          .gain_q15 = 32768, .peak_limit = 32767,
                                          .backstop = {.te_limit = 45, .re_min = 3000, .re_max = 12000, .ref_limit = 10,
                                                       .loud_peak = 3277}};
/* M17 PROBE END */
    int rc = m19_sink_run(&cfg);
    return rc == 0 ? 0 : 1;
}
