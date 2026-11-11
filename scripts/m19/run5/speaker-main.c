/* M19 R5b on-device speaker daemon entry (/run/m19/m19-speaker).
 * Started once by m19-r5-report.service during T12-audio; refuses PID 1, non-root, and extra arguments;
 * never exits once m11_entry_run begins so sealed endpoint, ION and dma-buf fds stay open until reset.
 */
#ifndef M11_CUSTODIAN_NATIVE
#error "m19 speaker-main requires the reviewed M11_CUSTODIAN_NATIVE build"
#endif
#include "speaker.h"
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv) {
    (void)argv;
    if (argc != 1 || getpid() <= 1 || geteuid() != 0) return 2;
    umask(077);
    struct m19_speaker_config cfg = m19_speaker_config_default();
    int rc = m19_speaker_run(&cfg);
    return rc == 0 ? 0 : 1;
}
