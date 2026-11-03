// Probe-only main. Linked without dm.c. No R1 invocation or fallback exists.
#include <cstring>
#include "binding.h"
#include "probe.h"

static int worker(const char* directory, m19_probe_progress progress, void* context,
                  int* detail, m19_upgrade_fact* upgrade, int* observed) {
    m19_keystore2_progress(progress, context);
    int legacy = -1;
    int status = m19_metadata_probe(directory, m19_keystore2_ops(), m19_keystore2_context(), detail, &legacy);
    *upgrade = m19_keystore2_upgrade();
    *observed = m19_keystore2_upgrade_observed();
    return status;
}
int main(int argc, char** argv) {
    if (argc != 3 || std::strcmp(argv[1], "--probe") || !argv[2][0]) return 64;
    return m19_probe_supervise(argv[2], worker);
}
