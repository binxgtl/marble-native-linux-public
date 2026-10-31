// m19-unlock: release the metadata key and load a read-only dm-default-key table.
// Output is one status line. Key material never reaches stdout, a file or a log.
#include <cstdio>
#include <cstdlib>

#include "binding.h"
#include "core.h"
#include "dm.h"

int main(int argc, char** argv) {
    struct m19_dm_real dm = {-1, 0, 0};
    int detail = 0;
    enum m19_status status = M19_ARGUMENTS;
    if (argc == 5) {
        struct m19_target target = {argv[2], argv[3], std::strtoull(argv[4], nullptr, 10)};
        status = m19_metadata_unlock(argv[1], &target, m19_keystore2_ops(), m19_keystore2_context(), &m19_dm_real_ops, &dm, &detail);
    }
    std::printf("M19_UNLOCK status=%s detail=%d dev=%u:%u\n", m19_status_name(status), detail, dm.major, dm.minor);
    return status == M19_OK ? 0 : 1;
}
