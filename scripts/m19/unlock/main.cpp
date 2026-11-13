// m19-unlock: release the metadata key and load a dm-default-key table, read-only. With --rw first (R8,
// docs/m19-r8.md) the table is read-write and the status line says table=rw before dev=.
// Output is one status line. Key material never reaches stdout, a file or a log.
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "binding.h"
#include "core.h"
#include "dm.h"

int main(int argc, char** argv) {
    struct m19_dm_real dm = {-1, 0, 0};
    int detail = 0, upgraded = 0;
    enum m19_status status = M19_ARGUMENTS;
    const int rw = argc == 6 && !std::strcmp(argv[1], "--rw");
    char** args = argv + rw;
    // Standalone probes use the separately supervised, DM-free m19-probe executable.
    if (argc - rw == 5 && std::strcmp(args[1], "--probe") && std::strcmp(args[1], "--rw")) {
        struct m19_target target = {args[2], args[3], std::strtoull(args[4], nullptr, 10)};
        status = m19_metadata_unlock(args[1], &target, m19_keystore2_ops(), m19_keystore2_context(), rw ? &m19_dm_real_rw_ops : &m19_dm_real_ops, &dm,
                                     &detail, &upgraded);
    }
    std::printf("M19_UNLOCK status=%s detail=%d upgraded=%d%s dev=%u:%u\n", m19_status_name(status), detail, upgraded, rw ? " table=rw" : "", dm.major,
                dm.minor);
    return status == M19_OK ? 0 : 1;
}
