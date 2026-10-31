// m19-unlock: release the metadata key and load a read-only dm-default-key table.
// Output is one status line. Key material never reaches stdout, a file or a log.
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "binding.h"
#include "core.h"
#include "dm.h"

namespace {

// --probe rehearses every key step inside a booted TWRP and touches no device.
constexpr uint64_t kProbeSectors = 8;

int probe_sectors(void*, const char*, uint64_t* sectors) {
    *sectors = kProbeSectors;
    return 0;
}
int probe_name(void*, const char*) { return 0; }
int probe_load(void*, const char*, uint64_t, const char*, const char*) { return 0; }

const struct m19_dm_ops kProbeOps = {probe_sectors, probe_name, probe_load, probe_name, probe_name};

}  // namespace

int main(int argc, char** argv) {
    struct m19_dm_real dm = {-1, 0, 0};
    int detail = 0, upgraded = 0;
    enum m19_status status = M19_ARGUMENTS;
    if (argc == 3 && !std::strcmp(argv[1], "--probe")) {
        struct m19_target target = {"m19-probe", "/dev/m19-probe", kProbeSectors};
        status = m19_metadata_unlock(argv[2], &target, m19_keystore2_ops(), m19_keystore2_context(), &kProbeOps, nullptr, &detail, &upgraded);
    } else if (argc == 5) {
        struct m19_target target = {argv[2], argv[3], std::strtoull(argv[4], nullptr, 10)};
        status = m19_metadata_unlock(argv[1], &target, m19_keystore2_ops(), m19_keystore2_context(), &m19_dm_real_ops, &dm, &detail, &upgraded);
    }
    std::printf("M19_UNLOCK status=%s detail=%d upgraded=%d dev=%u:%u\n", m19_status_name(status), detail, upgraded, dm.major, dm.minor);
    return status == M19_OK ? 0 : 1;
}
