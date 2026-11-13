// m19-ce, run inside the TEE island (docs/m19-r7.md). Output is status codes and counts only.
//   m19-ce de       DE system and user 0 keys added to /data, the Keystore2 database copied into RAM.
//   m19-ce broker <socket>
//                   Binds <socket> in a directory T9-ce bound in from the session's /run, waits for one PIN from
//                   uid 0, runs the CE path once, answers, logs the status line to the kernel log and exits.
#include <dirent.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>

#include "../unlock/binding.h"
#include "broker.h"
#include "ce.h"
#include "crypto.h"
#include "fscrypt.h"
#include "gk.h"
#include "ks.h"

namespace {

constexpr char kData[] = "/data";
constexpr char kSystemDe[] = "/data/unencrypted/key";
constexpr char kUserDe[] = "/data/misc/vold/user_keys/de/0";
constexpr char kSpblob[] = "/data/system_de/0/spblob";
constexpr char kCe[] = "/data/misc/vold/user_keys/ce/0/current";
constexpr char kDatabase[] = "/data/misc/keystore/persistent.sqlite";
constexpr char kIslandDatabase[] = "/tmp/misc/keystore/persistent.sqlite";
constexpr char kCrypto[] = "libcrypto.so";
constexpr char kGatekeeper[] = "android.hardware.gatekeeper@1.0.so";
constexpr int kBrokerWaitMs = 30 * 60 * 1000;

int count_entries(const char* path)
{
    DIR* directory = opendir(path);
    if (!directory)
        return -1;
    int count = 0;
    for (dirent* entry; (entry = readdir(directory));)
        count += std::strcmp(entry->d_name, ".") && std::strcmp(entry->d_name, "..");
    closedir(directory);
    return count;
}

int de_main()
{
    m19_ce_fs_context fs;
    int detail[2] = {0, 0}, upgraded[2] = {0, 0}, keys = 0;
    m19_ce_status status = M19_CE_INSTALL, db = M19_CE_DB_COPY;
    int spblob = -1;
    if (!m19_ce_fs_open(&fs, kData)) {
        status = m19_ce_install_keystore_key(kSystemDe, m19_keystore2_ops(), m19_keystore2_context(), &m19_ce_fs_ops, &fs, &detail[0],
                                             &upgraded[0]);
        keys += status == M19_CE_OK;
        if (status == M19_CE_OK) {
            status = m19_ce_install_keystore_key(kUserDe, m19_keystore2_ops(), m19_keystore2_context(), &m19_ce_fs_ops, &fs, &detail[1],
                                                 &upgraded[1]);
            keys += status == M19_CE_OK;
        }
        if (status == M19_CE_OK) {
            spblob = count_entries(kSpblob);
            db = m19_ce_copy_db(kDatabase, kIslandDatabase);
        }
        close(fs.fd);
    }
    std::printf("M19_CE_DE status=%s keys=%d detail=%d,%d upgraded=%d,%d spblob=%d db=%s\n", m19_ce_status_name(status), keys, detail[0],
                detail[1], upgraded[0], upgraded[1], spblob, m19_ce_status_name(db));
    return status == M19_CE_OK && spblob > 0 && db == M19_CE_OK ? 0 : 1;
}

struct Island {
    m19_ce_env env;
    m19_ce_fs_context fs;
    m19_ce_gk_context gk;
};

m19_ce_status attempt(void* opaque, const char* pin, size_t size, m19_ce_report* report)
{
    auto* island = static_cast<Island*>(opaque);
    island->env.crypto = m19_ce_crypto_open(kCrypto);
    if (!island->env.crypto)
        return M19_CE_CRYPTO;
    return m19_ce_unlock(&island->env, pin, size, report);
}

int broker_main(const char* socket)
{
    static Island island;
    int listener = m19_ce_broker_listen(socket);
    if (listener < 0) {
        std::printf("M19_CE status=BROKER\n");
        return 1;
    }
    std::printf("M19_CE broker listening\n");
    std::fflush(stdout);
    island.gk.library = kGatekeeper;
    island.env.spblob_dir = open(kSpblob, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    island.env.ce_dir = open(kCe, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    island.env.user = 0;
    island.env.gatekeeper = &m19_ce_gk_ops;
    island.env.gatekeeper_context = &island.gk;
    island.env.keystore = m19_ce_ks_ops();
    island.env.keystore_context = m19_ce_ks_context();
    island.env.storage = m19_keystore2_ops();
    island.env.storage_context = m19_keystore2_context();
    island.env.fs = &m19_ce_fs_ops;
    island.env.fs_context = &island.fs;
    if (m19_ce_fs_open(&island.fs, kData))
        island.fs.fd = -1;
    char line[160];
    int result = m19_ce_broker_serve(listener, kBrokerWaitMs, 0, attempt, &island, line, sizeof(line));
    std::printf("%s\n", line);
    std::fflush(stdout);
    int kmsg = open("/dev/kmsg", O_WRONLY | O_CLOEXEC);
    if (kmsg >= 0) {
        dprintf(kmsg, "<6>%s\n", line);
        close(kmsg);
    }
    return result == M19_CE_OK ? 0 : 1;
}

}  // namespace

int main(int argc, char** argv)
{
    // Nothing of this process may be swapped, dumped or traced.
    (void)mlockall(MCL_CURRENT | MCL_FUTURE);
    (void)prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    if (argc == 2 && !std::strcmp(argv[1], "de"))
        return de_main();
    if (argc == 3 && !std::strcmp(argv[1], "broker"))
        return broker_main(argv[2]);
    std::printf("M19_CE status=ARGUMENTS\n");
    return 64;
}
