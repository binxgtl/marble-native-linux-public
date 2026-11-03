// Actual binding.cpp with typed host stand-ins. Never a TEE or wire qualification.
#include "binding-test-api.h"
#include "binding.h"
#include <cassert>
#include <cstdio>

extern "C" void m19_wipe(void* p, size_t n) {
    volatile uint8_t* b = static_cast<volatile uint8_t*>(p);
    for (size_t i = 0; i < n; ++i) b[i] = 0;
    ++m19_test::wipes;
    for (auto& r : m19_test::regions) if (r.address == p && n >= r.size) r.wiped = true;
}
int main() {
    uint8_t blob[214], app[64], nonce[12], body[40], storage[4096], ephemeral[4096];
    std::memset(blob, 0x11, sizeof(blob)); std::memset(app, 0x22, sizeof(app));
    std::memset(nonce, 0x33, sizeof(nonce)); std::memset(body, 0x44, sizeof(body));
    std::memset(storage, 0xdd, sizeof(storage)); std::memset(ephemeral, 0xdd, sizeof(ephemeral));
    const m19_keystore_ops* ops = m19_keystore2_ops(); void* context = m19_keystore2_context();
    int detail = 0; size_t size = 0;
    int result = ops->connect(context, &detail);
    bool connect_error = m19_test::fault("missing-library") || m19_test::fault("missing-marker") ||
        m19_test::fault("missing-lookup") || m19_test::fault("missing-service") ||
        m19_test::fault("null-level") || m19_test::fault("level-error");
    assert((result != M19_KS_OK) == connect_error);
    if (!connect_error) {
        m19_decrypt_request req = {blob, sizeof(blob), app, sizeof(app), nonce, sizeof(nonce), body, sizeof(body)};
        result = ops->decrypt(context, &req, storage, sizeof(storage), &size, &detail);
        bool fail_decrypt = m19_test::fault("create-error") || m19_test::fault("create-error-upgrade") ||
            m19_test::fault("empty-upgrade") || m19_test::fault("oversized-upgrade") || m19_test::fault("null-operation") ||
            m19_test::fault("update-error") || m19_test::fault("update-throw") || m19_test::fault("update-oversize") ||
            m19_test::fault("finish-error") || m19_test::fault("finish-throw") ||
            m19_test::fault("upgrade-then-fail") || m19_test::fault("empty");
        assert((result == M19_KS_ERROR) == fail_decrypt);
        if (fail_decrypt) {
            for (uint8_t b : storage) assert(b == 0);
            assert(m19_keystore2_upgrade() == M19_U_UNKNOWN);
        } else {
            assert(size == 40);
            assert((result == M19_KS_UPGRADE) == m19_test::fault("upgrade"));
            result = ops->ephemeral(context, storage, size, ephemeral, sizeof(ephemeral), &size, &detail);
            bool fail_ephemeral = m19_test::fault("convert-error") || m19_test::fault("convert-error-upgrade") ||
                m19_test::fault("convert-empty") || m19_test::fault("convert-oversize") || m19_test::fault("convert-throw") ||
                m19_test::fault("convert-empty-upgrade") || m19_test::fault("convert-oversized-upgrade");
            assert((result == M19_KS_ERROR) == fail_ephemeral);
            if (fail_ephemeral || m19_test::fault("convert-upgrade")) {
                for (uint8_t b : ephemeral) assert(b == 0);
                if (fail_ephemeral) assert(m19_keystore2_upgrade() == M19_U_UNKNOWN);
                else assert(result == M19_KS_UPGRADE);
            } else assert(result == M19_KS_OK && size == 64);
        }
    }
    bool observed = m19_test::fault("upgrade") || m19_test::fault("upgrade-then-fail") ||
        m19_test::fault("create-error-upgrade") || m19_test::fault("empty-upgrade") || m19_test::fault("oversized-upgrade") ||
        m19_test::fault("convert-upgrade") || m19_test::fault("convert-error-upgrade") ||
        m19_test::fault("convert-empty-upgrade") || m19_test::fault("convert-oversized-upgrade");
    if (m19_test::fault("empty-upgrade") || m19_test::fault("oversized-upgrade") ||
        m19_test::fault("convert-empty-upgrade") || m19_test::fault("convert-oversized-upgrade"))
        assert(m19_keystore2_upgrade() == M19_U_UNKNOWN && m19_keystore2_upgrade_observed() == 1);
    assert(m19_keystore2_upgrade_observed() == observed);
    for (const auto& r : m19_test::regions) assert(r.wiped);
    std::puts("PASS actual binding paths; client-owned watched copies wiped; host stand-ins only");
}
