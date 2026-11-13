// ks.cpp on typed fakes (ks-test-api.h): one status line per run. Test only.
#include <cstdio>
#include <cstring>

#include "ks-test-api.h"
#include "ks.h"

int main(int argc, char** argv)
{
    const char* alias = argc > 1 ? argv[1] : "synthetic_password_36d2c530c09343ab";
    const m19_ce_keystore* ops = m19_ce_ks_ops();
    void* context = m19_ce_ks_context();
    int detail = 0;
    if (ops->connect(context, &detail)) {
        std::printf("KS connect=%d\n", detail);
        return 1;
    }
    m19_ce_auth_token token = {};
    token.challenge = 11;
    token.user_id = 22;
    token.authenticator_id = 33;
    token.authenticator_type = 1;
    token.timestamp_ms = 4455667788;
    for (int i = 0; i < 32; i++)
        token.mac[i] = static_cast<uint8_t>(i + 100);
    int auth = ops->add_auth_token(context, &token, &detail);
    int auth_ok = m19_test::seen[0] == 11 && m19_test::seen[1] == 22 && m19_test::seen[2] == 33 && m19_test::seen[3] == 1 &&
                  m19_test::seen[4] == 4455667788 && m19_test::seen_mac.size() == 32 && m19_test::seen_mac[0] == 100 &&
                  m19_test::seen_mac[31] == 131;
    uint8_t nonce[12], sealed[40], output[64];
    for (int i = 0; i < 12; i++)
        nonce[i] = static_cast<uint8_t>(0x11 + i);
    for (int i = 0; i < 40; i++)
        sealed[i] = static_cast<uint8_t>(i);
    size_t size = 0;
    int result = ops->sp_decrypt(context, alias, nonce, sealed, sizeof(sealed), output, sizeof(output), &size, &detail);
    int plain_ok = size == 40 && output[0] == 39 && output[39] == 0;
    int input_ok = m19_test::last_input_size == 40;
    std::printf("KS auth=%d auth_ok=%d result=%d detail=%d size=%zu plain_ok=%d input_ok=%d\n", auth, auth_ok, result, detail, size,
                plain_ok, input_ok);
    return 0;
}
