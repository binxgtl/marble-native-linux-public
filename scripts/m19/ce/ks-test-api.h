// Host-only typed stand-in for the Keystore2 and IKeystoreAuthorization AIDL types ks.cpp uses. It checks the
// request contract TWRP's unwrapSyntheticPasswordBlob makes; it is not a Binder, wire or TEE emulator.
#ifndef M19_KS_TEST_API_H
#define M19_KS_TEST_API_H
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <variant>
#include <vector>

#include "ce.h"

#define EX_SERVICE_SPECIFIC (-8)
struct AIBinder {};
namespace ndk {
struct ScopedAStatus {
    int error = 0;
    bool isOk() const { return error == 0; }
    int getExceptionCode() const { return error ? EX_SERVICE_SPECIFIC : 0; }
    int getServiceSpecificError() const { return error; }
    int getStatus() const { return 0; }
};
struct SpAIBinder {
    AIBinder* value;
    explicit SpAIBinder(AIBinder* b) : value(b) {}
};
}  // namespace ndk

namespace m19_test {
inline bool fault(const char* s)
{
    const char* v = std::getenv("M19_TEST_FAULT");
    return v && std::strcmp(v, s) == 0;
}
inline bool token_added = false;
inline int64_t seen[5];
inline std::vector<uint8_t> seen_mac;
inline const uint8_t* last_input = nullptr;
inline size_t last_input_size = 0;
}  // namespace m19_test

namespace aidl::android::hardware::security::secureclock {
struct Timestamp {
    int64_t milliSeconds = 0;
};
}  // namespace aidl::android::hardware::security::secureclock

namespace aidl::android::hardware::security::keymint {
enum class Algorithm { AES = 32 };
enum class BlockMode { GCM = 32 };
enum class KeyPurpose { DECRYPT = 1 };
enum class PaddingMode { NONE = 1 };
enum class HardwareAuthenticatorType : int32_t {};
enum class Tag { ALGORITHM, BLOCK_MODE, PADDING, PURPOSE, NONCE, MAC_LENGTH };
struct KeyParameterValue {
    enum class Tag { algorithm, blockMode, paddingMode, keyPurpose, integer, blob };
    Tag tag = Tag::integer;
    std::variant<int, std::vector<uint8_t>> value = 0;
    template <Tag t, typename V>
    static KeyParameterValue make(V v)
    {
        KeyParameterValue p;
        p.tag = t;
        if constexpr (std::is_same_v<V, std::vector<uint8_t>>)
            p.value = std::move(v);
        else
            p.value = static_cast<int>(v);
        return p;
    }
};
struct KeyParameter {
    Tag tag = Tag::ALGORITHM;
    KeyParameterValue value;
};
struct HardwareAuthToken {
    int64_t challenge = 0, userId = 0, authenticatorId = 0;
    HardwareAuthenticatorType authenticatorType{};
    secureclock::Timestamp timestamp;
    std::vector<uint8_t> mac;
};
}  // namespace aidl::android::hardware::security::keymint

namespace aidl::android::security::authorization {
struct IKeystoreAuthorization {
    static std::shared_ptr<IKeystoreAuthorization> fromBinder(const ndk::SpAIBinder& b)
    {
        return b.value ? std::make_shared<IKeystoreAuthorization>() : nullptr;
    }
    ndk::ScopedAStatus addAuthToken(const ::aidl::android::hardware::security::keymint::HardwareAuthToken& token)
    {
        m19_test::seen[0] = token.challenge;
        m19_test::seen[1] = token.userId;
        m19_test::seen[2] = token.authenticatorId;
        m19_test::seen[3] = static_cast<int32_t>(token.authenticatorType);
        m19_test::seen[4] = token.timestamp.milliSeconds;
        m19_test::seen_mac = token.mac;
        if (m19_test::fault("auth-error"))
            return {-1};
        m19_test::token_added = true;
        return {};
    }
};
}  // namespace aidl::android::security::authorization

namespace aidl::android::system::keystore2 {
namespace km = ::aidl::android::hardware::security::keymint;
enum class Domain { APP, GRANT, SELINUX, BLOB, KEY_ID };
struct KeyDescriptor {
    Domain domain = Domain::APP;
    int64_t nspace = 0;
    std::optional<std::string> alias;
    std::optional<std::vector<uint8_t>> blob;
};
struct KeyMetadata {
    KeyDescriptor key;
};
struct IKeystoreOperation {
    ndk::ScopedAStatus finish(const std::optional<std::vector<uint8_t>>& input, const std::optional<std::vector<uint8_t>>& signature,
                              std::optional<std::vector<uint8_t>>* output)
    {
        if (!input || signature)
            throw std::runtime_error("finish contract");
        m19_test::last_input = input->data();
        m19_test::last_input_size = input->size();
        if (m19_test::fault("finish-error"))
            return {-30};
        std::vector<uint8_t> plain(input->rbegin(), input->rend()); // the fake's "decryption"
        if (m19_test::fault("finish-oversize"))
            plain.resize(4096, 0);
        if (m19_test::fault("finish-empty"))
            plain.clear();
        output->emplace(std::move(plain));
        return {};
    }
};
struct CreateOperationResponse {
    std::shared_ptr<IKeystoreOperation> iOperation;
};
struct IKeystoreSecurityLevel {
    ndk::ScopedAStatus createOperation(const KeyDescriptor& key, const std::vector<km::KeyParameter>& parameters, bool forced,
                                       CreateOperationResponse* response)
    {
        using K = km::KeyParameterValue::Tag;
        if (key.domain != Domain::KEY_ID || key.nspace != 4242 || key.alias || key.blob || !forced || parameters.size() != 6)
            throw std::runtime_error("create contract");
        const km::Tag tags[] = {km::Tag::ALGORITHM, km::Tag::BLOCK_MODE, km::Tag::PADDING, km::Tag::PURPOSE, km::Tag::NONCE, km::Tag::MAC_LENGTH};
        const K kinds[] = {K::algorithm, K::blockMode, K::paddingMode, K::keyPurpose, K::blob, K::integer};
        const int values[] = {32, 32, 1, 1, -1, 128};
        for (int i = 0; i < 6; i++) {
            if (parameters[i].tag != tags[i] || parameters[i].value.tag != kinds[i])
                throw std::runtime_error("parameter order");
            if (i == 4) {
                const auto& nonce = std::get<std::vector<uint8_t>>(parameters[i].value.value);
                if (nonce.size() != 12 || nonce[0] != 0x11 || nonce[11] != 0x1c)
                    throw std::runtime_error("nonce");
            } else if (std::get<int>(parameters[i].value.value) != values[i]) {
                throw std::runtime_error("parameter value");
            }
        }
        if (!m19_test::token_added || m19_test::fault("create-error"))
            return {-26}; // KEY_USER_NOT_AUTHENTICATED
        if (!m19_test::fault("null-operation"))
            response->iOperation = std::make_shared<IKeystoreOperation>();
        return {};
    }
};
struct KeyEntryResponse {
    std::shared_ptr<IKeystoreSecurityLevel> iSecurityLevel;
    KeyMetadata metadata;
};
struct IKeystoreService {
    static std::shared_ptr<IKeystoreService> fromBinder(const ndk::SpAIBinder& b)
    {
        return b.value ? std::make_shared<IKeystoreService>() : nullptr;
    }
    ndk::ScopedAStatus getKeyEntry(const KeyDescriptor& key, KeyEntryResponse* response)
    {
        if (key.domain != Domain::SELINUX || key.nspace != 103 || key.blob || !key.alias)
            throw std::runtime_error("entry contract");
        if (*key.alias != "synthetic_password_36d2c530c09343ab" || m19_test::fault("missing-key"))
            return {7}; // KEY_NOT_FOUND
        response->iSecurityLevel = std::make_shared<IKeystoreSecurityLevel>();
        response->metadata.key.domain = Domain::KEY_ID;
        response->metadata.key.nspace = 4242;
        return {};
    }
};
}  // namespace aidl::android::system::keystore2

inline AIBinder* m19_test_lookup(const char* name)
{
    static AIBinder binder;
    if (!std::strcmp(name, "android.system.keystore2.IKeystoreService/default"))
        return m19_test::fault("missing-keystore") ? nullptr : &binder;
    if (!std::strcmp(name, "android.security.authorization"))
        return m19_test::fault("missing-authorization") ? nullptr : &binder;
    throw std::runtime_error("unknown service");
}

inline AIBinder* (*m19_test_check())(const char*)
{
    return m19_test::fault("missing-lookup") ? nullptr : m19_test_lookup;
}
#endif
