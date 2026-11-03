// Host-only typed stand-in, NOT a Binder/wire/TEE emulator. Never linked into Android artifacts.
#ifndef M19_BINDING_TEST_API_H
#define M19_BINDING_TEST_API_H
#include "core.h"
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <variant>
#include <vector>
#include <unistd.h>
#define EX_SERVICE_SPECIFIC (-8)
struct AParcel {};
struct AIBinder {};
namespace ndk {
struct ScopedAStatus {
    int error = 0;
    bool isOk() const { return error == 0; }
    int getExceptionCode() const { return error ? EX_SERVICE_SPECIFIC : 0; }
    int getServiceSpecificError() const { return error; }
    int getStatus() const { return 0; }
};
struct SpAIBinder { AIBinder* value; explicit SpAIBinder(AIBinder* b) : value(b) {} };
}
namespace m19_test {
struct Region { const void* address; size_t size; bool wiped; };
inline std::vector<Region> regions;
inline unsigned calls = 0, wipes = 0;
inline bool fault(const char* s) { const char* v = std::getenv("M19_TEST_FAULT"); return v && std::strcmp(v, s) == 0; }
inline void watch(const std::vector<uint8_t>& v) { if (!v.empty()) regions.push_back({v.data(), v.size(), false}); }
inline void blocking(const char* s) { if (fault(s)) for (;;) pause(); }
inline void throwing(const char* s) { if (fault(s)) throw std::runtime_error("injected"); }
inline void fill(std::optional<std::vector<uint8_t>>& v, size_t size) { v.emplace(size, 0xa5); watch(*v); }
inline ndk::ScopedAStatus error(bool fail) { return {fail ? -62 : 0}; }
}
namespace aidl::android::hardware::security::keymint {
enum class BlockMode { GCM };
enum class KeyPurpose { DECRYPT };
enum class PaddingMode { NONE };
enum class SecurityLevel { TRUSTED_ENVIRONMENT };
enum class Tag { BLOCK_MODE, PADDING, MAC_LENGTH, APPLICATION_ID, NONCE, PURPOSE };
struct KeyParameterValue {
    enum class Tag { blockMode, paddingMode, integer, blob, keyPurpose };
    Tag tag = Tag::integer;
    std::variant<int, std::vector<uint8_t>> value = 0;
    template<Tag t, typename V> static KeyParameterValue make(V v) {
        KeyParameterValue p; p.tag = t;
        if constexpr (std::is_same_v<V, std::vector<uint8_t>>) p.value = std::move(v);
        else p.value = static_cast<int>(v);
        return p;
    }
    Tag getTag() const { return tag; }
    template<Tag t> std::vector<uint8_t>& get() { static_assert(t == Tag::blob); return std::get<std::vector<uint8_t>>(value); }
};
struct KeyParameter { Tag tag = Tag::BLOCK_MODE; KeyParameterValue value; };
}
namespace aidl::android::system::keystore2 {
namespace km = ::aidl::android::hardware::security::keymint;
enum class Domain { BLOB };
struct KeyDescriptor { Domain domain; int64_t nspace = 0; std::optional<std::string> alias; std::optional<std::vector<uint8_t>> blob; };
struct KeyParameters { std::vector<km::KeyParameter> keyParameter; };
struct IKeystoreOperation {
    ndk::ScopedAStatus update(const std::vector<uint8_t>& body, std::optional<std::vector<uint8_t>>* part) {
        ++m19_test::calls; m19_test::watch(body);
        m19_test::blocking("update-block");
        m19_test::fill(*part, m19_test::fault("update-oversize") ? 5000 : m19_test::fault("empty") ? 0 : 24);
        m19_test::throwing("update-throw");
        return m19_test::error(m19_test::fault("update-error"));
    }
    ndk::ScopedAStatus finish(const std::optional<std::vector<uint8_t>>&, const std::optional<std::vector<uint8_t>>&,
                             std::optional<std::vector<uint8_t>>* part) {
        ++m19_test::calls; m19_test::blocking("finish-block");
        m19_test::fill(*part, m19_test::fault("empty") ? 0 : 16);
        m19_test::throwing("finish-throw");
        return m19_test::error(m19_test::fault("finish-error") || m19_test::fault("upgrade-then-fail"));
    }
};
struct CreateOperationResponse {
    std::shared_ptr<IKeystoreOperation> iOperation;
    std::optional<std::vector<uint8_t>> upgradedBlob;
    std::optional<KeyParameters> parameters;
};
struct EphemeralStorageKeyResponse { std::vector<uint8_t> ephemeralKey; std::optional<std::vector<uint8_t>> upgradedBlob; };
struct IKeystoreSecurityLevel {
    ndk::ScopedAStatus createOperation(const KeyDescriptor& key, const std::vector<km::KeyParameter>& parameters,
                                      bool forced, CreateOperationResponse* response) {
        ++m19_test::calls;
        if (key.domain != Domain::BLOB || key.nspace != 100 || key.alias || !key.blob || key.blob->empty() ||
            !forced || parameters.size() != 6) throw std::runtime_error("bad request contract");
        m19_test::watch(*key.blob);
        for (const auto& p : parameters) if (p.value.getTag() == km::KeyParameterValue::Tag::blob)
            m19_test::watch(std::get<std::vector<uint8_t>>(p.value.value));
        m19_test::blocking("create-block");
        if (m19_test::fault("upgrade") || m19_test::fault("upgrade-then-fail") || m19_test::fault("create-error-upgrade"))
            m19_test::fill(response->upgradedBlob, 214);
        if (m19_test::fault("empty-upgrade")) m19_test::fill(response->upgradedBlob, 0);
        if (m19_test::fault("oversized-upgrade")) m19_test::fill(response->upgradedBlob, M19_KEY_MAX + 1);
        if (!m19_test::fault("null-operation")) response->iOperation = std::make_shared<IKeystoreOperation>();
        return m19_test::error(m19_test::fault("create-error") || m19_test::fault("create-error-upgrade"));
    }
    ndk::ScopedAStatus convertStorageKeyToEphemeral(const KeyDescriptor& key, EphemeralStorageKeyResponse* response) {
        ++m19_test::calls; m19_test::watch(*key.blob); m19_test::blocking("convert-block");
        response->ephemeralKey.assign(m19_test::fault("convert-empty") ? 0 : m19_test::fault("convert-oversize") ? 5000 : 64, 0x5a);
        m19_test::watch(response->ephemeralKey);
        if (m19_test::fault("convert-upgrade") || m19_test::fault("convert-error-upgrade"))
            m19_test::fill(response->upgradedBlob, 64);
        if (m19_test::fault("convert-empty-upgrade")) m19_test::fill(response->upgradedBlob, 0);
        if (m19_test::fault("convert-oversized-upgrade")) m19_test::fill(response->upgradedBlob, M19_KEY_MAX + 1);
        m19_test::throwing("convert-throw");
        return m19_test::error(m19_test::fault("convert-error") || m19_test::fault("convert-error-upgrade"));
    }
};
struct IKeystoreService {
    static std::shared_ptr<IKeystoreService> fromBinder(const ndk::SpAIBinder& b) {
        return b.value ? std::make_shared<IKeystoreService>() : nullptr;
    }
    ndk::ScopedAStatus getSecurityLevel(km::SecurityLevel level, std::shared_ptr<IKeystoreSecurityLevel>* output) {
        ++m19_test::calls; m19_test::blocking("level-block");
        if (level != km::SecurityLevel::TRUSTED_ENVIRONMENT) throw std::runtime_error("wrong level");
        if (!m19_test::fault("null-level")) *output = std::make_shared<IKeystoreSecurityLevel>();
        return m19_test::error(m19_test::fault("level-error"));
    }
};
}
inline void m19_test_mark(const AParcel*) {}
inline AIBinder* m19_test_lookup(const char* name) {
    ++m19_test::calls; m19_test::blocking("lookup-block");
    if (std::strcmp(name, "android.system.keystore2.IKeystoreService/default")) throw std::runtime_error("wrong service");
    static AIBinder b;
    return m19_test::fault("missing-service") ? nullptr : &b;
}
inline void* m19_test_open() { return m19_test::fault("missing-library") ? nullptr : reinterpret_cast<void*>(1); }
inline void* m19_test_symbol(void*, const char* name) {
    if (!std::strcmp(name, "AParcel_markSensitive"))
        return m19_test::fault("missing-marker") ? nullptr : reinterpret_cast<void*>(m19_test_mark);
    if (!std::strcmp(name, "AServiceManager_checkService"))
        return m19_test::fault("missing-lookup") ? nullptr : reinterpret_cast<void*>(m19_test_lookup);
    return nullptr;
}
#endif
