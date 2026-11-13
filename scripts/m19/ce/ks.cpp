// Keystore2 and IKeystoreAuthorization for the CE path, the calls TWRP's unwrapSyntheticPasswordBlob makes
// (docs/m19-r7.md): the auth token from Gatekeeper, then getKeyEntry {SELINUX, 103, alias}, createOperation
// with AES/GCM/NONE/DECRYPT, the blob's nonce and a 128-bit tag, forced, and finish on the ciphertext.
#ifdef M19_KS_TEST
#include "ks-test-api.h"
#else
#include <aidl/android/hardware/security/keymint/Algorithm.h>
#include <aidl/android/hardware/security/keymint/BlockMode.h>
#include <aidl/android/hardware/security/keymint/HardwareAuthToken.h>
#include <aidl/android/hardware/security/keymint/HardwareAuthenticatorType.h>
#include <aidl/android/hardware/security/keymint/KeyParameter.h>
#include <aidl/android/hardware/security/keymint/KeyParameterValue.h>
#include <aidl/android/hardware/security/keymint/KeyPurpose.h>
#include <aidl/android/hardware/security/keymint/PaddingMode.h>
#include <aidl/android/hardware/security/keymint/Tag.h>
#include <aidl/android/hardware/security/secureclock/Timestamp.h>
#include <aidl/android/security/authorization/IKeystoreAuthorization.h>
#include <aidl/android/system/keystore2/CreateOperationResponse.h>
#include <aidl/android/system/keystore2/Domain.h>
#include <aidl/android/system/keystore2/IKeystoreOperation.h>
#include <aidl/android/system/keystore2/IKeystoreSecurityLevel.h>
#include <aidl/android/system/keystore2/IKeystoreService.h>
#include <aidl/android/system/keystore2/KeyDescriptor.h>
#include <aidl/android/system/keystore2/KeyEntryResponse.h>
#include <android/binder_auto_utils.h>
#endif
#include <dlfcn.h>

#include <cerrno>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "ks.h"

namespace ks2 = ::aidl::android::system::keystore2;
namespace km = ::aidl::android::hardware::security::keymint;
namespace auth = ::aidl::android::security::authorization;

namespace {

constexpr char kKeystore[] = "android.system.keystore2.IKeystoreService/default";
constexpr char kAuthorization[] = "android.security.authorization";
constexpr int32_t kMacBits = 128;

struct Context {
    std::shared_ptr<ks2::IKeystoreService> service;
    std::shared_ptr<auth::IKeystoreAuthorization> authorization;
};

Context& state()
{
    static Context context;
    return context;
}

void wipe(std::vector<uint8_t>& v)
{
    m19_wipe(v.data(), v.size());
}

void wipe(std::optional<std::vector<uint8_t>>& v)
{
    if (v)
        wipe(*v);
}

int status_detail(const ndk::ScopedAStatus& status)
{
    if (status.getExceptionCode() == EX_SERVICE_SPECIFIC)
        return status.getServiceSpecificError();
    return status.getExceptionCode() ? status.getExceptionCode() : status.getStatus();
}

using Check = AIBinder* (*)(const char*);

Check lookup_function()
{
#ifdef M19_KS_TEST
    return m19_test_check();
#else
    void* library = dlopen("libbinder_ndk.so", RTLD_NOW);
    return library ? reinterpret_cast<Check>(dlsym(library, "AServiceManager_checkService")) : nullptr;
#endif
}

template <km::KeyParameterValue::Tag kind, typename Value>
km::KeyParameter parameter(km::Tag tag, Value value)
{
    km::KeyParameter result;
    result.tag = tag;
    result.value = km::KeyParameterValue::make<kind>(std::move(value));
    return result;
}

int connect(void* opaque, int* detail)
{
    auto* context = static_cast<Context*>(opaque);
    try {
        *detail = -ENOSYS;
        Check check = lookup_function();
        if (!check)
            return -1;
        *detail = -ENOENT;
        ndk::SpAIBinder keystore(check(kKeystore));
        context->service = ks2::IKeystoreService::fromBinder(keystore);
        ndk::SpAIBinder authorization(check(kAuthorization));
        context->authorization = auth::IKeystoreAuthorization::fromBinder(authorization);
        if (!context->service || !context->authorization)
            return -1;
        *detail = 0;
        return 0;
    } catch (...) {
        *detail = -EFAULT;
        return -1;
    }
}

int add_auth_token(void* opaque, const struct m19_ce_auth_token* token, int* detail)
{
    auto* context = static_cast<Context*>(opaque);
    km::HardwareAuthToken hat;
    int result = -1;
    try {
        hat.challenge = token->challenge;
        hat.userId = token->user_id;
        hat.authenticatorId = token->authenticator_id;
        hat.authenticatorType = static_cast<km::HardwareAuthenticatorType>(token->authenticator_type);
        hat.timestamp.milliSeconds = token->timestamp_ms;
        hat.mac.assign(token->mac, token->mac + sizeof(token->mac));
        auto status = context->authorization->addAuthToken(hat);
        *detail = status_detail(status);
        result = status.isOk() ? 0 : -1;
    } catch (...) {
        *detail = -EFAULT;
    }
    wipe(hat.mac);
    return result;
}

int sp_decrypt(void* opaque, const char* alias, const uint8_t nonce[M19_CE_GCM_NONCE], const uint8_t* sealed, size_t sealed_size,
               uint8_t* output, size_t capacity, size_t* size, int* detail)
{
    using Kind = km::KeyParameterValue::Tag;
    auto* context = static_cast<Context*>(opaque);
    std::vector<km::KeyParameter> parameters;
    std::optional<std::vector<uint8_t>> input, plain;
    int result = -1;
    *size = 0;
    try {
        ks2::KeyDescriptor key;
        key.domain = ks2::Domain::SELINUX;
        key.nspace = M19_CE_KEYSTORE_NAMESPACE;
        key.alias = std::string(alias);
        ks2::KeyEntryResponse entry;
        auto status = context->service->getKeyEntry(key, &entry);
        *detail = status_detail(status);
        if (!status.isOk() || !entry.iSecurityLevel)
            throw 1;
        parameters.reserve(6);
        parameters.push_back(parameter<Kind::algorithm>(km::Tag::ALGORITHM, km::Algorithm::AES));
        parameters.push_back(parameter<Kind::blockMode>(km::Tag::BLOCK_MODE, km::BlockMode::GCM));
        parameters.push_back(parameter<Kind::paddingMode>(km::Tag::PADDING, km::PaddingMode::NONE));
        parameters.push_back(parameter<Kind::keyPurpose>(km::Tag::PURPOSE, km::KeyPurpose::DECRYPT));
        parameters.push_back(parameter<Kind::blob>(km::Tag::NONCE, std::vector<uint8_t>(nonce, nonce + M19_CE_GCM_NONCE)));
        parameters.push_back(parameter<Kind::integer>(km::Tag::MAC_LENGTH, kMacBits));
        ks2::CreateOperationResponse operation;
        status = entry.iSecurityLevel->createOperation(entry.metadata.key, parameters, true, &operation);
        *detail = status_detail(status);
        if (!status.isOk() || !operation.iOperation)
            throw 2;
        input.emplace(sealed, sealed + sealed_size);
        status = operation.iOperation->finish(input, std::nullopt, &plain);
        *detail = status_detail(status);
        if (!status.isOk() || !plain || plain->empty() || plain->size() > capacity)
            throw 3;
        std::memcpy(output, plain->data(), plain->size());
        *size = plain->size();
        result = 0;
    } catch (int) {
    } catch (...) {
        *detail = -EFAULT;
    }
    wipe(input);
    wipe(plain);
    return result;
}

const m19_ce_keystore kOps = {connect, add_auth_token, sp_decrypt};

}  // namespace

const struct m19_ce_keystore* m19_ce_ks_ops()
{
    return &kOps;
}

void* m19_ce_ks_context()
{
    return &state();
}
