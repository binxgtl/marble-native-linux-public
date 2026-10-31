// Keystore2 binding for the M19 client: the calls AOSP vold makes, with upgrades refused.
#include <aidl/android/hardware/security/keymint/BlockMode.h>
#include <aidl/android/hardware/security/keymint/KeyParameter.h>
#include <aidl/android/hardware/security/keymint/KeyParameterValue.h>
#include <aidl/android/hardware/security/keymint/KeyPurpose.h>
#include <aidl/android/hardware/security/keymint/PaddingMode.h>
#include <aidl/android/hardware/security/keymint/SecurityLevel.h>
#include <aidl/android/hardware/security/keymint/Tag.h>
#include <aidl/android/system/keystore2/CreateOperationResponse.h>
#include <aidl/android/system/keystore2/Domain.h>
#include <aidl/android/system/keystore2/EphemeralStorageKeyResponse.h>
#include <aidl/android/system/keystore2/IKeystoreOperation.h>
#include <aidl/android/system/keystore2/IKeystoreSecurityLevel.h>
#include <aidl/android/system/keystore2/IKeystoreService.h>
#include <aidl/android/system/keystore2/KeyDescriptor.h>
#include <android/binder_auto_utils.h>
#include <dlfcn.h>

#include <cstring>
#include <memory>
#include <optional>
#include <vector>

#include "binding.h"
#include "core.h"

namespace ks2 = ::aidl::android::system::keystore2;
namespace km = ::aidl::android::hardware::security::keymint;

namespace {

constexpr char kService[] = "android.system.keystore2.IKeystoreService/default";
constexpr int64_t kVoldNamespace = 100;
constexpr int32_t kMacBits = M19_MAC_BYTES * 8;

struct Context {
    std::shared_ptr<ks2::IKeystoreSecurityLevel> level;
};

int status_detail(const ndk::ScopedAStatus& status) {
    if (status.getExceptionCode() == EX_SERVICE_SPECIFIC) return status.getServiceSpecificError();
    return status.getExceptionCode() ? status.getExceptionCode() : status.getStatus();
}

template <km::KeyParameterValue::Tag kind, typename Value>
km::KeyParameter parameter(km::Tag tag, Value value) {
    km::KeyParameter result;
    result.tag = tag;
    result.value = km::KeyParameterValue::make<kind>(value);
    return result;
}

ks2::KeyDescriptor descriptor(const uint8_t* blob, size_t size) {
    ks2::KeyDescriptor key;
    key.domain = ks2::Domain::BLOB;
    key.nspace = kVoldNamespace;
    key.blob = std::vector<uint8_t>(blob, blob + size);
    return key;
}

int connect(void* opaque, int* detail) {
    using Wait = AIBinder* (*)(const char*);
    auto* context = static_cast<Context*>(opaque);
    void* library = dlopen("libbinder_ndk.so", RTLD_NOW);
    if (!library) return M19_KS_ERROR;
    auto wait = reinterpret_cast<Wait>(dlsym(library, "AServiceManager_waitForService"));
    if (!wait) return M19_KS_ERROR;
    ndk::SpAIBinder binder(wait(kService));
    auto service = ks2::IKeystoreService::fromBinder(binder);
    if (!service) return M19_KS_ERROR;
    auto status = service->getSecurityLevel(km::SecurityLevel::TRUSTED_ENVIRONMENT, &context->level);
    *detail = status_detail(status);
    return status.isOk() && context->level ? M19_KS_OK : M19_KS_ERROR;
}

int finish_output(std::vector<uint8_t>& from, uint8_t* output, size_t capacity, size_t* size) {
    if (from.size() > capacity) return M19_KS_ERROR;
    std::memcpy(output, from.data(), from.size());
    *size = from.size();
    return M19_KS_OK;
}

int decrypt(void* opaque, const m19_decrypt_request* request, uint8_t* output, size_t capacity, size_t* size, int* detail) {
    auto* context = static_cast<Context*>(opaque);
    using Kind = km::KeyParameterValue::Tag;
    std::vector<km::KeyParameter> parameters;
    parameters.push_back(parameter<Kind::blockMode>(km::Tag::BLOCK_MODE, km::BlockMode::GCM));
    parameters.push_back(parameter<Kind::paddingMode>(km::Tag::PADDING, km::PaddingMode::NONE));
    parameters.push_back(parameter<Kind::integer>(km::Tag::MAC_LENGTH, kMacBits));
    parameters.push_back(parameter<Kind::blob>(km::Tag::APPLICATION_ID,
                                               std::vector<uint8_t>(request->app_id, request->app_id + request->app_id_size)));
    parameters.push_back(parameter<Kind::blob>(km::Tag::NONCE, std::vector<uint8_t>(request->nonce, request->nonce + request->nonce_size)));
    parameters.push_back(parameter<Kind::keyPurpose>(km::Tag::PURPOSE, km::KeyPurpose::DECRYPT));

    ks2::CreateOperationResponse response;
    auto status = context->level->createOperation(descriptor(request->blob, request->blob_size), parameters, true, &response);
    *detail = status_detail(status);
    if (!status.isOk() || !response.iOperation) return M19_KS_ERROR;
    if (response.upgradedBlob) {
        response.iOperation->abort();
        return M19_KS_UPGRADE;
    }
    std::vector<uint8_t> body(request->body_and_mac, request->body_and_mac + request->body_and_mac_size), plain;
    std::optional<std::vector<uint8_t>> part;
    status = response.iOperation->update(body, &part);
    *detail = status_detail(status);
    if (!status.isOk()) return M19_KS_ERROR;
    if (part) plain = *part;
    part.reset();
    status = response.iOperation->finish(std::nullopt, std::nullopt, &part);
    *detail = status_detail(status);
    if (!status.isOk()) return M19_KS_ERROR;
    if (part) plain.insert(plain.end(), part->begin(), part->end());
    int result = finish_output(plain, output, capacity, size);
    m19_wipe(plain.data(), plain.size());
    return result;
}

int ephemeral(void* opaque, const uint8_t* storage_key, size_t storage_key_size, uint8_t* output, size_t capacity, size_t* size, int* detail) {
    auto* context = static_cast<Context*>(opaque);
    ks2::EphemeralStorageKeyResponse response;
    auto status = context->level->convertStorageKeyToEphemeral(descriptor(storage_key, storage_key_size), &response);
    *detail = status_detail(status);
    if (!status.isOk()) return M19_KS_ERROR;
    int result = response.upgradedBlob ? static_cast<int>(M19_KS_UPGRADE) : finish_output(response.ephemeralKey, output, capacity, size);
    m19_wipe(response.ephemeralKey.data(), response.ephemeralKey.size());
    return result;
}

const m19_keystore_ops kOps = {connect, decrypt, ephemeral};

}  // namespace

const m19_keystore_ops* m19_keystore2_ops() { return &kOps; }

void* m19_keystore2_context() {
    static Context context;
    return &context;
}
